//! Saved identities never expose partial keys or rotate an existing invalid file.
use nethernet_tokio::util::identity::from_pem_or_create;
use std::path::PathBuf;

struct Directory(PathBuf);
impl Directory {
    /// Reserves an isolated directory owned by this fixture.
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "nethernet-key-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    /// Removes only this fixture's files after every owned creator has joined.
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

/// A prior empty claim contains no established identity and must recover normally.
#[tokio::test]
async fn an_empty_key_file_is_recovered_without_replacing_invalid_contents() {
    let directory = Directory::new();
    let path = directory.0.join("identity.pem");
    std::fs::write(&path, []).unwrap();
    let created = from_pem_or_create(&path, "self").await.unwrap();
    let loaded = from_pem_or_create(&path, "self").await.unwrap();
    assert_eq!(created.verifying_key(), loaded.verifying_key());
    let generated = created.to_pem().unwrap();
    let truncated = &generated.as_bytes()[..generated.len() / 2];
    for invalid in [b"not a key".as_slice(), truncated] {
        std::fs::write(&path, invalid).unwrap();
        assert!(from_pem_or_create(&path, "self").await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), invalid);
    }
}

/// All simultaneous first starts succeed and agree on the one saved public key.
#[tokio::test]
async fn concurrent_creators_reuse_one_private_saved_key() {
    let directory = Directory::new();
    let path = directory.0.join("private").join("identity.pem");
    let creators = (0..8).map(|_| from_pem_or_create(&path, "self"));
    let identities = futures::future::join_all(creators).await;
    let loaded = from_pem_or_create(&path, "self").await.unwrap();
    for identity in identities {
        assert_eq!(identity.unwrap().verifying_key(), loaded.verifying_key());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for (file, mode) in [
            (path.clone(), 0o600),
            (path.with_extension("pem.lock"), 0o600),
            (path.parent().unwrap().to_path_buf(), 0o700),
        ] {
            assert_eq!(
                std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
    }
}

/// Child-only entry point exercises the public API from an independently opened process.
#[test]
#[ignore = "subprocess fixture"]
fn saved_key_creator_process() {
    let path = PathBuf::from(std::env::var_os("NETHERNET_KEY_TEST_PATH").unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let identity = runtime.block_on(from_pem_or_create(path, "self")).unwrap();
    println!("KEY:{}", public_key(&identity));
}

/// Separate processes all reuse the same published key rather than failing a first-start race.
#[test]
fn separate_process_creators_all_succeed() {
    let directory = Directory::new();
    let path = directory.0.join("identity.pem");
    let children: Vec<_> = (0..8)
        .map(|_| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "saved_key_creator_process",
                    "--ignored",
                    "--nocapture",
                ])
                .env("NETHERNET_KEY_TEST_PATH", &path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let outcomes: Vec<_> = children
        .into_iter()
        .map(|child| child.wait_with_output())
        .collect();
    let keys: Vec<_> = outcomes
        .into_iter()
        .map(|outcome| {
            let outcome = outcome.unwrap();
            assert!(
                outcome.status.success(),
                "{}",
                String::from_utf8_lossy(&outcome.stderr)
            );
            String::from_utf8(outcome.stdout)
                .unwrap()
                .lines()
                .find_map(|line| {
                    line.split_once("KEY:")
                        .map(|(_, key)| key.trim().to_owned())
                })
                .unwrap()
        })
        .collect();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let identity = runtime.block_on(from_pem_or_create(path, "self")).unwrap();
    assert!(keys.iter().all(|key| key == &public_key(&identity)));
}

/// Compares only public key bytes across isolated fixture processes.
fn public_key(identity: &nethernet_tokio::ServerIdentity) -> String {
    identity
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

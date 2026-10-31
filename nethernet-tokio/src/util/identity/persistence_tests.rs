use super::*;
use std::{
    io::{BufRead, Read},
    process::{Command, Stdio},
};

struct Directory(PathBuf);
impl Directory {
    /// Reserves an isolated directory for the owned writer processes.
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "nethernet-publish-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    /// Removes only this fixture's directory after its writers have joined.
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

/// The final path remains absent until its complete synced temporary key is ready to publish.
#[test]
fn an_interrupted_publish_leaves_no_partial_destination() {
    let directory = Directory::new();
    let path = directory.0.join("identity.pem");
    let result = load_or_create(&path, "self".into(), |temporary| {
        assert!(!path.exists());
        assert!(read(temporary, "self").unwrap().is_some());
        Err(io::Error::other("fixture interrupts publication"))
    });
    assert!(result.is_err());
    assert!(!path.exists());
    assert_eq!(
        fs::read_dir(&directory.0).unwrap().count(),
        1,
        "only the stable lock remains"
    );
}

/// Stale cleanup covers both save formats without deleting unrelated files or directories.
#[test]
fn a_creator_cleans_only_stale_key_temporaries() {
    let directory = Directory::new();
    let path = directory.0.join("identity.pem");
    for name in [
        "identity.pem.tmp123",
        ".nethernet-key-456",
        "identity.pem.tmp",
        "identity.pem.tmpABC",
        "other.tmp123",
    ] {
        fs::write(directory.0.join(name), b"fixture temporary").unwrap();
    }
    fs::create_dir(directory.0.join("identity.pem.tmp789")).unwrap();
    load_or_create(&path, "self".into(), |_| Ok(())).unwrap();
    for name in ["identity.pem.tmp123", ".nethernet-key-456"] {
        assert!(!directory.0.join(name).exists());
    }
    for name in [
        "identity.pem.tmp",
        "identity.pem.tmpABC",
        "other.tmp123",
        "identity.pem.tmp789",
    ] {
        assert!(directory.0.join(name).exists());
    }
}

/// Child-only entry point holds the actual publisher after syncing, before its rename.
#[test]
#[ignore = "subprocess fixture"]
fn interrupted_publisher_process() {
    let path = PathBuf::from(std::env::var_os("NETHERNET_KEY_TEST_PATH").unwrap());
    load_or_create(&path, "self".into(), |_| {
        println!("TEMP_READY");
        io::stdout().flush()?;
        io::stdin().read_exact(&mut [0])?;
        Ok(())
    })
    .unwrap();
}

/// A creator killed while holding its lock leaves only an unpublished temp, recovered on restart.
#[test]
fn a_killed_creator_releases_its_lock_and_its_temporary_is_recovered() {
    let directory = Directory::new();
    let path = directory.0.join("identity.pem");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "util::identity::persistence_tests::interrupted_publisher_process",
            "--ignored",
            "--nocapture",
        ])
        .env("NETHERNET_KEY_TEST_PATH", &path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.stdout.take().unwrap();
    let mut lines = io::BufReader::new(output).lines();
    let ready = lines.any(|line| line.is_ok_and(|line| line == "TEMP_READY"));
    // Child::kill addresses only the exact child PID returned by this fixture's spawn.
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(ready);
    assert!(!path.exists());
    let identity = load_or_create(&path, "self".into(), |_| Ok(())).unwrap();
    assert_eq!(
        identity.verifying_key(),
        read(&path, "self").unwrap().unwrap().verifying_key()
    );
    assert_eq!(
        fs::read_dir(&directory.0).unwrap().count(),
        2,
        "only key and lock remain"
    );
}

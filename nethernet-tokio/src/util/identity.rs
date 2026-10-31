//! Loading and durably publishing a stable server identity key.
use crate::error::{NetherError, Result};
use nethernet::identity::ServerIdentity;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

/// Loads a saved P-384 key or creates it once under an exclusive adjacent file lock.
/// Cancelling the wait does not interrupt a publisher while it owns the lock.
pub async fn from_pem_or_create(
    pem: impl AsRef<Path>,
    domain: impl Into<String>,
) -> Result<ServerIdentity> {
    let path = pem.as_ref().to_owned();
    let domain = domain.into();
    tokio::task::spawn_blocking(move || load_or_create(&path, domain, |_| Ok(())))
        .await
        .map_err(|error| NetherError::Io(io::Error::other(error)))?
}

/// Loads an existing identity PEM; missing, empty, and malformed files are errors.
pub async fn from_pem(pem: impl AsRef<Path>, domain: impl Into<String>) -> Result<ServerIdentity> {
    let contents = tokio::fs::read_to_string(pem.as_ref()).await?;
    Ok(ServerIdentity::from_pem(
        &contents,
        domain,
        SystemTime::now(),
    )?)
}

/// Serializes creators and rechecks after locking, so a waiter adopts the first saved key.
fn load_or_create(
    path: &Path,
    domain: String,
    before_publish: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<ServerIdentity> {
    if let Some(identity) = read(path, &domain)? {
        return Ok(identity);
    }
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory)?;
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock = private_options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    loop {
        match lock.lock() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => {
                result?;
                break;
            }
        }
    }
    if let Some(identity) = read(path, &domain)? {
        return Ok(identity);
    }
    clean_temps(path, directory);
    let identity = ServerIdentity::generate(domain, SystemTime::now())?;
    let (temporary, mut file) = temporary(path, directory)?;
    file.write_all(identity.to_pem()?.as_bytes())?;
    file.sync_all()?;
    drop(file);
    before_publish(&temporary.0)?;
    fs::rename(&temporary.0, path)?;
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    Ok(identity)
}

/// Only an absent or empty destination permits creation; every nonempty parse error is preserved.
fn read(path: &Path, domain: &str) -> Result<Option<ServerIdentity>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if contents.is_empty() {
        return Ok(None);
    }
    Ok(Some(ServerIdentity::from_pem(
        &contents,
        domain,
        SystemTime::now(),
    )?))
}

/// Keeps key, lock, and temporary files private from their initial creation on Unix.
fn private_options() -> OpenOptions {
    let options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = options;
        options.mode(0o600);
        options
    }
    #[cfg(not(unix))]
    {
        options
    }
}

/// Reserves a same-directory destination so the completed key can be renamed atomically.
fn temporary(path: &Path, directory: &Path) -> io::Result<(Temporary, File)> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "server key has no file name")
    })?;
    loop {
        let mut candidate = name.to_os_string();
        candidate.push(format!(".tmp{}", rand::random::<u64>()));
        let candidate = directory.join(candidate);
        match private_options()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((Temporary(candidate), file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

/// Removes only regular files named by current or older crashed publishers, while locked.
fn clean_temps(path: &Path, directory: &Path) {
    let Some(base) = path.file_name() else {
        return;
    };
    let mut prefix = base.to_os_string();
    prefix.push(".tmp");
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.as_encoded_bytes();
        let digits = name
            .strip_prefix(prefix.as_encoded_bytes())
            .or_else(|| name.strip_prefix(b".nethernet-key-"));
        if digits.is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit))
            && entry.file_type().is_ok_and(|kind| kind.is_file())
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    /// Error and cancellation paths leave no unpublished key owned by this publisher.
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod persistence_tests;

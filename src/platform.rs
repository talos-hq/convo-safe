//! File permission helpers shared by the application and worker.

use std::{
    fs::{File, Metadata, OpenOptions},
    io,
    path::Path,
};

pub fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(unix)]
pub fn has_private_permissions(metadata: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
pub fn has_private_permissions(_: &Metadata) -> bool {
    true
}

//! Files this program writes.
//!
//! Every file it owns is written atomically - a temp file and a rename -
//! because a machine that loses power halfway through writing a WireGuard
//! config or a systemd unit is left with a half-written one, and a
//! half-written unit is a service that silently does not start.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Write a file with a mode, atomically.
pub fn write_file(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
    }
    // A unique temp name, created O_EXCL. `<path>.tmp-write` was fixed, so two
    // writers shared it - and the installer runs as root, so a name anything
    // else can predict in a shared directory is a name anything else can
    // replace with a symlink before the rename follows it.
    let tmp = unique_temp_path(path)?;
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            // The mode lives in the open flags: the file holds key material
            // (a WireGuard private key, a SOCKS password) and chmod-after-
            // write leaves it at the umask's 0644 until the chmod lands.
            .mode(mode)
            .open(&tmp)
            .map_err(|e| format!("could not write {}: {e}", tmp.display()))?;
        // A re-created file keeps the mode it had; set it explicitly too, so a
        // pre-existing 0644 file is narrow rather than briefly world-readable.
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| format!("could not set the mode on {}: {e}", tmp.display()))?;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("could not write {}: {e}", tmp.display()))?;
        file.sync_all()
            .map_err(|e| format!("could not flush {}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("could not replace {}: {e}", path.display())
    })
}

/// A sibling of `path` that nothing else is using.
fn unique_temp_path(path: &Path) -> Result<PathBuf, String> {
    let pid = std::process::id();
    for attempt in 0..64u32 {
        let candidate = path.with_extension(format!("tmp-{pid}-{attempt}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "could not find a free temp name beside {}",
        path.display()
    ))
}

/// Write a file that is meant to be run.
pub fn write_executable(path: &Path, content: &str) -> Result<(), String> {
    write_file(path, content, 0o755)
}

pub fn read_to_string(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

pub fn exists(path: &Path) -> bool {
    path.exists()
}

/// Keep the FIRST copy of a file, so a re-run cannot overwrite the
/// pristine original with an already-modified one.
pub fn backup_once(path: &Path, backup: &Path) -> Result<(), String> {
    if backup.exists() {
        return Ok(());
    }
    if !path.exists() {
        return Ok(());
    }
    fs::copy(path, backup).map_err(|e| format!("could not back up {}: {e}", path.display()))?;
    let _ = fs::set_permissions(backup, fs::Permissions::from_mode(0o600));
    Ok(())
}

/// Remove a file, ignoring the case where it is not there.
pub fn remove(path: &Path) {
    let _ = fs::remove_file(path);
}

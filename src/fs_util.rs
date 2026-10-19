//! Files this program writes.
//!
//! Every file it owns is written atomically - a temp file and a rename -
//! because a machine that loses power halfway through writing a WireGuard
//! config or a systemd unit is left with a half-written one, and a
//! half-written unit is a service that silently does not start.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Write a file with a mode, atomically.
pub fn write_file(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
    }
    let tmp: PathBuf = path.with_extension("tmp-write");
    {
        let mut file = fs::File::create(&tmp)
            .map_err(|e| format!("could not write {}: {e}", tmp.display()))?;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("could not write {}: {e}", tmp.display()))?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| format!("could not set the mode on {}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("could not replace {}: {e}", path.display())
    })
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

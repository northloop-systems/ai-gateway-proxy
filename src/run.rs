//! Running other programs.
//!
//! The node's work is mostly other people's tools - `wg`, `warp-cli`,
//! `systemctl`, `curl` - so this is the boundary where the binary talks to
//! the machine.

use std::process::{Command, Stdio};

/// What a program did.
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }

    /// The first line of stderr, which is where these tools put the reason.
    pub fn reason(&self) -> String {
        self.stderr.lines().next().unwrap_or("").trim().to_string()
    }
}

/// Run a program and capture what it said. The program's exit status is
/// returned rather than raised: plenty of calls here are expected to fail
/// (a probe, a `which`), and the caller decides what that means.
pub fn run(program: &str, args: &[&str]) -> Result<Output, String> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run {program}: {e}"))?;
    Ok(Output {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    })
}

/// Run a program and fail if it did not succeed.
pub fn run_ok(program: &str, args: &[&str]) -> Result<Output, String> {
    let out = run(program, args)?;
    if !out.ok() {
        let reason = out.reason();
        return Err(format!(
            "{program} failed (status {}): {reason}",
            out.status
        ));
    }
    Ok(out)
}

/// Run a program for its stdout, and `None` if it failed or said nothing.
/// For the calls where the output is an answer, not a result.
pub fn capture(program: &str, args: &[&str]) -> Option<String> {
    let out = run(program, args).ok()?;
    if !out.ok() {
        return None;
    }
    let text = out.stdout.trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Run a program and ignore whatever happened. For the calls where a failure
/// is genuinely fine.
pub fn try_run(program: &str, args: &[&str]) {
    let _ = run(program, args);
}

/// Is this program on the PATH?
pub fn have(program: &str) -> bool {
    run("sh", &["-c", &format!("command -v {program}")])
        .map(|o| o.ok())
        .unwrap_or(false)
}

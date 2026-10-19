//! Logging.
//!
//! Two streams on purpose: the progress lines the operator watches while
//! the install runs, and the errors that end it. Everything goes to stderr
//! except the final summary, which is the installer's actual output and
//! belongs on stdout.

use std::io::Write;
use std::sync::Mutex;

static STDERR_LOCK: Mutex<()> = Mutex::new(());

fn emit(prefix: &str, message: &str) {
    let _guard = STDERR_LOCK.lock();
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{prefix}{message}");
    let _ = err.flush();
}

/// A progress line, in the shape the installer has always used.
pub fn step(message: &str) {
    emit("[proxy] ", message);
}

/// Something worth noticing but not fatal.
pub fn warn(message: &str) {
    emit("[proxy] WARNING: ", message);
}

/// Something that stopped the work.
pub fn err(message: &str) {
    emit("[proxy] ERROR: ", message);
}

/// A plain line, for the summary the operator reads.
pub fn plain(message: &str) {
    println!("{message}");
}

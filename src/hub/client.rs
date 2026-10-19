//! The client for the hub's proxy API.
//!
//! The node asks the hub who it is bound to, registers itself, can list
//! the nodes the hub knows, and can take itself back off again.
//!
//! The calls go out through curl rather than a TLS stack of our own: a
//! TLS stack is the single largest dependency tree a program like this
//! could have, and curl is on every machine that would run it.
//!
//! THE TOKEN NEVER APPEARS IN A COMMAND LINE. `ps` shows every process's
//! arguments to every user on the machine, and this token grants access
//! to the node, so it goes into a 0600 curl config file that is deleted
//! as soon as the call is over - including when the call failed. The
//! request body goes into a file for the same reason: it carries the
//! SOCKS password the hub needs to reach this node's exits.

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::hub::json::Json;
use crate::hub::types::{NodeInfo, RegisterRequest, RegisterResponse};
use crate::run;

/// How long the registration may take.
///
/// The hub probes this node's exits while it registers, so this call can
/// take a while even though the hub itself answers quickly.
const REGISTER_TIMEOUT: u32 = 15;

/// How long the other calls may take: one request, one answer, and
/// nothing for the hub to probe.
const CALL_TIMEOUT: u32 = 10;

/// The hub, and the credential this node uses with it.
pub struct Hub {
    base: String,
    token: String,
}

impl std::fmt::Debug for Hub {
    /// The token is a secret, so it never appears in a debug dump.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hub")
            .field("base", &self.base)
            .field("token", &"[redacted]")
            .finish()
    }
}

impl Hub {
    /// The hub at `server_host`, and the token to use with it.
    pub fn new(server_host: &str, token: &str) -> Hub {
        Hub {
            base: base_url(server_host),
            token: token.to_string(),
        }
    }

    /// The node name the token is bound to.
    ///
    /// This is the preflight. The shell installer calls it before it
    /// changes anything, so a token the hub will not accept is caught
    /// while the machine is still untouched.
    ///
    /// An EMPTY string means the hub accepted the credential but it is
    /// not bound to a node - a front-door API key, which the hub lets
    /// register under any name. The shell installer keeps the machine's
    /// own hostname in that case, and so should the caller.
    pub fn whoami(&self) -> Result<String, String> {
        let body = match self.call("GET", "/proxy/whoami", None, CALL_TIMEOUT) {
            Ok(body) => body,
            Err(Failure::Refused { status, message }) => {
                let mut text = format!("the hub refused the token (HTTP {status}): {message}");
                let _ = writeln!(text);
                let _ = writeln!(
                    text,
                    "  Check the token and the server address. The token is the one the"
                );
                let _ = writeln!(
                    text,
                    "  hub issued for this node, and it is valid on /v1/proxy only."
                );
                return Err(text);
            }
            Err(other) => return Err(other.describe()),
        };
        let value = Json::parse(&body)
            .map_err(|e| format!("the hub's answer to whoami is not JSON: {e}"))?;
        // The hub says whether it accepted the credential. A 200 that
        // carries "authenticated": false is a refusal dressed as an
        // answer, and the preflight has to treat it as one.
        if let Some(authenticated) = value.get("authenticated").and_then(Json::as_bool) {
            if !authenticated {
                return Err(
                    "the hub did not accept the token. Check the token and the server address."
                        .to_string(),
                );
            }
        }
        Ok(bound_label(&value).unwrap_or_default())
    }

    /// Register this node with the hub.
    ///
    /// The answer carries the address the hub wants this node's tunnel
    /// to use and the key the hub's side of it holds.
    pub fn register(&self, request: &RegisterRequest) -> Result<RegisterResponse, String> {
        let body = request.to_json().write();
        let answer = match self.call("POST", "/proxy/register", Some(&body), REGISTER_TIMEOUT) {
            Ok(answer) => answer,
            Err(Failure::Refused { status, message }) => {
                return Err(refused(
                    format!("the hub refused the registration (HTTP {status}): {message}"),
                    request,
                ));
            }
            Err(other) => return Err(other.describe()),
        };
        let value = Json::parse(&answer)
            .map_err(|e| format!("the hub's registration answer is not JSON: {e}"))?;
        let status = value.get("status").and_then(Json::as_str).unwrap_or("");
        if status != "ok" {
            return Err(refused(
                format!(
                    "the hub refused the registration: {}",
                    error_message(&answer)
                ),
                request,
            ));
        }
        RegisterResponse::from_json(&value)
    }

    /// Revoke this node at the hub.
    ///
    /// The hub drops the registry entry and the WireGuard peer, so the
    /// tunnel really dies instead of lingering.
    pub fn deregister(&self, node_id: &str) -> Result<(), String> {
        if !is_node_id(node_id) {
            return Err(format!(
                "'{node_id}' is not a node id the hub would accept (node-<name>), so there is nothing to revoke"
            ));
        }
        let path = format!("/proxy/nodes/{node_id}");
        match self.call("DELETE", &path, None, CALL_TIMEOUT) {
            Ok(answer) => {
                if let Ok(value) = Json::parse(&answer) {
                    let status = value.get("status").and_then(Json::as_str).unwrap_or("ok");
                    if status != "ok" {
                        return Err(format!(
                            "the hub did not remove {node_id}: {}",
                            error_message(&answer)
                        ));
                    }
                }
                Ok(())
            }
            Err(Failure::Refused { status, message }) => Err(format!(
                "the hub refused to remove {node_id} (HTTP {status}): {message}"
            )),
            Err(other) => Err(other.describe()),
        }
    }

    /// The nodes the hub knows about.
    pub fn nodes(&self) -> Result<Vec<NodeInfo>, String> {
        let body = self
            .call("GET", "/proxy/nodes", None, CALL_TIMEOUT)
            .map_err(|failure| failure.describe())?;
        let value =
            Json::parse(&body).map_err(|e| format!("the hub's node list is not JSON: {e}"))?;
        let data = value
            .get("data")
            .ok_or("the hub's node list has no 'data' in it")?;
        let items = match data {
            Json::Arr(items) => items,
            _ => return Err("the hub's node list is not a list".to_string()),
        };
        let mut nodes = Vec::new();
        for item in items {
            nodes.push(NodeInfo::from_json(item)?);
        }
        Ok(nodes)
    }

    /// One call to the hub, and the body it answered with.
    ///
    /// The token is written to a private config file, the request body
    /// (which holds the SOCKS password) to a private file, and neither
    /// ever reaches a command line.
    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        timeout: u32,
    ) -> Result<String, Failure> {
        if self.base.is_empty() {
            return Err(Failure::Local("no hub address was given".to_string()));
        }
        if !usable_token(&self.token) {
            return Err(Failure::Local(
                "the token has a character in it that cannot go into a curl config file, so it was not sent"
                    .to_string(),
            ));
        }
        let url = format!("{}{}", self.base, path);
        let scratch = Scratch::new().map_err(Failure::Local)?;
        let config = scratch
            .file("curl.conf", &config_text(&self.token))
            .map_err(Failure::Local)?;
        let body_path = match body {
            Some(text) => Some(scratch.file("body.json", text).map_err(Failure::Local)?),
            None => None,
        };
        let args = curl_args(&config, body_path.as_deref(), method, &url, timeout);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = run::run("curl", &args).map_err(|e| {
            Failure::Local(format!(
                "could not run curl: {e}. curl is how the node reaches the hub; install it with 'apt-get install curl'"
            ))
        })?;
        if !out.ok() {
            let reason = out.reason();
            let detail = if reason.is_empty() {
                format!("curl exited with status {}", out.status)
            } else {
                reason
            };
            return Err(Failure::Unreachable(format!(
                "{detail} (the hub is at {url})"
            )));
        }
        let (text, status) = split_status(&out.stdout).map_err(Failure::Local)?;
        if status != 200 {
            return Err(Failure::Refused {
                status,
                message: error_message(&text),
            });
        }
        Ok(text)
    }
}

/// The message for a registration the hub would not take.
///
/// The hub refuses a registration under the wrong node name, and the
/// reason is worth saying out loud: the token is bound to one name, and
/// the fix is a different token, not a different request.
fn refused(reason: String, request: &RegisterRequest) -> String {
    let mut text = reason;
    let _ = writeln!(text);
    let _ = writeln!(
        text,
        "  The token is bound to one node name; register under that name, or ask"
    );
    let _ = writeln!(
        text,
        "  the operator for a token for '{}'.",
        request.hostname
    );
    text
}

/// What went wrong with a call.
enum Failure {
    /// The call never left this machine.
    Local(String),
    /// The call never reached the hub.
    Unreachable(String),
    /// The hub answered, and said no.
    Refused { status: i32, message: String },
}

impl Failure {
    /// A message for the operator: what failed, and what to look at.
    fn describe(&self) -> String {
        match self {
            Failure::Local(message) => format!("the request could not be made: {message}"),
            Failure::Unreachable(message) => format!("could not reach the hub: {message}"),
            Failure::Refused { status, message } => {
                format!("the hub refused the request (HTTP {status}): {message}")
            }
        }
    }
}

/// The curl command line for one call.
///
/// The token is NOT in here. It is in the config file, and only the path
/// of that file is on the command line.
fn curl_args(
    config: &Path,
    body: Option<&Path>,
    method: &str,
    url: &str,
    timeout: u32,
) -> Vec<String> {
    let mut args = vec![
        "-s".to_string(),
        "-S".to_string(),
        "-m".to_string(),
        timeout.to_string(),
        "--config".to_string(),
        config.display().to_string(),
        // The status code after the body, so one call gives both.
        "-w".to_string(),
        "|HTTP:%{http_code}".to_string(),
    ];
    if method != "GET" {
        args.push("-X".to_string());
        args.push(method.to_string());
    }
    if let Some(path) = body {
        args.push("-H".to_string());
        args.push("Content-Type: application/json".to_string());
        args.push("-d".to_string());
        args.push(format!("@{}", path.display()));
    }
    args.push(url.to_string());
    args
}

/// The body and the status code, out of what curl printed.
fn split_status(stdout: &str) -> Result<(String, i32), String> {
    const MARKER: &str = "|HTTP:";
    let at = stdout
        .rfind(MARKER)
        .ok_or("curl did not report a status code")?;
    let body = &stdout[..at];
    let code = stdout[at + MARKER.len()..].trim();
    let status = code
        .parse::<i32>()
        .map_err(|_| format!("curl reported an unreadable status code: {code}"))?;
    Ok((body.to_string(), status))
}

/// The hub's explanation, in words.
///
/// The gateway answers a refusal with the OpenAI error envelope, so the
/// reason is in there. Anything else is shown as it arrived, cut short so
/// a long answer cannot fill the screen.
fn error_message(body: &str) -> String {
    if let Ok(value) = Json::parse(body) {
        if let Some(message) = value
            .get("error")
            .and_then(|error| error.get("message"))
            .and_then(Json::as_str)
        {
            return message.to_string();
        }
        if let Some(message) = value.get("detail").and_then(Json::as_str) {
            return message.to_string();
        }
        if let Some(message) = value.get("message").and_then(Json::as_str) {
            return message.to_string();
        }
    }
    let text = body.trim();
    if text.is_empty() {
        return "the hub sent no explanation".to_string();
    }
    if text.chars().count() > 300 {
        let cut: String = text.chars().take(300).collect();
        return format!("{cut}...");
    }
    text.to_string()
}

/// The node label the hub says this credential is bound to.
///
/// The hub answers `{"authenticated": true, "bound_node": "laptop" | null,
/// "registered": true}`. The label carries no `node-` prefix: the
/// registry uses one, the token does not.
fn bound_label(value: &Json) -> Option<String> {
    for key in ["bound_node", "node"] {
        if let Some(name) = value.get(key).and_then(Json::as_str) {
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// The hub's base URL.
///
/// The caller usually has a host name, which becomes `https://host/v1`. A
/// full URL is accepted too, so a caller that already knows the base does
/// not have to take it apart.
fn base_url(server_host: &str) -> String {
    let host = server_host.trim().trim_end_matches('/');
    if host.is_empty() {
        return String::new();
    }
    if host.starts_with("http://") || host.starts_with("https://") {
        if host.ends_with("/v1") {
            host.to_string()
        } else {
            format!("{host}/v1")
        }
    } else {
        format!("https://{host}/v1")
    }
}

/// Is this a node id the hub would accept?
///
/// The hub's own rule: `node-` and then up to 128 characters of letters,
/// digits, dot, dash and underscore. Checking it here turns a strange id
/// into a clear message instead of a 400 from the hub.
fn is_node_id(node_id: &str) -> bool {
    let label = match node_id.strip_prefix("node-") {
        Some(label) => label,
        None => return false,
    };
    !label.is_empty()
        && label.len() <= 128
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// Can this token go into a curl config file?
///
/// The file holds the token in a quoted string, so a quote, a backslash
/// or a control character would either break the file or change what curl
/// sends. The tokens the hub issues are printable ASCII, so this only
/// ever catches one that was typed or copied wrong.
fn usable_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_graphic() && c != '"' && c != '\\')
}

/// The curl config that carries the token.
///
/// The token must never be on a command line: `ps` shows every process's
/// arguments to every user on the machine, and this token grants access
/// to the node. curl reads options from a config file, so the credential
/// goes in a file that is 0600 and is deleted straight after the call.
fn config_text(token: &str) -> String {
    let mut text = String::new();
    let _ = writeln!(text, r#"header = "Authorization: Bearer {}""#, token);
    text
}

/// A private directory for the files one call needs.
///
/// The curl config holds the token and the request body holds the SOCKS
/// password, so both are written 0600 inside a 0700 directory that is
/// removed when the call is over - including when the call failed. The
/// directory is made with create_dir and the files with create_new, so
/// neither can ever be something that was already there.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new() -> Result<Scratch, String> {
        let base = std::env::temp_dir();
        for attempt in 0..8u32 {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|since| since.as_nanos())
                .unwrap_or(0);
            let dir = base.join(format!(
                "ai-gateway-proxy-{}-{stamp}-{attempt}",
                process::id()
            ));
            match fs::create_dir(&dir) {
                Ok(()) => {
                    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
                    return Ok(Scratch { dir });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(format!(
                        "could not make a private directory in {}: {e}",
                        base.display()
                    ))
                }
            }
        }
        Err(format!(
            "could not make a private directory in {}",
            base.display()
        ))
    }

    /// A file in the private directory, readable by its owner only.
    fn file(&self, name: &str, content: &str) -> Result<PathBuf, String> {
        let path = self.dir.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;
        Ok(path)
    }
}

impl Drop for Scratch {
    /// The files go, whether the call worked or not.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_is_never_in_the_command_line() {
        let token = "tok_abcdef0123456789";
        let args = curl_args(
            Path::new("/tmp/scratch/curl.conf"),
            None,
            "GET",
            "https://hub.example/v1/proxy/whoami",
            CALL_TIMEOUT,
        );
        for arg in &args {
            assert!(
                !arg.contains(token),
                "the command line carries the token: {arg}"
            );
        }
        // And it really is in the config file, which is where curl reads
        // it from.
        assert!(config_text(token).contains(token));
    }

    #[test]
    fn the_request_body_is_never_in_the_command_line() {
        let args = curl_args(
            Path::new("/tmp/scratch/curl.conf"),
            Some(Path::new("/tmp/scratch/body.json")),
            "POST",
            "https://hub.example/v1/proxy/register",
            REGISTER_TIMEOUT,
        );
        for arg in &args {
            assert!(!arg.contains("s3cr3tpassword"), "{arg}");
        }
        // The body is named on the command line, but only its path.
        assert!(args.iter().any(|arg| arg == "@/tmp/scratch/body.json"));
    }

    #[test]
    fn the_config_carries_the_token_as_a_header() {
        let text = config_text("tok_abc");
        assert_eq!(text, "header = \"Authorization: Bearer tok_abc\"\n");
    }

    #[test]
    fn a_token_that_cannot_go_in_the_config_is_refused() {
        assert!(usable_token("tok_abc"));
        assert!(!usable_token(""));
        assert!(!usable_token("tok with space"));
        assert!(!usable_token("tok\"quoted"));
        assert!(!usable_token("tok\\slash"));
        assert!(!usable_token("tok\nnewline"));
    }

    #[test]
    fn the_command_line_asks_for_the_status_code() {
        let args = curl_args(
            Path::new("/tmp/scratch/curl.conf"),
            None,
            "GET",
            "https://hub.example/v1/proxy/whoami",
            10,
        );
        assert!(args.iter().any(|arg| arg == "|HTTP:%{http_code}"));
        assert!(args.iter().any(|arg| arg == "-m"));
        assert!(args.iter().any(|arg| arg == "10"));
        assert!(args.iter().any(|arg| arg == "--config"));
    }

    #[test]
    fn a_post_sends_its_body_as_json() {
        let args = curl_args(
            Path::new("/tmp/scratch/curl.conf"),
            Some(Path::new("/tmp/scratch/body.json")),
            "POST",
            "https://hub.example/v1/proxy/register",
            15,
        );
        assert!(args.iter().any(|arg| arg == "POST"));
        assert!(args
            .iter()
            .any(|arg| arg == "Content-Type: application/json"));
        assert_eq!(
            args.last().map(String::as_str),
            Some("https://hub.example/v1/proxy/register")
        );
    }

    #[test]
    fn the_body_and_the_status_code_are_taken_apart() {
        let (body, status) = split_status("{\"status\":\"ok\"}|HTTP:200").expect("split");
        assert_eq!(body, "{\"status\":\"ok\"}");
        assert_eq!(status, 200);
    }

    #[test]
    fn a_body_with_the_marker_in_it_is_still_split_right() {
        let (body, status) = split_status("a|HTTP:b|HTTP:404").expect("split");
        assert_eq!(body, "a|HTTP:b");
        assert_eq!(status, 404);
    }

    #[test]
    fn an_answer_without_a_status_code_is_an_error() {
        assert!(split_status("no status here").is_err());
        assert!(split_status("|HTTP:abc").is_err());
    }

    #[test]
    fn the_hub_s_explanation_is_found_in_its_error_envelope() {
        let body =
            r#"{"error":{"message":"token is bound to node 'laptop'","type":"permission_error"}}"#;
        assert_eq!(error_message(body), "token is bound to node 'laptop'");
    }

    #[test]
    fn an_explanation_that_is_not_an_envelope_is_shown_as_it_arrived() {
        assert_eq!(error_message("plain trouble"), "plain trouble");
        assert_eq!(error_message("   "), "the hub sent no explanation");
    }

    #[test]
    fn a_very_long_explanation_is_cut_short() {
        let body = "x".repeat(1000);
        let message = error_message(&body);
        assert_eq!(message.chars().count(), 303);
        assert!(message.ends_with("..."));
    }

    #[test]
    fn the_bound_node_is_read_from_the_hub_s_answer() {
        let value =
            Json::parse(r#"{"authenticated":true,"bound_node":"laptop","registered":false}"#)
                .expect("parse");
        assert_eq!(bound_label(&value), Some("laptop".to_string()));
    }

    #[test]
    fn a_credential_that_is_not_bound_to_a_node_has_no_label() {
        let value = Json::parse(r#"{"authenticated":true,"bound_node":null,"registered":false}"#)
            .expect("parse");
        assert_eq!(bound_label(&value), None);
    }

    #[test]
    fn a_host_name_becomes_a_base_url() {
        assert_eq!(base_url("hub.example"), "https://hub.example/v1");
        assert_eq!(base_url("hub.example/"), "https://hub.example/v1");
        assert_eq!(base_url("  hub.example  "), "https://hub.example/v1");
    }

    #[test]
    fn a_base_url_is_left_alone() {
        assert_eq!(base_url("https://hub.example/v1"), "https://hub.example/v1");
        assert_eq!(base_url("https://hub.example"), "https://hub.example/v1");
        assert_eq!(base_url("http://hub.example/v1/"), "http://hub.example/v1");
    }

    #[test]
    fn no_address_at_all_is_an_empty_base() {
        assert_eq!(base_url(""), "");
        assert_eq!(base_url("   "), "");
    }

    #[test]
    fn the_node_ids_the_hub_accepts_are_recognised() {
        assert!(is_node_id("node-laptop"));
        assert!(is_node_id("node-laptop.local"));
        assert!(is_node_id("node-a_b-c"));
        assert!(!is_node_id("laptop"));
        assert!(!is_node_id("node-"));
        assert!(!is_node_id("node-laptop/../other"));
        assert!(!is_node_id("node-laptop space"));
        assert!(!is_node_id(&format!("node-{}", "a".repeat(129))));
    }

    #[test]
    fn the_hub_never_prints_its_token() {
        let hub = Hub::new("hub.example", "tok_secret");
        let text = format!("{hub:?}");
        assert!(!text.contains("tok_secret"), "{text}");
        assert!(text.contains("redacted"), "{text}");
    }
}

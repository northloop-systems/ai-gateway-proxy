//! The shapes that go over the wire.
//!
//! The node sends one thing - a registration - and reads two: the hub's
//! answer to it, and the list of nodes the hub knows about. They are kept
//! as plain structs with the reading of them next to them, so a change in
//! what the hub answers is a change in one file.

use crate::hub::json::{self, Json};

/// What the node sends when it registers.
///
/// The field names are the hub's, not ours: the gateway reads this body
/// with a model that forbids extra fields, so a field spelled differently
/// here is a 422 from the hub.
pub struct RegisterRequest {
    pub hostname: String,
    pub wireguard_public_key: String,
    pub version: String,
    pub public_ip: String,
    pub socks_user: String,
    pub socks_pass: String,
    /// The exits this node offers, as (name, port): ("tor", 9050),
    /// ("warp", 40000), ("direct", 1080). A node in WARP tunnel mode has no
    /// WARP exit of its own, so it offers two.
    pub ports: Vec<(String, i64)>,
    /// How the node uses WARP: "proxy" or "tunnel".
    ///
    /// The hub keeps it with the node because it is what says whose address
    /// the node's own traffic leaves on: in tunnel mode WARP carries the
    /// machine's traffic and its DNS, so the machine's address is a WARP
    /// address.
    pub warp_mode: String,
}

impl std::fmt::Debug for RegisterRequest {
    /// The SOCKS password is a secret, so it never appears in a dump.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterRequest")
            .field("hostname", &self.hostname)
            .field("wireguard_public_key", &self.wireguard_public_key)
            .field("version", &self.version)
            .field("public_ip", &self.public_ip)
            .field("socks_user", &self.socks_user)
            .field("socks_pass", &"[redacted]")
            .field("ports", &self.ports)
            .finish()
    }
}

impl RegisterRequest {
    /// The request body, in the shape the shell installer sent.
    ///
    /// The key order is the shell installer's, so the two produce the
    /// same bytes and a reader comparing them sees one body, not two.
    pub fn to_json(&self) -> Json {
        let ports = Json::Obj(
            self.ports
                .iter()
                .map(|(name, port)| (name.clone(), json::n(*port)))
                .collect(),
        );
        json::obj(vec![
            ("hostname", json::s(&self.hostname)),
            ("version", json::s(&self.version)),
            ("wireguard_public_key", json::s(&self.wireguard_public_key)),
            ("ports", ports),
            ("public_ip", json::s(&self.public_ip)),
            ("socks_user", json::s(&self.socks_user)),
            ("socks_pass", json::s(&self.socks_pass)),
            ("warp_mode", json::s(&self.warp_mode)),
        ])
    }
}

/// What the hub sends back.
#[derive(Debug, Clone)]
pub struct RegisterResponse {
    pub status: String,
    pub node_id: String,
    pub wireguard_ip: String,
    pub wireguard_gateway_public_key: String,
    pub wireguard_endpoint: String,
    pub message: String,
}

impl RegisterResponse {
    /// Read the hub's answer.
    ///
    /// A missing field is an error rather than an empty string: the hub
    /// is the authority on the node's WireGuard address and on the key to
    /// trust, and a node that goes on to configure its tunnel with a blank
    /// one fails later, further from the cause.
    pub fn from_json(value: &Json) -> Result<RegisterResponse, String> {
        Ok(RegisterResponse {
            status: text(value, "status")?,
            node_id: text(value, "node_id")?,
            wireguard_ip: safe(text(value, "wireguard_ip")?, "wireguard_ip")?,
            wireguard_gateway_public_key: safe(
                text(value, "wireguard_gateway_public_key")?,
                "wireguard_gateway_public_key",
            )?,
            wireguard_endpoint: safe(text(value, "wireguard_endpoint")?, "wireguard_endpoint")?,
            message: optional_text(value, "message"),
        })
    }
}

/// One node as the hub lists it.
///
/// The SOCKS password is NOT here: the hub leaves it out of the list, and
/// a node has no business reading another node's password.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub node_id: String,
    pub hostname: String,
    pub wireguard_ip: String,
    pub public_ip: String,
}

impl NodeInfo {
    /// Read one entry of the hub's list.
    pub fn from_json(value: &Json) -> Result<NodeInfo, String> {
        Ok(NodeInfo {
            node_id: text(value, "node_id")?,
            hostname: text(value, "hostname")?,
            wireguard_ip: text(value, "wireguard_ip")?,
            public_ip: optional_text(value, "public_ip"),
        })
    }
}

/// A field that has to be there, and has to be text.
fn text(value: &Json, key: &str) -> Result<String, String> {
    match value.get(key) {
        Some(Json::Str(text)) => Ok(text.clone()),
        Some(_) => Err(format!(
            "the hub's answer has '{key}', but it is not text - the hub is not the one this node expects"
        )),
        None => Err(format!(
            "the hub's answer has no '{key}' - the hub is not the one this node expects"
        )),
    }
}

/// A field that may be missing, and is not important if it is.
fn optional_text(value: &Json, key: &str) -> String {
    match value.get(key) {
        Some(Json::Str(text)) => text.clone(),
        _ => String::new(),
    }
}

/// A value that is going into a WireGuard config file.
///
/// A config file is line based, so a value carrying a line break could
/// add a line of its own - and the hub's address, key and endpoint are
/// all written into one. The shell installer checks the same thing for
/// the same reason ("validate server-supplied values (prevent config
/// injection)"). The check is about the characters and not about the
/// shape: a hub that numbers its nodes differently is still a hub.
fn safe(value: String, key: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("the hub's answer has an empty '{key}'"));
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "the hub's answer has a '{key}' with a space or a line break in it, and that cannot go into a WireGuard config"
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RegisterRequest {
        RegisterRequest {
            hostname: "laptop".to_string(),
            wireguard_public_key: "hJGNPBFrDxKp8CmuAixj0D5L9lJ0V4yJ0V4yJ0V4yJ0=".to_string(),
            version: "3.0".to_string(),
            public_ip: "203.0.113.7".to_string(),
            socks_user: "proxyuser".to_string(),
            socks_pass: "s3cr3tpassword".to_string(),
            ports: vec![
                ("tor".to_string(), 9050),
                ("warp".to_string(), 40000),
                ("direct".to_string(), 1080),
            ],
            warp_mode: "proxy".to_string(),
        }
    }

    #[test]
    fn the_request_body_is_the_one_the_shell_installer_sent() {
        let body = sample().to_json().write();
        assert_eq!(
            body,
            r#"{"hostname":"laptop","version":"3.0","wireguard_public_key":"hJGNPBFrDxKp8CmuAixj0D5L9lJ0V4yJ0V4yJ0V4yJ0=","ports":{"tor":9050,"warp":40000,"direct":1080},"public_ip":"203.0.113.7","socks_user":"proxyuser","socks_pass":"s3cr3tpassword","warp_mode":"proxy"}"#
        );
    }

    #[test]
    fn the_request_carries_the_warp_mode_the_hub_needs() {
        // The hub keeps it with the node, because it is what says whose
        // address the node's own traffic leaves on.
        let mut request = sample();
        request.warp_mode = "tunnel".to_string();
        let body = request.to_json().write();
        assert!(body.contains(r#""warp_mode":"tunnel""#), "{body}");
    }

    #[test]
    fn the_request_body_reads_back_as_it_was() {
        let request = sample();
        let value = request.to_json();
        assert_eq!(value.get("hostname").and_then(Json::as_str), Some("laptop"));
        assert_eq!(value.get("version").and_then(Json::as_str), Some("3.0"));
        assert_eq!(
            value.get("public_ip").and_then(Json::as_str),
            Some("203.0.113.7")
        );
        assert_eq!(
            value.get("socks_user").and_then(Json::as_str),
            Some("proxyuser")
        );
        let ports = value.get("ports").expect("ports");
        assert_eq!(ports.get("tor").and_then(Json::as_i64), Some(9050));
        assert_eq!(ports.get("warp").and_then(Json::as_i64), Some(40000));
        assert_eq!(ports.get("direct").and_then(Json::as_i64), Some(1080));
    }

    #[test]
    fn the_request_body_is_json_the_hub_can_read() {
        let text = sample().to_json().write();
        let value = Json::parse(&text).expect("the body should parse");
        assert_eq!(value.get("hostname").and_then(Json::as_str), Some("laptop"));
    }

    #[test]
    fn a_body_with_no_ports_is_still_a_body() {
        let mut request = sample();
        request.ports.clear();
        let text = request.to_json().write();
        assert!(text.contains(r#""ports":{}"#));
        assert!(Json::parse(&text).is_ok());
    }

    #[test]
    fn reads_the_hub_s_registration_answer() {
        let value = Json::parse(
            r#"{"status":"ok","node_id":"node-laptop","wireguard_ip":"10.200.0.2","wireguard_gateway_public_key":"key","wireguard_endpoint":"hub.example:51820","message":"WireGuard peer configured."}"#,
        )
        .expect("parse");
        let response = RegisterResponse::from_json(&value).expect("read");
        assert_eq!(response.status, "ok");
        assert_eq!(response.node_id, "node-laptop");
        assert_eq!(response.wireguard_ip, "10.200.0.2");
        assert_eq!(response.wireguard_gateway_public_key, "key");
        assert_eq!(response.wireguard_endpoint, "hub.example:51820");
        assert_eq!(response.message, "WireGuard peer configured.");
    }

    #[test]
    fn an_answer_without_the_address_is_an_error() {
        let value = Json::parse(r#"{"status":"ok","node_id":"node-laptop"}"#).expect("parse");
        let error = RegisterResponse::from_json(&value).expect_err("should fail");
        assert!(error.contains("wireguard_ip"), "{error}");
    }

    #[test]
    fn an_answer_that_would_break_a_config_is_an_error() {
        // A value with a line break in it could add a line of its own to
        // the WireGuard config the node is about to write.
        let value = Json::parse(
            "{\"status\":\"ok\",\"node_id\":\"node-laptop\",\"wireguard_ip\":\"10.200.0.2\",\"wireguard_gateway_public_key\":\"key\",\"wireguard_endpoint\":\"hub.example:51820\\n[Interface]\\nAddress = 10.0.0.1\"}",
        )
        .expect("parse");
        let error = RegisterResponse::from_json(&value).expect_err("should fail");
        assert!(error.contains("wireguard_endpoint"), "{error}");
    }

    #[test]
    fn an_empty_address_is_an_error() {
        let value = Json::parse(
            r#"{"status":"ok","node_id":"node-laptop","wireguard_ip":"","wireguard_gateway_public_key":"key","wireguard_endpoint":"hub.example:51820"}"#,
        )
        .expect("parse");
        let error = RegisterResponse::from_json(&value).expect_err("should fail");
        assert!(error.contains("wireguard_ip"), "{error}");
    }

    #[test]
    fn reads_one_node_of_the_hub_s_list() {
        let value = Json::parse(
            r#"{"node_id":"node-laptop","hostname":"laptop","wireguard_ip":"10.200.0.2","public_ip":"203.0.113.7","ports":{"tor":9050},"socks_user":"proxyuser"}"#,
        )
        .expect("parse");
        let node = NodeInfo::from_json(&value).expect("read");
        assert_eq!(node.node_id, "node-laptop");
        assert_eq!(node.hostname, "laptop");
        assert_eq!(node.wireguard_ip, "10.200.0.2");
        assert_eq!(node.public_ip, "203.0.113.7");
    }

    #[test]
    fn a_node_without_a_public_ip_is_still_a_node() {
        let value = Json::parse(
            r#"{"node_id":"node-laptop","hostname":"laptop","wireguard_ip":"10.200.0.2","public_ip":null}"#,
        )
        .expect("parse");
        let node = NodeInfo::from_json(&value).expect("read");
        assert_eq!(node.public_ip, "");
    }
}

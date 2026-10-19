//! The proxy server: take a client, find out who it is, authenticate it,
//! and relay it to a destination the filter allows.
//!
//! This is the node's security boundary. The hub opens connections *through*
//! the node, so what this program is willing to forward is what the gateway
//! can reach, and the node is a machine that belongs to somebody else. The
//! rules are the ones from the Python proxy it replaces:
//!
//! - only the hub's address may connect at all
//! - a username and password are required, every time
//! - only port 443, and only to addresses that are global
//!
//! A client that misbehaves costs it its own connection and nothing else:
//! every failure ends that connection quietly and the server carries on.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::log;

use super::auth;
use super::filter;

/// How long a client has to finish the handshake. The Python proxy gave a
/// client thirty seconds and then dropped it, which is what keeps a
/// connection that never says anything from holding a slot for ever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the connection to the destination may take to come up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How many clients may be in flight at once. Past this the node is busy
/// enough, and the extra connections are dropped rather than queued.
const MAX_CLIENTS: usize = 128;

/// How much is copied at a time.
const BUFFER_SIZE: usize = 16 * 1024;

/// SOCKS5 reply codes (RFC 1928).
const SUCCEEDED: u8 = 0x00;
const NOT_ALLOWED: u8 = 0x02;
const CONNECTION_FAILED: u8 = 0x05;

/// What the proxy needs to know to run.
#[derive(Clone)]
pub struct Config {
    pub listen_addr: String,
    pub listen_port: u16,
    pub username: String,
    pub password: String,
    pub hub_ip: String,
}

/// Run the proxy until it is stopped.
pub fn serve(config: Config) -> Result<(), String> {
    // A hub address that cannot be parsed would silently let everybody in,
    // so it is a reason not to start.
    let hub_ip: IpAddr = config
        .hub_ip
        .parse()
        .map_err(|_| format!("hub-ip is not an address: {}", config.hub_ip))?;
    let address = format!("{}:{}", config.listen_addr, config.listen_port);
    let listener =
        TcpListener::bind(&address).map_err(|e| format!("could not listen on {address}: {e}"))?;

    log::step(&format!(
        "socks5 listening on {address}, only {hub_ip} may use it"
    ));
    if config.password.is_empty() {
        log::warn("the socks5 proxy has no password; anyone who reaches the port can use it");
    }

    let config = Arc::new(config);
    let clients = Arc::new(AtomicUsize::new(0));

    for incoming in listener.incoming() {
        let client = match incoming {
            Ok(client) => client,
            // A failed accept is not a reason to stop serving.
            Err(_) => continue,
        };
        // The source is checked before a slot is taken: a connection from
        // anywhere else must not be able to fill the node's capacity.
        if !from_hub(client.peer_addr().ok(), hub_ip) {
            continue;
        }
        if clients.load(Ordering::SeqCst) >= MAX_CLIENTS {
            continue;
        }
        clients.fetch_add(1, Ordering::SeqCst);
        let config = Arc::clone(&config);
        let clients = Arc::clone(&clients);
        thread::spawn(move || {
            let _slot = Slot(clients);
            handle_client(client, &config);
        });
    }
    Ok(())
}

/// Gives the client's slot back when it is done, however it ends.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Only the hub may use the proxy. It is the one that opens connections
/// through the node, and nobody else has any business here.
fn from_hub(peer: Option<SocketAddr>, hub: IpAddr) -> bool {
    match peer {
        Some(peer) => peer.ip() == hub,
        None => false,
    }
}

/// One client, from the greeting to the end of the tunnel.
fn handle_client(mut client: TcpStream, config: &Config) {
    let _ = client.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = client.set_write_timeout(Some(HANDSHAKE_TIMEOUT));

    if !authenticate(&mut client, &config.username, &config.password) {
        return;
    }
    let request = match read_request(&mut client) {
        Some(request) => request,
        None => return,
    };

    let targets = filter::allowed_targets(&request.host, request.port);
    let target = match targets.first() {
        Some(target) => *target,
        None => {
            reply(&mut client, NOT_ALLOWED);
            return;
        }
    };

    // The connection is made to the address that was checked, not to the
    // name that was asked for: a name that answers twice is not a name that
    // gets to choose where the traffic goes.
    let remote =
        match TcpStream::connect_timeout(&SocketAddr::new(target, request.port), CONNECT_TIMEOUT) {
            Ok(remote) => remote,
            Err(_) => {
                reply(&mut client, CONNECTION_FAILED);
                return;
            }
        };

    reply(&mut client, SUCCEEDED);
    // The handshake is over. An idle tunnel must not be torn down by a
    // timeout, or the hub's pooled connections would rot under it.
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    relay(client, remote);
}

/// The greeting and the RFC 1929 exchange. Username and password are the
/// only methods on offer, and a client that did not offer them gets
/// nothing.
fn authenticate(client: &mut TcpStream, username: &str, password: &str) -> bool {
    if read_u8(client) != Some(5) {
        return false;
    }
    let count = match read_u8(client) {
        Some(count) => count as usize,
        None => return false,
    };
    let methods = match read_bytes(client, count) {
        Some(methods) => methods,
        None => return false,
    };
    if !methods.contains(&0x02) {
        // The client did not offer username and password, and nothing else
        // is on offer, so there is nothing to negotiate.
        let _ = client.write_all(&[0x05, 0xff]);
        return false;
    }
    let _ = client.write_all(&[0x05, 0x02]);

    if read_u8(client) != Some(1) {
        return false;
    }
    let user_len = match read_u8(client) {
        Some(len) => len as usize,
        None => return false,
    };
    let offered_user = match read_bytes(client, user_len) {
        Some(user) => user,
        None => return false,
    };
    let pass_len = match read_u8(client) {
        Some(len) => len as usize,
        None => return false,
    };
    let offered_pass = match read_bytes(client, pass_len) {
        Some(pass) => pass,
        None => return false,
    };

    if !auth::check(username, password, &offered_user, &offered_pass) {
        let _ = client.write_all(&[0x01, 0x01]);
        return false;
    }
    let _ = client.write_all(&[0x01, 0x00]);
    true
}

/// Where the client wants to go.
struct Request {
    host: String,
    port: u16,
}

/// A CONNECT request. Anything else - a command that is not CONNECT, an
/// address type that does not exist - is a client that is talking nonsense,
/// and it is dropped.
fn read_request(client: &mut TcpStream) -> Option<Request> {
    let head = read_bytes(client, 4)?;
    if head[0] != 5 || head[1] != 1 {
        return None;
    }
    let host = match head[3] {
        1 => {
            let bytes = read_bytes(client, 4)?;
            Ipv4Addr::from([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string()
        }
        3 => {
            let length = read_u8(client)? as usize;
            let bytes = read_bytes(client, length)?;
            String::from_utf8(bytes).ok()?
        }
        4 => {
            let bytes = read_bytes(client, 16)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes);
            Ipv6Addr::from(octets).to_string()
        }
        _ => return None,
    };
    let port_bytes = read_bytes(client, 2)?;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    Some(Request { host, port })
}

/// The SOCKS5 reply. The bound address is always 0.0.0.0:0, like the
/// Python proxy: the client asked for a tunnel, not for the node's address.
fn reply(client: &mut TcpStream, code: u8) {
    let mut message = [0u8; 10];
    message[0] = 0x05;
    message[1] = code;
    message[3] = 0x01;
    let _ = client.write_all(&message);
}

/// Copy bytes both ways until one side is done.
///
/// One thread per direction: the standard library has no poll(2), and a
/// polling loop would put a delay in front of every byte the hub is waiting
/// for.
fn relay(client: TcpStream, remote: TcpStream) {
    let mut client_read = match client.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let mut remote_read = match remote.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let mut client_write = client;
    let mut remote_write = remote;

    let forward = thread::spawn(move || {
        copy(&mut client_read, &mut remote_write);
        // The client is done, so the pair comes down: the other direction
        // stops rather than waiting on a peer that may never speak again.
        let _ = remote_write.shutdown(Shutdown::Both);
        let _ = client_read.shutdown(Shutdown::Both);
    });

    copy(&mut remote_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Both);
    let _ = remote_read.shutdown(Shutdown::Both);
    let _ = forward.join();
}

/// Copy until the source is done or broken.
fn copy(from: &mut TcpStream, to: &mut TcpStream) {
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        match from.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if to.write_all(&buffer[..count]).is_err() {
                    break;
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// Read exactly this many bytes, or nothing at all.
fn read_bytes(client: &mut TcpStream, count: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; count];
    client.read_exact(&mut buffer).ok()?;
    Some(buffer)
}

/// Read one byte.
fn read_u8(client: &mut TcpStream) -> Option<u8> {
    let mut byte = [0u8; 1];
    client.read_exact(&mut byte).ok()?;
    Some(byte[0])
}

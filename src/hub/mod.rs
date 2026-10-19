//! The hub: the gateway this node registers with.
//!
//! Three things live here. `json` is the little JSON reader and writer
//! the hub's answers go through. `types` are the shapes that go over the
//! wire, with the reading of them next to them. `client` is the client
//! that makes the calls - with curl, because a TLS stack of our own is
//! the one dependency tree this program cannot justify.
//!
//! The calls that matter are three: who the token is bound to, the
//! registration itself, and the revocation that takes the node back off
//! the hub.

pub mod client;
pub mod json;
pub mod types;

// The short paths, so a caller can write `hub::Hub` or
// `hub::client::Hub` - whichever it reaches for first. A binary crate has
// no outside to publish to, so a re-export nobody has used yet looks
// unused to the compiler; that is not worth breaking an import over.
#[allow(unused_imports)]
pub use client::Hub;
#[allow(unused_imports)]
pub use types::{NodeInfo, RegisterRequest, RegisterResponse};

//! xngin-rs: SDK for building XNAP agents (see SPEC.md v1).
//!
//! An agent accepts multiplexed XNAP connections from nginx workers and
//! returns a [`Verdict`] for each request [`Request`].

pub mod tls;
pub mod proto;
pub mod server;

pub use proto::*;
pub use server::*;

#[cfg(test)]
#[path = "proto_tests.rs"]
mod proto_tests;

#[cfg(test)]
#[path = "conformance_tests.rs"]
mod conformance_tests;

#[cfg(test)]
#[path = "server_tests.rs"]
mod server_tests;

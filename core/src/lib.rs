//! `nft-gate-core`: the one implementation of what an nft-gate gateway decides and does.
//!
//! Everything platform-neutral lives here, once: the access-proof wire format ([`proof`]), Sui
//! signature verification ([`sig`]), the allow/deny decision ([`decision`]), the gRPC-web codec and Sui
//! chain reads behind a [`grpc::Transport`] ([`grpc`], [`chain`]), the nonce / rate / redemption state
//! machines ([`redemption`], [`state`]), header, path, origin and CORS policy ([`headers`],
//! [`origin`], [`forward`], [`net`]), configuration parsing and validation behind an [`config::Env`]
//! ([`config`]), and the request orchestration itself ([`gateway`]) as a state machine over ports
//! ([`state::StateStore`], [`decision::ChainQuery`], [`gateway::Upstream`], [`state::Clock`],
//! [`state::Rng`]).
//!
//! A platform is an adapter that supplies I/O only: `gateway-rust` (hyper/axum/tokio, Redis) and the
//! Cloudflare Worker (workers-rs: `fetch`, Durable Objects). The crate has no hyper, no tokio, no clock,
//! no RNG and no logging, so it compiles natively and for `wasm32-unknown-unknown`.
#![forbid(unsafe_code)]

pub mod chain;
pub mod config;
pub mod decision;
pub mod forward;
pub mod gateway;
pub mod grpc;
pub mod headers;
pub mod net;
pub mod origin;
pub mod proof;
pub mod quota;
pub mod redemption;
pub mod sig;
pub mod state;
#[cfg(test)]
#[allow(dead_code)]
mod testkit;

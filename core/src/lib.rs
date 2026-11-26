//! `access-gate-gateway-core`: the one implementation of what an access-gate gateway decides and does.
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
// A `str` slice by byte index panics inside a multi-byte character: use `get` (audit F58, the class the `grpc` fuzz target found).
#![cfg_attr(not(test), deny(clippy::string_slice))]

/// Sui chain reads over gRPC: ownership of a pass, the gate pause flag, and consume transactions.
pub mod chain;
/// Configuration parsing and validation, read through the `Env` trait.
pub mod config;
/// The allow/deny decision for one proof, generic over the chain and the nonce store.
pub mod decision;
/// Which requests may be forwarded, and how a failed forward is answered.
pub mod forward;
/// The request pipeline: loop guard, challenge, public paths, proof, verification, rate limits and forwarding.
pub mod gateway;
/// A minimal gRPC-web client and protobuf reader/writer, over a platform `Transport`.
pub mod grpc;
/// Header policy as lists and predicates, with no HTTP library.
pub mod headers;
/// Client identity for rate limiting (a key, never an authenticator).
pub mod net;
/// Canonical origin checks, and origin comparison for the request-loop guard.
pub mod origin;
/// The access-proof wire format and its signed message.
pub mod proof;
/// The Workers quota guard: plan allowances, the usage window and the verdict.
pub mod quota;
/// Single-use redemption as a pure state machine over an explicit clock.
pub mod redemption;
/// Sui personal-message signature verification and address helpers.
pub mod sig;
/// The state ports (nonces, rate budgets, redemptions) and their in-memory implementation.
pub mod state;
/// Protobuf builders shared by this crate's tests (compiled only for tests).
#[cfg(test)]
#[allow(dead_code)]
mod testkit;

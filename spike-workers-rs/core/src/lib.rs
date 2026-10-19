//! `nft-gate-core`: the pure decision logic of the nft-gate gateway — proof decoding, the signed
//! message, Sui signature verification, address normalisation, the allow/deny decision, the gRPC-web
//! codec + Sui chain queries (behind a [`grpc::Transport`] trait), redemption/nonce/rate semantics,
//! and the header policy. No hyper, no tokio, no clock, no RNG, no logging: it compiles for the
//! native axum gateway and for `wasm32-unknown-unknown` (Cloudflare Workers).
#![forbid(unsafe_code)]

pub mod chain;
pub mod decision;
pub mod grpc;
pub mod headers;
pub mod origin;
pub mod proof;
pub mod redemption;
pub mod sig;
#[cfg(test)]
#[allow(dead_code)]
mod testkit;

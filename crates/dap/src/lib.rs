//! A (partial) DAP implementation, sufficient to implement Unrealscript debugging.
//!
//! See: <https://microsoft.github.io/debug-adapter-protocol/overview>
//!
//! This crate implements only a subset of DAP. Not all requests are modeled, because Unrealscript
//! doesn't support them (e.g. it has no support for data breakpoints, moving the execution point,
//! etc). These request kinds are controlled by the capabilities advertised by the adapter when
//! connecting to the client, so editors should not send these requests to adapters that don't
//! claim to support them.
//!
//! Many fields in the DAP requests, responses, events, and types are optional, and this
//! implemetation excludes many optional fields that we don't support, relying on the default
//! serde behavior of skipping unknown fields during deserialization.
//!
//! In some cases optional fields in the response or event messages or in types exclusive to
//! those messages are modeled as required when we always want to include them for the purposes
//! of this implementation.
#![warn(missing_docs)]

pub mod events;
pub mod requests;
pub mod responses;
pub mod types;

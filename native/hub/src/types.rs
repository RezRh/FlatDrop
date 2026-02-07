//! Generated Protobuf Types for FlatDrop
//!
//! These types are generated from proto/messages.proto
//! Do not edit manually - run `cargo build` to regenerate

pub mod messages {
    include!(concat!(env!("OUT_DIR"), "/flatdrop.rs"));
}

// Re-export all generated types for convenience
pub use messages::*;

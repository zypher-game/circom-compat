//! Arkworks - Circom Compatibility layer
//!
//! Provides bindings to Circom's R1CS, for Groth16 Proof and Witness generation in Rust.
mod witness;
pub use witness::{Wasm, WitnessCalculator};

pub mod circom;
pub use circom::{CircomBuilder, CircomCircuit, CircomConfig, CircomReduction};

#[cfg(feature = "ethereum")]
pub mod ethereum;

pub mod zkey_bn254;
pub mod zkey_bls12_381;

pub mod zkp;

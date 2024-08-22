//! Arkworks - Circom Compatibility layer
//!
//! Provides bindings to Circom's R1CS, for Groth16 Proof and Witness generation in Rust.
mod witness;
pub use witness::{Wasm, WitnessCalculator};

pub mod circom;
pub use circom::{CircomBuilder, CircomCircuit, CircomConfig, CircomReduction};

#[cfg(feature = "ethereum")]
pub mod ethereum;

mod zkey;
pub use zkey::{read_bn254_zkey, read_bls12_381_zkey};

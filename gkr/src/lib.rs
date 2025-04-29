#![cfg_attr(target_arch = "x86_64", feature(stdarch_x86_avx512))]

pub mod prover;
pub use prover::*;

pub mod verifier;
pub use verifier::*;

pub mod utils;

pub mod executor;

pub mod gkr_configs;
pub use gkr_configs::*;

pub mod twine_verifier;
pub use twine_verifier::*;

pub mod verification_proto {
    tonic::include_proto!("verification");
}

#[cfg(test)]
mod tests;

#[cfg(feature = "grinding")]
const GRINDING_BITS: usize = 10;

use std::{
    fs,
    io::Cursor,
    process::exit,
    sync::{Arc, Mutex},
};

use arith::Field;
use circuit::Circuit;
use clap::{Parser, Subcommand};
use gkr_engine::{
    root_println, BN254Config, BabyBearExtConfig, FieldEngine, FieldType, GF2ExtConfig, GKREngine,
    GKRScheme, GoldilocksExtConfig, M31ExtConfig, MPIConfig, MPIEngine, SharedMemory,
};
use gkr_hashers::{Keccak256hasher, MiMC5FiatShamirHasher, PoseidonFiatShamirHasher, SHA256hasher};
use log::info;
use poly_commit::{
    expander_pcs_init_testing_only, HyperKZGPCS, HyraxPCS, OrionPCSForGKR, RawExpanderGKR,
};
use serdes::{ExpSerde, SerdeError};
use config_macros::declare_gkr_config;
use warp::{http::StatusCode, reply, Filter};
use gkr::{executor::load_proof_and_claimed_v, Verifier};
use transcript::{BytesHashTranscript, FieldHashTranscript};
use mersenne31::M31x16;
fn verify_bls<Cfg: GKREngine + 'static>() {

    // Initialize MPI with size 8
    let mpi_config = MPIConfig::verifier_new(8);
    let verifier = Verifier::<Cfg>::new(mpi_config);

    println!("loading circuit file");
    let mut circuit = Circuit::<Cfg::FieldConfig>::verifier_load_circuit::<Cfg>(
        "/home/user/ExpanderCompilerCollection/efc/circuit_blsverifier.txt"
    );

    println!("loading witness file");
    circuit.verifier_load_witness_file(
        "/home/user/ExpanderCompilerCollection/efc/witnesses/290001/blsverifier/witness_0.txt",
        &verifier.mpi_config,
    );

    println!("loading proof file");
    let bytes = fs::read("./test_bls_proof0_new").expect("Unable to read proof from file.");
    let (proof, claimed_v) = load_proof_and_claimed_v::<
                <Cfg::FieldConfig as FieldEngine>::ChallengeField,
            >(&bytes)
            .expect("Unable to deserialize proof.");

    println!("verifying proof");

    // Initialize PCS parameters
    let (pcs_params, _, pcs_verification_key, _) = expander_pcs_init_testing_only::<Cfg::FieldConfig, Cfg::PCSConfig>(
        circuit.log_input_size(),
        &verifier.mpi_config,
    );

    let public_input = circuit.public_input.clone();
    let result = verifier.verify(
        &mut circuit,
        &public_input,
        &claimed_v,
        &pcs_params,
        &pcs_verification_key,
        &proof,
    );

    if result {
        println!("success");
    } else {
        println!("verification failed");
    }
}

fn main() {
    // Configure GKR with the specified parameters
    declare_gkr_config!(
        BLSConfig,
        FieldType::M31,
        FiatShamirHashType::SHA256,
        PolynomialCommitmentType::Orion,
        GKRScheme::Vanilla,
    );
    verify_bls::<BLSConfig>();
}

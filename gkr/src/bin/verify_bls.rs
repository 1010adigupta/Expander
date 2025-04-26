use std::{
    fs,
    sync::{Arc, Mutex},
};

use circuit::Circuit;
use gkr_engine::{
    BN254Config, ExpanderPCS, FieldEngine, FieldType, GF2ExtConfig, GKREngine, GKRScheme, GoldilocksExtConfig, M31ExtConfig, MPIConfig, MPIEngine, SharedMemory, StructuredReferenceString
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
    let mut circuit = Circuit::<<Cfg>::FieldConfig>::verifier_load_circuit::<Cfg>(
        "./circuit_blsverifier.txt"
    );

    println!("loading witness file");
    circuit.verifier_load_witness_file(
        "./witnesses/290001/blsverifier/witness_0.txt",
        &verifier.mpi_config,
    );

    println!("loading proof file");
    let bytes = fs::read("./test_bls_proof0").expect("Unable to read proof from file.");
    let (proof, claimed_v) = load_proof_and_claimed_v::<
                <<Cfg>::FieldConfig as FieldEngine>::ChallengeField,
            >(&bytes)
            .expect("Unable to deserialize proof.");

    println!("verifying proof");

    // Initialize PCS parameters
    let (pcs_params, _, pcs_verification_key, _) = expander_pcs_init_testing_only::<<Cfg>::FieldConfig, <Cfg>::PCSConfig>(
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

pub struct VerificationData<Cfg: GKREngine + 'static> {
    public_input: Vec<<Cfg::FieldConfig as FieldEngine>::SimdCircuitField>,
    pcs_params: <Cfg::PCSConfig as ExpanderPCS<Cfg::FieldConfig>>::Params,
    pcs_verification_key: <<Cfg::PCSConfig as ExpanderPCS<Cfg::FieldConfig>>::SRS as StructuredReferenceString>::VKey,
    proof_bytes: Vec<u8>,
}
fn prepare_verification_data<Cfg: GKREngine + 'static>() -> VerificationData<Cfg> {
    // Initialize MPI with size 8
    let mpi_config = MPIConfig::verifier_new(8);
    let verifier = Verifier::<Cfg>::new(mpi_config);
    println!("loading circuit file");
    let mut circuit = Circuit::<<Cfg>::FieldConfig>::verifier_load_circuit::<Cfg>(
        "./circuit_blsverifier.txt"
    );

    println!("loading witness file");
    circuit.verifier_load_witness_file(
        "./witnesses/290001/blsverifier/witness_0.txt",
        &verifier.mpi_config,
    );

    println!("loading proof file");
    let proof_bytes = fs::read("./test_bls_proof0").expect("Unable to read proof from file.");
    // Initialize PCS parameters
    let (pcs_params, _, pcs_verification_key, _) = expander_pcs_init_testing_only::<<Cfg>::FieldConfig, <Cfg>::PCSConfig>(
        circuit.log_input_size(),
        &verifier.mpi_config,
    );
    let public_input = circuit.public_input.clone();

    VerificationData {
        public_input,
        pcs_params,
        pcs_verification_key,
        proof_bytes,
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
    let verification_data = prepare_verification_data::<BLSConfig>();
    verify_bls::<BLSConfig>();
}

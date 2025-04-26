use std::{fs, time::Duration, process};

use circuit::Circuit;
use gkr_engine::{
    FieldEngine, GKREngine,
    GKRScheme, M31ExtConfig, MPIConfig, MPIEngine,
};
use gkr_hashers::SHA256hasher;
use poly_commit::{
    expander_pcs_init_testing_only, OrionPCSForGKR,
};
use config_macros::declare_gkr_config;
use warp::{http::StatusCode, reply, Filter, Rejection, Reply};
use gkr::{executor::load_proof_and_claimed_v, Verifier};
use transcript::BytesHashTranscript;
use mersenne31::M31x16;
use tokio::{fs::File, io::AsyncWriteExt};
use futures_util::StreamExt;
use bytes::Buf;
use tokio_util::io::ReaderStream;

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
    let bytes = fs::read("./received_proof.bin").expect("Unable to read proof from file.");
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

fn verify_bls_in_different_server<Cfg: GKREngine + 'static>(proof_bytes_path: &str) {
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
    let bytes = fs::read(proof_bytes_path).expect("Unable to read proof from file.");
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

async fn handle_upload(mut file: warp::filters::multipart::Part) -> Result<impl Reply, Rejection> {
    println!("Receiving file upload...");
    let new_path = "./received_proof.bin";
    let mut dest = File::create(new_path).await.unwrap();
    let mut total_bytes = 0;
    
    while let Some(chunk) = file.data().await {
        let chunk = chunk.unwrap();
        let chunk_data = chunk.chunk();
        total_bytes += chunk_data.len();
        println!("Received chunk of {} bytes, total: {} bytes", chunk_data.len(), total_bytes);
        dest.write_all(chunk_data).await.unwrap();
    }
    
    println!("File received and saved to {} ({} bytes)", new_path, total_bytes);
    
    // Call verify function with the new path
    tokio::task::spawn_blocking(move || {
        println!("Starting verification...");
        declare_gkr_config!(
            BLSConfig,
            FieldType::M31,
            FiatShamirHashType::SHA256,
            PolynomialCommitmentType::Orion,
            GKRScheme::Vanilla,
        );
        verify_bls_in_different_server::<BLSConfig>(new_path);
        // Exit the process after verification
        process::exit(0);
    });
    
    Ok(reply::with_status(format!("File uploaded ({} bytes) and verification started", total_bytes), StatusCode::OK))
}

async fn start_receiver_server() {
    let upload_route = warp::path("upload")
        .and(warp::multipart::form().max_length(100 * 1024 * 1024)) // 100MB max
        .and_then(|mut form: warp::multipart::FormData| async move {
            println!("Processing multipart form...");
            while let Some(part) = form.next().await {
                match part {
                    Ok(part) => {
                        if part.name() == "file" {
                            println!("Found file part: {}", part.filename().unwrap_or("unnamed"));
                            return Ok(part);
                        }
                    },
                    Err(_) => {
                        println!("Error processing multipart form");
                        return Err(warp::reject::not_found());
                    }
                }
            }
            println!("No file part found in form");
            Err(warp::reject::not_found())
        })
        .and_then(handle_upload);

    println!("Starting receiver server on port 3030...");
    warp::serve(upload_route)
        .run(([127, 0, 0, 1], 3030))
        .await;
}

async fn send_file() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;
        
    let file_path = "/home/user/Expander/gkr/test_bls_proof0_new";
    println!("Reading file from {}", file_path);
    
    // Create a file stream
    let file = File::open(file_path).await?;
    let file_size = file.metadata().await?.len();
    println!("File size: {} bytes", file_size);
    
    let stream = reqwest::Body::wrap_stream(
        ReaderStream::new(file)
    );
    
    let form = reqwest::multipart::Form::new()
        .part("file", reqwest::multipart::Part::stream_with_length(stream, file_size)
            .file_name("proof.bin")
            .mime_str("application/octet-stream")?);
    
    println!("Sending file to server...");
    let response = client
        .post("http://127.0.0.1:3030/upload")
        .multipart(form)
        .send()
        .await?;
        
    println!("Server response status: {}", response.status());
    if response.status().is_success() {
        println!("File sent successfully");
        println!("Server response: {}", response.text().await?);
    } else {
        println!("Failed to send file: {}", response.status());
        println!("Error response: {}", response.text().await?);
    }
    
    Ok(())
}

#[tokio::main]
async fn main() {
    // Start receiver server in a background task
    let receiver = tokio::spawn(start_receiver_server());
    
    // Wait a moment for the server to start
    println!("Waiting for server to start...");
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    // Send the file
    println!("Starting file transfer...");
    if let Err(e) = send_file().await {
        eprintln!("Error sending file: {}", e);
    }
    
    // Keep the program running
    receiver.await.unwrap();
}

// fn main() {
//     // Configure GKR with the specified parameters
//     declare_gkr_config!(
//         BLSConfig,
//         FieldType::M31,
//         FiatShamirHashType::SHA256,
//         PolynomialCommitmentType::Orion,
//         GKRScheme::Vanilla,
//     );
//     verify_bls::<BLSConfig>();
// }
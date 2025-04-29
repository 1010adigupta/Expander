use std::{fs, time::Duration, net::SocketAddr, process};

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
use crate::{executor::load_proof_and_claimed_v, Verifier};
use transcript::BytesHashTranscript;
use mersenne31::M31x16;
use tokio::{fs::File, io::AsyncWriteExt};
use futures_util::StreamExt;
use bytes::Buf;
use tokio_util::io::ReaderStream;

pub fn verify_bls<Cfg: GKREngine + 'static>() {
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
    let bytes = fs::read("/home/user/Expander/gkr/test_bls_proof0_new").expect("Unable to read proof from file.");
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

// fn verify_bls_in_different_server<Cfg: GKREngine + 'static>(proof_bytes_path: &str) {
//     // Initialize MPI with size 8
//     let mpi_config = MPIConfig::verifier_new(8);
//     let verifier = Verifier::<Cfg>::new(mpi_config);

//     println!("loading circuit file");
//     let mut circuit = Circuit::<Cfg::FieldConfig>::verifier_load_circuit::<Cfg>(
//         "/home/user/ExpanderCompilerCollection/efc/circuit_blsverifier.txt"
//     );

//     println!("loading witness file");
//     circuit.verifier_load_witness_file(
//         "/home/user/ExpanderCompilerCollection/efc/witnesses/290001/blsverifier/witness_0.txt",
//         &verifier.mpi_config,
//     );

//     println!("loading proof file");
//     let bytes = fs::read(proof_bytes_path).expect("Unable to read proof from file.");
//     let (proof, claimed_v) = load_proof_and_claimed_v::<
//                 <Cfg::FieldConfig as FieldEngine>::ChallengeField,
//             >(&bytes)
//             .expect("Unable to deserialize proof.");

//     println!("verifying proof");

//     // Initialize PCS parameters
//     let (pcs_params, _, pcs_verification_key, _) = expander_pcs_init_testing_only::<Cfg::FieldConfig, Cfg::PCSConfig>(
//         circuit.log_input_size(),
//         &verifier.mpi_config,
//     );

//     let public_input = circuit.public_input.clone();
//     let result = verifier.verify(
//         &mut circuit,
//         &public_input,
//         &claimed_v,
//         &pcs_params,
//         &pcs_verification_key,
//         &proof,
//     );

//     if result {
//         println!("success");
//     } else {
//         println!("verification failed");
//     }
// }

// async fn send_file(index: usize) -> Result<(), Box<dyn std::error::Error>> {
//     let client = reqwest::Client::builder()
//         .timeout(Duration::from_secs(60))
//         .build()?;
        
//     let file_path = "/home/user/Expander/gkr/test_bls_proof0_new";
//     println!("Reading file from {}", file_path);
    
//     // Create a file stream
//     let file = File::open(file_path).await?;
//     let file_size = file.metadata().await?.len();
//     println!("File size: {} bytes", file_size);
    
//     let stream = reqwest::Body::wrap_stream(
//         ReaderStream::new(file)
//     );
    
//     let form = reqwest::multipart::Form::new()
//         .part("file", reqwest::multipart::Part::stream_with_length(stream, file_size)
//             .file_name(format!("proof{}.bin", index))
//             .mime_str("application/octet-stream")?);
    
//     println!("Sending file {} to server...", index);
//     let response = client
//         .post(format!("http://127.0.0.1:{}/upload", 3030 + index))
//         .multipart(form)
//         .send()
//         .await?;
        
//     println!("Server {} response status: {}", index, response.status());
//     if response.status().is_success() {
//         println!("File {} sent successfully", index);
//         println!("Server {} response: {}", index, response.text().await?);
//     } else {
//         println!("Failed to send file {}: {}", index, response.status());
//         println!("Error response: {}", response.text().await?);
//     }
    
//     Ok(())
// }

// async fn handle_upload(mut file: warp::filters::multipart::Part, index: usize) -> Result<impl Reply, Rejection> {
//     println!("Receiving file upload for server {}...", index);
//     let new_path = format!("./received_proof{}.bin", index);
//     let mut dest = File::create(&new_path).await.unwrap();
//     let mut total_bytes = 0;
    
//     while let Some(chunk) = file.data().await {
//         let chunk = chunk.unwrap();
//         let chunk_data = chunk.chunk();
//         total_bytes += chunk_data.len();
//         println!("Server {} received chunk of {} bytes, total: {} bytes", index, chunk_data.len(), total_bytes);
//         dest.write_all(chunk_data).await.unwrap();
//     }
    
//     println!("File received and saved to {} ({} bytes)", new_path, total_bytes);
    
//     // Call verify function with the new path
//     tokio::task::spawn_blocking(move || {
//         println!("Starting verification for server {}...", index);
//         declare_gkr_config!(
//             BLSConfig,
//             FieldType::M31,
//             FiatShamirHashType::SHA256,
//             PolynomialCommitmentType::Orion,
//             GKRScheme::Vanilla,
//         );
//         verify_bls_in_different_server::<BLSConfig>(&new_path);
//         println!("Server {} verification completed", index);
//     });
    
//     Ok(reply::with_status(format!("File uploaded ({} bytes) and verification started for server {}", total_bytes, index), StatusCode::OK))
// }

// async fn start_receiver_server(index: usize) {
//     let upload_route = warp::path("upload")
//         .and(warp::multipart::form().max_length(100 * 1024 * 1024)) // 100MB max
//         .and_then(move |mut form: warp::multipart::FormData| async move {
//             println!("Processing multipart form for server {}...", index);
//             while let Some(part) = form.next().await {
//                 match part {
//                     Ok(part) => {
//                         if part.name() == "file" {
//                             println!("Server {} found file part: {}", index, part.filename().unwrap_or("unnamed"));
//                             return Ok((part, index));
//                         }
//                     },
//                     Err(_) => {
//                         println!("Error processing multipart form for server {}", index);
//                         return Err(warp::reject::not_found());
//                     }
//                 }
//             }
//             println!("No file part found in form for server {}", index);
//             Err(warp::reject::not_found())
//         })
//         .and_then(|(part, idx)| handle_upload(part, idx));

//     println!("Starting receiver server {} on port {}...", index, 3030 + index);
//     let addr: SocketAddr = ([127, 0, 0, 1], (3030 + index) as u16).into();
//     warp::serve(upload_route)
//         .run(addr)
//         .await;
// }

// #[tokio::main]
// async fn main() {
//     let start_time = std::time::Instant::now();
    
//     // Start 8 receiver servers in background tasks
//     let mut receivers = vec![];
//     for i in 0..8 {
//         let receiver = tokio::spawn(start_receiver_server(i));
//         receivers.push(receiver);
//     }
    
//     // Wait a moment for the servers to start
//     println!("Waiting for servers to start...");
//     tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
//     // Send files to all servers
//     let mut senders = vec![];
//     for i in 0..8 {
//         let sender = tokio::spawn(async move {
//             if let Err(e) = send_file(i).await {
//                 eprintln!("Error sending file {}: {}", i, e);
//             }
//         });
//         senders.push(sender);
//     }
    
//     // Wait for all file transfers to complete
//     for sender in senders {
//         if let Err(e) = sender.await {
//             eprintln!("Error in sender task: {}", e);
//         }
//     }
    
//     // Wait for all verifications to complete (give them 60 seconds)
//     tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    
//     let duration = start_time.elapsed();
//     println!("All verifications completed in {:?}", duration);
    
//     // Exit after all tasks are done
//     std::process::exit(0);
// }

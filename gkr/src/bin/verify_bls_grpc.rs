use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use tonic::{transport::{Server, Channel}, Request, Response, Status};

use circuit::Circuit;
use gkr_engine::{
    ExpanderPCS, FieldEngine, GKREngine, GKRScheme, M31ExtConfig, MPIConfig, MPIEngine,
    StructuredReferenceString,
};
use gkr::{executor::load_proof_and_claimed_v, Verifier};
use gkr_hashers::SHA256hasher;
use mersenne31::M31x16;
use poly_commit::{expander_pcs_init_testing_only, OrionPCSForGKR};
use transcript::BytesHashTranscript;

use config_macros::declare_gkr_config;

pub mod verification {
    tonic::include_proto!("verification");
}

use verification::{
    verification_server::{Verification, VerificationServer},
    VerificationDataMsg, VerificationRequest, VerificationResponse,
};

// Global state for storing verification parameters
static mut VERIFICATION_PARAMS: Option<Arc<VerificationParams>> = None;

struct VerificationParams {
    pcs_params: Arc<<OrionPCSForGKR<M31ExtConfig, M31x16> as ExpanderPCS<M31ExtConfig>>::Params>,
    pcs_verification_key: Arc<<<OrionPCSForGKR<M31ExtConfig, M31x16> as ExpanderPCS<M31ExtConfig>>::SRS as StructuredReferenceString>::VKey>,
    public_input: Vec<M31x16>,
}

#[derive(Default)]
pub struct SharedState {
    pub data: Option<Vec<u8>>, // Changed to store raw bytes
    pub circuit: Option<Circuit<<BLSConfig as GKREngine>::FieldConfig>>,
}

#[derive(Default)]
pub struct VerificationService {
    pub state: Arc<Mutex<SharedState>>,
}

#[tonic::async_trait]
impl Verification for VerificationService {
    async fn send_verification_data(
        &self,
        request: Request<VerificationDataMsg>,
    ) -> Result<Response<VerificationResponse>, Status> {
        let mut state = self.state.lock().await;
        let msg = request.into_inner();
        
        state.data = Some(msg.proof_bytes);
        
        Ok(Response::new(VerificationResponse {
            success: true,
            message: "Data received".to_string(),
        }))
    }

    async fn download_and_verify(
        &self,
        request: Request<VerificationRequest>,
    ) -> Result<Response<VerificationResponse>, Status> {
        let circuit_path = &request.get_ref().circuit_path;
        let mut state = self.state.lock().await;
        
        // Initialize MPI with size 8
        let mpi_config = MPIConfig::verifier_new(8);
        let verifier = Verifier::<BLSConfig>::new(mpi_config);

        println!("Loading circuit file");
        let mut circuit = Circuit::<<BLSConfig as GKREngine>::FieldConfig>::verifier_load_circuit::<BLSConfig>(circuit_path);

        println!("Loading witness file");
        circuit.verifier_load_witness_file(
            "/home/user/ExpanderCompilerCollection/efc/witnesses/290001/blsverifier/witness_0.txt",
            &verifier.mpi_config,
        );

        // Get verification parameters from global state
        let params = unsafe {
            VERIFICATION_PARAMS.as_ref()
                .ok_or_else(|| Status::internal("Verification parameters not initialized"))?
                .clone()
        };

        let result = verifier.verify(
            &mut circuit,
            &params.public_input,
            &[],  // Empty claimed_v since we're using witness file
            &params.pcs_params,
            &params.pcs_verification_key,
            &[],  // Empty proof since we're using witness file
        );

        Ok(Response::new(VerificationResponse {
            success: result,
            message: if result { "Verification successful".into() } else { "Verification failed".into() },
        }))
    }
}

async fn run_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = "[::1]:50051".parse::<SocketAddr>()?;
    let service = VerificationService {
        state: Arc::new(Mutex::new(SharedState::default())),
    };

    println!("Starting gRPC server on {}", addr);
    let server = Server::builder()
        .add_service(
            VerificationServer::new(service)
                .max_decoding_message_size(100 * 1024 * 1024) // 100MB
                .max_encoding_message_size(100 * 1024 * 1024)  // 100MB
        );

    server.serve(addr).await?;

    Ok(())
}

async fn send_verification_data(
    proof_bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = Channel::from_static("http://[::1]:50051")
        .connect()
        .await?;
        
    let mut client = verification::verification_client::VerificationClient::new(channel)
        .max_decoding_message_size(100 * 1024 * 1024) // 100MB
        .max_encoding_message_size(100 * 1024 * 1024); // 100MB

    let request = Request::new(VerificationDataMsg {
        proof_bytes,
        public_input: vec![],    // Not needed since we use global state
        pcs_params: vec![],      // Not needed since we use global state
        pcs_verification_key: vec![], // Not needed since we use global state
    });

    let response = client.send_verification_data(request).await?;
    println!("Server response: {}", response.get_ref().message);

    Ok(())
}

fn prepare_verification_data() {
    // Initialize MPI with size 8
    let mpi_config = MPIConfig::verifier_new(8);
    let verifier = Verifier::<BLSConfig>::new(mpi_config);
    println!("loading circuit file");
    let mut circuit = Circuit::<<BLSConfig as GKREngine>::FieldConfig>::verifier_load_circuit::<BLSConfig>("/home/user/ExpanderCompilerCollection/efc/circuit_blsverifier.txt");

    println!("loading witness file");
    circuit.verifier_load_witness_file(
        "/home/user/ExpanderCompilerCollection/efc/witnesses/290001/blsverifier/witness_0.txt",
        &verifier.mpi_config,
    );

    // println!("loading proof file");
    // let proof_bytes = std::fs::read("./test_bls_proof0_new").expect("Unable to read proof from file.");
    
    // Initialize PCS parameters
    let (pcs_params, _, pcs_verification_key, _) = expander_pcs_init_testing_only::<<BLSConfig as GKREngine>::FieldConfig, <BLSConfig as GKREngine>::PCSConfig>(
        circuit.log_input_size(),
        &verifier.mpi_config,
    );
    let public_input = circuit.public_input.clone();

    // Store parameters in global state
    let params = VerificationParams {
        pcs_params: Arc::new(pcs_params),
        pcs_verification_key: Arc::new(pcs_verification_key),
        public_input,
    };

    unsafe {
        VERIFICATION_PARAMS = Some(Arc::new(params));
    }
}

declare_gkr_config!(
    BLSConfig,
    FieldType::M31,
    FiatShamirHashType::SHA256,
    PolynomialCommitmentType::Orion,
    GKRScheme::Vanilla,
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize verification parameters
    prepare_verification_data();
    
    let server = tokio::spawn(run_server());
    
    // Wait a bit for server to start
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    
    // Then download and verify directly without sending data through gRPC
    let mut client = verification::verification_client::VerificationClient::new(
        Channel::from_static("http://[::1]:50051")
            .connect()
            .await?
    ).max_decoding_message_size(100 * 1024 * 1024)
      .max_encoding_message_size(100 * 1024 * 1024);

    let verify_request = Request::new(VerificationRequest {
        circuit_path: "/home/user/ExpanderCompilerCollection/efc/circuit_blsverifier.txt".into(),
    });
    let verify_response = client.download_and_verify(verify_request).await?;
    println!("Verification result: {}", verify_response.get_ref().message);
    
    server.await??;
    Ok(())
}

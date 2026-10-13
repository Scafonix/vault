use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use rand_core::OsRng;
use scafonix_crypto::{
    address_from_projective, compute_joint_public_key, create_recovery_voucher, ShareB,
};
use scafonix_policy::{compute_policy_hash, PolicyDocument, TransactionContext};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
struct ServerState {
    vaults: Arc<Mutex<HashMap<String, VaultRecord>>>,
}

#[derive(Clone)]
struct VaultRecord {
    policy: PolicyDocument,
    policy_hash: [u8; 32],
    share_b: ShareB,
    vault_address: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

#[derive(Deserialize)]
struct DkgRequest {
    policy: PolicyDocument,
    client_qa_hex: String,
    recovery_password: String,
}

#[derive(Serialize)]
struct DkgResponse {
    vault_address: String,
    enclave_qb_hex: String,
    voucher_c: String,
    policy_hash: String,
}

#[derive(Deserialize)]
struct CosignRequest {
    vault_address: String,
    tx: TransactionContext,
    raw_msg_hash_hex: String,
}

#[derive(Serialize)]
struct CosignResponse {
    status: &'static str,
    message: &'static str,
    vault_address: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    reason: String,
}

#[tokio::main]
async fn main() {
    let state = ServerState {
        vaults: Arc::new(Mutex::new(HashMap::new())),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/api/v1/dkg", post(dkg_handler))
        .route("/api/v1/cosign", post(cosign_handler))
        .layer(cors)
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
    println!("========================================================================");
    println!("🛡️  scafonix Vault (2nd Inspector Server) starting on {}", addr);
    println!("   Endpoints:");
    println!("     GET  /health");
    println!("     POST /api/v1/dkg");
    println!("     POST /api/v1/cosign");
    println!("========================================================================");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        service: "scafonix-vault-inspector",
        version: "0.1.0",
    })
}

async fn dkg_handler(
    State(state): State<ServerState>,
    Json(payload): Json<DkgRequest>,
) -> Result<Json<DkgResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut rng = OsRng;

    // 1. Compute Policy Hash
    let policy_hash = compute_policy_hash(&payload.policy).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "INVALID_POLICY".to_string(),
                reason: format!("Canonical hash computation failed: {e}"),
            }),
        )
    })?;

    // 2. Decode Client Q_A
    let qa_bytes = hex::decode(&payload.client_qa_hex).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "INVALID_PUBLIC_KEY".to_string(),
                reason: format!("Failed to decode client_qa_hex: {e}"),
            }),
        )
    })?;

    let encoded_point = EncodedPoint::from_bytes(&qa_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "INVALID_PUBLIC_KEY".to_string(),
                reason: format!("Invalid secp256k1 point: {e}"),
            }),
        )
    })?;

    let qa_affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded_point))
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_PUBLIC_KEY".to_string(),
                    reason: "Q_A point is not on curve".to_string(),
                }),
            )
        })?;
    let qa_proj = ProjectivePoint::from(qa_affine);

    // 3. Enclave generates Share B with policy hash baked in
    let mut seed_bytes = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rng, &mut seed_bytes);
    let seed_b = Scalar::from_repr(seed_bytes.into()).unwrap_or(Scalar::ONE);
    let share_b = ShareB::from_seed_and_policy(seed_b, &policy_hash);
    let qb_proj = share_b.public_key();

    // 4. Derive joint EOA address Q = Q_A + Q_B
    let q_joint = compute_joint_public_key(&qa_proj, &qb_proj);
    let vault_address = address_from_projective(&q_joint);

    // 5. Generate Voucher C (AES-256-GCM encrypted Share B)
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand_core::RngCore::fill_bytes(&mut rng, &mut salt);
    rand_core::RngCore::fill_bytes(&mut rng, &mut nonce);

    let voucher_c = create_recovery_voucher(
        share_b.scalar(),
        &payload.recovery_password,
        salt,
        nonce,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "VOUCHER_CREATION_FAILED".to_string(),
                reason: format!("{e}"),
            }),
        )
    })?;

    // Encode Q_B to hex
    let qb_encoded = qb_proj.to_affine().to_encoded_point(false);
    let qb_hex = hex::encode(qb_encoded.as_bytes());

    // Store record in server memory
    {
        let mut vaults = state.vaults.lock().unwrap();
        vaults.insert(
            vault_address.to_ascii_lowercase(),
            VaultRecord {
                policy: payload.policy,
                policy_hash,
                share_b,
                vault_address: vault_address.clone(),
            },
        );
    }

    Ok(Json(DkgResponse {
        vault_address,
        enclave_qb_hex: qb_hex,
        voucher_c,
        policy_hash: format!("0x{}", hex::encode(policy_hash)),
    }))
}

async fn cosign_handler(
    State(state): State<ServerState>,
    Json(payload): Json<CosignRequest>,
) -> Result<Json<CosignResponse>, (StatusCode, Json<ErrorResponse>)> {
    let vaults = state.vaults.lock().unwrap();
    let record = vaults
        .get(&payload.vault_address.to_ascii_lowercase())
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "VAULT_NOT_FOUND".to_string(),
                    reason: "No vault found with the specified address".to_string(),
                }),
            )
        })?;

    // 2nd Inspector: Evaluate Immutable Policy
    record.policy.evaluate(&payload.tx).map_err(|e| {
        (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "POLICY_VIOLATION".to_string(),
                reason: format!("2nd Inspector (Enclave/Server) rejected: {e}"),
            }),
        )
    })?;

    // Policy Approved!
    Ok(Json(CosignResponse {
        status: "approved",
        message: "Transaction satisfies all immutable policy rules",
        vault_address: payload.vault_address,
    }))
}

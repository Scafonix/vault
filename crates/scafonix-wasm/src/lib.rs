use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use rand_core::OsRng;
use scafonix_crypto::{
    address_from_projective, compute_joint_public_key, decrypt_recovery_voucher,
    patent_local_zero_assembly_sign, recover_ethereum_address, ShareA,
};
use scafonix_policy::{compute_policy_hash, PolicyDocument, TransactionContext};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
pub struct KeypairResult {
    pub sk_a_hex: String,
    pub q_a_hex: String,
}

#[derive(Serialize)]
pub struct EmergencySignatureResult {
    pub r: String,
    pub s: String,
    pub v: u8,
    pub recovered_address: String,
}

/// Generates a new Client Share A and public key Q_A using browser WebCrypto / CSPRNG
#[wasm_bindgen]
pub fn generate_client_keypair() -> Result<JsValue, JsValue> {
    let mut rng = OsRng;
    let share_a = ShareA::random(&mut rng);
    let qa_proj = share_a.public_key();
    let qa_encoded = qa_proj.to_affine().to_encoded_point(false);

    let result = KeypairResult {
        sk_a_hex: hex::encode(share_a.scalar().to_bytes()),
        q_a_hex: hex::encode(qa_encoded.as_bytes()),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Computes the deterministic canonical policy hash h_p
#[wasm_bindgen]
pub fn compute_policy_hash_wasm(policy_json: &str) -> Result<String, JsValue> {
    let policy: PolicyDocument = serde_json::from_str(policy_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid policy JSON: {e}")))?;
    let hash = compute_policy_hash(&policy)
        .map_err(|e| JsValue::from_str(&format!("Canonical serialization failed: {e}")))?;
    Ok(format!("0x{}", hex::encode(hash)))
}

/// Evaluates a transaction against an IAM policy document
#[wasm_bindgen]
pub fn evaluate_policy_wasm(policy_json: &str, tx_json: &str) -> Result<bool, JsValue> {
    let policy: PolicyDocument = serde_json::from_str(policy_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid policy JSON: {e}")))?;
    let tx: TransactionContext = serde_json::from_str(tx_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid transaction JSON: {e}")))?;

    match policy.evaluate(&tx) {
        Ok(()) => Ok(true),
        Err(e) => Err(JsValue::from_str(&format!("Policy rejected: {e}"))),
    }
}

/// Computes the joint vault EOA address from Q_A and Q_B
#[wasm_bindgen]
pub fn compute_vault_address_wasm(qa_hex: &str, qb_hex: &str) -> Result<String, JsValue> {
    let qa_bytes = hex::decode(qa_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let qb_bytes = hex::decode(qb_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let pt_a = EncodedPoint::from_bytes(&qa_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pt_b = EncodedPoint::from_bytes(&qb_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let affine_a = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&pt_a))
        .ok_or_else(|| JsValue::from_str("Invalid Q_A point"))?;
    let affine_b = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&pt_b))
        .ok_or_else(|| JsValue::from_str("Invalid Q_B point"))?;

    let q_joint = compute_joint_public_key(&ProjectivePoint::from(affine_a), &ProjectivePoint::from(affine_b));
    Ok(address_from_projective(&q_joint))
}

/// Decrypts the Share C emergency voucher
#[wasm_bindgen]
pub fn decrypt_recovery_voucher_wasm(voucher_c: &str, password: &str) -> Result<String, JsValue> {
    let sk_b = decrypt_recovery_voucher(voucher_c, password)
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {e}")))?;
    Ok(hex::encode(sk_b.to_bytes()))
}

/// Executes the Patent Zero-Assembly Local Signature (10-2026-0134084)
#[wasm_bindgen]
pub fn patent_emergency_sign_wasm(
    sk_a_hex: &str,
    sk_b_hex: &str,
    msg_hash_hex: &str,
) -> Result<JsValue, JsValue> {
    let mut rng = OsRng;
    let a_bytes = hex::decode(sk_a_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let b_bytes = hex::decode(sk_b_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let hash_bytes = hex::decode(msg_hash_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;

    if a_bytes.len() != 32 || b_bytes.len() != 32 || hash_bytes.len() != 32 {
        return Err(JsValue::from_str("Invalid parameter byte length (expected 32 bytes)"));
    }

    let mut a_arr = [0u8; 32];
    let mut b_arr = [0u8; 32];
    a_arr.copy_from_slice(&a_bytes);
    b_arr.copy_from_slice(&b_bytes);

    let sk_a = Option::from(Scalar::from_repr(a_arr.into()))
        .ok_or_else(|| JsValue::from_str("Invalid sk_A scalar"))?;
    let sk_b = Option::from(Scalar::from_repr(b_arr.into()))
        .ok_or_else(|| JsValue::from_str("Invalid sk_B scalar"))?;

    let mut msg_hash = [0u8; 32];
    msg_hash.copy_from_slice(&hash_bytes);

    let mut k_bytes = [0u8; 32];
    let mut beta_bytes = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rng, &mut k_bytes);
    rand_core::RngCore::fill_bytes(&mut rng, &mut beta_bytes);

    let k = Scalar::from_repr(k_bytes.into()).unwrap_or(Scalar::ONE);
    let beta = Scalar::from_repr(beta_bytes.into()).unwrap_or(Scalar::ONE);

    let sig = patent_local_zero_assembly_sign(&sk_a, &sk_b, &msg_hash, k, beta)
        .map_err(|e| JsValue::from_str(&format!("Signing failed: {e}")))?;

    let recovered_address = recover_ethereum_address(&msg_hash, &sig)
        .map_err(|e| JsValue::from_str(&format!("Verification failed: {e}")))?;

    let (r_hex, s_hex, v) = sig.to_hex();
    let result = EmergencySignatureResult {
        r: r_hex,
        s: s_hex,
        v,
        recovered_address,
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

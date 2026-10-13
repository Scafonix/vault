use crate::address::{derive_ethereum_address_from_encoded, to_checksum_address};
use crate::patent_sign::EcdsaSignature;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Failed to construct ECDSA signature: {0}")]
    Signature(#[from] k256::ecdsa::Error),
    #[error("Public key recovery failed")]
    RecoveryFailed,
}

/// Recovers the Ethereum checksum address from an ECDSA (r, s, v) signature and message hash
pub fn recover_ethereum_address(
    msg_hash: &[u8; 32],
    sig: &EcdsaSignature,
) -> Result<String, VerifyError> {
    let raw_v = if sig.v >= 27 { sig.v - 27 } else { sig.v };
    let recovery_id = RecoveryId::from_byte(raw_v).ok_or(VerifyError::RecoveryFailed)?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes[0..32].copy_from_slice(&sig.r);
    sig_bytes[32..64].copy_from_slice(&sig.s);

    let k256_sig = Signature::from_bytes((&sig_bytes).into())?;
    let verifying_key = VerifyingKey::recover_from_prehash(msg_hash, &k256_sig, recovery_id)
        .map_err(|_| VerifyError::RecoveryFailed)?;

    let encoded_point = verifying_key.to_encoded_point(false);
    let raw_address = derive_ethereum_address_from_encoded(&encoded_point);
    Ok(to_checksum_address(&raw_address))
}

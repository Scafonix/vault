use crate::model::PolicyDocument;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CanonicalError {
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Serializes the policy deterministically (canonical JSON)
pub fn to_canonical_json(policy: &PolicyDocument) -> Result<String, CanonicalError> {
    // serde_json value normalization with sorted keys
    let value = serde_json::to_value(policy)?;
    let canonical_str = serde_json::to_string(&value)?;
    Ok(canonical_str)
}

/// Derives the 32-byte cryptographic policy hash (h_p)
pub fn compute_policy_hash(policy: &PolicyDocument) -> Result<[u8; 32], CanonicalError> {
    let canonical_json = to_canonical_json(policy)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum VoucherError {
    #[error("Encryption failure")]
    Encryption,
    #[error("Decryption failure: incorrect password or corrupted ticket")]
    Decryption,
    #[error("Invalid hex format: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Invalid scalar payload")]
    InvalidScalar,
}

/// Derives a 32-byte AES key from password and salt using repeated SHA-256 (KDF)
fn derive_aes_key(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let mut round = hasher.finalize();

    // 10,000 iterations for basic KDF protection
    for _ in 0..10_000 {
        let mut h = Sha256::new();
        h.update(&round);
        h.update(salt);
        round = h.finalize();
    }

    key.copy_from_slice(&round);
    key
}

/// Encrypts Share B into an emergency recovery voucher string (Share C)
pub fn create_recovery_voucher(
    share_b_scalar: &Scalar,
    password: &str,
    salt: [u8; 16],
    nonce_bytes: [u8; 12],
) -> Result<String, VoucherError> {
    let mut key = derive_aes_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| VoucherError::Encryption)?;
    key.zeroize();

    let scalar_bytes = share_b_scalar.to_bytes();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, scalar_bytes.as_slice())
        .map_err(|_| VoucherError::Encryption)?;

    // Payload: [salt (16 bytes)] || [nonce (12 bytes)] || [ciphertext + tag]
    let mut payload = Vec::with_capacity(16 + 12 + ciphertext.len());
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    Ok(format!("scafonix-vault-c-{}", hex::encode(payload)))
}

/// Decrypts the emergency recovery voucher string (Share C) to recover Share B scalar
pub fn decrypt_recovery_voucher(voucher_str: &str, password: &str) -> Result<Scalar, VoucherError> {
    let hex_part = voucher_str
        .strip_prefix("scafonix-vault-c-")
        .unwrap_or(voucher_str);

    let payload = hex::decode(hex_part)?;
    if payload.len() < 16 + 12 + 16 {
        return Err(VoucherError::Decryption);
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&payload[0..16]);

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&payload[16..28]);

    let ciphertext = &payload[28..];

    let mut key = derive_aes_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| VoucherError::Decryption)?;
    key.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VoucherError::Decryption)?;

    if plaintext.len() != 32 {
        return Err(VoucherError::InvalidScalar);
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&plaintext);
    Option::from(Scalar::from_repr(bytes.into())).ok_or(VoucherError::InvalidScalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_voucher_encrypt_decrypt() {
        let scalar = Scalar::from(42u64);
        let password = "SuperSecretPassword123!";
        let salt = [7u8; 16];
        let nonce = [9u8; 12];

        let voucher = create_recovery_voucher(&scalar, password, salt, nonce).unwrap();
        assert!(voucher.starts_with("scafonix-vault-c-"));

        // Decrypt with correct password
        let recovered = decrypt_recovery_voucher(&voucher, password).unwrap();
        assert_eq!(scalar, recovered);

        // Decrypt with wrong password fails
        assert!(decrypt_recovery_voucher(&voucher, "WrongPassword!").is_err());
    }
}

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint};
use sha3::{Digest, Keccak256};

/// Derives standard Ethereum 20-byte address from uncompressed affine public key
pub fn derive_ethereum_address(point: &AffinePoint) -> [u8; 20] {
    let uncompressed = point.to_encoded_point(false);
    derive_ethereum_address_from_encoded(&uncompressed)
}

/// Derives standard Ethereum 20-byte address from encoded point (uncompressed 65 bytes)
pub fn derive_ethereum_address_from_encoded(
    encoded: &k256::elliptic_curve::sec1::EncodedPoint<k256::Secp256k1>,
) -> [u8; 20] {
    let bytes = encoded.as_bytes();
    // bytes[0] is 0x04 format tag, bytes[1..65] is X || Y (64 bytes)
    let pubkey_bytes = &bytes[1..65];

    let mut hasher = Keccak256::new();
    hasher.update(pubkey_bytes);
    let hash = hasher.finalize();

    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

/// Formats 20-byte address to EIP-55 checksum string (e.g. 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed)
pub fn to_checksum_address(address: &[u8; 20]) -> String {
    let hex_addr = hex::encode(address);

    let mut hasher = Keccak256::new();
    hasher.update(hex_addr.as_bytes());
    let hash = hex::encode(hasher.finalize());

    let mut checksum = String::with_capacity(42);
    checksum.push_str("0x");

    for (i, c) in hex_addr.chars().enumerate() {
        if c.is_ascii_digit() {
            checksum.push(c);
        } else {
            let hash_nibble = u8::from_str_radix(&hash[i..i + 1], 16).unwrap_or(0);
            if hash_nibble >= 8 {
                checksum.push(c.to_ascii_uppercase());
            } else {
                checksum.push(c.to_ascii_lowercase());
            }
        }
    }

    checksum
}

/// Convenience function to derive checksum address from ProjectivePoint
pub fn address_from_projective(point: &ProjectivePoint) -> String {
    let affine = point.to_affine();
    let raw = derive_ethereum_address(&affine);
    to_checksum_address(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{ProjectivePoint, Scalar};

    #[test]
    fn test_ethereum_address_known_vector() {
        // Private key = 1
        let privkey = Scalar::ONE;
        let pubkey = ProjectivePoint::GENERATOR * privkey;
        let addr = address_from_projective(&pubkey);
        // Known address for private key 1 is 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
        assert_eq!(addr.to_ascii_lowercase(), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }
}

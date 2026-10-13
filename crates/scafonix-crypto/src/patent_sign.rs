use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum SignError {
    #[error("Inversion failed (zero scalar)")]
    ZeroInverse,
    #[error("Invalid hash length")]
    InvalidHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8, // 27 or 28
}

impl EcdsaSignature {
    pub fn to_hex(&self) -> (String, String, u8) {
        (format!("0x{}", hex::encode(self.r)), format!("0x{}", hex::encode(self.s)), self.v)
    }
}

/// Patent Algorithm (Application 10-2026-0134084)
/// Local Non-assembled Cryptographic Signature using Combined Blinded Nonce
/// Used for standalone Disaster Recovery (Share A + decrypted Share B)
pub fn patent_local_zero_assembly_sign(
    share_a: &Scalar,
    share_b: &Scalar,
    msg_hash: &[u8; 32],
    k: Scalar,
    beta: Scalar,
) -> Result<EcdsaSignature, SignError> {
    let mut e = Scalar::from_repr((*msg_hash).into()).unwrap_or(Scalar::ONE);
    let mut beta = beta;
    if bool::from(beta.is_zero()) {
        beta = Scalar::ONE;
    }

    // 1. Term-by-term blinding
    let mut p1_beta = *share_a * beta;
    let mut p2_beta = *share_b * beta;

    // 2. Linear combination of blinded terms (blindedD = d * beta)
    let mut blinded_d = p1_beta + p2_beta;

    // 3. Ephemeral point R = k * G
    let r_proj = ProjectivePoint::GENERATOR * k;
    let r_affine = r_proj.to_affine();
    let r_encoded = r_affine.to_encoded_point(false);
    let rx_bytes = r_encoded.x().ok_or(SignError::InvalidHash)?;
    let mut r = Scalar::from_repr(*rx_bytes).unwrap_or(Scalar::ONE);

    // 4. Combined Blinded Nonce: k_blind = k * beta
    let mut k_blind = k * beta;

    // 5. Blinded Signature: s_blind = e * beta + r * blindedD
    let mut e_beta = e * beta;
    let mut r_blinded_d = r * blinded_d;
    let mut s_blind = e_beta + r_blinded_d;

    // 6. Direct inversion of combined blinded nonce: (k * beta)^(-1)
    let k_blind_inv: Scalar = Option::from(k_blind.invert()).ok_or(SignError::ZeroInverse)?;

    // 7. Final signature s = s_blind * (k * beta)^(-1) -> beta cancels out algebraically!
    let mut s: Scalar = s_blind * k_blind_inv;

    // 8. Low-S malleability check & recovery id v (EIP-2)
    let mut v: u8 = 27;
    let ry_bytes = r_encoded.y().ok_or(SignError::InvalidHash)?;
    if (ry_bytes[31] & 1) == 1 {
        v = 28;
    }

    // Check if s > N/2
    let is_high = bool::from(s.is_high());
    if is_high {
        s = -s;
        v = if v == 27 { 28 } else { 27 };
    }

    let mut out_r = [0u8; 32];
    let mut out_s = [0u8; 32];
    out_r.copy_from_slice(&r.to_bytes());
    out_s.copy_from_slice(&s.to_bytes());

    // 9. Zeroize sensitive intermediate buffers (Patent Claims 4, 11)
    p1_beta.zeroize();
    p2_beta.zeroize();
    blinded_d.zeroize();
    e_beta.zeroize();
    r_blinded_d.zeroize();
    s_blind.zeroize();
    k_blind.zeroize();
    beta.zeroize();
    e.zeroize();
    r.zeroize();

    Ok(EcdsaSignature {
        r: out_r,
        s: out_s,
        v,
    })
}

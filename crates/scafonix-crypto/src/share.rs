use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Client secret share (Share A)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShareA {
    scalar: Scalar,
}

impl ShareA {
    pub fn new(scalar: Scalar) -> Self {
        Self { scalar }
    }

    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        // Reduce into scalar field
        let scalar = Scalar::from_repr(bytes.into()).unwrap_or(Scalar::ONE);
        Self { scalar }
    }

    pub fn public_key(&self) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * self.scalar
    }

    pub fn scalar(&self) -> &Scalar {
        &self.scalar
    }
}

/// Enclave secret share (Share B), with policy hash baked in
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShareB {
    scalar: Scalar,
}

impl ShareB {
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self { scalar }
    }

    pub fn from_seed_and_policy(seed: Scalar, policy_hash: &[u8; 32]) -> Self {
        let hp = Scalar::from_repr((*policy_hash).into()).unwrap_or(Scalar::ONE);
        let scalar = seed + hp;
        Self { scalar }
    }

    pub fn random_with_policy<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
        policy_hash: &[u8; 32],
    ) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let seed = Scalar::from_repr(bytes.into()).unwrap_or(Scalar::ONE);
        Self::from_seed_and_policy(seed, policy_hash)
    }

    pub fn public_key(&self) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * self.scalar
    }

    pub fn scalar(&self) -> &Scalar {
        &self.scalar
    }
}

/// Computes the joint master public key Q = Q_A + Q_B
pub fn compute_joint_public_key(qa: &ProjectivePoint, qb: &ProjectivePoint) -> ProjectivePoint {
    *qa + *qb
}

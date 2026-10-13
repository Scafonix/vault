use crate::client::ClientVault;
use crate::enclave::EnclaveGuardian;
use crate::VaultError;
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use scafonix_crypto::{
    address_from_projective, compute_joint_public_key, create_recovery_voucher, ShareA, ShareB,
};
use scafonix_policy::{compute_policy_hash, PolicyDocument};

pub struct VaultCreationResult {
    pub client: ClientVault,
    pub enclave: EnclaveGuardian,
    pub vault_address: String,
    pub voucher_c: String,
}

/// Zero-Mnemonic Distributed Vault Creation (DKG)
pub fn create_new_vault<R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
    policy: PolicyDocument,
    recovery_password: &str,
) -> Result<VaultCreationResult, VaultError> {
    // 1. Calculate deterministic policy hash
    let policy_hash = compute_policy_hash(&policy).map_err(|e| {
        VaultError::EnclaveRejected(format!("Failed to compute canonical policy hash: {e}"))
    })?;

    // 2. Client generates Share A (Random scalar)
    let share_a = ShareA::random(rng);
    let qa = share_a.public_key();

    // 3. Enclave generates Share B with policy hash baked in
    let mut b_bytes = [0u8; 32];
    rng.fill_bytes(&mut b_bytes);
    let seed_b = Scalar::from_repr(b_bytes.into()).unwrap_or(Scalar::ONE);
    let share_b = ShareB::from_seed_and_policy(seed_b, &policy_hash);
    let qb = share_b.public_key();

    // 4. Derive joint EOA address: Q = Q_A + Q_B
    let q_joint = compute_joint_public_key(&qa, &qb);
    let vault_address = address_from_projective(&q_joint);

    // 5. Enclave creates 1-time emergency recovery voucher (Share C)
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let voucher_c = create_recovery_voucher(share_b.scalar(), recovery_password, salt, nonce)?;

    let client = ClientVault::new(share_a, policy.clone(), vault_address.clone());
    let enclave = EnclaveGuardian::new(share_b, policy, policy_hash);

    Ok(VaultCreationResult {
        client,
        enclave,
        vault_address,
        voucher_c,
    })
}

pub mod address;
pub mod patent_sign;
pub mod share;
pub mod verify;
pub mod voucher;

pub use address::{address_from_projective, derive_ethereum_address, to_checksum_address};
pub use patent_sign::{patent_local_zero_assembly_sign, EcdsaSignature, SignError};
pub use share::{compute_joint_public_key, ShareA, ShareB};
pub use verify::{recover_ethereum_address, VerifyError};
pub use voucher::{create_recovery_voucher, decrypt_recovery_voucher, VoucherError};

#[cfg(test)]
mod tests {
    use super::*;
    use k256::Scalar;
    use scafonix_policy::compute_policy_hash;
    use scafonix_policy::PolicyTemplates;

    #[test]
    fn test_end_to_end_patent_zero_assembly_and_recovery() {
        // 1. Create Policy and Policy Hash
        let policy = PolicyTemplates::daily_limit_eth("vault-1", 1_000_000, 1);
        let policy_hash = compute_policy_hash(&policy).unwrap();

        // 2. Generate Share A and Share B
        let sk_a = Scalar::from(123456789u64);
        let sk_b_seed = Scalar::from(987654321u64);
        let share_a = ShareA::new(sk_a);
        let share_b = ShareB::from_seed_and_policy(sk_b_seed, &policy_hash);

        // 3. Compute Joint Vault Public Key & Ethereum Address
        let qa = share_a.public_key();
        let qb = share_b.public_key();
        let q_joint = compute_joint_public_key(&qa, &qb);
        let vault_address = address_from_projective(&q_joint);
        println!("Derived Vault EOA Address: {}", vault_address);

        // 4. Create Recovery Voucher (Share C)
        let password = "MySecureRecoveryPassword123!";
        let salt = [1u8; 16];
        let nonce = [2u8; 12];
        let voucher_c = create_recovery_voucher(share_b.scalar(), password, salt, nonce).unwrap();

        // Verify voucher decrypts back to exact Share B
        let recovered_sk_b = decrypt_recovery_voucher(&voucher_c, password).unwrap();
        assert_eq!(*share_b.scalar(), recovered_sk_b);

        // 5. Sign a message hash using Patent Local Zero-Assembly Engine
        let msg_hash = [0xabu8; 32];
        let k = Scalar::from(777888999u64);
        let beta = Scalar::from(555444333u64);

        let sig = patent_local_zero_assembly_sign(
            share_a.scalar(),
            &recovered_sk_b,
            &msg_hash,
            k,
            beta,
        )
        .unwrap();

        // 6. Verify that the signature recovers the EXACT Vault Ethereum Address!
        let recovered_address = recover_ethereum_address(&msg_hash, &sig).unwrap();
        println!("Recovered Signer Address: {}", recovered_address);
        assert_eq!(vault_address, recovered_address);
        println!("✅ Patent Zero-Assembly Signature mathematically verified with 100% address match!");
    }

    #[test]
    fn test_tampered_policy_fails_verification() {
        // Create original policy
        let p_orig = PolicyTemplates::daily_limit_eth("vault-1", 1_000_000, 1);
        let h_orig = compute_policy_hash(&p_orig).unwrap();

        let sk_a = Scalar::from(111222u64);
        let sk_b_seed = Scalar::from(333444u64);

        let share_a = ShareA::new(sk_a);
        let share_b_orig = ShareB::from_seed_and_policy(sk_b_seed, &h_orig);

        let vault_address_orig =
            address_from_projective(&compute_joint_public_key(&share_a.public_key(), &share_b_orig.public_key()));

        // Attacker tampers policy (raises limit to 10,000,000)
        let p_tampered = PolicyTemplates::daily_limit_eth("vault-1", 10_000_000, 1);
        let h_tampered = compute_policy_hash(&p_tampered).unwrap();
        let share_b_tampered = ShareB::from_seed_and_policy(sk_b_seed, &h_tampered);

        // Sign with tampered Share B
        let msg_hash = [0x55u8; 32];
        let k = Scalar::from(999u64);
        let beta = Scalar::from(888u64);

        let sig = patent_local_zero_assembly_sign(
            share_a.scalar(),
            share_b_tampered.scalar(),
            &msg_hash,
            k,
            beta,
        )
        .unwrap();

        // Recovered address will NOT match the original vault address!
        let recovered_addr = recover_ethereum_address(&msg_hash, &sig).unwrap();
        assert_ne!(vault_address_orig, recovered_addr);
        println!("✅ Tampered policy proven to produce invalid signature for original vault!");
    }
}

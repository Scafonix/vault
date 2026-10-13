use crate::VaultError;
use k256::Scalar;
use scafonix_crypto::{
    decrypt_recovery_voucher, patent_local_zero_assembly_sign, EcdsaSignature, ShareA,
};
use scafonix_policy::{PolicyDocument, TransactionContext};

pub struct ClientVault {
    pub share_a: ShareA,
    pub policy: PolicyDocument,
    pub vault_address: String,
}

impl ClientVault {
    pub fn new(share_a: ShareA, policy: PolicyDocument, vault_address: String) -> Self {
        Self {
            share_a,
            policy,
            vault_address,
        }
    }

    /// 1st Inspector: Local policy evaluation on the user's device
    pub fn evaluate_local(&self, tx: &TransactionContext) -> Result<(), VaultError> {
        self.policy.evaluate(tx).map_err(VaultError::Policy)
    }

    /// Disaster Recovery: Sign 100% locally using Share A + decrypted Share B (from Share C voucher)
    /// Runs the patent local zero-assembly engine without any server communication
    pub fn emergency_local_sign(
        &self,
        voucher_c: &str,
        recovery_password: &str,
        msg_hash: &[u8; 32],
        k: Scalar,
        beta: Scalar,
    ) -> Result<EcdsaSignature, VaultError> {
        let recovered_share_b = decrypt_recovery_voucher(voucher_c, recovery_password)?;
        let sig = patent_local_zero_assembly_sign(
            self.share_a.scalar(),
            &recovered_share_b,
            msg_hash,
            k,
            beta,
        )?;
        Ok(sig)
    }
}

use crate::VaultError;
use scafonix_crypto::ShareB;
use scafonix_policy::{PolicyDocument, TransactionContext};

#[derive(Debug, Clone)]
pub enum EnclaveResponse {
    Approved {
        policy_hash: [u8; 32],
    },
    Rejected {
        reason: String,
    },
}

/// Represents the AWS Nitro Enclave 2nd Inspector
pub struct EnclaveGuardian {
    pub share_b: ShareB,
    pub policy: PolicyDocument,
    pub policy_hash: [u8; 32],
}

impl EnclaveGuardian {
    pub fn new(share_b: ShareB, policy: PolicyDocument, policy_hash: [u8; 32]) -> Self {
        Self {
            share_b,
            policy,
            policy_hash,
        }
    }

    /// 2nd Inspector: Immutable policy evaluation inside the Enclave
    /// Notice: There are NO setter methods, NO admin endpoints to relax policy!
    pub fn evaluate_and_approve(&self, tx: &TransactionContext) -> Result<(), VaultError> {
        self.policy.evaluate(tx).map_err(|e| {
            VaultError::EnclaveRejected(format!("Enclave 2nd Inspector rejected: {e}"))
        })
    }
}

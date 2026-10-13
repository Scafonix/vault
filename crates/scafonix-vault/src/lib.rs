pub mod client;
pub mod enclave;
pub mod factory;

pub use client::ClientVault;
pub use enclave::{EnclaveGuardian, EnclaveResponse};
pub use factory::{create_new_vault, VaultCreationResult};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Policy evaluation failed: {0}")]
    Policy(#[from] scafonix_policy::EvaluationError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] scafonix_crypto::SignError),
    #[error("Voucher error: {0}")]
    Voucher(#[from] scafonix_crypto::VoucherError),
    #[error("Verification error: {0}")]
    Verify(#[from] scafonix_crypto::VerifyError),
    #[error("Enclave rejected transaction: {0}")]
    EnclaveRejected(String),
}

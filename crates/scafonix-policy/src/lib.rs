pub mod canonical;
pub mod evaluator;
pub mod model;
pub mod templates;

pub use canonical::{compute_policy_hash, to_canonical_json};
pub use evaluator::EvaluationError;
pub use model::{Condition, Effect, PolicyDocument, Statement, TransactionContext};
pub use templates::PolicyTemplates;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_hash_deterministic() {
        let p1 = PolicyTemplates::daily_limit_eth("vault-1", 1_000_000, 1);
        let p2 = PolicyTemplates::daily_limit_eth("vault-1", 1_000_000, 1);
        let h1 = compute_policy_hash(&p1).unwrap();
        let h2 = compute_policy_hash(&p2).unwrap();
        assert_eq!(h1, h2);

        // Different vault id or limit changes hash
        let p3 = PolicyTemplates::daily_limit_eth("vault-2", 1_000_000, 1);
        let h3 = compute_policy_hash(&p3).unwrap();
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_policy_evaluation_allow_and_deny() {
        let policy = PolicyTemplates::daily_limit_eth("vault-1", 1_000_000, 1);

        // Valid Tx
        let tx_ok = TransactionContext {
            action: "web3:TransferETH".to_string(),
            recipient: "0x1234567890123456789012345678901234567890".to_string(),
            value_wei: 500_000,
            chain_id: 1,
        };
        assert!(policy.evaluate(&tx_ok).is_ok());

        // Value exceeds limit
        let tx_over = TransactionContext {
            action: "web3:TransferETH".to_string(),
            recipient: "0x1234567890123456789012345678901234567890".to_string(),
            value_wei: 2_000_000,
            chain_id: 1,
        };
        assert_eq!(policy.evaluate(&tx_over), Err(EvaluationError::NoMatchingAllow));

        // Wrong chain id
        let tx_wrong_chain = TransactionContext {
            action: "web3:TransferETH".to_string(),
            recipient: "0x1234567890123456789012345678901234567890".to_string(),
            value_wei: 500_000,
            chain_id: 137, // Polygon
        };
        assert_eq!(policy.evaluate(&tx_wrong_chain), Err(EvaluationError::NoMatchingAllow));
    }

    #[test]
    fn test_full_access_and_explicit_deny() {
        // Policy: Allow all, but Deny > 10 ETH
        let mut gt = std::collections::BTreeMap::new();
        gt.insert("web3:ValueWei".to_string(), 10_000_000_000_000_000_000); // 10 ETH

        let policy = PolicyDocument {
            version: "scafonix-2026-v1".to_string(),
            vault_id: "vault-full".to_string(),
            statement: vec![
                Statement {
                    sid: Some("AllowAllTransactions".to_string()),
                    effect: Effect::Allow,
                    action: vec!["*".to_string()],
                    resource: vec!["*".to_string()],
                    condition: None,
                },
                Statement {
                    sid: Some("DenyDrainOver10Eth".to_string()),
                    effect: Effect::Deny,
                    action: vec!["*".to_string()],
                    resource: vec!["*".to_string()],
                    condition: Some(Condition {
                        numeric_greater_than: Some(gt),
                        ..Default::default()
                    }),
                },
            ],
        };

        // 1. Regular 1 ETH Tx -> Allowed
        let tx_normal = TransactionContext {
            action: "web3:TransferETH".to_string(),
            recipient: "0x1234567890123456789012345678901234567890".to_string(),
            value_wei: 1_000_000_000_000_000_000,
            chain_id: 1,
        };
        assert!(policy.evaluate(&tx_normal).is_ok());

        // 2. Huge 15 ETH Tx -> ExplicitDeny overrides Allow
        let tx_huge = TransactionContext {
            action: "web3:TransferETH".to_string(),
            recipient: "0x1234567890123456789012345678901234567890".to_string(),
            value_wei: 15_000_000_000_000_000_000,
            chain_id: 1,
        };
        assert_eq!(
            policy.evaluate(&tx_huge),
            Err(EvaluationError::ExplicitDeny(Some("DenyDrainOver10Eth".to_string())))
        );
    }
}

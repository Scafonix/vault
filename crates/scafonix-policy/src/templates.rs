use crate::model::{Condition, Effect, PolicyDocument, Statement};
use std::collections::BTreeMap;

pub struct PolicyTemplates;

impl PolicyTemplates {
    /// Template 1: Daily spending limit on ETH transfers
    pub fn daily_limit_eth(vault_id: &str, max_wei: u64, chain_id: u64) -> PolicyDocument {
        let mut num_lte = BTreeMap::new();
        num_lte.insert("web3:ValueWei".to_string(), max_wei);

        let mut num_eq = BTreeMap::new();
        num_eq.insert("web3:ChainId".to_string(), chain_id);

        let condition = Condition {
            numeric_less_than_equals: Some(num_lte),
            numeric_equals: Some(num_eq),
            string_equals: None,
        };

        PolicyDocument {
            version: "scafonix-2026-v1".to_string(),
            vault_id: vault_id.to_string(),
            statement: vec![Statement {
                sid: Some("AllowEthTransferWithLimit".to_string()),
                effect: Effect::Allow,
                action: vec!["web3:TransferETH".to_string()],
                resource: vec!["*".to_string()],
                condition: Some(condition),
            }],
        }
    }

    /// Template 2: Whitelisted destinations only
    pub fn whitelisted_recipients(
        vault_id: &str,
        recipients: Vec<String>,
        max_wei: u64,
        chain_id: u64,
    ) -> PolicyDocument {
        let mut num_lte = BTreeMap::new();
        num_lte.insert("web3:ValueWei".to_string(), max_wei);

        let mut num_eq = BTreeMap::new();
        num_eq.insert("web3:ChainId".to_string(), chain_id);

        let condition = Condition {
            numeric_less_than_equals: Some(num_lte),
            numeric_equals: Some(num_eq),
            string_equals: None,
        };

        let resources = recipients
            .into_iter()
            .map(|addr| format!("ethereum:recipient:{addr}"))
            .collect();

        PolicyDocument {
            version: "scafonix-2026-v1".to_string(),
            vault_id: vault_id.to_string(),
            statement: vec![Statement {
                sid: Some("AllowWhitelistedRecipientsOnly".to_string()),
                effect: Effect::Allow,
                action: vec!["web3:TransferETH".to_string(), "web3:TransferERC20".to_string()],
                resource: resources,
                condition: Some(condition),
            }],
        }
    }
}

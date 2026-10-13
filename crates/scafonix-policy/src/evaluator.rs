use crate::model::{Effect, PolicyDocument, TransactionContext};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum EvaluationError {
    #[error("Transaction denied: explicit Deny matched (Sid: {0:?})")]
    ExplicitDeny(Option<String>),
    #[error("Transaction denied: no Allow statement matched the transaction")]
    NoMatchingAllow,
}

impl PolicyDocument {
    pub fn evaluate(&self, tx: &TransactionContext) -> Result<(), EvaluationError> {
        let mut allow_matched = false;

        for stmt in &self.statement {
            if !self.matches_action(stmt, &tx.action) {
                continue;
            }
            if !self.matches_resource(stmt, &tx.recipient) {
                continue;
            }
            if !self.matches_condition(stmt, tx) {
                continue;
            }

            match stmt.effect {
                Effect::Deny => {
                    return Err(EvaluationError::ExplicitDeny(stmt.sid.clone()));
                }
                Effect::Allow => {
                    allow_matched = true;
                }
            }
        }

        if allow_matched {
            Ok(())
        } else {
            Err(EvaluationError::NoMatchingAllow)
        }
    }

    fn matches_action(&self, stmt: &crate::model::Statement, action: &str) -> bool {
        stmt.action.iter().any(|a| a == "*" || a.eq_ignore_ascii_case(action))
    }

    fn matches_resource(&self, stmt: &crate::model::Statement, recipient: &str) -> bool {
        stmt.resource.iter().any(|r| {
            if r == "*" {
                return true;
            }
            // Case-insensitive address match or resource URI
            if r.eq_ignore_ascii_case(recipient) {
                return true;
            }
            // Support "ethereum:recipient:0x..." format
            if let Some(stripped) = r.strip_prefix("ethereum:recipient:") {
                return stripped.eq_ignore_ascii_case(recipient);
            }
            if let Some(stripped) = r.strip_prefix("ethereum:contract:") {
                return stripped.eq_ignore_ascii_case(recipient);
            }
            false
        })
    }

    fn matches_condition(&self, stmt: &crate::model::Statement, tx: &TransactionContext) -> bool {
        let Some(cond) = &stmt.condition else {
            return true;
        };

        if let Some(num_lte) = &cond.numeric_less_than_equals {
            if let Some(max_val) = num_lte.get("web3:ValueWei") {
                if tx.value_wei > *max_val {
                    return false;
                }
            }
        }

        if let Some(num_eq) = &cond.numeric_equals {
            if let Some(req_chain_id) = num_eq.get("web3:ChainId") {
                if tx.chain_id != *req_chain_id {
                    return false;
                }
            }
        }

        if let Some(str_eq) = &cond.string_equals {
            if let Some(req_action) = str_eq.get("web3:Action") {
                if !req_action.eq_ignore_ascii_case(&tx.action) {
                    return false;
                }
            }
        }

        true
    }
}

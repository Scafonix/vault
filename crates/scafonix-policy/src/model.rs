use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    #[serde(rename = "Allow")]
    Allow,
    #[serde(rename = "Deny")]
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Condition {
    #[serde(rename = "NumericLessThanEquals", skip_serializing_if = "Option::is_none")]
    pub numeric_less_than_equals: Option<BTreeMap<String, u64>>,

    #[serde(rename = "NumericGreaterThan", skip_serializing_if = "Option::is_none")]
    pub numeric_greater_than: Option<BTreeMap<String, u64>>,

    #[serde(rename = "NumericGreaterThanEquals", skip_serializing_if = "Option::is_none")]
    pub numeric_greater_than_equals: Option<BTreeMap<String, u64>>,

    #[serde(rename = "NumericEquals", skip_serializing_if = "Option::is_none")]
    pub numeric_equals: Option<BTreeMap<String, u64>>,

    #[serde(rename = "StringEquals", skip_serializing_if = "Option::is_none")]
    pub string_equals: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "Sid", skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,

    #[serde(rename = "Effect")]
    pub effect: Effect,

    #[serde(rename = "Action")]
    pub action: Vec<String>,

    #[serde(rename = "Resource")]
    pub resource: Vec<String>,

    #[serde(rename = "Condition", skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDocument {
    #[serde(rename = "Version")]
    pub version: String,

    #[serde(rename = "VaultId")]
    pub vault_id: String,

    #[serde(rename = "Statement")]
    pub statement: Vec<Statement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionContext {
    pub action: String,
    pub recipient: String,
    pub value_wei: u64,
    pub chain_id: u64,
}

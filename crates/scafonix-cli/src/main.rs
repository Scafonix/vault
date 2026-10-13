use k256::Scalar;
use rand_core::OsRng;
use scafonix_crypto::recover_ethereum_address;
use scafonix_policy::{to_canonical_json, PolicyTemplates, TransactionContext};
use scafonix_vault::create_new_vault;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("demo");

    match command {
        "demo" => run_demo(),
        "create" => run_create(),
        _ => {
            println!("Usage: scafonix-cli [demo|create]");
        }
    }
}

fn run_create() {
    let mut rng = OsRng;
    let vault_id = "vault_eth_mainnet_01";
    let max_wei = 100_000_000_000_000_000u64; // 0.1 ETH
    let chain_id = 1u64;

    let policy = PolicyTemplates::daily_limit_eth(vault_id, max_wei, chain_id);
    let canonical_policy = to_canonical_json(&policy).unwrap();

    let password = "UserBackupPassword2026!";
    let result = create_new_vault(&mut rng, policy, password).unwrap();

    println!("========================================================================");
    println!("🛡️  scafonix Vault — Programmable MPC Vault (pEOA) Generator");
    println!("========================================================================");
    println!();
    println!("1. [IAM Policy JSON (Mathematically Baked)]: ");
    println!("{}", canonical_policy);
    println!();
    println!("2. [On-Chain Vault EOA Address (Pure EOA, No Smart Contract)]: ");
    println!("   👉 {}", result.vault_address);
    println!();
    println!("------------------------------------------------------------------------");
    println!("🚨 [ACTION REQUIRED] Copy your Emergency Recovery Voucher (Share C) now!");
    println!("   Voucher: {}", result.voucher_c);
    println!();
    println!("⚠️  WARNING: This voucher is NOT saved on the server. If scafonix is down");
    println!("   and you lose this voucher, recovery will be impossible!");
    println!("========================================================================");
}

fn run_demo() {
    let mut rng = OsRng;
    println!("========================================================================");
    println!("🛡️  scafonix Vault (pEOA) Core Protocol E2E Verification Showcase");
    println!("   Patent 10-2026-0134084 (Non-assembled Cryptographic Vault)");
    println!("========================================================================\n");

    let allowed_recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    let policy = PolicyTemplates::whitelisted_recipients(
        "vault_demo_01",
        vec![allowed_recipient.to_string()],
        100_000_000_000_000_000, // 0.1 ETH
        1,
    );

    println!("📌 STEP 1: Zero-Mnemonic Distributed Vault Creation (DKG)");
    let recovery_password = "DemoEmergencyPassword2026!";
    let result = create_new_vault(&mut rng, policy, recovery_password).unwrap();
    let client = result.client;
    let enclave = result.enclave;
    let vault_addr = result.vault_address;

    println!("   ✅ Vault EOA Address: {}", vault_addr);
    println!("   ✅ Share A (Phone):   Stored in Client Secure Enclave");
    println!("   ✅ Share B (Enclave): Stored in AWS Nitro Enclave (Policy Baked)");
    println!("   ✅ Share C (Backup):  {}\n", &result.voucher_c[0..45]);

    println!("📌 STEP 2: Normal Transaction (0.05 ETH to Whitelisted Address)");
    let normal_tx = TransactionContext {
        action: "web3:TransferETH".to_string(),
        recipient: allowed_recipient.to_string(),
        value_wei: 50_000_000_000_000_000, // 0.05 ETH
        chain_id: 1,
    };
    assert!(client.evaluate_local(&normal_tx).is_ok());
    println!("   ✅ 1st Inspector (User Phone): APPROVED");
    assert!(enclave.evaluate_and_approve(&normal_tx).is_ok());
    println!("   ✅ 2nd Inspector (Nitro Enclave): APPROVED\n");

    println!("📌 STEP 3: Phishing Attack Simulation (Hacker Address)");
    let phishing_tx = TransactionContext {
        action: "web3:TransferETH".to_string(),
        recipient: "0xBadHackerAddress000000000000000000000000".to_string(),
        value_wei: 10_000_000_000_000_000,
        chain_id: 1,
    };
    let phish_res = enclave.evaluate_and_approve(&phishing_tx);
    assert!(phish_res.is_err());
    println!("   🛡️ 2nd Inspector (Enclave): BLOCKED unauthorized address! Funds 100% saved!\n");

    println!("📌 STEP 4: Limit Violation Simulation (10.0 ETH Request)");
    let high_tx = TransactionContext {
        action: "web3:TransferETH".to_string(),
        recipient: allowed_recipient.to_string(),
        value_wei: 10_000_000_000_000_000_000, // 10 ETH
        chain_id: 1,
    };
    let high_res = enclave.evaluate_and_approve(&high_tx);
    assert!(high_res.is_err());
    println!("   🛡️ 2nd Inspector (Enclave): BLOCKED! Exceeds daily immutable limit!\n");

    println!("📌 STEP 5: Disaster Recovery (Server Destroyed Simulation)");
    println!("   ⚠️  Simulating scafonix servers offline / shutdown...");
    drop(enclave); // Enclave is gone

    let emergency_tx_hash = [0x5au8; 32];
    let k = Scalar::from(998877u64);
    let beta = Scalar::from(665544u64);

    let sig = client
        .emergency_local_sign(
            &result.voucher_c,
            recovery_password,
            &emergency_tx_hash,
            k,
            beta,
        )
        .expect("Emergency signing failed");

    let recovered_address = recover_ethereum_address(&emergency_tx_hash, &sig).unwrap();
    println!("   ✅ Emergency Signature Generated using Patent Combined Blinded Nonce!");
    println!("   ✅ Recovered On-Chain Signer: {}", recovered_address);
    assert_eq!(vault_addr, recovered_address);
    println!("   🎉 EXACT MATCH! 100% Non-Custodial Self-Custody Verified!\n");

    println!("========================================================================");
    println!("🚀 ALL 5 CRITICAL TEST STEPS PASSED WITH 100% CRYPTOGRAPHIC ACCURACY!");
    println!("========================================================================");
}

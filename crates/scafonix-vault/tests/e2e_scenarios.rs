use k256::Scalar;
use rand_core::OsRng;
use scafonix_crypto::recover_ethereum_address;
use scafonix_policy::{PolicyTemplates, TransactionContext};
use scafonix_vault::create_new_vault;

#[test]
fn test_scenario_1_normal_transaction_approval() {
    let mut rng = OsRng;
    let allowed_recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    let policy = PolicyTemplates::whitelisted_recipients(
        "vault-alpha-01",
        vec![allowed_recipient.to_string()],
        1_000_000_000, // 1 Gwei limit
        1,             // Ethereum Mainnet
    );

    let password = "UltraSecurePassword2026!";
    let vault_result = create_new_vault(&mut rng, policy, password).unwrap();
    let client = vault_result.client;
    let enclave = vault_result.enclave;
    let vault_addr = vault_result.vault_address;

    println!("\n=== [SCENARIO 1: NORMAL TRANSACTION APPROVAL] ===");
    println!("Created Vault Address: {}", vault_addr);
    println!("Emergency Voucher (Share C): {}...", &vault_result.voucher_c[0..35]);

    let valid_tx = TransactionContext {
        action: "web3:TransferETH".to_string(),
        recipient: allowed_recipient.to_string(),
        value_wei: 500_000,
        chain_id: 1,
    };

    // 1st Inspector (Client) checks
    assert!(client.evaluate_local(&valid_tx).is_ok());
    println!("✅ 1st Inspector (Client Device): PASSED");

    // 2nd Inspector (Enclave) checks
    assert!(enclave.evaluate_and_approve(&valid_tx).is_ok());
    println!("✅ 2nd Inspector (scafonix Enclave): PASSED");
}

#[test]
fn test_scenario_2_phishing_attack_blocked_by_enclave() {
    let mut rng = OsRng;
    let allowed_recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    let attacker_phishing_address = "0x9999999999999999999999999999999999999999";

    let policy = PolicyTemplates::whitelisted_recipients(
        "vault-alpha-02",
        vec![allowed_recipient.to_string()],
        1_000_000_000,
        1,
    );

    let password = "Password123!";
    let vault_result = create_new_vault(&mut rng, policy, password).unwrap();
    let enclave = vault_result.enclave;

    println!("\n=== [SCENARIO 2: PHISHING ATTACK BLOCKED] ===");

    // Hacker tries to send funds to attacker address
    let phishing_tx = TransactionContext {
        action: "web3:TransferETH".to_string(),
        recipient: attacker_phishing_address.to_string(),
        value_wei: 100_000,
        chain_id: 1,
    };

    let result = enclave.evaluate_and_approve(&phishing_tx);
    assert!(result.is_err());
    println!("🛡️ 2nd Inspector (Enclave): BLOCKED unauthorized phishing destination! Asset 100% saved!");
}

#[test]
fn test_scenario_3_limit_exceeded_blocked_by_enclave() {
    let mut rng = OsRng;
    let allowed_recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

    // Limit is 1,000,000 wei
    let policy = PolicyTemplates::whitelisted_recipients(
        "vault-alpha-03",
        vec![allowed_recipient.to_string()],
        1_000_000,
        1,
    );

    let password = "Password123!";
    let vault_result = create_new_vault(&mut rng, policy, password).unwrap();
    let enclave = vault_result.enclave;

    println!("\n=== [SCENARIO 3: LIMIT EXCEEDED BLOCKED] ===");

    // Attacker tries to drain 100,000,000 wei
    let high_value_tx = TransactionContext {
        action: "web3:TransferETH".to_string(),
        recipient: allowed_recipient.to_string(),
        value_wei: 100_000_000,
        chain_id: 1,
    };

    let result = enclave.evaluate_and_approve(&high_value_tx);
    assert!(result.is_err());
    println!("🛡️ 2nd Inspector (Enclave): BLOCKED high value transaction exceeding immutable limit!");
}

#[test]
fn test_scenario_4_disaster_recovery_when_server_is_destroyed() {
    let mut rng = OsRng;
    let allowed_recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    let policy = PolicyTemplates::whitelisted_recipients(
        "vault-alpha-04",
        vec![allowed_recipient.to_string()],
        1_000_000_000,
        1,
    );

    let recovery_password = "MyEmergencyPassword2026!";
    let vault_result = create_new_vault(&mut rng, policy, recovery_password).unwrap();
    let client = vault_result.client;
    let vault_address = vault_result.vault_address;
    let voucher_c = vault_result.voucher_c;

    // SIMULATION: scafonix server is completely destroyed / deleted!
    drop(vault_result.enclave);
    println!("\n=== [SCENARIO 4: DISASTER RECOVERY (SERVER DESTROYED)] ===");
    println!("Server is DEAD. Client has Share A and Voucher C.");

    // User signs emergency withdrawal transaction locally
    let emergency_tx_hash = [0xeeu8; 32];
    let k = Scalar::from(444555666u64);
    let beta = Scalar::from(111222333u64);

    let emergency_sig = client
        .emergency_local_sign(
            &voucher_c,
            recovery_password,
            &emergency_tx_hash,
            k,
            beta,
        )
        .expect("Emergency signing must succeed locally");

    // Verify on-chain recovery matches exact vault address
    let recovered_addr = recover_ethereum_address(&emergency_tx_hash, &emergency_sig).unwrap();
    assert_eq!(vault_address, recovered_addr);

    println!("🎉 Emergency Local Withdrawal Signature VERIFIED on-chain!");
    println!("   Vault Address:     {}", vault_address);
    println!("   Recovered Address: {}", recovered_addr);
    println!("✅ 100% Non-Custodial Emergency Escape proven!");
}

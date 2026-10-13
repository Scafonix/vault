# 🛡️ scafonix Vault

> **The Programmable MPC Vault (pEOA)**  
> *Zero Mnemonic, Mathematically Policy-Bound, Pure EOA (Zero Smart Contracts)*

[![License: BSL 1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Patent: Pending](https://img.shields.io/badge/Patent-KR%2010--2026--0134084-green.svg)](#patent-foundation)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![WASM](https://img.shields.io/badge/WebAssembly-secp256k1-purple.svg)](web/pkg)

---

## ⚡ Quick Links
* 🌐 **Web Vault**: [vault.scafonix.com](https://vault.scafonix.com)
* 🔒 **Official Inspector API**: `https://vault-api.scafonix.com`
* 💾 **100% Offline Air-Gap Tool**: [`scafonix-vault-airgap.html`](docs/scafonix-vault-airgap.html)
* 📜 **Patent Application**: KR `10-2026-0134084` (*"분산키 및 결합 은닉 난수 기반의 비조립식 암호 서명 시스템 및 그 방법"*, Inventor: 김부연)

---

## 💡 What is pEOA (Programmable EOA)?

Until now, Web3 users faced a painful dilemma:
1. **Standard EOA (MetaMask / Ledger):** 0 gas setup, standard compatibility, but **vulnerable to phishing, blind signing, and mnemonic paper theft**.
2. **Smart Contract Accounts (ERC-4337):** Programmable rules, but **expensive deployment gas, multi-chain fragmentation, and bridge incompatibilities**.

**scafonix Vault introduces pEOA:** A **pure, standard Ethereum address** where an AWS IAM-style security policy is **cryptographically baked into an MPC key share**.

| Feature | Standard EOA (MetaMask) | ERC-4337 Smart Account | scafonix Vault (pEOA) |
| :--- | :--- | :--- | :--- |
| **On-Chain Contract?** | No (0 gas setup) | Yes (Gas required to deploy) | **No (0 gas setup)** |
| **Mnemonic Storage?** | 12-24 Words (Theft risk) | Varied (Admin key) | **Zero Mnemonic (Never exists)** |
| **Phishing / Hack Protection**| None (Blind signing) | Contract logic | **Enclave Policy Inspector (Veto)** |
| **Server Compromise Risk** | N/A | Paymaster dependent | **Zero (Server cannot sign alone)** |
| **Disaster Recovery** | Paper Seed Words | Social Guardians | **Encrypted Voucher C + Patent Blinded Nonce Sign** |

---

## 🏗️ Cryptographic Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        scafonix pEOA 2-of-2 Architecture               │
│                                                                        │
│  [Party A: Client / Phone Passkey]                                     │
│    - Private Share: sk_A (Kept in local device memory/Passkey)         │
│    - Public Commitment: Q_A = sk_A * G (Transmitted to Inspector)      │
│                                                                        │
│  [Party B: 2nd Inspector / Enclave]                                    │
│    - Canonical Policy Hash: h_p = SHA256(Deterministic_IAM_JSON)       │
│    - Private Share: sk_B = sk_B_seed + h_p                             │
│    - Public Commitment: Q_B = sk_B * G (Returned to Client)            │
│                                                                        │
│  [On-Chain Master EOA Address]                                         │
│    - Joint Public Key: Q = Q_A + Q_B = (sk_A + sk_B) * G               │
│    - Vault Address: keccak256(Q)[12..31] (EIP-55 Checksummed)         │
│                                                                        │
│  [Disaster Recovery Ticket (Share C)]                                  │
│    - Voucher C = AES-256-GCM(sk_B, key: UserPassword)                  │
│    - Output ONCE to user, NEVER stored on scafonix servers.            │
└────────────────────────────────────────────────────────────────────────┘
```

### Key Security Guarantees
1. **Server Veto-Only Power**: The client's partial signature $s_A$ is cryptographically bound to the raw transaction hash $e$. The 2nd inspector **cannot redirect, modify, or steal** any funds. Its only power is to **refuse to sign** if a transaction violates the user's spending policy.
2. **Zero Plaintext Key Assembly**: Even during disaster recovery, the patent algorithm computes $s = s_{blind} \cdot (k \beta)^{-1} \pmod N$, preventing plaintext reconstitution in memory.

---

## 🚀 "Don't Trust, Verify" — Self-Hosting Guide

If you do not wish to rely on scafonix infrastructure, you can run the entire 2nd Inspector on your own server or local machine.

### 1. Run Your Own 2nd Inspector Server
```bash
git clone https://github.com/Scafonix/vault.git
cd vault
cargo run --release -p scafonix-server
```
The server will start on `http://127.0.0.1:3000`.

### 2. Connect via Web or Standalone HTML
Open [vault.scafonix.com](https://vault.scafonix.com) (or double-click `docs/scafonix-vault-airgap.html`), expand **Advanced Network Settings**, and change the Inspector URL to:
```text
http://127.0.0.1:3000
```
Your vault will now operate with 100% self-sovereignty.

---

## 📂 Repository Structure

* `crates/scafonix-policy`: Deterministic AWS IAM Web3 policy parser, canonical JSON serializer, and $h_p$ hash generator.
* `crates/scafonix-crypto`: secp256k1 elliptic curve scalar math, zero-allocation memory zeroization, AES-256-GCM voucher encryption, and Patent KR `10-2026-0134084` zero-assembly signature.
* `crates/scafonix-vault`: High-level orchestration for ClientVault, EnclaveGuardian, and 2-Party DKG factory.
* `crates/scafonix-server`: Axum-based HTTP 2nd Inspector server (`/health`, `/api/v1/dkg`, `/api/v1/cosign`).
* `crates/scafonix-wasm`: WebAssembly engine compiled for client browsers.
* `crates/scafonix-cli`: Utility CLI for creating vaults and running automated E2E simulations.
* `web/` & `docs/`: Minimalist, zero-dependency client tool and Ian Coleman style standalone offline HTML.

---

## 🧪 Testing

Run the full cryptographic test suite:
```bash
cargo test --workspace
```

Run end-to-end policy defense scenarios (Normal approval, Phishing block, Daily limit exceeded block, Disaster recovery escape):
```bash
cargo test --test e2e_scenarios
```

---

## 📜 License & Patent Notice

* **Software License:** [Business Source License 1.1 (BSL 1.1)](LICENSE). Free for personal use, security auditing, non-commercial evaluation, and self-hosted personal vaults. Commercial SaaS hosting or competitive services require a separate commercial license.
* **Patent Application:** Korean Patent Application No. `10-2026-0134084` (*"분산키 및 결합 은닉 난수 기반의 비조립식 암호 서명 시스템 및 그 방법"*).

Copyright (c) 2026 Scafonix. All rights reserved.

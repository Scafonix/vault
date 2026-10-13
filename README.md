# scafonix Vault

A non-custodial 2-Party ECDSA programmable vault (pEOA) for EVM-compatible blockchains.

[![License: BSL 1.1](https://img.shields.io/badge/license-BUSL--1.1-informational.svg)](LICENSE)
[![Patent: Pending](https://img.shields.io/badge/patent-KR%2010--2026--0134084-informational.svg)](#patent-notice)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-informational.svg)](https://www.rust-lang.org/)
[![WebAssembly](https://img.shields.io/badge/wasm-secp256k1-informational.svg)](web/pkg)

---

## Overview

scafonix Vault implements **pEOA (Programmable Externally Owned Account)**: a standard Ethereum address where execution policies (e.g., daily spending limits, contract whitelists) are cryptographically bound to an MPC key share rather than enforced via smart contract bytecode.

Transactions are signed using a 2-of-2 threshold signature scheme. Neither party possesses the full private key at any point.

* **No Smart Contract Deployment:** Standard secp256k1 EOA address. Zero deployment gas, universal EVM chain compatibility, and native bridge support.
* **Zero Mnemonic Generation:** Private keys and seed phrases are never generated, transmitted, or assembled in plaintext.
* **Deterministic Policy Commitment:** The policy hash $h_p$ is added directly into the second key share ($sk_B = sk_{B\_seed} + h_p$). Altering the policy produces a different address.
* **Server Veto-Only Authorization:** The second party (Inspector) can only approve or veto transactions against the agreed policy. It cannot redirect funds or sign arbitrary transactions.
* **Unilateral Disaster Recovery:** An encrypted backup voucher (Share C) allows the user to sign emergency exit transactions locally without server availability, using a blinded nonce scheme (Patent KR 10-2026-0134084).

---

## Cryptographic Specification

```text
+------------------------------------------------------------------------+
|                      scafonix 2-of-2 MPC Topology                      |
|                                                                        |
|  Party A (Client / Passkey)                                            |
|    - Private scalar: sk_A (Kept in client memory / Secure Enclave)     |
|    - Public commitment: Q_A = sk_A * G                                 |
|                                                                        |
|  Party B (Inspector / Server)                                          |
|    - Policy hash: h_p = SHA256(Canonical_IAM_JSON)                    |
|    - Private scalar: sk_B = sk_B_seed + h_p                            |
|    - Public commitment: Q_B = sk_B * G                                 |
|                                                                        |
|  Master On-Chain EOA                                                   |
|    - Joint public key: Q = Q_A + Q_B = (sk_A + sk_B) * G               |
|    - Address: keccak256(Q)[12..31] (EIP-55 formatted)                  |
|                                                                        |
|  Emergency Recovery Voucher (Share C)                                  |
|    - Voucher = AES-256-GCM(sk_B, key: Argon2id(UserPassword))          |
|    - Stored client-side only; never retained by the Inspector          |
+------------------------------------------------------------------------+
```

### Partial Signing Protocol
1. Client constructs raw transaction $tx$ and computes message digest $e = \text{keccak256}(tx)$.
2. Client verifies local policy, signs $e$ using $sk_A$, and transmits $(tx, \text{proof})$ to the Inspector.
3. Inspector independently verifies that $tx$ satisfies the canonical policy document.
4. If approved, Inspector produces partial signature using $sk_B$.
5. The combined signature $(r, s, v)$ verifies against $Q$ on any standard EVM execution client.

---

## Workspace Structure

The project is organized as a Cargo workspace:

* [`crates/scafonix-crypto`](crates/scafonix-crypto): secp256k1 scalar arithmetic, zero-allocation memory zeroization, AES-256-GCM voucher routines, and patent-based non-assembled signing.
* [`crates/scafonix-policy`](crates/scafonix-policy): Deterministic canonical JSON serialization and AWS IAM-style transaction condition evaluators.
* [`crates/scafonix-vault`](crates/scafonix-vault): High-level client and enclave orchestration, 2-party DKG factory, and end-to-end policy enforcement logic.
* [`crates/scafonix-server`](crates/scafonix-server): Axum-based HTTP 2nd Inspector daemon with persistent SQLite storage.
* [`crates/scafonix-wasm`](crates/scafonix-wasm): WebAssembly compilation target exposing in-browser key generation, canonical hashing, and emergency signing.
* [`crates/scafonix-cli`](crates/scafonix-cli): Command-line interface for local verification and automated scenario simulation.
* [`web`](web) / [`docs`](docs): Minimal, dependency-free web interface and standalone single-file offline air-gap tool (`scafonix-vault-airgap.html`).

---

## Getting Started

### Prerequisites
* Rust 1.80 or later (`cargo`, `rustc`)
* `wasm-pack` (optional, for compiling WebAssembly)
* SQLite 3 (bundled with `rusqlite`)

### Building from Source
```bash
git clone https://github.com/Scafonix/vault.git
cd vault
cargo build --release
```

### Running the Test Suite
The workspace includes unit tests and end-to-end adversarial defense scenarios (normal approval, phishing address rejection, spending limit violation, and disaster recovery):

```bash
cargo test --workspace
```

---

## Self-Hosting the Inspector

For complete autonomy, you may run your own 2nd Inspector daemon on local hardware or private cloud infrastructure.

### 1. Launch the Server Daemon
```bash
cargo run --release -p scafonix-server
```
By default, the server binds to `0.0.0.0:3000` and creates a persistent SQLite database at `./vault.db` (or `/var/lib/scafonix-vault/vault.db` in production Linux environments).

Environment configuration:
```bash
PORT=3000
DATABASE_PATH=/var/lib/scafonix-vault/vault.db
RUST_LOG=info
```

### 2. Connect Your Client
Open [vault.scafonix.com](https://vault.scafonix.com) (or the offline air-gap file `docs/scafonix-vault-airgap.html`), expand **Advanced Network Settings**, and specify your self-hosted endpoint:
```text
http://127.0.0.1:3000
```

---

## Deployment & Production Notes

A systemd service unit and setup script are provided in [`deploy/`](deploy):

```bash
# Setup systemd service and directories
sudo ./deploy/setup_server.sh
```

Nginx configuration example:
```nginx
server {
    listen 80;
    server_name vault-api.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Patent Notice

This implementation incorporates technologies described in Korean Patent Application No. `10-2026-0134084` (*"분산키 및 결합 은닉 난수 기반의 비조립식 암호 서명 시스템 및 그 방법"*, Inventor: 김부연).

---

## License

This project is licensed under the [Business Source License 1.1 (BSL 1.1)](LICENSE).

* **Non-Commercial & Self-Hosting:** Free for personal use, security audits, academic research, and self-hosted personal vaults.
* **Commercial Services:** Commercial SaaS hosting or competitive services require a commercial license agreement.

---

## Contact & Inquiries

For enterprise deployment, custom policy modules, security audits, or partnerships:
* **Email:** [contact@scafonix.com](mailto:contact@scafonix.com)
* **Website:** [scafonix.com](https://scafonix.com)

Copyright (c) 2026 Scafonix. All rights reserved.

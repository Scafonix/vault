use anyhow::{Context, Result};
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use rusqlite::{params, Connection};
use scafonix_crypto::ShareB;
use scafonix_policy::PolicyDocument;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct StoredVault {
    pub vault_address: String,
    pub policy: PolicyDocument,
    pub policy_hash: [u8; 32],
    pub share_b: ShareB,
    pub client_qa_hex: String,
    pub created_at: String,
}

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
    db_path: PathBuf,
}

impl Database {
    pub fn open_default() -> Result<Self> {
        let db_path = resolve_db_path();
        Self::open(&db_path)
    }

    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create database directory: {:?}", parent))?;
            }
        }

        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open SQLite database at {:?}", path))?;

        // Enable WAL mode for high concurrency and crash durability
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             
             CREATE TABLE IF NOT EXISTS vaults (
                 vault_address TEXT PRIMARY KEY,
                 policy_json TEXT NOT NULL,
                 policy_hash TEXT NOT NULL,
                 share_b_hex TEXT NOT NULL,
                 client_qa_hex TEXT NOT NULL,
                 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
             );
             
             CREATE INDEX IF NOT EXISTS idx_vaults_created_at ON vaults(created_at);",
        )
        .context("Failed to initialize database schema")?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: path.to_path_buf(),
        })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn insert_vault(
        &self,
        vault_address: &str,
        policy: &PolicyDocument,
        policy_hash: &[u8; 32],
        share_b: &ShareB,
        client_qa_hex: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let policy_json = serde_json::to_string(policy)?;
        let policy_hash_hex = hex::encode(policy_hash);
        let share_b_hex = hex::encode(share_b.scalar().to_bytes());

        conn.execute(
            "INSERT OR REPLACE INTO vaults (vault_address, policy_json, policy_hash, share_b_hex, client_qa_hex)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                vault_address.to_ascii_lowercase(),
                policy_json,
                policy_hash_hex,
                share_b_hex,
                client_qa_hex,
            ],
        )?;

        Ok(())
    }

    pub fn get_vault(&self, vault_address: &str) -> Result<Option<StoredVault>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT vault_address, policy_json, policy_hash, share_b_hex, client_qa_hex, created_at 
             FROM vaults WHERE vault_address = ?1",
        )?;

        let mut rows = stmt.query(params![vault_address.to_ascii_lowercase()])?;

        if let Some(row) = rows.next()? {
            let addr: String = row.get(0)?;
            let policy_json: String = row.get(1)?;
            let policy_hash_hex: String = row.get(2)?;
            let share_b_hex: String = row.get(3)?;
            let client_qa_hex: String = row.get(4)?;
            let created_at: String = row.get(5)?;

            let policy: PolicyDocument = serde_json::from_str(&policy_json)?;
            let hash_bytes = hex::decode(&policy_hash_hex)?;
            let mut policy_hash = [0u8; 32];
            policy_hash.copy_from_slice(&hash_bytes);

            let sb_bytes = hex::decode(&share_b_hex)?;
            let mut sb_arr = [0u8; 32];
            sb_arr.copy_from_slice(&sb_bytes);
            let scalar_b = Option::from(Scalar::from_repr(sb_arr.into()))
                .ok_or_else(|| anyhow::anyhow!("Invalid scalar in DB"))?;

            let share_b = ShareB::from_scalar(scalar_b);

            Ok(Some(StoredVault {
                vault_address: addr,
                policy,
                policy_hash,
                share_b,
                client_qa_hex,
                created_at,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn count_vaults(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: usize = conn.query_row("SELECT COUNT(*) FROM vaults", [], |r| r.get(0))?;
        Ok(count)
    }
}

fn resolve_db_path() -> PathBuf {
    if let Ok(env_path) = std::env::var("DATABASE_PATH") {
        return PathBuf::from(env_path);
    }

    // In production on Linux server, default to /var/lib/scafonix-vault/vault.db
    let prod_dir = Path::new("/var/lib/scafonix-vault");
    if prod_dir.exists() {
        return prod_dir.join("vault.db");
    }

    // Fallback for local development or non-root environments: ./data/vault.db or ./vault.db
    let data_dir = Path::new("data");
    if data_dir.exists() {
        return data_dir.join("vault.db");
    }

    PathBuf::from("vault.db")
}

#[cfg(test)]
mod tests {
    use super::*;
    use scafonix_crypto::ShareB;
    use scafonix_policy::{PolicyDocument, Statement};

    #[test]
    fn test_sqlite_persistence() {
        let temp_dir = std::env::temp_dir();
        let db_file = temp_dir.join(format!("test_vault_{}.db", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));

        {
            let db = Database::open(&db_file).unwrap();
            assert_eq!(db.count_vaults().unwrap(), 0);

            let policy = PolicyDocument {
                version: "2026-v1".to_string(),
                vault_id: "test_v1".to_string(),
                statement: vec![Statement {
                    sid: Some("Test".to_string()),
                    effect: scafonix_policy::Effect::Allow,
                    action: vec!["web3:TransferETH".to_string()],
                    resource: vec!["*".to_string()],
                    condition: None,
                }],
            };
            let policy_hash = [42u8; 32];
            let share_b = ShareB::from_scalar(Scalar::from(123456789u64));

            db.insert_vault("0x1234567890abcdef1234567890abcdef12345678", &policy, &policy_hash, &share_b, "04abcdef").unwrap();
            assert_eq!(db.count_vaults().unwrap(), 1);
        }

        // Reopen the database from disk - simulates server reboot
        {
            let db = Database::open(&db_file).unwrap();
            assert_eq!(db.count_vaults().unwrap(), 1);

            let stored = db.get_vault("0x1234567890abcdef1234567890abcdef12345678").unwrap().unwrap();
            assert_eq!(stored.vault_address, "0x1234567890abcdef1234567890abcdef12345678");
            assert_eq!(stored.policy.vault_id, "test_v1");
            assert_eq!(stored.policy_hash, [42u8; 32]);
            assert_eq!(stored.share_b.scalar(), &Scalar::from(123456789u64));
        }

        let _ = std::fs::remove_file(db_file);
    }
}


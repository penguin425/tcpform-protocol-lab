//! SQLite-backed persistence for shared visualizer state and background jobs.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static IDS: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct Store {
    path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub status: String,
    pub payload: Value,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub attempt: u32,
    pub cancel_requested: bool,
    pub progress: f64,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let store = Self {
            path: path.as_ref().to_path_buf(),
        };
        let connection = store.connection()?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA foreign_keys=ON;
                 CREATE TABLE IF NOT EXISTS runs(
                   id TEXT PRIMARY KEY, protocol TEXT NOT NULL, status TEXT NOT NULL,
                   created_at INTEGER NOT NULL, document TEXT NOT NULL);
                 CREATE INDEX IF NOT EXISTS runs_protocol_created ON runs(protocol,created_at DESC);
                 CREATE TABLE IF NOT EXISTS baselines(
                   id TEXT PRIMARY KEY, protocol TEXT NOT NULL, name TEXT NOT NULL,
                   created_at INTEGER NOT NULL, document TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS annotations(
                   id TEXT PRIMARY KEY, protocol TEXT NOT NULL, event_index INTEGER NOT NULL,
                   step TEXT NOT NULL, text TEXT NOT NULL, author TEXT NOT NULL,
                   created_at INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS jobs(
                   id TEXT PRIMARY KEY, status TEXT NOT NULL, payload TEXT NOT NULL,
                   result TEXT, error TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                   attempt INTEGER NOT NULL DEFAULT 0, cancel_requested INTEGER NOT NULL DEFAULT 0,
                   progress REAL NOT NULL DEFAULT 0);
                 CREATE INDEX IF NOT EXISTS jobs_status_created ON jobs(status,created_at);
                 CREATE TABLE IF NOT EXISTS audit_log(
                   id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL,
                   actor TEXT NOT NULL, action TEXT NOT NULL, resource TEXT NOT NULL,
                   outcome TEXT NOT NULL, detail TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS corpus(
                   id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, protocol TEXT NOT NULL,
                   status TEXT NOT NULL, occurrences INTEGER NOT NULL DEFAULT 1,
                   first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, document TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS shares(
                   id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER,
                   document TEXT NOT NULL);",
            )
            .map_err(|error| error.to_string())?;
        drop(connection);
        let _ = store.connection()?.execute(
            "ALTER TABLE jobs ADD COLUMN progress REAL NOT NULL DEFAULT 0",
            [],
        );
        store.recover_jobs()?;
        Ok(store)
    }

    fn connection(&self) -> Result<Connection, String> {
        Connection::open(&self.path).map_err(|error| error.to_string())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save_run(
        &self,
        protocol: &str,
        status: &str,
        document: &Value,
    ) -> Result<String, String> {
        let id = new_id("run");
        self.connection()?
            .execute(
                "INSERT INTO runs(id,protocol,status,created_at,document) VALUES(?1,?2,?3,?4,?5)",
                params![id, protocol, status, now(), document.to_string()],
            )
            .map_err(|error| error.to_string())?;
        Ok(id)
    }

    pub fn list_runs(&self, protocol: Option<&str>, limit: usize) -> Result<Vec<Value>, String> {
        let connection = self.connection()?;
        let sql = if protocol.is_some() {
            "SELECT id,protocol,status,created_at,document FROM runs WHERE protocol=?1 ORDER BY created_at DESC LIMIT ?2"
        } else {
            "SELECT id,protocol,status,created_at,document FROM runs ORDER BY created_at DESC LIMIT ?2"
        };
        let mut statement = connection.prepare(sql).map_err(|error| error.to_string())?;
        let collect = |row: &rusqlite::Row<'_>| -> rusqlite::Result<Value> {
            let document: String = row.get(4)?;
            Ok(
                json!({"id":row.get::<_,String>(0)?,"protocol":row.get::<_,String>(1)?,
                "status":row.get::<_,String>(2)?,"created_at":row.get::<_,i64>(3)?,
                "document":serde_json::from_str::<Value>(&document).unwrap_or(Value::Null)}),
            )
        };
        let rows = if let Some(protocol) = protocol {
            statement.query_map(params![protocol, limit.min(10_000) as i64], collect)
        } else {
            statement.query_map(params![limit.min(10_000) as i64], collect)
        }
        .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    pub fn save_baseline(
        &self,
        protocol: &str,
        name: &str,
        document: &Value,
    ) -> Result<String, String> {
        let id = new_id("baseline");
        self.connection()?.execute(
            "INSERT INTO baselines(id,protocol,name,created_at,document) VALUES(?1,?2,?3,?4,?5)",
            params![id,protocol,name,now(),document.to_string()],
        ).map_err(|error| error.to_string())?;
        Ok(id)
    }

    pub fn add_annotation(
        &self,
        protocol: &str,
        event_index: usize,
        step: &str,
        text: &str,
        author: &str,
    ) -> Result<String, String> {
        let id = new_id("annotation");
        self.connection()?.execute(
            "INSERT INTO annotations(id,protocol,event_index,step,text,author,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![id,protocol,event_index as i64,step,text,author,now()],
        ).map_err(|error| error.to_string())?;
        Ok(id)
    }

    pub fn create_job(&self, payload: &Value) -> Result<Job, String> {
        let id = new_id("job");
        let timestamp = now();
        self.connection()?.execute(
            "INSERT INTO jobs(id,status,payload,created_at,updated_at) VALUES(?1,'queued',?2,?3,?3)",
            params![id,payload.to_string(),timestamp],
        ).map_err(|error| error.to_string())?;
        self.get_job(&id)?.ok_or("created job is missing".into())
    }

    pub fn get_job(&self, id: &str) -> Result<Option<Job>, String> {
        self.connection()?.query_row(
            "SELECT id,status,payload,result,error,created_at,updated_at,attempt,cancel_requested,progress FROM jobs WHERE id=?1",
            params![id],job_row,
        ).optional().map_err(|error| error.to_string())
    }

    pub fn list_jobs(&self, limit: usize) -> Result<Vec<Job>, String> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id,status,payload,result,error,created_at,updated_at,attempt,cancel_requested,progress FROM jobs ORDER BY created_at DESC LIMIT ?1"
        ).map_err(|error| error.to_string())?;
        let jobs = statement
            .query_map(params![limit.min(10_000) as i64], job_row)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        Ok(jobs)
    }

    pub fn claim_job(&self) -> Result<Option<Job>, String> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let id: Option<String> = transaction.query_row(
            "SELECT id FROM jobs WHERE status='queued' AND cancel_requested=0 ORDER BY created_at LIMIT 1",
            [], |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        let Some(id) = id else { return Ok(None) };
        transaction
            .execute(
                "UPDATE jobs SET status='running',updated_at=?2,attempt=attempt+1,progress=0.05 WHERE id=?1",
                params![id, now()],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        self.get_job(&id)
    }

    pub fn finish_job(&self, id: &str, result: Result<&Value, &str>) -> Result<(), String> {
        let (status, document, error) = match result {
            Ok(value) => ("completed", Some(value.to_string()), None),
            Err(error) => ("failed", None, Some(error.to_string())),
        };
        self.connection()?
            .execute(
                "UPDATE jobs SET status=CASE WHEN cancel_requested=1 THEN 'cancelled' ELSE ?2 END,result=CASE WHEN cancel_requested=1 THEN NULL ELSE ?3 END,error=CASE WHEN cancel_requested=1 THEN 'cancelled by user' ELSE ?4 END,updated_at=?5,progress=1 WHERE id=?1",
                params![id, status, document, error, now()],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn update_job_progress(&self, id: &str, progress: f64) -> Result<(), String> {
        self.connection()?
            .execute(
                "UPDATE jobs SET progress=?2,updated_at=?3 WHERE id=?1 AND status='running'",
                params![id, progress.clamp(0.0, 0.99), now()],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn cancel_job(&self, id: &str) -> Result<bool, String> {
        let changed = self.connection()?.execute(
            "UPDATE jobs SET cancel_requested=1,status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,updated_at=?2 WHERE id=?1 AND status IN ('queued','running')",
            params![id,now()],
        ).map_err(|error| error.to_string())?;
        Ok(changed > 0)
    }

    pub fn retry_job(&self, id: &str) -> Result<bool, String> {
        let changed = self.connection()?.execute(
            "UPDATE jobs SET status='queued',result=NULL,error=NULL,cancel_requested=0,updated_at=?2,progress=0 WHERE id=?1 AND status IN ('failed','cancelled','completed')",
            params![id,now()],
        ).map_err(|error| error.to_string())?;
        Ok(changed > 0)
    }

    pub fn recover_jobs(&self) -> Result<usize, String> {
        self.connection()?.execute(
            "UPDATE jobs SET status='queued',updated_at=?1 WHERE status='running' AND cancel_requested=0",
            params![now()],
        ).map_err(|error| error.to_string())
    }

    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        outcome: &str,
        detail: &str,
    ) -> Result<(), String> {
        self.connection()?.execute(
            "INSERT INTO audit_log(created_at,actor,action,resource,outcome,detail) VALUES(?1,?2,?3,?4,?5,?6)",
            params![now(),actor,action,resource,outcome,detail],
        ).map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn record_corpus(&self, protocol: &str, document: &Value) -> Result<String, String> {
        let fingerprint = format!(
            "{:x}",
            sha2::Sha256::digest(document.to_string().as_bytes())
        );
        let id = new_id("corpus");
        let timestamp = now();
        self.connection()?.execute(
            "INSERT INTO corpus(id,fingerprint,protocol,status,occurrences,first_seen,last_seen,document) VALUES(?1,?2,?3,'active',1,?4,?4,?5) ON CONFLICT(fingerprint) DO UPDATE SET occurrences=occurrences+1,last_seen=excluded.last_seen",
            params![id,fingerprint,protocol,timestamp,document.to_string()],
        ).map_err(|error|error.to_string())?;
        Ok(fingerprint)
    }

    pub fn list_corpus(&self, limit: usize) -> Result<Vec<Value>, String> {
        let connection = self.connection()?;
        let mut statement=connection.prepare("SELECT id,fingerprint,protocol,status,occurrences,first_seen,last_seen,document FROM corpus ORDER BY last_seen DESC LIMIT ?1").map_err(|e|e.to_string())?;
        let rows=statement.query_map(params![limit.min(10_000) as i64],|row| { let document:String=row.get(7)?; Ok(json!({"id":row.get::<_,String>(0)?,"fingerprint":row.get::<_,String>(1)?,"protocol":row.get::<_,String>(2)?,"status":row.get::<_,String>(3)?,"occurrences":row.get::<_,i64>(4)?,"first_seen":row.get::<_,i64>(5)?,"last_seen":row.get::<_,i64>(6)?,"document":serde_json::from_str::<Value>(&document).unwrap_or(Value::Null)})) }).map_err(|e|e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
        Ok(rows)
    }

    pub fn create_share(
        &self,
        document: &Value,
        ttl_seconds: Option<u64>,
    ) -> Result<String, String> {
        let id = new_id("share");
        let created = now();
        let expires =
            ttl_seconds.map(|ttl| created.saturating_add(ttl.min(i64::MAX as u64) as i64));
        self.connection()?
            .execute(
                "INSERT INTO shares(id,created_at,expires_at,document) VALUES(?1,?2,?3,?4)",
                params![id, created, expires, document.to_string()],
            )
            .map_err(|e| e.to_string())?;
        Ok(id)
    }

    pub fn get_share(&self, id: &str) -> Result<Option<Value>, String> {
        self.connection()?.query_row("SELECT document FROM shares WHERE id=?1 AND (expires_at IS NULL OR expires_at>=?2)",params![id,now()],|row|{let value:String=row.get(0)?;Ok(serde_json::from_str(&value).unwrap_or(Value::Null))}).optional().map_err(|e|e.to_string())
    }

    pub fn promote_corpus(&self, fingerprint: &str) -> Result<bool, String> {
        Ok(self
            .connection()?
            .execute(
                "UPDATE corpus SET status='regression' WHERE fingerprint=?1",
                params![fingerprint],
            )
            .map_err(|error| error.to_string())?
            > 0)
    }

    pub fn corpus_revalidation_payloads(&self) -> Result<Vec<Value>, String> {
        Ok(self.list_corpus(10_000)?.into_iter().filter(|value| value["status"] == "regression").filter_map(|value| {
            let document=&value["document"];
            Some(json!({"files":document.get("sources")?.clone(),"root":document.get("root")?.clone(),"protocol":document.pointer("/manifest/protocol/name")?.clone()}))
        }).collect())
    }

    pub fn prune(&self, retention_days: u64) -> Result<usize, String> {
        let cutoff = now().saturating_sub((retention_days.saturating_mul(86_400)) as i64);
        let connection = self.connection()?;
        let mut removed = 0;
        for table in ["runs", "baselines", "annotations", "audit_log"] {
            removed += connection
                .execute(
                    &format!("DELETE FROM {table} WHERE created_at < ?1"),
                    params![cutoff],
                )
                .map_err(|error| error.to_string())?;
        }
        Ok(removed)
    }
}

fn job_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Job> {
    let payload: String = row.get(2)?;
    let result: Option<String> = row.get(3)?;
    Ok(Job {
        id: row.get(0)?,
        status: row.get(1)?,
        payload: serde_json::from_str(&payload).unwrap_or(Value::Null),
        result: result.and_then(|value| serde_json::from_str(&value).ok()),
        error: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
        attempt: row.get(7)?,
        cancel_requested: row.get::<_, i64>(8)? != 0,
        progress: row.get(9)?,
    })
}

fn new_id(prefix: &str) -> String {
    format!(
        "{prefix}-{:x}-{:x}",
        now(),
        IDS.fetch_add(1, Ordering::Relaxed)
    )
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_store_persists_runs_annotations_and_recoverable_jobs() {
        let path =
            std::env::temp_dir().join(format!("tcpform-store-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).unwrap();
        store.save_run("p", "ok", &json!({"events":[]})).unwrap();
        store
            .save_baseline("p", "known", &json!({"events":[]}))
            .unwrap();
        store
            .add_annotation("p", 0, "open", "note", "tester")
            .unwrap();
        assert_eq!(store.list_runs(Some("p"), 10).unwrap().len(), 1);
        let job = store.create_job(&json!({"source":"x"})).unwrap();
        assert_eq!(store.claim_job().unwrap().unwrap().id, job.id);
        drop(store);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.get_job(&job.id).unwrap().unwrap().status, "queued");
        reopened.cancel_job(&job.id).unwrap();
        assert_eq!(
            reopened.get_job(&job.id).unwrap().unwrap().status,
            "cancelled"
        );
        reopened
            .record_corpus("p", &json!({"failure":"x"}))
            .unwrap();
        reopened
            .record_corpus("p", &json!({"failure":"x"}))
            .unwrap();
        assert_eq!(reopened.list_corpus(10).unwrap()[0]["occurrences"], 2);
        let share = reopened
            .create_share(&json!({"trace":[]}), Some(60))
            .unwrap();
        assert!(reopened.get_share(&share).unwrap().is_some());
        std::fs::remove_file(path).unwrap();
    }
}

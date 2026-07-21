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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunMetadata {
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub environment: Option<String>,
    pub source: Option<String>,
    pub duration_us: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunFilter {
    pub protocol: Option<String>,
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub environment: Option<String>,
    pub status: Option<String>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub limit: usize,
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
        for migration in [
            "ALTER TABLE runs ADD COLUMN branch TEXT",
            "ALTER TABLE runs ADD COLUMN commit_sha TEXT",
            "ALTER TABLE runs ADD COLUMN environment TEXT",
            "ALTER TABLE runs ADD COLUMN source TEXT",
            "ALTER TABLE runs ADD COLUMN duration_us INTEGER",
        ] {
            let _ = store.connection()?.execute(migration, []);
        }
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
        self.save_run_with_metadata(protocol, status, document, &RunMetadata::default())
    }

    pub fn save_run_with_metadata(
        &self,
        protocol: &str,
        status: &str,
        document: &Value,
        metadata: &RunMetadata,
    ) -> Result<String, String> {
        let id = new_id("run");
        self.connection()?
            .execute(
                "INSERT INTO runs(id,protocol,status,created_at,document,branch,commit_sha,environment,source,duration_us) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![id, protocol, status, now(), document.to_string(), metadata.branch,
                    metadata.commit, metadata.environment, metadata.source,
                    metadata.duration_us.map(|value| value.min(i64::MAX as u64) as i64)],
            )
            .map_err(|error| error.to_string())?;
        Ok(id)
    }

    pub fn list_runs(&self, protocol: Option<&str>, limit: usize) -> Result<Vec<Value>, String> {
        self.list_runs_filtered(&RunFilter {
            protocol: protocol.map(str::to_string),
            limit,
            ..RunFilter::default()
        })
    }

    pub fn list_runs_filtered(&self, filter: &RunFilter) -> Result<Vec<Value>, String> {
        let connection = self.connection()?;
        let sql = "SELECT id,protocol,status,created_at,document,branch,commit_sha,environment,source,duration_us FROM runs ORDER BY created_at DESC,rowid DESC LIMIT ?1";
        let mut statement = connection.prepare(sql).map_err(|error| error.to_string())?;
        let collect = |row: &rusqlite::Row<'_>| -> rusqlite::Result<Value> {
            let document: String = row.get(4)?;
            Ok(
                json!({"id":row.get::<_,String>(0)?,"protocol":row.get::<_,String>(1)?,
                "status":row.get::<_,String>(2)?,"created_at":row.get::<_,i64>(3)?,
                "document":serde_json::from_str::<Value>(&document).unwrap_or(Value::Null),
                "branch":row.get::<_,Option<String>>(5)?,"commit":row.get::<_,Option<String>>(6)?,
                "environment":row.get::<_,Option<String>>(7)?,"source":row.get::<_,Option<String>>(8)?,
                "duration_us":row.get::<_,Option<i64>>(9)?}),
            )
        };
        let rows = statement
            .query_map(params![10_000i64], collect)
            .map_err(|error| error.to_string())?;
        let mut values = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        values.retain(|run| run_matches(run, filter));
        values.truncate(filter.limit.clamp(1, 10_000));
        Ok(values)
    }

    pub fn get_run(&self, id: &str) -> Result<Option<Value>, String> {
        self.connection()?
            .query_row(
                "SELECT id,protocol,status,created_at,document,branch,commit_sha,environment,source,duration_us FROM runs WHERE id=?1",
                params![id],
                |row| {
                    let document: String = row.get(4)?;
                    Ok(json!({"id":row.get::<_,String>(0)?,"protocol":row.get::<_,String>(1)?,
                        "status":row.get::<_,String>(2)?,"created_at":row.get::<_,i64>(3)?,
                        "document":serde_json::from_str::<Value>(&document).unwrap_or(Value::Null),
                        "branch":row.get::<_,Option<String>>(5)?,"commit":row.get::<_,Option<String>>(6)?,
                        "environment":row.get::<_,Option<String>>(7)?,"source":row.get::<_,Option<String>>(8)?,
                        "duration_us":row.get::<_,Option<i64>>(9)?}))
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn run_summary(&self, filter: &RunFilter) -> Result<Value, String> {
        let runs = self.list_runs_filtered(&RunFilter {
            limit: 10_000,
            ..filter.clone()
        })?;
        let total = runs.len();
        let passed = runs
            .iter()
            .filter(|run| run["status"] == "ok" || run["status"] == "pass")
            .count();
        let mut durations = runs
            .iter()
            .filter_map(|run| run["duration_us"].as_u64())
            .collect::<Vec<_>>();
        durations.sort_unstable();
        let p95 = durations
            .get(
                durations
                    .len()
                    .saturating_mul(95)
                    .div_ceil(100)
                    .saturating_sub(1),
            )
            .copied();
        let mut outcomes =
            std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
        for run in &runs {
            for (name, status) in test_outcomes(&run["document"]) {
                outcomes.entry(name).or_default().insert(status);
            }
        }
        let flaky = outcomes
            .into_iter()
            .filter(|(_, states)| states.contains("pass") && states.contains("fail"))
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        Ok(
            json!({"total":total,"passed":passed,"failed":total.saturating_sub(passed),
            "success_rate":if total == 0 { 0.0 } else { passed as f64 / total as f64 },
            "p95_duration_us":p95,"flaky_tests":flaky,
            "trend":runs.iter().rev().map(|run| json!({"id":run["id"],"created_at":run["created_at"],"status":run["status"],"duration_us":run["duration_us"]})).collect::<Vec<_>>() }),
        )
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
        let fingerprint =
            crate::bytes_to_hex(&sha2::Sha256::digest(document.to_string().as_bytes()));
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

    pub fn corpus_regression_bundle(&self, fingerprint: &str) -> Result<Option<Value>, String> {
        let entry = self
            .list_corpus(10_000)?
            .into_iter()
            .find(|value| value["fingerprint"] == fingerprint);
        Ok(entry.and_then(|entry| {
            let document = &entry["document"];
            Some(json!({
                "format":"tcpform-regression-case","version":1,
                "name":format!("regression-{}", &fingerprint[..fingerprint.len().min(12)]),
                "fingerprint":fingerprint,"protocol":entry["protocol"],
                "expected_status":"ok","sources":document.get("sources")?.clone(),
                "root":document.get("root")?.clone(),"original_failure":document.clone()
            }))
        }))
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
        for (table, column) in [
            ("runs", "created_at"),
            ("baselines", "created_at"),
            ("annotations", "created_at"),
            ("audit_log", "created_at"),
            ("jobs", "created_at"),
            ("corpus", "last_seen"),
            ("shares", "created_at"),
        ] {
            removed += connection
                .execute(
                    &format!("DELETE FROM {table} WHERE {column} < ?1"),
                    params![cutoff],
                )
                .map_err(|error| error.to_string())?;
        }
        Ok(removed)
    }

    pub fn retention_status(&self, retention_days: u64) -> Result<Value, String> {
        let cutoff = now().saturating_sub((retention_days.saturating_mul(86_400)) as i64);
        let connection = self.connection()?;
        let mut tables = serde_json::Map::new();
        for (table, column) in [
            ("runs", "created_at"),
            ("baselines", "created_at"),
            ("annotations", "created_at"),
            ("audit_log", "created_at"),
            ("jobs", "created_at"),
            ("corpus", "last_seen"),
            ("shares", "created_at"),
        ] {
            let total: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .map_err(|error| error.to_string())?;
            let expired: i64 = connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column} < ?1"),
                    params![cutoff],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            tables.insert(table.into(), json!({"total":total,"expired":expired}));
        }
        let bytes = std::fs::metadata(&self.path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        Ok(
            json!({"retention_days":retention_days,"cutoff":cutoff,"database_bytes":bytes,"tables":tables}),
        )
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

fn run_matches(run: &Value, filter: &RunFilter) -> bool {
    let equals = |field: &str, expected: &Option<String>| {
        expected
            .as_deref()
            .is_none_or(|value| run.get(field).and_then(Value::as_str) == Some(value))
    };
    equals("protocol", &filter.protocol)
        && equals("branch", &filter.branch)
        && equals("commit", &filter.commit)
        && equals("environment", &filter.environment)
        && equals("status", &filter.status)
        && filter
            .from
            .is_none_or(|value| run["created_at"].as_i64().is_some_and(|time| time >= value))
        && filter
            .to
            .is_none_or(|value| run["created_at"].as_i64().is_some_and(|time| time <= value))
}

fn test_outcomes(document: &Value) -> Vec<(String, String)> {
    if let Some(documents) = document.get("documents").and_then(Value::as_object) {
        return documents
            .iter()
            .map(|(name, value)| {
                let status = if value
                    .get("status")
                    .and_then(Value::as_str)
                    .is_some_and(|status| status == "fail")
                    || value
                        .get("events")
                        .and_then(Value::as_array)
                        .is_some_and(|events| {
                            events
                                .iter()
                                .any(|event| event.get("ok") == Some(&Value::Bool(false)))
                        }) {
                    "fail"
                } else {
                    "pass"
                };
                (name.clone(), status.into())
            })
            .collect();
    }
    document
        .get("tests")
        .and_then(Value::as_array)
        .map(|tests| {
            tests
                .iter()
                .enumerate()
                .map(|(index, test)| {
                    let name = test
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("test-{index}"));
                    let status = test
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    (
                        name,
                        if matches!(status, "ok" | "pass" | "passed") {
                            "pass"
                        } else {
                            "fail"
                        }
                        .into(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn normalize_run_import(
    format: &str,
    content: &Value,
) -> Result<(String, String, Value, RunMetadata), String> {
    match format {
        "junit" => {
            let xml = content
                .as_str()
                .ok_or("JUnit content must be an XML string")?;
            let mut reader = quick_xml::Reader::from_str(xml);
            let mut tests = Vec::new();
            let mut current: Option<(String, bool)> = None;
            loop {
                match reader.read_event().map_err(|error| error.to_string())? {
                    quick_xml::events::Event::Start(event)
                        if event.name().as_ref() == b"testcase" =>
                    {
                        let name = event
                            .attributes()
                            .flatten()
                            .find(|attribute| attribute.key.as_ref() == b"name")
                            .and_then(|attribute| {
                                String::from_utf8(attribute.value.into_owned()).ok()
                            })
                            .unwrap_or_else(|| "unnamed".into());
                        current = Some((name, false));
                    }
                    quick_xml::events::Event::Empty(event)
                        if event.name().as_ref() == b"testcase" =>
                    {
                        let name = event
                            .attributes()
                            .flatten()
                            .find(|attribute| attribute.key.as_ref() == b"name")
                            .and_then(|attribute| {
                                String::from_utf8(attribute.value.into_owned()).ok()
                            })
                            .unwrap_or_else(|| "unnamed".into());
                        tests.push(json!({"name":name,"status":"pass"}));
                    }
                    quick_xml::events::Event::Start(event)
                        if matches!(event.name().as_ref(), b"failure" | b"error") =>
                    {
                        if let Some((_, failed)) = current.as_mut() {
                            *failed = true;
                        }
                    }
                    quick_xml::events::Event::Empty(event)
                        if matches!(event.name().as_ref(), b"failure" | b"error") =>
                    {
                        if let Some((_, failed)) = current.as_mut() {
                            *failed = true;
                        }
                    }
                    quick_xml::events::Event::End(event)
                        if event.name().as_ref() == b"testcase" =>
                    {
                        if let Some((name, failed)) = current.take() {
                            tests.push(
                                json!({"name":name,"status":if failed {"fail"} else {"pass"}}),
                            );
                        }
                    }
                    quick_xml::events::Event::Eof => break,
                    _ => {}
                }
            }
            let failed = tests.iter().any(|test| test["status"] == "fail");
            Ok((
                "junit".into(),
                if failed { "fail" } else { "ok" }.into(),
                json!({"format":"junit","tests":tests}),
                RunMetadata {
                    source: Some("junit".into()),
                    ..RunMetadata::default()
                },
            ))
        }
        "sarif" => {
            let results = content
                .pointer("/runs/0/results")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let tests = results.iter().enumerate().map(|(index, result)| json!({
                "name":result.get("ruleId").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| format!("result-{index}")),
                "status":if result.get("level").and_then(Value::as_str).is_some_and(|level| matches!(level,"error"|"warning")) {"fail"} else {"pass"}
            })).collect::<Vec<_>>();
            let failed = tests.iter().any(|test| test["status"] == "fail");
            Ok((
                "sarif".into(),
                if failed { "fail" } else { "ok" }.into(),
                json!({"format":"sarif","tests":tests,"raw":content}),
                RunMetadata {
                    source: Some("sarif".into()),
                    ..RunMetadata::default()
                },
            ))
        }
        "otlp" => {
            let spans = content
                .get("resourceSpans")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .flat_map(|resource| {
                    resource
                        .get("scopeSpans")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                })
                .flat_map(|scope| {
                    scope
                        .get("spans")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                })
                .collect::<Vec<_>>();
            let tests = spans.iter().enumerate().map(|(index, span)| json!({"name":span.get("name").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| format!("span-{index}")),"status":if span.pointer("/status/code").and_then(Value::as_str)==Some("STATUS_CODE_ERROR") {"fail"} else {"pass"}})).collect::<Vec<_>>();
            let failed = tests.iter().any(|test| test["status"] == "fail");
            Ok((
                "otlp".into(),
                if failed { "fail" } else { "ok" }.into(),
                json!({"format":"otlp","tests":tests,"raw":content}),
                RunMetadata {
                    source: Some("otlp".into()),
                    ..RunMetadata::default()
                },
            ))
        }
        _ => Err("format must be `junit`, `sarif`, or `otlp`".into()),
    }
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

    #[test]
    fn shared_runs_support_metadata_filters_trends_flakes_and_imports() {
        let path = std::env::temp_dir().join(format!("tcpform-runs-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).unwrap();
        for (status, test_status, commit, duration) in
            [("ok", "pass", "abc", 100), ("fail", "fail", "def", 300)]
        {
            store
                .save_run_with_metadata(
                    "wire",
                    status,
                    &json!({"tests":[{"name":"roundtrip","status":test_status}]}),
                    &RunMetadata {
                        branch: Some("main".into()),
                        commit: Some(commit.into()),
                        environment: Some("ci".into()),
                        source: Some("tcpform".into()),
                        duration_us: Some(duration),
                    },
                )
                .unwrap();
        }
        let runs = store
            .list_runs_filtered(&RunFilter {
                protocol: Some("wire".into()),
                branch: Some("main".into()),
                environment: Some("ci".into()),
                limit: 10,
                ..RunFilter::default()
            })
            .unwrap();
        assert_eq!(runs.len(), 2);
        let summary = store
            .run_summary(&RunFilter {
                protocol: Some("wire".into()),
                limit: 10,
                ..RunFilter::default()
            })
            .unwrap();
        assert_eq!(summary["success_rate"], 0.5);
        assert_eq!(summary["p95_duration_us"], 300);
        assert_eq!(summary["flaky_tests"], json!(["roundtrip"]));
        let retention = store.retention_status(30).unwrap();
        assert_eq!(retention["tables"]["runs"]["total"], 2);
        assert_eq!(store.prune(30).unwrap(), 0);
        let fingerprint = store.record_corpus("wire", &json!({"sources":{"protocol.tcpf":"protocol \"wire\" { step \"x\" { role=\"a\" action=\"send\" } }"},"root":"protocol.tcpf","manifest":{"protocol":{"name":"wire"}}})).unwrap();
        let regression = store
            .corpus_regression_bundle(&fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(regression["expected_status"], "ok");
        assert_eq!(regression["format"], "tcpform-regression-case");

        let (protocol, status, document, metadata) = normalize_run_import("junit", &Value::String("<testsuite><testcase name=\"passes\"/><testcase name=\"fails\"><failure/></testcase></testsuite>".into())).unwrap();
        assert_eq!(protocol, "junit");
        assert_eq!(status, "fail");
        assert_eq!(document["tests"].as_array().unwrap().len(), 2);
        assert_eq!(metadata.source.as_deref(), Some("junit"));
        assert!(
            normalize_run_import(
                "sarif",
                &json!({"runs":[{"results":[{"ruleId":"R1","level":"error"}]}]})
            )
            .unwrap()
            .1 == "fail"
        );
        assert!(normalize_run_import("otlp", &json!({"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"request","status":{"code":"STATUS_CODE_OK"}}]}]}]})).unwrap().1 == "ok");
        std::fs::remove_file(path).unwrap();
    }
}

use crate::{
    execution_activity::{ExecutionSnapshot, ExecutionStatus},
    permission_policy::{PolicyDecisionEvent, PolicyOutcome},
    risk_policy::assess_command,
};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    Decision,
    Execution,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub id: i64,
    pub kind: AuditKind,
    pub timestamp_ms: u64,
    pub execution_id: Option<String>,
    pub source: String,
    pub command_summary: String,
    pub operation_class: String,
    pub directory: String,
    pub outcome: Option<String>,
    pub status: Option<String>,
    pub duration_ms: Option<u64>,
    pub risk_class: Option<String>,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Default)]
pub struct AuditState {
    connection: Mutex<Option<Connection>>,
}

impl AuditState {
    fn connection(&self) -> MutexGuard<'_, Option<Connection>> {
        self.connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn initialize(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create audit directory: {error}"))?;
        }

        let connection =
            Connection::open(path).map_err(|error| format!("failed to open audit database: {error}"))?;
        connection
            .execute_batch(
                "
                PRAGMA journal_mode = WAL;
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS audit_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_key TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL CHECK(kind IN ('decision', 'execution')),
                    timestamp_ms INTEGER NOT NULL,
                    execution_id TEXT NULL,
                    source TEXT NOT NULL,
                    command_summary TEXT NOT NULL,
                    operation_class TEXT NOT NULL,
                    directory TEXT NOT NULL,
                    outcome TEXT NULL,
                    status TEXT NULL,
                    duration_ms INTEGER NULL,
                    risk_class TEXT NULL,
                    rule_id TEXT NULL,
                    reason TEXT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                    ON audit_entries(timestamp_ms DESC, id DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_rule
                    ON audit_entries(rule_id);
                CREATE INDEX IF NOT EXISTS idx_audit_execution
                    ON audit_entries(execution_id);
                ",
            )
            .map_err(|error| format!("failed to initialize audit database: {error}"))?;

        *self.connection() = Some(connection);
        Ok(())
    }

    pub fn record_decision(&self, event: &PolicyDecisionEvent) -> Result<(), String> {
        let outcome = policy_outcome_text(event.outcome);
        let event_key = format!(
            "decision:{}:{}:{}:{}",
            event.timestamp_ms, event.sequence, event.source, outcome
        );

        self.with_connection(|connection| {
            connection.execute(
                "INSERT OR IGNORE INTO audit_entries (
                    event_key, kind, timestamp_ms, execution_id, source, command_summary,
                    operation_class, directory, outcome, status, duration_ms, risk_class,
                    rule_id, reason
                ) VALUES (?1, 'decision', ?2, NULL, ?3, ?4, ?5, ?6, ?7, NULL, NULL, NULL, ?8, ?9)",
                params![
                    event_key,
                    event.timestamp_ms as i64,
                    event.source,
                    redacted_command_summary(&event.executable, event.argument_count),
                    event.operation_class,
                    event.directory,
                    outcome,
                    event.rule_id,
                    event.reason,
                ],
            )?;
            Ok(())
        })
    }

    pub fn record_execution(&self, execution: &ExecutionSnapshot) -> Result<(), String> {
        if !execution.state.is_terminal() {
            return Ok(());
        }

        let risk = assess_command(
            &execution.request.command,
            &execution.request.operation_class,
        )
        .ok();
        let duration_ms = execution
            .updated_at_ms
            .saturating_sub(execution.created_at_ms);
        let event_key = format!("execution:{}", execution.request.id);

        self.with_connection(|connection| {
            connection.execute(
                "INSERT OR REPLACE INTO audit_entries (
                    event_key, kind, timestamp_ms, execution_id, source, command_summary,
                    operation_class, directory, outcome, status, duration_ms, risk_class,
                    rule_id, reason
                ) VALUES (?1, 'execution', ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9, ?10, ?11, NULL)",
                params![
                    event_key,
                    execution.updated_at_ms as i64,
                    execution.request.id,
                    execution.request.source,
                    redacted_command_summary(
                        execution.request.command.first().map(String::as_str).unwrap_or("unknown"),
                        execution.request.command.len().saturating_sub(1),
                    ),
                    execution.request.operation_class,
                    execution.request.directory,
                    execution_status_text(execution.state),
                    duration_ms as i64,
                    risk.map(|value| format!("{:?}", value.class).to_ascii_lowercase()),
                    execution.policy_rule_id,
                ],
            )?;
            Ok(())
        })
    }

    pub fn list(&self, limit: usize) -> Result<Vec<AuditEntry>, String> {
        let limit = limit.clamp(1, 2_000) as i64;
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, kind, timestamp_ms, execution_id, source, command_summary,
                        operation_class, directory, outcome, status, duration_ms, risk_class,
                        rule_id, reason
                 FROM audit_entries
                 ORDER BY timestamp_ms DESC, id DESC
                 LIMIT ?1",
            )?;

            let rows = statement.query_map(params![limit], |row| {
                let kind_text: String = row.get(1)?;
                let timestamp_ms: i64 = row.get(2)?;
                let duration_ms: Option<i64> = row.get(10)?;

                Ok(AuditEntry {
                    id: row.get(0)?,
                    kind: if kind_text == "execution" {
                        AuditKind::Execution
                    } else {
                        AuditKind::Decision
                    },
                    timestamp_ms: timestamp_ms.max(0) as u64,
                    execution_id: row.get(3)?,
                    source: row.get(4)?,
                    command_summary: row.get(5)?,
                    operation_class: row.get(6)?,
                    directory: row.get(7)?,
                    outcome: row.get(8)?,
                    status: row.get(9)?,
                    duration_ms: duration_ms.map(|value| value.max(0) as u64),
                    risk_class: row.get(11)?,
                    rule_id: row.get(12)?,
                    reason: row.get(13)?,
                })
            })?;

            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, String> {
        let guard = self.connection();
        let connection = guard
            .as_ref()
            .ok_or_else(|| "audit store is not initialized".to_string())?;
        operation(connection).map_err(|error| format!("audit store error: {error}"))
    }
}

pub fn redacted_command_summary(executable: &str, argument_count: usize) -> String {
    if argument_count == 0 {
        return executable.to_string();
    }

    let noun = if argument_count == 1 {
        "argument"
    } else {
        "arguments"
    };
    format!("{executable} [{argument_count} {noun} redacted]")
}

fn policy_outcome_text(outcome: PolicyOutcome) -> &'static str {
    match outcome {
        PolicyOutcome::Allow => "allow",
        PolicyOutcome::Ask => "ask",
        PolicyOutcome::Deny => "deny",
    }
}

fn execution_status_text(status: ExecutionStatus) -> &'static str {
    match status {
        ExecutionStatus::Requested => "requested",
        ExecutionStatus::AwaitingApproval => "awaiting_approval",
        ExecutionStatus::Queued => "queued",
        ExecutionStatus::Running => "running",
        ExecutionStatus::Succeeded => "succeeded",
        ExecutionStatus::Failed => "failed",
        ExecutionStatus::Denied => "denied",
        ExecutionStatus::Cancelled => "cancelled",
        ExecutionStatus::TimedOut => "timed_out",
    }
}

#[cfg(test)]
mod tests {
    use super::{redacted_command_summary, AuditState};
    use crate::{
        execution_activity::{
            ExecutionActivityState, ExecutionStatus, NewExecutionRequest,
        },
        permission_policy::{PolicyDecisionEvent, PolicyOutcome},
    };
    use std::{
        fs,
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "shellwarden-audit-{name}-{}-{nonce}",
            process::id()
        ));
        fs::create_dir_all(&root).expect("create root");
        root
    }

    #[test]
    fn command_summary_never_contains_arguments() {
        assert_eq!(redacted_command_summary("git", 0), "git");
        assert_eq!(
            redacted_command_summary("curl", 3),
            "curl [3 arguments redacted]"
        );
        assert!(!redacted_command_summary("tool", 1).contains("super-secret"));
    }

    #[test]
    fn audit_persists_decisions_across_restart_without_raw_arguments() {
        let root = temp_root("decision");
        let path = root.join("audit.sqlite3");

        {
            let audit = AuditState::default();
            audit.initialize(&path).expect("initialize");
            audit
                .record_decision(&PolicyDecisionEvent {
                    sequence: 1,
                    timestamp_ms: 123,
                    source: "test-client".to_string(),
                    executable: "curl".to_string(),
                    argument_count: 4,
                    operation_class: "external_write".to_string(),
                    directory: root.to_string_lossy().to_string(),
                    outcome: PolicyOutcome::Allow,
                    rule_id: Some("persistent-7".to_string()),
                    reason: "Matched persistent rule.".to_string(),
                })
                .expect("record decision");
        }

        let restarted = AuditState::default();
        restarted.initialize(&path).expect("restart");
        let entries = restarted.list(50).expect("list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rule_id.as_deref(), Some("persistent-7"));
        assert_eq!(entries[0].command_summary, "curl [4 arguments redacted]");

        let bytes = fs::read(&path).expect("read database");
        let database_text = String::from_utf8_lossy(&bytes);
        assert!(!database_text.contains("super-secret"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn terminal_execution_is_recorded_once_with_duration_and_risk() {
        let root = temp_root("execution");
        let audit = AuditState::default();
        audit
            .initialize(&root.join("audit.sqlite3"))
            .expect("initialize");

        let activity = ExecutionActivityState::default();
        let execution = activity.begin(NewExecutionRequest {
            source: "test-client".to_string(),
            session_id: None,
            command: vec!["git".to_string(), "status".to_string()],
            operation_class: "read".to_string(),
            directory: root.to_string_lossy().to_string(),
            timeout_seconds: Some(30),
            environment_keys: Vec::new(),
        });
        activity
            .transition(&execution.id, ExecutionStatus::Running)
            .expect("run");
        activity
            .set_policy_rule(&execution.id, Some("persistent-9".to_string()))
            .expect("rule");
        activity
            .transition(&execution.id, ExecutionStatus::Succeeded)
            .expect("success");

        let snapshot = activity.snapshot();
        audit.record_execution(&snapshot[0]).expect("record");
        audit.record_execution(&snapshot[0]).expect("dedupe");

        let entries = audit.list(50).expect("list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status.as_deref(), Some("succeeded"));
        assert_eq!(entries[0].risk_class.as_deref(), Some("low"));
        assert_eq!(entries[0].rule_id.as_deref(), Some("persistent-9"));
        assert!(entries[0].duration_ms.is_some());

        let _ = fs::remove_dir_all(root);
    }
}

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

impl PolicyEffect {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            other => Err(format!("invalid stored policy effect: {other}")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    Allow,
    Ask,
    Deny,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRequestInput {
    pub source: String,
    pub session_id: Option<String>,
    pub command: Vec<String>,
    pub operation_class: String,
    pub directory: String,
    #[serde(default)]
    pub environment_keys: Vec<String>,
}

#[derive(Clone, Debug)]
struct NormalizedPolicyRequest {
    source: String,
    session_id: Option<String>,
    executable: String,
    command: Vec<String>,
    operation_class: String,
    directory: String,
    environment_keys: Vec<String>,
    fingerprint: String,
}

impl NormalizedPolicyRequest {
    fn from_input(input: PolicyRequestInput) -> Result<Self, String> {
        if input.command.is_empty() || input.command.iter().any(|part| part.is_empty()) {
            return Err("policy command must be a non-empty argv array".to_string());
        }
        if input.source.trim().is_empty() {
            return Err("policy source must not be empty".to_string());
        }
        if input.operation_class.trim().is_empty() {
            return Err("policy operation class must not be empty".to_string());
        }

        let canonical_directory = PathBuf::from(&input.directory)
            .canonicalize()
            .map_err(|error| format!("failed to canonicalize policy directory: {error}"))?;

        let mut environment_keys = input.environment_keys;
        environment_keys.sort();
        environment_keys.dedup();
        if environment_keys.iter().any(|key| key.is_empty()) {
            return Err("environment key names must not be empty".to_string());
        }

        let executable = input.command[0].clone();
        let directory = canonical_directory.to_string_lossy().to_string();
        let fingerprint = request_fingerprint(
            &input.source,
            &input.command,
            &input.operation_class,
            &directory,
            &environment_keys,
        )?;

        Ok(Self {
            source: input.source,
            session_id: input.session_id,
            executable,
            command: input.command,
            operation_class: input.operation_class,
            directory,
            environment_keys,
            fingerprint,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FingerprintMaterial<'a> {
    source: &'a str,
    command: &'a [String],
    operation_class: &'a str,
    directory: &'a str,
    environment_keys: &'a [String],
}

fn request_fingerprint(
    source: &str,
    command: &[String],
    operation_class: &str,
    directory: &str,
    environment_keys: &[String],
) -> Result<String, String> {
    let material = FingerprintMaterial {
        source,
        command,
        operation_class,
        directory,
        environment_keys,
    };
    let encoded = serde_json::to_vec(&material)
        .map_err(|error| format!("failed to fingerprint policy request: {error}"))?;
    let digest = Sha256::digest(encoded);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDecision {
    pub outcome: PolicyOutcome,
    pub rule_id: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRuleView {
    pub id: String,
    pub effect: PolicyEffect,
    pub persistence: String,
    pub source: String,
    pub session_id: Option<String>,
    pub executable: String,
    pub operation_class: String,
    pub directory: String,
    pub environment_key_count: usize,
    pub created_at_ms: u64,
}

#[derive(Clone)]
struct SessionRule {
    id: u64,
    effect: PolicyEffect,
    session_id: String,
    fingerprint: String,
    source: String,
    executable: String,
    operation_class: String,
    directory: String,
    environment_key_count: usize,
    created_at_ms: u64,
}

struct PersistentRuleStore {
    connection: Connection,
}

impl PersistentRuleStore {
    fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create policy data directory: {error}"))?;
        }

        let connection = Connection::open(path)
            .map_err(|error| format!("failed to open policy database: {error}"))?;
        connection
            .execute_batch(
                "
                PRAGMA journal_mode = WAL;
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS policy_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
                    fingerprint TEXT NOT NULL,
                    source TEXT NOT NULL,
                    executable TEXT NOT NULL,
                    operation_class TEXT NOT NULL,
                    directory TEXT NOT NULL,
                    environment_key_count INTEGER NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    UNIQUE(effect, fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_policy_rules_match
                    ON policy_rules(fingerprint, effect);
                ",
            )
            .map_err(|error| format!("failed to initialize policy database: {error}"))?;

        Ok(Self { connection })
    }

    fn insert(
        &self,
        effect: PolicyEffect,
        request: &NormalizedPolicyRequest,
    ) -> Result<i64, String> {
        let created_at_ms = now_ms() as i64;
        self.connection
            .execute(
                "INSERT OR IGNORE INTO policy_rules (
                    effect, fingerprint, source, executable, operation_class,
                    directory, environment_key_count, created_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    effect.as_str(),
                    request.fingerprint,
                    request.source,
                    request.executable,
                    request.operation_class,
                    request.directory,
                    request.environment_keys.len() as i64,
                    created_at_ms,
                ],
            )
            .map_err(|error| format!("failed to persist policy rule: {error}"))?;

        self.connection
            .query_row(
                "SELECT id FROM policy_rules WHERE effect = ?1 AND fingerprint = ?2",
                params![effect.as_str(), request.fingerprint],
                |row| row.get(0),
            )
            .map_err(|error| format!("failed to resolve persistent policy rule id: {error}"))
    }

    fn matching_rule(
        &self,
        effect: PolicyEffect,
        fingerprint: &str,
    ) -> Result<Option<PolicyRuleView>, String> {
        self.connection
            .query_row(
                "SELECT id, effect, source, executable, operation_class, directory,
                        environment_key_count, created_at_ms
                 FROM policy_rules
                 WHERE effect = ?1 AND fingerprint = ?2
                 ORDER BY id ASC
                 LIMIT 1",
                params![effect.as_str(), fingerprint],
                |row| persistent_rule_view(row),
            )
            .optional()
            .map_err(|error| format!("failed to match persistent policy rule: {error}"))
    }

    fn list(&self) -> Result<Vec<PolicyRuleView>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, effect, source, executable, operation_class, directory,
                        environment_key_count, created_at_ms
                 FROM policy_rules
                 ORDER BY id ASC",
            )
            .map_err(|error| format!("failed to prepare policy rule list: {error}"))?;

        let rows = statement
            .query_map([], persistent_rule_view)
            .map_err(|error| format!("failed to list persistent policy rules: {error}"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("failed to decode persistent policy rule: {error}"))
    }

    fn revoke(&self, id: i64) -> Result<bool, String> {
        let deleted = self
            .connection
            .execute("DELETE FROM policy_rules WHERE id = ?1", params![id])
            .map_err(|error| format!("failed to revoke persistent policy rule: {error}"))?;
        Ok(deleted > 0)
    }

    fn reset(&self) -> Result<usize, String> {
        self.connection
            .execute("DELETE FROM policy_rules", [])
            .map_err(|error| format!("failed to reset persistent policy rules: {error}"))
    }
}

fn persistent_rule_view(row: &rusqlite::Row<'_>) -> rusqlite::Result<PolicyRuleView> {
    let id: i64 = row.get(0)?;
    let effect: String = row.get(1)?;
    let environment_key_count: i64 = row.get(6)?;
    let created_at_ms: i64 = row.get(7)?;

    Ok(PolicyRuleView {
        id: format!("persistent-{id}"),
        effect: PolicyEffect::parse(&effect).unwrap_or(PolicyEffect::Deny),
        persistence: "persistent".to_string(),
        source: row.get(2)?,
        session_id: None,
        executable: row.get(3)?,
        operation_class: row.get(4)?,
        directory: row.get(5)?,
        environment_key_count: environment_key_count.max(0) as usize,
        created_at_ms: created_at_ms.max(0) as u64,
    })
}

struct PolicyEngine {
    persistent: PersistentRuleStore,
    sessions: Vec<SessionRule>,
    next_session_rule_id: u64,
}

impl PolicyEngine {
    fn open(path: &Path) -> Result<Self, String> {
        Ok(Self {
            persistent: PersistentRuleStore::open(path)?,
            sessions: Vec::new(),
            next_session_rule_id: 1,
        })
    }

    fn decide(&self, request: &NormalizedPolicyRequest) -> Result<PolicyDecision, String> {
        if let Some(rule) = self.match_session(PolicyEffect::Deny, request) {
            return Ok(decision_for_rule(PolicyOutcome::Deny, &rule));
        }
        if let Some(rule) = self
            .persistent
            .matching_rule(PolicyEffect::Deny, &request.fingerprint)?
        {
            return Ok(decision_for_rule(PolicyOutcome::Deny, &rule));
        }
        if let Some(rule) = self.match_session(PolicyEffect::Allow, request) {
            return Ok(decision_for_rule(PolicyOutcome::Allow, &rule));
        }
        if let Some(rule) = self
            .persistent
            .matching_rule(PolicyEffect::Allow, &request.fingerprint)?
        {
            return Ok(decision_for_rule(PolicyOutcome::Allow, &rule));
        }

        Ok(PolicyDecision {
            outcome: PolicyOutcome::Ask,
            rule_id: None,
            reason: "No matching ShellWarden permission rule; explicit user approval is required."
                .to_string(),
        })
    }

    fn grant_session(
        &mut self,
        effect: PolicyEffect,
        request: &NormalizedPolicyRequest,
    ) -> Result<PolicyRuleView, String> {
        let session_id = request
            .session_id
            .clone()
            .ok_or_else(|| "session-scoped permission requires a session id".to_string())?;

        if let Some(existing) = self
            .sessions
            .iter()
            .find(|rule| {
                rule.effect == effect
                    && rule.session_id == session_id
                    && rule.fingerprint == request.fingerprint
            })
            .cloned()
        {
            return Ok(session_rule_view(&existing));
        }

        let rule = SessionRule {
            id: self.next_session_rule_id,
            effect,
            session_id,
            fingerprint: request.fingerprint.clone(),
            source: request.source.clone(),
            executable: request.executable.clone(),
            operation_class: request.operation_class.clone(),
            directory: request.directory.clone(),
            environment_key_count: request.environment_keys.len(),
            created_at_ms: now_ms(),
        };
        self.next_session_rule_id += 1;
        let view = session_rule_view(&rule);
        self.sessions.push(rule);
        Ok(view)
    }

    fn grant_persistent(
        &self,
        effect: PolicyEffect,
        request: &NormalizedPolicyRequest,
    ) -> Result<PolicyRuleView, String> {
        let id = self.persistent.insert(effect, request)?;
        self.persistent
            .list()?
            .into_iter()
            .find(|rule| rule.id == format!("persistent-{id}"))
            .ok_or_else(|| "persistent policy rule was inserted but could not be reloaded".to_string())
    }

    fn list(&self) -> Result<Vec<PolicyRuleView>, String> {
        let mut rules: Vec<PolicyRuleView> =
            self.sessions.iter().map(session_rule_view).collect();
        rules.extend(self.persistent.list()?);
        rules.sort_by(|left, right| left.created_at_ms.cmp(&right.created_at_ms).then(left.id.cmp(&right.id)));
        Ok(rules)
    }

    fn revoke(&mut self, id: &str) -> Result<bool, String> {
        if let Some(raw) = id.strip_prefix("session-") {
            let parsed = raw
                .parse::<u64>()
                .map_err(|_| format!("invalid session policy rule id: {id}"))?;
            let before = self.sessions.len();
            self.sessions.retain(|rule| rule.id != parsed);
            return Ok(self.sessions.len() != before);
        }

        if let Some(raw) = id.strip_prefix("persistent-") {
            let parsed = raw
                .parse::<i64>()
                .map_err(|_| format!("invalid persistent policy rule id: {id}"))?;
            return self.persistent.revoke(parsed);
        }

        Err(format!("unknown policy rule id: {id}"))
    }

    fn reset_session(&mut self, session_id: &str) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|rule| rule.session_id != session_id);
        before - self.sessions.len()
    }

    fn reset_all_sessions(&mut self) -> usize {
        let removed = self.sessions.len();
        self.sessions.clear();
        removed
    }

    fn reset_persistent(&self) -> Result<usize, String> {
        self.persistent.reset()
    }

    fn match_session(
        &self,
        effect: PolicyEffect,
        request: &NormalizedPolicyRequest,
    ) -> Option<PolicyRuleView> {
        let session_id = request.session_id.as_deref()?;
        self.sessions
            .iter()
            .filter(|rule| {
                rule.effect == effect
                    && rule.session_id == session_id
                    && rule.fingerprint == request.fingerprint
            })
            .min_by_key(|rule| rule.id)
            .map(session_rule_view)
    }
}

fn session_rule_view(rule: &SessionRule) -> PolicyRuleView {
    PolicyRuleView {
        id: format!("session-{}", rule.id),
        effect: rule.effect,
        persistence: "session".to_string(),
        source: rule.source.clone(),
        session_id: Some(rule.session_id.clone()),
        executable: rule.executable.clone(),
        operation_class: rule.operation_class.clone(),
        directory: rule.directory.clone(),
        environment_key_count: rule.environment_key_count,
        created_at_ms: rule.created_at_ms,
    }
}

fn decision_for_rule(outcome: PolicyOutcome, rule: &PolicyRuleView) -> PolicyDecision {
    PolicyDecision {
        outcome,
        rule_id: Some(rule.id.clone()),
        reason: format!(
            "Matched {} {} rule {} for {} in {}.",
            rule.persistence,
            rule.effect.as_str(),
            rule.id,
            rule.executable,
            rule.directory
        ),
    }
}

#[derive(Default)]
pub struct PolicyState {
    engine: Mutex<Option<PolicyEngine>>,
}

impl PolicyState {
    fn engine(&self) -> MutexGuard<'_, Option<PolicyEngine>> {
        self.engine
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn initialize(&self, database_path: &Path) -> Result<(), String> {
        let engine = PolicyEngine::open(database_path)?;
        *self.engine() = Some(engine);
        Ok(())
    }

    pub fn decide(&self, input: PolicyRequestInput) -> Result<PolicyDecision, String> {
        let request = NormalizedPolicyRequest::from_input(input)?;
        let engine = self.engine();
        engine
            .as_ref()
            .ok_or_else(|| "policy engine is not initialized".to_string())?
            .decide(&request)
    }

    pub fn grant_session(
        &self,
        effect: PolicyEffect,
        input: PolicyRequestInput,
    ) -> Result<PolicyRuleView, String> {
        let request = NormalizedPolicyRequest::from_input(input)?;
        let mut engine = self.engine();
        engine
            .as_mut()
            .ok_or_else(|| "policy engine is not initialized".to_string())?
            .grant_session(effect, &request)
    }

    pub fn grant_persistent(
        &self,
        effect: PolicyEffect,
        input: PolicyRequestInput,
    ) -> Result<PolicyRuleView, String> {
        let request = NormalizedPolicyRequest::from_input(input)?;
        let engine = self.engine();
        engine
            .as_ref()
            .ok_or_else(|| "policy engine is not initialized".to_string())?
            .grant_persistent(effect, &request)
    }

    pub fn list(&self) -> Result<Vec<PolicyRuleView>, String> {
        let engine = self.engine();
        engine
            .as_ref()
            .ok_or_else(|| "policy engine is not initialized".to_string())?
            .list()
    }

    pub fn revoke(&self, rule_id: &str) -> Result<bool, String> {
        let mut engine = self.engine();
        engine
            .as_mut()
            .ok_or_else(|| "policy engine is not initialized".to_string())?
            .revoke(rule_id)
    }

    pub fn reset_session(&self, session_id: &str) -> Result<usize, String> {
        let mut engine = self.engine();
        Ok(engine
            .as_mut()
            .ok_or_else(|| "policy engine is not initialized".to_string())?
            .reset_session(session_id))
    }

    pub fn reset_all_sessions(&self) -> Result<usize, String> {
        let mut engine = self.engine();
        Ok(engine
            .as_mut()
            .ok_or_else(|| "policy engine is not initialized".to_string())?
            .reset_all_sessions())
    }

    pub fn reset_persistent(&self) -> Result<usize, String> {
        let engine = self.engine();
        engine
            .as_ref()
            .ok_or_else(|| "policy engine is not initialized".to_string())?
            .reset_persistent()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::{
        PolicyEffect, PolicyOutcome, PolicyRequestInput, PolicyState,
    };
    use std::{
        fs,
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn test_directory() -> PathBuf {
        std::env::current_dir().expect("test current directory")
    }

    fn database_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "shellwarden-policy-{name}-{}-{nonce}.sqlite3",
            process::id()
        ))
    }

    fn request(session_id: Option<&str>) -> PolicyRequestInput {
        PolicyRequestInput {
            source: "test-client".to_string(),
            session_id: session_id.map(str::to_string),
            command: vec!["git".to_string(), "status".to_string()],
            operation_class: "read".to_string(),
            directory: test_directory().to_string_lossy().to_string(),
            environment_keys: vec!["PATH".to_string()],
        }
    }

    #[test]
    fn unknown_request_defaults_to_ask_and_session_grant_disappears() {
        let path = database_path("session");
        let state = PolicyState::default();
        state.initialize(&path).expect("initialize policy");

        let unknown = state.decide(request(Some("session-a"))).expect("decide");
        assert_eq!(unknown.outcome, PolicyOutcome::Ask);

        state
            .grant_session(PolicyEffect::Allow, request(Some("session-a")))
            .expect("grant session allow");
        assert_eq!(
            state
                .decide(request(Some("session-a")))
                .expect("decide allowed")
                .outcome,
            PolicyOutcome::Allow
        );
        assert_eq!(
            state
                .decide(request(Some("session-b")))
                .expect("different session")
                .outcome,
            PolicyOutcome::Ask
        );

        drop(state);

        let restarted = PolicyState::default();
        restarted.initialize(&path).expect("reinitialize policy");
        assert_eq!(
            restarted
                .decide(request(Some("session-a")))
                .expect("session grant must be gone")
                .outcome,
            PolicyOutcome::Ask
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persistent_allow_survives_restart_without_storing_argv() {
        let path = database_path("persistent");
        {
            let state = PolicyState::default();
            state.initialize(&path).expect("initialize policy");
            state
                .grant_persistent(PolicyEffect::Allow, request(Some("session-a")))
                .expect("grant persistent allow");
        }

        let restarted = PolicyState::default();
        restarted.initialize(&path).expect("reinitialize policy");
        let decision = restarted
            .decide(request(Some("different-session")))
            .expect("persistent decision");
        assert_eq!(decision.outcome, PolicyOutcome::Allow);
        assert!(decision.rule_id.as_deref().is_some_and(|id| id.starts_with("persistent-")));

        let bytes = fs::read(&path).expect("read sqlite bytes");
        let database_text = String::from_utf8_lossy(&bytes);
        assert!(
            !database_text.contains("status"),
            "raw argv must not be persisted in the policy database"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn deny_takes_precedence_over_allow_and_rules_are_revocable() {
        let path = database_path("deny");
        let state = PolicyState::default();
        state.initialize(&path).expect("initialize policy");

        let allow = state
            .grant_persistent(PolicyEffect::Allow, request(Some("session-a")))
            .expect("persistent allow");
        let deny = state
            .grant_session(PolicyEffect::Deny, request(Some("session-a")))
            .expect("session deny");

        let decision = state.decide(request(Some("session-a"))).expect("decide");
        assert_eq!(decision.outcome, PolicyOutcome::Deny);
        assert_eq!(decision.rule_id.as_deref(), Some(deny.id.as_str()));

        assert!(state.revoke(&deny.id).expect("revoke deny"));
        assert_eq!(
            state.decide(request(Some("session-a"))).expect("allow").outcome,
            PolicyOutcome::Allow
        );

        assert!(state.revoke(&allow.id).expect("revoke allow"));
        assert_eq!(
            state.decide(request(Some("session-a"))).expect("ask").outcome,
            PolicyOutcome::Ask
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persistent_store_exposes_metadata_without_environment_values_or_argv() {
        let path = database_path("metadata");
        let state = PolicyState::default();
        state.initialize(&path).expect("initialize policy");
        state
            .grant_persistent(PolicyEffect::Deny, request(Some("session-a")))
            .expect("grant persistent deny");

        let rules = state.list().expect("list rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].effect, PolicyEffect::Deny);
        assert_eq!(rules[0].environment_key_count, 1);
        assert_eq!(rules[0].executable, "git");

        assert_eq!(state.reset_persistent().expect("reset persistent"), 1);
        assert!(state.list().expect("list after reset").is_empty());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn session_reset_removes_only_the_target_session() {
        let path = database_path("reset-session");
        let state = PolicyState::default();
        state.initialize(&path).expect("initialize policy");
        state
            .grant_session(PolicyEffect::Allow, request(Some("session-a")))
            .expect("session a");
        state
            .grant_session(PolicyEffect::Allow, request(Some("session-b")))
            .expect("session b");

        assert_eq!(state.reset_session("session-a").expect("reset"), 1);
        assert_eq!(
            state.decide(request(Some("session-a"))).expect("a").outcome,
            PolicyOutcome::Ask
        );
        assert_eq!(
            state.decide(request(Some("session-b"))).expect("b").outcome,
            PolicyOutcome::Allow
        );

        let _ = fs::remove_file(path);
    }
}

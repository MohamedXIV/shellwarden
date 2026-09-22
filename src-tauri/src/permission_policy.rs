use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, MutexGuard,
    },
    time::{SystemTime, UNIX_EPOCH},
};

static RULE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    Allow,
    Deny,
}

impl RuleEffect {
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
            other => Err(format!("unknown rule effect: {other}")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RulePersistence {
    Session,
    Persistent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionKind {
    Allow,
    Ask,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRequest {
    pub executable: String,
    pub argv: Vec<String>,
    pub operation_key: String,
    pub directory: String,
    pub environment_keys: Vec<String>,
    pub source: String,
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewPolicyRule {
    pub effect: RuleEffect,
    pub executable: String,
    pub operation_key: String,
    pub environment_keys: Vec<String>,
    pub source: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRule {
    pub id: String,
    pub effect: RuleEffect,
    pub persistence: RulePersistence,
    pub executable: String,
    pub operation_key: String,
    pub environment_keys: Vec<String>,
    pub source: Option<String>,
    pub session_id: Option<String>,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDecision {
    pub decision: PolicyDecisionKind,
    pub rule_id: Option<String>,
    pub reason: String,
}

pub struct PermissionPolicyState {
    database: Mutex<Connection>,
    session_rules: Mutex<HashMap<String, PolicyRule>>,
}

impl PermissionPolicyState {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create permission store directory: {error}"))?;
        }

        let connection = Connection::open(path)
            .map_err(|error| format!("failed to open permission store: {error}"))?;
        initialize_schema(&connection)?;

        Ok(Self {
            database: Mutex::new(connection),
            session_rules: Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    fn open_in_memory() -> Result<Self, String> {
        let connection = Connection::open_in_memory()
            .map_err(|error| format!("failed to open in-memory permission store: {error}"))?;
        initialize_schema(&connection)?;

        Ok(Self {
            database: Mutex::new(connection),
            session_rules: Mutex::new(HashMap::new()),
        })
    }

    fn database(&self) -> MutexGuard<'_, Connection> {
        self.database
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn session_rules(&self) -> MutexGuard<'_, HashMap<String, PolicyRule>> {
        self.session_rules
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn evaluate(&self, request: &PolicyRequest) -> Result<PolicyDecision, String> {
        let request = normalize_request(request)?;
        let rules = self.list_rules()?;
        let mut matching: Vec<PolicyRule> = rules
            .into_iter()
            .filter(|rule| rule_matches(rule, &request))
            .collect();

        matching.sort_by(|left, right| {
            decision_priority(right)
                .cmp(&decision_priority(left))
                .then_with(|| left.id.cmp(&right.id))
        });

        if let Some(rule) = matching.first() {
            return Ok(PolicyDecision {
                decision: match rule.effect {
                    RuleEffect::Allow => PolicyDecisionKind::Allow,
                    RuleEffect::Deny => PolicyDecisionKind::Deny,
                },
                rule_id: Some(rule.id.clone()),
                reason: format!(
                    "{} rule {} matched executable '{}' operation '{}'",
                    rule.effect.as_str(),
                    rule.id,
                    rule.executable,
                    rule.operation_key
                ),
            });
        }

        Ok(PolicyDecision {
            decision: PolicyDecisionKind::Ask,
            rule_id: None,
            reason: format!(
                "no permission rule matches executable '{}' operation '{}'",
                request.executable, request.operation_key
            ),
        })
    }

    pub fn grant_session(&self, rule: NewPolicyRule) -> Result<PolicyRule, String> {
        let normalized = normalize_rule(rule, RulePersistence::Session)?;
        self.session_rules()
            .insert(normalized.id.clone(), normalized.clone());
        Ok(normalized)
    }

    pub fn persist_rule(&self, rule: NewPolicyRule) -> Result<PolicyRule, String> {
        if rule.session_id.is_some() {
            return Err("persistent rules cannot contain a session id".to_string());
        }

        let normalized = normalize_rule(rule, RulePersistence::Persistent)?;
        let env_json = serde_json::to_string(&normalized.environment_keys)
            .map_err(|error| format!("failed to encode environment key metadata: {error}"))?;

        self.database()
            .execute(
                "INSERT INTO permission_rules
                 (id, effect, executable, operation_key, environment_keys_json, source, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    normalized.id,
                    normalized.effect.as_str(),
                    normalized.executable,
                    normalized.operation_key,
                    env_json,
                    normalized.source,
                    normalized.created_at_ms as i64,
                ],
            )
            .map_err(|error| format!("failed to persist permission rule: {error}"))?;

        Ok(normalized)
    }

    pub fn list_rules(&self) -> Result<Vec<PolicyRule>, String> {
        let mut rules: Vec<PolicyRule> = self.session_rules().values().cloned().collect();
        let connection = self.database();
        let mut statement = connection
            .prepare(
                "SELECT id, effect, executable, operation_key, environment_keys_json, source, created_at_ms
                 FROM permission_rules
                 ORDER BY created_at_ms ASC, id ASC",
            )
            .map_err(|error| format!("failed to query permission rules: {error}"))?;

        let rows = statement
            .query_map([], |row| {
                let effect: String = row.get(1)?;
                let environment_keys_json: String = row.get(4)?;
                Ok((
                    row.get::<_, String>(0)?,
                    effect,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    environment_keys_json,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .map_err(|error| format!("failed to read permission rules: {error}"))?;

        for row in rows {
            let (id, effect, executable, operation_key, environment_keys_json, source, created_at) =
                row.map_err(|error| format!("failed to decode permission rule: {error}"))?;
            let environment_keys: Vec<String> = serde_json::from_str(&environment_keys_json)
                .map_err(|error| format!("invalid environment key metadata for rule {id}: {error}"))?;

            rules.push(PolicyRule {
                id,
                effect: RuleEffect::parse(&effect)?,
                persistence: RulePersistence::Persistent,
                executable,
                operation_key,
                environment_keys,
                source,
                session_id: None,
                created_at_ms: created_at.max(0) as u64,
            });
        }

        rules.sort_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(rules)
    }

    pub fn revoke(&self, rule_id: &str) -> Result<bool, String> {
        if self.session_rules().remove(rule_id).is_some() {
            return Ok(true);
        }

        let changed = self
            .database()
            .execute("DELETE FROM permission_rules WHERE id = ?1", params![rule_id])
            .map_err(|error| format!("failed to revoke permission rule: {error}"))?;
        Ok(changed > 0)
    }

    pub fn reset_session(&self) -> usize {
        let mut rules = self.session_rules();
        let count = rules.len();
        rules.clear();
        count
    }

    pub fn reset_persistent(&self) -> Result<usize, String> {
        self.database()
            .execute("DELETE FROM permission_rules", [])
            .map_err(|error| format!("failed to reset persistent permission rules: {error}"))
    }
}

fn initialize_schema(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS permission_rules (
                 id TEXT PRIMARY KEY NOT NULL,
                 effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
                 executable TEXT NOT NULL,
                 operation_key TEXT NOT NULL,
                 environment_keys_json TEXT NOT NULL,
                 source TEXT NULL,
                 created_at_ms INTEGER NOT NULL
             );
             PRAGMA user_version = 1;",
        )
        .map_err(|error| format!("failed to initialize permission store: {error}"))
}

fn normalize_request(request: &PolicyRequest) -> Result<PolicyRequest, String> {
    if request.argv.is_empty() {
        return Err("policy request argv must not be empty".to_string());
    }

    let executable = normalize_required("executable", &request.executable)?;
    let operation_key = normalize_required("operation key", &request.operation_key)?;
    let directory = normalize_required("directory", &request.directory)?;
    let source = normalize_required("source", &request.source)?;

    Ok(PolicyRequest {
        executable,
        argv: request.argv.clone(),
        operation_key,
        directory,
        environment_keys: normalize_environment_keys(&request.environment_keys)?,
        source,
        session_id: request
            .session_id
            .as_deref()
            .map(|value| normalize_required("session id", value))
            .transpose()?,
    })
}

fn normalize_rule(
    rule: NewPolicyRule,
    persistence: RulePersistence,
) -> Result<PolicyRule, String> {
    let session_id = rule
        .session_id
        .as_deref()
        .map(|value| normalize_required("session id", value))
        .transpose()?;

    Ok(PolicyRule {
        id: new_rule_id(),
        effect: rule.effect,
        persistence,
        executable: normalize_required("executable", &rule.executable)?,
        operation_key: normalize_required("operation key", &rule.operation_key)?,
        environment_keys: normalize_environment_keys(&rule.environment_keys)?,
        source: rule
            .source
            .as_deref()
            .map(|value| normalize_required("source", value))
            .transpose()?,
        session_id,
        created_at_ms: now_ms(),
    })
}

fn normalize_required(label: &str, value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(value.to_ascii_lowercase())
}

fn normalize_environment_keys(keys: &[String]) -> Result<Vec<String>, String> {
    let mut normalized = Vec::with_capacity(keys.len());

    for key in keys {
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|character| character.is_ascii_alphanumeric() || character == '_') {
            return Err(format!("invalid environment key name: {key:?}"));
        }
        normalized.push(key.to_ascii_uppercase());
    }

    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn rule_matches(rule: &PolicyRule, request: &PolicyRequest) -> bool {
    if rule.executable != request.executable
        || rule.operation_key != request.operation_key
        || rule.environment_keys != request.environment_keys
    {
        return false;
    }

    if rule
        .source
        .as_ref()
        .is_some_and(|source| source != &request.source)
    {
        return false;
    }

    if rule
        .session_id
        .as_ref()
        .is_some_and(|session_id| request.session_id.as_ref() != Some(session_id))
    {
        return false;
    }

    true
}

fn decision_priority(rule: &PolicyRule) -> (u8, u8, u8) {
    let effect = match rule.effect {
        RuleEffect::Deny => 2,
        RuleEffect::Allow => 1,
    };
    let specificity =
        u8::from(rule.source.is_some()) + u8::from(rule.session_id.is_some());
    let persistence = match rule.persistence {
        RulePersistence::Session => 1,
        RulePersistence::Persistent => 0,
    };

    (effect, specificity, persistence)
}

fn new_rule_id() -> String {
    format!(
        "rule-{}-{}",
        now_ms(),
        RULE_COUNTER.fetch_add(1, Ordering::Relaxed) + 1
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn request() -> PolicyRequest {
        PolicyRequest {
            executable: "git".to_string(),
            argv: vec!["git".to_string(), "status".to_string()],
            operation_key: "git.read".to_string(),
            directory: "C:/work/project".to_string(),
            environment_keys: vec!["PATH".to_string()],
            source: "chatgpt".to_string(),
            session_id: Some("session-a".to_string()),
        }
    }

    fn rule(effect: RuleEffect) -> NewPolicyRule {
        NewPolicyRule {
            effect,
            executable: "git".to_string(),
            operation_key: "git.read".to_string(),
            environment_keys: vec!["PATH".to_string()],
            source: Some("chatgpt".to_string()),
            session_id: None,
        }
    }

    fn temp_db() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "shellwarden-permissions-{}-{}-{id}.sqlite3",
            std::process::id(),
            now_ms()
        ))
    }

    #[test]
    fn unknown_request_asks() {
        let state = PermissionPolicyState::open_in_memory().expect("policy store");
        let decision = state.evaluate(&request()).expect("decision");

        assert_eq!(decision.decision, PolicyDecisionKind::Ask);
        assert!(decision.rule_id.is_none());
    }

    #[test]
    fn persistent_deny_wins_over_session_allow() {
        let state = PermissionPolicyState::open_in_memory().expect("policy store");
        state.persist_rule(rule(RuleEffect::Deny)).expect("deny rule");

        let mut allow = rule(RuleEffect::Allow);
        allow.session_id = Some("session-a".to_string());
        state.grant_session(allow).expect("session allow");

        let decision = state.evaluate(&request()).expect("decision");
        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert!(decision.reason.starts_with("deny rule"));
    }

    #[test]
    fn session_rules_disappear_when_state_is_recreated() {
        let path = temp_db();

        {
            let state = PermissionPolicyState::open(&path).expect("policy store");
            let mut allow = rule(RuleEffect::Allow);
            allow.session_id = Some("session-a".to_string());
            state.grant_session(allow).expect("session rule");
            assert_eq!(
                state.evaluate(&request()).expect("decision").decision,
                PolicyDecisionKind::Allow
            );
        }

        let reopened = PermissionPolicyState::open(&path).expect("reopened store");
        assert_eq!(
            reopened.evaluate(&request()).expect("decision").decision,
            PolicyDecisionKind::Ask
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persistent_rules_survive_restart_and_can_be_revoked() {
        let path = temp_db();
        let rule_id = {
            let state = PermissionPolicyState::open(&path).expect("policy store");
            state
                .persist_rule(rule(RuleEffect::Allow))
                .expect("persistent rule")
                .id
        };

        let reopened = PermissionPolicyState::open(&path).expect("reopened store");
        let decision = reopened.evaluate(&request()).expect("decision");
        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(decision.rule_id.as_deref(), Some(rule_id.as_str()));

        assert!(reopened.revoke(&rule_id).expect("revoke"));
        assert_eq!(
            reopened.evaluate(&request()).expect("decision").decision,
            PolicyDecisionKind::Ask
        );

        drop(reopened);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn store_persists_environment_names_but_never_environment_values_or_argv() {
        let state = PermissionPolicyState::open_in_memory().expect("policy store");
        state.persist_rule(rule(RuleEffect::Allow)).expect("rule");

        let connection = state.database();
        let columns: Vec<String> = {
            let mut statement = connection
                .prepare("PRAGMA table_info(permission_rules)")
                .expect("table info");
            statement
                .query_map([], |row| row.get::<_, String>(1))
                .expect("columns")
                .map(|row| row.expect("column"))
                .collect()
        };

        assert!(!columns.iter().any(|column| column.contains("argv")));
        assert!(!columns.iter().any(|column| column.contains("value")));
        assert!(columns.iter().any(|column| column == "environment_keys_json"));
    }

    #[test]
    fn matching_is_deterministic_after_normalization() {
        let state = PermissionPolicyState::open_in_memory().expect("policy store");
        let created = state.persist_rule(rule(RuleEffect::Allow)).expect("rule");

        let mut variant = request();
        variant.executable = " GIT ".to_string();
        variant.operation_key = " Git.Read ".to_string();
        variant.source = " ChatGPT ".to_string();
        variant.environment_keys = vec!["path".to_string(), "PATH".to_string()];

        let decision = state.evaluate(&variant).expect("decision");
        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(decision.rule_id.as_deref(), Some(created.id.as_str()));
    }
}

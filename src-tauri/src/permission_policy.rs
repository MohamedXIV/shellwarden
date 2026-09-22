use crate::risk_policy::assess_command;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
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

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    Once,
    Session,
    ExactRequest,
    ExactDirectory,
    DirectoryTree,
    Always,
    Deny,
}

impl ApprovalScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
            Self::ExactRequest => "exact_request",
            Self::ExactDirectory => "exact_directory",
            Self::DirectoryTree => "directory_tree",
            Self::Always => "always",
            Self::Deny => "deny",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "once" => Ok(Self::Once),
            "session" => Ok(Self::Session),
            "exact_request" => Ok(Self::ExactRequest),
            "exact_directory" => Ok(Self::ExactDirectory),
            "directory_tree" => Ok(Self::DirectoryTree),
            "always" => Ok(Self::Always),
            "deny" => Ok(Self::Deny),
            other => Err(format!("invalid stored approval scope: {other}")),
        }
    }

    fn is_persistent(self) -> bool {
        matches!(
            self,
            Self::ExactRequest | Self::ExactDirectory | Self::DirectoryTree | Self::Always | Self::Deny
        )
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
    operation_class: String,
    directory: PathBuf,
    directory_text: String,
    environment_keys: Vec<String>,
    fingerprint: String,
    operation_fingerprint: String,
}

impl NormalizedPolicyRequest {
    fn from_input(input: PolicyRequestInput) -> Result<Self, String> {
        if input.command.is_empty() || input.command.iter().any(|part| part.is_empty()) {
            return Err("policy command must be a non-empty argv array".to_string());
        }

        let source = input.source.trim().to_string();
        if source.is_empty() {
            return Err("policy source must not be empty".to_string());
        }

        let operation_class = input.operation_class.trim().to_string();
        if operation_class.is_empty() {
            return Err("policy operation class must not be empty".to_string());
        }

        let session_id = input
            .session_id
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        let directory = canonical_directory(&input.directory)?;
        let directory_text = path_text(&directory)?;

        let mut environment_keys = input
            .environment_keys
            .into_iter()
            .map(|key| key.trim().to_string())
            .collect::<Vec<_>>();
        if environment_keys.iter().any(|key| key.is_empty()) {
            return Err("environment key names must not be empty".to_string());
        }
        environment_keys.sort();
        environment_keys.dedup();

        let executable = input.command[0].clone();
        let operation_fingerprint = operation_fingerprint(
            &source,
            &input.command,
            &operation_class,
            &environment_keys,
        )?;
        let fingerprint = request_fingerprint(
            &source,
            &input.command,
            &operation_class,
            &directory_text,
            &environment_keys,
        )?;

        Ok(Self {
            source,
            session_id,
            executable,
            operation_class,
            directory,
            directory_text,
            environment_keys,
            fingerprint,
            operation_fingerprint,
        })
    }
}

fn canonical_directory(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("policy directory must not be empty".to_string());
    }

    PathBuf::from(trimmed)
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize policy directory: {error}"))
}

fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| "policy paths must be valid Unicode".to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationFingerprintMaterial<'a> {
    source: &'a str,
    command: &'a [String],
    operation_class: &'a str,
    environment_keys: &'a [String],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestFingerprintMaterial<'a> {
    source: &'a str,
    command: &'a [String],
    operation_class: &'a str,
    directory: &'a str,
    environment_keys: &'a [String],
}

fn operation_fingerprint(
    source: &str,
    command: &[String],
    operation_class: &str,
    environment_keys: &[String],
) -> Result<String, String> {
    hash_material(&OperationFingerprintMaterial {
        source,
        command,
        operation_class,
        environment_keys,
    })
}

fn request_fingerprint(
    source: &str,
    command: &[String],
    operation_class: &str,
    directory: &str,
    environment_keys: &[String],
) -> Result<String, String> {
    hash_material(&RequestFingerprintMaterial {
        source,
        command,
        operation_class,
        directory,
        environment_keys,
    })
}

fn hash_material<T: Serialize>(material: &T) -> Result<String, String> {
    let encoded = serde_json::to_vec(material)
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
pub struct PolicyDecisionEvent {
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub source: String,
    pub executable: String,
    pub operation_class: String,
    pub directory: String,
    pub outcome: PolicyOutcome,
    pub rule_id: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRuleView {
    pub id: String,
    pub effect: PolicyEffect,
    pub scope: ApprovalScope,
    pub persistence: String,
    pub source: String,
    pub session_id: Option<String>,
    pub executable: String,
    pub operation_class: String,
    pub directory: String,
    pub scope_root: Option<String>,
    pub environment_key_count: usize,
    pub created_at_ms: u64,
}

#[derive(Clone)]
struct EphemeralRule {
    id: u64,
    effect: PolicyEffect,
    scope: ApprovalScope,
    session_id: Option<String>,
    fingerprint: String,
    source: String,
    executable: String,
    operation_class: String,
    directory: String,
    environment_key_count: usize,
    created_at_ms: u64,
}

#[derive(Clone)]
struct PersistentRule {
    id: i64,
    effect: PolicyEffect,
    scope: ApprovalScope,
    fingerprint: String,
    operation_fingerprint: Option<String>,
    source: String,
    executable: String,
    operation_class: String,
    directory: String,
    scope_root: Option<String>,
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
        initialize_schema(&connection)?;
        Ok(Self { connection })
    }

    fn insert(
        &self,
        effect: PolicyEffect,
        scope: ApprovalScope,
        request: &NormalizedPolicyRequest,
        scope_root: Option<&Path>,
    ) -> Result<PersistentRule, String> {
        if !scope.is_persistent() {
            return Err(format!("scope {} is not persistent", scope.as_str()));
        }

        let scope_root_text = scope_root.map(path_text).transpose()?;

        if let Some(existing) = self
            .list()?
            .into_iter()
            .find(|rule| persistent_rule_identity_matches(rule, effect, scope, request, scope_root_text.as_deref()))
        {
            return Ok(existing);
        }

        let created_at_ms = now_ms() as i64;
        self.connection
            .execute(
                "INSERT INTO policy_rules (
                    effect, scope, fingerprint, operation_fingerprint, source,
                    executable, operation_class, directory, scope_root,
                    environment_key_count, created_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    effect.as_str(),
                    scope.as_str(),
                    request.fingerprint,
                    request.operation_fingerprint,
                    request.source,
                    request.executable,
                    request.operation_class,
                    request.directory_text,
                    scope_root_text,
                    request.environment_keys.len() as i64,
                    created_at_ms,
                ],
            )
            .map_err(|error| format!("failed to persist policy rule: {error}"))?;

        let id = self.connection.last_insert_rowid();
        self.find(id)?
            .ok_or_else(|| "persistent policy rule was inserted but could not be reloaded".to_string())
    }

    fn find(&self, id: i64) -> Result<Option<PersistentRule>, String> {
        self.list()
            .map(|rules| rules.into_iter().find(|rule| rule.id == id))
    }

    fn list(&self) -> Result<Vec<PersistentRule>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, effect, scope, fingerprint, operation_fingerprint, source,
                        executable, operation_class, directory, scope_root,
                        environment_key_count, created_at_ms
                 FROM policy_rules
                 ORDER BY id ASC",
            )
            .map_err(|error| format!("failed to prepare policy rule list: {error}"))?;

        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            })
            .map_err(|error| format!("failed to list persistent policy rules: {error}"))?;

        let mut rules = Vec::new();
        for row in rows {
            let (
                id,
                effect,
                scope,
                fingerprint,
                operation_fingerprint,
                source,
                executable,
                operation_class,
                directory,
                scope_root,
                environment_key_count,
                created_at_ms,
            ) = row.map_err(|error| format!("failed to decode persistent policy rule: {error}"))?;

            rules.push(PersistentRule {
                id,
                effect: PolicyEffect::parse(&effect)?,
                scope: ApprovalScope::parse(&scope)?,
                fingerprint,
                operation_fingerprint,
                source,
                executable,
                operation_class,
                directory,
                scope_root,
                environment_key_count: environment_key_count.max(0) as usize,
                created_at_ms: created_at_ms.max(0) as u64,
            });
        }

        Ok(rules)
    }

    fn matching(
        &self,
        effect: PolicyEffect,
        request: &NormalizedPolicyRequest,
    ) -> Result<Vec<PersistentRule>, String> {
        let mut matching = self
            .list()?
            .into_iter()
            .filter(|rule| rule.effect == effect && persistent_rule_matches(rule, request))
            .collect::<Vec<_>>();

        matching.sort_by_key(|rule| persistent_scope_priority(rule.scope));
        Ok(matching)
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

fn initialize_schema(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            ",
        )
        .map_err(|error| format!("failed to initialize policy database pragmas: {error}"))?;

    let has_table: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'policy_rules'
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("failed to inspect policy database: {error}"))?;

    if !has_table {
        create_current_schema(connection)?;
        return Ok(());
    }

    let mut statement = connection
        .prepare("PRAGMA table_info(policy_rules)")
        .map_err(|error| format!("failed to inspect policy schema: {error}"))?;
    let column_rows = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|error| format!("failed to read policy schema: {error}"))?;
    let columns = column_rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to decode policy schema: {error}"))?;

    if columns.iter().any(|column| column == "scope") {
        return Ok(());
    }

    connection
        .execute_batch(
            "
            BEGIN IMMEDIATE;
            ALTER TABLE policy_rules RENAME TO policy_rules_legacy;
            CREATE TABLE policy_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
                scope TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                operation_fingerprint TEXT NULL,
                source TEXT NOT NULL,
                executable TEXT NOT NULL,
                operation_class TEXT NOT NULL,
                directory TEXT NOT NULL,
                scope_root TEXT NULL,
                environment_key_count INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            INSERT INTO policy_rules (
                id, effect, scope, fingerprint, operation_fingerprint, source,
                executable, operation_class, directory, scope_root,
                environment_key_count, created_at_ms
            )
            SELECT
                id, effect, 'exact_request', fingerprint, NULL, source,
                executable, operation_class, directory, directory,
                environment_key_count, created_at_ms
            FROM policy_rules_legacy;
            DROP TABLE policy_rules_legacy;
            CREATE INDEX idx_policy_rules_fingerprint
                ON policy_rules(effect, fingerprint);
            CREATE INDEX idx_policy_rules_operation
                ON policy_rules(effect, operation_fingerprint, scope);
            COMMIT;
            ",
        )
        .map_err(|error| format!("failed to migrate policy database: {error}"))
}

fn create_current_schema(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "
            CREATE TABLE policy_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
                scope TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                operation_fingerprint TEXT NULL,
                source TEXT NOT NULL,
                executable TEXT NOT NULL,
                operation_class TEXT NOT NULL,
                directory TEXT NOT NULL,
                scope_root TEXT NULL,
                environment_key_count INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            CREATE INDEX idx_policy_rules_fingerprint
                ON policy_rules(effect, fingerprint);
            CREATE INDEX idx_policy_rules_operation
                ON policy_rules(effect, operation_fingerprint, scope);
            ",
        )
        .map_err(|error| format!("failed to create policy database schema: {error}"))
}

fn persistent_rule_identity_matches(
    rule: &PersistentRule,
    effect: PolicyEffect,
    scope: ApprovalScope,
    request: &NormalizedPolicyRequest,
    scope_root: Option<&str>,
) -> bool {
    rule.effect == effect
        && rule.scope == scope
        && rule.fingerprint == request.fingerprint
        && rule.operation_fingerprint.as_deref() == Some(request.operation_fingerprint.as_str())
        && rule.scope_root.as_deref() == scope_root
}

fn persistent_rule_matches(rule: &PersistentRule, request: &NormalizedPolicyRequest) -> bool {
    match rule.scope {
        ApprovalScope::ExactRequest | ApprovalScope::Deny => rule.fingerprint == request.fingerprint,
        ApprovalScope::ExactDirectory => {
            rule.operation_fingerprint.as_deref() == Some(request.operation_fingerprint.as_str())
                && rule
                    .scope_root
                    .as_deref()
                    .is_some_and(|root| path_equals_stored_root(&request.directory, root))
        }
        ApprovalScope::DirectoryTree => {
            rule.operation_fingerprint.as_deref() == Some(request.operation_fingerprint.as_str())
                && rule
                    .scope_root
                    .as_deref()
                    .is_some_and(|root| path_within_stored_root(&request.directory, root))
        }
        ApprovalScope::Always => {
            rule.operation_fingerprint.as_deref() == Some(request.operation_fingerprint.as_str())
        }
        ApprovalScope::Once | ApprovalScope::Session => false,
    }
}

fn path_equals_stored_root(request_directory: &Path, stored_root: &str) -> bool {
    request_directory == Path::new(stored_root)
}

fn path_within_stored_root(request_directory: &Path, stored_root: &str) -> bool {
    request_directory.starts_with(Path::new(stored_root))
}

fn persistent_scope_priority(scope: ApprovalScope) -> u8 {
    match scope {
        ApprovalScope::Deny => 0,
        ApprovalScope::ExactRequest => 1,
        ApprovalScope::ExactDirectory => 2,
        ApprovalScope::DirectoryTree => 3,
        ApprovalScope::Always => 4,
        ApprovalScope::Once => 5,
        ApprovalScope::Session => 6,
    }
}

struct PolicyEngine {
    persistent: PersistentRuleStore,
    ephemeral: Vec<EphemeralRule>,
    next_ephemeral_rule_id: u64,
    recent_decisions: VecDeque<PolicyDecisionEvent>,
    next_decision_sequence: u64,
}

impl PolicyEngine {
    fn open(path: &Path) -> Result<Self, String> {
        Ok(Self {
            persistent: PersistentRuleStore::open(path)?,
            ephemeral: Vec::new(),
            next_ephemeral_rule_id: 1,
            recent_decisions: VecDeque::new(),
            next_decision_sequence: 1,
        })
    }

    fn record_decision(
        &mut self,
        request: &NormalizedPolicyRequest,
        decision: &PolicyDecision,
    ) {
        const RECENT_DECISIONS_LIMIT: usize = 20;

        self.recent_decisions.push_front(PolicyDecisionEvent {
            sequence: self.next_decision_sequence,
            timestamp_ms: now_ms(),
            source: request.source.clone(),
            executable: request.executable.clone(),
            operation_class: request.operation_class.clone(),
            directory: request.directory_text.clone(),
            outcome: decision.outcome,
            rule_id: decision.rule_id.clone(),
            reason: decision.reason.clone(),
        });
        self.next_decision_sequence += 1;

        while self.recent_decisions.len() > RECENT_DECISIONS_LIMIT {
            self.recent_decisions.pop_back();
        }
    }

    fn recent_decisions(&self) -> Vec<PolicyDecisionEvent> {
        self.recent_decisions.iter().cloned().collect()
    }

    fn decide(&mut self, request: &NormalizedPolicyRequest) -> Result<PolicyDecision, String> {
        if let Some(rule) = self
            .ephemeral
            .iter()
            .find(|rule| ephemeral_rule_matches(rule, PolicyEffect::Deny, request))
            .cloned()
        {
            return Ok(decision_for_rule(PolicyOutcome::Deny, &ephemeral_rule_view(&rule)));
        }

        if let Some(rule) = self
            .persistent
            .matching(PolicyEffect::Deny, request)?
            .into_iter()
            .next()
        {
            return Ok(decision_for_rule(PolicyOutcome::Deny, &persistent_rule_view(&rule)));
        }

        if let Some(index) = self.ephemeral.iter().position(|rule| {
            rule.effect == PolicyEffect::Allow
                && rule.scope == ApprovalScope::Once
                && ephemeral_request_matches(rule, request)
        }) {
            let rule = self.ephemeral.remove(index);
            return Ok(decision_for_rule(PolicyOutcome::Allow, &ephemeral_rule_view(&rule)));
        }

        if let Some(rule) = self
            .ephemeral
            .iter()
            .find(|rule| {
                rule.effect == PolicyEffect::Allow
                    && rule.scope == ApprovalScope::Session
                    && ephemeral_request_matches(rule, request)
            })
            .cloned()
        {
            return Ok(decision_for_rule(PolicyOutcome::Allow, &ephemeral_rule_view(&rule)));
        }

        if let Some(rule) = self
            .persistent
            .matching(PolicyEffect::Allow, request)?
            .into_iter()
            .next()
        {
            return Ok(decision_for_rule(PolicyOutcome::Allow, &persistent_rule_view(&rule)));
        }

        Ok(PolicyDecision {
            outcome: PolicyOutcome::Ask,
            rule_id: None,
            reason: "No matching ShellWarden permission rule; explicit user approval is required."
                .to_string(),
        })
    }

    fn grant_scope(
        &mut self,
        scope: ApprovalScope,
        request: &NormalizedPolicyRequest,
        risk_policy_allows_always: bool,
    ) -> Result<PolicyRuleView, String> {
        match scope {
            ApprovalScope::Once => self.grant_ephemeral(PolicyEffect::Allow, scope, request, false),
            ApprovalScope::Session => {
                self.grant_ephemeral(PolicyEffect::Allow, scope, request, true)
            }
            ApprovalScope::ExactRequest => self.grant_persistent(
                PolicyEffect::Allow,
                ApprovalScope::ExactRequest,
                request,
                Some(&request.directory),
            ),
            ApprovalScope::ExactDirectory => self.grant_persistent(
                PolicyEffect::Allow,
                scope,
                request,
                Some(&request.directory),
            ),
            ApprovalScope::DirectoryTree => self.grant_persistent(
                PolicyEffect::Allow,
                scope,
                request,
                Some(&request.directory),
            ),
            ApprovalScope::Always => {
                if !risk_policy_allows_always {
                    return Err(
                        "always-allow scope requires an explicit positive risk-policy decision"
                            .to_string(),
                    );
                }
                self.grant_persistent(PolicyEffect::Allow, scope, request, None)
            }
            ApprovalScope::Deny => {
                self.grant_persistent(PolicyEffect::Deny, scope, request, Some(&request.directory))
            }
        }
    }

    fn grant_ephemeral(
        &mut self,
        effect: PolicyEffect,
        scope: ApprovalScope,
        request: &NormalizedPolicyRequest,
        require_session: bool,
    ) -> Result<PolicyRuleView, String> {
        if !matches!(scope, ApprovalScope::Once | ApprovalScope::Session | ApprovalScope::Deny) {
            return Err(format!("scope {} is not ephemeral", scope.as_str()));
        }

        if require_session && request.session_id.is_none() {
            return Err("session-scoped permission requires a session id".to_string());
        }

        if let Some(existing) = self
            .ephemeral
            .iter()
            .find(|rule| {
                rule.effect == effect
                    && rule.scope == scope
                    && rule.session_id == request.session_id
                    && rule.fingerprint == request.fingerprint
            })
            .cloned()
        {
            return Ok(ephemeral_rule_view(&existing));
        }

        let rule = EphemeralRule {
            id: self.next_ephemeral_rule_id,
            effect,
            scope,
            session_id: request.session_id.clone(),
            fingerprint: request.fingerprint.clone(),
            source: request.source.clone(),
            executable: request.executable.clone(),
            operation_class: request.operation_class.clone(),
            directory: request.directory_text.clone(),
            environment_key_count: request.environment_keys.len(),
            created_at_ms: now_ms(),
        };
        self.next_ephemeral_rule_id += 1;
        let view = ephemeral_rule_view(&rule);
        self.ephemeral.push(rule);
        Ok(view)
    }

    fn grant_persistent(
        &self,
        effect: PolicyEffect,
        scope: ApprovalScope,
        request: &NormalizedPolicyRequest,
        scope_root: Option<&Path>,
    ) -> Result<PolicyRuleView, String> {
        self.persistent
            .insert(effect, scope, request, scope_root)
            .map(|rule| persistent_rule_view(&rule))
    }

    fn list(&self) -> Result<Vec<PolicyRuleView>, String> {
        let mut rules = self
            .ephemeral
            .iter()
            .map(ephemeral_rule_view)
            .collect::<Vec<_>>();
        rules.extend(
            self.persistent
                .list()?
                .iter()
                .map(persistent_rule_view),
        );
        rules.sort_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then(left.id.cmp(&right.id))
        });
        Ok(rules)
    }

    fn revoke(&mut self, id: &str) -> Result<bool, String> {
        if let Some(raw) = id.strip_prefix("ephemeral-") {
            let parsed = raw
                .parse::<u64>()
                .map_err(|_| format!("invalid ephemeral policy rule id: {id}"))?;
            let before = self.ephemeral.len();
            self.ephemeral.retain(|rule| rule.id != parsed);
            return Ok(self.ephemeral.len() != before);
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
        let before = self.ephemeral.len();
        self.ephemeral
            .retain(|rule| rule.session_id.as_deref() != Some(session_id));
        before - self.ephemeral.len()
    }

    fn reset_all_sessions(&mut self) -> usize {
        let removed = self.ephemeral.len();
        self.ephemeral.clear();
        removed
    }

    fn reset_persistent(&self) -> Result<usize, String> {
        self.persistent.reset()
    }
}

fn ephemeral_rule_matches(
    rule: &EphemeralRule,
    effect: PolicyEffect,
    request: &NormalizedPolicyRequest,
) -> bool {
    rule.effect == effect && ephemeral_request_matches(rule, request)
}

fn ephemeral_request_matches(rule: &EphemeralRule, request: &NormalizedPolicyRequest) -> bool {
    rule.fingerprint == request.fingerprint
        && rule
            .session_id
            .as_ref()
            .is_none_or(|session_id| request.session_id.as_ref() == Some(session_id))
}

fn ephemeral_rule_view(rule: &EphemeralRule) -> PolicyRuleView {
    PolicyRuleView {
        id: format!("ephemeral-{}", rule.id),
        effect: rule.effect,
        scope: rule.scope,
        persistence: "ephemeral".to_string(),
        source: rule.source.clone(),
        session_id: rule.session_id.clone(),
        executable: rule.executable.clone(),
        operation_class: rule.operation_class.clone(),
        directory: rule.directory.clone(),
        scope_root: Some(rule.directory.clone()),
        environment_key_count: rule.environment_key_count,
        created_at_ms: rule.created_at_ms,
    }
}

fn persistent_rule_view(rule: &PersistentRule) -> PolicyRuleView {
    PolicyRuleView {
        id: format!("persistent-{}", rule.id),
        effect: rule.effect,
        scope: rule.scope,
        persistence: "persistent".to_string(),
        source: rule.source.clone(),
        session_id: None,
        executable: rule.executable.clone(),
        operation_class: rule.operation_class.clone(),
        directory: rule.directory.clone(),
        scope_root: rule.scope_root.clone(),
        environment_key_count: rule.environment_key_count,
        created_at_ms: rule.created_at_ms,
    }
}

fn decision_for_rule(outcome: PolicyOutcome, rule: &PolicyRuleView) -> PolicyDecision {
    PolicyDecision {
        outcome,
        rule_id: Some(rule.id.clone()),
        reason: format!(
            "Matched {} {} {} rule {} for {}.",
            rule.persistence,
            rule.scope.as_str(),
            rule.effect.as_str(),
            rule.id,
            rule.executable
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
        let mut engine = self.engine();
        let engine = engine
            .as_mut()
            .ok_or_else(|| "policy engine is not initialized".to_string())?;
        let decision = engine.decide(&request)?;
        engine.record_decision(&request, &decision);
        Ok(decision)
    }

    pub fn recent_decisions(&self) -> Result<Vec<PolicyDecisionEvent>, String> {
        let engine = self.engine();
        Ok(engine
            .as_ref()
            .ok_or_else(|| "policy engine is not initialized".to_string())?
            .recent_decisions())
    }

    pub fn grant_scope_checked(
        &self,
        scope: ApprovalScope,
        input: PolicyRequestInput,
    ) -> Result<PolicyRuleView, String> {
        let risk = assess_command(&input.command, &input.operation_class)?;
        if !risk.allows_scope(scope) {
            return Err(format!(
                "risk policy {:?} does not permit {} scope: {}",
                risk.class,
                scope.as_str(),
                risk.reason
            ));
        }

        let risk_policy_allows_always = risk.allows_scope(ApprovalScope::Always);
        self.grant_scope(scope, input, risk_policy_allows_always)
    }

    pub fn grant_scope(
        &self,
        scope: ApprovalScope,
        input: PolicyRequestInput,
        risk_policy_allows_always: bool,
    ) -> Result<PolicyRuleView, String> {
        let request = NormalizedPolicyRequest::from_input(input)?;
        let mut engine = self.engine();
        engine
            .as_mut()
            .ok_or_else(|| "policy engine is not initialized".to_string())?
            .grant_scope(scope, &request, risk_policy_allows_always)
    }

    pub fn grant_session(
        &self,
        effect: PolicyEffect,
        input: PolicyRequestInput,
    ) -> Result<PolicyRuleView, String> {
        let request = NormalizedPolicyRequest::from_input(input)?;
        let mut engine = self.engine();
        let engine = engine
            .as_mut()
            .ok_or_else(|| "policy engine is not initialized".to_string())?;

        match effect {
            PolicyEffect::Allow => {
                engine.grant_ephemeral(effect, ApprovalScope::Session, &request, true)
            }
            PolicyEffect::Deny => {
                engine.grant_ephemeral(effect, ApprovalScope::Deny, &request, true)
            }
        }
    }

    pub fn grant_persistent(
        &self,
        effect: PolicyEffect,
        input: PolicyRequestInput,
    ) -> Result<PolicyRuleView, String> {
        let request = NormalizedPolicyRequest::from_input(input)?;
        let engine = self.engine();
        let engine = engine
            .as_ref()
            .ok_or_else(|| "policy engine is not initialized".to_string())?;

        match effect {
            PolicyEffect::Allow => engine.grant_persistent(
                effect,
                ApprovalScope::ExactRequest,
                &request,
                Some(&request.directory),
            ),
            PolicyEffect::Deny => engine.grant_persistent(
                effect,
                ApprovalScope::Deny,
                &request,
                Some(&request.directory),
            ),
        }
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
        now_ms, ApprovalScope, NormalizedPolicyRequest, PolicyEffect, PolicyOutcome,
        PolicyRequestInput, PolicyState,
    };
    use rusqlite::{params, Connection};
    use std::{
        fs,
        path::{Path, PathBuf},
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[cfg(windows)]
    use std::process::Command;

    fn unique_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "shellwarden-scope-{name}-{}-{nonce}",
            process::id()
        ))
    }

    fn database_path(root: &Path) -> PathBuf {
        root.join("permissions.sqlite3")
    }

    fn request(directory: &Path, session_id: Option<&str>, arg: &str) -> PolicyRequestInput {
        PolicyRequestInput {
            source: "test-client".to_string(),
            session_id: session_id.map(str::to_string),
            command: vec!["git".to_string(), arg.to_string()],
            operation_class: "read".to_string(),
            directory: directory.to_string_lossy().to_string(),
            environment_keys: vec!["PATH".to_string()],
        }
    }

    fn setup(name: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let root = unique_root(name);
        let repo = root.join("repo");
        let child = repo.join("child");
        let sibling = root.join("sibling");
        fs::create_dir_all(&child).expect("child");
        fs::create_dir_all(&sibling).expect("sibling");
        (root, repo, child, sibling)
    }

    #[test]
    fn once_grant_is_consumed_only_by_the_intended_request() {
        let (root, repo, _, _) = setup("once");
        let state = PolicyState::default();
        state.initialize(&database_path(&root)).expect("initialize");

        state
            .grant_scope(
                ApprovalScope::Once,
                request(&repo, Some("session-a"), "status"),
                false,
            )
            .expect("once grant");

        assert_eq!(
            state
                .decide(request(&repo, Some("session-a"), "diff"))
                .expect("different argv")
                .outcome,
            PolicyOutcome::Ask
        );
        assert_eq!(
            state
                .decide(request(&repo, Some("session-a"), "status"))
                .expect("first intended request")
                .outcome,
            PolicyOutcome::Allow
        );
        assert_eq!(
            state
                .decide(request(&repo, Some("session-a"), "status"))
                .expect("consumed")
                .outcome,
            PolicyOutcome::Ask
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn session_grant_is_bound_to_session_and_exact_request() {
        let (root, repo, _, _) = setup("session");
        let state = PolicyState::default();
        state.initialize(&database_path(&root)).expect("initialize");

        state
            .grant_scope(
                ApprovalScope::Session,
                request(&repo, Some("session-a"), "status"),
                false,
            )
            .expect("session grant");

        assert_eq!(
            state
                .decide(request(&repo, Some("session-a"), "status"))
                .expect("same")
                .outcome,
            PolicyOutcome::Allow
        );
        assert_eq!(
            state
                .decide(request(&repo, Some("session-b"), "status"))
                .expect("different session")
                .outcome,
            PolicyOutcome::Ask
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn exact_directory_does_not_authorize_child_or_sibling() {
        let (root, repo, child, sibling) = setup("exact");
        let state = PolicyState::default();
        state.initialize(&database_path(&root)).expect("initialize");

        state
            .grant_scope(
                ApprovalScope::ExactDirectory,
                request(&repo, Some("session-a"), "status"),
                false,
            )
            .expect("exact directory grant");

        assert_eq!(
            state
                .decide(request(&repo, Some("session-b"), "status"))
                .expect("root")
                .outcome,
            PolicyOutcome::Allow
        );
        assert_eq!(
            state
                .decide(request(&child, Some("session-b"), "status"))
                .expect("child")
                .outcome,
            PolicyOutcome::Ask
        );
        assert_eq!(
            state
                .decide(request(&sibling, Some("session-b"), "status"))
                .expect("sibling")
                .outcome,
            PolicyOutcome::Ask
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn directory_tree_authorizes_descendants_but_not_siblings_or_traversal() {
        let (root, repo, child, sibling) = setup("tree");
        let state = PolicyState::default();
        state.initialize(&database_path(&root)).expect("initialize");

        state
            .grant_scope(
                ApprovalScope::DirectoryTree,
                request(&repo, None, "status"),
                false,
            )
            .expect("tree grant");

        assert_eq!(
            state.decide(request(&child, None, "status")).expect("child").outcome,
            PolicyOutcome::Allow
        );
        assert_eq!(
            state
                .decide(request(&sibling, None, "status"))
                .expect("sibling")
                .outcome,
            PolicyOutcome::Ask
        );

        let traversal = child.join("..").join("..").join("sibling");
        assert_eq!(
            state
                .decide(request(&traversal, None, "status"))
                .expect("traversal")
                .outcome,
            PolicyOutcome::Ask
        );

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn tree_grant_does_not_follow_symlink_outside_canonical_root() {
        use std::os::unix::fs::symlink;

        let (root, repo, _, sibling) = setup("symlink");
        let outside_child = sibling.join("outside-child");
        fs::create_dir_all(&outside_child).expect("outside child");
        let link = repo.join("escape");
        symlink(&sibling, &link).expect("symlink");

        let state = PolicyState::default();
        state.initialize(&database_path(&root)).expect("initialize");
        state
            .grant_scope(
                ApprovalScope::DirectoryTree,
                request(&repo, None, "status"),
                false,
            )
            .expect("tree grant");

        assert_eq!(
            state
                .decide(request(&link.join("outside-child"), None, "status"))
                .expect("symlink escape")
                .outcome,
            PolicyOutcome::Ask
        );

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn tree_grant_does_not_follow_junction_outside_canonical_root() {
        let (root, repo, _, sibling) = setup("junction");
        let outside_child = sibling.join("outside-child");
        fs::create_dir_all(&outside_child).expect("outside child");
        let link = repo.join("escape");

        let status = Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                link.to_str().expect("link path"),
                sibling.to_str().expect("target path"),
            ])
            .status()
            .expect("run mklink");
        assert!(status.success(), "junction creation must succeed for path-escape coverage");

        let state = PolicyState::default();
        state.initialize(&database_path(&root)).expect("initialize");
        state
            .grant_scope(
                ApprovalScope::DirectoryTree,
                request(&repo, None, "status"),
                false,
            )
            .expect("tree grant");

        assert_eq!(
            state
                .decide(request(&link.join("outside-child"), None, "status"))
                .expect("junction escape")
                .outcome,
            PolicyOutcome::Ask
        );

        let _ = Command::new("cmd")
            .args(["/C", "rmdir", link.to_str().expect("link path")])
            .status();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn always_scope_requires_positive_risk_policy_gate() {
        let (root, repo, _, sibling) = setup("always");
        let state = PolicyState::default();
        state.initialize(&database_path(&root)).expect("initialize");

        assert!(state
            .grant_scope(
                ApprovalScope::Always,
                request(&repo, None, "status"),
                false,
            )
            .is_err());

        state
            .grant_scope(
                ApprovalScope::Always,
                request(&repo, None, "status"),
                true,
            )
            .expect("risk-approved always");

        assert_eq!(
            state
                .decide(request(&sibling, None, "status"))
                .expect("global operation")
                .outcome,
            PolicyOutcome::Allow
        );
        assert_eq!(
            state
                .decide(request(&sibling, None, "diff"))
                .expect("different argv")
                .outcome,
            PolicyOutcome::Ask
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deny_precedes_scoped_allow_and_revoke_invalidates_future_match() {
        let (root, repo, child, _) = setup("deny");
        let state = PolicyState::default();
        state.initialize(&database_path(&root)).expect("initialize");

        state
            .grant_scope(
                ApprovalScope::DirectoryTree,
                request(&repo, None, "status"),
                false,
            )
            .expect("tree grant");
        let deny = state
            .grant_scope(
                ApprovalScope::Deny,
                request(&child, None, "status"),
                false,
            )
            .expect("deny");

        assert_eq!(
            state
                .decide(request(&child, None, "status"))
                .expect("deny wins")
                .outcome,
            PolicyOutcome::Deny
        );

        assert!(state.revoke(&deny.id).expect("revoke"));
        assert_eq!(
            state
                .decide(request(&child, None, "status"))
                .expect("tree allow returns")
                .outcome,
            PolicyOutcome::Allow
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn persistent_scopes_survive_restart_without_raw_argv() {
        let (root, repo, child, _) = setup("restart");
        let db = database_path(&root);

        {
            let state = PolicyState::default();
            state.initialize(&db).expect("initialize");
            state
                .grant_scope(
                    ApprovalScope::DirectoryTree,
                    request(&repo, None, "status"),
                    false,
                )
                .expect("tree grant");
        }

        let restarted = PolicyState::default();
        restarted.initialize(&db).expect("reinitialize");
        assert_eq!(
            restarted
                .decide(request(&child, None, "status"))
                .expect("persisted tree")
                .outcome,
            PolicyOutcome::Allow
        );

        let database_text = String::from_utf8_lossy(&fs::read(&db).expect("read db")).to_string();
        assert!(
            !database_text.contains("status"),
            "raw argv must not be persisted in scoped permission rules"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_exact_rules_migrate_and_keep_exact_behavior() {
        let (root, repo, child, _) = setup("migration");
        let db = database_path(&root);
        {
            let connection = Connection::open(&db).expect("legacy db");
            connection
                .execute_batch(
                    "
                    CREATE TABLE policy_rules (
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
                    ",
                )
                .expect("legacy schema");

            let normalized =
                NormalizedPolicyRequest::from_input(request(&repo, None, "status")).expect("normalize");
            connection
                .execute(
                    "INSERT INTO policy_rules (
                        effect, fingerprint, source, executable, operation_class,
                        directory, environment_key_count, created_at_ms
                     ) VALUES ('allow', ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        normalized.fingerprint,
                        normalized.source,
                        normalized.executable,
                        normalized.operation_class,
                        normalized.directory_text,
                        normalized.environment_keys.len() as i64,
                        now_ms() as i64,
                    ],
                )
                .expect("legacy row");
        }

        let state = PolicyState::default();
        state.initialize(&db).expect("migrate");
        assert_eq!(
            state.decide(request(&repo, None, "status")).expect("exact").outcome,
            PolicyOutcome::Allow
        );
        assert_eq!(
            state
                .decide(request(&child, None, "status"))
                .expect("child remains out of scope")
                .outcome,
            PolicyOutcome::Ask
        );

        let rules = state.list().expect("list");
        assert_eq!(rules[0].scope, ApprovalScope::ExactRequest);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn recent_decisions_are_bounded_session_memory_with_explainable_metadata() {
        let (root, repo, _, _) = setup("recent-decisions");
        let state = PolicyState::default();
        state.initialize(&database_path(&root)).expect("initialize");

        for _ in 0..25 {
            let decision = state
                .decide(request(&repo, Some("session-a"), "status"))
                .expect("decision");
            assert_eq!(decision.outcome, PolicyOutcome::Ask);
        }

        let recent = state.recent_decisions().expect("recent decisions");
        assert_eq!(recent.len(), 20);
        assert_eq!(recent[0].executable, "git");
        assert_eq!(recent[0].operation_class, "read");
        assert_eq!(recent[0].outcome, PolicyOutcome::Ask);
        assert!(recent[0].reason.contains("explicit user approval"));

        let _ = fs::remove_dir_all(root);
    }

}

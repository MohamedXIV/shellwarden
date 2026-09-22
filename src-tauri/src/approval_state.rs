use crate::{
    permission_policy::{ApprovalScope, PolicyDecision, PolicyOutcome, PolicyRequestInput, PolicyState},
    risk_policy::{assess_command, RiskAssessment},
};
use serde::Serialize;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, Sender},
        Mutex, MutexGuard,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const RETAINED_APPROVALS: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Allowed,
    Denied,
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalView {
    pub id: String,
    pub execution_id: Option<String>,
    pub source: String,
    pub session_id: Option<String>,
    pub command: Vec<String>,
    pub operation_class: String,
    pub directory: String,
    pub environment_keys: Vec<String>,
    pub risk: RiskAssessment,
    pub status: ApprovalStatus,
    pub requested_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub resolved_at_ms: Option<u64>,
    pub resolution_scope: Option<ApprovalScope>,
    pub decision_rule_id: Option<String>,
    pub decision_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalResolution {
    pub approval: ApprovalView,
    pub decision: Option<PolicyDecision>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApprovalEvent {
    Changed {
        sequence: u64,
        approval: ApprovalView,
    },
}

#[derive(Clone)]
struct ApprovalRecord {
    view: ApprovalView,
    input: PolicyRequestInput,
}

#[derive(Default)]
struct ApprovalInner {
    records: VecDeque<ApprovalRecord>,
    subscribers: Vec<Sender<ApprovalEvent>>,
}

#[derive(Default)]
pub struct ApprovalState {
    inner: Mutex<ApprovalInner>,
    id_counter: AtomicU64,
    event_counter: AtomicU64,
}

impl ApprovalState {
    fn inner(&self) -> MutexGuard<'_, ApprovalInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn request(
        &self,
        input: PolicyRequestInput,
        execution_id: Option<String>,
        ttl_seconds: Option<u64>,
    ) -> Result<ApprovalView, String> {
        let risk = assess_command(&input.command, &input.operation_class)?;
        let requested_at_ms = now_ms();
        let expires_at_ms = ttl_seconds
            .filter(|seconds| *seconds > 0)
            .map(|seconds| requested_at_ms.saturating_add(seconds.saturating_mul(1000)));
        let id = format!(
            "approval-{}-{}",
            requested_at_ms,
            self.id_counter.fetch_add(1, Ordering::Relaxed) + 1
        );

        let view = ApprovalView {
            id,
            execution_id,
            source: input.source.clone(),
            session_id: input.session_id.clone(),
            command: input.command.clone(),
            operation_class: input.operation_class.clone(),
            directory: input.directory.clone(),
            environment_keys: input.environment_keys.clone(),
            risk,
            status: ApprovalStatus::Pending,
            requested_at_ms,
            expires_at_ms,
            resolved_at_ms: None,
            resolution_scope: None,
            decision_rule_id: None,
            decision_reason: None,
        };

        let mut inner = self.inner();
        inner.records.push_front(ApprovalRecord {
            view: view.clone(),
            input,
        });
        while inner.records.len() > RETAINED_APPROVALS {
            inner.records.pop_back();
        }
        self.publish(&mut inner, view.clone());
        Ok(view)
    }

    pub fn snapshot(&self) -> Vec<ApprovalView> {
        self.expire_due();
        self.inner()
            .records
            .iter()
            .map(|record| record.view.clone())
            .collect()
    }

    pub fn pending_count(&self) -> usize {
        self.inner()
            .records
            .iter()
            .filter(|record| record.view.status == ApprovalStatus::Pending)
            .count()
    }

    pub fn resolve(
        &self,
        approval_id: &str,
        scope: ApprovalScope,
        policy: &PolicyState,
    ) -> Result<ApprovalResolution, String> {
        self.expire_due();

        let input = {
            let inner = self.inner();
            let record = inner
                .records
                .iter()
                .find(|record| record.view.id == approval_id)
                .ok_or_else(|| format!("unknown approval id: {approval_id}"))?;

            if record.view.status != ApprovalStatus::Pending {
                return Err(format!(
                    "approval {approval_id} is no longer pending ({:?})",
                    record.view.status
                ));
            }

            if !record.view.risk.allows_scope(scope) {
                return Err(format!(
                    "risk policy {:?} does not permit {:?} approval scope",
                    record.view.risk.class, scope
                ));
            }

            record.input.clone()
        };

        let decision = if scope == ApprovalScope::Deny {
            Some(policy.record_manual_denial(
                input.clone(),
                "User denied this pending execution request.",
            )?)
        } else {
            policy.grant_scope_checked(scope, input.clone())?;
            Some(policy.decide(input)?)
        };

        let status = match decision.as_ref().map(|value| value.outcome) {
            Some(PolicyOutcome::Allow) => ApprovalStatus::Allowed,
            Some(PolicyOutcome::Deny) => ApprovalStatus::Denied,
            Some(PolicyOutcome::Ask) | None => {
                return Err("approval resolution did not produce a terminal policy decision".to_string())
            }
        };

        let resolved_at_ms = now_ms();
        let mut inner = self.inner();
        let record = inner
            .records
            .iter_mut()
            .find(|record| record.view.id == approval_id)
            .ok_or_else(|| format!("unknown approval id: {approval_id}"))?;

        if record.view.status != ApprovalStatus::Pending {
            return Err(format!(
                "approval {approval_id} changed while it was being resolved"
            ));
        }

        record.view.status = status;
        record.view.resolved_at_ms = Some(resolved_at_ms);
        record.view.resolution_scope = Some(scope);
        record.view.decision_rule_id = decision.as_ref().and_then(|value| value.rule_id.clone());
        record.view.decision_reason = decision.as_ref().map(|value| value.reason.clone());
        let view = record.view.clone();
        self.publish(&mut inner, view.clone());

        Ok(ApprovalResolution {
            approval: view,
            decision,
        })
    }

    pub fn cancel(&self, approval_id: &str, reason: impl Into<String>) -> Result<ApprovalView, String> {
        let mut inner = self.inner();
        let record = inner
            .records
            .iter_mut()
            .find(|record| record.view.id == approval_id)
            .ok_or_else(|| format!("unknown approval id: {approval_id}"))?;

        if record.view.status != ApprovalStatus::Pending {
            return Ok(record.view.clone());
        }

        record.view.status = ApprovalStatus::Cancelled;
        record.view.resolved_at_ms = Some(now_ms());
        record.view.decision_reason = Some(reason.into());
        let view = record.view.clone();
        self.publish(&mut inner, view.clone());
        Ok(view)
    }

    pub fn cancel_pending_by_source(&self, source: &str, reason: &str) -> usize {
        let mut inner = self.inner();
        let timestamp_ms = now_ms();
        let mut changed = Vec::new();

        for record in &mut inner.records {
            if record.view.status == ApprovalStatus::Pending && record.view.source == source {
                record.view.status = ApprovalStatus::Cancelled;
                record.view.resolved_at_ms = Some(timestamp_ms);
                record.view.decision_reason = Some(reason.to_string());
                changed.push(record.view.clone());
            }
        }

        let count = changed.len();
        for approval in changed {
            self.publish(&mut inner, approval);
        }
        count
    }

    pub fn subscribe(&self) -> Receiver<ApprovalEvent> {
        let (sender, receiver) = mpsc::channel();
        self.inner().subscribers.push(sender);
        receiver
    }

    fn expire_due(&self) {
        let timestamp_ms = now_ms();
        let mut inner = self.inner();
        let mut changed = Vec::new();

        for record in &mut inner.records {
            if record.view.status == ApprovalStatus::Pending
                && record
                    .view
                    .expires_at_ms
                    .is_some_and(|expires_at_ms| expires_at_ms <= timestamp_ms)
            {
                record.view.status = ApprovalStatus::Expired;
                record.view.resolved_at_ms = Some(timestamp_ms);
                record.view.decision_reason =
                    Some("Approval expired before the user resolved it.".to_string());
                changed.push(record.view.clone());
            }
        }

        for approval in changed {
            self.publish(&mut inner, approval);
        }
    }

    fn publish(&self, inner: &mut ApprovalInner, approval: ApprovalView) {
        let event = ApprovalEvent::Changed {
            sequence: self.event_counter.fetch_add(1, Ordering::Relaxed) + 1,
            approval,
        };
        inner
            .subscribers
            .retain(|subscriber| subscriber.send(event.clone()).is_ok());
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
    use super::{ApprovalState, ApprovalStatus};
    use crate::permission_policy::{
        ApprovalScope, PolicyOutcome, PolicyRequestInput, PolicyState,
    };
    use std::{
        fs,
        path::{Path, PathBuf},
        process,
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    fn unique_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "shellwarden-approval-{name}-{}-{nonce}",
            process::id()
        ));
        fs::create_dir_all(&root).expect("create test root");
        root
    }

    fn request(directory: &Path, command: &[&str]) -> PolicyRequestInput {
        PolicyRequestInput {
            source: "test-client".to_string(),
            session_id: Some("session-a".to_string()),
            command: command.iter().map(|part| part.to_string()).collect(),
            operation_class: "read".to_string(),
            directory: directory.to_string_lossy().to_string(),
            environment_keys: vec!["PATH".to_string()],
        }
    }

    #[test]
    fn critical_request_exposes_only_temporary_allow_scopes_and_deny() {
        let root = unique_root("critical");
        let approvals = ApprovalState::default();
        let approval = approvals
            .request(
                request(&root, &["powershell", "-Command", "Get-ChildItem"]),
                None,
                None,
            )
            .expect("request approval");

        assert!(approval.risk.allowed_scopes.contains(&ApprovalScope::Once));
        assert!(approval.risk.allowed_scopes.contains(&ApprovalScope::Session));
        assert!(approval.risk.allowed_scopes.contains(&ApprovalScope::Deny));
        assert!(!approval
            .risk
            .allowed_scopes
            .contains(&ApprovalScope::ExactDirectory));
        assert!(!approval.risk.allowed_scopes.contains(&ApprovalScope::Always));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn allow_once_resolves_request_and_updates_policy_decision_history() {
        let root = unique_root("allow");
        let approvals = ApprovalState::default();
        let policy = PolicyState::default();
        policy
            .initialize(&root.join("permissions.sqlite3"))
            .expect("initialize policy");
        let input = request(&root, &["git", "status"]);
        let approval = approvals
            .request(input.clone(), Some("exec-1".to_string()), None)
            .expect("request approval");

        let resolution = approvals
            .resolve(&approval.id, ApprovalScope::Once, &policy)
            .expect("resolve");
        assert_eq!(resolution.approval.status, ApprovalStatus::Allowed);
        assert_eq!(
            resolution.decision.as_ref().map(|value| value.outcome),
            Some(PolicyOutcome::Allow)
        );
        assert_eq!(policy.recent_decisions().expect("decisions").len(), 1);

        assert_eq!(
            policy.decide(input).expect("once consumed").outcome,
            PolicyOutcome::Ask
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deny_resolves_only_the_pending_request_without_persisting_a_rule() {
        let root = unique_root("deny");
        let approvals = ApprovalState::default();
        let policy = PolicyState::default();
        policy
            .initialize(&root.join("permissions.sqlite3"))
            .expect("initialize policy");
        let input = request(&root, &["git", "status"]);
        let approval = approvals
            .request(input.clone(), None, None)
            .expect("request approval");

        let resolution = approvals
            .resolve(&approval.id, ApprovalScope::Deny, &policy)
            .expect("deny");
        assert_eq!(resolution.approval.status, ApprovalStatus::Denied);
        assert_eq!(
            resolution.decision.as_ref().map(|value| value.outcome),
            Some(PolicyOutcome::Deny)
        );
        assert!(policy.list().expect("rules").is_empty());
        assert_eq!(
            policy.decide(input).expect("future request").outcome,
            PolicyOutcome::Ask
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cancelled_and_expired_requests_cannot_be_approved() {
        let root = unique_root("terminal");
        let approvals = ApprovalState::default();
        let policy = PolicyState::default();
        policy
            .initialize(&root.join("permissions.sqlite3"))
            .expect("initialize policy");

        let cancelled = approvals
            .request(request(&root, &["git", "status"]), None, None)
            .expect("request");
        approvals
            .cancel(&cancelled.id, "requester disconnected")
            .expect("cancel");
        assert!(approvals
            .resolve(&cancelled.id, ApprovalScope::Once, &policy)
            .is_err());

        let expired = approvals
            .request(request(&root, &["git", "status"]), None, Some(1))
            .expect("expiring request");
        thread::sleep(Duration::from_millis(1100));
        let snapshot = approvals.snapshot();
        let expired_view = snapshot
            .iter()
            .find(|approval| approval.id == expired.id)
            .expect("expired view");
        assert_eq!(expired_view.status, ApprovalStatus::Expired);
        assert!(approvals
            .resolve(&expired.id, ApprovalScope::Once, &policy)
            .is_err());

        let _ = fs::remove_dir_all(root);
    }
}

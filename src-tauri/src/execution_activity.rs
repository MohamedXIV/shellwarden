use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, Sender},
        Mutex, MutexGuard,
    },
    time::{SystemTime, UNIX_EPOCH},
};

pub const RETAINED_STREAM_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Requested,
    AwaitingApproval,
    Queued,
    Running,
    Succeeded,
    Failed,
    Denied,
    Cancelled,
    TimedOut,
}

impl ExecutionStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Denied | Self::Cancelled | Self::TimedOut
        )
    }

    fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Requested => matches!(
                next,
                Self::AwaitingApproval
                    | Self::Queued
                    | Self::Running
                    | Self::Failed
                    | Self::Denied
                    | Self::Cancelled
            ),
            Self::AwaitingApproval => matches!(next, Self::Queued | Self::Denied | Self::Cancelled),
            Self::Queued => matches!(next, Self::Running | Self::Failed | Self::Cancelled),
            Self::Running => matches!(
                next,
                Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut
            ),
            Self::Succeeded | Self::Failed | Self::Denied | Self::Cancelled | Self::TimedOut => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug)]
pub struct NewExecutionRequest {
    pub source: String,
    pub session_id: Option<String>,
    pub command: Vec<String>,
    pub operation_class: String,
    pub directory: String,
    pub timeout_seconds: Option<u64>,
    pub environment_keys: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionRequest {
    pub id: String,
    pub source: String,
    pub session_id: Option<String>,
    pub command: Vec<String>,
    pub operation_class: String,
    pub directory: String,
    pub timeout_seconds: Option<u64>,
    pub environment_keys: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionSnapshot {
    pub request: ExecutionRequest,
    pub state: ExecutionStatus,
    pub stdout_tail: String,
    pub stderr_tail: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub policy_rule_id: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecutionEvent {
    State {
        sequence: u64,
        execution_id: String,
        state: ExecutionStatus,
        timestamp_ms: u64,
    },
    Output {
        sequence: u64,
        execution_id: String,
        stream: ExecutionStream,
        chunk: String,
        timestamp_ms: u64,
    },
}

struct ExecutionRecord {
    request: ExecutionRequest,
    state: ExecutionStatus,
    stdout_tail: String,
    stderr_tail: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
    policy_rule_id: Option<String>,
    created_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Default)]
struct ActivityInner {
    records: HashMap<String, ExecutionRecord>,
    order: Vec<String>,
    subscribers: Vec<Sender<ExecutionEvent>>,
}

#[derive(Default)]
pub struct ExecutionActivityState {
    inner: Mutex<ActivityInner>,
    id_counter: AtomicU64,
    event_counter: AtomicU64,
}

impl ExecutionActivityState {
    fn inner(&self) -> MutexGuard<'_, ActivityInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn begin(&self, request: NewExecutionRequest) -> ExecutionRequest {
        let id = format!(
            "exec-{}-{}",
            now_ms(),
            self.id_counter.fetch_add(1, Ordering::Relaxed) + 1
        );
        let normalized = ExecutionRequest {
            id: id.clone(),
            source: request.source,
            session_id: request.session_id,
            command: request.command,
            operation_class: request.operation_class,
            directory: request.directory,
            timeout_seconds: request.timeout_seconds,
            environment_keys: request.environment_keys,
        };
        let timestamp_ms = now_ms();
        let event = self.state_event(&id, ExecutionStatus::Requested, timestamp_ms);
        let record = ExecutionRecord {
            request: normalized.clone(),
            state: ExecutionStatus::Requested,
            stdout_tail: String::new(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            policy_rule_id: None,
            created_at_ms: timestamp_ms,
            updated_at_ms: timestamp_ms,
        };

        let mut inner = self.inner();
        inner.order.push(id);
        inner.records.insert(normalized.id.clone(), record);
        publish(&mut inner, event);
        normalized
    }

    pub fn transition(
        &self,
        execution_id: &str,
        next: ExecutionStatus,
    ) -> Result<ExecutionEvent, String> {
        let timestamp_ms = now_ms();
        let event = self.state_event(execution_id, next, timestamp_ms);
        let mut inner = self.inner();
        let record = inner
            .records
            .get_mut(execution_id)
            .ok_or_else(|| format!("unknown execution id: {execution_id}"))?;

        if record.state == next {
            return Ok(event);
        }

        if !record.state.can_transition_to(next) {
            return Err(format!(
                "invalid execution transition: {:?} -> {:?}",
                record.state, next
            ));
        }

        record.state = next;
        record.updated_at_ms = timestamp_ms;
        publish(&mut inner, event.clone());
        Ok(event)
    }

    pub fn set_policy_rule(
        &self,
        execution_id: &str,
        rule_id: Option<String>,
    ) -> Result<(), String> {
        let mut inner = self.inner();
        let record = inner
            .records
            .get_mut(execution_id)
            .ok_or_else(|| format!("unknown execution id: {execution_id}"))?;
        record.policy_rule_id = rule_id;
        Ok(())
    }

    pub fn append_output(
        &self,
        execution_id: &str,
        stream: ExecutionStream,
        chunk: impl Into<String>,
    ) -> Result<ExecutionEvent, String> {
        let chunk = chunk.into();
        let timestamp_ms = now_ms();
        let mut inner = self.inner();
        let record = inner
            .records
            .get_mut(execution_id)
            .ok_or_else(|| format!("unknown execution id: {execution_id}"))?;

        if record.state != ExecutionStatus::Running {
            return Err(format!(
                "cannot append output while execution is {:?}",
                record.state
            ));
        }

        match stream {
            ExecutionStream::Stdout => {
                record.stdout_truncated |= append_bounded(&mut record.stdout_tail, &chunk);
            }
            ExecutionStream::Stderr => {
                record.stderr_truncated |= append_bounded(&mut record.stderr_tail, &chunk);
            }
        }

        record.updated_at_ms = timestamp_ms;
        let event = ExecutionEvent::Output {
            sequence: self.next_event_sequence(),
            execution_id: execution_id.to_string(),
            stream,
            chunk,
            timestamp_ms,
        };
        publish(&mut inner, event.clone());
        Ok(event)
    }

    pub fn snapshot(&self) -> Vec<ExecutionSnapshot> {
        let inner = self.inner();
        inner
            .order
            .iter()
            .filter_map(|id| inner.records.get(id))
            .map(|record| ExecutionSnapshot {
                request: record.request.clone(),
                state: record.state,
                stdout_tail: record.stdout_tail.clone(),
                stderr_tail: record.stderr_tail.clone(),
                stdout_truncated: record.stdout_truncated,
                stderr_truncated: record.stderr_truncated,
                policy_rule_id: record.policy_rule_id.clone(),
                created_at_ms: record.created_at_ms,
                updated_at_ms: record.updated_at_ms,
            })
            .collect()
    }

    pub fn subscribe(&self) -> Receiver<ExecutionEvent> {
        let (sender, receiver) = mpsc::channel();
        self.inner().subscribers.push(sender);
        receiver
    }

    pub fn cancel_all_non_terminal(&self) -> usize {
        let timestamp_ms = now_ms();
        let mut inner = self.inner();
        let ids: Vec<String> = inner
            .order
            .iter()
            .filter(|id| {
                inner
                    .records
                    .get(*id)
                    .is_some_and(|record| !record.state.is_terminal())
            })
            .cloned()
            .collect();

        for id in &ids {
            if let Some(record) = inner.records.get_mut(id) {
                record.state = ExecutionStatus::Cancelled;
                record.updated_at_ms = timestamp_ms;
            }
        }

        for id in &ids {
            let event = self.state_event(id, ExecutionStatus::Cancelled, timestamp_ms);
            publish(&mut inner, event);
        }

        ids.len()
    }

    fn state_event(
        &self,
        execution_id: &str,
        state: ExecutionStatus,
        timestamp_ms: u64,
    ) -> ExecutionEvent {
        ExecutionEvent::State {
            sequence: self.next_event_sequence(),
            execution_id: execution_id.to_string(),
            state,
            timestamp_ms,
        }
    }

    fn next_event_sequence(&self) -> u64 {
        self.event_counter.fetch_add(1, Ordering::Relaxed) + 1
    }
}

fn publish(inner: &mut ActivityInner, event: ExecutionEvent) {
    inner
        .subscribers
        .retain(|subscriber| subscriber.send(event.clone()).is_ok());
}

fn append_bounded(buffer: &mut String, chunk: &str) -> bool {
    buffer.push_str(chunk);
    if buffer.len() <= RETAINED_STREAM_BYTES {
        return false;
    }

    let mut cut = buffer.len() - RETAINED_STREAM_BYTES;
    while cut < buffer.len() && !buffer.is_char_boundary(cut) {
        cut += 1;
    }
    buffer.drain(..cut);
    true
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
        ExecutionActivityState, ExecutionEvent, ExecutionStatus, ExecutionStream,
        NewExecutionRequest, RETAINED_STREAM_BYTES,
    };
    use std::time::Duration;

    fn request(command: &str) -> NewExecutionRequest {
        NewExecutionRequest {
            source: "test".to_string(),
            session_id: Some("session-1".to_string()),
            command: vec![command.to_string()],
            operation_class: "read".to_string(),
            directory: ".".to_string(),
            timeout_seconds: Some(30),
            environment_keys: Vec::new(),
        }
    }

    #[test]
    fn state_machine_reaches_success_and_rejects_terminal_rewrites() {
        let activity = ExecutionActivityState::default();
        let execution = activity.begin(request("git"));

        activity
            .transition(&execution.id, ExecutionStatus::Running)
            .expect("requested execution should run");
        activity
            .transition(&execution.id, ExecutionStatus::Succeeded)
            .expect("running execution should succeed");

        assert!(activity
            .transition(&execution.id, ExecutionStatus::Failed)
            .is_err());
        assert_eq!(activity.snapshot()[0].state, ExecutionStatus::Succeeded);
    }

    #[test]
    fn retained_output_is_bounded_on_utf8_boundaries() {
        let activity = ExecutionActivityState::default();
        let execution = activity.begin(request("git"));
        activity
            .transition(&execution.id, ExecutionStatus::Running)
            .expect("execution should run");

        let chunk = "é".repeat(RETAINED_STREAM_BYTES);
        activity
            .append_output(&execution.id, ExecutionStream::Stdout, chunk)
            .expect("output should append");

        let snapshot = activity.snapshot();
        assert!(snapshot[0].stdout_tail.len() <= RETAINED_STREAM_BYTES);
        assert!(snapshot[0].stdout_truncated);
        assert_eq!(snapshot[0].stdout_tail.len() % "é".len(), 0);
    }

    #[test]
    fn subscribers_can_distinguish_multiple_execution_ids() {
        let activity = ExecutionActivityState::default();
        let receiver = activity.subscribe();
        let first = activity.begin(request("git"));
        let second = activity.begin(request("git"));

        let first_event = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("first event");
        let second_event = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("second event");

        let id = |event: ExecutionEvent| match event {
            ExecutionEvent::State { execution_id, .. }
            | ExecutionEvent::Output { execution_id, .. } => execution_id,
        };

        assert_eq!(id(first_event), first.id);
        assert_eq!(id(second_event), second.id);
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn shutdown_resolves_non_terminal_executions_as_cancelled() {
        let activity = ExecutionActivityState::default();
        let running = activity.begin(request("git"));
        let done = activity.begin(request("git"));

        activity
            .transition(&running.id, ExecutionStatus::Running)
            .expect("execution should run");
        activity
            .transition(&done.id, ExecutionStatus::Running)
            .expect("execution should run");
        activity
            .transition(&done.id, ExecutionStatus::Succeeded)
            .expect("execution should succeed");

        assert_eq!(activity.cancel_all_non_terminal(), 1);
        let snapshot = activity.snapshot();
        assert_eq!(snapshot[0].state, ExecutionStatus::Cancelled);
        assert_eq!(snapshot[1].state, ExecutionStatus::Succeeded);
    }
}

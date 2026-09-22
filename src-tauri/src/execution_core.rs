use crate::{
    execution_activity::{
        ExecutionActivityState, ExecutionStatus, ExecutionStream, NewExecutionRequest,
    },
    process_supervisor::terminate_child_tree,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    env,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Mutex, MutexGuard},
};

pub const EXPECTED_CORE_VERSION: &str = "1.1.12";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionCoreStatus {
    pub running: bool,
    pub expected_version: &'static str,
    pub detected_version: Option<String>,
    pub error: Option<String>,
}

impl ExecutionCoreStatus {
    fn unavailable(error: impl Into<String>) -> Self {
        Self {
            running: false,
            expected_version: EXPECTED_CORE_VERSION,
            detected_version: None,
            error: Some(error.into()),
        }
    }
}

struct BrokerProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    detected_version: String,
}

impl BrokerProcess {
    fn spawn(repo_root: &Path) -> Result<Self, String> {
        let python = env::var("SHELLWARDEN_PYTHON").unwrap_or_else(|_| "python".to_string());
        let broker = repo_root.join("execution").join("broker.py");

        if !broker.is_file() {
            return Err(format!("execution broker not found: {}", broker.display()));
        }

        let mut command = Command::new(python);
        command
            .arg("-u")
            .arg(&broker)
            .current_dir(repo_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = command
            .spawn()
            .map_err(|error| format!("failed to launch execution broker: {error}"))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "execution broker stdin was not captured".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "execution broker stdout was not captured".to_string())?;
        let mut stdout = BufReader::new(stdout);
        let mut ready_line = String::new();

        let bytes = stdout
            .read_line(&mut ready_line)
            .map_err(|error| format!("failed to read execution broker readiness: {error}"))?;

        if bytes == 0 {
            let status = child
                .try_wait()
                .ok()
                .flatten()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            return Err(format!(
                "execution broker exited before readiness (status {status})"
            ));
        }

        let ready: Value = serde_json::from_str(ready_line.trim())
            .map_err(|error| format!("invalid execution broker readiness payload: {error}"))?;

        if ready.get("type").and_then(Value::as_str) != Some("ready")
            || ready.get("ok").and_then(Value::as_bool) != Some(true)
        {
            return Err(format!("execution broker did not become ready: {ready}"));
        }

        let detected_version = ready
            .get("coreVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| "execution broker did not report its core version".to_string())?
            .to_string();

        if detected_version != EXPECTED_CORE_VERSION {
            return Err(format!(
                "execution core version mismatch: expected {EXPECTED_CORE_VERSION}, got {detected_version}"
            ));
        }

        Ok(Self {
            child,
            stdin,
            stdout,
            detected_version,
        })
    }

    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn request<F>(&mut self, payload: Value, mut on_event: F) -> Result<Value, String>
    where
        F: FnMut(&Value),
    {
        if !self.is_running() {
            return Err("execution broker is not running".to_string());
        }

        let request_id = payload
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string);

        serde_json::to_writer(&mut self.stdin, &payload)
            .map_err(|error| format!("failed to encode execution request: {error}"))?;
        self.stdin
            .write_all(b"\n")
            .map_err(|error| format!("failed to write execution request: {error}"))?;
        self.stdin
            .flush()
            .map_err(|error| format!("failed to flush execution request: {error}"))?;

        loop {
            let mut line = String::new();
            let bytes = self
                .stdout
                .read_line(&mut line)
                .map_err(|error| format!("failed to read execution response: {error}"))?;

            if bytes == 0 {
                return Err("execution broker closed its output stream".to_string());
            }

            let message: Value = serde_json::from_str(line.trim())
                .map_err(|error| format!("invalid execution broker response: {error}"))?;
            let message_id = message
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string);

            if request_id != message_id {
                return Err(format!(
                    "execution broker returned mismatched id: expected {:?}, got {:?}",
                    request_id, message_id
                ));
            }

            match message.get("type").and_then(Value::as_str) {
                Some("event") => on_event(&message),
                Some("response") => return Ok(message),
                other => {
                    return Err(format!(
                        "execution broker returned unexpected message type: {other:?}"
                    ))
                }
            }
        }
    }

    fn execute_bootstrap_probe<F>(
        &mut self,
        directory: &Path,
        request_id: &str,
        on_event: F,
    ) -> Result<Value, String>
    where
        F: FnMut(&Value),
    {
        self.request(
            json!({
                "id": request_id,
                "type": "execute",
                "command": ["git", "--version"],
                "directory": directory,
                "timeout": 15
            }),
            on_event,
        )
    }

    fn stop(&mut self) {
        terminate_child_tree(&mut self.child);
    }
}

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ExecutionCoreInner {
    broker: Option<BrokerProcess>,
    last_error: Option<String>,
}

impl Default for ExecutionCoreInner {
    fn default() -> Self {
        Self {
            broker: None,
            last_error: Some("execution core has not been started".to_string()),
        }
    }
}

#[derive(Default)]
pub struct ExecutionCoreState {
    inner: Mutex<ExecutionCoreInner>,
}

impl ExecutionCoreState {
    fn inner(&self) -> MutexGuard<'_, ExecutionCoreInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn start(&self, repo_root: &Path) {
        let mut inner = self.inner();

        if let Some(mut existing) = inner.broker.take() {
            existing.stop();
        }

        match BrokerProcess::spawn(repo_root) {
            Ok(broker) => {
                inner.last_error = None;
                inner.broker = Some(broker);
            }
            Err(error) => {
                inner.last_error = Some(error);
            }
        }
    }

    pub fn status(&self) -> ExecutionCoreStatus {
        let mut inner = self.inner();

        if let Some(broker) = inner.broker.as_mut() {
            if broker.is_running() {
                return ExecutionCoreStatus {
                    running: true,
                    expected_version: EXPECTED_CORE_VERSION,
                    detected_version: Some(broker.detected_version.clone()),
                    error: None,
                };
            }

            inner.broker = None;
            inner.last_error = Some("execution broker exited unexpectedly".to_string());
        }

        ExecutionCoreStatus::unavailable(
            inner
                .last_error
                .clone()
                .unwrap_or_else(|| "execution core unavailable".to_string()),
        )
    }

    pub fn execute_bootstrap_probe_with_activity(
        &self,
        activity: &ExecutionActivityState,
        directory: &Path,
    ) -> Result<(String, Value), String> {
        let canonical_directory = directory
            .canonicalize()
            .map_err(|error| format!("failed to canonicalize execution directory: {error}"))?;
        let execution = activity.begin(NewExecutionRequest {
            source: "shellwarden-bootstrap".to_string(),
            session_id: None,
            command: vec!["git".to_string(), "--version".to_string()],
            operation_class: "read".to_string(),
            directory: canonical_directory.display().to_string(),
            timeout_seconds: Some(15),
            environment_keys: Vec::new(),
        });
        let execution_id = execution.id.clone();

        let result = {
            let mut inner = self.inner();
            match inner.broker.as_mut() {
                Some(broker) => broker.execute_bootstrap_probe(
                    &canonical_directory,
                    &execution_id,
                    |event| apply_broker_event(activity, &execution_id, event),
                ),
                None => Err("execution broker is not running".to_string()),
            }
        };

        if result.is_err() {
            let _ = activity.transition(&execution_id, ExecutionStatus::Failed);
        }

        result.map(|response| (execution_id, response))
    }

    pub fn stop(&self) {
        let mut inner = self.inner();
        if let Some(mut broker) = inner.broker.take() {
            broker.stop();
        }
    }
}

fn apply_broker_event(activity: &ExecutionActivityState, execution_id: &str, event: &Value) {
    if event.get("id").and_then(Value::as_str) != Some(execution_id) {
        return;
    }

    match event.get("event").and_then(Value::as_str) {
        Some("requested") => {}
        Some("running") => {
            let _ = activity.transition(execution_id, ExecutionStatus::Running);
        }
        Some("output") => {
            let stream = match event.get("stream").and_then(Value::as_str) {
                Some("stdout") => ExecutionStream::Stdout,
                Some("stderr") => ExecutionStream::Stderr,
                _ => return,
            };
            if let Some(chunk) = event.get("chunk").and_then(Value::as_str) {
                let _ = activity.append_output(execution_id, stream, chunk);
            }
        }
        Some("succeeded") => {
            let _ = activity.transition(execution_id, ExecutionStatus::Succeeded);
        }
        Some("failed") => {
            let _ = activity.transition(execution_id, ExecutionStatus::Failed);
        }
        Some("denied") => {
            let _ = activity.transition(execution_id, ExecutionStatus::Denied);
        }
        Some("cancelled") => {
            let _ = activity.transition(execution_id, ExecutionStatus::Cancelled);
        }
        Some("timed_out") => {
            let _ = activity.transition(execution_id, ExecutionStatus::TimedOut);
        }
        _ => {}
    }
}

pub fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri must live directly under the repository root")
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::{repository_root, ExecutionCoreState, EXPECTED_CORE_VERSION};
    use crate::execution_activity::{ExecutionActivityState, ExecutionStatus};
    use serde_json::Value;

    #[test]
    #[ignore = "requires execution/requirements.txt to be installed"]
    fn pinned_upstream_streams_harmless_git_probe_into_activity() {
        let root = repository_root();
        let core = ExecutionCoreState::default();
        let activity = ExecutionActivityState::default();
        core.start(&root);

        assert_eq!(
            core.status().detected_version.as_deref(),
            Some(EXPECTED_CORE_VERSION)
        );

        let (execution_id, response) = core
            .execute_bootstrap_probe_with_activity(&activity, &root)
            .expect("bootstrap git probe should return");

        assert_eq!(response.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            response
                .pointer("/result/status")
                .and_then(Value::as_i64),
            Some(0)
        );

        let snapshot = activity.snapshot();
        let execution = snapshot
            .iter()
            .find(|execution| execution.request.id == execution_id)
            .expect("activity should retain the probe");

        assert_eq!(execution.state, ExecutionStatus::Succeeded);
        assert!(execution
            .stdout_tail
            .to_ascii_lowercase()
            .contains("git version"));

        core.stop();
    }
}

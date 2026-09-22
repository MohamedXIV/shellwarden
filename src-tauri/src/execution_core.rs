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

    fn request(&mut self, payload: Value) -> Result<Value, String> {
        if !self.is_running() {
            return Err("execution broker is not running".to_string());
        }

        serde_json::to_writer(&mut self.stdin, &payload)
            .map_err(|error| format!("failed to encode execution request: {error}"))?;
        self.stdin
            .write_all(b"\n")
            .map_err(|error| format!("failed to write execution request: {error}"))?;
        self.stdin
            .flush()
            .map_err(|error| format!("failed to flush execution request: {error}"))?;

        let mut line = String::new();
        let bytes = self
            .stdout
            .read_line(&mut line)
            .map_err(|error| format!("failed to read execution response: {error}"))?;

        if bytes == 0 {
            return Err("execution broker closed its output stream".to_string());
        }

        serde_json::from_str(line.trim())
            .map_err(|error| format!("invalid execution broker response: {error}"))
    }

    fn execute_bootstrap_probe(&mut self, directory: &Path) -> Result<Value, String> {
        self.request(json!({
            "id": "shellwarden-bootstrap-probe",
            "type": "execute",
            "command": ["git", "--version"],
            "directory": directory,
            "timeout": 15
        }))
    }

    fn stop(&mut self) {
        if self.is_running() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
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

    pub fn stop(&self) {
        let mut inner = self.inner();
        if let Some(mut broker) = inner.broker.take() {
            broker.stop();
        }
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
    use super::{repository_root, BrokerProcess, EXPECTED_CORE_VERSION};

    #[test]
    #[ignore = "requires execution/requirements.txt to be installed"]
    fn pinned_upstream_executes_harmless_git_probe() {
        let root = repository_root();
        let mut broker = BrokerProcess::spawn(&root).expect("broker should start");

        assert_eq!(broker.detected_version, EXPECTED_CORE_VERSION);

        let response = broker
            .execute_bootstrap_probe(&root)
            .expect("bootstrap git probe should return");

        assert_eq!(response.get("ok").and_then(|value| value.as_bool()), Some(true));
        assert_eq!(
            response
                .pointer("/result/status")
                .and_then(|value| value.as_i64()),
            Some(0)
        );
        assert!(response
            .pointer("/result/stdout")
            .and_then(|value| value.as_str())
            .is_some_and(|stdout| stdout.to_ascii_lowercase().contains("git version")));

        broker.stop();
    }
}

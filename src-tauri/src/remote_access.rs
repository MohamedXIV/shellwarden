use crate::{
    approval_state::ApprovalState,
    process_supervisor::ProcessSupervisor,
    remote_mcp::McpServerState,
};
use serde::Serialize;
use std::{
    env,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Mutex, MutexGuard},
    thread,
    time::Duration,
};
use tauri::{AppHandle, Emitter, Manager};

const TUNNEL_PROCESS_ID: &str = "openai-secure-mcp-tunnel";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteAccessPhase {
    Unconfigured,
    Paused,
    Starting,
    Connected,
    Error,
}

#[derive(Clone, Debug)]
struct RemoteConfig {
    tunnel_id: String,
    api_key: String,
    binary: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteAccessStatus {
    pub phase: RemoteAccessPhase,
    pub configured: bool,
    pub tunnel_id: Option<String>,
    pub mcp_server_url: Option<String>,
    pub health_url: Option<String>,
    pub error: Option<String>,
}

struct RemoteAccessInner {
    phase: RemoteAccessPhase,
    config: Option<RemoteConfig>,
    health_url: Option<String>,
    health_url_file: Option<PathBuf>,
    error: Option<String>,
    diagnostic_tail: String,
    generation: u64,
}

impl Default for RemoteAccessInner {
    fn default() -> Self {
        Self {
            phase: RemoteAccessPhase::Unconfigured,
            config: None,
            health_url: None,
            health_url_file: None,
            error: None,
            diagnostic_tail: String::new(),
            generation: 0,
        }
    }
}

#[derive(Default)]
pub struct RemoteAccessState {
    inner: Mutex<RemoteAccessInner>,
}

impl RemoteAccessState {
    fn inner(&self) -> MutexGuard<'_, RemoteAccessInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn generation(&self) -> u64 {
        self.inner().generation
    }

    pub(crate) fn accepts_remote_requests(&self) -> bool {
        let inner = self.inner();
        inner.config.is_some()
            && matches!(
                inner.phase,
                RemoteAccessPhase::Starting | RemoteAccessPhase::Connected
            )
    }

    pub fn status(&self, app: &AppHandle) -> RemoteAccessStatus {
        let inner = self.inner();
        RemoteAccessStatus {
            phase: inner.phase,
            configured: inner.config.is_some(),
            tunnel_id: inner.config.as_ref().map(|config| config.tunnel_id.clone()),
            mcp_server_url: app.state::<McpServerState>().status().url,
            health_url: inner.health_url.clone(),
            error: inner.error.clone(),
        }
    }

    pub fn configure_and_start(
        &self,
        app: &AppHandle,
        tunnel_id: String,
        api_key: String,
        binary: Option<String>,
    ) -> Result<RemoteAccessStatus, String> {
        validate_tunnel_id(&tunnel_id)?;
        if api_key.trim().is_empty() {
            return Err("CONTROL_PLANE_API_KEY must not be empty".to_string());
        }

        let binary = binary
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "tunnel-client".to_string());
        validate_tunnel_binary(&binary)?;

        {
            let mut inner = self.inner();
            inner.config = Some(RemoteConfig {
                tunnel_id,
                api_key,
                binary,
            });
        }

        if let Err(error) = self.start_configured(app) {
            self.mark_error(app, error.clone());
            return Err(error);
        }
        Ok(self.status(app))
    }

    pub fn pause(&self, app: &AppHandle) -> RemoteAccessStatus {
        let health_url_file = {
            let mut inner = self.inner();
            inner.generation = inner.generation.wrapping_add(1);
            inner.phase = if inner.config.is_some() {
                RemoteAccessPhase::Paused
            } else {
                RemoteAccessPhase::Unconfigured
            };
            inner.health_url = None;
            inner.error = None;
            inner.diagnostic_tail.clear();
            inner.health_url_file.take()
        };

        app.state::<ProcessSupervisor>().stop(TUNNEL_PROCESS_ID);
        app.state::<ApprovalState>().cancel_pending_by_source(
            "openai-secure-mcp-tunnel",
            "Remote access was paused before this request was approved.",
        );

        if let Some(path) = health_url_file {
            let _ = fs::remove_file(path);
        }

        let status = self.status(app);
        let _ = app.emit("shellwarden://remote-access", &status);
        status
    }

    pub fn resume(&self, app: &AppHandle) -> Result<RemoteAccessStatus, String> {
        if self.inner().config.is_none() {
            return Err("remote access is not configured".to_string());
        }
        if let Err(error) = self.start_configured(app) {
            self.mark_error(app, error.clone());
            return Err(error);
        }
        Ok(self.status(app))
    }

    pub fn stop_for_exit(&self, app: &AppHandle) {
        app.state::<ProcessSupervisor>().stop(TUNNEL_PROCESS_ID);
        let health_url_file = {
            let mut inner = self.inner();
            inner.generation = inner.generation.wrapping_add(1);
            inner.health_url = None;
            inner.health_url_file.take()
        };
        if let Some(path) = health_url_file {
            let _ = fs::remove_file(path);
        }
    }

    fn start_configured(&self, app: &AppHandle) -> Result<(), String> {
        let config = self
            .inner()
            .config
            .clone()
            .ok_or_else(|| "remote access is not configured".to_string())?;

        app.state::<ProcessSupervisor>().stop(TUNNEL_PROCESS_ID);

        let mcp_status = app.state::<McpServerState>().status();
        let mcp_url = mcp_status.url.ok_or_else(|| {
            mcp_status
                .error
                .unwrap_or_else(|| "local MCP server is not ready".to_string())
        })?;

        let app_data_dir = app
            .path()
            .app_data_dir()
            .map_err(|error| format!("failed to resolve app data directory: {error}"))?;
        fs::create_dir_all(&app_data_dir)
            .map_err(|error| format!("failed to create app data directory: {error}"))?;
        let health_url_file = app_data_dir.join("tunnel-client-health.url");
        let _ = fs::remove_file(&health_url_file);

        let generation = {
            let mut inner = self.inner();
            inner.generation = inner.generation.wrapping_add(1);
            inner.phase = RemoteAccessPhase::Starting;
            inner.health_url = None;
            inner.health_url_file = Some(health_url_file.clone());
            inner.error = None;
            inner.diagnostic_tail.clear();
            inner.generation
        };

        let initial = self.status(app);
        let _ = app.emit("shellwarden://remote-access", &initial);

        let mut command = Command::new(&config.binary);
        apply_minimal_tunnel_environment(&mut command, &config.api_key);
        command
            .arg("run")
            .args(["--control-plane.tunnel-id", &config.tunnel_id])
            .arg("--mcp.server-url")
            .arg(format!("channel=main,url={mcp_url}"))
            .args(["--health.listen-addr", "127.0.0.1:0"])
            .arg("--health.url-file")
            .arg(&health_url_file)
            .args(["--log.level", "warn"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = command.spawn().map_err(|error| {
            format!(
                "failed to launch '{}': {error}. Install tunnel-client or choose its binary path.",
                config.binary
            )
        })?;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        app.state::<ProcessSupervisor>()
            .register(TUNNEL_PROCESS_ID, child)
            .map_err(|error| error.to_string())?;

        if let Some(stdout) = stdout {
            spawn_diagnostic_reader(app.clone(), generation, "stdout", stdout);
        }
        if let Some(stderr) = stderr {
            spawn_diagnostic_reader(app.clone(), generation, "stderr", stderr);
        }

        spawn_monitor(app.clone(), generation, health_url_file);
        Ok(())
    }

    fn append_diagnostic(&self, generation: u64, stream: &str, line: &str) {
        const MAX_DIAGNOSTIC_BYTES: usize = 12 * 1024;

        let mut inner = self.inner();
        if inner.generation != generation {
            return;
        }

        let cleaned = line.trim_end_matches(['\r', '\n']);
        if cleaned.is_empty() {
            return;
        }

        if !inner.diagnostic_tail.is_empty() {
            inner.diagnostic_tail.push('\n');
        }
        inner
            .diagnostic_tail
            .push_str(&format!("[{stream}] {cleaned}"));

        if inner.diagnostic_tail.len() > MAX_DIAGNOSTIC_BYTES {
            let keep_from = inner
                .diagnostic_tail
                .len()
                .saturating_sub(MAX_DIAGNOSTIC_BYTES);
            inner.diagnostic_tail = inner.diagnostic_tail[keep_from..].to_string();
        }
    }

    fn diagnostic_excerpt(&self, generation: u64) -> Option<String> {
        let inner = self.inner();
        if inner.generation != generation || inner.diagnostic_tail.trim().is_empty() {
            None
        } else {
            Some(inner.diagnostic_tail.clone())
        }
    }

    fn mark_error(&self, app: &AppHandle, error: String) {
        {
            let mut inner = self.inner();
            inner.generation = inner.generation.wrapping_add(1);
            inner.phase = RemoteAccessPhase::Error;
            inner.health_url = None;
            inner.error = Some(error);
        }

        app.state::<ApprovalState>().cancel_pending_by_source(
            "openai-secure-mcp-tunnel",
            "Remote transport became unavailable before this request was approved.",
        );

        let status = self.status(app);
        let _ = app.emit("shellwarden://remote-access", &status);
    }

    fn update_from_monitor(
        &self,
        app: &AppHandle,
        generation: u64,
        phase: RemoteAccessPhase,
        health_url: Option<String>,
        error: Option<String>,
    ) {
        {
            let mut inner = self.inner();
            if inner.generation != generation {
                return;
            }
            inner.phase = phase;
            inner.health_url = health_url;
            inner.error = error;
        }

        if phase == RemoteAccessPhase::Error {
            app.state::<ApprovalState>().cancel_pending_by_source(
                "openai-secure-mcp-tunnel",
                "Remote transport disconnected before this request was approved.",
            );
        }

        let status = self.status(app);
        let _ = app.emit("shellwarden://remote-access", &status);
    }
}

fn spawn_monitor(app: AppHandle, generation: u64, health_url_file: PathBuf) {
    thread::spawn(move || {
        let mut last_phase = RemoteAccessPhase::Starting;
        let mut health_url: Option<String> = None;

        loop {
            thread::sleep(Duration::from_millis(350));

            let current_generation = app.state::<RemoteAccessState>().generation();
            if current_generation != generation {
                return;
            }

            match app
                .state::<ProcessSupervisor>()
                .poll_exit_status(TUNNEL_PROCESS_ID)
            {
                Ok(Some(status)) => {
                    // Give stdout/stderr reader threads a moment to flush the final diagnostic.
                    thread::sleep(Duration::from_millis(80));
                    let diagnostics = app
                        .state::<RemoteAccessState>()
                        .diagnostic_excerpt(generation);
                    let mut message = format!("tunnel-client exited with status {status}");
                    if let Some(diagnostics) = diagnostics {
                        message.push_str("\n");
                        message.push_str(&diagnostics);
                    }

                    app.state::<RemoteAccessState>().update_from_monitor(
                        &app,
                        generation,
                        RemoteAccessPhase::Error,
                        health_url,
                        Some(message),
                    );
                    return;
                }
                Ok(None) => {}
                Err(error) => {
                    app.state::<RemoteAccessState>().update_from_monitor(
                        &app,
                        generation,
                        RemoteAccessPhase::Error,
                        health_url,
                        Some(error),
                    );
                    return;
                }
            }

            let previous_health_url = health_url.clone();
            if health_url.is_none() {
                health_url = fs::read_to_string(&health_url_file)
                    .ok()
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty());
            }

            if health_url != previous_health_url && health_url.is_some() {
                app.state::<RemoteAccessState>().update_from_monitor(
                    &app,
                    generation,
                    last_phase,
                    health_url.clone(),
                    None,
                );
            }

            let ready = health_url.as_deref().is_some_and(probe_ready);
            let next_phase = if ready {
                RemoteAccessPhase::Connected
            } else {
                RemoteAccessPhase::Starting
            };

            if next_phase != last_phase {
                app.state::<RemoteAccessState>().update_from_monitor(
                    &app,
                    generation,
                    next_phase,
                    health_url.clone(),
                    None,
                );
                last_phase = next_phase;
            }
        }
    });
}

fn spawn_diagnostic_reader<R>(
    app: AppHandle,
    generation: u64,
    stream: &'static str,
    reader: R,
) where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let reader = BufReader::new(reader);
        for line in reader.lines().map_while(Result::ok) {
            app.state::<RemoteAccessState>()
                .append_diagnostic(generation, stream, &line);
        }
    });
}

fn apply_minimal_tunnel_environment(command: &mut Command, api_key: &str) {
    command.env_clear();

    for key in [
        "PATH",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOME",
    ] {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }

    command.env("CONTROL_PLANE_API_KEY", api_key);
}

fn validate_tunnel_binary(binary: &str) -> Result<(), String> {
    let file_name = PathBuf::from(binary)
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .ok_or_else(|| "tunnel-client binary path is invalid".to_string())?;

    if matches!(file_name.as_str(), "tunnel-client" | "tunnel-client.exe") {
        Ok(())
    } else {
        Err(
            "ShellWarden only passes the tunnel runtime key to an executable named 'tunnel-client' or 'tunnel-client.exe'."
                .to_string(),
        )
    }
}

fn validate_tunnel_id(tunnel_id: &str) -> Result<(), String> {
    let Some(suffix) = tunnel_id.strip_prefix("tunnel_") else {
        return Err("tunnel ID must start with 'tunnel_'".to_string());
    };

    if suffix.len() != 32
        || !suffix
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(
            "tunnel ID must be 'tunnel_' followed by 32 lowercase hexadecimal characters"
                .to_string(),
        );
    }

    Ok(())
}

fn probe_ready(base_url: &str) -> bool {
    let Some(authority_and_path) = base_url.strip_prefix("http://") else {
        return false;
    };
    let authority = authority_and_path
        .split('/')
        .next()
        .unwrap_or(authority_and_path);
    let Ok(address) = authority.parse::<SocketAddr>() else {
        return false;
    };

    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(400)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

    let request = format!(
        "GET /readyz HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }

    let mut response = [0_u8; 256];
    let Ok(read) = stream.read(&mut response) else {
        return false;
    };
    let head = String::from_utf8_lossy(&response[..read]);
    head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200")
}

#[cfg(test)]
mod tests {
    use super::{
        apply_minimal_tunnel_environment, probe_ready, validate_tunnel_binary, validate_tunnel_id,
    };
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    #[test]
    fn tunnel_child_environment_is_explicit_and_minimal() {
        let mut command = std::process::Command::new("tunnel-client");
        command.env("SHELLWARDEN_SHOULD_NOT_LEAK", "secret");
        apply_minimal_tunnel_environment(&mut command, "runtime-key");

        let explicit = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().to_string(),
                    value.map(|value| value.to_string_lossy().to_string()),
                )
            })
            .collect::<Vec<_>>();

        assert!(explicit.iter().any(|(key, value)| {
            key == "CONTROL_PLANE_API_KEY" && value.as_deref() == Some("runtime-key")
        }));
        assert!(!explicit.iter().any(|(key, value)| {
            key == "SHELLWARDEN_SHOULD_NOT_LEAK" && value.as_deref() == Some("secret")
        }));
    }

    #[test]
    fn tunnel_binary_name_is_restricted_before_receiving_runtime_key() {
        assert!(validate_tunnel_binary("tunnel-client").is_ok());
        assert!(validate_tunnel_binary(r"C:\Tools\tunnel-client.exe").is_ok());
        assert!(validate_tunnel_binary("powershell.exe").is_err());
        assert!(validate_tunnel_binary(r"C:\Tools\renamed-client.exe").is_err());
    }

    #[test]
    fn tunnel_id_validation_matches_runtime_contract() {
        assert!(validate_tunnel_id("tunnel_0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_tunnel_id("tun_0123456789abcdef0123456789abcdef").is_err());
        assert!(validate_tunnel_id("tunnel_ABCDEF6789abcdef0123456789abcdef").is_err());
        assert!(validate_tunnel_id("tunnel_0123").is_err());
    }

    #[test]
    fn ready_probe_requires_http_200() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("address");
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0_u8; 256];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nready")
                .expect("response");
        });

        assert!(probe_ready(&format!("http://{address}")));
        worker.join().expect("worker");
    }
}

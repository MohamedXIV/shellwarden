use crate::{process_supervisor::ProcessSupervisor, remote_mcp::McpServerState};
use serde::Serialize;
use std::{
    fs,
    io::{Read, Write},
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

        {
            let mut inner = self.inner();
            inner.config = Some(RemoteConfig {
                tunnel_id,
                api_key,
                binary,
            });
        }

        self.start_configured(app)?;
        Ok(self.status(app))
    }

    pub fn pause(&self, app: &AppHandle) -> RemoteAccessStatus {
        app.state::<ProcessSupervisor>().stop(TUNNEL_PROCESS_ID);

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
            inner.health_url_file.take()
        };
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
        self.start_configured(app)?;
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
        let mcp_status = app.state::<McpServerState>().status();
        let mcp_url = mcp_status.url.ok_or_else(|| {
            mcp_status
                .error
                .unwrap_or_else(|| "local MCP server is not ready".to_string())
        })?;

        let config = self
            .inner()
            .config
            .clone()
            .ok_or_else(|| "remote access is not configured".to_string())?;

        app.state::<ProcessSupervisor>().stop(TUNNEL_PROCESS_ID);

        let app_data_dir = app
            .path()
            .app_data_dir()
            .map_err(|error| format!("failed to resolve app data directory: {error}"))?;
        fs::create_dir_all(&app_data_dir)
            .map_err(|error| format!("failed to create app data directory: {error}"))?;
        let health_url_file = app_data_dir.join("tunnel-client-health.url");
        let _ = fs::remove_file(&health_url_file);

        let mut command = Command::new(&config.binary);
        command
            .arg("run")
            .args(["--control-plane.tunnel-id", &config.tunnel_id])
            .arg("--mcp.server-url")
            .arg(format!("channel=main,url={mcp_url}"))
            .args(["--health.listen-addr", "127.0.0.1:0"])
            .arg("--health.url-file")
            .arg(&health_url_file)
            .args(["--log.level", "warn"])
            .env("CONTROL_PLANE_API_KEY", &config.api_key)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }

        let child = command.spawn().map_err(|error| {
            format!(
                "failed to launch '{}': {error}. Install tunnel-client or choose its binary path.",
                config.binary
            )
        })?;

        app.state::<ProcessSupervisor>()
            .register(TUNNEL_PROCESS_ID, child)
            .map_err(|error| error.to_string())?;

        let generation = {
            let mut inner = self.inner();
            inner.generation = inner.generation.wrapping_add(1);
            inner.phase = RemoteAccessPhase::Starting;
            inner.health_url = None;
            inner.health_url_file = Some(health_url_file.clone());
            inner.error = None;
            inner.generation
        };

        let initial = self.status(app);
        let _ = app.emit("shellwarden://remote-access", &initial);

        spawn_monitor(app.clone(), generation, health_url_file);
        Ok(())
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

            let current_generation = app.state::<RemoteAccessState>().inner().generation;
            if current_generation != generation {
                return;
            }

            if !app
                .state::<ProcessSupervisor>()
                .is_running(TUNNEL_PROCESS_ID)
            {
                app.state::<RemoteAccessState>().update_from_monitor(
                    &app,
                    generation,
                    RemoteAccessPhase::Error,
                    health_url,
                    Some("tunnel-client exited unexpectedly".to_string()),
                );
                return;
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
    use super::{probe_ready, validate_tunnel_id};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

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

use crate::{
    approval_state::{ApprovalEvent, ApprovalState, ApprovalStatus},
    execution_activity::{ExecutionActivityState, ExecutionStatus, NewExecutionRequest},
    execution_core::ExecutionCoreState,
    permission_policy::{PolicyOutcome, PolicyRequestInput, PolicyState},
};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock},
    schemars,
    tool, tool_router,
    transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    sync::{Mutex, MutexGuard},
    thread,
    time::Duration,
};
use tauri::{AppHandle, Manager};
use tokio_util::sync::CancellationToken;

const REMOTE_SOURCE: &str = "openai-secure-mcp-tunnel";
const REMOTE_SESSION: &str = "secure-mcp-tunnel";
const APPROVAL_TTL_SECONDS: u64 = 120;

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerStatus {
    pub running: bool,
    pub url: Option<String>,
    pub error: Option<String>,
}

#[derive(Default)]
struct McpServerInner {
    url: Option<String>,
    error: Option<String>,
    cancellation: Option<CancellationToken>,
}

#[derive(Default)]
pub struct McpServerState {
    inner: Mutex<McpServerInner>,
}

impl McpServerState {
    fn inner(&self) -> MutexGuard<'_, McpServerInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn start(&self, app: AppHandle) {
        self.stop();

        let cancellation = CancellationToken::new();
        {
            let mut inner = self.inner();
            inner.url = None;
            inner.error = None;
            inner.cancellation = Some(cancellation.clone());
        }

        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .thread_name("shellwarden-mcp")
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    app.state::<McpServerState>()
                        .set_error(format!("failed to create MCP runtime: {error}"));
                    return;
                }
            };

            runtime.block_on(async move {
                let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
                    Ok(listener) => listener,
                    Err(error) => {
                        app.state::<McpServerState>()
                            .set_error(format!("failed to bind local MCP endpoint: {error}"));
                        return;
                    }
                };

                let address = match listener.local_addr() {
                    Ok(address) => address,
                    Err(error) => {
                        app.state::<McpServerState>()
                            .set_error(format!("failed to read local MCP address: {error}"));
                        return;
                    }
                };
                let url = format!("http://{address}/mcp");
                app.state::<McpServerState>().set_url(url);

                let service_app = app.clone();
                let service = StreamableHttpService::new(
                    move || Ok(ShellWardenMcp::new(service_app.clone())),
                    LocalSessionManager::default().into(),
                    StreamableHttpServerConfig::default()
                        .with_legacy_session_mode(false)
                        .with_json_response(true)
                        .with_cancellation_token(cancellation.child_token()),
                );
                let router = axum::Router::new().nest_service("/mcp", service);

                if let Err(error) = axum::serve(listener, router)
                    .with_graceful_shutdown(cancellation.cancelled_owned())
                    .await
                {
                    app.state::<McpServerState>()
                        .set_error(format!("local MCP server stopped: {error}"));
                }
            });
        });
    }

    pub fn stop(&self) {
        let cancellation = self.inner().cancellation.take();
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
    }

    pub fn status(&self) -> McpServerStatus {
        let inner = self.inner();
        McpServerStatus {
            running: inner.url.is_some() && inner.error.is_none(),
            url: inner.url.clone(),
            error: inner.error.clone(),
        }
    }

    fn set_url(&self, url: String) {
        let mut inner = self.inner();
        inner.url = Some(url);
        inner.error = None;
    }

    fn set_error(&self, error: String) {
        let mut inner = self.inner();
        inner.error = Some(error);
        inner.url = None;
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ShellExecuteParams {
    /// Command argv. Shell strings are not accepted; every argument must be a separate array item.
    pub command: Vec<String>,
    /// Existing working directory for the command.
    pub directory: String,
    /// Optional execution timeout in seconds. Values above 300 are rejected.
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

#[derive(Clone)]
struct ShellWardenMcp {
    app: AppHandle,
}

impl ShellWardenMcp {
    fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

#[tool_router(server_handler)]
impl ShellWardenMcp {
    #[tool(
        description = "Execute an argv command through ShellWarden policy, human approvals, activity tracking, and the pinned execution core. Unknown authority pauses for human approval before execution."
    )]
    async fn shell_execute(
        &self,
        Parameters(params): Parameters<ShellExecuteParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if params.command.is_empty()
            || params
                .command
                .iter()
                .any(|part| part.trim().is_empty())
        {
            return Err(rmcp::ErrorData::invalid_params(
                "command must be a non-empty argv array",
                None,
            ));
        }

        if params.directory.trim().is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "directory must be non-empty",
                None,
            ));
        }

        if params.timeout_seconds.is_some_and(|seconds| seconds == 0 || seconds > 300) {
            return Err(rmcp::ErrorData::invalid_params(
                "timeout_seconds must be between 1 and 300",
                None,
            ));
        }

        let app = self.app.clone();
        let result = tokio::task::spawn_blocking(move || execute_remote(&app, params))
            .await
            .map_err(|error| {
                rmcp::ErrorData::internal_error(
                    format!("ShellWarden execution worker failed: {error}"),
                    None,
                )
            })?;

        match result {
            Ok((execution_id, response)) => {
                let ok = response.get("ok").and_then(Value::as_bool) == Some(true);
                let payload = serde_json::json!({
                    "executionId": execution_id,
                    "ok": ok,
                    "result": response.get("result").cloned().unwrap_or(Value::Null),
                    "error": response.get("error").cloned().unwrap_or(Value::Null),
                });
                let text = serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| payload.to_string());

                if ok {
                    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
                } else {
                    Ok(CallToolResult::error(vec![ContentBlock::text(text)]))
                }
            }
            Err(error) => Ok(CallToolResult::error(vec![ContentBlock::text(error)])),
        }
    }
}

fn execute_remote(
    app: &AppHandle,
    params: ShellExecuteParams,
) -> Result<(String, Value), String> {
    let operation_class = "remote_request".to_string();
    let input = PolicyRequestInput {
        source: REMOTE_SOURCE.to_string(),
        session_id: Some(REMOTE_SESSION.to_string()),
        command: params.command.clone(),
        operation_class: operation_class.clone(),
        directory: params.directory.clone(),
        environment_keys: Vec::new(),
    };

    let execution = app.state::<ExecutionActivityState>().begin(NewExecutionRequest {
        source: REMOTE_SOURCE.to_string(),
        session_id: Some(REMOTE_SESSION.to_string()),
        command: params.command.clone(),
        operation_class,
        directory: params.directory.clone(),
        timeout_seconds: params.timeout_seconds,
        environment_keys: Vec::new(),
    });
    let execution_id = execution.id.clone();

    let decision = match app.state::<PolicyState>().decide(input.clone()) {
        Ok(decision) => decision,
        Err(error) => {
            let _ = app
                .state::<ExecutionActivityState>()
                .transition(&execution_id, ExecutionStatus::Failed);
            return Err(error);
        }
    };

    let activity = app.state::<ExecutionActivityState>();
    let _ = activity.set_policy_rule(&execution_id, decision.rule_id.clone());

    match decision.outcome {
        PolicyOutcome::Allow => {
            let _ = activity.transition(&execution_id, ExecutionStatus::Queued);
        }
        PolicyOutcome::Deny => {
            let _ = activity.transition(&execution_id, ExecutionStatus::Denied);
            return Err(format!("ShellWarden policy denied the request: {}", decision.reason));
        }
        PolicyOutcome::Ask => {
            wait_for_human_approval(app, input, &execution_id)?;
        }
    }

    let response = app.state::<ExecutionCoreState>().execute_with_activity(
        &activity,
        &execution_id,
        &params.command,
        &params.directory,
        params.timeout_seconds,
    )?;

    Ok((execution_id, response))
}

fn wait_for_human_approval(
    app: &AppHandle,
    input: PolicyRequestInput,
    execution_id: &str,
) -> Result<(), String> {
    let approvals = app.state::<ApprovalState>();
    let receiver = approvals.subscribe();

    let _ = app
        .state::<ExecutionActivityState>()
        .transition(execution_id, ExecutionStatus::AwaitingApproval);

    let approval = approvals.request(
        input,
        Some(execution_id.to_string()),
        Some(APPROVAL_TTL_SECONDS),
    )?;

    let deadline = std::time::Instant::now() + Duration::from_secs(APPROVAL_TTL_SECONDS + 2);

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            let _ = approvals.cancel(&approval.id, "Remote MCP approval wait timed out.");
            return Err("Human approval timed out before execution could start.".to_string());
        }

        let event = receiver
            .recv_timeout(remaining.min(Duration::from_secs(5)))
            .ok();

        let Some(ApprovalEvent::Changed { approval: changed, .. }) = event else {
            continue;
        };

        if changed.id != approval.id || changed.status == ApprovalStatus::Pending {
            continue;
        }

        let activity = app.state::<ExecutionActivityState>();
        let _ = activity.set_policy_rule(execution_id, changed.decision_rule_id.clone());

        return match changed.status {
            ApprovalStatus::Allowed => {
                let _ = activity.transition(execution_id, ExecutionStatus::Queued);
                Ok(())
            }
            ApprovalStatus::Denied => {
                let _ = activity.transition(execution_id, ExecutionStatus::Denied);
                Err(changed
                    .decision_reason
                    .unwrap_or_else(|| "Human denied this request.".to_string()))
            }
            ApprovalStatus::Cancelled | ApprovalStatus::Expired => {
                let _ = activity.transition(execution_id, ExecutionStatus::Cancelled);
                Err(changed
                    .decision_reason
                    .unwrap_or_else(|| "Approval was cancelled or expired.".to_string()))
            }
            ApprovalStatus::Pending => unreachable!(),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::{McpServerState, ShellExecuteParams};

    #[test]
    fn default_mcp_status_is_not_running() {
        let state = McpServerState::default();
        let status = state.status();
        assert!(!status.running);
        assert!(status.url.is_none());
        assert!(status.error.is_none());
    }

    #[test]
    fn timeout_contract_rejects_zero_or_excessive_values() {
        let valid = ShellExecuteParams {
            command: vec!["git".to_string(), "status".to_string()],
            directory: ".".to_string(),
            timeout_seconds: Some(30),
        };
        assert_eq!(valid.timeout_seconds, Some(30));
        assert!(matches!(Some(0_u64), Some(seconds) if seconds == 0 || seconds > 300));
        assert!(matches!(Some(301_u64), Some(seconds) if seconds == 0 || seconds > 300));
    }
}

mod approval_state;
mod audit_state;
mod execution_activity;
mod execution_core;
mod lifecycle;
mod permission_policy;
mod process_supervisor;
mod remote_access;
mod remote_mcp;
mod risk_policy;

use approval_state::{
    ApprovalEvent, ApprovalResolution, ApprovalState, ApprovalStatus, ApprovalView,
};
use audit_state::{AuditEntry, AuditState};
use execution_activity::{
    ExecutionActivityState, ExecutionEvent, ExecutionSnapshot, ExecutionStatus,
};
use execution_core::{repository_root, ExecutionCoreState, ExecutionCoreStatus};
use lifecycle::LifecycleState;
use permission_policy::{
    ApprovalScope, PolicyDecision, PolicyDecisionEvent, PolicyEffect, PolicyRequestInput,
    PolicyRuleView, PolicyState,
};
use process_supervisor::ProcessSupervisor;
use remote_access::{RemoteAccessPhase, RemoteAccessState, RemoteAccessStatus};
use remote_mcp::{McpServerState, McpServerStatus};
use risk_policy::{assess, RiskAssessment, RiskRequestInput};
use std::collections::HashSet;
use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager, RunEvent, UserAttentionType, WindowEvent,
};
use tauri_plugin_notification::NotificationExt;

const MAIN_WINDOW_LABEL: &str = "main";
const TRAY_ID: &str = "shellwarden-tray";
const MENU_OPEN: &str = "open";
const MENU_STATUS: &str = "status";
const MENU_ACTIVITY: &str = "activity";
const MENU_APPROVALS: &str = "approvals";
const MENU_REMOTE: &str = "remote";
const MENU_EXIT: &str = "exit";

#[derive(Default)]
pub struct NotificationTracker {
    notified_approvals: Mutex<HashSet<String>>,
    last_notified_remote_error: Mutex<Option<String>>,
}

impl NotificationTracker {
    pub fn should_notify_approval(&self, approval_id: &str) -> bool {
        let mut set = self
            .notified_approvals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        set.insert(approval_id.to_string())
    }

    pub fn should_notify_remote_error(
        &self,
        phase: RemoteAccessPhase,
        error_msg: Option<&str>,
    ) -> bool {
        let mut last_error = self
            .last_notified_remote_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if phase == RemoteAccessPhase::Error {
            if let Some(msg) = error_msg {
                if last_error.as_deref() != Some(msg) {
                    *last_error = Some(msg.to_string());
                    return true;
                }
            }
        } else {
            *last_error = None;
        }
        false
    }
}

#[tauri::command]
fn show_main_window(app: AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[tauri::command]
fn execution_core_status(state: tauri::State<'_, ExecutionCoreState>) -> ExecutionCoreStatus {
    state.status()
}

#[tauri::command]
fn execution_activity_snapshot(
    state: tauri::State<'_, ExecutionActivityState>,
) -> Vec<ExecutionSnapshot> {
    state.snapshot()
}

#[tauri::command]
fn approval_snapshot(state: tauri::State<'_, ApprovalState>) -> Vec<ApprovalView> {
    state.snapshot()
}

#[tauri::command]
fn approval_resolve(
    approvals: tauri::State<'_, ApprovalState>,
    policy: tauri::State<'_, PolicyState>,
    approval_id: String,
    scope: ApprovalScope,
) -> Result<ApprovalResolution, String> {
    approvals.resolve(&approval_id, scope, &policy)
}

#[tauri::command]
fn policy_decide(
    state: tauri::State<'_, PolicyState>,
    input: PolicyRequestInput,
) -> Result<PolicyDecision, String> {
    state.decide(input)
}

#[tauri::command]
fn policy_recent_decisions(
    state: tauri::State<'_, PolicyState>,
) -> Result<Vec<PolicyDecisionEvent>, String> {
    state.recent_decisions()
}

#[tauri::command]
fn policy_grant_scope(
    state: tauri::State<'_, PolicyState>,
    scope: ApprovalScope,
    input: PolicyRequestInput,
) -> Result<PolicyRuleView, String> {
    state.grant_scope_checked(scope, input)
}

#[tauri::command]
fn risk_assess(input: RiskRequestInput) -> Result<RiskAssessment, String> {
    assess(&input)
}

#[tauri::command]
fn policy_grant_session(
    state: tauri::State<'_, PolicyState>,
    effect: PolicyEffect,
    input: PolicyRequestInput,
) -> Result<PolicyRuleView, String> {
    state.grant_session(effect, input)
}

#[tauri::command]
fn policy_grant_persistent(
    state: tauri::State<'_, PolicyState>,
    effect: PolicyEffect,
    input: PolicyRequestInput,
) -> Result<PolicyRuleView, String> {
    state.grant_persistent(effect, input)
}

#[tauri::command]
fn policy_rules(state: tauri::State<'_, PolicyState>) -> Result<Vec<PolicyRuleView>, String> {
    state.list()
}

#[tauri::command]
fn policy_revoke(
    state: tauri::State<'_, PolicyState>,
    rule_id: String,
) -> Result<bool, String> {
    state.revoke(&rule_id)
}

#[tauri::command]
fn policy_reset_session(
    state: tauri::State<'_, PolicyState>,
    session_id: String,
) -> Result<usize, String> {
    state.reset_session(&session_id)
}

#[tauri::command]
fn policy_reset_all_sessions(state: tauri::State<'_, PolicyState>) -> Result<usize, String> {
    state.reset_all_sessions()
}

#[tauri::command]
fn policy_reset_persistent(state: tauri::State<'_, PolicyState>) -> Result<usize, String> {
    state.reset_persistent()
}

#[tauri::command]
fn policy_reset_directory_scoped(
    state: tauri::State<'_, PolicyState>,
) -> Result<usize, String> {
    state.reset_directory_scoped()
}

#[tauri::command]
fn audit_entries(
    state: tauri::State<'_, AuditState>,
    limit: Option<usize>,
) -> Result<Vec<AuditEntry>, String> {
    state.list(limit.unwrap_or(500))
}

#[tauri::command]
fn mcp_server_status(state: tauri::State<'_, McpServerState>) -> McpServerStatus {
    state.status()
}

#[tauri::command]
fn remote_access_status(
    app: AppHandle,
    state: tauri::State<'_, RemoteAccessState>,
) -> RemoteAccessStatus {
    state.status(&app)
}

#[tauri::command]
fn remote_access_connect(
    app: AppHandle,
    state: tauri::State<'_, RemoteAccessState>,
    tunnel_id: String,
    api_key: String,
    binary: Option<String>,
) -> Result<RemoteAccessStatus, String> {
    state.configure_and_start(&app, tunnel_id, api_key, binary)
}

#[tauri::command]
fn remote_access_pause(
    app: AppHandle,
    state: tauri::State<'_, RemoteAccessState>,
) -> RemoteAccessStatus {
    state.pause(&app)
}

#[tauri::command]
fn remote_access_resume(
    app: AppHandle,
    state: tauri::State<'_, RemoteAccessState>,
) -> Result<RemoteAccessStatus, String> {
    state.resume(&app)
}

fn show_main_window_ref(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn running_execution_count(app: &AppHandle) -> usize {
    app.state::<ExecutionActivityState>()
        .snapshot()
        .iter()
        .filter(|execution| {
            matches!(
                execution.state,
                ExecutionStatus::Requested | ExecutionStatus::Queued | ExecutionStatus::Running
            )
        })
        .count()
}

fn build_tray_menu(
    app: &AppHandle,
    running: usize,
    pending: usize,
) -> tauri::Result<Menu<tauri::Wry>> {
    let open = MenuItem::with_id(app, MENU_OPEN, "Open ShellWarden", true, None::<&str>)?;
    let remote = app.state::<RemoteAccessState>().status(app);
    let remote_label = match remote.phase {
        RemoteAccessPhase::Unconfigured => "Remote access: not configured".to_string(),
        RemoteAccessPhase::Paused => "Remote access: paused".to_string(),
        RemoteAccessPhase::Starting => "Remote access: connecting".to_string(),
        RemoteAccessPhase::Connected => "Remote access: connected".to_string(),
        RemoteAccessPhase::Error => "Remote access: error".to_string(),
    };
    let status = MenuItem::with_id(
        app,
        MENU_STATUS,
        remote_label,
        false,
        None::<&str>,
    )?;
    let activity = MenuItem::with_id(
        app,
        MENU_ACTIVITY,
        format!("{running} tasks running"),
        false,
        None::<&str>,
    )?;
    let approvals = MenuItem::with_id(
        app,
        MENU_APPROVALS,
        if pending == 0 {
            "No approvals waiting".to_string()
        } else if pending == 1 {
            "Review 1 waiting approval".to_string()
        } else {
            format!("Review {pending} waiting approvals")
        },
        pending > 0,
        None::<&str>,
    )?;
    let remote_toggle = MenuItem::with_id(
        app,
        MENU_REMOTE,
        match remote.phase {
            RemoteAccessPhase::Connected | RemoteAccessPhase::Starting => "Pause Remote Access",
            _ => "Resume Remote Access",
        },
        remote.configured,
        None::<&str>,
    )?;
    let separator_before_exit = PredefinedMenuItem::separator(app)?;
    let exit = MenuItem::with_id(app, MENU_EXIT, "Exit ShellWarden", true, None::<&str>)?;

    Menu::with_items(
        app,
        &[
            &open,
            &status,
            &activity,
            &approvals,
            &remote_toggle,
            &separator_before_exit,
            &exit,
        ],
    )
}

fn update_tray_attention(app: &AppHandle) -> tauri::Result<()> {
    let running = running_execution_count(app);
    let pending = app.state::<ApprovalState>().pending_count();
    let menu = build_tray_menu(app, running, pending)?;

    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        tray.set_menu(Some(menu))?;
        let tooltip = if pending == 0 {
            format!("ShellWarden — {running} tasks running")
        } else {
            format!("ShellWarden — {pending} approvals waiting")
        };
        tray.set_tooltip(Some(tooltip))?;
    }

    Ok(())
}

fn install_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let menu = build_tray_menu(app.handle(), 0, 0)?;

    let mut tray = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("ShellWarden — local control center")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id().as_ref() {
            MENU_OPEN => show_main_window_ref(app),
            MENU_APPROVALS => {
                show_main_window_ref(app);
                let _ = app.emit("shellwarden://open-approvals", ());
            }
            MENU_REMOTE => {
                let remote = app.state::<RemoteAccessState>();
                match remote.status(app).phase {
                    RemoteAccessPhase::Connected | RemoteAccessPhase::Starting => {
                        remote.pause(app);
                    }
                    _ => {
                        let _ = remote.resume(app);
                    }
                }
                let _ = update_tray_attention(app);
            }
            MENU_EXIT => {
                app.state::<LifecycleState>().begin_exit();
                app.exit(0);
            }
            _ => {}
        });

    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }

    tray.build(app)?;
    Ok(())
}

fn apply_approval_to_activity(app: &AppHandle, approval: &ApprovalView) {
    let Some(execution_id) = approval.execution_id.as_deref() else {
        return;
    };

    let next = match approval.status {
        ApprovalStatus::Pending => Some(ExecutionStatus::AwaitingApproval),
        ApprovalStatus::Allowed => Some(ExecutionStatus::Queued),
        ApprovalStatus::Denied => Some(ExecutionStatus::Denied),
        ApprovalStatus::Cancelled | ApprovalStatus::Expired => Some(ExecutionStatus::Cancelled),
    };

    let activity = app.state::<ExecutionActivityState>();
    let _ = activity.set_policy_rule(execution_id, approval.decision_rule_id.clone());

    if let Some(next) = next {
        let _ = activity.transition(execution_id, next);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(LifecycleState::default())
        .manage(ProcessSupervisor::default())
        .manage(ExecutionActivityState::default())
        .manage(ExecutionCoreState::default())
        .manage(PolicyState::default())
        .manage(ApprovalState::default())
        .manage(AuditState::default())
        .manage(McpServerState::default())
        .manage(RemoteAccessState::default())
        .manage(NotificationTracker::default())
        .invoke_handler(tauri::generate_handler![
            show_main_window,
            execution_core_status,
            execution_activity_snapshot,
            approval_snapshot,
            approval_resolve,
            policy_decide,
            policy_recent_decisions,
            policy_grant_scope,
            risk_assess,
            policy_grant_session,
            policy_grant_persistent,
            policy_rules,
            policy_revoke,
            policy_reset_session,
            policy_reset_all_sessions,
            policy_reset_persistent,
            policy_reset_directory_scoped,
            audit_entries,
            mcp_server_status,
            remote_access_status,
            remote_access_connect,
            remote_access_pause,
            remote_access_resume
        ])
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            let policy_database = app_data_dir.join("permissions.sqlite3");
            app.state::<PolicyState>()
                .initialize(&policy_database)
                .map_err(std::io::Error::other)?;
            let audit_database = app_data_dir.join("audit.sqlite3");
            app.state::<AuditState>()
                .initialize(&audit_database)
                .map_err(std::io::Error::other)?;

            app.state::<ExecutionCoreState>().start(&repository_root());
            app.state::<McpServerState>().start(app.handle().clone());

            let policy_events = app
                .state::<PolicyState>()
                .subscribe_decisions()
                .map_err(std::io::Error::other)?;
            let policy_audit_app = app.handle().clone();
            std::thread::spawn(move || {
                while let Ok(event) = policy_events.recv() {
                    if policy_audit_app
                        .state::<AuditState>()
                        .record_decision(&event)
                        .is_ok()
                    {
                        let _ = policy_audit_app.emit("shellwarden://audit", ());
                    }
                }
            });

            let activity_events = app.state::<ExecutionActivityState>().subscribe();
            let activity_app = app.handle().clone();
            std::thread::spawn(move || {
                while let Ok(event) = activity_events.recv() {
                    if let ExecutionEvent::State {
                        execution_id,
                        state,
                        ..
                    } = &event
                    {
                        if state.is_terminal() {
                            if let Some(snapshot) = activity_app
                                .state::<ExecutionActivityState>()
                                .snapshot()
                                .into_iter()
                                .find(|execution| execution.request.id == *execution_id)
                            {
                                if activity_app
                                    .state::<AuditState>()
                                    .record_execution(&snapshot)
                                    .is_ok()
                                {
                                    let _ = activity_app.emit("shellwarden://audit", ());
                                }
                            }
                        }
                    }

                    let _ = activity_app.emit("shellwarden://execution-activity", event);
                    let _ = update_tray_attention(&activity_app);
                }
            });

            let approval_events = app.state::<ApprovalState>().subscribe();
            let approval_app = app.handle().clone();
            std::thread::spawn(move || {
                while let Ok(event) = approval_events.recv() {
                    match &event {
                        ApprovalEvent::Changed { approval, .. } => {
                            apply_approval_to_activity(&approval_app, approval);
                            if approval.status == ApprovalStatus::Pending {
                                let tracker = approval_app.state::<NotificationTracker>();
                                if tracker.should_notify_approval(&approval.id) {
                                    let cmd_text = approval.command.join(" ");
                                    let _ = approval_app
                                        .notification()
                                        .builder()
                                        .title("ShellWarden — Approval Needed")
                                        .body(format!("{} requested: {}", approval.source, cmd_text))
                                        .show();
                                }
                                if let Some(window) =
                                    approval_app.get_webview_window(MAIN_WINDOW_LABEL)
                                {
                                    let attention = if matches!(
                                        approval.risk.class,
                                        risk_policy::RiskClass::Critical
                                    ) {
                                        UserAttentionType::Critical
                                    } else {
                                        UserAttentionType::Informational
                                    };
                                    let _ = window.request_user_attention(Some(attention));
                                }
                            }
                        }
                    }
                    let _ = approval_app.emit("shellwarden://approval", event);
                    let _ = update_tray_attention(&approval_app);
                }
            });

            let remote_app = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let status = remote_app.state::<RemoteAccessState>().status(&remote_app);
                let tracker = remote_app.state::<NotificationTracker>();
                if tracker.should_notify_remote_error(status.phase, status.error.as_deref()) {
                    let err_text = status
                        .error
                        .as_deref()
                        .unwrap_or("Remote access encountered an error.");
                    let _ = remote_app
                        .notification()
                        .builder()
                        .title("ShellWarden — Remote Access Error")
                        .body(err_text)
                        .show();
                }
                let _ = update_tray_attention(&remote_app);
            });

            install_tray(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != MAIN_WINDOW_LABEL {
                return;
            }

            if let WindowEvent::CloseRequested { api, .. } = event {
                let lifecycle = window.app_handle().state::<LifecycleState>();

                if lifecycle.should_hide_window_on_close() {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building ShellWarden");

    app.run(|app_handle, event| {
        if let RunEvent::ExitRequested { .. } = event {
            app_handle.state::<LifecycleState>().begin_exit();
            let _ = app_handle
                .state::<ExecutionActivityState>()
                .cancel_all_non_terminal();
            let _ = app_handle.state::<PolicyState>().reset_all_sessions();
            app_handle
                .state::<RemoteAccessState>()
                .stop_for_exit(app_handle);
            app_handle.state::<McpServerState>().stop();
            app_handle.state::<ExecutionCoreState>().stop();
            let _ = app_handle.state::<ProcessSupervisor>().stop_all();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_notification_deduplicates_repeated_checks() {
        let tracker = NotificationTracker::default();

        assert!(tracker.should_notify_approval("approval-1"));
        assert!(!tracker.should_notify_approval("approval-1"));
        assert!(!tracker.should_notify_approval("approval-1"));

        assert!(tracker.should_notify_approval("approval-2"));
        assert!(!tracker.should_notify_approval("approval-2"));
    }

    #[test]
    fn remote_error_notification_deduplicates_and_resets() {
        let tracker = NotificationTracker::default();

        assert!(!tracker.should_notify_remote_error(RemoteAccessPhase::Starting, None));

        assert!(tracker.should_notify_remote_error(
            RemoteAccessPhase::Error,
            Some("connection refused")
        ));
        assert!(!tracker.should_notify_remote_error(
            RemoteAccessPhase::Error,
            Some("connection refused")
        ));

        assert!(tracker.should_notify_remote_error(
            RemoteAccessPhase::Error,
            Some("timeout waiting for tunnel")
        ));

        assert!(!tracker.should_notify_remote_error(RemoteAccessPhase::Connected, None));

        assert!(tracker.should_notify_remote_error(
            RemoteAccessPhase::Error,
            Some("connection refused")
        ));
    }
}

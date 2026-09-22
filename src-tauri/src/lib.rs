mod approval_state;
mod execution_activity;
mod execution_core;
mod lifecycle;
mod permission_policy;
mod process_supervisor;
mod risk_policy;

use approval_state::{
    ApprovalEvent, ApprovalResolution, ApprovalState, ApprovalStatus, ApprovalView,
};
use execution_activity::{ExecutionActivityState, ExecutionSnapshot, ExecutionStatus};
use execution_core::{repository_root, ExecutionCoreState, ExecutionCoreStatus};
use lifecycle::LifecycleState;
use permission_policy::{
    ApprovalScope, PolicyDecision, PolicyDecisionEvent, PolicyEffect, PolicyRequestInput,
    PolicyRuleView, PolicyState,
};
use process_supervisor::ProcessSupervisor;
use risk_policy::{assess, RiskAssessment, RiskRequestInput};
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager, RunEvent, UserAttentionType, WindowEvent,
};

const MAIN_WINDOW_LABEL: &str = "main";
const TRAY_ID: &str = "shellwarden-tray";
const MENU_OPEN: &str = "open";
const MENU_STATUS: &str = "status";
const MENU_ACTIVITY: &str = "activity";
const MENU_APPROVALS: &str = "approvals";
const MENU_EXIT: &str = "exit";

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

fn show_main_window(app: &AppHandle) {
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
    let status = MenuItem::with_id(
        app,
        MENU_STATUS,
        "Remote access: not configured",
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
    let separator_before_exit = PredefinedMenuItem::separator(app)?;
    let exit = MenuItem::with_id(app, MENU_EXIT, "Exit ShellWarden", true, None::<&str>)?;

    Menu::with_items(
        app,
        &[
            &open,
            &status,
            &activity,
            &approvals,
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
            MENU_OPEN => show_main_window(app),
            MENU_APPROVALS => {
                show_main_window(app);
                let _ = app.emit("shellwarden://open-approvals", ());
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

    if let Some(next) = next {
        let _ = app
            .state::<ExecutionActivityState>()
            .transition(execution_id, next);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .manage(LifecycleState::default())
        .manage(ProcessSupervisor::default())
        .manage(ExecutionActivityState::default())
        .manage(ExecutionCoreState::default())
        .manage(PolicyState::default())
        .manage(ApprovalState::default())
        .invoke_handler(tauri::generate_handler![
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
            policy_reset_persistent
        ])
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            let policy_database = app_data_dir.join("permissions.sqlite3");
            app.state::<PolicyState>()
                .initialize(&policy_database)
                .map_err(std::io::Error::other)?;

            app.state::<ExecutionCoreState>().start(&repository_root());

            let activity_events = app.state::<ExecutionActivityState>().subscribe();
            let activity_app = app.handle().clone();
            std::thread::spawn(move || {
                while let Ok(event) = activity_events.recv() {
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
            app_handle.state::<ExecutionCoreState>().stop();
            let _ = app_handle.state::<ProcessSupervisor>().stop_all();
        }
    });
}

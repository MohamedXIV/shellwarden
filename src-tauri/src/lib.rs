mod execution_activity;
mod execution_core;
mod lifecycle;
mod permission_policy;
mod process_supervisor;

use execution_activity::{ExecutionActivityState, ExecutionSnapshot};
use execution_core::{repository_root, ExecutionCoreState, ExecutionCoreStatus};
use lifecycle::LifecycleState;
use permission_policy::{
    PermissionPolicyState, PolicyDecision, PolicyRequest, PolicyRule,
};
use process_supervisor::ProcessSupervisor;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    Manager, RunEvent, WindowEvent,
};

const MAIN_WINDOW_LABEL: &str = "main";
const TRAY_ID: &str = "shellwarden-tray";
const MENU_OPEN: &str = "open";
const MENU_STATUS: &str = "status";
const MENU_ACTIVITY: &str = "activity";
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
fn permission_evaluate(
    state: tauri::State<'_, PermissionPolicyState>,
    request: PolicyRequest,
) -> Result<PolicyDecision, String> {
    state.evaluate(&request)
}

#[tauri::command]
fn permission_rules(
    state: tauri::State<'_, PermissionPolicyState>,
) -> Result<Vec<PolicyRule>, String> {
    state.list_rules()
}

#[tauri::command]
fn permission_revoke(
    state: tauri::State<'_, PermissionPolicyState>,
    rule_id: String,
) -> Result<bool, String> {
    state.revoke(&rule_id)
}

#[tauri::command]
fn permission_reset_session(state: tauri::State<'_, PermissionPolicyState>) -> usize {
    state.reset_session()
}

#[tauri::command]
fn permission_reset_persistent(
    state: tauri::State<'_, PermissionPolicyState>,
) -> Result<usize, String> {
    state.reset_persistent()
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn install_tray(app: &mut tauri::App) -> tauri::Result<()> {
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
        "0 tasks running · 0 approvals waiting",
        false,
        None::<&str>,
    )?;
    let separator_before_exit = PredefinedMenuItem::separator(app)?;
    let exit = MenuItem::with_id(app, MENU_EXIT, "Exit ShellWarden", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[&open, &status, &activity, &separator_before_exit, &exit],
    )?;

    let mut tray = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("ShellWarden — local control center")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id().as_ref() {
            MENU_OPEN => show_main_window(app),
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .manage(LifecycleState::default())
        .manage(ProcessSupervisor::default())
        .manage(ExecutionActivityState::default())
        .manage(ExecutionCoreState::default())
        .invoke_handler(tauri::generate_handler![
            execution_core_status,
            execution_activity_snapshot,
            permission_evaluate,
            permission_rules,
            permission_revoke,
            permission_reset_session,
            permission_reset_persistent
        ])
        .setup(|app| {
            let app_data = app
                .path()
                .app_data_dir()
                .map_err(|error| std::io::Error::other(format!("app data path unavailable: {error}")))?;
            let permission_store = PermissionPolicyState::open(&app_data.join("permissions.sqlite3"))
                .map_err(std::io::Error::other)?;
            app.manage(permission_store);

            app.state::<ExecutionCoreState>().start(&repository_root());
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
            app_handle.state::<ExecutionCoreState>().stop();
            let _ = app_handle.state::<ProcessSupervisor>().stop_all();
        }
    });
}

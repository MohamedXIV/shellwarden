mod lifecycle;
mod process_supervisor;

use lifecycle::LifecycleState;
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
    let menu = Menu::with_items(
        app,
        &[&open, &status, &activity, &separator_before_exit, &MenuItem::with_id(
            app,
            MENU_EXIT,
            "Exit ShellWarden",
            true,
            None::<&str>,
        )?],
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
        .setup(|app| {
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
            let _ = app_handle.state::<ProcessSupervisor>().stop_all();
        }
    });
}

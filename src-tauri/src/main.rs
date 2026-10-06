#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(windows)]
    if shellwarden_lib::intercept_windows_notification_activation() {
        return;
    }

    shellwarden_lib::run();
}

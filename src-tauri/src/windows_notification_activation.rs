use std::{
    env,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::OnceLock,
    thread,
    time::Duration,
};

use tauri::{AppHandle, Emitter, Manager};
use windows::{
    core::HSTRING,
    Data::Xml::Dom::XmlDocument,
    UI::Notifications::{ToastNotification, ToastNotificationManager},
};
use winreg::{enums::HKEY_CURRENT_USER, RegKey};

const APP_ID: &str = "io.github.mohamedxiv.shellwarden";
const ACTIVATION_ARGUMENT: &str = "--notification-activation";
const PROTOCOL_SCHEME: &str = "shellwarden-notification";
const APPROVAL_ROUTE_PREFIX: &str = "shellwarden-notification://approval/";
const SETTINGS_ROUTE: &str = "shellwarden-notification://settings";
const ENDPOINT_FILE: &str = "notification-activation.port";
const MAX_ACTIVATION_BYTES: u64 = 2048;

static INITIAL_ACTIVATION: OnceLock<String> = OnceLock::new();
static OWNED_ENDPOINT: OnceLock<(PathBuf, u16)> = OnceLock::new();

/// Handle a Windows protocol activation before Tauri creates the desktop app.
///
/// Returns true when an already-running ShellWarden accepted the activation, in
/// which case this short-lived protocol-handler process should exit immediately.
pub fn intercept_process_activation() -> bool {
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        if argument != ACTIVATION_ARGUMENT {
            continue;
        }

        let Some(route) = args.next() else {
            return false;
        };
        if !is_supported_route(&route) {
            return false;
        }

        if forward_to_running_instance(&route).is_ok() {
            return true;
        }

        let _ = INITIAL_ACTIVATION.set(route);
        return false;
    }

    false
}

pub(crate) fn install(app: &AppHandle) -> Result<(), String> {
    register_protocol_if_packaged()?;
    start_activation_listener(app)?;

    if let Some(route) = INITIAL_ACTIVATION.get().cloned() {
        dispatch_activation(app, route);
    }

    Ok(())
}

pub(crate) fn cleanup() {
    let Some((path, owned_port)) = OWNED_ENDPOINT.get() else {
        return;
    };

    let still_owned = fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok())
        == Some(*owned_port);
    if still_owned {
        let _ = fs::remove_file(path);
    }
}

pub(crate) fn show_approval(
    app: &AppHandle,
    approval_id: &str,
    title: &str,
    body: &str,
) -> Result<(), String> {
    if !approval_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("approval id contains unsupported notification-route characters".to_string());
    }

    show_protocol_toast(
        app,
        title,
        body,
        &format!("{APPROVAL_ROUTE_PREFIX}{approval_id}"),
    )
}

pub(crate) fn show_settings(app: &AppHandle, title: &str, body: &str) -> Result<(), String> {
    show_protocol_toast(app, title, body, SETTINGS_ROUTE)
}

fn show_protocol_toast(
    app: &AppHandle,
    title: &str,
    body: &str,
    launch_uri: &str,
) -> Result<(), String> {
    let document = XmlDocument::new().map_err(|error| error.to_string())?;
    let xml = format!(
        r#"<toast activationType="protocol" launch="{}"><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual></toast>"#,
        escape_xml(launch_uri),
        escape_xml(title),
        escape_xml(body),
    );
    document
        .LoadXml(&HSTRING::from(xml))
        .map_err(|error| error.to_string())?;

    let toast =
        ToastNotification::CreateToastNotification(&document).map_err(|error| error.to_string())?;
    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(
        app.config().identifier.clone(),
    ))
    .map_err(|error| error.to_string())?;
    notifier.Show(&toast).map_err(|error| error.to_string())
}

fn register_protocol_if_packaged() -> Result<(), String> {
    let executable = env::current_exe()
        .map_err(|error| format!("failed to resolve ShellWarden executable: {error}"))?;
    if running_from_cargo_target(&executable) {
        return Ok(());
    }

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let base = format!(r"Software\Classes\{PROTOCOL_SCHEME}");
    let (scheme, _) = hkcu
        .create_subkey(&base)
        .map_err(|error| format!("failed to register notification protocol: {error}"))?;
    scheme
        .set_value("", &"URL:ShellWarden Notification Protocol")
        .map_err(|error| format!("failed to set notification protocol label: {error}"))?;
    scheme
        .set_value("URL Protocol", &"")
        .map_err(|error| format!("failed to mark notification URL protocol: {error}"))?;

    let (icon, _) = scheme
        .create_subkey("DefaultIcon")
        .map_err(|error| format!("failed to register notification protocol icon: {error}"))?;
    icon.set_value("", &format!(r#""{}",0"#, executable.display()))
        .map_err(|error| format!("failed to set notification protocol icon: {error}"))?;

    let (command, _) = scheme
        .create_subkey(r"shell\open\command")
        .map_err(|error| format!("failed to register notification protocol command: {error}"))?;
    command
        .set_value(
            "",
            &format!(
                r#""{}" {} "%1""#,
                executable.display(),
                ACTIVATION_ARGUMENT
            ),
        )
        .map_err(|error| format!("failed to set notification protocol command: {error}"))?;

    Ok(())
}

fn running_from_cargo_target(executable: &Path) -> bool {
    executable
        .parent()
        .map(|parent| parent.to_string_lossy().replace('/', "\\").to_ascii_lowercase())
        .is_some_and(|parent| {
            parent.ends_with(r"\target\debug") || parent.ends_with(r"\target\release")
        })
}

fn start_activation_listener(app: &AppHandle) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("failed to bind notification activation endpoint: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("failed to resolve notification activation endpoint: {error}"))?
        .port();

    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("failed to resolve ShellWarden app data directory: {error}"))?;
    fs::create_dir_all(&app_data_dir)
        .map_err(|error| format!("failed to create ShellWarden app data directory: {error}"))?;
    let endpoint_path = app_data_dir.join(ENDPOINT_FILE);
    fs::write(&endpoint_path, port.to_string())
        .map_err(|error| format!("failed to publish notification activation endpoint: {error}"))?;
    let _ = OWNED_ENDPOINT.set((endpoint_path, port));

    let activation_app = app.clone();
    thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
            let route = read_bounded_line(&mut stream);
            match route {
                Ok(route) if is_supported_route(&route) => {
                    dispatch_activation(&activation_app, route);
                    let _ = stream.write_all(b"ok\n");
                }
                _ => {
                    let _ = stream.write_all(b"invalid\n");
                }
            }
        }
    });

    Ok(())
}

fn forward_to_running_instance(route: &str) -> Result<(), String> {
    let endpoint_path = activation_endpoint_path_from_environment()
        .ok_or_else(|| "APPDATA is unavailable".to_string())?;
    let port = fs::read_to_string(&endpoint_path)
        .map_err(|error| format!("activation endpoint is unavailable: {error}"))?
        .trim()
        .parse::<u16>()
        .map_err(|error| format!("activation endpoint is invalid: {error}"))?;

    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(750))
        .map_err(|error| format!("running ShellWarden activation endpoint is unavailable: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|error| format!("failed to configure activation response timeout: {error}"))?;
    stream
        .write_all(format!("{route}\n").as_bytes())
        .map_err(|error| format!("failed to forward notification activation: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("failed to flush notification activation: {error}"))?;

    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .map_err(|error| format!("failed to read notification activation acknowledgement: {error}"))?;
    if response.trim() == "ok" {
        Ok(())
    } else {
        Err("running ShellWarden rejected notification activation".to_string())
    }
}

fn activation_endpoint_path_from_environment() -> Option<PathBuf> {
    env::var_os("APPDATA")
        .map(PathBuf::from)
        .map(|path| path.join(APP_ID).join(ENDPOINT_FILE))
}

fn read_bounded_line(stream: &mut TcpStream) -> Result<String, String> {
    let mut payload = String::new();
    stream
        .take(MAX_ACTIVATION_BYTES)
        .read_to_string(&mut payload)
        .map_err(|error| format!("failed to read notification activation: {error}"))?;
    let route = payload.lines().next().unwrap_or_default().trim().to_string();
    if route.is_empty() {
        Err("notification activation payload is empty".to_string())
    } else {
        Ok(route)
    }
}

fn is_supported_route(route: &str) -> bool {
    route == SETTINGS_ROUTE
        || route
            .strip_prefix(APPROVAL_ROUTE_PREFIX)
            .is_some_and(|approval_id| {
                !approval_id.is_empty()
                    && approval_id.len() <= 256
                    && approval_id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            })
}

fn dispatch_activation(app: &AppHandle, route: String) {
    let ui_app = app.clone();
    let dispatch_app = app.clone();
    let _ = ui_app.run_on_main_thread(move || {
        super::show_main_window_ref(&dispatch_app);
        if route == SETTINGS_ROUTE {
            let _ = dispatch_app.emit("shellwarden://open-settings", ());
        } else if let Some(approval_id) = route.strip_prefix(APPROVAL_ROUTE_PREFIX) {
            let _ = dispatch_app.emit("shellwarden://open-approval", approval_id.to_string());
        }
    });
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_routes_are_bounded_and_explicit() {
        assert!(is_supported_route(SETTINGS_ROUTE));
        assert!(is_supported_route(
            "shellwarden-notification://approval/approval-123-1"
        ));
        assert!(!is_supported_route("shellwarden-notification://approval/"));
        assert!(!is_supported_route("shellwarden-notification://approval/a/b"));
        assert!(!is_supported_route("https://example.com"));
    }

    #[test]
    fn notification_xml_values_are_escaped() {
        assert_eq!(
            escape_xml(r#"a&b<c>d"e'f"#),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }
}

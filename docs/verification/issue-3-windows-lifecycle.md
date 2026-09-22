# Issue #3 — Windows lifecycle verification

This checklist verifies the native tray behavior that is not usefully proven by unit tests alone.

## Automated evidence

CI must pass:

- frontend lint/typecheck/tests/build;
- Rust lifecycle/process-supervisor unit tests;
- Tauri release build on Windows;
- release executable launch smoke.

## Manual Windows checklist

Run from a fresh checkout of the issue branch or merged `main`:

```powershell
npm install
npm run tauri:dev
```

Then verify:

1. ShellWarden opens with the main window visible.
2. A ShellWarden tray icon is visible while the app is running.
3. Press the main window **X**.
4. The window disappears, but the ShellWarden process and tray icon remain.
5. Open the tray menu and confirm it shows:
   - `Open ShellWarden`;
   - `Remote access: not configured`;
   - `0 tasks running · 0 approvals waiting`;
   - `Exit ShellWarden`.
6. Choose **Open ShellWarden** and confirm the existing main window returns and receives focus.
7. Close the window to tray again.
8. Choose **Exit ShellWarden**.
9. Confirm the tray icon disappears and no `shellwarden.exe` process remains in Task Manager:

```powershell
Get-Process shellwarden -ErrorAction SilentlyContinue
```

Expected output after Exit: no process.

## Security/lifecycle expectation

ShellWarden v0.1 must not install or depend on a Windows Service, startup daemon, or invisible always-on helper. If the tray application exits, ShellWarden access is off.

# Roadmap

The roadmap is deliberately constrained. The objective is a real dogfoodable **v0.1**, not a complete agent platform.

## Phase 0 — Foundation

Status: documentation initialized.

- product and security invariants;
- architecture direction;
- UX contract;
- Semantic Versioning + Keep a Changelog policy;
- initial development version `0.0.0-dev`.

Exit: implementation issues are defined and ordered.

## Phase 1 — Desktop shell

Deliver a runnable Windows Tauri application with:

- React/TypeScript UI shell;
- tray integration;
- close-to-tray behavior;
- explicit Exit;
- child-process supervisor foundation;
- development health/status surface.

Exit: the app can be opened, minimized to tray, restored, and fully exited with no ShellWarden-managed helper intentionally left behind.

## Phase 2 — Execution path

- integrate a pinned upstream `mcp-shell-server`;
- establish broker-to-execution boundary;
- normalize execution requests;
- emit structured execution lifecycle events;
- track and stop managed processes;
- baseline tests for execution/security behavior.

Exit: a local request can execute an allowlisted harmless command and appear as a structured activity.

## Phase 3 — Permission gate

- policy model and persistence;
- once/session/exact-directory/tree/persistent scopes;
- canonical path enforcement;
- deterministic risk classes;
- dangerous-shell/interpreter treatment;
- approve/deny request lifecycle;
- revoke/reset.

Exit: an unknown command cannot run until policy resolves it, and the resulting grant can be inspected and revoked.

## Phase 4 — Control center

- live Activity UI;
- approval cards + desktop/tray notifications;
- Permissions view;
- Audit view;
- pause/resume remote access;
- clear connection and process status.

Exit: normal dogfooding no longer requires editing policy/config files manually.

## Phase 5 — Real remote dogfood

- integrate OpenAI Secure MCP Tunnel;
- provide connection setup/status;
- verify pause disconnects remote authority;
- run a real ChatGPT -> ShellWarden -> local command flow;
- dogfood with Git plus at least one agent CLI such as Jules or Codex;
- fix critical usability/security gaps found during dogfood.

Exit: the complete workflow below passes.

## v0.1 acceptance flow

```text
Open ShellWarden
-> remote access visibly ON
-> MCP client requests a harmless read command
-> request is shown live
-> policy asks because no matching grant exists
-> user approves for the intended repo/session
-> command executes
-> output/result is visible
-> audit explains why it was allowed
-> a risky command shows a stronger warning
-> user can revoke the grant
-> Pause Remote Access blocks/disconnects new remote authority
-> Resume restores it
-> Exit stops tunnel + MCP/broker + managed executions
-> no hidden ShellWarden service remains
```

## Version target

- Development foundation: `0.0.0-dev`
- First runnable dogfood artifact: `0.1.0-alpha.1`
- Subsequent dogfood fixes: `0.1.0-alpha.N`
- Feature-complete candidate: `0.1.0-beta.1`
- Stable v0.1 acceptance: `0.1.0`

## Explicitly post-v0.1

- macOS/Linux product support;
- cloud control plane;
- teams/RBAC;
- full terminal emulator;
- agent orchestration;
- marketplace/plugins;
- ML risk scoring;
- bundled sandbox/VM/container runtime.

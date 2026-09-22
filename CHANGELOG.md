# Changelog

All notable changes to ShellWarden are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and ShellWarden follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial product definition, architecture, security model, UX contract, roadmap, and release policy.
- Development version source initialized at `0.0.0-dev`.
- Windows-first Tauri 2 + React/TypeScript application foundation with a dark control-center shell and roadmap navigation.
- Baseline Biome linting/formatting, TypeScript checks, version consistency tests, frontend build verification, and GitHub Actions CI.
- Repository version injection into the UI so the application displays the canonical `VERSION` value.
- Native Windows tray lifecycle with Open and Exit actions plus visible placeholder status for running work and approvals.
- Managed-process supervisor foundation that terminates registered child processes during ShellWarden shutdown.
- Rust lifecycle tests and a documented manual Windows tray/exit verification checklist.
- Pinned `mcp-shell-server 1.1.12` execution core behind a ShellWarden-owned JSON-lines broker boundary.
- Execution-core health/version status surfaced in the desktop dashboard and verified with a real harmless `git --version` broker probe.
- Structured execution IDs, lifecycle state, backend subscriptions, bounded stdout/stderr activity tails, and read-only activity snapshots.
- Broker-level stdout/stderr streaming events while retaining the pinned upstream validator/executor path.
- Per-process stop support and Windows process-tree termination for managed helpers.
- Positive allow/ask/deny permission engine with session-only grants, exact persistent grants/denies, rule listing/revocation/reset APIs, and a local SQLite store.
- Scoped approvals for Once, Session, Exact Directory, Directory Tree, risk-gated Always, and Deny, including migration of earlier exact persistent rules.
- Deterministic Low/Medium/High/Critical risk assessment with user-facing reasons and allowed approval scopes.
- Live Control Center dashboard and Activity stream with execution state, requester, cwd, elapsed time, risk assessment, bounded output, pending-approval counts, and session-recent policy decisions.
- Interactive pending-approval queue and Approvals UI with risk-limited scope choices, expiry/cancellation states, direct tray navigation, and Windows attention signaling.
- Searchable Permissions management with revoke/reset controls and durable SQLite Audit history for policy decisions and terminal executions.
- Loopback Streamable HTTP MCP ingress plus managed OpenAI Secure MCP Tunnel configuration, readiness, Pause/Resume, tray status, and shutdown supervision.

### Changed
- Closing the main ShellWarden window now hides it to the tray instead of terminating the application.
- Hard Exit now resolves unfinished activity as cancelled before terminating execution-core and managed process trees.

### Security
- Established the core rule that ShellWarden is a trusted execution gateway, not an OS sandbox.
- Established Windows-first least-privilege and explicit lifecycle requirements for v0.1.
- Started the desktop application with only Tauri core permissions and no remote transport capability enabled.
- Explicit tray Exit initiates managed-process cleanup before the application terminates; no Windows Service or hidden always-on ShellWarden helper is introduced.
- Bootstrap execution remains local-only, accepts argv arrays rather than shell strings, exposes no per-request environment overrides, and admits only `git` before upstream validation.
- Added a process-local Windows compatibility adapter for the pinned upstream package instead of weakening or replacing its validation path.
- Live activity retains bounded output tails rather than an unbounded in-memory terminal transcript.
- Persistent permission matching stores SHA-256 request/operation fingerprints and non-secret metadata instead of raw argv or environment values; deny rules take precedence over allow rules.
- Path-scoped grants use canonical resolved directories and component-aware matching so traversal, symlink, junction, and reparse-point escapes do not inherit authority from a textual path prefix.
- General-purpose shells/eval interpreters and destructive operations are classified Critical and cannot receive persistent allow scopes; external side effects cannot receive tree/global authority.
- Approval-scope enforcement is computed inside ShellWarden; MCP/UI clients cannot assert that an Always grant is risk-approved.
- Denying a single pending request records the decision without silently creating a persistent deny rule; expired or cancelled requests cannot later be approved.
- Durable audit storage excludes raw argv, stdout/stderr, and environment values; command summaries persist only the executable plus a redacted argument count.
- Remote tunnel credentials remain memory-only, are handed only to a `tunnel-client`-named executable in a minimal explicit child environment, and the tunnel targets ShellWarden's loopback policy broker rather than the execution core directly.


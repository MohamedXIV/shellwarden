# Product

## One sentence

ShellWarden is a local-first desktop control center that lets people expose selected shell capabilities to AI agents over MCP while retaining visible, scoped, revocable human control.

## Problem

AI agents and CLI coding tools become dramatically more useful when they can operate on the real development machine. A raw remote terminal, however, grants far more authority than most users intend and makes it difficult to answer basic questions:

- Who is executing something right now?
- What command is running?
- In which repository or directory?
- Why was it allowed?
- What did I approve previously?
- Can I stop remote access immediately?
- Does quitting the app actually stop access?

ShellWarden exists to make that authority visible and deliberate.

## Target user

v0.1 is built first for an individual developer on Windows who:

- uses AI coding agents and CLIs such as Jules, Codex, Gemini/agy, Git, npm/bun, and development toolchains;
- wants ChatGPT or another MCP client to invoke selected local capabilities;
- wants a clear approval model instead of raw unrestricted terminal access;
- values local-first operation and explicit shutdown.

The product remains generic: no core behavior may depend on a particular AI vendor or repository.

## v0.1 job to be done

A user can launch ShellWarden, connect an MCP client, observe requested and running commands, grant appropriately scoped permissions, inspect/revoke them later, pause remote access instantly, and fully terminate access by exiting the app.

## v0.1 scope

### In

- Windows desktop application.
- System tray lifecycle.
- Real-time connection and execution state.
- Pinned upstream `mcp-shell-server` execution core.
- Command and directory policy.
- Allow once.
- Allow for current ShellWarden session.
- Allow for exact directory/repository.
- Allow for directory tree where explicitly chosen.
- Persistent allow where risk policy permits.
- Deny.
- Deterministic risk warnings.
- Approval UX and notifications.
- Permission inspection, revoke, and reset.
- Audit history with secret-aware redaction.
- Pause/resume remote access.
- OpenAI Secure MCP Tunnel integration for initial dogfooding.
- End-to-end proof with real development commands.

### Out

- Hidden Windows service or daemon.
- General terminal emulator.
- Full OS sandbox/container implementation.
- Cloud account/control plane.
- Team RBAC.
- Organization policy management.
- Marketplace/plugin ecosystem.
- AI/ML-based risk classifier.
- macOS/Linux product polish.
- Agent orchestration platform.
- Bundled AI model.

## Success criteria

v0.1 succeeds when ShellWarden is safe and pleasant enough for daily dogfooding with real repositories and agents, without requiring the user to edit policy files by hand during normal use.

The concrete exit test is documented in [ROADMAP.md](ROADMAP.md).

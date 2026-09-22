# Architecture

## Guiding rule

ShellWarden adds a **human-controlled authority broker** in front of shell execution. It should not reinvent process execution, MCP transport, or an operating-system sandbox when mature components already exist.

## v0.1 topology

```text
MCP client (initially ChatGPT)
        |
        | remote MCP
        v
OpenAI Secure MCP Tunnel
        |
        v
ShellWarden MCP / policy broker
        |
        +----> Permission engine
        |        |
        |        +---- allow
        |        +---- ask -> desktop approval
        |        +---- deny
        |
        v
pinned mcp-shell-server execution core
        |
        v
managed child process
```

The desktop application owns the visible lifecycle and supervises the components it launches.

## Desktop application

**Tauri 2 + React + TypeScript** is the v0.1 direction.

Responsibilities:

- window and tray lifecycle;
- connection status;
- live activity;
- approvals;
- permission management;
- audit views;
- local notifications;
- process supervision;
- pause/resume/exit controls.

No background Windows service is required for v0.1.

## Policy broker

The broker evaluates a normalized execution request before it reaches the execution core.

A request includes at least:

- client/session identity when available;
- executable;
- argv;
- canonical working directory;
- requested timeout;
- requested environment keys;
- metadata needed for audit and UI.

Decision output:

- `allow`;
- `ask`;
- `deny`.

The decision must record the rule/reason that produced it.

## Execution core

Use a pinned upstream release/commit of `tumf/mcp-shell-server`.

We rely on upstream for capabilities including:

- argv-based process creation rather than shell-string execution;
- safe pipeline handling;
- contained server-managed redirection;
- minimal child environment;
- timeout and output caps;
- structured audit metadata;
- known dangerous-argument hardening.

ShellWarden adds policy and UX **in front** of this core. We do not fork upstream during v0.1 unless an issue proves that a required capability cannot be implemented safely at the broker boundary.

The broker wraps the pinned upstream `ProcessManager` only to mirror stdout/stderr chunks into structured protocol events while preserving upstream validation, process creation, timeout, and output-cap behavior. The broker protocol emits `requested`, `running`, bounded `output`, and terminal lifecycle events before the final response.

## Permission store

Two stores are required:

### Ephemeral
Memory-only grants such as:

- once;
- current ShellWarden session.

They disappear when the session/app ends.

### Persistent
User-granted rules such as:

- command in exact directory;
- command in directory tree;
- globally allowed command/operation when risk policy permits;
- explicit deny rules.

Persistent rules must be inspectable and revocable from the UI.

`SQLite` is the v0.1 persistent permission store. ShellWarden opens `permissions.sqlite3` under the platform app-data directory with a small schema-versioned table. Session rules never enter SQLite; they live only in memory and disappear when the app/session state is recreated.

Persistent rules store normalized authority metadata only: effect, executable, operation key, environment-variable **names**, optional source constraint, and creation metadata. Raw argv and environment-variable values are deliberately not persisted in the permission table. Directory-scope semantics are added separately in the scoped-approvals slice.

Policy evaluation is deterministic: matching deny rules take precedence over matching allow rules; more specific source/session constraints win within the same effect; unknown requests resolve to `ask`. Every non-ask decision returns the exact matching rule ID and a human-readable reason.

## Activity model

Execution is represented as structured events rather than an undifferentiated terminal scroll.

Typical states:

```text
requested -> awaiting_approval -> queued -> running -> succeeded
                                      |          |
                                      |          +-> failed
                                      |          +-> cancelled
                                      |          +-> timed_out
                                      +-> denied
```

Every execution has a ShellWarden-generated execution ID and normalized metadata. Backend subscribers receive state/output events keyed by that ID, so multiple executions remain distinguishable before the final Activity UI is implemented.

ShellWarden retains only the latest 64 KiB of stdout and 64 KiB of stderr per execution for in-memory activity snapshots. This UI retention cap is separate from the upstream execution output cap. Full unbounded terminal history is intentionally not part of the activity model.

## Process ownership

Every execution launched through ShellWarden must be tracked.

On Windows, ShellWarden currently uses `taskkill /T /F` as the process-tree termination primitive for managed children and the Python execution broker, with direct child termination as fallback. This prevents hard Exit from intentionally leaving broker descendants behind. A future Job Object implementation may replace this primitive without changing the activity model.

## Transport boundary

Secure MCP Tunnel is the first remote transport, not the definition of ShellWarden.

Transport-specific code should stay behind a small adapter so local/stdio or other MCP transports can be supported later without changing the policy model.

## Shutdown contract

Tray **Exit** means:

1. stop accepting new requests;
2. stop/disconnect remote transport;
3. resolve non-terminal activity as cancelled;
4. terminate or explicitly resolve managed running processes;
5. stop MCP/broker components;
6. flush durable audit state;
7. exit the ShellWarden process.

Nothing intentionally remains running as a hidden ShellWarden service.

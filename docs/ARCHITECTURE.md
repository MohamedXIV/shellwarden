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

The v0.1 policy foundation uses a local SQLite database under the ShellWarden application-data directory. Persistent exact-request rules store a SHA-256 fingerprint of the normalized request plus non-secret metadata (source, executable, operation class, canonical directory, environment-key count, effect, timestamps). Raw argv and environment values are intentionally not persisted.

Scoped approvals build on two hashes: the exact-request fingerprint includes source, argv, operation class, canonical working directory, and environment-key names; the operation fingerprint excludes working directory so the same approved operation can be matched against an explicit path scope without persisting raw argv.

Once and Session grants stay memory-only and exact-request bound. Once is consumed only when its matching request is actually allowed. Exact-directory and directory-tree grants persist the operation fingerprint plus the canonical scope root. Always stores the operation fingerprint without a path root and can only be created when the caller supplies an explicit positive risk-policy gate. Deny rules remain exact-request persistent rules and are evaluated before any allow.

Directory decisions compare canonical `Path` values/components, never string prefixes. Because the requested cwd is canonicalized before matching, `..`, symlink, junction, and reparse-point paths resolve to their target first; if that target is outside the stored canonical root, the scoped rule does not match.

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

## Durable audit

ShellWarden stores durable audit history in a separate local SQLite database under the application-data directory. The audit stream receives policy-decision events and terminal execution events from the same backend state machines used by the UI.

Durable audit records intentionally exclude raw argv values, stdout, stderr, environment values, and approval payload copies. Command summaries retain only the executable plus the number of redacted arguments. Records may retain source, canonical cwd, operation class, decision/result status, duration, deterministic risk class, execution ID, matched rule ID, and an explainable decision reason.

Terminal execution rows are deduplicated by ShellWarden execution ID. Policy decisions carry their matched rule ID when one exists. When an approval is linked to an execution, that rule ID is also attached to the execution activity record so the terminal audit row can explain which remembered authority was used.

## Process ownership

Every execution launched through ShellWarden must be tracked.

On Windows, ShellWarden currently uses `taskkill /T /F` as the process-tree termination primitive for managed children and the Python execution broker, with direct child termination as fallback. This prevents hard Exit from intentionally leaving broker descendants behind. A future Job Object implementation may replace this primitive without changing the activity model.

## Approval queue

Requests that evaluate to `ask` can be represented as bounded in-memory pending approvals before transport-specific code is added. Each record carries the normalized request, deterministic risk assessment, optional linked execution ID, request/expiry timestamps, and terminal resolution state.

The approval state owns no hidden authority. Allow resolutions call the same risk-gated policy grant path used elsewhere; Deny records a one-shot policy decision without silently creating a persistent deny rule. Cancelled or expired requests are terminal and cannot later be approved.

Approval events update the desktop UI, tray attention state, and linked execution lifecycle. Durable approval/audit history remains the responsibility of the Audit slice rather than this in-memory queue.

## Transport boundary

Secure MCP Tunnel is the first remote transport, not the definition of ShellWarden.

ShellWarden hosts its own Streamable HTTP MCP endpoint on an ephemeral `127.0.0.1` port. The tunnel points at that loopback endpoint — never directly at `mcp-shell-server` — so every remote `shell_execute` call enters the same Policy -> Approval -> Activity -> execution-core path as local ShellWarden-managed work.

The local MCP endpoint uses the official Rust MCP SDK and remains available while the desktop app is running. Remote access is a separate managed `tunnel-client` child process. Pause kills only that child, immediately removing remote ingress while leaving the local control center and loopback listener alive.

The tunnel runtime key is supplied only through the managed child environment and is not written to ShellWarden SQLite/config files. `tunnel-client` publishes an ephemeral loopback health URL; ShellWarden treats `/readyz` HTTP 200 as Connected and distinguishes Starting/Error states from process liveness.

Transport-specific code stays behind this adapter so local/stdio or other MCP transports can be supported later without changing the policy model.

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

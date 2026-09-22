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

A lightweight local database such as SQLite is appropriate once implementation reaches this stage; the issue implementing persistence owns the final choice.

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

UI blocks subscribe to this model and may show bounded live stdout/stderr.

## Process ownership

Every execution launched through ShellWarden must be tracked.

On Windows, the implementation should use process-group/Job Object semantics where appropriate so app termination does not intentionally leave managed descendant processes orphaned.

## Transport boundary

Secure MCP Tunnel is the first remote transport, not the definition of ShellWarden.

Transport-specific code should stay behind a small adapter so local/stdio or other MCP transports can be supported later without changing the policy model.

## Shutdown contract

Tray **Exit** means:

1. stop accepting new requests;
2. stop/disconnect remote transport;
3. terminate or explicitly resolve managed running processes;
4. stop MCP/broker components;
5. flush durable audit state;
6. exit the ShellWarden process.

Nothing intentionally remains running as a hidden ShellWarden service.

# Security Model

## Security statement

ShellWarden is a **trusted execution gateway**, not an operating-system sandbox.

Allowing a program delegates the authority available to the OS account running ShellWarden. Command allowlists and argument validation reduce exposure but cannot fully constrain what every allowed executable may do internally.

For workflows that process untrusted repository content, web content, issue text, or model-generated instructions, use ShellWarden under a dedicated least-privilege OS account and add stronger OS/container/VM isolation where the threat model requires it.

## v0.1 threat model

We defend primarily against:

- accidental execution outside the intended repository/directory;
- silent authority expansion;
- an agent requesting a command the user did not expect;
- dangerous command families receiving the same trust as read-only operations;
- stale persistent grants that cannot be understood or revoked;
- secret leakage through inherited environment variables or logs;
- path traversal and link/junction escapes in ShellWarden-managed path policy;
- hidden remote access continuing after the user believes the app is off;
- unmanaged child processes continuing after ShellWarden exits.

We do **not** claim to defend, by ourselves, against:

- a fully compromised OS account;
- a malicious allowed executable with access to the same OS resources;
- kernel/admin-level compromise;
- unrestricted network or filesystem behavior performed internally by an allowed program unless externally contained.

## Least privilege deployment

v0.1 should be dogfooded under a dedicated standard Windows user such as `AIWorker`.

That account should have access only to:

- intended workspaces;
- required executables;
- narrowly scoped credentials needed by the selected workflows.

It should not have administrator rights or routine access to the primary user's browser profile, password manager, SSH keys, unrelated personal files, or broad cloud credentials.

## Policy philosophy

Use positive policy:

```text
known safe request       -> allow
matching user grant      -> allow within that grant
unknown request          -> ask
known dangerous request  -> warn strongly / ask / deny
everything else          -> deny
```

Do not rely on an ever-growing blacklist.

## Permission scopes

v0.1 supports:

- **Once** — exact request only.
- **Session** — temporary grant for the active ShellWarden session.
- **Exact directory/repository** — persistent grant scoped to one canonical root.
- **Directory tree** — persistent grant for a chosen canonical subtree.
- **Always** — persistent global grant only when risk policy allows it.
- **Deny** — reject the request/rule scope.

An approval must not silently widen executable, arguments, path, environment, or side-effect class beyond what the selected scope communicates.

## Risk classes

The v0.1 classifier is deterministic and explainable.

Example classes:

- **Read-only / low:** status, inspection, listing.
- **Local write / medium:** dependency install, file generation, commit.
- **External side effect / high:** push, publish, deployment, network mutation.
- **Critical:** force push, destructive recursive deletion, disk/registry operations, privilege elevation, arbitrary general-purpose shells/interpreters.

Not every scope is offered for every risk class. The v0.1 scope matrix is deterministic: Low may use all allow scopes; Medium cannot use Always; High is limited to Once, Session, Exact Request, or Exact Directory; Critical is limited to Once or Session. Deny is always available.

The classifier includes explicit rules for general-purpose shells and eval interpreters, force/destructive Git operations, package publishing, infrastructure/cluster mutation, destructive filesystem commands, privilege elevation, and known read/write Git operations. Unknown operation classes default to Medium rather than Low.

Risk classification is defense in depth and a UX/persistence control. It does not replace `mcp-shell-server` argument validation, OS least privilege, or stronger sandboxing when required.

## General-purpose interpreters

Commands such as the following require special treatment because broad approval can collapse command-level policy:

- `powershell`, `cmd`;
- `bash`, `sh`;
- interpreter/eval forms such as `python -c`, `node -e`;
- equivalent command-wrapper or shell-escape mechanisms.

Do not make them globally trusted by default.

## Paths

Path policy uses canonical resolved paths, not string-prefix checks.

Windows implementation must account for:

- `..` traversal;
- symlinks where available;
- junctions;
- reparse points;
- case/normalization differences.

A path that resolves outside an allowed scope is outside the scope.

Implementation rules:
- canonicalize both the request cwd and the root at grant creation;
- persist the resolved canonical root, not the user-entered alias;
- compare exact roots by path equality and tree roots by path components (`Path::starts_with`), never textual prefix;
- do not re-resolve a stored root during matching, so replacing a previously granted path with a junction/symlink to a new target does not silently move the authority;
- reject a request whose cwd cannot be canonicalized before policy evaluation.

## Environment

Child processes receive a minimal environment.

Additional variables are explicitly allowlisted. Secret-bearing variables should be scoped to the smallest set of executables that require them, and logs must redact secret-like values.

## Audit

Every request should produce structured audit data including:

- timestamp;
- source/session when available;
- executable and redacted argv;
- canonical working directory;
- policy decision;
- matching rule or rejection reason;
- risk class;
- execution result;
- duration;
- bounded output metadata.

The UI must be able to answer: **Why was this allowed?**

## Remote transport boundary

The OpenAI Secure MCP Tunnel is outbound-only transport into a loopback ShellWarden MCP endpoint. It does not receive direct access to the pinned execution core. Remote tool calls therefore cannot bypass ShellWarden policy, deterministic risk classification, human approvals, activity tracking, or durable audit.

The tunnel runtime API key is session-memory configuration and child-process environment only. ShellWarden does not persist it in SQLite, audit rows, logs, or its non-secret status API. The Settings UI never receives the key back from Rust after configuration.
Before receiving that key, the configured tunnel executable must have the basename `tunnel-client` or `tunnel-client.exe`. This prevents accidental credential handoff to an unrelated executable while still allowing the official binary to live anywhere on disk.

Pause terminates the managed `tunnel-client` process rather than merely changing UI state. The MCP listener remains bound to `127.0.0.1`, so pausing removes remote ingress without creating a LAN-accessible endpoint.

## Kill switches

The user always has:

- Pause Remote Access;
- stop/cancel for tracked executions where supported;
- tray Exit.

Exit must end ShellWarden-managed access, not merely hide the window.

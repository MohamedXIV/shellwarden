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

Not every scope is offered for every risk class. Critical requests may be restricted to Once or Session, or denied entirely.

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

## Kill switches

The user always has:

- Pause Remote Access;
- stop/cancel for tracked executions where supported;
- tray Exit.

Exit must end ShellWarden-managed access, not merely hide the window.

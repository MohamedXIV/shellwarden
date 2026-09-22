# Execution Core

## Pin

ShellWarden currently pins:

```text
mcp-shell-server==1.1.12
```

The pin lives in `execution/requirements.txt`. The broker also verifies the detected upstream version at startup and refuses a mismatched version.

Version 1.1.12 is a security release and is the baseline for ShellWarden's first execution integration.

## Boundary

```text
ShellWarden / future MCP request
            |
            v
    normalized request
            |
            v
  ShellWarden broker policy
            |
            v
 mcp-shell-server ShellExecutor
            |
            v
 argv subprocess execution
```

For issue #4 the ShellWarden policy is intentionally tiny: only `git` is admitted by the bootstrap broker. The same executable is also placed in upstream's own `ALLOW_COMMANDS` so both layers agree.

The persisted human permission model arrives in later roadmap issues. This bootstrap rule only proves the boundary without exposing arbitrary execution.

## Preserved upstream protections

ShellWarden delegates actual execution to the pinned upstream `ShellExecutor`, retaining argv process creation, command allowlisting, upstream argument hardening, contained server-managed redirection, minimal child environments, timeout handling, output caps, and upstream audit events.

ShellWarden does not convert command arrays into shell strings.

## Local protocol

The desktop process supervises a small Python JSON-lines broker. stdout is protocol-only; upstream logging and audit output stay on stderr.

The bootstrap protocol supports health plus execute with a string-array command, canonicalized working directory, and optional positive integer timeout. Per-request environment overrides are deliberately not exposed in this slice.

## Windows compatibility

The pinned upstream version contains Windows-specific child-environment handling, but `shell_executor.py` imports Python's Unix-only `pwd` module at import time.

Rather than fork upstream, `execution/broker.py` installs a narrowly scoped compatibility module inside the broker process before importing the unmodified upstream package. The adapter does not replace upstream validation or execution and should be removed once the pinned upstream release no longer needs it.

## Development setup

Install the pinned execution dependency:

```powershell
python -m pip install -r execution/requirements.txt
```

Then run ShellWarden normally:

```powershell
npm run tauri:dev
```

If Python or the pinned dependency is unavailable, ShellWarden stays open and reports the execution core as unavailable. It never falls back to a less constrained executor.

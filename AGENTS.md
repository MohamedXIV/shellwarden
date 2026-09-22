# AGENTS.md

This repository is execution-first. Prefer finishing the smallest useful slice over expanding the design surface.

## Product invariants

These are not optional implementation details:

1. ShellWarden is a **visible desktop control center**, not a hidden background service.
2. Closing the main window may minimize to tray. **Exit must stop ShellWarden completely**, including the MCP endpoint, tunnel client, and managed child processes.
3. The user must always have an obvious **Pause Remote Access** control.
4. Unknown authority is denied or requires approval. Do not silently widen permissions.
5. Persistent permission grants must be inspectable, revocable, and resettable.
6. Directory scopes must use canonical paths and defend against traversal/symlink/junction/reparse-point escapes where applicable.
7. Generic shells/interpreters and destructive or external-side-effect operations require stronger treatment than ordinary read-only commands.
8. Do not describe ShellWarden, command allowlisting, or `mcp-shell-server` as an OS sandbox.
9. Keep `mcp-shell-server` pinned and upstream-friendly. Do not fork it unless a concrete required capability cannot be implemented cleanly in the ShellWarden broker.
10. Windows is the v0.1 product target. Do not expand v0.1 to macOS/Linux unless an issue explicitly changes scope.

## Architecture direction

- Tauri 2 desktop application.
- React + TypeScript UI.
- ShellWarden policy/permission broker in front of the execution core.
- Pinned upstream `mcp-shell-server` for argv-based execution and its security hardening.
- Secure MCP Tunnel as the first remote transport used by our dogfood workflow.
- Transport-specific logic must stay behind a small adapter boundary.

## Security changes

Any change that affects command validation, permission scopes, path resolution, environment inheritance, remote connectivity, or child-process lifecycle requires focused tests.

Prefer positive policy over increasingly large denylists.

Never solve an execution problem by broadly enabling `powershell`, `cmd`, `bash`, `sh`, `python -c`, `node -e`, or equivalent interpreters without an explicit issue and a user-visible risk model.

## Versioning and changelog

- `VERSION` is the repository-level version source until release automation synchronizes package/Tauri manifests.
- Follow Semantic Versioning.
- Pre-1.0 releases use alpha/beta/rc prereleases when appropriate.
- Every merged user-visible behavior, security change, breaking change, or meaningful developer-facing capability must update `CHANGELOG.md` under `[Unreleased]` in the same change.
- Pure refactors/tests/internal cleanup with no meaningful behavior impact do not need a changelog entry.
- Use Conventional Commit style for commit/PR titles where practical: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `build:`, `ci:`, `chore:`, `security:`.
- Do not bump a released version casually. Version bumps happen as part of a release change following `docs/RELEASING.md`.

## Working style

- Read the active issue plus only directly relevant docs/code.
- Keep diffs narrow.
- Add tests with behavior.
- Do not add speculative abstractions for post-v0.1 ideas.
- Prefer a runnable vertical slice over a framework waiting for future consumers.

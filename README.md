# ShellWarden

**Your shell. Your rules. Agents ask first.**

ShellWarden is a local-first desktop control center for safely exposing shell access to AI agents over MCP. It adds scoped human approvals, real-time execution visibility, audit history, and tray-controlled access in front of a hardened shell execution core.

> [!IMPORTANT]
> ShellWarden is a trusted execution gateway, **not an OS sandbox**. An allowed executable still runs with the authority of the OS account running ShellWarden. v0.1 is designed to be used under a dedicated least-privilege Windows account.

## Current status

ShellWarden is in its desktop-foundation phase. The current application is intentionally **local-only**: it establishes the Windows Tauri shell, navigation, health/status surface, build verification, and repository version plumbing. MCP execution, permissions, tray lifecycle, and remote connectivity are added in later roadmap slices.

Current development version: **0.0.0-dev**

## Development

### Prerequisites

- Windows 10/11 for the target desktop workflow.
- Node.js 22.13 or newer.
- Rust stable toolchain with Cargo.
- Tauri's Windows prerequisites, including Microsoft C++ Build Tools and WebView2 where not already present.

### Install

```powershell
npm install
```

### Run the desktop app

```powershell
npm run tauri:dev
```

### Verify

```powershell
npm run check
npm run build:web
cargo check --manifest-path src-tauri/Cargo.toml
```

The pull-request CI runs frontend checks on Linux plus a real Tauri release build and short launch smoke on Windows.

## v0.1 goal

Ship a Windows-first application that we can dogfood daily:

1. Open ShellWarden.
2. Remote MCP access becomes visibly available.
3. An agent requests a command in a specific working directory.
4. Existing policy either allows it, denies it, or asks the user.
5. The user can approve once, for the current session, for a directory scope, or persistently where safe.
6. Execution is visible live and recorded in an audit history.
7. The tray provides a clear pause switch.
8. **Exit** stops the tunnel, MCP endpoint, managed executions, and ShellWarden itself. No hidden always-on service remains.

## Product shape

- **Desktop:** Tauri 2 + React + TypeScript, Windows first.
- **Execution core:** pinned [mcp-shell-server](https://github.com/tumf/mcp-shell-server) upstream dependency.
- **Remote transport:** OpenAI Secure MCP Tunnel for our initial ChatGPT workflow; ShellWarden itself remains transport-agnostic.
- **Security model:** positive allow/ask/deny policy, scoped grants, minimal child environments, upstream argument hardening, explicit warnings, and OS-level least privilege.
- **Lifecycle:** window or tray only. Closing the window may minimize to tray; choosing Exit stops everything.

## Documentation

- [Product](docs/PRODUCT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [UX](docs/UX.md)
- [Roadmap](docs/ROADMAP.md)
- [Versioning and releases](docs/RELEASING.md)
- [Changelog](CHANGELOG.md)

## License

MIT. See [LICENSE](LICENSE).

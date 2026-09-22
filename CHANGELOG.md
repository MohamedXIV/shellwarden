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

### Security
- Established the core rule that ShellWarden is a trusted execution gateway, not an OS sandbox.
- Established Windows-first least-privilege and explicit lifecycle requirements for v0.1.
- Started the desktop application with only Tauri core permissions and no shell, remote transport, or execution capability enabled.


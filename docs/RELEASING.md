# Versioning, Changelog, and Releases

ShellWarden treats versioning and release history as product infrastructure from day one.

## Version scheme

Use Semantic Versioning.

Before 1.0, minor versions represent meaningful product milestones and may still contain breaking changes when clearly documented.

Examples:

- `0.1.0-alpha.1` — first runnable dogfood build;
- `0.1.0-beta.1` — feature-complete v0.1 candidate;
- `0.1.0` — accepted v0.1;
- `0.1.1` — compatible bug/security fixes;
- `0.2.0` — next feature milestone or documented pre-1.0 breaking evolution.

## Canonical version

`VERSION` is the repository source of truth. Development currently uses:

```text
0.0.0-dev
```

The following files must always match it:

- `package.json`;
- `src-tauri/Cargo.toml`;
- `src-tauri/tauri.conf.json`.

Run:

```bash
npm run version:check
```

The same check runs inside `npm run check`, so manifest drift fails normal CI verification.

The UI version is injected from `VERSION` by Vite; do not maintain a second frontend version literal.

## Changelog

Maintain `CHANGELOG.md` using Keep a Changelog sections.

All notable merged changes go under `[Unreleased]` immediately. Typical headings are Added, Changed, Deprecated, Removed, Fixed, and Security.

Do not dump raw commit messages into the changelog. Entries must describe meaningful user, developer, or security effects. Pure internal refactoring, formatting, and test maintenance with no behavior effect do not require entries.

Release preparation never writes release-note prose. It only validates and mechanically promotes the curated `[Unreleased]` text that a human already wrote.

## Prepare a release

First curate `CHANGELOG.md` under `[Unreleased]`. It must contain at least one meaningful bullet.

Then run exactly one preparation command with the chosen SemVer and release date:

```bash
npm run release:prepare -- 0.1.0-alpha.1 --date 2026-09-26
```

The command:

1. verifies the repository starts with no version drift;
2. validates the target as SemVer and requires an explicit `YYYY-MM-DD` date;
3. refuses an empty `[Unreleased]` section;
4. moves the existing curated `[Unreleased]` content verbatim under `## [VERSION] - DATE`;
5. leaves a fresh empty `[Unreleased]` section;
6. updates `VERSION`, `package.json`, `src-tauri/Cargo.toml`, and `src-tauri/tauri.conf.json`;
7. verifies the resulting files are still consistent.

Review the resulting diff, run verification, and commit it as `chore(release): vX.Y.Z`. Tag/build/publish only from that accepted release commit.

The same command is used for alpha, beta, stable, patch, and later pre-1.0 milestone releases; only the SemVer argument changes. For example:

```bash
npm run release:prepare -- 0.1.0-alpha.1 --date 2026-09-26
npm run release:prepare -- 0.1.0-beta.1 --date 2026-10-10
npm run release:prepare -- 0.1.0 --date 2026-10-24
```

Dates above illustrate the required explicit format; use the actual intended release date.

## First dogfood release

Issue #14 owns the actual `0.1.0-alpha.1` release decision and artifact/tag. Issue #13 provides the tooling but does not bump the development branch merely to demonstrate it.

A safe test fixture proves that `0.1.0-alpha.1` preparation synchronizes every manifest and promotes only prewritten changelog text.

## Commit and PR naming

Use Conventional Commit style where practical:

- `feat:`
- `fix:`
- `docs:`
- `refactor:`
- `test:`
- `build:`
- `ci:`
- `chore:`
- `security:`

This keeps history searchable, but the curated changelog remains authoritative.

## Security releases

Security fixes receive explicit `Security` changelog entries at the appropriate disclosure level and must not be hidden behind an unrelated release title.

## Rule of thumb

If a user would care that the behavior changed, or if the security/authority model changed, update `[Unreleased]` in the same PR.

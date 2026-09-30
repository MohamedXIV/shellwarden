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

## Development version

The repository starts at:

```text
0.0.0-dev
```

This is intentionally not a published release.

The `VERSION` file is the repository-level source of truth until release automation is implemented. The release tooling issue will synchronize this value into Tauri/package/Cargo manifests rather than allowing versions to drift.

## Changelog

Maintain `CHANGELOG.md` using Keep a Changelog sections.

All notable merged changes go under `[Unreleased]` immediately.

Typical headings:

- Added
- Changed
- Deprecated
- Removed
- Fixed
- Security

Do not dump raw commit messages into the changelog. Entries should explain the meaningful user/developer/security effect.

Pure internal refactoring, formatting, and test maintenance with no meaningful behavior effect do not require entries.

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

This keeps history searchable and will support future release automation, but the curated changelog remains authoritative.

## Release procedure

Until automated:

1. Confirm the release acceptance criteria and tests.
2. Choose the SemVer version.
3. Move relevant `[Unreleased]` entries into a new dated release heading.
4. Leave a fresh empty `[Unreleased]` section.
5. Update `VERSION`.
6. Synchronize all application/package manifests once they exist.
7. Commit as `chore(release): vX.Y.Z`.
8. Create annotated/tagged release `vX.Y.Z`.
9. Build/publish artifacts from that exact tag/commit.

The release automation issue should make these steps reproducible and verify version consistency.

## Security releases

Security fixes receive explicit `Security` changelog entries at the appropriate disclosure level and must not be hidden behind an unrelated release title.

## Rule of thumb

If a user would care that the behavior changed, or if the security/authority model changed, update `[Unreleased]` in the same PR.

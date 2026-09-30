import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { checkReleaseState, prepareRelease } from "./release.mjs";

function fixture(t, version = "0.0.0-dev") {
  const root = mkdtempSync(join(tmpdir(), "shellwarden-release-"));
  mkdirSync(join(root, "src-tauri"), { recursive: true });

  writeFileSync(join(root, "VERSION"), `${version}\n`);
  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({ name: "shellwarden", version }, null, 2) + "\n",
  );
  writeFileSync(
    join(root, "src-tauri", "Cargo.toml"),
    `[package]\nname = "shellwarden"\nversion = "${version}"\n`,
  );
  writeFileSync(
    join(root, "src-tauri", "tauri.conf.json"),
    JSON.stringify({ productName: "ShellWarden", version }, null, 2) + "\n",
  );
  writeFileSync(
    join(root, "CHANGELOG.md"),
    "# Changelog\n\n## [Unreleased]\n\n### Added\n- Curated operator-facing release note.\n",
  );

  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test("version drift fails verification", (t) => {
  const root = fixture(t);
  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({ name: "shellwarden", version: "9.9.9" }, null, 2) + "\n",
  );

  assert.throws(
    () => checkReleaseState(root),
    /Version drift from VERSION .*package\.json=9\.9\.9/,
  );
});

test("release preparation updates manifests and promotes curated changelog verbatim", (t) => {
  const root = fixture(t);

  prepareRelease(root, "0.1.0-alpha.1", "2026-09-26");

  assert.equal(checkReleaseState(root), "0.1.0-alpha.1");
  assert.equal(readFileSync(join(root, "VERSION"), "utf8"), "0.1.0-alpha.1\n");
  assert.equal(JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version, "0.1.0-alpha.1");
  assert.equal(
    JSON.parse(readFileSync(join(root, "src-tauri", "tauri.conf.json"), "utf8")).version,
    "0.1.0-alpha.1",
  );
  assert.match(
    readFileSync(join(root, "src-tauri", "Cargo.toml"), "utf8"),
    /^version = "0\.1\.0-alpha\.1"$/m,
  );

  const changelog = readFileSync(join(root, "CHANGELOG.md"), "utf8");
  assert.match(changelog, /## \[Unreleased\]\n\n## \[0\.1\.0-alpha\.1\] - 2026-09-26/);
  assert.match(changelog, /- Curated operator-facing release note\./);
});

test("release preparation refuses an empty Unreleased section", (t) => {
  const root = fixture(t);
  writeFileSync(join(root, "CHANGELOG.md"), "# Changelog\n\n## [Unreleased]\n");

  assert.throws(
    () => prepareRelease(root, "0.1.0-alpha.1", "2026-09-26"),
    /must contain at least one curated bullet/,
  );
});

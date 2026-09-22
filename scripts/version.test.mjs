import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function readCargoVersion() {
  const cargo = readFileSync("src-tauri/Cargo.toml", "utf8");
  const match = cargo.match(/^version\s*=\s*"([^"]+)"/m);
  assert.ok(match, "Cargo.toml must declare a package version");
  return match[1];
}

test("all application manifests match VERSION", () => {
  const canonical = readFileSync("VERSION", "utf8").trim();
  const packageJson = readJson("package.json");
  const tauriConfig = readJson("src-tauri/tauri.conf.json");

  assert.equal(packageJson.version, canonical, "package.json version drifted from VERSION");
  assert.equal(tauriConfig.version, canonical, "tauri.conf.json version drifted from VERSION");
  assert.equal(readCargoVersion(), canonical, "Cargo.toml version drifted from VERSION");
});

test("foundation remains on the development version", () => {
  assert.equal(readFileSync("VERSION", "utf8").trim(), "0.0.0-dev");
});

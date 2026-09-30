import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const cargo = readFileSync(new URL("../src-tauri/Cargo.toml", import.meta.url), "utf8");
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

test("Tauri Rust and JavaScript packages stay on the same minor release", () => {
  const apiVersion = pkg.dependencies["@tauri-apps/api"];
  const apiMinor = apiVersion.match(/^(\d+\.\d+)\./)?.[1];
  const rustVersion = cargo.match(/tauri = \{ version = "=(\d+\.\d+\.\d+)"/)?.[1];
  const rustMinor = rustVersion?.match(/^(\d+\.\d+)\./)?.[1];

  assert.equal(apiMinor, "2.11");
  assert.equal(rustMinor, apiMinor);
});

test("Tauri 2.11 companion crates are pinned to the proven release set", () => {
  for (const dependency of [
    'tauri-build = { version = "=2.6.3"',
    'tauri = { version = "=2.11.6"',
    'tauri-runtime = "=2.11.3"',
    'tauri-runtime-wry = { version = "=2.11.4"',
    'tauri-macros = "=2.6.3"',
    'tauri-utils = "=2.9.3"',
  ]) {
    assert.ok(cargo.includes(dependency), "missing deterministic Tauri pin: " + dependency);
  }
});

test("notification dependencies remain present while Tauri is pinned", () => {
  assert.ok(cargo.includes('tauri-plugin-notification = "~2.2.0"'));
  assert.ok(cargo.includes('tauri-winrt-notification = "=0.7.3"'));
});

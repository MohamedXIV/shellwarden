import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const releaseConfig = JSON.parse(
  readFileSync(new URL("../src-tauri/tauri.release.conf.json", import.meta.url), "utf8"),
);
const workflow = readFileSync(
  new URL("../.github/workflows/package-windows.yml", import.meta.url),
  "utf8",
);
const runtimePrep = readFileSync(
  new URL("./prepare-windows-runtime.ps1", import.meta.url),
  "utf8",
);
const executionCore = readFileSync(
  new URL("../src-tauri/src/execution_core.rs", import.meta.url),
  "utf8",
);
const lib = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
const remote = readFileSync(
  new URL("../src-tauri/src/remote_access.rs", import.meta.url),
  "utf8",
);
const app = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");

test("release config produces a per-user NSIS installer with packaged runtimes", () => {
  assert.equal(releaseConfig.bundle.active, true);
  assert.deepEqual(releaseConfig.bundle.targets, ["nsis"]);
  assert.equal(releaseConfig.bundle.windows.nsis.installMode, "perUser");
  assert.equal(
    releaseConfig.bundle.resources["../execution/dist/shellwarden-broker.exe"],
    "execution/shellwarden-broker.exe",
  );
  assert.equal(
    releaseConfig.bundle.resources["../packaging/runtime/tunnel-client.exe"],
    "runtime/tunnel-client.exe",
  );
});

test("packaging pins and verifies the proven tunnel runtime", () => {
  assert.match(runtimePrep, /tunnelVersion = "0\.0\.14"/);
  assert.ok(
    runtimePrep.includes(
      "c276db68609ac9771b07f078eac3dc23f8943a42f9dedd4c50a4001cb74df149",
    ),
  );
  assert.match(runtimePrep, /Get-FileHash -Algorithm SHA256/);
  assert.match(runtimePrep, /tunnel-client-LICENSES\.txt/);
  assert.match(runtimePrep, /tunnel-client\.spdx\.json/);
});

test("installed builds prefer packaged broker and tunnel runtimes without removing dev fallbacks", () => {
  assert.match(lib, /execution\/shellwarden-broker\.exe/);
  assert.match(executionCore, /packaged_broker/);
  assert.match(executionCore, /SHELLWARDEN_PYTHON/);
  assert.match(remote, /runtime\/tunnel-client\.exe/);
  assert.match(remote, /unwrap_or_else\(\|\| "tunnel-client"\.to_string\(\)\)/);
  assert.ok(app.includes('useState("")'));
  assert.match(app, /Bundled runtime \(recommended\)/);
});

test("package workflow exercises installer lifecycle rather than only compiling", () => {
  assert.match(workflow, /prepare-windows-runtime\.ps1/);
  assert.match(workflow, /tauri:build -- --config src-tauri\/tauri\.release\.conf\.json/);
  assert.match(workflow, /Install, launch, and uninstall smoke/);
  assert.match(workflow, /upload-artifact@v4/);
});

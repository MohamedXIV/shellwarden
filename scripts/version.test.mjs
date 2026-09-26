import assert from "node:assert/strict";
import test from "node:test";
import { checkReleaseState } from "./release.mjs";

test("all application manifests match canonical VERSION", () => {
  const canonical = checkReleaseState(".");
  assert.match(
    canonical,
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/,
  );
});

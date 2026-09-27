import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const css = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");

const requiredTokens = [
  "--type-micro: 10px",
  "--type-meta: 11px",
  "--type-label: 12px",
  "--type-body: 13px",
  "--type-body-strong: 14px",
  "--type-heading: 16px",
  "--type-display: clamp(30px, 4vw, 44px)",
  "--text-secondary:",
  "--text-muted:",
  "--text-dim:",
];

test("control-center typography exposes the shared readable scale", () => {
  for (const token of requiredTokens) {
    assert.ok(css.includes(token), "missing typography token: " + token);
  }
});

test("component font sizes use shared typography tokens", () => {
  const rawFontSizes = [...css.matchAll(/font-size:\s*(?:\d+(?:\.\d+)?px|clamp\([^;]+\));/g)].map(
    (match) => match[0],
  );
  assert.deepEqual(rawFontSizes, []);
});

test("the smallest typography token remains at least ten pixels", () => {
  const match = css.match(/--type-micro:\s*(\d+)px/);
  assert.ok(match, "missing --type-micro token");
  assert.ok(Number(match[1]) >= 10, "--type-micro must remain readable at normal Windows scaling");
});

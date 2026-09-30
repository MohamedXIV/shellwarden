import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const app = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
const css = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");

test("approval inbox exposes every canonical approval state plus deterministic ordering", () => {
  for (const value of ["all", "pending", "allowed", "denied", "cancelled", "expired"]) {
    assert.ok(app.includes(`value: "${value}"`), `missing approval status filter: ${value}`);
  }
  assert.match(app, /type ApprovalSortOrder = "newest" \| "oldest"/);
  assert.match(app, /left\.requestedAtMs - right\.requestedAtMs/);
  assert.match(app, /localeCompare\(left\.id\)|left\.id\.localeCompare\(right\.id\)/);
});

test("approval search stays client-side over operator-visible metadata", () => {
  for (const field of [
    "approval.source",
    "commandText(approval.command)",
    "approval.directory",
    "approval.sessionId",
    "approval.operationClass",
    "approval.status",
    "approval.risk.class",
    "approval.risk.reason",
  ]) {
    assert.ok(app.includes(field), `search metadata missing: ${field}`);
  }
  assert.ok(!app.includes('invoke<ApprovalView[]>("approval_search"'));
});

test("resolved approval rendering is page-bounded", () => {
  assert.ok(app.includes("const APPROVAL_HISTORY_PAGE_SIZE = 25"));
  assert.ok(app.includes("history.slice("));
  assert.ok(app.includes("safeHistoryPage * APPROVAL_HISTORY_PAGE_SIZE"));
  assert.ok(app.includes("approval-history-row"));
});

test("only explicit notification focus can move the approvals viewport", () => {
  const scrollCalls = app.match(/scrollIntoView\(/g) ?? [];
  assert.equal(scrollCalls.length, 1);
  assert.ok(app.includes('if (!focusedApprovalId || section !== "Approvals") return;'));
  assert.ok(app.includes("target.focus({ preventScroll: true })"));
  assert.ok(app.includes('target.scrollIntoView({ behavior: "smooth", block: "center" })'));
  assert.ok(app.includes("setFocusedApprovalId(null)"));
  assert.ok(app.includes("focusedApprovalId={focusedApprovalId}"));
});

test("approval inbox remains keyboard and narrow-window usable", () => {
  assert.ok(app.includes('aria-label="Approval inbox controls"'));
  assert.ok(app.includes('aria-pressed={statusFilter === option.value}'));
  assert.ok(css.includes(".approval-card:focus-visible"));
  assert.ok(css.includes(".approval-history-row:focus-visible"));
  assert.match(css, /@media \(max-width: 980px\)[\s\S]*\.approval-inbox-toolbar/);
  assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.approval-history-row/);
});

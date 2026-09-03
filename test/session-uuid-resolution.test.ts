/// <reference types="node" />
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { resolveSessionIdForRun, resolveSessionIdFromKey } from "../src/injector.js";

/**
 * Build a temp workspaceDir containing an agent sqlite store with a
 * session_nodes table. Mirrors the OpenClaw 2.0 schema:
 *   session_nodes(session_key TEXT PK, current_session_id TEXT, ...)
 */
function buildTempStore(opts: { withTable?: boolean; agentId?: string; rows?: Array<{ session_key: string; current_session_id: string }> } = {}): string {
  const workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), "ocm-uuid-"));
  const agentId = opts.agentId || "main";
  const dbDir = path.join(workspaceDir, "agents", agentId, "agent");
  fs.mkdirSync(dbDir, { recursive: true });
  const dbPath = path.join(dbDir, "openclaw-agent.sqlite");
  // node:sqlite is required for the resolver; if unavailable the tests still
  // exercise the fallback path.
  let DatabaseSync: any;
  try {
    ({ DatabaseSync } = createRequire(import.meta.url)("node:sqlite"));
  } catch {
    // No sqlite in this runtime — leave the file absent so the resolver falls
    // back. Tests below assert the fallback in that case.
    return workspaceDir;
  }
  const db = new DatabaseSync(dbPath);
  try {
    if (opts.withTable === false) {
      // Create an empty db (no session_nodes table) — Kore-era simulation.
      db.exec("CREATE TABLE IF NOT EXISTS schema_meta (k TEXT PRIMARY KEY, v TEXT)");
    } else {
      db.exec(
        "CREATE TABLE IF NOT EXISTS session_nodes (" +
          "session_key TEXT NOT NULL PRIMARY KEY," +
          "current_session_id TEXT NOT NULL," +
          "entry_json TEXT NOT NULL," +
          "entry_valid INTEGER NOT NULL DEFAULT 0," +
          "updated_at INTEGER NOT NULL" +
        ")",
      );
      for (const r of opts.rows || []) {
        db.prepare(
          "INSERT INTO session_nodes (session_key, current_session_id, entry_json, entry_valid, updated_at) VALUES (?, ?, '{}', 1, 0)",
        ).run(r.session_key, r.current_session_id);
      }
    }
  } finally {
    db.close();
  }
  return workspaceDir;
}

describe("resolveSessionIdForRun (2.0 sqlite session_nodes)", () => {
  const tmpDirs: string[] = [];
  after(() => {
    for (const d of tmpDirs) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  });

  it("resolves the real uuid when a session_nodes row exists", () => {
    const uuid = "a7956aa2-5f4e-46c6-96d0-712473d94f7d";
    const ws = buildTempStore({ rows: [{ session_key: "agent:main:main", current_session_id: uuid }] });
    tmpDirs.push(ws);
    const resolved = resolveSessionIdForRun("agent:main:main", "main", ws);
    assert.equal(resolved, uuid);
  });

  it("falls back to key-derived when the row is missing", () => {
    const ws = buildTempStore({ rows: [{ session_key: "agent:main:other", current_session_id: "11111111-2222-3333-4444-555555555555" }] });
    tmpDirs.push(ws);
    const resolved = resolveSessionIdForRun("agent:main:main", "main", ws);
    assert.equal(resolved, resolveSessionIdFromKey("agent:main:main"));
    assert.equal(resolved, "main");
  });

  it("falls back to key-derived when session_nodes table is absent (Kore-era)", () => {
    const ws = buildTempStore({ withTable: false });
    tmpDirs.push(ws);
    const resolved = resolveSessionIdForRun("agent:main:main", "main", ws);
    assert.equal(resolved, "main");
  });

  it("falls back to key-derived when the sqlite file does not exist", () => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), "ocm-nostore-"));
    tmpDirs.push(ws);
    const resolved = resolveSessionIdForRun("agent:main:main", "main", ws);
    assert.equal(resolved, "main");
  });

  it("resolves for a non-default agent id / session key", () => {
    const uuid = "deadbeef-0000-1111-2222-333333333333";
    const ws = buildTempStore({ agentId: "emts", rows: [{ session_key: "agent:emts:review", current_session_id: uuid }] });
    tmpDirs.push(ws);
    const resolved = resolveSessionIdForRun("agent:emts:review", "emts", ws);
    assert.equal(resolved, uuid);
  });
});

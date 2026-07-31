/**
 * Durable outbox for mesh delivery and injection failures.
 *
 * Failed events are appended as JSONL to a rotated log under the mesh workspace
 * so an operator or a sidecar can replay, inspect, or clean them up later.
 */

import fs from "node:fs";
import path from "node:path";
import { createDebugLogger } from "./logging.js";

const debugLog = createDebugLogger();

export const DEFAULT_OUTBOX_DIR = "/home/emil/.openclaw/workspaces/kore/mesh/outbox";

export interface OutboxEntry {
  direction: "send" | "receive";
  ts: number;
  peer?: string;
  text?: string;
  envelope?: Record<string, any>;
  error?: string;
  status?: number;
  attempts?: number;
}

function todayFileName(): string {
  const d = new Date();
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}.jsonl`;
}

export function resolveOutboxDir(pluginCfg: { outboxDir?: string }): string {
  return pluginCfg.outboxDir || process.env.OPENCLAW_MESH_OUTBOX_DIR || DEFAULT_OUTBOX_DIR;
}

export function appendToOutbox(entry: OutboxEntry, outboxDir = DEFAULT_OUTBOX_DIR): void {
  try {
    fs.mkdirSync(outboxDir, { recursive: true });
    const file = path.join(outboxDir, todayFileName());
    const line = JSON.stringify({ ...entry, ts: entry.ts || Date.now() }) + "\n";
    fs.appendFileSync(file, line);
    debugLog(`outbox: wrote ${entry.direction} failure for ${entry.peer || "unknown"}`);
  } catch (e: any) {
    debugLog(`outbox: failed to write: ${e.message || e}`);
  }
}

export function listOutbox(outboxDir = DEFAULT_OUTBOX_DIR, max = 100): OutboxEntry[] {
  if (!fs.existsSync(outboxDir)) return [];
  const entries: OutboxEntry[] = [];
  const files = fs
    .readdirSync(outboxDir)
    .filter((f) => f.endsWith(".jsonl"))
    .sort()
    .reverse();
  for (const file of files) {
    const data = fs.readFileSync(path.join(outboxDir, file), "utf-8");
    for (const line of data.split("\n")) {
      if (!line.trim()) continue;
      try {
        entries.push(JSON.parse(line));
        if (entries.length >= max) break;
      } catch {
        // ignore corrupt lines
      }
    }
    if (entries.length >= max) break;
  }
  return entries.sort((a, b) => (b.ts || 0) - (a.ts || 0)).slice(0, max);
}

export function cleanOutbox(olderThanMs: number, outboxDir = DEFAULT_OUTBOX_DIR): number {
  if (!fs.existsSync(outboxDir)) return 0;
  const now = Date.now();
  let removed = 0;
  for (const file of fs.readdirSync(outboxDir)) {
    if (!file.endsWith(".jsonl")) continue;
    const p = path.join(outboxDir, file);
    try {
      const stat = fs.statSync(p);
      if (now - stat.mtimeMs > olderThanMs) {
        fs.unlinkSync(p);
        removed++;
      }
    } catch (e: any) {
      debugLog(`outbox: failed to clean ${file}: ${e.message || e}`);
    }
  }
  return removed;
}

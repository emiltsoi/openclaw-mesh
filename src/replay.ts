/**
 * Inbound mesh message replay window.
 *
 * Tracks recently seen message ids with a TTL and a size cap, matching the
 * behavior of hermes-mesh's `_seen_message_ids` replay protection.
 */

import { createDebugLogger } from "./logging.js";

const debugLog = createDebugLogger();

export interface ReplayWindow {
  has(id: string): boolean;
  add(id: string): void;
}

export interface ReplayWindowOptions {
  ttlMs?: number;
  maxSize?: number;
}

export function createReplayWindow(opts?: ReplayWindowOptions): ReplayWindow {
  const ttlMs = opts?.ttlMs ?? 300_000;
  const maxSize = opts?.maxSize ?? 10_000;
  const seen = new Map<string, number>();

  function evict(now: number) {
    for (const [id, ts] of seen) {
      if (now - ts > ttlMs) {
        seen.delete(id);
      }
    }
    while (seen.size > maxSize) {
      let oldestId = "";
      let oldestTs = Infinity;
      for (const [id, ts] of seen) {
        if (ts < oldestTs) {
          oldestTs = ts;
          oldestId = id;
        }
      }
      if (oldestId) seen.delete(oldestId);
      else break;
    }
  }

  return {
    has(id: string): boolean {
      if (!id) return false;
      const now = Date.now();
      evict(now);
      return seen.has(id);
    },
    add(id: string) {
      if (!id) return;
      const now = Date.now();
      evict(now);
      seen.set(id, now);
      debugLog(`replay: recorded id ${id}`);
    },
  };
}

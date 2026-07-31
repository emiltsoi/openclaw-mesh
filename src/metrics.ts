/**
 * Lightweight mesh metrics for the OpenClaw mesh bridge.
 *
 * Counters are in-memory only; they are mirrored to a JSONL file when
 * `flush()` is called so operators can inspect them without querying the
 * running gateway.
 */

import fs from "node:fs";
import path from "node:path";
import { createDebugLogger } from "./logging.js";

const debugLog = createDebugLogger();

export type MetricDirection = "send" | "receive" | "mirror" | "outbox";
export type MetricResult = "total" | "success" | "failure" | "duplicate" | "unauthorized" | "rate_limited";

type CounterMap = Record<string, number>;

const counters: CounterMap = {};

function key(direction: MetricDirection, result: MetricResult): string {
  return `${direction}:${result}`;
}

export function recordMetric(direction: MetricDirection, result: MetricResult): void {
  const k = key(direction, result);
  counters[k] = (counters[k] || 0) + 1;
}

export function getMetric(direction: MetricDirection, result: MetricResult): number {
  return counters[key(direction, result)] || 0;
}

export function getAllMetrics(): Record<string, number> {
  return { ...counters };
}

export function resetMetrics(): void {
  for (const k of Object.keys(counters)) {
    delete counters[k];
  }
}

export function flushMetrics(filePath = "/tmp/openclaw-mesh/metrics.jsonl"): void {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const line = JSON.stringify({ ts: Date.now(), metrics: getAllMetrics() }) + "\n";
    fs.appendFileSync(filePath, line);
  } catch (e: any) {
    debugLog(`metrics flush failed: ${e.message || e}`);
  }
}

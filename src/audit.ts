/**
 * Structured audit logging for openclaw-mesh.
 *
 * Writes one JSON line per security-relevant event (registration, send,
 * deregister, inbound webhook) to an append-only file.  Paths can be
 * configured via `auditLogPath` in plugin config or `OPENCLAW_MESH_AUDIT_LOG`.
 */
import fs from "node:fs";
import path from "node:path";
import type { MeshBridgePluginConfig } from "./types.js";

export interface AuditEvent {
  ts: string;
  event: "mesh_register" | "mesh_send" | "mesh_deregister" | "webhook_receive" | "webhook_verify";
  agent?: string;
  target?: string;
  success: boolean;
  source?: string;
  error?: string;
  [key: string]: any;
}

function expandHome(input: string): string {
  if (input.startsWith("~")) {
    return input.replace(/^~(?=$|[\\/])/, process.env.HOME || "/tmp");
  }
  return input;
}

export function resolveAuditLogPath(extra?: MeshBridgePluginConfig): string {
  const configured = extra?.auditLogPath || extra?.audit_log_path || "";
  if (configured) return path.resolve(expandHome(String(configured)));
  const env = process.env.OPENCLAW_MESH_AUDIT_LOG || process.env.OPENCLAW_STATE_DIR;
  if (env) {
    const base = env === process.env.OPENCLAW_MESH_AUDIT_LOG
      ? env
      : path.join(env, "openclaw-mesh-audit.jsonl");
    return path.resolve(expandHome(base));
  }
  return "/tmp/openclaw-mesh/audit.jsonl";
}

export function logAudit(event: AuditEvent, extra?: MeshBridgePluginConfig): void {
  const logPath = resolveAuditLogPath(extra);
  try {
    const dir = path.dirname(logPath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch {
    // ignore
  }
  const line = JSON.stringify(event) + "\n";
  try {
    fs.appendFileSync(logPath, line, { mode: 0o600 });
  } catch {
    // Best-effort: if audit log is not writable, do not block the operation.
  }
}

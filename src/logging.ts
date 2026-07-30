/**
 * Shared file-backed debug logger used by the OpenClaw mesh bridge plugin.
 */
import fs from "node:fs";

export const DEFAULT_DEBUG_LOG = "/tmp/openclaw-mesh-debug.log";

export type Logger = (msg: string) => void;

let _debugEnabled: boolean | undefined = undefined;

function isDebugEnabled(): boolean {
  if (_debugEnabled !== undefined) return _debugEnabled;
  const env = process.env.OPENCLAW_MESH_DEBUG || process.env.A2A_BRIDGE_DEBUG || "";
  return env === "1" || env.toLowerCase() === "true";
}

/**
 * Enable or disable debug logging globally. Call from the plugin register
 * function with the plugin config value, after which all existing loggers
 * respect the flag.
 */
export function setDebugEnabled(enabled: boolean): void {
  _debugEnabled = enabled;
}

function redactSecrets(msg: string): string {
  // Redact Telegram bot tokens and long hex-looking HMAC secrets that may
  // appear in error messages or URLs.
  let out = msg;
  out = out.replace(/bot\d+:[A-Za-z0-9_-]+/g, "***telegram-bot-token***");
  out = out.replace(/[a-f0-9]{64}/gi, "***hmac-secret***");
  return out;
}

export function createDebugLogger(
  path = DEFAULT_DEBUG_LOG,
  label = "openclaw-mesh",
): Logger {
  return (msg: string) => {
    if (!isDebugEnabled()) return;
    const safe = redactSecrets(msg);
    const line = `[${new Date().toISOString()}] ${label}: ${safe}\n`;
    // eslint-disable-next-line no-console
    console.error(line);
    try {
      fs.appendFileSync(path, line);
    } catch {
      // ignore fs errors (e.g. disk full / no permissions)
    }
  };
}

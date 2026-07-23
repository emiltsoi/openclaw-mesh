import crypto from "node:crypto";
import { parseA2AEnvelope } from "./envelope.js";

/**
 * Send an A2A message to a Hermes peer.
 * Uses the hermes-mesh webhook protocol (same envelope format + HMAC-SHA256).
 */
export async function a2aSend(
  api: any,
  params: {
    target: string;       // Agent name (e.g., "agent0")
    message: string;
    action?: "do" | "info";
    replyExpected?: boolean;
  },
): Promise<string> {
  const pluginCfg = api.pluginConfig || {};
  const peers = pluginCfg.peers || {};
  const targetConfig = peers[params.target];

  if (!targetConfig) {
    throw new Error(`a2a-bridge: unknown peer "${params.target}". Available: ${Object.keys(peers).join(", ") || "none"}`);
  }

  const { url, secret } = targetConfig;
  if (!url || !secret) {
    throw new Error(`a2a-bridge: peer "${params.target}" missing url or secret`);
  }

  const id = crypto.randomUUID();
  const action = params.action || "do";
  const reply = params.replyExpected !== false ? "yes" : "no";

  const envelope = `[a2a][from:emts][to:${params.target}][id:${id}][action:${action}][reply:${reply}] ${params.message}`;

  const body = JSON.stringify({ text: envelope });
  const signature = crypto.createHmac("sha256", secret).update(body).digest("hex");

  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Hub-Signature-256": `sha256=${signature}`,
    },
    body,
    signal: AbortSignal.timeout(10_000),
  });

  if (!resp.ok) {
    throw new Error(`a2a-bridge: send to ${params.target} failed: HTTP ${resp.status}`);
  }

  return id;
}

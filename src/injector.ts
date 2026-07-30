/**
 * injectIntoSession — inject mesh inbound messages into the OpenClaw agent session
 * by running the configured embedded agent in-process.
 */

import fs from "node:fs";
import crypto from "node:crypto";
import type { MeshEnvelope } from "./envelope.js";
import { validateMeshToken } from "./envelope.js";
import { createDebugLogger } from "./logging.js";
import { mirrorMessage } from "./mirror.js";
import type { MeshBridgePluginConfig } from "./types.js";

const DEFAULT_INBOX = "/tmp/openclaw-mesh/mesh-inbox.jsonl";
const debugLog = createDebugLogger();

const DEFAULT_MODEL = "deepseek/deepseek-v4-pro";

export function resolveModel(
  pluginCfg: MeshBridgePluginConfig,
  globalCfg: any,
): { provider: string; model: string } {
  const primary = pluginCfg.model || globalCfg?.agents?.defaults?.model?.primary || DEFAULT_MODEL;
  const [provider = "deepseek", model = primary] = String(primary).split("/", 2);
  return { provider, model };
}

export function resolveSessionIdFromKey(sessionKey: string): string {
  const parts = sessionKey.split(":");
  if (parts.length >= 3 && parts[0] === "agent") return parts[2];
  if (parts.length >= 2 && parts[0] === "agent") return parts[1];
  return sessionKey || "main";
}

export async function injectIntoSession(
  api: any,
  messageText: string,
  envelope: MeshEnvelope,
): Promise<void> {
  const pluginCfg: MeshBridgePluginConfig = api.pluginConfig || {};
  const globalCfg = api.config || {};

  // Defensive: validate tokens before reconstructing the header.
  validateMeshToken(envelope.from, "from");
  validateMeshToken(envelope.to, "to");
  validateMeshToken(envelope.id, "id");
  validateMeshToken(envelope.action, "action");
  validateMeshToken(envelope.reply, "reply");

  const sanitize = (s: string) => s.replace(/[\[\]]/g, "");
  const text = `[mesh][from:${sanitize(envelope.from)}][to:${sanitize(envelope.to)}][id:${sanitize(envelope.id)}][action:${sanitize(envelope.action)}][reply:${sanitize(envelope.reply)}] ${messageText}`;

  const targetSessionKey = pluginCfg.targetSessionKey || "agent:main:main";
  const targetAgentId =
    pluginCfg.targetAgentId ||
    (targetSessionKey.match(/^agent:([^:]+):/)?.[1] as string | undefined) ||
    "main";
  const sessionId = resolveSessionIdFromKey(targetSessionKey);

  // Step 1: Write to inbox for durability (belt-and-suspenders)
  const inboxDir = pluginCfg.inboxPath || DEFAULT_INBOX;
  try {
    fs.appendFileSync(inboxDir, JSON.stringify({ ts: Date.now(), text, sessionKey: targetSessionKey }) + "\n");
    debugLog("inbox written");
  } catch (e: any) {
    debugLog(`inbox write failed: ${e.message || e}`);
  }

  // Step 2: Surface the incoming mesh on the configured mirror platform (if any)
  const inboundDisplay = `📥 [Mesh from ${envelope.from}]\n\n${messageText}`;
  await mirrorMessage(pluginCfg.mirrorInbound, inboundDisplay, api);

  // Step 3 (primary): trigger an immediate embedded agent turn in the configured session.
  // The Gateway RPC "agent" dispatch accepts the message but does not wake the session,
  // so we use the in-process runtime directly.
  const runtime = api.runtime;
  if (typeof runtime?.agent?.runEmbeddedAgent !== "function") {
    debugLog("runtime.agent.runEmbeddedAgent is not available");
    return;
  }

  const workspaceDir = runtime.agent.resolveAgentWorkspaceDir(globalCfg, targetAgentId);
  const agentDir = runtime.agent.resolveAgentDir(globalCfg, targetAgentId);
  const timeoutMs = runtime.agent.resolveAgentTimeoutMs({ cfg: globalCfg });
  const runId = `mesh-${crypto.randomUUID()}`;
  const messageChannel = pluginCfg.sourceChannel || "mesh";
  const messageTo = pluginCfg.sourceTo || envelope.from || "";

  // Resolve the target model so auth resolves to the configured provider.
  const { provider, model } = resolveModel(pluginCfg, globalCfg);

  debugLog(`starting embedded agent run ${runId} for session ${targetSessionKey} (agent ${targetAgentId}, sessionId ${sessionId}, channel ${messageChannel}, model ${provider}/${model})`);

  // Fire-and-forget: the HTTP webhook should return quickly, but the run
  // continues on the gateway event loop.
  runtime.agent.runEmbeddedAgent({
    agentId: targetAgentId,
    sessionId,
    sessionKey: targetSessionKey,
    prompt: text,
    workspaceDir,
    agentDir,
    timeoutMs,
    runId,
    provider,
    model,
    trigger: "user",
    messageChannel,
    messageTo,
    requireExplicitMessageTarget: false,
    config: globalCfg,
  }).catch(async (e: any) => {
    const errorText = `⚠️ Mesh run failed: ${e.message || e}\n\nInbound message:\n${messageText}`;
    debugLog(`embedded agent run failed: ${e.message || e}`);

    // Fallback 1: mirror the failure so it is visible.
    await mirrorMessage(pluginCfg.mirrorInbound, errorText, api);

    // Fallback 2: append an error record to the durable inbox.
    try {
      fs.appendFileSync(inboxDir, JSON.stringify({ ts: Date.now(), error: e.message || String(e), sessionKey: targetSessionKey, text }) + "\n");
    } catch (err: any) {
      debugLog(`inbox error write failed: ${err.message || err}`);
    }
  });

  debugLog("embedded agent run started");
}

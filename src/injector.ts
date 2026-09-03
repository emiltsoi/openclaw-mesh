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
import { sendDeliveryError } from "./discovery.js";
import { resolveEffectivePluginConfig } from "./config.js";
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
  const pluginCfg: MeshBridgePluginConfig = resolveEffectivePluginConfig(api);
  const meshApi = { pluginConfig: pluginCfg, resolvePath: typeof api.resolvePath === "function" ? api.resolvePath : undefined };
  const globalCfg = api.config || {};

  // Defensive: validate tokens before reconstructing the header.
  validateMeshToken(envelope.from, "from");
  validateMeshToken(envelope.to, "to");
  validateMeshToken(envelope.id, "id");
  validateMeshToken(envelope.action, "action");
  validateMeshToken(envelope.reply, "reply");

  const sanitize = (s: string) => s.replace(/[\[\]]/g, "");
  // U10: rebuild the header with [v:1] and carry [ref:...] when present so the
  // inbox/prompt preserves the reply reference.
  let header = `[mesh][v:1][from:${sanitize(envelope.from)}][to:${sanitize(envelope.to)}][id:${sanitize(envelope.id)}]`;
  // Session-selector tokens (0.1.8): preserve them in the rebuilt header so
  // the reply can swap session/from_session.
  if (envelope.session) {
    header += `[session:${sanitize(envelope.session)}]`;
  }
  if (envelope.fromSession) {
    header += `[from_session:${sanitize(envelope.fromSession)}]`;
  }
  header += `[action:${sanitize(envelope.action)}][reply:${sanitize(envelope.reply)}]`;
  if (envelope.ref) {
    header += `[ref:${sanitize(envelope.ref)}]`;
  }
  const text = `${header} ${messageText}`;

  // Session-selector routing (0.1.8): [session:<name>] looks up the local
  // session_map (session name -> targetSessionKey). Absent/unmapped -> the
  // configured default (unchanged, backward-compatible).
  let targetSessionKey = pluginCfg.targetSessionKey || "agent:main:main";
  if (envelope.session) {
    const sessionMap = pluginCfg.sessionMap || pluginCfg.session_map || {};
    const mapped = sessionMap[envelope.session];
    if (mapped) {
      targetSessionKey = mapped;
      debugLog(`session_map: [session:${envelope.session}] -> ${mapped}`);
    } else {
      debugLog(`session_map: [session:${envelope.session}] not mapped — using default ${targetSessionKey}`);
    }
  }
  const targetAgentId =
    pluginCfg.targetAgentId ||
    (targetSessionKey.match(/^agent:([^:]+):/)?.[1] as string | undefined) ||
    "main";
  const sessionId = resolveSessionIdFromKey(targetSessionKey);

  // Step 1: Write to inbox for durability (belt-and-suspenders).
  // U16: an unwritable inbox is LOUD — throw so the webhook returns non-200
  // instead of silently succeeding with no durable record.
  const inboxDir = pluginCfg.inboxPath || DEFAULT_INBOX;
  try {
    fs.appendFileSync(inboxDir, JSON.stringify({ ts: Date.now(), text, sessionKey: targetSessionKey }) + "\n");
    debugLog("inbox written");
  } catch (e: any) {
    debugLog(`inbox write failed: ${e.message || e}`);
    throw new Error(`inbox write failed: ${e.message || e}`);
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

    // Best-effort DSN to the sender so they know injection failed.
    try {
      const routingAgent = pluginCfg.targetAgentId || "emts";
      await sendDeliveryError(
        envelope.to,
        envelope.from,
        envelope.id,
        "injection-failed",
        envelope.from,
        envelope.to,
        envelope.ref,
        meshApi,
      );
    } catch (dsnErr: any) {
      debugLog(`embedded agent run failed: DSN could not be sent: ${dsnErr.message || dsnErr}`);
    }

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

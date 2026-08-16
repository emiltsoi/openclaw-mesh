import crypto from "node:crypto";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerPluginHttpRoute } from "openclaw/plugin-sdk/webhook-targets";
import { resolveEffectivePluginConfig, resolveMeshExtra, resolveRoutingAgent } from "./config.js";
import { logAudit } from "./audit.js";
import {
  registerMeshTools,
  resolveMeshVaultPath,
  resolveLegacyMeshVaultPath,
  resolvePeer,
  sendDeliveryError,
} from "./discovery.js";
import { parseMeshEnvelope, validateMeshToken } from "./envelope.js";
import { injectIntoSession } from "./injector.js";
import { createDebugLogger, setDebugEnabled } from "./logging.js";
import { verifyEd25519Signature } from "./registry.js";
import { createReplayWindow } from "./replay.js";
import type { MeshBridgePluginConfig } from "./types.js";

const debugLog = createDebugLogger();

// U6/C1: replay protection window — MODULE SCOPE, one per process lifetime.
// The beta loader (2026.8.1-beta.2) runs register() twice (full + discovery,
// finding F1). A per-registration window would orphan the first pass's window
// when the discovery pass splices over the handler (replaceExisting:true) —
// envelope ids seen by the first handler would be replayable indefinitely
// through the second. A single shared window closes that gap: both passes'
// handlers record and check the SAME store (gate 1b adversarial diff C1).
const replayWindow = createReplayWindow();

export function extractMessageText(payload: any): string {
  if (payload === null || payload === undefined || typeof payload !== "object") return "";
  if (typeof payload.text === "string") return payload.text;
  if (payload?.envelope) {
    const e = payload.envelope;
    let header = `[mesh][from:${e.from || ""}][to:${e.to || ""}][id:${e.id || ""}][action:${e.action || "do"}][reply:${e.reply || "no"}]`;
    if (e.ref) {
      header += `[ref:${e.ref}]`;
    }
    return `${header} ${payload.message || ""}`;
  }
  return "";
}

export { validateMeshToken };

function sendJson(res: any, statusCode: number, body: Record<string, unknown>) {
  res.statusCode = statusCode;
  res.end(JSON.stringify(body));
}

const plugin: any = definePluginEntry({
  id: "openclaw-mesh",
  name: "OpenClaw Mesh",
  description: "Receives Hermes mesh webhooks, verifies Ed25519 signatures, and injects into the configured agent session",
  register(api: any) {
    const pluginCfg: MeshBridgePluginConfig = resolveEffectivePluginConfig(api);
    setDebugEnabled(pluginCfg.debug === true);
    const meshApi = { pluginConfig: pluginCfg, resolvePath: typeof api.resolvePath === "function" ? api.resolvePath : undefined };
    const isFullMode = api.registrationMode === "full";
    debugLog("register called");
    debugLog(`registrationMode = ${api.registrationMode ?? "<unset>"}`);

    // Always expose mesh vault tools; this works both when OpenClaw
    // loads us as a plugin (registrationMode === "full") and when it loads
    // us as a runtime extension (registrationMode unset).
    registerMeshTools(api);

    const resolvePath = typeof api.resolvePath === "function" ? api.resolvePath : undefined;
    const vaultPath = resolveMeshVaultPath(pluginCfg, resolvePath);
    const legacyVaultPath = resolveLegacyMeshVaultPath(pluginCfg, resolvePath);

    // BETA-COMPAT (2026-08-16, pilot wave finding F1): the webhook route is
    // registered BEFORE the full-mode gate. The beta loader (2026.8.1-beta.2)
    // runs register() twice — once in "full" mode (root activation) and once
    // in "discovery" mode (agent-runtime handle, activate:false). The
    // discovery pass runs AFTER server start and its registry wins, so a
    // full-mode-only route vanishes (webhook 404). registerPluginHttpRoute is
    // mode-agnostic on the beta (no registrationMode gate in the SDK), so
    // registering in ALL modes keeps the route alive. Stable 2026.7.1-2 is
    // unaffected (registrationMode unset or "full" — same behavior).
    // Verified on pilot bench: 404 -> 403 (route mounted) on beta; stable
    // untouched (403 healthy). Evidence: fleet/artifacts/waves/
    // 2026-08-16-openclaw-pilot-agent/outputs/finding-F1-resolution-fix-verified.md
    registerPluginHttpRoute({
      path: "/plugins/openclaw-mesh/webhook",
      auth: "plugin",
      match: "exact",
      pluginId: "openclaw-mesh",
      source: "openclaw-mesh plugin",
      replaceExisting: true,
      handler: async (req: any, res: any) => {
        debugLog("handler fired");
        const extra = resolveMeshExtra(api);
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk);
        const body = Buffer.concat(chunks);
        let payload: any;

        try {
          const meshSig = (req.headers["x-mesh-signature"] as string) || "";
          const meshTs = (req.headers["x-mesh-timestamp"] as string) || "";
          if (!meshSig || !meshTs) {
            sendJson(res, 403, { status: "forbidden", reason: "missing-signature" });
            return true;
          }

          try {
            payload = JSON.parse(body.toString("utf-8"));
          } catch {
            sendJson(res, 400, { status: "bad-request", reason: "invalid-json" });
            return true;
          }

          // U19: a JSON null/array/primitive body is a clean 400, not a 500.
          if (payload === null || payload === undefined || typeof payload !== "object" || Array.isArray(payload)) {
            sendJson(res, 400, { status: "bad-request", reason: "invalid-payload" });
            return true;
          }

          const text = extractMessageText(payload);

          // U1/U5: invalid ref in the header is LOUD — 400 with reason.
          let envelope;
          try {
            envelope = parseMeshEnvelope(text);
          } catch (e: any) {
            sendJson(res, 400, { status: "bad-request", reason: "invalid-envelope" });
            return true;
          }
          if (!envelope) {
            sendJson(res, 200, { status: "ok", note: "ignored-non-envelope" });
            return true;
          }

          // DSN loop guard: do not inject a DSN back into the agent, and do not
          // generate further DSNs for a DSN.
          if (envelope.dsn || (req.headers["x-mesh-dsn"] === "1")) {
            sendJson(res, 200, { status: "ok", note: "ignored-dsn" });
            return true;
          }

          // Validate envelope tokens before use.
          try {
            validateMeshToken(envelope.from, "from");
            validateMeshToken(envelope.to, "to");
            validateMeshToken(envelope.id, "id");
          } catch (e: any) {
            sendJson(res, 400, { status: "bad-request", reason: "invalid-envelope-token", message: e.message });
            return true;
          }

          const fromName = typeof payload?.from === "string" ? payload.from : envelope.from;
          if (!fromName) {
            sendJson(res, 403, { status: "forbidden", reason: "missing-sender" });
            return true;
          }

          try {
            validateMeshToken(fromName, "from");
          } catch {
            sendJson(res, 403, { status: "forbidden", reason: "invalid-sender" });
            return true;
          }

          const publicKeyResolver = async (name: string): Promise<string | null> => {
            const sender = resolvePeer(vaultPath, name) || resolvePeer(legacyVaultPath, name);
            return sender?.transports?.hermes_webhook?.auth?.public_key || null;
          };

          // U2: verify the Ed25519 signature BEFORE any sendDeliveryError path.
          // This closes the unauthenticated DSN oracle: an unsigned/forged
          // webhook is rejected with 403 and never triggers a DSN side-effect.
          const ok = await verifyEd25519Signature(req.headers, body, fromName, extra, publicKeyResolver);
          if (!ok) {
            logAudit({ ts: new Date().toISOString(), event: "webhook_verify", source: "ed25519", agent: fromName, success: false, error: "invalid-signature" }, extra);
            sendJson(res, 403, { status: "forbidden", reason: "invalid-signature" });
            return true;
          }
          logAudit({ ts: new Date().toISOString(), event: "webhook_verify", source: "ed25519", agent: fromName, success: true }, extra);

          // U6: replay protection — verify-signature → check replay window →
          // record → process. Key is the parsed-header envelope.id (trustworthy
          // after U1); fallback for a missing id is the signed-body SHA-256.
          const replayKey = envelope.id && envelope.id !== "unknown"
            ? `id:${envelope.id}`
            : `body:${crypto.createHash("sha256").update(body).digest("hex")}`;
          if (replayWindow.has(replayKey)) {
            logAudit({ ts: new Date().toISOString(), event: "webhook_receive", agent: fromName, target: envelope.to, success: false, error: "replay-detected" }, extra);
            sendJson(res, 409, { status: "rejected", reason: "replay-detected" });
            return true;
          }
          replayWindow.add(replayKey);

          // U15: use the SAME routing-agent resolver as outbound signing
          // (routingAgent → MESH_AGENT_NAME → A2A_AGENT_NAME → "emts").
          const routingAgent = resolveRoutingAgent(api);
          if (envelope.to !== routingAgent && envelope.to !== "*") {
            try {
              await sendDeliveryError(routingAgent, envelope.from, envelope.id, "not-found", envelope.from, envelope.to, envelope.ref, meshApi);
            } catch (e: any) {
              debugLog(`webhook: DSN for not-found failed: ${e.message || e}`);
            }
            sendJson(res, 200, { status: "ok", note: "not-addressed-to-me" });
            return true;
          }

          if (payload?.from && envelope.from !== fromName) {
            try {
              await sendDeliveryError(routingAgent, fromName, envelope.id, "unauthorized", envelope.from, envelope.to, envelope.ref, meshApi);
            } catch (e: any) {
              debugLog(`webhook: DSN for sender-mismatch failed: ${e.message || e}`);
            }
            sendJson(res, 401, { status: "unauthorized", reason: "envelope-sender-mismatch" });
            return true;
          }

          const messageText = text.replace(/^\[mesh\](?:\[[^\]]*:[^\]]*\])*\s*/, "");
          await injectIntoSession(api, messageText, envelope);

          logAudit({ ts: new Date().toISOString(), event: "webhook_receive", agent: fromName, target: envelope.to, success: true }, extra);
          sendJson(res, 200, { status: "ok" });
          return true;
        } catch (e: any) {
          debugLog(`handler error: ${e.message || e}`);
          try {
            const text = extractMessageText(payload);
            const envelope = parseMeshEnvelope(text);
            if (envelope && !envelope.dsn) {
              const routingAgent = resolveRoutingAgent(api);
              await sendDeliveryError(routingAgent, envelope.from, envelope.id, "internal-error", envelope.from, envelope.to, envelope.ref, meshApi);
            }
          } catch (dsnErr: any) {
            debugLog(`handler error: DSN failed: ${dsnErr.message || dsnErr}`);
          }
          sendJson(res, 500, { status: "error", message: e.message });
          return true;
        }
      },
    });

    debugLog("registerPluginHttpRoute completed");

    // Full-mode-only registrations below. The webhook route above is
    // mode-agnostic (beta-compat, finding F1); the agent_end hook is a
    // lightweight observability side effect that stays gated to full
    // activation to avoid duplicate registration across beta passes.
    if (!isFullMode) {
      debugLog("skipping full-mode-only setup: mode is not 'full'");
      return;
    }

    // Lightweight agent_end hook for observability only.
    api.on("agent_end", async (event: any) => {
      try {
        const messages: any[] = event.messages || [];
        const hasMesh = messages.some((m: any) => {
          const text = typeof m.content === "string"
            ? m.content
            : Array.isArray(m.content)
              ? m.content.filter((part: any) => part.type === "text" && typeof part.text === "string").map((part: any) => part.text).join("")
              : "";
          return text.includes("[mesh]");
        });

        if (hasMesh) {
          const assistantCount = messages.filter((m: any) => m.role === "assistant").length;
          debugLog(`agent_end: mesh turn completed (${assistantCount} assistant messages)`);
        }
      } catch (e: any) {
        debugLog(`agent_end: handler error: ${e.message || e}`);
      }
    });
  },
});
export default plugin;

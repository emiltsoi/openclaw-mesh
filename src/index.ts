import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerPluginHttpRoute } from "openclaw/plugin-sdk/webhook-targets";
import { resolveEffectivePluginConfig, resolveMeshExtra } from "./config.js";
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
import type { MeshBridgePluginConfig } from "./types.js";

const debugLog = createDebugLogger();

export function extractMessageText(payload: any): string {
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

    if (!isFullMode) {
      debugLog("skipping plugin-only setup: mode is not 'full'");
      return;
    }

    const resolvePath = typeof api.resolvePath === "function" ? api.resolvePath : undefined;
    const vaultPath = resolveMeshVaultPath(pluginCfg, resolvePath);
    const legacyVaultPath = resolveLegacyMeshVaultPath(pluginCfg, resolvePath);

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

          const text = extractMessageText(payload);
          const envelope = parseMeshEnvelope(text);
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

          const routingAgent = pluginCfg.routingAgent || "emts";
          if (envelope.to !== routingAgent && envelope.to !== "*") {
            try {
              await sendDeliveryError(routingAgent, envelope.from, envelope.id, "not-found", envelope.from, envelope.to, envelope.ref, meshApi);
            } catch (e: any) {
              debugLog(`webhook: DSN for not-found failed: ${e.message || e}`);
            }
            sendJson(res, 200, { status: "ok", note: "not-addressed-to-me" });
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

          const ok = await verifyEd25519Signature(req.headers, body, fromName, extra, publicKeyResolver);
          if (!ok) {
            logAudit({ ts: new Date().toISOString(), event: "webhook_verify", source: "ed25519", agent: fromName, success: false, error: "invalid-signature" }, extra);
            sendJson(res, 403, { status: "forbidden", reason: "invalid-signature" });
            return true;
          }
          logAudit({ ts: new Date().toISOString(), event: "webhook_verify", source: "ed25519", agent: fromName, success: true }, extra);

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
              const routingAgent = pluginCfg.routingAgent || "emts";
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

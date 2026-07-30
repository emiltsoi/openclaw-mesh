import crypto from "node:crypto";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerPluginHttpRoute } from "openclaw/plugin-sdk/webhook-targets";
import { resolveSecret } from "./config.js";
import { logAudit } from "./audit.js";
import {
  registerMeshTools,
  resolveMeshVaultPath,
  resolveLegacyMeshVaultPath,
  resolvePeer,
} from "./discovery.js";
import { parseMeshEnvelope, validateMeshToken } from "./envelope.js";
import { injectIntoSession } from "./injector.js";
import { createDebugLogger, setDebugEnabled } from "./logging.js";
import { resolveMeshExtra, getIdentitySource, verifyEd25519Signature } from "./registry.js";
import type { MeshBridgePluginConfig } from "./types.js";

const debugLog = createDebugLogger();

function extractMessageText(payload: any): string {
  if (typeof payload.text === "string") return payload.text;
  if (payload?.envelope) {
    const e = payload.envelope;
    return `[mesh][v:1][from:${e.from || ""}][to:${e.to || ""}][id:${e.id || ""}][action:${e.action || "do"}][reply:${e.reply || "no"}] ${payload.message || ""}`;
  }
  return "";
}

function verifyHmacSignature(sigHeader: string, secret: string, body: Buffer): boolean {
  const expected = sigHeader.startsWith("sha256=") ? sigHeader.slice(7) : sigHeader;
  const computed = crypto.createHmac("sha256", secret).update(body).digest("hex");
  const computedBuf = Buffer.from(computed);
  const expectedBuf = Buffer.from(expected);
  return computedBuf.length === expectedBuf.length && crypto.timingSafeEqual(computedBuf, expectedBuf);
}

function sendJson(res: any, statusCode: number, body: Record<string, unknown>) {
  res.statusCode = statusCode;
  res.end(JSON.stringify(body));
}

const plugin: any = definePluginEntry({
  id: "openclaw-mesh",
  name: "OpenClaw Mesh",
  description: "Receives Hermes mesh webhooks, verifies HMAC, and injects into the configured agent session",
  register(api: any) {
    const pluginCfg: MeshBridgePluginConfig = api.pluginConfig || {};
    setDebugEnabled(pluginCfg.debug === true);
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

        try {
          const hubSig = (req.headers["x-hub-signature-256"] as string) || "";
          const meshSig = (req.headers["x-mesh-signature"] as string) || "";
          if (!hubSig && !meshSig) {
            sendJson(res, 403, { status: "forbidden", reason: "missing-signature" });
            return true;
          }

          let payload: any;
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
            sendJson(res, 200, { status: "ok", note: "not-addressed-to-me" });
            return true;
          }

          // Per-agent signature: verify with the sender's HMAC secret (file backend)
          // or Ed25519 public key from the registry.
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

          if (hubSig) {
            const sender = resolvePeer(vaultPath, fromName) || resolvePeer(legacyVaultPath, fromName);
            let senderSecret = sender?.webhook_secret || sender?.transports?.hermes_webhook?.auth?.secret || "";
            // Fall back to the shared bridge secret for backward compatibility.
            if (!senderSecret) {
              try {
                senderSecret = resolveSecret(api);
              } catch {
                // no shared secret either
              }
            }
            if (!senderSecret) {
              sendJson(res, 403, { status: "forbidden", reason: "unknown-sender" });
              return true;
            }

            if (!verifyHmacSignature(hubSig, senderSecret, body)) {
              logAudit({ ts: new Date().toISOString(), event: "webhook_verify", source: "hmac", agent: fromName, success: false, error: "invalid-signature" }, extra);
              sendJson(res, 403, { status: "forbidden", reason: "invalid-signature" });
              return true;
            }
            logAudit({ ts: new Date().toISOString(), event: "webhook_verify", source: "hmac", agent: fromName, success: true }, extra);
          } else if (meshSig) {
            const extra = resolveMeshExtra(api);
            const isRegistry = getIdentitySource(extra) === "registry";
            if (!isRegistry) {
              logAudit({ ts: new Date().toISOString(), event: "webhook_verify", source: "ed25519", agent: fromName, success: false, error: "ed25519-not-configured" }, extra);
              sendJson(res, 403, { status: "forbidden", reason: "ed25519-not-configured" });
              return true;
            }
            const ok = await verifyEd25519Signature(req.headers, body, fromName, extra);
            if (!ok) {
              logAudit({ ts: new Date().toISOString(), event: "webhook_verify", source: "ed25519", agent: fromName, success: false, error: "invalid-signature" }, extra);
              sendJson(res, 403, { status: "forbidden", reason: "invalid-signature" });
              return true;
            }
            logAudit({ ts: new Date().toISOString(), event: "webhook_verify", source: "ed25519", agent: fromName, success: true }, extra);
          }

          // HMAC verified. Enforce that the envelope sender matches the signed payload.
          if (payload?.from && envelope.from !== fromName) {
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

import crypto from "node:crypto";
import fs from "node:fs";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerPluginHttpRoute } from "openclaw/plugin-sdk/webhook-targets";
import { resolveSecret } from "./config.js";
import { parseA2AEnvelope, stripEnvelope } from "./envelope.js";
import { injectIntoSession, cachedBotToken, cachedChatId } from "./injector.js";
import { a2aSend } from "./outbound.js";
const DEBUG_LOG = "/tmp/a2a-debug.log";
function debugLog(msg) {
    const timestamp = new Date().toISOString();
    const line = `[${timestamp}] ${msg}\n`;
    console.error(line);
    try {
        fs.appendFileSync(DEBUG_LOG, line);
    }
    catch (e) {
        // ignore fs errors
    }
}
const plugin = definePluginEntry({
    id: "a2a-bridge",
    name: "A2A Bridge",
    description: "Receives Hermes A2A webhooks, verifies HMAC, injects into main session",
    register(api) {
        debugLog("register called");
        debugLog(`registrationMode = ${api.registrationMode}`);
        if (api.registrationMode !== "full") {
            debugLog("skipping registration: mode is not 'full'");
            return;
        }
        // Dump current registry state before registration
        try {
            const reg = api.pluginRegistry;
            if (reg?.httpRoutes) {
                const paths = reg.httpRoutes.map((r) => `${r.path} (${r.auth}, pluginId=${r.pluginId})`);
                debugLog(`registry BEFORE: ${paths.length} routes: ${JSON.stringify(paths)}`);
            }
            else {
                debugLog("registry BEFORE: no httpRoutes array");
            }
        }
        catch (e) {
            debugLog(`registry BEFORE dump failed: ${e.message}`);
        }
        debugLog("calling registerPluginHttpRoute with path = /plugins/a2a-bridge/webhook");
        registerPluginHttpRoute({
            path: "/plugins/a2a-bridge/webhook",
            auth: "plugin",
            match: "exact",
            pluginId: "a2a-bridge",
            source: "a2a-bridge plugin",
            replaceExisting: true,
            handler: async (req, res) => {
                debugLog("HANDLER FIRED");
                const chunks = [];
                for await (const chunk of req)
                    chunks.push(chunk);
                const body = Buffer.concat(chunks);
                try {
                    const sigHeader = req.headers["x-hub-signature-256"] || "";
                    const secret = resolveSecret(api);
                    if (!sigHeader) {
                        res.statusCode = 403;
                        res.end(JSON.stringify({ status: "forbidden" }));
                        return true;
                    }
                    const expected = sigHeader.startsWith("sha256=") ? sigHeader.slice(7) : sigHeader;
                    const computed = crypto.createHmac("sha256", secret).update(body).digest("hex");
                    const computedBuf = Buffer.from(computed);
                    const expectedBuf = Buffer.from(expected);
                    if (computedBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(computedBuf, expectedBuf)) {
                        res.statusCode = 403;
                        res.end(JSON.stringify({ status: "forbidden" }));
                        return true;
                    }
                    let payload;
                    try {
                        payload = JSON.parse(body.toString("utf-8"));
                    }
                    catch {
                        res.statusCode = 400;
                        res.end(JSON.stringify({ status: "bad-request" }));
                        return true;
                    }
                    const text = typeof payload.text === "string" ? payload.text : "";
                    const envelope = parseA2AEnvelope(text);
                    if (!envelope) {
                        res.statusCode = 200;
                        res.end(JSON.stringify({ status: "ok", note: "ignored-non-envelope" }));
                        return true;
                    }
                    if (envelope.to !== "emts" && envelope.to !== "*") {
                        res.statusCode = 200;
                        res.end(JSON.stringify({ status: "ok", note: "not-addressed-to-me" }));
                        return true;
                    }
                    const messageText = stripEnvelope(text);
                    await injectIntoSession(api, messageText, envelope);
                    res.statusCode = 200;
                    res.end(JSON.stringify({ status: "ok" }));
                    return true;
                }
                catch (e) {
                    console.error("a2a-bridge: handler error:", e);
                    res.statusCode = 500;
                    res.end(JSON.stringify({ status: "error", message: e.message }));
                    return true;
                }
            },
        });
        debugLog("registerPluginHttpRoute completed successfully");
        // Dump registry AFTER
        try {
            const reg = api.pluginRegistry;
            if (reg?.httpRoutes) {
                const paths = reg.httpRoutes.map((r) => `${r.path} (${r.auth}, pluginId=${r.pluginId})`);
                debugLog(`registry AFTER: ${paths.length} routes: ${JSON.stringify(paths)}`);
            }
        }
        catch (e) {
            debugLog(`registry AFTER dump failed: ${e.message}`);
        }
        // Register a2a_send tool for outbound mesh messages
        api.registerTool({
            name: "a2a_send",
            description: "Send an A2A message to a Hermes mesh peer via HMAC-signed webhook",
            parameters: {
                type: "object",
                properties: {
                    target: { type: "string", description: "Target agent name (e.g., 'agent0', 'linda')" },
                    message: { type: "string", description: "Message text to send" },
                    action: { type: "string", enum: ["do", "info"], description: "Action type", default: "do" },
                    replyExpected: { type: "boolean", description: "Whether a reply is expected", default: true },
                },
                required: ["target", "message"],
            },
            execute: async (call) => {
                const id = await a2aSend(api, {
                    target: call.target,
                    message: call.message,
                    action: call.action || "do",
                    replyExpected: call.replyExpected !== false,
                });
                return { type: "text", text: `A2A message sent to ${call.target} (id: ${id})` };
            },
        });
        debugLog("a2a_send tool registered");
        // Register agent_end hook to forward outbound A2A replies to Telegram
        api.on("agent_end", async (event) => {
            debugLog("agent_end: hook fired");
            const messages = event.messages || [];
            debugLog(`agent_end: ${messages.length} messages, roles: ${messages.map((m) => m.role).join(",")}`);
            // Only forward if this turn was A2A-triggered (check any role — wake events may be system, not user)
            const hasA2A = messages.some((m) => m.content?.includes("[a2a]") || m.content?.includes("[A2A from") || m.content?.includes("A2A from"));
            debugLog(`agent_end: hasA2A=${hasA2A}`);
            if (!hasA2A)
                return;
            // Get the last assistant message
            const assistantMsgs = messages.filter((m) => m.role === "assistant");
            const lastReply = assistantMsgs[assistantMsgs.length - 1]?.content || "";
            // Skip empty/noise replies
            debugLog(`agent_end: lastReply length=${lastReply.length}, starts=${lastReply.substring(0, 40)}`);
            if (!lastReply || lastReply === "NO_REPLY" || lastReply === "ANNOUNCE_SKIP" || lastReply === "HEARTBEAT_OK") {
                debugLog(`agent_end: skipped (empty/noise)`);
                return;
            }
            if (lastReply.startsWith("🦞 OpenClaw")) {
                debugLog(`agent_end: skipped (status card)`);
                return;
            }
            // Forward to Telegram (try cached from injector, fallback to config)
            let tgToken = cachedBotToken;
            if (!tgToken) {
                const tgCfg = (api.config?.channels?.telegram || {});
                tgToken = tgCfg.botToken || "";
            }
            const chatId = cachedChatId;
            debugLog(`agent_end: tgToken present=${!!tgToken}, chatId=${chatId}`);
            if (!tgToken) {
                debugLog(`agent_end: no tgToken, skipping forward`);
                return;
            }
            try {
                const resp = await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({
                        chat_id: chatId,
                        text: `📤 [A2A reply]\n\n${lastReply}`,
                        disable_web_page_preview: true,
                    }),
                    signal: AbortSignal.timeout(5_000),
                });
                debugLog(`agent_end: Telegram forward HTTP ${resp.status}`);
            }
            catch (e) {
                debugLog(`agent_end: Telegram forward failed: ${e.message}`);
            }
        });
    },
});
export default plugin;

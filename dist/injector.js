"use strict";
/**
 * injectIntoSession — inject A2A inbound messages into the OpenClaw agent session
 * via the Gateway RPC client (replacing the broken SDK + hooks/wake approach).
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.cachedChatId = exports.cachedBotToken = void 0;
exports.injectIntoSession = injectIntoSession;
const node_fs_1 = __importDefault(require("node:fs"));
const rpc_client_js_1 = require("./rpc-client.js");
const DEFAULT_INBOX = "/tmp/openclaw-mesh/a2a-inbox.jsonl";
// Module-level cache for Telegram credentials (accessible from hooks)
exports.cachedBotToken = "";
exports.cachedChatId = "";
function resolveConfig(api) {
    const cfg = api.config || {};
    const gateway = cfg.gateway || {};
    const hooks = cfg.hooks || {};
    const telegram = cfg.channels?.telegram || {};
    const port = gateway.port || 18860;
    exports.cachedBotToken = telegram.botToken || "";
    exports.cachedChatId = telegram.chatId || "7945905361";
    return {
        port,
        wsUrl: `ws://localhost:${port}`,
        gatewayToken: gateway.auth?.token || hooks.token || "",
        gatewayPassword: gateway.auth?.password || "",
        telegramBotToken: exports.cachedBotToken,
        telegramChatId: exports.cachedChatId,
    };
}
async function forwardToTelegram(config, text) {
    if (!config.telegramBotToken)
        return;
    try {
        const resp = await fetch(`https://api.telegram.org/bot${config.telegramBotToken}/sendMessage`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ chat_id: config.telegramChatId, text, disable_web_page_preview: true }),
            signal: AbortSignal.timeout(5_000),
        });
        console.error("a2a-bridge: Telegram forward HTTP", resp.status);
    }
    catch (e) {
        console.error("a2a-bridge: Telegram forward failed:", e);
    }
}
async function injectIntoSession(api, messageText, envelope) {
    const sanitize = (s) => s.replace(/[\[\]]/g, "");
    const text = `[a2a][from:${sanitize(envelope.from)}][to:${sanitize(envelope.to)}][id:${sanitize(envelope.id)}][action:${sanitize(envelope.action)}][reply:${sanitize(envelope.reply)}] ${messageText}`;
    const config = resolveConfig(api);
    const pluginCfg = api.pluginConfig || {};
    const targetSessionKey = pluginCfg.targetSessionKey || "agent:main:main";
    // Step 1: Write to inbox for durability (belt-and-suspenders)
    const inboxDir = pluginCfg.inboxPath || DEFAULT_INBOX;
    try {
        const inbox = inboxDir;
        node_fs_1.default.appendFileSync(inbox, JSON.stringify({ ts: Date.now(), text, sessionKey: targetSessionKey }) + "\n");
        console.error("a2a-bridge: inbox written");
    }
    catch (e) {
        console.error("a2a-bridge: inbox write failed:", e.message || e);
    }
    // Step 2: Forward incoming A2A to Emil on Telegram (mechanical, before wake)
    const tgDisplay = `📥 [A2A from ${envelope.from}]

${messageText}`;
    await forwardToTelegram(config, tgDisplay);
    // Step 3 (primary): Gateway RPC dispatch — connect, authenticate, send agent message, close
    try {
        const client = new rpc_client_js_1.GatewayRpcClient({
            wsUrl: config.wsUrl,
            token: config.gatewayToken,
            password: config.gatewayPassword,
            agentResponseTimeoutMs: 300_000,
        });
        console.error(`a2a-bridge: dispatching via Gateway RPC to session ${targetSessionKey}`);
        await client.dispatchAgentMessage(targetSessionKey, text);
        console.error("a2a-bridge: Gateway RPC dispatch succeeded");
        return;
    }
    catch (e) {
        console.error("a2a-bridge: Gateway RPC dispatch failed:", e.message || e);
    }
    // Step 4 (fallback): hooks/wake (only reached if Gateway RPC fails)
    try {
        const fallbackUrl = `http://localhost:${config.port}/hooks/wake`;
        console.error(`a2a-bridge: trying hooks/wake fallback at ${fallbackUrl}`);
        const resp = await fetch(fallbackUrl, {
            method: "POST",
            headers: {
                authorization: `Bearer ${config.gatewayToken}`,
                "content-type": "application/json",
            },
            body: JSON.stringify({ text, mode: "now" }),
            signal: AbortSignal.timeout(5_000),
        });
        console.error("a2a-bridge: hooks/wake (fallback) HTTP", resp.status);
    }
    catch (e) {
        console.error("a2a-bridge: hooks/wake (fallback) failed:", e.message || e);
    }
}

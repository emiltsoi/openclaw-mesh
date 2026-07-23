import fs from "node:fs";
import type { A2AEnvelope } from "./envelope.js";

const DEFAULT_INBOX = "/tmp/openclaw-mesh/a2a-inbox.jsonl";

// Module-level cache for Telegram credentials (accessible from hooks)
export let cachedBotToken = "";
export let cachedChatId = "";

function resolveConfig(api: any) {
  const cfg = api.config || {};
  const gateway = cfg.gateway || {};
  const hooks = cfg.hooks || {};
  const telegram = cfg.channels?.telegram || {};
  const port = gateway.port || 18860;
  cachedBotToken = telegram.botToken || "";
  cachedChatId = telegram.chatId || "7945905361";
  return {
    port,
    hooksWakeUrl: `http://localhost:${port}/hooks/wake`,
    hooksToken: hooks.token || "",
    telegramBotToken: cachedBotToken,
    telegramChatId: cachedChatId,
  };
}

async function forwardToTelegram(config: any, text: string): Promise<void> {
  if (!config.telegramBotToken) return;
  try {
    const resp = await fetch(
      `https://api.telegram.org/bot${config.telegramBotToken}/sendMessage`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ chat_id: config.telegramChatId, text, disable_web_page_preview: true }),
        signal: AbortSignal.timeout(5_000),
      },
    );
    console.error("a2a-bridge: Telegram forward HTTP", resp.status);
  } catch (e) {
    console.error("a2a-bridge: Telegram forward failed:", e);
  }
}

export async function injectIntoSession(
  api: any,
  messageText: string,
  envelope: A2AEnvelope,
): Promise<void> {
  const sanitize = (s: string) => s.replace(/[\[\]]/g, "");
  const text = `[a2a][from:${sanitize(envelope.from)}][to:${sanitize(envelope.to)}][id:${sanitize(envelope.id)}][action:${sanitize(envelope.action)}][reply:${sanitize(envelope.reply)}] ${messageText}`;
  const config = resolveConfig(api);
  const pluginCfg = api.pluginConfig || {};
  const targetSessionKey = pluginCfg.targetSessionKey || "agent:main:main";
  const idempotencyKey = `a2a:${envelope.id}`;

  // Step 1: Write to inbox for durability (belt-and-suspenders)
  const inboxDir = pluginCfg.inboxPath || DEFAULT_INBOX;
  try {
    const inbox = inboxDir;
    fs.appendFileSync(inbox, JSON.stringify({ ts: Date.now(), text, sessionKey: targetSessionKey }) + "\n");
    console.error("a2a-bridge: inbox written");
  } catch (e: any) {
    console.error("a2a-bridge: inbox write failed:", e.message || e);
  }

  // Step 2: Forward incoming A2A to Emil on Telegram (mechanical, before wake)
  const tgDisplay = `📥 [A2A from ${envelope.from}]

${messageText}`;
  await forwardToTelegram(config, tgDisplay);

  // Default: fallback to hooks/wake
  if (!config.hooksToken) {
    console.error("a2a-bridge: no hooks token — accepted to inbox but NOT injected");
    return;
  }

  // Step 3 (primary): SDK-based injection + autonomous wake
  try {
    await api.session.workflow.enqueueNextTurnInjection({
      sessionKey: targetSessionKey,
      idempotencyKey,
      content: text,
      ttlMs: 10 * 60_000,
    });
    console.error("a2a-bridge: injection enqueued");

    await api.runtime.agent.runEmbeddedAgent({
      sessionId: targetSessionKey,
      prompt: "",
      timeoutMs: 600_000,
    });
    console.error("a2a-bridge: embedded agent run queued");
    return;
  } catch (e: any) {
    console.error("a2a-bridge: SDK wake failed, falling back to hooks/wake:", e.message || e);
    // Fallback: use hooks/wake for older OpenClaw versions
  }

  // Step 4 (fallback): hooks/wake
  try {
    const resp = await fetch(config.hooksWakeUrl, {
      method: "POST",
      headers: {
        authorization: `Bearer ${config.hooksToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ text, mode: "now" }),
      signal: AbortSignal.timeout(5_000),
    });
    console.error("a2a-bridge: hooks/wake (fallback) HTTP", resp.status);
  } catch (e: any) {
    console.error("a2a-bridge: hooks/wake (fallback) failed:", e.message || e);
  }
}

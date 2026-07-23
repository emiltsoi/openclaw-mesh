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

  // Step 0: Can fs even write?
  try {
    fs.writeFileSync("/tmp/a2a-fs-test.txt", "works");
    console.error("a2a-bridge: fs.write OK");
  } catch (e: any) {
    console.error("a2a-bridge: fs.write FAILED:", e.message || e);
  }

  // Step 1: Write to inbox for durability
  try {
    fs.appendFileSync(DEFAULT_INBOX, JSON.stringify({ ts: Date.now(), text, sessionKey: "agent:main:main" }) + "\n");
  } catch (e) {
    // silent
  }

  // Step 2: Forward incoming A2A to Emil on Telegram (mechanical, before wake)
  const tgDisplay = `📥 [A2A from ${envelope.from}]

${messageText}`;
  await forwardToTelegram(config, tgDisplay);

  // Step 3: Wake the session via hooks/wake
  if (!config.hooksToken) {
    console.error("a2a-bridge: no hooks token — accepted to inbox but NOT injected");
    return;
  }

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
    console.error("a2a-bridge: hooks/wake HTTP", resp.status);
  } catch (e) {
    console.error("a2a-bridge: hooks/wake failed:", e);
  }
}

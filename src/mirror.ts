/**
 * Configurable mesh message mirroring to external surfaces.
 *
 * Supports per-direction (inbound/outbound) mirroring to:
 * - "none"    : no mirroring
 * - "telegram": Telegram Bot API sendMessage
 * - "cli"     : stdout log (appears in gateway logs)
 */

import { createDebugLogger } from "./logging.js";

const debugLog = createDebugLogger();

export type MirrorPlatform = "none" | "telegram" | "cli";

export const MIRROR_PLATFORMS: MirrorPlatform[] = ["none", "telegram", "cli"];

export function normalizeMirrorPlatform(value?: string): MirrorPlatform {
  const v = String(value || "").toLowerCase().trim();
  if (v === "telegram" || v === "cli") return v;
  return "none";
}

export function resolveTelegramConfig(api: { config?: any }) {
  const telegram = api.config?.channels?.telegram || {};
  const botToken = telegram.botToken || "";
  const firstAllowFrom = telegram.allowFrom?.[0] ?? telegram.groupAllowFrom?.[0];
  const chatId = telegram.chatId ? String(telegram.chatId) : firstAllowFrom ? String(firstAllowFrom) : "";
  return { botToken, chatId };
}

export async function forwardToTelegram(botToken: string, chatId: string, text: string): Promise<void> {
  if (!botToken || !chatId) return;
  try {
    const resp = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }),
      signal: AbortSignal.timeout(5_000),
    });
    debugLog(`Telegram forward HTTP ${resp.status}`);
  } catch (e) {
    debugLog(`Telegram forward failed: ${e}`);
  }
}

export async function mirrorMessage(platform: MirrorPlatform | string | undefined, text: string, api: any): Promise<void> {
  const p = normalizeMirrorPlatform(platform);
  if (p === "none") return;

  if (p === "cli") {
    // eslint-disable-next-line no-console
    console.log(`[mesh mirror]\n${text}`);
    return;
  }

  if (p === "telegram") {
    const { botToken, chatId } = resolveTelegramConfig(api);
    if (!botToken || !chatId) {
      debugLog("Telegram mirroring skipped: no botToken or chatId configured");
      return;
    }
    await forwardToTelegram(botToken, chatId, text);
  }
}

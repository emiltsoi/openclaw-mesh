/**
 * Standalone Gateway RPC dispatcher. Spawned from the a2a-bridge webhook handler.
 *
 * Lifecycle: spawned → WS connect → challenge-response → agent RPC → close → exit
 * No stdin. Logs to stderr. Returns nothing to parent.
 */

import { GatewayRpcClient } from "./rpc-client.js";
import crypto from "node:crypto";

async function resolveConfig() {
  const cfgPath = process.env.CONFIG_PATH || "./openclaw.plugin.json";
  try {
    // Read plugin config
    const fs = await import("node:fs");
    const raw = fs.readFileSync(cfgPath, "utf-8");
    const cfg = JSON.parse(raw);
    return {
      wsUrl: cfg.config?.wsUrl || "ws://localhost:18860",
      token: cfg.config?.gatewayToken || "",
      password: cfg.config?.gatewayPassword || "",
    };
  } catch {
    return {
      wsUrl: "ws://localhost:18860",
      token: process.env.GATEWAY_TOKEN || "",
      password: "",
    };
  }
}

async function main() {
  const sessionKey = process.env.SESSION_KEY;
  const message = process.env.MESSAGE;

  if (!sessionKey || !message) {
    console.error("dispatch.js: SESSION_KEY or MESSAGE not set");
    process.exit(1);
  }

  console.error(`dispatch.js: dispatching to ${sessionKey} via ws://localhost:18860`);

  const config = resolveConfig();
  const client = new GatewayRpcClient({
    wsUrl: config.wsUrl,
    token: config.token,
    password: config.password,
    agentResponseTimeoutMs: 300_000,
  });

  try {
    await client.dispatchAgentMessage(sessionKey, message);
    console.error("dispatch.js: Gateway RPC dispatch succeeded");
    process.exit(0);
  } catch (e) {
    console.error("dispatch.js: Gateway RPC dispatch failed:", e.message || e);
    process.exit(1);
  }
}

main();

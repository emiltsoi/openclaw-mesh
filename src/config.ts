import type { MeshBridgePluginConfig } from "./types.js";

export function resolveSecret(api: { pluginConfig?: MeshBridgePluginConfig; config?: any }): string {
  // pluginConfig may not include secret (OpenClaw strips sensitive fields)
  const pluginCfg = api.pluginConfig || {};
  if (typeof pluginCfg.secret === "string" && pluginCfg.secret) return pluginCfg.secret;
  // Fall back to full gateway config
  const fullCfg = api.config?.plugins?.entries?.["openclaw-mesh"]?.config ?? {};
  if (typeof fullCfg.secret === "string" && fullCfg.secret) return fullCfg.secret;
  const envVarName = pluginCfg.secretEnvVar || "OPENCLAW_MESH_SECRET";
  const envSecret = process.env[envVarName];
  if (typeof envSecret === "string" && envSecret) return envSecret;
  throw new Error("openclaw-mesh: no secret configured.");
}

export function resolveDeliveryRetries(api?: { pluginConfig?: MeshBridgePluginConfig }): number {
  const pluginCfg = api?.pluginConfig || {};
  if (typeof pluginCfg.deliveryRetries === "number" && pluginCfg.deliveryRetries > 0) {
    return pluginCfg.deliveryRetries;
  }
  const env = process.env.OPENCLAW_MESH_DELIVERY_RETRIES || process.env.A2A_WEBHOOK_DELIVERY_RETRIES || "";
  const parsed = env ? parseInt(env, 10) : NaN;
  if (!Number.isNaN(parsed) && parsed > 0) return parsed;
  return 3;
}

export function resolveDeliveryBackoffMs(api?: { pluginConfig?: MeshBridgePluginConfig }): number {
  const pluginCfg = api?.pluginConfig || {};
  if (typeof pluginCfg.deliveryBackoffMs === "number" && pluginCfg.deliveryBackoffMs >= 0) {
    return pluginCfg.deliveryBackoffMs;
  }
  const env = process.env.OPENCLAW_MESH_DELIVERY_BACKOFF || process.env.A2A_WEBHOOK_DELIVERY_BACKOFF || "";
  const parsed = env ? parseFloat(env) : NaN;
  if (!Number.isNaN(parsed) && parsed >= 0) return parsed * 1000;
  return 1000;
}

export function resolveDeliveryTimeoutMs(api?: { pluginConfig?: MeshBridgePluginConfig }): number {
  const pluginCfg = api?.pluginConfig || {};
  if (typeof pluginCfg.deliveryTimeoutMs === "number" && pluginCfg.deliveryTimeoutMs > 0) {
    return pluginCfg.deliveryTimeoutMs;
  }
  const env = process.env.OPENCLAW_MESH_DELIVERY_TIMEOUT || process.env.A2A_WEBHOOK_DELIVERY_TIMEOUT || "";
  const parsed = env ? parseInt(env, 10) : NaN;
  if (!Number.isNaN(parsed) && parsed > 0) return parsed * 1000;
  return 15_000;
}

export function isDebugEnabled(api?: { pluginConfig?: MeshBridgePluginConfig }): boolean {
  const pluginCfg = api?.pluginConfig || {};
  if (typeof pluginCfg.debug === "boolean") return pluginCfg.debug;
  const env = process.env.OPENCLAW_MESH_DEBUG || process.env.A2A_BRIDGE_DEBUG || "";
  return env === "1" || env.toLowerCase() === "true";
}

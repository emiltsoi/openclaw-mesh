import type { MeshBridgePluginConfig } from "./types.js";

/**
 * Resolve the effective plugin config from the various shapes OpenClaw passes
 * at registration and tool-execution time. It may live on api.pluginConfig,
 * under api.config.plugins.entries["openclaw-mesh"].config, or directly on
 * api.config when OpenClaw hands the plugin its own config object.
 */
export function resolveEffectivePluginConfig(api?: { pluginConfig?: MeshBridgePluginConfig; config?: any }): MeshBridgePluginConfig {
  const pluginCfg = api?.pluginConfig || {};
  const fullGatewayCfg = api?.config?.plugins?.entries?.["openclaw-mesh"]?.config;
  const directCfg =
    api?.config &&
    (api.config.routingAgent !== undefined ||
      api.config.allowLoopback !== undefined ||
      api.config.meshVaultPath !== undefined ||
      api.config.identitySource !== undefined ||
      api.config.privateNetworkPolicy !== undefined)
      ? api.config
      : undefined;
  const fullCfg = fullGatewayCfg || directCfg || {};
  return { ...fullCfg, ...pluginCfg };
}

export function resolveSecret(api: { pluginConfig?: MeshBridgePluginConfig; config?: any }): string {
  const cfg = resolveEffectivePluginConfig(api);
  if (typeof cfg.secret === "string" && cfg.secret) return cfg.secret;
  const envVarName = cfg.secretEnvVar || "OPENCLAW_MESH_SECRET";
  const envSecret = process.env[envVarName];
  if (typeof envSecret === "string" && envSecret) return envSecret;
  throw new Error("openclaw-mesh: no secret configured.");
}

export function resolveDeliveryRetries(api?: { pluginConfig?: MeshBridgePluginConfig; config?: any }): number {
  const cfg = resolveEffectivePluginConfig(api);
  if (typeof cfg.deliveryRetries === "number" && cfg.deliveryRetries > 0) {
    return cfg.deliveryRetries;
  }
  const env = process.env.OPENCLAW_MESH_DELIVERY_RETRIES || process.env.A2A_WEBHOOK_DELIVERY_RETRIES || "";
  const parsed = env ? parseInt(env, 10) : NaN;
  if (!Number.isNaN(parsed) && parsed > 0) return parsed;
  return 3;
}

export function resolveDeliveryBackoffMs(api?: { pluginConfig?: MeshBridgePluginConfig; config?: any }): number {
  const cfg = resolveEffectivePluginConfig(api);
  if (typeof cfg.deliveryBackoffMs === "number" && cfg.deliveryBackoffMs >= 0) {
    return cfg.deliveryBackoffMs;
  }
  const env = process.env.OPENCLAW_MESH_DELIVERY_BACKOFF || process.env.A2A_WEBHOOK_DELIVERY_BACKOFF || "";
  const parsed = env ? parseFloat(env) : NaN;
  if (!Number.isNaN(parsed) && parsed >= 0) return parsed * 1000;
  return 1000;
}

export function resolveDeliveryTimeoutMs(api?: { pluginConfig?: MeshBridgePluginConfig; config?: any }): number {
  const cfg = resolveEffectivePluginConfig(api);
  if (typeof cfg.deliveryTimeoutMs === "number" && cfg.deliveryTimeoutMs > 0) {
    return cfg.deliveryTimeoutMs;
  }
  const env = process.env.OPENCLAW_MESH_DELIVERY_TIMEOUT || process.env.A2A_WEBHOOK_DELIVERY_TIMEOUT || "";
  const parsed = env ? parseInt(env, 10) : NaN;
  if (!Number.isNaN(parsed) && parsed > 0) return parsed * 1000;
  return 15_000;
}

export function isDebugEnabled(api?: { pluginConfig?: MeshBridgePluginConfig; config?: any }): boolean {
  const cfg = resolveEffectivePluginConfig(api);
  if (typeof cfg.debug === "boolean") return cfg.debug;
  const env = process.env.OPENCLAW_MESH_DEBUG || process.env.A2A_BRIDGE_DEBUG || "";
  return env === "1" || env.toLowerCase() === "true";
}

export type PrivateNetworkPolicy = "allow" | "warn" | "deny";

export function resolvePrivateNetworkPolicy(
  api?: { pluginConfig?: MeshBridgePluginConfig; config?: any },
  peerAllowLoopback = false,
): PrivateNetworkPolicy {
  const cfg = resolveEffectivePluginConfig(api);
  const allowLoopback =
    cfg.allowLoopback === true ||
    String(cfg.allowLoopback ?? "").toLowerCase() === "true";
  if (allowLoopback || peerAllowLoopback) return "allow";
  const policy =
    cfg.privateNetworkPolicy ||
    cfg.private_network_policy;
  if (policy === "allow" || policy === "warn" || policy === "deny") return policy;
  const env = process.env.OPENCLAW_MESH_ALLOW_LOOPBACK || process.env.A2A_WEBHOOK_ALLOW_LOOPBACK || "";
  if (env === "1" || env.toLowerCase() === "true") return "allow";
  return "deny";
}

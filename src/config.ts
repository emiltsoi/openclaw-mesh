import type { MeshBridgePluginConfig } from "./types.js";

type ConfigInput = { pluginConfig?: MeshBridgePluginConfig; config?: any } | MeshBridgePluginConfig;

/**
 * Resolve the effective plugin config from the various shapes OpenClaw passes
 * at registration and tool-execution time. It may live on api.pluginConfig,
 * under api.config.plugins.entries["openclaw-mesh"].config, or directly on
 * api.config when OpenClaw hands the plugin its own config object.
 */
export function resolveEffectivePluginConfig(api?: ConfigInput): MeshBridgePluginConfig {
  if (api && typeof api === "object" && !("pluginConfig" in api) && !("config" in api)) {
    return api as MeshBridgePluginConfig;
  }
  const pluginCfg = (api as any)?.pluginConfig || {};
  const fullGatewayCfg = (api as any)?.config?.plugins?.entries?.["openclaw-mesh"]?.config;
  const directCfg =
    (api as any)?.config &&
    ((api as any).config.routingAgent !== undefined ||
      (api as any).config.allowLoopback !== undefined ||
      (api as any).config.meshVaultPath !== undefined ||
      (api as any).config.privateNetworkPolicy !== undefined)
      ? (api as any).config
      : undefined;
  const fullCfg = fullGatewayCfg || directCfg || {};
  return { ...fullCfg, ...pluginCfg };
}

export function getRegistryUrl(extra?: MeshBridgePluginConfig): string {
  return extra?.registryUrl || extra?.registry_url || process.env.MESH_REGISTRY_URL || "";
}

export function resolveRoutingAgent(api?: ConfigInput): string {
  const cfg = resolveEffectivePluginConfig(api);
  return cfg.routingAgent || process.env.MESH_AGENT_NAME || process.env.A2A_AGENT_NAME || "emts";
}

export function resolvePrivateKeyPath(api?: ConfigInput): string | undefined {
  const cfg = resolveEffectivePluginConfig(api);
  return cfg.privateKeyPath || cfg.private_key_path || process.env.MESH_PRIVATE_KEY_PATH;
}

export function resolveSignTimestamp(api?: ConfigInput): boolean {
  const cfg = resolveEffectivePluginConfig(api);
  if (typeof cfg.signTimestamp === "boolean") return cfg.signTimestamp;
  if (typeof cfg.sign_timestamp === "boolean") return cfg.sign_timestamp;
  const env = process.env.MESH_SIGN_TIMESTAMP || process.env.OPENCLAW_MESH_SIGN_TIMESTAMP || "";
  if (env === "" && (cfg.signTimestamp === undefined || cfg.sign_timestamp === undefined)) return true;
  return env === "1" || env.toLowerCase() === "true";
}

export function resolveRegistryPin(api?: ConfigInput): string {
  const cfg = resolveEffectivePluginConfig(api);
  return (cfg.registryPin || cfg.registry_pin || process.env.MESH_REGISTRY_PIN || "").toLowerCase().trim();
}

export function resolveAllowInsecureRegistry(api?: ConfigInput): boolean {
  const cfg = resolveEffectivePluginConfig(api);
  if (cfg.allowInsecureRegistry === true || cfg.allow_insecure_registry === true) return true;
  const env = (process.env.MESH_REGISTRY_ALLOW_INSECURE || "").toLowerCase();
  return ["1", "true", "yes"].includes(env);
}

export function resolveDeliveryRetries(api?: ConfigInput): number {
  const cfg = resolveEffectivePluginConfig(api);
  if (typeof cfg.deliveryRetries === "number" && cfg.deliveryRetries > 0) {
    return cfg.deliveryRetries;
  }
  const env = process.env.OPENCLAW_MESH_DELIVERY_RETRIES || process.env.A2A_WEBHOOK_DELIVERY_RETRIES || "";
  const parsed = env ? parseInt(env, 10) : NaN;
  if (!Number.isNaN(parsed) && parsed > 0) return parsed;
  return 3;
}

export function resolveDeliveryBackoffMs(api?: ConfigInput): number {
  const cfg = resolveEffectivePluginConfig(api);
  if (typeof cfg.deliveryBackoffMs === "number" && cfg.deliveryBackoffMs >= 0) {
    return cfg.deliveryBackoffMs;
  }
  const env = process.env.OPENCLAW_MESH_DELIVERY_BACKOFF || process.env.A2A_WEBHOOK_DELIVERY_BACKOFF || "";
  const parsed = env ? parseFloat(env) : NaN;
  if (!Number.isNaN(parsed) && parsed >= 0) return parsed * 1000;
  return 1000;
}

export function resolveDeliveryTimeoutMs(api?: ConfigInput): number {
  const cfg = resolveEffectivePluginConfig(api);
  if (typeof cfg.deliveryTimeoutMs === "number" && cfg.deliveryTimeoutMs > 0) {
    return cfg.deliveryTimeoutMs;
  }
  const env = process.env.OPENCLAW_MESH_DELIVERY_TIMEOUT || process.env.A2A_WEBHOOK_DELIVERY_TIMEOUT || "";
  const parsed = env ? parseInt(env, 10) : NaN;
  if (!Number.isNaN(parsed) && parsed > 0) return parsed * 1000;
  return 15_000;
}

export function isDebugEnabled(api?: ConfigInput): boolean {
  const cfg = resolveEffectivePluginConfig(api);
  if (typeof cfg.debug === "boolean") return cfg.debug;
  const env = process.env.OPENCLAW_MESH_DEBUG || process.env.A2A_BRIDGE_DEBUG || "";
  return env === "1" || env.toLowerCase() === "true";
}

export function resolveMeshExtra(api?: ConfigInput): MeshBridgePluginConfig {
  return resolveEffectivePluginConfig(api);
}

export type PrivateNetworkPolicy = "allow" | "warn" | "deny";

export function resolvePrivateNetworkPolicy(
  api?: ConfigInput,
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

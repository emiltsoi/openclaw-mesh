/**
 * Typed OpenClaw mesh bridge plugin configuration.
 */
export interface MeshBridgePluginConfig {
  /** mesh agent name this bridge accepts messages for. */
  routingAgent?: string;
  /** HMAC-SHA256 shared secret for inbound webhook verification. */
  secret?: string;
  /** Environment variable name for the shared secret. */
  secretEnvVar?: string;
  /** Target OpenClaw session key (e.g. "agent:main:main"). */
  targetSessionKey?: string;
  /** Target OpenClaw agent ID (e.g. "main"). */
  targetAgentId?: string;
  /** Channel to attribute the injected turn to. */
  sourceChannel?: string;
  /** Channel target/to (e.g. Telegram chat id) for the injected turn. */
  sourceTo?: string;
  /** Optional explicit model override (e.g. "deepseek/deepseek-v4-pro"). */
  model?: string;
  /** Optional durable inbox file path. */
  inboxPath?: string;
  /** Optional path to the mesh vault root (defaults to $OPENCLAW_STATE_DIR/mesh or /tmp/openclaw-mesh; then appends mesh/agents). */
  meshVaultPath?: string;
  /** Platform to mirror inbound mesh messages to: "none", "telegram", or "cli". Defaults to "none". */
  mirrorInbound?: string;
  /** Platform to mirror outbound mesh messages to: "none", "telegram", or "cli". Defaults to "none". */
  mirrorOutbound?: string;
  /** Whether to emit verbose debug logs. */
  debug?: boolean;
  /** Allow outbound webhook deliveries to loopback/private addresses. */
  allowLoopback?: boolean;
  /** Number of outbound webhook delivery attempts. */
  deliveryRetries?: number;
  /** Initial retry backoff in milliseconds. */
  deliveryBackoffMs?: number;
  /** Per-attempt delivery timeout in milliseconds. */
  deliveryTimeoutMs?: number;
  /** Identity source: "file" (default, local mesh vault) or "registry" (mesh-peer-registry). */
  identitySource?: string;
  identity_source?: string;
  /** mesh-peer-registry URL (required when identitySource is "registry"). */
  registryUrl?: string;
  registry_url?: string;
  /** Path to the local Ed25519 private key PEM (used with identitySource="registry"). */
  privateKeyPath?: string;
  private_key_path?: string;
}

export interface MeshIdentity {
  id?: string;
  name?: string;
  description?: string;
  role?: string;
  platforms?: Record<string, any>;
  transports?: Record<string, any>;
  webhook_url?: string;
  webhook_secret?: string;
  a2a_url?: string;
  allow_loopback?: boolean;
  [key: string]: any;
}

export interface MeshPeer {
  name: string;
  platform?: string;
  a2a_url?: string;
  webhook_url?: string;
  description?: string;
  role?: string;
}

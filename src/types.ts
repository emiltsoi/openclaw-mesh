/**
 * Typed OpenClaw mesh bridge plugin configuration.
 */
export interface MeshBridgePluginConfig {
  /** mesh agent name this bridge accepts messages for. */
  routingAgent?: string;
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
  /** Private network policy for outbound delivery: "allow", "warn", or "deny". */
  privateNetworkPolicy?: "allow" | "warn" | "deny";
  private_network_policy?: "allow" | "warn" | "deny";
  /** Optional durable outbox directory for failed deliveries (defaults to $OPENCLAW_MESH_OUTBOX_DIR or a workspace path). */
  outboxDir?: string;
  /** Optional path to the audit log (JSON lines). */
  auditLogPath?: string;
  audit_log_path?: string;
  /** Number of outbound webhook delivery attempts. */
  deliveryRetries?: number;
  /** Initial retry backoff in milliseconds. */
  deliveryBackoffMs?: number;
  /** Per-attempt delivery timeout in milliseconds. */
  deliveryTimeoutMs?: number;
  /** mesh-peer-registry URL. Optional; when set, registry tools can sync/publish. */
  registryUrl?: string;
  registry_url?: string;
  /** Path to the local Ed25519 private key PEM. */
  privateKeyPath?: string;
  private_key_path?: string;
  /** Whether to sign the X-Mesh-Timestamp header in outbound payloads. Default true. */
  signTimestamp?: boolean;
  sign_timestamp?: boolean;
  /** Allow insecure http registry URLs. */
  allowInsecureRegistry?: boolean;
  allow_insecure_registry?: boolean;
  /** SHA-256 hex digest of the registry server's certificate SPKI for pinning. */
  registryPin?: string;
  registry_pin?: string;
}

export interface MeshIdentity {
  id?: string;
  name?: string;
  description?: string;
  role?: string;
  /** Canonical platform, matching the identity schema (hermes|openclaw|diploid). */
  platform?: string;
  /** Legacy/compat map of platform-specific config (e.g. telegram). */
  platforms?: Record<string, any>;
  transports?: Record<string, any>;
  public_key?: string;
  webhook_url?: string;
  a2a_url?: string;
  allow_loopback?: boolean;
  [key: string]: any;
}

export interface MeshPeer {
  name: string;
  platform?: string;
  a2a_url?: string;
  webhook_url?: string;
  public_key?: string;
  description?: string;
  role?: string;
}

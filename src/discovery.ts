/**
 * mesh vault discovery and outbound sending.
 *
 * Reads the shared Hermes/OpenClaw mesh vault (one directory per agent with
 * identity.yaml under mesh/agents) and exposes mesh tools to the binding agent.
 * All outbound messages are signed with Ed25519 and verified with the peer's
 * cached public_key. The mesh-peer-registry is only used for explicit
 * mesh_sync / mesh_publish calls.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import os from "node:os";
import { load as yamlLoad, dump as yamlDump } from "js-yaml";
import { fetchWithSsrFGuard, ssrfPolicyFromDangerouslyAllowPrivateNetwork } from "openclaw/plugin-sdk/ssrf-runtime";
import type { MeshBridgePluginConfig, MeshIdentity, MeshPeer } from "./types.js";
import {
  resolveDeliveryBackoffMs,
  resolveDeliveryRetries,
  resolveDeliveryTimeoutMs,
  resolveEffectivePluginConfig,
  resolvePrivateNetworkPolicy,
  resolveRoutingAgent,
  resolveSignTimestamp,
} from "./config.js";
import { validateMeshToken } from "./envelope.js";
import { createDebugLogger } from "./logging.js";
import { mirrorMessage } from "./mirror.js";
import { logAudit } from "./audit.js";
import { appendToOutbox, resolveOutboxDir } from "./outbox.js";
import {
  deregisterPeerOnRegistry,
  getRegistryUrl,
  listPeersFromRegistry,
  loadOrGenerateKeyPair,
  registerPeerOnRegistry,
  resolveMeshExtra,
  resolveTargetFromRegistry,
  signMessage,
} from "./registry.js";

const debugLog = createDebugLogger();

function safeKey(value: any): string {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "-")
    .replace(/^[._-]+|[._-]+$/g, "");
}

// U3: realpath-based vault confinement. Resolves both the target and the vault
// through symlinks (resolving the nearest existing ancestor for not-yet-written
// paths) so a symlink inside the vault pointing outside is rejected for both
// read and write. Equivalent to the spec's "lstat-reject symlinks in vault path
// components (or resolve-then-check)" option — resolve-then-check is used.
function realpathResolve(p: string): string {
  const resolved = path.resolve(p);
  const suffix: string[] = [];
  let probe = resolved;
  while (!fs.existsSync(probe)) {
    const parent = path.dirname(probe);
    if (parent === probe) break;
    suffix.unshift(path.basename(probe));
    probe = parent;
  }
  let realBase: string;
  try {
    realBase = fs.realpathSync(probe);
  } catch {
    realBase = probe;
  }
  return path.join(realBase, ...suffix);
}

function isPathWithinVault(targetPath: string, vaultPath: string): boolean {
  const realTarget = realpathResolve(targetPath);
  const realVault = realpathResolve(vaultPath);
  const prefix = `${realVault}${path.sep}`;
  return realTarget === realVault || realTarget.startsWith(prefix);
}

function throwIfOutsideVault(targetPath: string, vaultPath: string, operation: string): void {
  if (!isPathWithinVault(targetPath, vaultPath)) {
    throw new Error(`${operation} refused: ${targetPath} is outside mesh vault ${vaultPath}`);
  }
}

function normalizeAgentName(name: any): string {
  return String(name || "").trim().toLowerCase();
}

// U4 + U20: shared name validation for registration/vault-path use.
// Rejects empty names (no `|| "emts"` default — the bridge's own identity is
// the trust anchor and must never be overwritten by an empty name), names with
// '.' (e.g. "." writes to the vault root) or whitespace, and anything that is
// not a safe mesh token.
function validateRegisterName(name: any): string {
  const agentName = normalizeAgentName(name);
  if (!agentName) {
    throw new Error("agent name must not be empty");
  }
  if (/[.\s]/.test(agentName)) {
    throw new Error(
      `Invalid agent name: ${JSON.stringify(agentName)}. Must not contain '.' or whitespace`
    );
  }
  validateMeshToken(agentName, "agent name");
  return agentName;
}

function hasPathTraversal(name: string): boolean {
  if (!name) return false;
  return name.includes("..") || name.includes(path.sep) || name.includes("/") || name.includes("\\");
}

function expandHome(input: string): string {
  if (input.startsWith("~")) {
    return input.replace(/^~(?=$|[\\/])/, os.homedir());
  }
  return input;
}

function resolveOpenClawMeshRoot(): string {
  const stateDir = process.env.OPENCLAW_STATE_DIR;
  if (stateDir) {
    return path.resolve(expandHome(stateDir));
  }
  return path.resolve("/tmp/openclaw-mesh");
}

export function resolveMeshVaultPath(
  config?: MeshBridgePluginConfig,
  resolvePath?: (input: string) => string,
): string {
  const resolve = resolvePath || ((input: string) => path.resolve(expandHome(input)));

  function resolveMeshRoot(): string {
    if (config?.meshVaultPath) {
      return resolve(config.meshVaultPath);
    }
    const envVault = process.env.MESH_VAULT_PATH || process.env.A2A_VAULT_PATH;
    if (envVault) {
      return resolve(envVault);
    }

    const hermesHome = process.env.HERMES_HOME;
    if (hermesHome) {
      let root = resolve(hermesHome);

      // If HERMES_HOME points inside /profiles/<name>, strip to the Hermes root.
      const profileMarker = `${path.sep}profiles${path.sep}`;
      const idx = root.indexOf(profileMarker);
      if (idx !== -1) {
        root = root.slice(0, idx);
      }
      if (root.endsWith(`${path.sep}profiles`)) {
        root = path.dirname(root);
      }
      return path.join(root, "fleet");
    }

    return resolveOpenClawMeshRoot();
  }

  return path.join(resolveMeshRoot(), "mesh", "agents");
}

export function resolveLegacyMeshVaultPath(
  config?: MeshBridgePluginConfig,
  resolvePath?: (input: string) => string,
): string {
  const resolve = resolvePath || ((input: string) => path.resolve(expandHome(input)));
  const meshRoot = resolveMeshVaultPath(config, resolvePath);
  return path.join(path.dirname(path.dirname(meshRoot)), "a2a", "agents");
}

/**
 * F1 (2026-08-16 key-framing-interop): canonicalize a public key to PEM-framed
 * SPKI at WRITE time so both substrates (openclaw-mesh and hermes' strict-PEM
 * reader) agree on framing. Accepts PEM and raw base64 SPKI DER (Node's
 * crypto.createPublicKey tolerance; raw base64 is decoded to DER explicitly).
 * Invalid input throws so callers keep their existing rejection flow.
 * Idempotent: PEM in -> PEM out (re-encoding an SPKI key yields SPKI PEM, never
 * double-framed).
 */
export function canonicalizePublicKey(input: string): string {
  let publicKey: crypto.KeyObject;
  try {
    publicKey = crypto.createPublicKey(input);
  } catch {
    // Raw base64 SPKI DER (the migration-bridge format) is not a PEM string;
    // decode to DER bytes and re-parse explicitly. Garbage fails here, so the
    // error propagates to the caller's existing invalid-key rejection.
    publicKey = crypto.createPublicKey({
      key: Buffer.from(input, "base64"),
      format: "der",
      type: "spki",
    });
  }
  return publicKey.export({ type: "spki", format: "pem" }).toString();
}

export function normalizeIdentity(raw: any): MeshIdentity {
  if (!raw || typeof raw !== "object") return {};
  const data: MeshIdentity = { ...raw };

  const transports = data.transports && typeof data.transports === "object" ? { ...data.transports } : {};

  const hermesWebhook = transports.hermes_webhook && typeof transports.hermes_webhook === "object"
    ? transports.hermes_webhook
    : {};
  const a2aRpc = transports.a2a_rpc && typeof transports.a2a_rpc === "object" ? transports.a2a_rpc : {};

  const fallbackWebhookUrl = data.webhook_url || "";
  const fallbackA2aUrl = data.a2a_url || "";

  const webhookUrl = hermesWebhook.url || fallbackWebhookUrl;
  const webhookAuth = hermesWebhook.auth && typeof hermesWebhook.auth === "object" ? hermesWebhook.auth : {};
  let publicKey = webhookAuth.public_key || "";
  if (publicKey) {
    // F1: canonicalize the identity public key to PEM SPKI at write so both
    // substrates (openclaw-mesh + hermes strict-PEM reader) agree on framing.
    publicKey = canonicalizePublicKey(publicKey);
  }

  const a2aUrl = a2aRpc.url || fallbackA2aUrl;

  if (webhookUrl) {
    transports.hermes_webhook = {
      protocol: hermesWebhook.protocol || "hermes-webhook",
      url: webhookUrl,
      auth: { public_key: publicKey },
    };
  }
  if (a2aUrl) {
    transports.a2a_rpc = {
      protocol: a2aRpc.protocol || "google-a2a",
      url: a2aUrl,
      auth: a2aRpc.auth && typeof a2aRpc.auth === "object" ? a2aRpc.auth : { type: "none" },
    };
  }

  data.transports = transports;
  data.webhook_url = webhookUrl;
  data.a2a_url = a2aUrl;

  // Canonicalize the identity key used for lookup and envelope addressing.
  const providedId = data.id ? safeKey(data.id) : "";
  const providedName = data.name ? safeKey(data.name) : "";
  data.id = providedId || providedName;
  data.name = data.id; // use the safe canonical key for routing
  if (providedName && providedName !== data.id) {
    data.display_name = providedName;
  }

  return data;
}

export function loadIdentity(yamlPath: string): MeshIdentity | null {
  if (!fs.existsSync(yamlPath)) return null;
  try {
    const raw = yamlLoad(fs.readFileSync(yamlPath, "utf-8"));
    return normalizeIdentity(raw);
  } catch (e: any) {
    debugLog(`failed to parse ${yamlPath}: ${e.message || e}`);
    return null;
  }
}

export function listPeers(vaultPath: string): MeshPeer[] {
  if (!fs.existsSync(vaultPath) || !fs.statSync(vaultPath).isDirectory()) {
    return [];
  }
  const peers: MeshPeer[] = [];
  const seen = new Set<string>();
  for (const entry of fs.readdirSync(vaultPath)) {
    const dir = path.join(vaultPath, entry);
    // U3: skip entries that resolve outside the vault (symlink escape).
    if (!isPathWithinVault(dir, vaultPath)) continue;
    if (!fs.statSync(dir).isDirectory()) continue;
    const identity = loadIdentity(path.join(dir, "identity.yaml"));
    if (!identity) continue;
    const name = String(identity.id || identity.name || entry).toLowerCase();
    if (seen.has(name)) continue;
    seen.add(name);
    const platforms = identity.platforms && typeof identity.platforms === "object" ? identity.platforms : {};
    const platformNames = Object.keys(platforms).filter((k) => platforms[k]);
    peers.push({
      name,
      platform: platformNames[0] || "unknown",
      a2a_url: identity.a2a_url || identity.transports?.a2a_rpc?.url || "",
      webhook_url: identity.webhook_url || identity.transports?.hermes_webhook?.url || "",
      public_key: identity.public_key || identity.transports?.hermes_webhook?.auth?.public_key || "",
      description: identity.description || identity.role || "",
      role: identity.role || "",
    });
  }
  return peers.sort((a, b) => a.name.localeCompare(b.name));
}

export function resolvePeer(vaultPath: string, name: string): MeshIdentity | null {
  if (!name || !fs.existsSync(vaultPath)) return null;
  const key = name.toLowerCase();
  if (hasPathTraversal(key)) return null;
  const directPath = path.join(vaultPath, key, "identity.yaml");
  // U3: read refused when the path resolves outside the vault.
  if (!isPathWithinVault(path.dirname(directPath), vaultPath)) return null;
  const identity = loadIdentity(directPath);
  if (identity) return identity;
  for (const entry of fs.readdirSync(vaultPath)) {
    const dir = path.join(vaultPath, entry);
    if (!isPathWithinVault(dir, vaultPath)) continue;
    if (!fs.statSync(dir).isDirectory()) continue;
    const candidate = loadIdentity(path.join(dir, "identity.yaml"));
    if (candidate && (String(candidate.id || entry).toLowerCase() === key || String(candidate.name || entry).toLowerCase() === key)) return candidate;
  }
  return null;
}

const OUTBOUND_ACTIONS = new Set(["do", "info"]);
const OUTBOUND_REPLIES = new Set(["yes", "no", "end"]);

export function makeOutboundPayload(
  fromName: string,
  toName: string,
  message: string,
  action = "do",
  reply = "yes",
  id?: string,
  ref?: string,
): string {
  // U11: validate enum values and use validateMeshToken's trimmed return for
  // from/to. Invalid action/reply/ref throw instead of silently interpolating
  // an arbitrary value or dropping the ref.
  const trimmedFrom = validateMeshToken(fromName, "from");
  const trimmedTo = validateMeshToken(toName, "to");
  const trimmedAction = String(action ?? "do").trim();
  const trimmedReply = String(reply ?? "yes").trim();
  if (!OUTBOUND_ACTIONS.has(trimmedAction)) {
    throw new Error(`Invalid action: ${JSON.stringify(trimmedAction)}. Allowed: do, info`);
  }
  if (!OUTBOUND_REPLIES.has(trimmedReply)) {
    throw new Error(`Invalid reply: ${JSON.stringify(trimmedReply)}. Allowed: yes, no, end`);
  }
  const envelopeId = id && typeof id === "string" && id.trim() ? validateMeshToken(id, "envelope id") : `mesh-${crypto.randomUUID()}`;
  let header = `[mesh][v:1][from:${trimmedFrom}][to:${trimmedTo}][id:${envelopeId}][action:${trimmedAction}][reply:${trimmedReply}]`;
  if (ref && typeof ref === "string" && ref.trim()) {
    // U5: loud — never silently drop an invalid ref.
    header += `[ref:${validateMeshToken(ref, "ref")}]`;
  }
  return `${header} ${message}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function statusFromError(err: Error | undefined): number | undefined {
  if (!err) return undefined;
  const match = err.message.match(/\bHTTP\s+(\d{3})\b/);
  if (match) return parseInt(match[1], 10);
  return undefined;
}

function dsnEnabled(api?: any): boolean {
  const explicit = process.env.OPENCLAW_MESH_DSN_ENABLED;
  if (typeof explicit === "string") {
    return ["1", "true", "yes"].includes(explicit.toLowerCase());
  }
  const cfg = api?.pluginConfig || {};
  if (typeof cfg.dsnEnabled === "boolean") return cfg.dsnEnabled;
  return true; // on by default
}

function mapFailureReason(lastError: Error | undefined, status?: number): string {
  if (status !== undefined) {
    if (status === 401 || status === 403) return "unauthorized";
    if (status === 404) return "not-found";
    if (status === 400) return "bad-request";
    if (status === 429) return "rate-limited";
    if (status === 503) return "busy";
    if (status >= 500) return "internal-error";
  }
  const msg = String(lastError?.message || "").toLowerCase();
  if (msg.includes("private") || msg.includes("loopback") || msg.includes("blocked") || msg.includes("ssrf")) {
    return "loopback-blocked";
  }
  if (msg.includes("timeout") || msg.includes("abort")) return "unreachable";
  return "unreachable";
}

export async function sendToAgent(
  fromName: string,
  peer: MeshIdentity,
  message: string,
  action = "do",
  reply = "yes",
  id?: string,
  api?: any,
  ref?: string,
  isDsn = false,
): Promise<{ ok: boolean; status?: number; error?: string; delivery_id?: string; text?: string }> {
  const webhookUrl = peer.webhook_url || peer.transports?.hermes_webhook?.url || "";
  if (!webhookUrl) return { ok: false, error: "peer has no hermes_webhook url" };

  const extra = resolveEffectivePluginConfig(api);
  const { privatePem } = loadOrGenerateKeyPair(fromName, extra);
  const toName = String(peer.id || peer.name || "unknown").toLowerCase();

  let payload: { from: string; text: string };
  try {
    payload = {
      from: fromName,
      text: makeOutboundPayload(fromName, toName, message, action, reply, id, ref),
    };
  } catch (e: any) {
    // U5/U11: invalid ref/action/reply → loud failure, never ok:true.
    return { ok: false, error: e.message || String(e) };
  }
  const body = JSON.stringify(payload, Object.keys(payload).sort());

  const timestamp = String(Math.floor(Date.now() / 1000));
  const signTimestamp = resolveSignTimestamp(api);
  const signedBody = signTimestamp
    ? `${timestamp}\n${body}`
    : body;
  const signature = signMessage(privatePem, Buffer.from(signedBody, "utf-8"));

  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-mesh-timestamp": timestamp,
    "x-mesh-signature": signature,
  };
  if (isDsn) headers["x-mesh-dsn"] = "1";

  const networkPolicy = resolvePrivateNetworkPolicy(api, peer.allow_loopback === true);
  // U14: "warn" means warn — allow the delivery AND log it (it previously
  // behaved as deny).
  const allowLoopback = networkPolicy === "allow" || networkPolicy === "warn";
  if (networkPolicy === "warn") {
    debugLog(`sendToAgent: private network policy is "warn"; allowing and logging for ${webhookUrl}`);
  }
  const policy = ssrfPolicyFromDangerouslyAllowPrivateNetwork(allowLoopback) ?? undefined;
  const retries = resolveDeliveryRetries(api);
  const initialBackoff = resolveDeliveryBackoffMs(api);
  const timeoutMs = resolveDeliveryTimeoutMs(api);

  let lastError: Error | undefined;
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const { response, release } = await fetchWithSsrFGuard({
        url: webhookUrl,
        init: {
          method: "POST",
          headers,
          body,
          signal: AbortSignal.timeout(timeoutMs),
        },
        policy,
        mode: "strict",
        timeoutMs,
        fetchImpl: fetch,
      });

      let deliveryId: string | undefined;
      let bodyText = "";
      try {
        bodyText = await response.text();
        const json = JSON.parse(bodyText);
        deliveryId = json?.delivery_id;
      } catch {
        // ignore non-JSON response body
      }
      await release();

      if (!response.ok) {
        lastError = new Error(`webhook returned HTTP ${response.status}: ${bodyText.slice(0, 200)}`);
      } else {
        return { ok: true, status: response.status, delivery_id: deliveryId, text: payload.text };
      }
    } catch (e: any) {
      lastError = e instanceof Error ? e : new Error(String(e));
    }

    if (attempt < retries - 1) {
      const backoff = initialBackoff * 2 ** attempt;
      debugLog(`sendToAgent: attempt ${attempt + 1}/${retries} failed, retrying in ${backoff}ms`);
      await sleep(backoff);
    }
  }

  // U9: write failed sends to the durable outbox (env/config-overridable dir).
  const outboxDir = resolveOutboxDir(extra);
  appendToOutbox({
    direction: "send",
    ts: Date.now(),
    peer: toName,
    text: payload.text,
    error: lastError?.message || String(lastError),
    status: statusFromError(lastError),
    attempts: retries,
  }, outboxDir);

  const reason = mapFailureReason(lastError, statusFromError(lastError));
  if (!isDsn && dsnEnabled(api)) {
    try {
      // U13: the DSN always goes to the bridge's own agent (the sender that
      // initiated this delivery), never to the intended recipient.
      const dsnTo = fromName;
      const envelopeId = id && typeof id === "string" ? id : `mesh-${crypto.randomUUID()}`;
      await sendDeliveryError(fromName, dsnTo, envelopeId, reason, fromName, toName, ref, api);
    } catch (e: any) {
      debugLog(`sendToAgent: DSN for failed delivery to ${toName} could not be sent: ${e.message || e}`);
    }
  }
  return { ok: false, error: lastError?.message || String(lastError), text: payload.text };
}

export async function sendDeliveryError(
  dsnFrom: string,
  dsnTo: string,
  originalId: string,
  reason: string,
  originalFrom: string,
  originalTo: string,
  originalRef: string | undefined,
  api: any,
): Promise<void> {
  if (!dsnEnabled(api)) return;

  const extra = resolveMeshExtra(api);
  const resolvePath = typeof api.resolvePath === "function" ? api.resolvePath : undefined;
  const vaultPath = resolveMeshVaultPath(extra, resolvePath);
  const legacyVaultPath = resolveLegacyMeshVaultPath(extra, resolvePath);

  let dsnToPeer = resolvePeer(vaultPath, dsnTo) || resolvePeer(legacyVaultPath, dsnTo);

  if (!dsnToPeer && getRegistryUrl(extra)) {
    try {
      const peer = await resolveTargetFromRegistry(dsnTo, extra);
      if (peer) dsnToPeer = peer;
    } catch (e: any) {
      debugLog(`sendDeliveryError: could not resolve target from registry: ${e.message || e}`);
    }
  }

  if (!dsnToPeer) {
    debugLog(`sendDeliveryError: target '${dsnTo}' not found`);
    return;
  }

  const safeReason = String(reason || "unreachable").replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 32);
  const dsnId = `mesh-${crypto.randomUUID()}`;
  const bodyText = `[mesh-dsn][status:failed][reason:${safeReason}] Delivery of message ${originalId} from ${originalFrom} to ${originalTo} failed: ${safeReason}.`;

  try {
    await sendToAgent(dsnFrom, dsnToPeer, bodyText, "info", "no", dsnId, api, originalId, true);
  } catch (e: any) {
    debugLog(`sendDeliveryError: DSN delivery to '${dsnTo}' failed: ${e.message || e}`);
  }
}

export function resolveGatewayUrl(api: any): string {
  const gateway = api?.config?.gateway;
  if (gateway && typeof gateway === "object") {
    const port = gateway.port ?? 18860;
    let host = typeof gateway.bind === "string" ? gateway.bind : "127.0.0.1";
    if (host === "loopback" || host === "0.0.0.0" || host === "*" || host === "::") host = "127.0.0.1";
    const scheme = gateway.scheme || gateway.protocol || "http";
    return `${scheme}://${host}:${port}`;
  }
  return "http://127.0.0.1:18860";
}

export function registerAgent(
  vaultPath: string,
  name: string,
  baseUrl: string,
  options: {
    description?: string;
    role?: string;
    platform?: string;
    kind?: string;
    a2a_url?: string;
    webhook_url?: string;
    public_key?: string;
    allow_loopback?: boolean;
  } = {},
): { ok: boolean; path: string; name: string; public_key: string } {
  // U4: empty name → throw (never default to "emts" — the bridge's own
  // identity.yaml is the trust anchor and must not be overwritten).
  // U20: also validate the name token (no '.', no spaces) and key format.
  const agentName = validateRegisterName(name);
  if (hasPathTraversal(agentName)) {
    throw new Error(`registerAgent refused: agent name '${name}' contains path traversal`);
  }
  // F1: canonicalize a provided public key to PEM-framed SPKI at write. Both
  // PEM and raw base64 SPKI DER are accepted; invalid keys keep the existing
  // rejection flow.
  let publicPem = "";
  if (options.public_key) {
    try {
      publicPem = canonicalizePublicKey(options.public_key);
    } catch {
      throw new Error("registerAgent refused: invalid public_key");
    }
  }
  const agentDir = path.join(vaultPath, agentName);
  throwIfOutsideVault(agentDir, vaultPath, "registerAgent");
  const yamlPath = path.join(agentDir, "identity.yaml");

  const a2aUrl = options.a2a_url || baseUrl;
  const webhookUrl = options.webhook_url || `${baseUrl}/plugins/openclaw-mesh/webhook`;

  const agentBaseName = normalizeAgentName(options.a2a_url ? new URL(a2aUrl).hostname : agentName) || agentName;
  if (!options.public_key) {
    publicPem = loadOrGenerateKeyPair(agentBaseName, options as any).publicPem;
  }

  const identity: any = {
    id: agentName,
    name: agentName,
    kind: options.kind || "openclaw-agent",
    role: options.role || "mesh_peer",
    description: options.description || "OpenClaw mesh peer",
    a2a_url: a2aUrl,
    webhook_url: webhookUrl,
    allow_loopback: options.allow_loopback === true,
    transports: {
      hermes_webhook: {
        protocol: "hermes-webhook",
        url: webhookUrl,
        auth: { public_key: publicPem },
      },
    },
  };

  const platform = options.platform || "openclaw";
  if (platform) {
    identity.platforms = { [platform]: {} };
  }

  fs.mkdirSync(agentDir, { recursive: true });
  fs.writeFileSync(yamlPath, yamlDump(identity), "utf-8");
  try {
    fs.chmodSync(agentDir, 0o700);
    fs.chmodSync(yamlPath, 0o600);
  } catch {
    // Best-effort: ignore filesystems that do not support chmod.
  }
  return { ok: true, path: yamlPath, name: agentName, public_key: publicPem };
}

function textResult(text: string): any {
  return { content: [{ type: "text", text }], details: { result: text } };
}

// Resolve the agent name for the register/deregister/publish tools.
// When the caller omits `name` entirely, fall back to the routing agent
// (documented default). When `name` is provided but empty/whitespace/invalid,
// fail loudly — never silently default to "emts" (U4).
function resolveToolAgentName(name: any, fromName: string): string {
  if (name === undefined || name === null) {
    const fallback = String(fromName || "").trim().toLowerCase();
    if (!fallback) throw new Error("'name' is required");
    return fallback;
  }
  return validateRegisterName(name);
}

export function registerMeshTools(api: any) {
  if (typeof api.registerTool !== "function") {
    debugLog("api.registerTool is not available; skipping mesh tool registration");
    return;
  }

  const extra = resolveMeshExtra(api);
  const effectiveCfg = resolveEffectivePluginConfig(api);
  const meshApi = { pluginConfig: effectiveCfg };
  const resolvePath = typeof api.resolvePath === "function" ? api.resolvePath : undefined;
  const fromName = resolveRoutingAgent(api);
  const registryUrl = getRegistryUrl(extra);

  // Resolve once at registration so users can see which vault path is being used.
  const vaultPath = resolveMeshVaultPath(extra, resolvePath);
  const legacyVaultPath = resolveLegacyMeshVaultPath(extra, resolvePath);
  debugLog(`mesh vault path: ${vaultPath}`);
  debugLog(`legacy mesh vault path: ${legacyVaultPath}`);

  api.registerTool(
    {
      name: "mesh_list",
      label: "List mesh peers",
      description:
        "List all agents in the local mesh vault. Returns names, platforms, a2a_url, and hermes webhook_url for each discoverable peer. Use this before sending a message with mesh_send.",
      parameters: {
        type: "object",
        properties: {},
        required: [],
        additionalProperties: false,
      },
      execute: async () => {
        let peers = [...listPeers(vaultPath), ...listPeers(legacyVaultPath)];
        const seen = new Set<string>();
        peers = peers.filter((p) => {
          if (seen.has(p.name)) return false;
          seen.add(p.name);
          return true;
        });
        return textResult(JSON.stringify({ count: peers.length, peers }, null, 2));
      },
    },
    { name: "mesh_list" },
  );

  api.registerTool(
    {
      name: "mesh_send",
      label: "Send mesh session message",
      description:
        "Send a mesh session message to a named peer's Hermes gateway webhook. The message is Ed25519-signed with this agent's private key; the peer's identity in the mesh vault provides the target URL and public key for verification.",
      parameters: {
        type: "object",
        properties: {
          agent: {
            type: "string",
            description: "Name of the target agent from mesh_list",
          },
          message: {
            type: "string",
            description: "Message payload to send (without the [mesh] envelope header)",
          },
          action: {
            type: "string",
            enum: ["do", "info"],
            description: "CTA action: do (request action) or info (log/acknowledge). For replies, match the incoming message's action.",
            default: "do",
          },
          reply: {
            type: "string",
            enum: ["yes", "no", "end"],
            description: "Whether the sender expects a reply: yes (a reply is expected), no (no reply expected, thread stays open), or end (terminal reply — no reply expected; hermes-mesh expects replies to a terminal message to carry ref=<anchor>). For replies, match the incoming message's reply value.",
            default: "yes",
          },
          id: {
            type: "string",
            description: "mesh envelope id. For replies, reuse the id from the incoming [mesh][...][id:XXX] header to keep the thread.",
          },
          thread_id: {
            type: "string",
            description: "Alias for id. For replies, reuse the incoming message's id.",
          },
          ref: {
            type: "string",
            description: "Optional message ID being replied to. For replies, set this to the incoming message's id.",
          },
        },
        required: ["agent", "message"],
        additionalProperties: false,
      },
      execute: async (_toolCallId: string, params: any) => {
        const { agent, message, action = "do", reply = "yes", id, thread_id, ref } = params || {};
        const envelopeId = id || thread_id;
        if (!agent || typeof agent !== "string") return textResult(JSON.stringify({ error: "'agent' is required" }));
        if (!message || typeof message !== "string") return textResult(JSON.stringify({ error: "'message' is required" }));

        let peer = resolvePeer(vaultPath, agent) || resolvePeer(legacyVaultPath, agent);

        if (!peer && registryUrl) {
          try {
            const regPeer = await resolveTargetFromRegistry(agent, extra);
            if (regPeer) {
              const publicKey = regPeer.transports?.hermes_webhook?.auth?.public_key || "";
              const webhookUrl = regPeer.webhook_url || "";
              const a2aUrl = regPeer.a2a_url || "";
              try {
                registerAgent(vaultPath, regPeer.name || agent, a2aUrl || webhookUrl, {
                  role: regPeer.role,
                  description: regPeer.description,
                  platform: "openclaw",
                  a2a_url: a2aUrl,
                  webhook_url: webhookUrl,
                  public_key: publicKey,
                });
                peer = resolvePeer(vaultPath, agent) || resolvePeer(legacyVaultPath, agent);
              } catch (e: any) {
                debugLog(`mesh_send: could not cache registry peer '${agent}': ${e.message || e}`);
              }
            }
          } catch (e: any) {
            debugLog(`mesh_send: could not resolve target from registry: ${e.message || e}`);
          }
        }

        if (!peer) return textResult(JSON.stringify({ error: `Agent '${agent}' not found in mesh vault or registry` }));

        const result = await sendToAgent(fromName, peer, message, action, reply, envelopeId, meshApi, ref, false);

        logAudit({
          ts: new Date().toISOString(),
          event: "mesh_send",
          agent: fromName,
          target: agent,
          success: result.ok,
          error: result.error,
        }, extra);

        const outboundDisplay = `📤 [Mesh to ${agent}]\n\n${result.text || message}`;
        try {
          await mirrorMessage(extra.mirrorOutbound, outboundDisplay, api);
        } catch (e: any) {
          debugLog(`mesh_send: mirror failed: ${e.message || e}`);
        }

        return textResult(JSON.stringify(result, null, 2));
      },
    },
    { name: "mesh_send" },
  );

  api.registerTool(
    {
      name: "mesh_register",
      label: "Register this agent in the mesh vault",
      description:
        "Write or update this agent's identity.yaml in the shared mesh vault so peers can discover it with mesh_list and send messages with mesh_send. If a mesh-peer-registry URL is configured, also publish the public key. Safe to call repeatedly; it is idempotent.",
      parameters: {
        type: "object",
        properties: {
          name: {
            type: "string",
            description: "Agent name to register (defaults to routingAgent)",
          },
          description: {
            type: "string",
            description: "Human-readable description of this agent",
          },
          role: {
            type: "string",
            description: "Role, e.g. mesh_peer, operator, bridge",
          },
          platform: {
            type: "string",
            description: "Platform, e.g. openclaw or hermes",
            default: "openclaw",
          },
          a2a_url: {
            type: "string",
            description: "Override the A2A URL (defaults to this OpenClaw gateway)",
          },
          webhook_url: {
            type: "string",
            description: "Override the webhook URL (defaults to <a2a_url>/plugins/openclaw-mesh/webhook)",
          },
          public_key: {
            type: "string",
            description: "Override the Ed25519 public key (defaults to a generated keypair)",
          },
          allow_loopback: {
            type: "boolean",
            description: "Allow loopback/private webhook deliveries for this agent",
            default: false,
          },
        },
        required: [],
        additionalProperties: false,
      },
      execute: async (_toolCallId: string, params: any) => {
        const {
          name,
          description,
          role,
          platform,
          a2a_url,
          webhook_url,
          public_key,
          allow_loopback,
        } = params || {};
        let agentName: string;
        try {
          agentName = resolveToolAgentName(name, fromName);
        } catch (e: any) {
          return textResult(JSON.stringify({ ok: false, error: e.message || String(e) }));
        }

        const baseUrl = a2a_url || resolveGatewayUrl(api);
        const targetUrl = webhook_url || `${baseUrl}/plugins/openclaw-mesh/webhook`;

        try {
          const result = registerAgent(vaultPath, agentName, baseUrl, {
            description,
            role,
            platform,
            a2a_url,
            webhook_url: targetUrl,
            public_key,
            allow_loopback,
          });

          let registryResult: { ok: boolean } | undefined;
          if (registryUrl) {
            try {
              registryResult = await registerPeerOnRegistry(agentName, targetUrl, role || "mesh_peer", description || "", extra);
            } catch (e: any) {
              debugLog(`mesh_register: registry publish failed: ${e.message || e}`);
            }
          }

          logAudit({ ts: new Date().toISOString(), event: "mesh_register", agent: agentName, target: "file", success: true }, extra);
          return textResult(JSON.stringify({
            ok: true,
            name: result.name,
            path: result.path,
            public_key: result.public_key,
            registry: registryUrl ? { published: registryResult?.ok ?? false } : undefined,
          }, null, 2));
        } catch (e: any) {
          logAudit({ ts: new Date().toISOString(), event: "mesh_register", agent: agentName, target: "file", success: false, error: e.message || String(e) }, extra);
          return textResult(JSON.stringify({ ok: false, error: e.message || String(e) }));
        }
      },
    },
    { name: "mesh_register" },
  );

  api.registerTool(
    {
      name: "mesh_deregister",
      label: "Deregister this agent from the mesh vault or registry",
      description:
        "Remove this agent's identity from the local mesh vault and, if configured, from the mesh-peer-registry. This is destructive: by default it returns a dry-run preview and only deletes when force=true. The target path is verified to stay inside the mesh vault.",
      parameters: {
        type: "object",
        properties: {
          name: {
            type: "string",
            description: "Agent name to deregister (defaults to routingAgent)",
          },
          force: {
            type: "boolean",
            description: "Confirm destructive recursive deletion of the agent directory",
            default: false,
          },
        },
        required: [],
        additionalProperties: false,
      },
      execute: async (_toolCallId: string, params: any) => {
        const { name, force } = params || {};
        let agentName: string;
        try {
          agentName = resolveToolAgentName(name, fromName);
        } catch (e: any) {
          return textResult(JSON.stringify({ ok: false, error: e.message || String(e) }));
        }

        const agentDir = path.join(vaultPath, agentName);
        if (!isPathWithinVault(agentDir, vaultPath)) {
          return textResult(JSON.stringify({ ok: false, error: `Agent path '${agentDir}' is outside mesh vault` }));
        }
        if (!fs.existsSync(agentDir)) {
          return textResult(JSON.stringify({ ok: false, error: `Agent '${agentName}' not found in mesh vault` }));
        }
        // U8: force check FIRST. A dry-run must be completely non-destructive —
        // no registry deletion, no vault deletion.
        if (force !== true) {
          return textResult(JSON.stringify({
            ok: false,
            dry_run: true,
            warning: "mesh_deregister would recursively delete this agent directory",
            agent: agentName,
            path: agentDir,
            hint: "Set force=true to perform the deletion.",
          }, null, 2));
        }
        if (registryUrl) {
          try {
            await deregisterPeerOnRegistry(agentName, extra);
            logAudit({ ts: new Date().toISOString(), event: "mesh_deregister", agent: agentName, target: "registry", success: true }, extra);
          } catch (e: any) {
            logAudit({ ts: new Date().toISOString(), event: "mesh_deregister", agent: agentName, target: "registry", success: false, error: e.message || String(e) }, extra);
            return textResult(JSON.stringify({ ok: false, error: e.message || String(e) }));
          }
        }
        try {
          fs.rmSync(agentDir, { recursive: true, force: true });
          logAudit({ ts: new Date().toISOString(), event: "mesh_deregister", agent: agentName, target: "file", success: true }, extra);
          return textResult(JSON.stringify({ ok: true, name: agentName, path: agentDir }, null, 2));
        } catch (e: any) {
          logAudit({ ts: new Date().toISOString(), event: "mesh_deregister", agent: agentName, target: "file", success: false, error: e.message || String(e) }, extra);
          return textResult(JSON.stringify({ ok: false, error: e.message || String(e) }));
        }
      },
    },
    { name: "mesh_deregister" }
  );

  api.registerTool(
    {
      name: "mesh_sync",
      label: "Sync peer from registry",
      description: "Fetch a peer (or all peers) from the mesh-peer-registry and write to the local vault.",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string", description: "Peer name to sync; omit to sync all" },
          registry_url: { type: "string", description: "Optional registry URL override" },
        },
        additionalProperties: false,
      },
      execute: async (_toolCallId: string, params: any) => {
        const { name, registry_url } = params || {};
        const effective = { ...extra };
        if (registry_url) effective.registryUrl = registry_url;
        try {
          if (name) {
            const peer = await resolveTargetFromRegistry(name, effective);
            if (!peer) return textResult(JSON.stringify({ error: `peer '${name}' not found in registry` }));
            const publicKey = peer.transports?.hermes_webhook?.auth?.public_key || "";
            const webhookUrl = peer.webhook_url || "";
            const a2aUrl = peer.a2a_url || "";
            const r = registerAgent(vaultPath, name, a2aUrl || webhookUrl, {
              role: peer.role,
              description: peer.description,
              platform: "openclaw",
              a2a_url: a2aUrl,
              webhook_url: webhookUrl,
              public_key: publicKey,
            });
            return textResult(JSON.stringify({ synced: true, name, path: r.path }, null, 2));
          }
          const peers = await listPeersFromRegistry(effective);
          const results: any[] = [];
          for (const regPeer of peers) {
            const a2aUrl = regPeer.a2a_url || "";
            const webhookUrl = regPeer.webhook_url || "";
            const publicKey = regPeer.public_key || "";
            try {
              const r = registerAgent(vaultPath, regPeer.name, a2aUrl || webhookUrl, {
                role: regPeer.role,
                description: regPeer.description,
                platform: "openclaw",
                a2a_url: a2aUrl,
                webhook_url: webhookUrl,
                public_key: publicKey,
              });
              results.push({ synced: true, name: regPeer.name, path: r.path });
            } catch (e: any) {
              results.push({ synced: false, name: regPeer.name, error: e.message || String(e) });
            }
          }
          return textResult(JSON.stringify({ synced: results.filter((r) => r.synced).length, total: results.length, results }, null, 2));
        } catch (e: any) {
          return textResult(JSON.stringify({ error: e.message || String(e) }));
        }
      },
    },
    { name: "mesh_sync" },
  );

  api.registerTool(
    {
      name: "mesh_publish",
      label: "Publish this agent to the registry",
      description: "Publish this agent's webhook URL and Ed25519 public key to the mesh-peer-registry.",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string", description: "Agent name (defaults to routingAgent)" },
          url: { type: "string", description: "Hermes webhook URL" },
          role: { type: "string", default: "mesh_peer" },
          description: { type: "string", default: "" },
          ttl: { type: "integer", description: "Optional TTL in seconds" },
          registry_url: { type: "string", description: "Optional registry URL override" },
        },
        required: ["url"],
        additionalProperties: false,
      },
      execute: async (_toolCallId: string, params: any) => {
        const { name, url, role, description, ttl, registry_url } = params || {};
        let agentName: string;
        try {
          agentName = resolveToolAgentName(name, fromName);
        } catch (e: any) {
          return textResult(JSON.stringify({ ok: false, error: e.message || String(e) }));
        }
        const effective = { ...extra };
        if (registry_url) effective.registryUrl = registry_url;
        try {
          const result = await registerPeerOnRegistry(
            agentName,
            url,
            role || "mesh_peer",
            description || "",
            effective,
            ttl,
          );
          return textResult(JSON.stringify({ published: true, name: agentName, url, registry: result }, null, 2));
        } catch (e: any) {
          return textResult(JSON.stringify({ published: false, error: e.message || String(e) }));
        }
      },
    },
    { name: "mesh_publish" },
  );
}

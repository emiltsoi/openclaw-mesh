/**
 * mesh vault discovery and outbound sending.
 *
 * Reads the shared Hermes/OpenClaw mesh vault (one directory per agent with
 * identity.yaml under mesh/agents) and exposes two tools to the binding agent:
 *  - mesh_list  : list discoverable peers and their transport URLs
 *  - mesh_send  : send a mesh session message to a peer's Hermes webhook with HMAC
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
  resolveSecret,
} from "./config.js";
import { validateMeshToken } from "./envelope.js";
import { createDebugLogger } from "./logging.js";
import { mirrorMessage } from "./mirror.js";
import { logAudit } from "./audit.js";
import {
  deregisterPeerOnRegistry,
  getIdentitySource,
  listPeersFromRegistry,
  registerPeerOnRegistry,
  resolveMeshExtra,
  resolveSenderFromRegistry,
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

function isPathWithinVault(targetPath: string, vaultPath: string): boolean {
  const resolvedTarget = path.resolve(targetPath);
  const resolvedVault = path.resolve(vaultPath);
  const prefix = `${resolvedVault}${path.sep}`;
  return resolvedTarget === resolvedVault || resolvedTarget.startsWith(prefix);
}

function throwIfOutsideVault(targetPath: string, vaultPath: string, operation: string): void {
  if (!isPathWithinVault(targetPath, vaultPath)) {
    throw new Error(`${operation} refused: ${targetPath} is outside mesh vault ${vaultPath}`);
  }
}

function normalizeAgentName(name: any): string {
  return String(name || "").trim().toLowerCase();
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

export function normalizeIdentity(raw: any): MeshIdentity {
  if (!raw || typeof raw !== "object") return {};
  const data: MeshIdentity = { ...raw };

  const transports = data.transports && typeof data.transports === "object" ? { ...data.transports } : {};

  const hermesWebhook = transports.hermes_webhook && typeof transports.hermes_webhook === "object"
    ? transports.hermes_webhook
    : {};
  const a2aRpc = transports.a2a_rpc && typeof transports.a2a_rpc === "object" ? transports.a2a_rpc : {};

  const fallbackWebhookUrl = data.webhook_url || "";
  const fallbackWebhookSecret = data.webhook_secret || "";
  const fallbackA2aUrl = data.a2a_url || "";

  const webhookUrl = hermesWebhook.url || fallbackWebhookUrl;
  const webhookAuth = hermesWebhook.auth && typeof hermesWebhook.auth === "object" ? hermesWebhook.auth : {};
  const webhookSecret = webhookAuth.secret || fallbackWebhookSecret;

  const a2aUrl = a2aRpc.url || fallbackA2aUrl;

  if (webhookUrl) {
    transports.hermes_webhook = {
      protocol: hermesWebhook.protocol || "hermes-webhook",
      url: webhookUrl,
      auth: { type: webhookSecret ? "hmac-sha256" : "none", secret: webhookSecret },
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
  data.webhook_secret = webhookSecret;
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
  throwIfOutsideVault(path.dirname(directPath), vaultPath, "resolvePeer");
  const identity = loadIdentity(directPath);
  if (identity) return identity;
  for (const entry of fs.readdirSync(vaultPath)) {
    const dir = path.join(vaultPath, entry);
    if (!fs.statSync(dir).isDirectory()) continue;
    const candidate = loadIdentity(path.join(dir, "identity.yaml"));
    if (candidate && (String(candidate.id || entry).toLowerCase() === key || String(candidate.name || entry).toLowerCase() === key)) return candidate;
  }
  return null;
}

export function makeOutboundPayload(
  fromName: string,
  toName: string,
  message: string,
  action = "do",
  reply = "yes",
  id?: string,
  ref?: string,
): string {
  const envelopeId = id && typeof id === "string" && id.trim() ? validateMeshToken(id, "envelope id") : `mesh-${crypto.randomUUID()}`;
  validateMeshToken(fromName, "from");
  validateMeshToken(toName, "to");
  let header = `[mesh][v:1][from:${fromName}][to:${toName}][id:${envelopeId}][action:${action}][reply:${reply}]`;
  if (ref && typeof ref === "string" && ref.trim()) {
    try {
      header += `[ref:${validateMeshToken(ref, "ref")}]`;
    } catch {
      // drop an invalid ref rather than failing the whole send
    }
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
  signingMaterial: string,
  peer: MeshIdentity,
  message: string,
  action = "do",
  reply = "yes",
  id?: string,
  api?: any,
  authType = "hmac-sha256",
  ref?: string,
  isDsn = false,
): Promise<{ ok: boolean; status?: number; error?: string; delivery_id?: string; text?: string }> {
  const webhookUrl = peer.webhook_url || peer.transports?.hermes_webhook?.url || "";
  if (!webhookUrl) return { ok: false, error: "peer has no hermes_webhook url" };

  const toName = String(peer.id || peer.name || "unknown").toLowerCase();
  const payload = {
    from: fromName,
    text: makeOutboundPayload(fromName, toName, message, action, reply, id, ref),
  };
  const body = JSON.stringify(payload, Object.keys(payload).sort());

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (isDsn) {
    headers["x-mesh-dsn"] = "1";
  }
  if (authType === "ed25519") {
    headers["x-mesh-timestamp"] = String(Math.floor(Date.now() / 1000));
    headers["x-mesh-signature"] = signMessage(signingMaterial, body);
  } else {
    headers["x-hub-signature-256"] = `sha256=${crypto.createHmac("sha256", signingMaterial).update(body).digest("hex")}`;
  }

  const networkPolicy = resolvePrivateNetworkPolicy(api, peer.allow_loopback === true);
  const allowLoopback = networkPolicy === "allow";
  if (networkPolicy === "warn") {
    debugLog(`sendToAgent: private network policy is "warn"; will block and log for ${webhookUrl}`);
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

  const reason = mapFailureReason(lastError, statusFromError(lastError));
  if (!isDsn && dsnEnabled(api)) {
    try {
      const dsnTo = ref ? toName : fromName;
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
  const identitySource = getIdentitySource(extra);
  const resolvePath = typeof api.resolvePath === "function" ? api.resolvePath : undefined;
  const vaultPath = resolveMeshVaultPath(extra, resolvePath);
  const legacyVaultPath = resolveLegacyMeshVaultPath(extra, resolvePath);

  let dsnFromPeer: MeshIdentity | null = null;
  let dsnToPeer: MeshIdentity | null = null;
  let signingMaterial = "";
  let authType = "hmac-sha256";

  if (identitySource === "registry") {
    try {
      const sender = await resolveSenderFromRegistry(dsnFrom, extra);
      if (!sender) {
        debugLog(`sendDeliveryError: sender '${dsnFrom}' has no Ed25519 key in registry`);
        return;
      }
      signingMaterial = sender.material;
      authType = "ed25519";
    } catch (e: any) {
      debugLog(`sendDeliveryError: could not resolve sender from registry: ${e.message || e}`);
      return;
    }
    try {
      dsnToPeer = await resolveTargetFromRegistry(dsnTo, extra);
    } catch (e: any) {
      debugLog(`sendDeliveryError: could not resolve target from registry: ${e.message || e}`);
      return;
    }
  } else {
    dsnFromPeer = resolvePeer(vaultPath, dsnFrom) || resolvePeer(legacyVaultPath, dsnFrom);
    if (!dsnFromPeer) {
      debugLog(`sendDeliveryError: sender '${dsnFrom}' not found in vault`);
      return;
    }
    const fromTransport = dsnFromPeer.transports?.hermes_webhook || dsnFromPeer.webhook_secret
      ? { auth: { secret: dsnFromPeer.webhook_secret } }
      : undefined;
    signingMaterial = fromTransport?.auth?.secret || dsnFromPeer.webhook_secret || "";
    if (!signingMaterial) {
      debugLog(`sendDeliveryError: sender '${dsnFrom}' has no webhook secret`);
      return;
    }
    dsnToPeer = resolvePeer(vaultPath, dsnTo) || resolvePeer(legacyVaultPath, dsnTo);
  }

  if (!dsnToPeer) {
    debugLog(`sendDeliveryError: target '${dsnTo}' not found`);
    return;
  }

  const safeReason = String(reason || "unreachable").replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 32);
  const dsnId = `mesh-${crypto.randomUUID()}`;
  const bodyText = `[mesh-dsn][status:failed][reason:${safeReason}] Delivery of message ${originalId} from ${originalFrom} to ${originalTo} failed: ${safeReason}.`;

  try {
    await sendToAgent(dsnFrom, signingMaterial, dsnToPeer, bodyText, "info", "no", dsnId, api, authType, originalId, true);
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
  secret: string,
  baseUrl: string,
  options: {
    description?: string;
    role?: string;
    platform?: string;
    kind?: string;
    a2a_url?: string;
    webhook_url?: string;
    webhook_secret?: string;
    allow_loopback?: boolean;
  } = {},
): { ok: boolean; path: string; name: string } {
  const agentName = normalizeAgentName(name) || "emts";
  if (hasPathTraversal(agentName)) {
    throw new Error(`registerAgent refused: agent name '${name}' contains path traversal`);
  }
  const agentDir = path.join(vaultPath, agentName);
  throwIfOutsideVault(agentDir, vaultPath, "registerAgent");
  const yamlPath = path.join(agentDir, "identity.yaml");

  const a2aUrl = options.a2a_url || baseUrl;
  const webhookUrl = options.webhook_url || `${baseUrl}/plugins/openclaw-mesh/webhook`;
  const webhookSecret = options.webhook_secret || secret;

  const identity: any = {
    id: agentName,
    name: agentName,
    kind: options.kind || "openclaw-agent",
    role: options.role || "mesh_peer",
    description: options.description || "OpenClaw mesh peer",
    a2a_url: a2aUrl,
    webhook_url: webhookUrl,
    webhook_secret: webhookSecret,
    allow_loopback: options.allow_loopback === true,
  };

  const platform = options.platform || "openclaw";
  if (platform) {
    identity.platforms = { [platform]: {} };
  }

  if (webhookUrl || webhookSecret) {
    identity.transports = {
      hermes_webhook: {
        protocol: "hermes-webhook",
        url: webhookUrl,
        auth: {
          type: webhookSecret ? "hmac-sha256" : "none",
          secret: webhookSecret,
          header: "X-Hub-Signature-256",
          prefix: "sha256=",
        },
      },
    };
  }

  fs.mkdirSync(agentDir, { recursive: true });
  fs.writeFileSync(yamlPath, yamlDump(identity), "utf-8");
  try {
    fs.chmodSync(agentDir, 0o700);
    fs.chmodSync(yamlPath, 0o600);
  } catch {
    // Best-effort: ignore filesystems that do not support chmod.
  }
  return { ok: true, path: yamlPath, name: agentName };
}

function textResult(text: string): any {
  return { content: [{ type: "text", text }], details: { result: text } };
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
  const fromName = extra.routingAgent || process.env.MESH_AGENT_NAME || process.env.A2A_AGENT_NAME || "emts";
  const identitySource = getIdentitySource(extra);

  // Resolve once at registration so users can see which vault path is being used.
  const vaultPath = resolveMeshVaultPath(extra, resolvePath);
  const legacyVaultPath = resolveLegacyMeshVaultPath(extra, resolvePath);
  debugLog(`mesh vault path: ${vaultPath}`);
  debugLog(`legacy mesh vault path: ${legacyVaultPath}`);

  // Secret used for inbound webhook verification; reused as the default webhook_secret
  // when mesh_register writes this agent's identity.yaml (file backend only).
  let pluginSecret: string | undefined;
  try {
    pluginSecret = resolveSecret(api);
  } catch (e: any) {
    debugLog(`mesh_register: no plugin secret available: ${e.message || e}`);
  }

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
        let peers: MeshPeer[];
        if (identitySource === "registry") {
          try {
            peers = await listPeersFromRegistry(extra);
          } catch (e: any) {
            return textResult(JSON.stringify({ error: e.message || String(e) }));
          }
        } else {
          peers = [...listPeers(vaultPath), ...listPeers(legacyVaultPath)];
          const seen = new Set<string>();
          peers = peers.filter((p) => {
            if (seen.has(p.name)) return false;
            seen.add(p.name);
            return true;
          });
        }
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
        "Send a mesh session message to a named peer's Hermes gateway webhook. The message is HMAC-signed with this agent's own webhook secret (per-agent HMAC); the peer's identity in the mesh vault provides the target URL.",
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
            enum: ["yes", "no"],
            description: "Whether the sender expects a reply. For replies, match the incoming message's reply value.",
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

        let peer: MeshIdentity | null = null;
        let signingMaterial: string;
        let authType = "hmac-sha256";

        if (identitySource === "registry") {
          peer = await resolveTargetFromRegistry(agent, extra);
          if (!peer) return textResult(JSON.stringify({ error: `Agent '${agent}' not found in registry` }));
          const sender = await resolveSenderFromRegistry(fromName, extra);
          if (!sender) return textResult(JSON.stringify({ error: `Sender '${fromName}' has no Ed25519 key` }));
          signingMaterial = sender.material;
          authType = "ed25519";
        } else {
          if (!pluginSecret) {
            return textResult(JSON.stringify({ error: "mesh_send requires a configured plugin secret to sign outbound messages" }));
          }
          peer = resolvePeer(vaultPath, agent) || resolvePeer(legacyVaultPath, agent);
          if (!peer) return textResult(JSON.stringify({ error: `Agent '${agent}' not found in mesh vault` }));
          signingMaterial = pluginSecret;
        }

        const result = await sendToAgent(fromName, signingMaterial, peer, message, action, reply, envelopeId, meshApi, authType, ref, false);

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
        "Write or update this agent's identity.yaml in the shared mesh vault so peers can discover it with mesh_list and send messages with mesh_send. Safe to call repeatedly; it is idempotent. Usually just call mesh_register() with no arguments; the plugin fills in the gateway URL and secret.",
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
          webhook_secret: {
            type: "string",
            description: "Override the webhook secret (defaults to the plugin secret; not recommended)",
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
          webhook_secret,
          allow_loopback,
        } = params || {};
        const agentName = String(name || fromName || "emts").trim().toLowerCase();
        if (!agentName) return textResult(JSON.stringify({ error: "'name' is required" }));

        if (identitySource === "registry") {
          const baseUrl = a2a_url || resolveGatewayUrl(api);
          const targetUrl = webhook_url || `${baseUrl}/plugins/openclaw-mesh/webhook`;
          try {
            await registerPeerOnRegistry(agentName, targetUrl, role || "mesh_peer", description || "", extra);
            logAudit({ ts: new Date().toISOString(), event: "mesh_register", agent: agentName, target: "registry", success: true }, extra);
            return textResult(JSON.stringify({ ok: true, name: agentName, source: "registry" }, null, 2));
          } catch (e: any) {
            logAudit({ ts: new Date().toISOString(), event: "mesh_register", agent: agentName, target: "registry", success: false, error: e.message || String(e) }, extra);
            return textResult(JSON.stringify({ ok: false, error: e.message || String(e) }));
          }
        }

        const secret = typeof webhook_secret === "string" && webhook_secret ? webhook_secret : pluginSecret;
        if (!secret) {
          return textResult(
            JSON.stringify({
              error: "no webhook_secret provided and no plugin secret is configured",
            }),
          );
        }

        try {
          const baseUrl = a2a_url || resolveGatewayUrl(api);
          const result = registerAgent(vaultPath, agentName, secret, baseUrl, {
            description,
            role,
            platform,
            a2a_url,
            webhook_url,
            webhook_secret: secret,
            allow_loopback,
          });
          logAudit({ ts: new Date().toISOString(), event: "mesh_register", agent: agentName, target: "file", success: true }, extra);
          return textResult(JSON.stringify({ ok: true, name: result.name, path: result.path }, null, 2));
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
        "Remove this agent's identity from the local mesh vault or the mesh-peer-registry. This is destructive: by default it returns a dry-run preview and only deletes when force=true. The target path is verified to stay inside the mesh vault.",
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
        const agentName = normalizeAgentName(name) || fromName || "emts";
        if (!agentName) return textResult(JSON.stringify({ error: "'name' is required" }));
        if (hasPathTraversal(agentName)) {
          return textResult(JSON.stringify({ ok: false, error: `Agent name '${agentName}' contains path traversal` }));
        }

        if (identitySource === "registry") {
          try {
            await deregisterPeerOnRegistry(agentName, extra);
            logAudit({ ts: new Date().toISOString(), event: "mesh_deregister", agent: agentName, target: "registry", success: true }, extra);
            return textResult(JSON.stringify({ ok: true, name: agentName, source: "registry" }, null, 2));
          } catch (e: any) {
            logAudit({ ts: new Date().toISOString(), event: "mesh_deregister", agent: agentName, target: "registry", success: false, error: e.message || String(e) }, extra);
            return textResult(JSON.stringify({ ok: false, error: e.message || String(e) }));
          }
        }

        const agentDir = path.join(vaultPath, agentName);
        if (!isPathWithinVault(agentDir, vaultPath)) {
          return textResult(JSON.stringify({ ok: false, error: `Agent path '${agentDir}' is outside mesh vault` }));
        }
        if (!fs.existsSync(agentDir)) {
          return textResult(JSON.stringify({ ok: false, error: `Agent '${agentName}' not found in mesh vault` }));
        }
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
}

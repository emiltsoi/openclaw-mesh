/**
 * Bridge between openclaw-mesh and the optional mesh-peer-registry server.
 *
 * All registry / Ed25519 code lives here so the rest of openclaw-mesh can still
 * run without mesh-peer-registry installed.
 */
import fs from "node:fs";
import https from "node:https";
import tls from "node:tls";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import type { MeshBridgePluginConfig, MeshIdentity, MeshPeer } from "./types.js";
import { createDebugLogger } from "./logging.js";
import { validateMeshToken } from "./envelope.js";
import {
  getRegistryUrl,
  resolveAllowInsecureRegistry,
  resolveEffectivePluginConfig,
  resolveMeshExtra,
  resolveRegistryPin,
} from "./config.js";

const debugLog = createDebugLogger();

export { resolveMeshExtra, getRegistryUrl, resolveEffectivePluginConfig } from "./config.js";

const _peerCache = new Map<string, { data: RegistryPeer | null; expiry: number }>();
const _listCache = new Map<string, { data: RegistryPeer[]; expiry: number }>();
const _keyCache = new Map<string, { data: { privatePem: string; publicPem: string }; expiry: number }>();

const _CACHE_TTL_MS = 30_000;
const _CACHE_MAX_SIZE = 256;

function _cacheEvictIfNeeded(map: Map<string, any>): void {
  if (map.size >= _CACHE_MAX_SIZE) {
    const firstKey = map.keys().next().value as string | undefined;
    if (firstKey !== undefined) map.delete(firstKey);
  }
}

function _cacheGet<T>(map: Map<string, { data: T; expiry: number }>, key: string): T | undefined {
  const entry = map.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expiry) {
    map.delete(key);
    return undefined;
  }
  return entry.data;
}

function _cacheSet<T>(map: Map<string, { data: T; expiry: number }>, key: string, value: T): void {
  _cacheEvictIfNeeded(map);
  map.set(key, { data: value, expiry: Date.now() + _CACHE_TTL_MS });
}

export interface RegistryPeer {
  name: string;
  url: string;
  public_key: string;
  role: string;
  description: string;
}

export interface RegistryClient {
  register(name: string, url: string, role?: string, description?: string, ttl?: number): Promise<{ ok: boolean }>;
  deregister(name: string): Promise<{ ok: boolean }>;
  listPeers(): Promise<RegistryPeer[]>;
  getPeer(name: string): Promise<RegistryPeer | null>;
}

function expandHome(input: string): string {
  if (input.startsWith("~")) {
    return input.replace(/^~(?=$|[\\/])/, os.homedir());
  }
  return input;
}

export function getPrivateKeyPath(name: string, extra?: MeshBridgePluginConfig): string {
  const configured = extra?.privateKeyPath || extra?.private_key_path || "";
  if (configured) {
    return path.resolve(expandHome(configured.toString()));
  }
  // U17: sanitize the name before interpolating it into a filesystem path
  // (`../` and separators would escape the key directory). The token regex
  // rejects path separators and other hostile characters.
  if (!name || typeof name !== "string") {
    throw new Error(`Invalid key name: ${JSON.stringify(name)}`);
  }
  validateMeshToken(name, "key name");
  return path.resolve(expandHome("~/.mesh/keys"), `${name}.pem`);
}

export function canonicalizeJson(obj: Record<string, any>): string {
  const keys = Object.keys(obj).sort();
  const pairs = keys.map((k) => `${JSON.stringify(k)}:${JSON.stringify(obj[k])}`);
  return `{${pairs.join(",")}}`;
}

function ensureKeyDir(keyPath: string): void {
  const dir = path.dirname(keyPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

export function loadOrGenerateKeyPair(
  name: string,
  extra?: MeshBridgePluginConfig,
): { privatePem: string; publicPem: string } {
  const keyPath = getPrivateKeyPath(name, extra);
  const cacheKey = keyPath;
  const cached = _cacheGet(_keyCache, cacheKey);
  if (cached) {
    debugLog(`loadOrGenerateKeyPair: cache hit for ${name}`);
    return cached;
  }

  let result: { privatePem: string; publicPem: string };
  if (fs.existsSync(keyPath)) {
    const privatePem = fs.readFileSync(keyPath, "utf-8");
    const publicKey = crypto.createPublicKey(privatePem);
    const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    result = { privatePem, publicPem };
  } else {
    ensureKeyDir(keyPath);
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });
    result = { privatePem: privateKey, publicPem: publicKey };
  }

  _cacheSet(_keyCache, cacheKey, result);
  return result;
}

function privateKeyFor(name: string, extra?: MeshBridgePluginConfig): crypto.KeyObject {
  const { privatePem } = loadOrGenerateKeyPair(name, extra);
  return crypto.createPrivateKey(privatePem);
}

export function signMessage(privatePem: string, message: Buffer | string): string {
  const data = typeof message === "string" ? Buffer.from(message, "utf-8") : message;
  const privateKey = crypto.createPrivateKey(privatePem);
  return crypto.sign(null, data, privateKey).toString("base64");
}

function _isValidBase64(input: string): boolean {
  if (typeof input !== "string" || input.length === 0) return false;
  return /^[A-Za-z0-9+/=]+$/.test(input);
}

export function verifyMessage(publicPem: string, message: Buffer | string, signatureB64: string): boolean {
  const data = typeof message === "string" ? Buffer.from(message, "utf-8") : message;
  if (!_isValidBase64(signatureB64)) return false;
  let publicKey: crypto.KeyObject;
  try {
    publicKey = crypto.createPublicKey(publicPem);
  } catch {
    return false;
  }
  const signature = Buffer.from(signatureB64, "base64");
  if (signature.length !== 64) return false;
  try {
    return crypto.verify(null, data, publicKey, signature);
  } catch {
    return false;
  }
}

function _spkiHashFromCert(derCert: Buffer): string {
  const cert = new crypto.X509Certificate(derCert);
  const spki = cert.publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return crypto.createHash("sha256").update(spki).digest("hex");
}

function _createPinningAgent(pin: string, allowInsecure: boolean): https.Agent | undefined {
  if (allowInsecure) return undefined;
  const pinValue = pin.toLowerCase().trim();
  if (!pinValue) return undefined;

  return new https.Agent({
    checkServerIdentity: (hostname, cert) => {
      if (cert && (cert as any).raw) {
        const got = _spkiHashFromCert((cert as any).raw);
        if (got !== pinValue) {
          return new Error(`certificate pinning failed: expected ${pinValue.slice(0, 16)}..., got ${got.slice(0, 16)}...`);
        }
      }
      return tls.checkServerIdentity(hostname, cert);
    },
  });
}

export function createRegistryClient(
  agentName: string,
  extra?: MeshBridgePluginConfig,
): RegistryClient {
  const registryUrl = getRegistryUrl(extra);
  if (!registryUrl) {
    throw new Error("registryUrl is required for registry operations");
  }

  const urlLower = registryUrl.toLowerCase();
  // U7: the allowInsecure guard is reachable again — http:// registry URLs are
  // refused unless the operator explicitly opts in.
  const allowInsecure = resolveAllowInsecureRegistry(extra);
  if (urlLower.startsWith("http://") && !allowInsecure) {
    throw new Error("insecure http registry URL; set MESH_REGISTRY_ALLOW_INSECURE=1 or allowInsecureRegistry=true");
  }

  const baseUrl = registryUrl.replace(/\/$/, "");
  const { privatePem, publicPem } = loadOrGenerateKeyPair(agentName, extra);
  const privateKey = crypto.createPrivateKey(privatePem);
  const pin = resolveRegistryPin(extra);
  const httpsAgent = _createPinningAgent(pin, allowInsecure || !pin);

  async function signedFetch(
    method: string,
    path: string,
    payload?: Record<string, any>,
  ): Promise<Response> {
    const url = `${baseUrl}${path}`;
    const body = payload ? canonicalizeJson(payload) : undefined;
    const sig = body ? crypto.sign(null, Buffer.from(body, "utf-8"), privateKey).toString("base64") : "";
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (sig) headers["x-mesh-signature"] = sig;

    const init: any = {
      method,
      headers,
      body,
      signal: AbortSignal.timeout(10_000),
    };
    if (httpsAgent) init.dispatcher = httpsAgent;

    return fetch(url, init);
  }

  async function plainFetch(url: string, init: any = {}): Promise<Response> {
    if (httpsAgent) init.dispatcher = httpsAgent;
    return fetch(url, init);
  }

  return {
    async register(name, url, role = "agent", description = "", ttl?: number): Promise<{ ok: boolean }> {
      const payload: Record<string, any> = {
        name,
        url,
        public_key: publicPem,
        role,
        description,
      };
      if (ttl !== undefined) payload.ttl = ttl;
      const res = await signedFetch("POST", "/register", payload);
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`registry register failed: HTTP ${res.status}: ${text.slice(0, 200)}`);
      }
      return { ok: true };
    },

    async deregister(name): Promise<{ ok: boolean }> {
      const payload = { name, action: "deregister" };
      const body = canonicalizeJson(payload);
      const url = `${baseUrl}/peers/${encodeURIComponent(name)}`;
      const sig = crypto.sign(null, Buffer.from(body, "utf-8"), privateKey).toString("base64");
      const init: any = {
        method: "DELETE",
        headers: { "content-type": "application/json", "x-mesh-signature": sig },
        body,
        signal: AbortSignal.timeout(10_000),
      };
      if (httpsAgent) init.dispatcher = httpsAgent;
      const res = await fetch(url, init);
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`registry deregister failed: HTTP ${res.status}: ${text.slice(0, 200)}`);
      }
      return { ok: true };
    },

    async listPeers(): Promise<RegistryPeer[]> {
      const cacheKey = `${baseUrl}:peers`;
      const cached = _cacheGet(_listCache, cacheKey);
      if (cached) {
        debugLog(`listPeers: cache hit for ${baseUrl}`);
        return cached;
      }
      const res = await plainFetch(`${baseUrl}/peers`, {
        method: "GET",
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) return [];
      const json: any = await res.json();
      if (!Array.isArray(json)) return [];
      const peers = json.map((p: any) => ({
        name: p.name || "",
        url: p.url || "",
        public_key: p.public_key || "",
        role: p.role || "agent",
        description: p.description || "",
      }));
      _cacheSet(_listCache, cacheKey, peers);
      return peers;
    },

    async getPeer(name): Promise<RegistryPeer | null> {
      const cacheKey = `${baseUrl}:peer:${name}`;
      const cached = _cacheGet(_peerCache, cacheKey);
      if (cached !== undefined) {
        debugLog(`getPeer: cache hit for ${name}`);
        return cached;
      }
      const res = await plainFetch(`${baseUrl}/peers/${encodeURIComponent(name)}`, {
        method: "GET",
        signal: AbortSignal.timeout(10_000),
      });
      if (res.status === 404) {
        _cacheSet(_peerCache, cacheKey, null);
        return null;
      }
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`registry getPeer failed: HTTP ${res.status}: ${text.slice(0, 200)}`);
      }
      const p: any = await res.json();
      const peer: RegistryPeer = {
        name: p.name || "",
        url: p.url || "",
        public_key: p.public_key || "",
        role: p.role || "agent",
        description: p.description || "",
      };
      _cacheSet(_peerCache, cacheKey, peer);
      return peer;
    },
  };
}

export async function resolveTargetFromRegistry(
  name: string,
  extra?: MeshBridgePluginConfig,
): Promise<MeshIdentity | null> {
  const agentName = process.env.MESH_AGENT_NAME || process.env.A2A_AGENT_NAME || "emts";
  const client = createRegistryClient(agentName, extra);
  const peer = await client.getPeer(name);
  if (!peer) return null;
  return {
    id: peer.name,
    name: peer.name,
    description: peer.description,
    role: peer.role,
    webhook_url: peer.url,
    a2a_url: peer.url,
    transports: {
      hermes_webhook: {
        protocol: "hermes-webhook",
        url: peer.url,
        auth: { public_key: peer.public_key },
      },
    },
  };
}

export async function resolveSenderFromRegistry(
  name: string,
  extra?: MeshBridgePluginConfig,
): Promise<{ material: string; authType: string; publicPem: string } | null> {
  const { privatePem, publicPem } = loadOrGenerateKeyPair(name, extra);
  return { material: privatePem, authType: "ed25519", publicPem };
}

export async function listPeersFromRegistry(extra?: MeshBridgePluginConfig): Promise<MeshPeer[]> {
  const agentName = process.env.MESH_AGENT_NAME || process.env.A2A_AGENT_NAME || "emts";
  const client = createRegistryClient(agentName, extra);
  const peers = await client.listPeers();
  return peers.map((p) => ({
    name: p.name,
    platform: "unknown",
    a2a_url: p.url,
    webhook_url: p.url,
    public_key: p.public_key,
    description: p.description,
    role: p.role,
  }));
}

export async function registerPeerOnRegistry(
  name: string,
  url: string,
  role: string,
  description: string,
  extra?: MeshBridgePluginConfig,
  ttl?: number,
): Promise<{ ok: boolean }> {
  const agentName = process.env.MESH_AGENT_NAME || process.env.A2A_AGENT_NAME || "emts";
  const client = createRegistryClient(agentName, extra);
  return client.register(name, url, role, description, ttl);
}

export async function deregisterPeerOnRegistry(
  name: string,
  extra?: MeshBridgePluginConfig,
): Promise<{ ok: boolean }> {
  const agentName = process.env.MESH_AGENT_NAME || process.env.A2A_AGENT_NAME || "emts";
  const client = createRegistryClient(agentName, extra);
  return client.deregister(name);
}

export async function verifyEd25519Signature(
  headers: Record<string, string | string[] | undefined>,
  body: Buffer,
  fromName: string,
  extra?: MeshBridgePluginConfig,
  getPublicKey?: (name: string) => string | null | Promise<string | null>,
): Promise<boolean> {
  const timestampStr = headers["x-mesh-timestamp"];
  const sig = headers["x-mesh-signature"];
  if (!sig || Array.isArray(sig) || !timestampStr || Array.isArray(timestampStr)) {
    return false;
  }
  const ts = Number(timestampStr);
  if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > 300) {
    return false;
  }

  let publicPem = "";
  if (getPublicKey) {
    const resolved = await getPublicKey(fromName);
    if (resolved) publicPem = resolved;
  }

  if (!publicPem) {
    const registryUrl = getRegistryUrl(extra);
    if (!registryUrl) return false;
    const client = createRegistryClient(process.env.MESH_AGENT_NAME || process.env.A2A_AGENT_NAME || "emts", extra);
    const peer = await client.getPeer(fromName);
    if (!peer) return false;
    publicPem = peer.public_key;
  }

  if (!publicPem) return false;

  // U12: require a timestamp-covered signature. The body-only fallback
  // accepted an unauthenticated timestamp (an attacker could replay the same
  // body with a fresh ts). COMPAT NOTE: legacy peers with signTimestamp:false
  // must migrate to signing `"<ts>\n<body>"` — we own both ends, so the
  // fallback is dropped rather than kept.
  const timestamped = Buffer.concat([Buffer.from(`${timestampStr}\n`, "utf-8"), body]);
  return verifyMessage(publicPem, timestamped, sig);
}

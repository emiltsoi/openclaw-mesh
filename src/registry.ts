/**
 * Bridge between openclaw-mesh and the optional mesh-peer-registry server.
 *
 * All registry / Ed25519 code lives here so the rest of openclaw-mesh can still
 * run without mesh-peer-registry installed (identity_source stays "file").
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import type { MeshBridgePluginConfig, MeshIdentity, MeshPeer } from "./types.js";
import { createDebugLogger } from "./logging.js";

const debugLog = createDebugLogger();

export interface RegistryPeer {
  name: string;
  url: string;
  public_key: string;
  role: string;
  description: string;
}

export interface RegistryClient {
  register(name: string, url: string, role?: string, description?: string): Promise<{ ok: boolean }>;
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

export function resolveMeshExtra(api: { pluginConfig?: MeshBridgePluginConfig; config?: any }): MeshBridgePluginConfig {
  const pluginCfg = api?.pluginConfig || {};
  const fullCfg = api?.config?.plugins?.entries?.["openclaw-mesh"]?.config ?? {};
  return { ...fullCfg, ...pluginCfg };
}

export function getIdentitySource(extra?: MeshBridgePluginConfig): string {
  return (extra?.identitySource || extra?.identity_source || "file").toString().toLowerCase();
}

export function getRegistryUrl(extra?: MeshBridgePluginConfig): string {
  return (extra?.registryUrl || extra?.registry_url || "").toString();
}

export function getPrivateKeyPath(name: string, extra?: MeshBridgePluginConfig): string {
  const configured = extra?.privateKeyPath || extra?.private_key_path || "";
  if (configured) {
    return path.resolve(expandHome(configured.toString()));
  }
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
  if (fs.existsSync(keyPath)) {
    const privatePem = fs.readFileSync(keyPath, "utf-8");
    const publicKey = crypto.createPublicKey(privatePem);
    const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    return { privatePem, publicPem };
  }

  ensureKeyDir(keyPath);
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });
  return { privatePem: privateKey, publicPem: publicKey };
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

export function verifyMessage(publicPem: string, message: Buffer | string, signatureB64: string): boolean {
  const data = typeof message === "string" ? Buffer.from(message, "utf-8") : message;
  const publicKey = crypto.createPublicKey(publicPem);
  const signature = Buffer.from(signatureB64, "base64");
  return crypto.verify(null, data, publicKey, signature);
}

export function createRegistryClient(
  agentName: string,
  extra?: MeshBridgePluginConfig,
): RegistryClient {
  const registryUrl = getRegistryUrl(extra);
  if (!registryUrl) {
    throw new Error("registryUrl is required for identity_source=registry");
  }
  const baseUrl = registryUrl.replace(/\/$/, "");
  const { privatePem, publicPem } = loadOrGenerateKeyPair(agentName, extra);
  const privateKey = crypto.createPrivateKey(privatePem);

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

    const res = await fetch(url, {
      method,
      headers,
      body,
      signal: AbortSignal.timeout(10_000),
    });
    return res;
  }

  return {
    async register(name, url, role = "agent", description = ""): Promise<{ ok: boolean }> {
      const res = await signedFetch("POST", "/register", {
        name,
        url,
        public_key: publicPem,
        role,
        description,
      });
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
      const res = await fetch(url, {
        method: "DELETE",
        headers: { "content-type": "application/json", "x-mesh-signature": sig },
        body,
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`registry deregister failed: HTTP ${res.status}: ${text.slice(0, 200)}`);
      }
      return { ok: true };
    },

    async listPeers(): Promise<RegistryPeer[]> {
      const res = await fetch(`${baseUrl}/peers`, {
        method: "GET",
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) return [];
      const json: any = await res.json();
      if (!Array.isArray(json)) return [];
      return json.map((p) => ({
        name: p.name || "",
        url: p.url || "",
        public_key: p.public_key || "",
        role: p.role || "agent",
        description: p.description || "",
      }));
    },

    async getPeer(name): Promise<RegistryPeer | null> {
      const res = await fetch(`${baseUrl}/peers/${encodeURIComponent(name)}`, {
        method: "GET",
        signal: AbortSignal.timeout(10_000),
      });
      if (res.status === 404) return null;
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`registry getPeer failed: HTTP ${res.status}: ${text.slice(0, 200)}`);
      }
      const p: any = await res.json();
      return {
        name: p.name || "",
        url: p.url || "",
        public_key: p.public_key || "",
        role: p.role || "agent",
        description: p.description || "",
      };
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
    transports: {
      hermes_webhook: {
        protocol: "hermes-webhook",
        url: peer.url,
        auth: { type: "ed25519", public_key: peer.public_key },
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
): Promise<{ ok: boolean }> {
  const agentName = process.env.MESH_AGENT_NAME || process.env.A2A_AGENT_NAME || "emts";
  const client = createRegistryClient(agentName, extra);
  return client.register(name, url, role, description);
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

  const registryUrl = getRegistryUrl(extra);
  if (!registryUrl) return false;

  const agentName = process.env.MESH_AGENT_NAME || process.env.A2A_AGENT_NAME || "emts";
  const client = createRegistryClient(agentName, extra);
  const peer = await client.getPeer(fromName);
  if (!peer) return false;

  return verifyMessage(peer.public_key, body, sig);
}

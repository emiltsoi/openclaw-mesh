/// <reference types="node" />
import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { dump as yamlDump } from "js-yaml";
import { parseMeshEnvelope, stripEnvelope } from "../src/envelope.js";
import {
  canonicalizePublicKey,
  listPeers,
  makeOutboundPayload,
  normalizeIdentity,
  registerAgent,
  resolveGatewayUrl,
  resolveMeshVaultPath,
  resolvePeer,
  sendToAgent,
} from "../src/discovery.js";
import { resolveSessionIdFromKey } from "../src/injector.js";
import { resolveTelegramConfig } from "../src/mirror.js";
import { signMessage, verifyMessage } from "../src/registry.js";

function generateKeyPair() {
  return crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

describe("parseMeshEnvelope", () => {
  it("parses a complete envelope", () => {
    const env = parseMeshEnvelope("[mesh][from:agent0][to:emts][id:123][action:do][reply:yes] Hello");
    assert.equal(env?.from, "agent0");
    assert.equal(env?.to, "emts");
    assert.equal(env?.id, "123");
    assert.equal(env?.action, "do");
    assert.equal(env?.reply, "yes");
  });

  it("returns defaults for missing optional fields", () => {
    const env = parseMeshEnvelope("[mesh][from:bot][id:abc]");
    assert.equal(env?.from, "bot");
    assert.equal(env?.to, "emts");
    assert.equal(env?.id, "abc");
    assert.equal(env?.action, "info");
    assert.equal(env?.reply, "no");
  });

  it("returns null for non-mesh text", () => {
    assert.equal(parseMeshEnvelope("hello"), null);
  });

  it("ignores invalid action and reply values", () => {
    const env = parseMeshEnvelope("[mesh][action:bad][reply:maybe]");
    assert.equal(env?.action, "info");
    assert.equal(env?.reply, "no");
  });

  it("parses ref", () => {
    const env = parseMeshEnvelope("[mesh][from:agent0][to:emts][id:123][action:do][reply:yes][ref:parent-456] Hello");
    assert.equal(env?.ref, "parent-456");
  });

  it("rejects an invalid ref loudly (U5)", () => {
    assert.throws(
      () => parseMeshEnvelope("[mesh][from:agent0][to:emts][id:123][ref:bad ref!] Hello"),
      /Invalid ref/
    );
  });

  it("marks DSN messages", () => {
    const env = parseMeshEnvelope("[mesh][from:agent0][to:emts][id:123][action:info][reply:no] [mesh-dsn][status:failed][reason:unreachable] Delivery failed.");
    assert.equal(env?.dsn, true);
  });
});

describe("stripEnvelope", () => {
  it("removes the envelope header", () => {
    assert.equal(stripEnvelope("[mesh][from:agent0] Hello"), "Hello");
  });

  it("preserves brackets inside the message", () => {
    assert.equal(stripEnvelope("[mesh][from:agent0] Reply: [ok] done"), "Reply: [ok] done");
  });

  it("returns input unchanged if no header", () => {
    assert.equal(stripEnvelope("just text"), "just text");
  });
});

describe("resolveSessionIdFromKey", () => {
  it("extracts session id from agent:agentId:sessionId", () => {
    assert.equal(resolveSessionIdFromKey("agent:main:main"), "main");
  });

  it("falls back to second part for agent:sessionId", () => {
    assert.equal(resolveSessionIdFromKey("agent:foo"), "foo");
  });

  it("returns the key for non-agent keys", () => {
    assert.equal(resolveSessionIdFromKey("custom-key"), "custom-key");
  });

  it("defaults to main for empty input", () => {
    assert.equal(resolveSessionIdFromKey(""), "main");
  });
});

describe("resolveTelegramConfig", () => {
  it("prefers explicit chatId", () => {
    const api = { config: { channels: { telegram: { botToken: "token", chatId: "123", allowFrom: ["456"] } } } };
    assert.deepEqual(resolveTelegramConfig(api), { botToken: "token", chatId: "123" });
  });

  it("falls back to allowFrom first entry", () => {
    const api = { config: { channels: { telegram: { botToken: "token", allowFrom: ["456", "789"] } } } };
    assert.deepEqual(resolveTelegramConfig(api), { botToken: "token", chatId: "456" });
  });

  it("falls back to groupAllowFrom", () => {
    const api = { config: { channels: { telegram: { botToken: "token", groupAllowFrom: ["grp"] } } } };
    assert.deepEqual(resolveTelegramConfig(api), { botToken: "token", chatId: "grp" });
  });

  it("returns empty config when missing", () => {
    assert.deepEqual(resolveTelegramConfig({ config: {} }), { botToken: "", chatId: "" });
  });
});

function setupVault() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-vault-"));
  const agentsRoot = path.join(tmp, "mesh", "agents");
  const agent0Dir = path.join(agentsRoot, "agent0");
  const emtsDir = path.join(agentsRoot, "emts");
  fs.mkdirSync(agent0Dir, { recursive: true });
  fs.mkdirSync(emtsDir, { recursive: true });

  const { publicKey: emtsPublic } = generateKeyPair();

  const agent0Identity = {
    id: "agent0",
    name: "Agent Zero",
    description: "Hermes agent zero",
    role: "operator",
    platforms: { telegram: { bot_token: "bot0", default_chat_id: "chat0" } },
    allow_loopback: true,
    transports: {
      hermes_webhook: {
        url: "http://127.0.0.1:8645/mesh/receive",
        auth: { public_key: emtsPublic },
      },
      a2a_rpc: { url: "http://127.0.0.1:41808/a2a", auth: { type: "none" } },
    },
  };

  const emtsIdentity = {
    id: "emts",
    name: "emts",
    description: "OpenClaw bridge",
    role: "bridge",
    allow_loopback: true,
    transports: {
      hermes_webhook: {
        url: "http://127.0.0.1:8080/plugins/openclaw-mesh/webhook",
        auth: { public_key: emtsPublic },
      },
    },
  };

  fs.writeFileSync(path.join(agent0Dir, "identity.yaml"), yamlDump(agent0Identity));
  fs.writeFileSync(path.join(emtsDir, "identity.yaml"), yamlDump(emtsIdentity));
  return { tmp, publicKey: emtsPublic };
}

describe("resolveMeshVaultPath", () => {
  // Isolate the mesh env vars so ambient HERMES_HOME / MESH_VAULT_PATH /
  // A2A_VAULT_PATH values from the surrounding shell cannot leak into these tests.
  const MESH_ENV_KEYS = ["MESH_VAULT_PATH", "A2A_VAULT_PATH", "HERMES_HOME", "OPENCLAW_STATE_DIR"];
  const savedEnv = new Map<string, string | undefined>();
  beforeEach(() => {
    savedEnv.clear();
    for (const key of MESH_ENV_KEYS) {
      savedEnv.set(key, process.env[key]);
      delete process.env[key];
    }
  });
  afterEach(() => {
    for (const key of MESH_ENV_KEYS) {
      const value = savedEnv.get(key);
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it("defaults to /tmp/openclaw-mesh/mesh/agents when no overrides are set", () => {
    const expected = path.join("/tmp/openclaw-mesh", "mesh", "agents");
    assert.equal(resolveMeshVaultPath(), expected);
  });

  it("uses $OPENCLAW_STATE_DIR/mesh when set", () => {
    process.env.OPENCLAW_STATE_DIR = "/tmp/oc-state";
    try {
      const expected = path.join("/tmp/oc-state", "mesh", "agents");
      assert.equal(resolveMeshVaultPath(), expected);
    } finally {
      delete process.env.OPENCLAW_STATE_DIR;
    }
  });

  it("treats pluginConfig.meshVaultPath as the mesh root", () => {
    assert.equal(
      resolveMeshVaultPath({ meshVaultPath: "/tmp/custom" }),
      path.join("/tmp/custom", "mesh", "agents"),
    );
  });

  it("treats MESH_VAULT_PATH as the mesh root and expands ~", () => {
    delete process.env.HERMES_HOME;
    delete process.env.OPENCLAW_STATE_DIR;
    process.env.MESH_VAULT_PATH = "~/a2a-mesh";
    try {
      assert.equal(
        resolveMeshVaultPath(),
        path.join(os.homedir(), "a2a-mesh", "mesh", "agents"),
      );
    } finally {
      delete process.env.MESH_VAULT_PATH;
    }
  });

  it("strips /profiles/<name> from HERMES_HOME", () => {
    delete process.env.OPENCLAW_STATE_DIR;
    process.env.HERMES_HOME = "/home/user/.hermes/profiles/agent0";
    try {
      const expected = path.join("/home/user/.hermes", "fleet", "mesh", "agents");
      assert.equal(resolveMeshVaultPath(), expected);
    } finally {
      delete process.env.HERMES_HOME;
    }
  });
});

describe("normalizeIdentity", () => {
  it("extracts transports and falls back to top-level webhook fields", () => {
    const { publicKey } = generateKeyPair();
    const raw = {
      name: "agent0",
      webhook_url: "http://old",
      transports: {
        hermes_webhook: {
          url: "http://new",
          auth: { public_key: publicKey },
        },
      },
    };
    const identity = normalizeIdentity(raw);
    assert.equal(identity.webhook_url, "http://new");
    assert.equal(identity.transports?.hermes_webhook?.auth?.public_key, canonicalizePublicKey(publicKey));
  });
});

describe("listPeers", () => {
  it("lists agents without exposing secrets", () => {
    const { tmp, publicKey } = setupVault();
    try {
      const peers = listPeers(path.join(tmp, "mesh", "agents"));
      assert.equal(peers.length, 2);
      const agent0 = peers.find((p) => p.name === "agent0");
      assert.ok(agent0);
      assert.equal(agent0?.webhook_url, "http://127.0.0.1:8645/mesh/receive");
      assert.equal(agent0?.a2a_url, "http://127.0.0.1:41808/a2a");
      assert.equal(agent0?.public_key, publicKey);
      assert.equal((agent0 as any).webhook_secret, undefined);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("resolvePeer", () => {
  it("finds a peer and includes the public key", () => {
    const { tmp, publicKey } = setupVault();
    try {
      const peer = resolvePeer(path.join(tmp, "mesh", "agents"), "agent0");
      assert.ok(peer);
      assert.equal(peer?.name, "agent0");
      assert.equal(peer?.transports?.hermes_webhook?.auth?.public_key, publicKey);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("makeOutboundPayload", () => {
  it("builds an mesh envelope from the bridge to a peer", () => {
    const payload = makeOutboundPayload("emts", "agent0", "ping");
    assert.ok(payload.startsWith("[mesh][v:1][from:emts][to:agent0]"));
    assert.ok(payload.includes("[action:do][reply:yes] ping"));
  });

  it("includes a ref for replies", () => {
    const payload = makeOutboundPayload("emts", "agent0", "pong", "info", "no", "child-789", "parent-456");
    assert.ok(payload.includes("[id:child-789]"));
    assert.ok(payload.includes("[ref:parent-456]"));
  });
});

describe("sendToAgent", () => {
  it("Ed25519-signs and POSTs the outbound payload", async () => {
    const { tmp, publicKey } = setupVault();
    const captured: { url?: string; headers?: Record<string, string>; body?: string } = {};

    const server = http.createServer((req, res) => {
      let body = "";
      req.setEncoding("utf-8");
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        captured.url = `http://127.0.0.1:${(server.address() as { port: number }).port}${req.url}`;
        captured.headers = req.headers as Record<string, string>;
        captured.body = body;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: "ok" }));
      });
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const serverUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}/mesh/receive`;

    // Generate a sender key and point both the local keystore and the peer's
    // expected public key at it so the round-trip verifies deterministically.
    const keyFile = path.join(tmp, "emts.pem");
    const { privateKey } = generateKeyPair();
    fs.writeFileSync(keyFile, privateKey, { mode: 0o600 });
    const senderPublic = crypto.createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();
    fs.writeFileSync(path.join(tmp, "mesh", "agents", "agent0", "identity.yaml"), yamlDump({
      id: "agent0",
      name: "Agent Zero",
      role: "operator",
      allow_loopback: true,
      transports: {
        hermes_webhook: {
          url: serverUrl,
          auth: { public_key: senderPublic },
        },
      },
    }));

    try {
      const peer = resolvePeer(path.join(tmp, "mesh", "agents"), "agent0")!;
      const extra = { privateKeyPath: keyFile };
      const result = await sendToAgent("emts", peer, "ping", "info", "no", undefined, { pluginConfig: extra });
      assert.equal(result.ok, true);
      assert.ok(captured.body, "request body was captured");
      assert.equal(captured.url, serverUrl);

      const body = captured.body;
      const payload = JSON.parse(body);
      assert.equal(payload.from, "emts");
      assert.ok(payload.text.startsWith("[mesh][v:1][from:emts][to:agent0]"));
      assert.ok(payload.text.includes("[action:info][reply:no] ping"));

      const headers = captured.headers;
      const sigHeader = headers?.["x-mesh-signature"];
      assert.ok(sigHeader, "x-mesh-signature header present");
      const tsHeader = headers?.["x-mesh-timestamp"];
      assert.ok(tsHeader, "x-mesh-timestamp header present");

      const expected = signMessage(privateKey, Buffer.from(`${tsHeader}\n${body}`, "utf-8"));
      assert.equal(sigHeader, expected);
      assert.equal(verifyMessage(senderPublic, Buffer.from(`${tsHeader}\n${body}`, "utf-8"), sigHeader), true);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("resolveGatewayUrl", () => {
  it("derives gateway URL from api.config.gateway", () => {
    assert.equal(
      resolveGatewayUrl({ config: { gateway: { port: 18860, bind: "loopback" } } }),
      "http://127.0.0.1:18860",
    );
  });

  it("normalizes 0.0.0.0 to 127.0.0.1", () => {
    assert.equal(
      resolveGatewayUrl({ config: { gateway: { port: 8080, bind: "0.0.0.0", scheme: "http" } } }),
      "http://127.0.0.1:8080",
    );
  });

  it("falls back to 127.0.0.1:18860 when gateway config is missing", () => {
    assert.equal(resolveGatewayUrl({}), "http://127.0.0.1:18860");
  });
});

describe("registerAgent", () => {
  it("writes an identity.yaml that mesh_list can discover", () => {
    const vault = fs.mkdtempSync(path.join(os.tmpdir(), "a2a-register-"));
    try {
      const agentsDir = path.join(vault, "mesh", "agents");
      const result = registerAgent(agentsDir, "newbie", "http://127.0.0.1:18860", {
        description: "Test agent",
        role: "operator",
        platform: "openclaw",
      });
      assert.equal(result.name, "newbie");
      assert.ok(fs.existsSync(result.path));
      assert.ok(result.public_key.includes("BEGIN PUBLIC KEY"));

      const peers = listPeers(agentsDir);
      const newbie = peers.find((p) => p.name === "newbie");
      assert.ok(newbie);
      assert.equal(newbie?.platform, "openclaw");
      assert.equal(newbie?.a2a_url, "http://127.0.0.1:18860");
      assert.equal(newbie?.webhook_url, "http://127.0.0.1:18860/plugins/openclaw-mesh/webhook");
      assert.equal(newbie?.role, "operator");
      assert.equal(newbie?.description, "Test agent");
      assert.equal((newbie as any).webhook_secret, undefined);
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });

  it("uses custom a2a_url and webhook_url when provided", () => {
    const vault = fs.mkdtempSync(path.join(os.tmpdir(), "a2a-register-"));
    try {
      const agentsDir = path.join(vault, "mesh", "agents");
      registerAgent(agentsDir, "custom", "http://default", {
        a2a_url: "http://custom/a2a",
        webhook_url: "http://custom/webhook",
      });
      const peer = resolvePeer(agentsDir, "custom")!;
      assert.equal(peer?.a2a_url, "http://custom/a2a");
      assert.equal(peer?.webhook_url, "http://custom/webhook");
      assert.ok(peer?.transports?.hermes_webhook?.auth?.public_key?.includes("BEGIN PUBLIC KEY"));
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });
});

describe("key framing interop (F1)", () => {
  function rawSpkiBase64() {
    const { publicKey } = generateKeyPair();
    return crypto.createPublicKey(publicKey).export({ type: "spki", format: "der" }).toString("base64");
  }

  it("AC-1.1: register with raw base64 SPKI public key → identity.yaml public_key is PEM-framed", () => {
    const vault = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-f1-"));
    try {
      const agentsDir = path.join(vault, "mesh", "agents");
      const raw = rawSpkiBase64();
      const result = registerAgent(agentsDir, "newbie", "http://default", { public_key: raw });
      const yamlText = fs.readFileSync(result.path, "utf-8");
      assert.match(yamlText, /BEGIN PUBLIC KEY/);
      assert.match(yamlText, /END PUBLIC KEY/);
      assert.ok(result.public_key.includes("BEGIN PUBLIC KEY"));
      assert.ok(result.public_key.includes("END PUBLIC KEY"));
      // same key material, new framing
      assert.equal(
        crypto.createPublicKey(result.public_key).export({ type: "spki", format: "der" }).toString("base64"),
        raw,
      );
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });

  it("AC-1.1b: discovery-handle write (normalizeIdentity :202) with raw input → PEM in the written entry", () => {
    const raw = rawSpkiBase64();
    const identity = normalizeIdentity({
      name: "agent0",
      webhook_url: "http://old",
      transports: {
        hermes_webhook: {
          url: "http://new",
          auth: { public_key: raw },
        },
      },
    });
    const pub = identity.transports?.hermes_webhook?.auth?.public_key || "";
    assert.ok(pub.includes("BEGIN PUBLIC KEY"));
    assert.ok(pub.includes("END PUBLIC KEY"));
    assert.equal(
      crypto.createPublicKey(pub).export({ type: "spki", format: "der" }).toString("base64"),
      raw,
    );
  });

  it("AC-1.2: existing raw entry still registered/read (no regression)", () => {
    const vault = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-f1-"));
    try {
      const agentsDir = path.join(vault, "mesh", "agents");
      const legacyDir = path.join(agentsDir, "legacy");
      fs.mkdirSync(legacyDir, { recursive: true });
      const raw = rawSpkiBase64();
      fs.writeFileSync(path.join(legacyDir, "identity.yaml"), yamlDump({
        id: "legacy",
        allow_loopback: true,
        transports: {
          hermes_webhook: {
            url: "http://127.0.0.1:1/webhook",
            auth: { public_key: raw },
          },
        },
      }));
      // read path still resolves the pre-existing raw entry
      const peer = resolvePeer(agentsDir, "legacy");
      assert.ok(peer, "legacy raw entry is still readable");
      assert.ok(peer?.transports?.hermes_webhook?.auth?.public_key?.includes("BEGIN PUBLIC KEY"));
      // re-register with the same raw key still works and writes PEM
      const r = registerAgent(agentsDir, "legacy", "http://default", { public_key: raw });
      assert.ok(r.public_key.includes("BEGIN PUBLIC KEY"));
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });

  it("AC-1.3: idempotent — PEM in → PEM out, canonicalize twice == once (both sites)", () => {
    const { publicKey } = generateKeyPair();
    // helper idempotency
    assert.equal(canonicalizePublicKey(canonicalizePublicKey(publicKey)), canonicalizePublicKey(publicKey));
    // registerAgent write site
    const vault = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-f1-"));
    try {
      const agentsDir = path.join(vault, "mesh", "agents");
      const r = registerAgent(agentsDir, "newbie", "http://default", { public_key: publicKey });
      assert.ok(r.public_key.includes("BEGIN PUBLIC KEY"));
      const r2 = registerAgent(agentsDir, "newbie", "http://default", { public_key: r.public_key });
      assert.equal(r2.public_key, r.public_key);
      // discovery-handle write site (normalizeIdentity)
      const identity = normalizeIdentity({
        transports: {
          hermes_webhook: { url: "http://x", auth: { public_key: publicKey } },
        },
      });
      assert.equal(
        identity.transports?.hermes_webhook?.auth?.public_key,
        canonicalizePublicKey(publicKey),
      );
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });

  it("invalid public_key → existing registerAgent rejection (test stays green)", () => {
    const vault = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-f1-"));
    try {
      const agentsDir = path.join(vault, "mesh", "agents");
      assert.throws(
        () => registerAgent(agentsDir, "newbie", "http://default", { public_key: "not-a-real-key" }),
        /invalid public_key/,
      );
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });
});

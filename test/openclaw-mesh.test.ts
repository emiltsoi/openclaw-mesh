/// <reference types="node" />
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { dump as yamlDump } from "js-yaml";
import { resolveSecret } from "../src/config.js";
import { parseMeshEnvelope, stripEnvelope } from "../src/envelope.js";
import {
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

describe("resolveSecret", () => {
  it("prefers pluginConfig.secret", () => {
    assert.equal(resolveSecret({ pluginConfig: { secret: "a" }, config: {} }), "a");
  });

  it("falls back to gateway config", () => {
    const cfg = { plugins: { entries: { "openclaw-mesh": { config: { secret: "b" } } } } };
    assert.equal(resolveSecret({ pluginConfig: {}, config: cfg }), "b");
  });

  it("falls back to env var", () => {
    process.env.OPENCLAW_MESH_SECRET = "c";
    try {
      assert.equal(resolveSecret({ pluginConfig: {}, config: {} }), "c");
    } finally {
      delete process.env.OPENCLAW_MESH_SECRET;
    }
  });

  it("throws when no secret is configured", () => {
    assert.throws(() => resolveSecret({ pluginConfig: {}, config: {} }), /no secret configured/);
  });
});

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

describe("HMAC round-trip", () => {
  it("signs and verifies a payload", () => {
    const secret = "test-secret";
    const body = JSON.stringify({ text: "[mesh][from:emts][to:agent0][id:1][action:do][reply:yes] hi" });
    const sig = crypto.createHmac("sha256", secret).update(body).digest("hex");
    const computed = crypto.createHmac("sha256", secret).update(body).digest("hex");
    assert.equal(computed, sig);
  });
});

function setupVault() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-vault-"));
  const agentsRoot = path.join(tmp, "mesh", "agents");
  const agent0Dir = path.join(agentsRoot, "agent0");
  const emtsDir = path.join(agentsRoot, "emts");
  fs.mkdirSync(agent0Dir, { recursive: true });
  fs.mkdirSync(emtsDir, { recursive: true });

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
        auth: { type: "hmac-sha256", secret: "agent0-secret" },
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
        auth: { type: "hmac-sha256", secret: "emts-secret" },
      },
    },
  };

  fs.writeFileSync(path.join(agent0Dir, "identity.yaml"), yamlDump(agent0Identity));
  fs.writeFileSync(path.join(emtsDir, "identity.yaml"), yamlDump(emtsIdentity));
  return tmp;
}

describe("resolveMeshVaultPath", () => {
  it("defaults to /tmp/openclaw-mesh/mesh/agents when no overrides are set", () => {
    const origHermes = process.env.HERMES_HOME;
    const origState = process.env.OPENCLAW_STATE_DIR;
    const origVault = process.env.MESH_VAULT_PATH;
    delete process.env.MESH_VAULT_PATH;
    delete process.env.HERMES_HOME;
    delete process.env.OPENCLAW_STATE_DIR;
    try {
      const expected = path.join("/tmp/openclaw-mesh", "mesh", "agents");
      assert.equal(resolveMeshVaultPath(), expected);
    } finally {
      if (origHermes) process.env.HERMES_HOME = origHermes;
      if (origState) process.env.OPENCLAW_STATE_DIR = origState;
      if (origVault) process.env.MESH_VAULT_PATH = origVault;
    }
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
    const raw = {
      name: "agent0",
      webhook_url: "http://old",
      webhook_secret: "old-secret",
      transports: {
        hermes_webhook: {
          url: "http://new",
          auth: { secret: "new-secret" },
        },
      },
    };
    const identity = normalizeIdentity(raw);
    assert.equal(identity.webhook_url, "http://new");
    assert.equal(identity.webhook_secret, "new-secret");
    assert.equal(identity.transports?.hermes_webhook?.auth?.secret, "new-secret");
  });
});

describe("listPeers", () => {
  it("lists agents without exposing secrets", () => {
    const vault = setupVault();
    try {
      const peers = listPeers(path.join(vault, "mesh", "agents"));
      assert.equal(peers.length, 2);
      const agent0 = peers.find((p) => p.name === "agent0");
      assert.ok(agent0);
      assert.equal(agent0?.webhook_url, "http://127.0.0.1:8645/mesh/receive");
      assert.equal(agent0?.a2a_url, "http://127.0.0.1:41808/a2a");
      assert.equal((agent0 as any).webhook_secret, undefined);
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });
});

describe("resolvePeer", () => {
  it("finds a peer and includes the webhook secret", () => {
    const vault = setupVault();
    try {
      const peer = resolvePeer(path.join(vault, "mesh", "agents"), "agent0");
      assert.ok(peer);
      assert.equal(peer?.name, "agent0");
      assert.equal(peer?.webhook_secret, "agent0-secret");
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });
});

describe("makeOutboundPayload", () => {
  it("builds an mesh envelope from the bridge to a peer", () => {
    const payload = makeOutboundPayload("emts", "agent0", "ping");
    assert.ok(payload.startsWith("[mesh][v:1][from:emts][to:agent0]"));
    assert.ok(payload.includes("[action:do][reply:yes] ping"));
  });
});

describe("sendToAgent", () => {
  it("HMAC-signs and POSTs the outbound payload", async () => {
    const vault = setupVault();
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

    try {
      const peer = resolvePeer(path.join(vault, "mesh", "agents"), "agent0")!;
      // Aim at the ephemeral test server so the SSRF guard exercises a real loopback request.
      peer.webhook_url = serverUrl;
      if (peer.transports?.hermes_webhook) {
        (peer.transports as any).hermes_webhook.url = serverUrl;
      }

      const result = await sendToAgent("emts", "emts-secret", peer, "ping", "info", "no");
      assert.equal(result.ok, true);
      assert.ok(captured.body, "request body was captured");
      assert.equal(captured.url, serverUrl);

      const body = captured.body;
      assert.ok(body, "request body was captured");
      const payload = JSON.parse(body);
      assert.equal(payload.from, "emts");
      assert.ok(payload.text.startsWith("[mesh][v:1][from:emts][to:agent0]"));
      assert.ok(payload.text.includes("[action:info][reply:no] ping"));

      const headers = captured.headers;
      const sigHeader = headers?.["x-hub-signature-256"];
      assert.ok(sigHeader, "x-hub-signature-256 header present");
      const expected = crypto
        .createHmac("sha256", "emts-secret")
        .update(body)
        .digest("hex");
      assert.equal(sigHeader, `sha256=${expected}`);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      fs.rmSync(vault, { recursive: true, force: true });
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
      const result = registerAgent(agentsDir, "newbie", "secret123", "http://127.0.0.1:18860", {
        description: "Test agent",
        role: "operator",
        platform: "openclaw",
      });
      assert.equal(result.name, "newbie");
      assert.ok(fs.existsSync(result.path));

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
      registerAgent(agentsDir, "custom", "secret", "http://default", {
        a2a_url: "http://custom/a2a",
        webhook_url: "http://custom/webhook",
      });
      const peer = resolvePeer(agentsDir, "custom")!;
      assert.equal(peer?.a2a_url, "http://custom/a2a");
      assert.equal(peer?.webhook_url, "http://custom/webhook");
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });
});

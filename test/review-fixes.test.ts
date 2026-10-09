/// <reference types="node" />
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { dump as yamlDump } from "js-yaml";
import { parseMeshEnvelope } from "../src/envelope.js";
import {
  listPeers,
  makeOutboundPayload,
  registerAgent,
  registerMeshTools,
  resolvePeer,
  sendToAgent,
} from "../src/discovery.js";
import { injectIntoSession } from "../src/injector.js";
import { DEFAULT_OUTBOX_DIR, listOutbox, resolveOutboxDir } from "../src/outbox.js";
import {
  createRegistryClient,
  getPrivateKeyPath,
  signMessage,
  verifyEd25519Signature,
} from "../src/registry.js";
import {
  currentTs,
  findWebhookHandler,
  generateKeyPair,
  invokeWebhook,
  makeApi,
  registerPlugin,
  signBody,
} from "./helpers/webhook-harness.js";

function hashFile(p: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

interface ServerHandle {
  server: http.Server;
  port: number;
  url: string;
  close: () => Promise<void>;
}

function startServer(handler: (req: http.IncomingMessage, res: http.ServerResponse, body: string) => void): Promise<ServerHandle> {
  const server = http.createServer((req, res) => {
    let body = "";
    req.setEncoding("utf-8");
    req.on("data", (c) => (body += c));
    req.on("end", () => handler(req, res, body));
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as { port: number }).port;
      resolve({ server, port, url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

function okServer(bodies: any[]) {
  return startServer((req, res, body) => {
    bodies.push({ method: req.method, url: req.url, headers: req.headers, body });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
  });
}

function failServer(bodies: any[], status = 503) {
  return startServer((req, res, body) => {
    bodies.push({ method: req.method, url: req.url, body });
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "error" }));
  });
}

function setupWire(opts: {
  senderWebhookUrl?: string;
  senderName?: string;
  pluginConfig?: any;
  extraPeers?: Array<{ name: string; webhookUrl: string; allowLoopback?: boolean }>;
} = {}) {
  // Isolate from ambient agent-name env vars (the dev shell sets
  // MESH_AGENT_NAME=britney) so routing defaults to "emts" unless a test
  // explicitly sets the env after capture.
  const savedAgentEnv = { MESH_AGENT_NAME: process.env.MESH_AGENT_NAME, A2A_AGENT_NAME: process.env.A2A_AGENT_NAME };
  delete process.env.MESH_AGENT_NAME;
  delete process.env.A2A_AGENT_NAME;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-wire-"));
  const vaultRoot = path.join(tmp, "mesh", "agents");
  fs.mkdirSync(vaultRoot, { recursive: true });

  const senderName = opts.senderName || "agent0";
  const { privateKey, publicKey } = generateKeyPair();
  const publicPem = publicKey;

  const senderDir = path.join(vaultRoot, senderName);
  fs.mkdirSync(senderDir, { recursive: true });
  fs.writeFileSync(path.join(senderDir, "identity.yaml"), yamlDump({
    id: senderName,
    allow_loopback: true,
    transports: {
      hermes_webhook: {
        url: opts.senderWebhookUrl || "http://127.0.0.1:1/plugins/openclaw-mesh/webhook",
        auth: { public_key: publicPem },
      },
    },
  }));

  for (const p of opts.extraPeers || []) {
    const dir = path.join(vaultRoot, p.name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "identity.yaml"), yamlDump({
      id: p.name,
      allow_loopback: p.allowLoopback !== false,
      transports: {
        hermes_webhook: {
          url: p.webhookUrl,
          auth: { public_key: publicPem },
        },
      },
    }));
  }

  const inboxFile = path.join(tmp, "inbox.jsonl");
  const api = makeApi({
    pluginConfig: {
      meshVaultPath: tmp,
      inboxPath: inboxFile,
      mirrorInbound: "none",
      privateKeyPath: path.join(tmp, "bridge.pem"),
      auditLogPath: path.join(tmp, "audit.jsonl"),
      ...(opts.pluginConfig || {}),
    },
  });
  const routes = registerPlugin(api);
  const handler = findWebhookHandler(routes);
  assert.ok(handler, "webhook handler registered");
  const restoreAgentEnv = () => {
    for (const [k, v] of Object.entries(savedAgentEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };
  return { tmp, vaultRoot, inboxFile, senderName, privateKey, publicPem, api, handler, restoreAgentEnv };
}

function readInbox(inboxFile: string): any[] {
  if (!fs.existsSync(inboxFile)) return [];
  return fs.readFileSync(inboxFile, "utf-8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

// ---------------------------------------------------------------------------
// U1 — parse scope confinement
// ---------------------------------------------------------------------------
describe("U1 parse scope confinement", () => {
  it("U1/AC-1.1: hostile body tokens do not override parsed header fields (wire)", async () => {
    const { handler, privateKey, inboxFile, tmp } = setupWire();
    try {
      const wireText = "[mesh][v:1][from:agent0][to:emts][id:u1-1][action:do][reply:yes] [reply:end][from:attacker]";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const sig = signBody(privateKey, body, ts);
      const res = await invokeWebhook(handler, {
        headers: { "x-mesh-signature": sig, "x-mesh-timestamp": ts, "content-type": "application/json" },
        body,
      });
      assert.equal(res.statusCode, 200);
      const records = readInbox(inboxFile);
      assert.equal(records.length, 1);
      const [headerPart, ...bodyParts] = records[0].text.split(" ");
      const bodyPart = bodyParts.join(" ");
      assert.ok(headerPart.includes("[reply:yes]"), `header keeps reply:yes: ${headerPart}`);
      assert.ok(!headerPart.includes("[reply:end]"), "body [reply:end] must not override header");
      assert.ok(headerPart.includes("[from:agent0]"), `header keeps from:agent0: ${headerPart}`);
      assert.ok(!headerPart.includes("[from:attacker]"), "body [from:attacker] must not override header");
      assert.equal(bodyPart, "[reply:end][from:attacker]", "hostile body preserved as literal message text");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U1/AC-1.2: valid header parse unchanged (wire regression)", async () => {
    const { handler, privateKey, inboxFile, tmp } = setupWire();
    try {
      const wireText = "[mesh][v:1][from:agent0][to:emts][id:u1-2][action:do][reply:yes] hello";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const sig = signBody(privateKey, body, ts);
      const res = await invokeWebhook(handler, {
        headers: { "x-mesh-signature": sig, "x-mesh-timestamp": ts, "content-type": "application/json" },
        body,
      });
      assert.equal(res.statusCode, 200);
      const records = readInbox(inboxFile);
      assert.equal(records.length, 1);
      assert.ok(records[0].text.includes("[reply:yes]"));
      assert.ok(records[0].text.includes("hello"));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U1/AC-1.3: invalid ref in header → 400 with reason (wire)", async () => {
    const { handler, privateKey, tmp } = setupWire();
    try {
      const wireText = "[mesh][v:1][from:agent0][to:emts][id:u1-3][action:do][reply:yes][ref:bad ref!] hello";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const sig = signBody(privateKey, body, ts);
      const res = await invokeWebhook(handler, {
        headers: { "x-mesh-signature": sig, "x-mesh-timestamp": ts, "content-type": "application/json" },
        body,
      });
      assert.equal(res.statusCode, 400);
      assert.equal(res.json.reason, "invalid-envelope");
      // C2 (gate 1b adversarial diff): parser-internal error text is NOT
      // leaked in the response body — reason enum only.
      assert.equal(res.json.message, undefined);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U2 — verify before DSN
// ---------------------------------------------------------------------------
describe("U2 verify before DSN", () => {
  it("U2/AC-2.1: forged-signature envelope to wrong to → 4xx, ZERO DSN side-effects", async () => {
    const dsns: any[] = [];
    const dsnServer = await okServer(dsns);
    const { handler, tmp } = setupWire({ senderWebhookUrl: `${dsnServer.url}/mesh/receive` });
    try {
      const wireText = "[mesh][v:1][from:agent0][to:someoneelse][id:u2-1][action:do][reply:yes] hi";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const forgedSig = crypto.randomBytes(64).toString("base64");
      const res = await invokeWebhook(handler, {
        headers: { "x-mesh-signature": forgedSig, "x-mesh-timestamp": ts, "content-type": "application/json" },
        body,
      });
      assert.equal(res.statusCode, 403);
      assert.equal(res.json.reason, "invalid-signature");
      assert.equal(dsns.length, 0, "no DSN webhook POST emitted for a forged signature");
    } finally {
      await dsnServer.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U2/AC-2.1b: unsigned (missing sig header) to wrong to → 403, zero DSN", async () => {
    const dsns: any[] = [];
    const dsnServer = await okServer(dsns);
    const { handler, tmp } = setupWire({ senderWebhookUrl: `${dsnServer.url}/mesh/receive` });
    try {
      const wireText = "[mesh][v:1][from:agent0][to:someoneelse][id:u2-1b][action:do][reply:yes] hi";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const res = await invokeWebhook(handler, {
        headers: { "x-mesh-timestamp": ts, "content-type": "application/json" },
        body,
      });
      assert.equal(res.statusCode, 403);
      assert.equal(res.json.reason, "missing-signature");
      assert.equal(dsns.length, 0);
    } finally {
      await dsnServer.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U2/AC-2.2: signed envelope to wrong to → DSN still emitted (regression)", async () => {
    const dsns: any[] = [];
    const dsnServer = await okServer(dsns);
    const { handler, privateKey, tmp } = setupWire({
      senderWebhookUrl: `${dsnServer.url}/mesh/receive`,
      pluginConfig: { deliveryRetries: 2, deliveryBackoffMs: 0 },
    });
    try {
      const wireText = "[mesh][v:1][from:agent0][to:someoneelse][id:u2-2][action:do][reply:yes] hi";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const sig = signBody(privateKey, body, ts);
      const res = await invokeWebhook(handler, {
        headers: { "x-mesh-signature": sig, "x-mesh-timestamp": ts, "content-type": "application/json" },
        body,
      });
      assert.equal(res.statusCode, 200);
      assert.equal(res.json.note, "not-addressed-to-me");
      assert.equal(dsns.length, 1, "authenticated DSN emitted");
      assert.ok(dsns[0].body.includes("[mesh-dsn]"), `DSN body carries mesh-dsn: ${dsns[0].body}`);
    } finally {
      await dsnServer.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U3 — realpath confinement
// ---------------------------------------------------------------------------
describe("U3 realpath confinement", () => {
  it("U3/AC-3.1: symlink inside vault → outside → read AND write refused", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-symlink-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const outsideDir = path.join(tmp, "outside");
      fs.mkdirSync(vaultRoot, { recursive: true });
      fs.mkdirSync(outsideDir, { recursive: true });
      fs.writeFileSync(path.join(outsideDir, "identity.yaml"), yamlDump({ id: "evil", webhook_url: "http://evil" }));
      fs.symlinkSync(outsideDir, path.join(vaultRoot, "evil"), "dir");

      // read refused
      assert.equal(resolvePeer(vaultRoot, "evil"), null, "resolvePeer refuses symlink escape");
      const peers = listPeers(vaultRoot);
      assert.equal(peers.some((p) => p.name === "evil"), false, "listPeers skips symlink escape");

      // write refused
      assert.throws(
        () => registerAgent(vaultRoot, "evil", "http://default", { privateKeyPath: path.join(tmp, "k.pem") } as any),
        /outside mesh vault/,
        "registerAgent refuses symlink escape",
      );
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U3/AC-3.2: normal paths unchanged (regression)", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-symlink2-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      fs.mkdirSync(vaultRoot, { recursive: true });
      const r = registerAgent(vaultRoot, "alice", "http://default", { privateKeyPath: path.join(tmp, "k.pem") } as any);
      assert.equal(r.name, "alice");
      assert.ok(fs.existsSync(r.path));
      const peer = resolvePeer(vaultRoot, "alice");
      assert.ok(peer);
      assert.equal(peer?.name, "alice");
      assert.equal(listPeers(vaultRoot).some((p) => p.name === "alice"), true);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U4 — reject empty names (all register paths)
// ---------------------------------------------------------------------------
describe("U4 reject empty names", () => {
  it("U4/AC-4.1a: registerAgent empty name → throws, identity.yaml hash-verified unchanged", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-empty-name-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const emtsDir = path.join(vaultRoot, "emts");
      fs.mkdirSync(emtsDir, { recursive: true });
      const identityPath = path.join(emtsDir, "identity.yaml");
      fs.writeFileSync(identityPath, yamlDump({ id: "emts", webhook_url: "http://bridge" }));
      const hashBefore = hashFile(identityPath);
      assert.throws(() => registerAgent(vaultRoot, "", "http://default", { privateKeyPath: path.join(tmp, "k.pem") } as any), /empty/);
      assert.throws(() => registerAgent(vaultRoot, "   ", "http://default", { privateKeyPath: path.join(tmp, "k.pem") } as any), /empty/);
      assert.equal(hashFile(identityPath), hashBefore, "bridge identity.yaml untouched");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U4/AC-4.1b: mesh_register tool empty name → error result, no vault write", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-empty-tool-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const emtsDir = path.join(vaultRoot, "emts");
      fs.mkdirSync(emtsDir, { recursive: true });
      const identityPath = path.join(emtsDir, "identity.yaml");
      fs.writeFileSync(identityPath, yamlDump({ id: "emts", webhook_url: "http://bridge" }));
      const hashBefore = hashFile(identityPath);

      const tools: any[] = [];
      const api = makeApi({ pluginConfig: { meshVaultPath: tmp, privateKeyPath: path.join(tmp, "k.pem") }, tools });
      registerMeshTools(api);
      const meshRegister = tools.find((t) => t && t.name === "mesh_register");
      assert.ok(meshRegister, "mesh_register tool registered");
      const result = await meshRegister.execute("id", { name: "" });
      const parsed = JSON.parse(result.content[0].text);
      assert.equal(parsed.ok, false);
      assert.match(parsed.error, /empty|required/);
      assert.equal(hashFile(identityPath), hashBefore, "bridge identity.yaml untouched by empty-name tool call");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U4/AC-4.2: valid names unchanged (all register paths)", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-valid-name-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      fs.mkdirSync(vaultRoot, { recursive: true });
      const r = registerAgent(vaultRoot, "newbie", "http://default", { privateKeyPath: path.join(tmp, "k.pem") } as any);
      assert.equal(r.name, "newbie");
      assert.ok(fs.existsSync(r.path));

      const tools: any[] = [];
      const api = makeApi({ pluginConfig: { meshVaultPath: tmp, privateKeyPath: path.join(tmp, "k2.pem") }, tools });
      registerMeshTools(api);
      const meshRegister = tools.find((t) => t && t.name === "mesh_register");
      const res = await meshRegister.execute("id", { name: "alice", webhook_url: "http://alice/webhook" });
      const parsed = JSON.parse(res.content[0].text);
      assert.equal(parsed.ok, true);
      assert.equal(parsed.name, "alice");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U5 — loud ref handling
// ---------------------------------------------------------------------------
describe("U5 loud ref handling", () => {
  it("U5/AC-5.1: invalid-ref send → never ok:true", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-ref-send-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const agent0Dir = path.join(vaultRoot, "agent0");
      fs.mkdirSync(agent0Dir, { recursive: true });
      fs.writeFileSync(path.join(agent0Dir, "identity.yaml"), yamlDump({
        id: "agent0",
        allow_loopback: true,
        transports: { hermes_webhook: { url: "http://127.0.0.1:1/x", auth: { public_key: "" } } },
      }));
      const peer = resolvePeer(vaultRoot, "agent0")!;
      const extra = { privateKeyPath: path.join(tmp, "k.pem") };
      const result = await sendToAgent("emts", peer, "hi", "do", "yes", "id-1", { pluginConfig: extra }, "bad ref!", false);
      assert.equal(result.ok, false);
      assert.match(result.error || "", /Invalid ref/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U5/AC-5.2: signed payload is byte-identical to the input (signature-over-input)", async () => {
    const captured: any[] = [];
    const server = await okServer(captured);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-sig-input-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const agent0Dir = path.join(vaultRoot, "agent0");
      fs.mkdirSync(agent0Dir, { recursive: true });
      const { privateKey, publicKey } = generateKeyPair();
      fs.writeFileSync(path.join(agent0Dir, "identity.yaml"), yamlDump({
        id: "agent0",
        allow_loopback: true,
        transports: { hermes_webhook: { url: `${server.url}/mesh/receive`, auth: { public_key: publicKey } } },
      }));
      const keyFile = path.join(tmp, "k.pem");
      fs.writeFileSync(keyFile, privateKey, { mode: 0o600 });
      const peer = resolvePeer(vaultRoot, "agent0")!;
      const extra = { privateKeyPath: keyFile };
      const result = await sendToAgent("emts", peer, "ping", "info", "no", undefined, { pluginConfig: extra });
      assert.equal(result.ok, true);
      assert.equal(captured.length, 1);
      const body = captured[0].body;
      const tsHeader = captured[0].headers["x-mesh-timestamp"] as string;
      const sigHeader = captured[0].headers["x-mesh-signature"] as string;
      const expected = signMessage(privateKey, Buffer.from(`${tsHeader}\n${body}`, "utf-8"));
      assert.equal(sigHeader, expected, "signature covers the exact serialized body");
    } finally {
      await server.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U6 — wire replay protection
// ---------------------------------------------------------------------------
describe("U6 wire replay protection", () => {
  it("U6/AC-6.1: identical signed webhook replayed → rejected (window hit)", async () => {
    const { handler, privateKey, tmp } = setupWire();
    try {
      const wireText = "[mesh][v:1][from:agent0][to:emts][id:u6-1][action:do][reply:yes] hello";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const sig = signBody(privateKey, body, ts);
      const headers = { "x-mesh-signature": sig, "x-mesh-timestamp": ts, "content-type": "application/json" };
      const first = await invokeWebhook(handler, { headers, body });
      assert.equal(first.statusCode, 200);
      const second = await invokeWebhook(handler, { headers, body });
      assert.equal(second.statusCode, 409);
      assert.equal(second.json.reason, "replay-detected");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U6/AC-6.2: fresh signed webhook → accepted (regression)", async () => {
    const { handler, privateKey, inboxFile, tmp } = setupWire();
    try {
      const wireText = "[mesh][v:1][from:agent0][to:emts][id:u6-2][action:do][reply:yes] fresh";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const sig = signBody(privateKey, body, ts);
      const res = await invokeWebhook(handler, {
        headers: { "x-mesh-signature": sig, "x-mesh-timestamp": ts, "content-type": "application/json" },
        body,
      });
      assert.equal(res.statusCode, 200);
      assert.equal(readInbox(inboxFile).length, 1);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// C1 — replay-window dual-creation (gate 1b adversarial diff, 2026-08-16)
// ---------------------------------------------------------------------------
// The beta loader runs register() twice (full + discovery, finding F1). A
// per-registration replay window would orphan the first pass's window when the
// discovery pass splices over the handler (replaceExisting:true) — envelope
// ids seen by the first handler would be replayable indefinitely through the
// second. The fix hoists createReplayWindow() to module scope: one
// process-lifetime window shared by BOTH passes' handlers. This mutation test
// simulates the dual pass: record via handler A, replay via handler B → expect
// 409. With a per-registration window this fails (second call returns 200).
describe("C1 replay-window dual-pass (module-scope window)", () => {
  it("C1/AC-1.1: replay across two registration passes → rejected (window shared)", async () => {
    const { tmp, privateKey, handlerA, handlerB } = (() => {
      const savedAgentEnv = { MESH_AGENT_NAME: process.env.MESH_AGENT_NAME, A2A_AGENT_NAME: process.env.A2A_AGENT_NAME };
      delete process.env.MESH_AGENT_NAME;
      delete process.env.A2A_AGENT_NAME;
      const t = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-c1-"));
      const vaultRoot = path.join(t, "mesh", "agents");
      fs.mkdirSync(vaultRoot, { recursive: true });
      const { privateKey: pk, publicKey: pub } = generateKeyPair();
      fs.mkdirSync(path.join(vaultRoot, "agent0"), { recursive: true });
      fs.writeFileSync(path.join(vaultRoot, "agent0", "identity.yaml"), yamlDump({
        id: "agent0",
        allow_loopback: true,
        transports: { hermes_webhook: { url: "http://127.0.0.1:1/plugins/openclaw-mesh/webhook", auth: { public_key: pub } } },
      }));
      const inboxFile = path.join(t, "inbox.jsonl");
      fs.writeFileSync(inboxFile, "");
      const pluginConfig = {
        routingAgent: "emts",
        targetSessionKey: "agent:main:main",
        targetAgentId: "main",
        meshVaultPath: t,
        inboxPath: inboxFile,
        mirrorInbound: "none",
        privateKeyPath: path.join(t, "bridge.pem"),
        auditLogPath: path.join(t, "audit.jsonl"),
      };
      // Pass A — full registration
      const apiA = makeApi({ pluginConfig });
      apiA.registrationMode = "full";
      const routesA = registerPlugin(apiA);
      const handlerA = findWebhookHandler(routesA);
      assert.ok(handlerA, "pass A handler registered");
      // Pass B — discovery registration (beta dual-pass), same module scope
      const apiB = makeApi({ pluginConfig });
      apiB.registrationMode = "discovery";
      const routesB = registerPlugin(apiB);
      const handlerB = findWebhookHandler(routesB);
      assert.ok(handlerB, "pass B handler registered");
      return { tmp: t, privateKey: pk, handlerA, handlerB };
    })();
    try {
      const wireText = "[mesh][v:1][from:agent0][to:emts][id:c1-1][action:do][reply:yes] hello";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const sig = signBody(privateKey, body, ts);
      const headers = { "x-mesh-signature": sig, "x-mesh-timestamp": ts, "content-type": "application/json" };
      // Record through pass-A handler
      const first = await invokeWebhook(handlerA, { headers, body });
      assert.equal(first.statusCode, 200);
      // Replay through pass-B handler — MUST be rejected (shared window)
      const second = await invokeWebhook(handlerB, { headers, body });
      assert.equal(second.statusCode, 409);
      assert.equal(second.json.reason, "replay-detected");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
describe("U7 allowInsecure registry boolean", () => {
  it("U7/AC-7.1: http:// registry WITHOUT flag → refused", () => {
    assert.throws(
      () => createRegistryClient("emts", { registryUrl: "http://127.0.0.1:9999", privateKeyPath: "/tmp/k.pem" }),
      /insecure http registry URL/,
    );
  });

  it("U7/AC-7.1b: http:// registry WITH allowInsecureRegistry → accepted", () => {
    const client = createRegistryClient("emts", { registryUrl: "http://127.0.0.1:9999", allowInsecureRegistry: true, privateKeyPath: "/tmp/k2.pem" });
    assert.ok(client);
    assert.equal(typeof client.register, "function");
  });

  it("U7/AC-7.2: https:// registry without flag → accepted", () => {
    const client = createRegistryClient("emts", { registryUrl: "https://registry.example.com", privateKeyPath: "/tmp/k3.pem" });
    assert.ok(client);
  });
});

// ---------------------------------------------------------------------------
// U8 — force before delete
// ---------------------------------------------------------------------------
describe("U8 force before delete", () => {
  it("U8/AC-8.1: dry-run deregister → no registry delete, no vault delete (state hash-verified)", async () => {
    const hits: any[] = [];
    const registryServer = await okServer(hits);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-dereg-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const victimDir = path.join(vaultRoot, "victim");
      fs.mkdirSync(victimDir, { recursive: true });
      const identityPath = path.join(victimDir, "identity.yaml");
      fs.writeFileSync(identityPath, yamlDump({ id: "victim", webhook_url: "http://victim" }));
      const hashBefore = hashFile(identityPath);

      const tools: any[] = [];
      const api = makeApi({
        pluginConfig: {
          meshVaultPath: tmp,
          registryUrl: registryServer.url,
          allowInsecureRegistry: true,
          privateKeyPath: path.join(tmp, "k.pem"),
        },
        tools,
      });
      registerMeshTools(api);
      const tool = tools.find((t) => t && t.name === "mesh_deregister");
      assert.ok(tool, "mesh_deregister tool registered");
      const result = await tool.execute("id", { name: "victim", force: false });
      const parsed = JSON.parse(result.content[0].text);
      assert.equal(parsed.dry_run, true);
      assert.equal(hits.length, 0, "no registry DELETE on dry-run");
      assert.equal(hashFile(identityPath), hashBefore, "vault identity.yaml unchanged on dry-run");
      assert.ok(fs.existsSync(victimDir), "vault dir still exists on dry-run");
    } finally {
      await registryServer.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U8/AC-8.2: force=true still deletes (regression)", async () => {
    const hits: any[] = [];
    const registryServer = await okServer(hits);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-dereg-force-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const victimDir = path.join(vaultRoot, "victim");
      fs.mkdirSync(victimDir, { recursive: true });
      fs.writeFileSync(path.join(victimDir, "identity.yaml"), yamlDump({ id: "victim", webhook_url: "http://victim" }));

      const tools: any[] = [];
      const api = makeApi({
        pluginConfig: {
          meshVaultPath: tmp,
          registryUrl: registryServer.url,
          allowInsecureRegistry: true,
          privateKeyPath: path.join(tmp, "k.pem"),
        },
        tools,
      });
      registerMeshTools(api);
      const tool = tools.find((t) => t && t.name === "mesh_deregister");
      const result = await tool.execute("id", { name: "victim", force: true });
      const parsed = JSON.parse(result.content[0].text);
      assert.equal(parsed.ok, true);
      assert.ok(hits.some((h) => h.method === "DELETE"), `registry DELETE issued: ${JSON.stringify(hits)}`);
      assert.equal(fs.existsSync(path.join(victimDir, "identity.yaml")), false, "vault identity.yaml deleted");
    } finally {
      await registryServer.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U9 — wire the outbox
// ---------------------------------------------------------------------------
describe("U9 outbox wiring", () => {
  it("U9/AC-9.1: failed send (503 after retries) → outbox entry exists", async () => {
    const bodies: any[] = [];
    const server = await failServer(bodies, 503);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-outbox-send-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const agent0Dir = path.join(vaultRoot, "agent0");
      fs.mkdirSync(agent0Dir, { recursive: true });
      fs.writeFileSync(path.join(agent0Dir, "identity.yaml"), yamlDump({
        id: "agent0",
        allow_loopback: true,
        transports: { hermes_webhook: { url: `${server.url}/mesh/receive`, auth: { public_key: "" } } },
      }));
      const outboxDir = path.join(tmp, "outbox");
      const peer = resolvePeer(vaultRoot, "agent0")!;
      const extra = { privateKeyPath: path.join(tmp, "k.pem"), outboxDir, deliveryRetries: 2, deliveryBackoffMs: 0 };
      const result = await sendToAgent("emts", peer, "ping", "do", "yes", "u9-1", { pluginConfig: extra });
      assert.equal(result.ok, false);
      const entries = listOutbox(outboxDir);
      assert.equal(entries.length, 1, "outbox has one failed send entry");
      const entry = entries[0]!;
      assert.equal(entry.direction, "send");
      assert.equal(entry.peer, "agent0");
      assert.equal(entry.status, 503);
      assert.ok(entry.text?.includes("[mesh][v:1][from:emts][to:agent0]"), "entry carries the exact payload text");
    } finally {
      await server.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U9/AC-9.2: successful send → no outbox entry (regression)", async () => {
    const bodies: any[] = [];
    const server = await okServer(bodies);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-outbox-ok-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const agent0Dir = path.join(vaultRoot, "agent0");
      fs.mkdirSync(agent0Dir, { recursive: true });
      fs.writeFileSync(path.join(agent0Dir, "identity.yaml"), yamlDump({
        id: "agent0",
        allow_loopback: true,
        transports: { hermes_webhook: { url: `${server.url}/mesh/receive`, auth: { public_key: "" } } },
      }));
      const outboxDir = path.join(tmp, "outbox");
      const peer = resolvePeer(vaultRoot, "agent0")!;
      const extra = { privateKeyPath: path.join(tmp, "k.pem"), outboxDir, deliveryRetries: 2, deliveryBackoffMs: 0 };
      const result = await sendToAgent("emts", peer, "ping", "do", "yes", "u9-2", { pluginConfig: extra });
      assert.equal(result.ok, true);
      assert.equal(listOutbox(outboxDir).length, 0, "no outbox entry on success");
    } finally {
      await server.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U10 — injector ref + v:1
// ---------------------------------------------------------------------------
describe("U10 injector ref", () => {
  it("U10/AC-10.1: inbound end+ref → inbox/prompt carries the ref and v:1", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-inject-ref-"));
    try {
      const inboxFile = path.join(tmp, "inbox.jsonl");
      const api = makeApi({ pluginConfig: { inboxPath: inboxFile, mirrorInbound: "none", targetSessionKey: "agent:main:main" } });
      const envelope = parseMeshEnvelope("[mesh][v:1][from:agent0][to:emts][id:t-1][action:do][reply:end][ref:anchor-1] done");
      assert.ok(envelope);
      await injectIntoSession(api, "done", envelope!);
      const record = readInbox(inboxFile)[0];
      assert.ok(record.text.startsWith("[mesh][v:1][from:agent0][to:emts][id:t-1][action:do][reply:end][ref:anchor-1]"), record.text);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U10/AC-10.2: no-ref message unchanged (no [ref:])", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-inject-noref-"));
    try {
      const inboxFile = path.join(tmp, "inbox.jsonl");
      const api = makeApi({ pluginConfig: { inboxPath: inboxFile, mirrorInbound: "none", targetSessionKey: "agent:main:main" } });
      const envelope = parseMeshEnvelope("[mesh][v:1][from:agent0][to:emts][id:t-2][action:do][reply:yes] hi");
      assert.ok(envelope);
      await injectIntoSession(api, "hi", envelope!);
      const record = readInbox(inboxFile)[0];
      assert.ok(record.text.startsWith("[mesh][v:1][from:agent0][to:emts][id:t-2][action:do][reply:yes]"));
      assert.ok(!record.text.includes("[ref:"), "no [ref:] for a no-ref message");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U11 — outbound enum validation
// ---------------------------------------------------------------------------
describe("U11 outbound enum validation", () => {
  it("U11/AC-11.1: invalid action/reply → throw; sendToAgent not ok", async () => {
    assert.throws(() => makeOutboundPayload("emts", "agent0", "hi", "bad", "yes"), /Invalid action/);
    assert.throws(() => makeOutboundPayload("emts", "agent0", "hi", "do", "maybe"), /Invalid reply/);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-enum-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const agent0Dir = path.join(vaultRoot, "agent0");
      fs.mkdirSync(agent0Dir, { recursive: true });
      fs.writeFileSync(path.join(agent0Dir, "identity.yaml"), yamlDump({
        id: "agent0",
        allow_loopback: true,
        transports: { hermes_webhook: { url: "http://127.0.0.1:1/x", auth: { public_key: "" } } },
      }));
      const peer = resolvePeer(vaultRoot, "agent0")!;
      const extra = { privateKeyPath: path.join(tmp, "k.pem") };
      const result = await sendToAgent("emts", peer, "hi", "bad", "yes", undefined, { pluginConfig: extra });
      assert.equal(result.ok, false);
      assert.match(result.error || "", /Invalid action/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U11/AC-11.2: valid values unchanged; whitespace-trimmed from/to", () => {
    const payload = makeOutboundPayload(" emts ", " agent0 ", "ping");
    assert.ok(payload.startsWith("[mesh][v:1][from:emts][to:agent0]"));
    assert.ok(payload.includes("[action:do][reply:yes] ping"));
  });
});

// ---------------------------------------------------------------------------
// U12 — timestamp-covered signatures
// ---------------------------------------------------------------------------
describe("U12 timestamp-covered signatures", () => {
  it("U12/AC-12.1: body-only signature → rejected", async () => {
    const { privateKey, publicKey } = generateKeyPair();
    const body = Buffer.from(JSON.stringify({ from: "agent0", text: "hi" }));
    const ts = currentTs();
    const bodySig = signMessage(privateKey, body);
    const ok = await verifyEd25519Signature(
      { "x-mesh-timestamp": ts, "x-mesh-signature": bodySig },
      body,
      "agent0",
      undefined,
      async () => publicKey,
    );
    assert.equal(ok, false);
  });

  it("U12/AC-12.2: timestamped sig accepted; tampered ts rejected", async () => {
    const { privateKey, publicKey } = generateKeyPair();
    const body = Buffer.from(JSON.stringify({ from: "agent0", text: "hi" }));
    const ts = currentTs();
    const tsSig = signMessage(privateKey, Buffer.from(`${ts}\n${body.toString("utf-8")}`, "utf-8"));
    const ok = await verifyEd25519Signature(
      { "x-mesh-timestamp": ts, "x-mesh-signature": tsSig },
      body,
      "agent0",
      undefined,
      async () => publicKey,
    );
    assert.equal(ok, true);

    // replay the SAME signature with a DIFFERENT (still fresh) ts header
    const forgedTs = String(Number(ts) + 1);
    const ok2 = await verifyEd25519Signature(
      { "x-mesh-timestamp": forgedTs, "x-mesh-signature": tsSig },
      body,
      "agent0",
      undefined,
      async () => publicKey,
    );
    assert.equal(ok2, false, "signature over original ts must not verify against a forged ts");
  });
});

// ---------------------------------------------------------------------------
// U13 — DSN target
// ---------------------------------------------------------------------------
describe("U13 DSN target", () => {
  it("U13/AC-13.1: reply-with-ref failure → DSN goes to the original sender (bridge), not the recipient", async () => {
    const recipientBodies: any[] = [];
    const recipientServer = await failServer(recipientBodies, 503);
    const senderDsns: any[] = [];
    const senderServer = await okServer(senderDsns);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-dsn-target-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      // agent0 = recipient (delivery fails); emts = the bridge's own agent
      for (const [name, url] of [["agent0", `${recipientServer.url}/mesh/receive`], ["emts", `${senderServer.url}/mesh/receive`]]) {
        const dir = path.join(vaultRoot, name);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, "identity.yaml"), yamlDump({
          id: name,
          allow_loopback: true,
          transports: { hermes_webhook: { url, auth: { public_key: "" } } },
        }));
      }
      const peer = resolvePeer(vaultRoot, "agent0")!;
      // meshVaultPath must be the tmp ROOT so the DSN path resolves the test vault,
      // not the ambient $MESH_VAULT_PATH.
      const extra = { privateKeyPath: path.join(tmp, "k.pem"), deliveryRetries: 2, deliveryBackoffMs: 0, meshVaultPath: tmp };
      const result = await sendToAgent("emts", peer, "reply text", "do", "end", "child-1", { pluginConfig: extra }, "parent-ref", false);
      assert.equal(result.ok, false);
      // DSN must go to the bridge's own agent ("emts"), not to "agent0"
      assert.equal(senderDsns.length, 1, `DSN delivered to the original sender: ${JSON.stringify(senderDsns)}`);
      assert.ok(senderDsns[0].body.includes("[mesh-dsn]"), "DSN body carries mesh-dsn");
      assert.ok(senderDsns[0].body.includes("[to:emts]"), `DSN targets the bridge's own agent (emts): ${senderDsns[0].body}`);
      assert.ok(senderDsns[0].body.includes("[ref:child-1]"), `DSN references the original message id: ${senderDsns[0].body}`);
      assert.ok(!recipientBodies.some((b) => b.body.includes("[mesh-dsn]")), "recipient must not receive the DSN");
    } finally {
      await recipientServer.close();
      await senderServer.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U14 — warn means warn
// ---------------------------------------------------------------------------
describe("U14 private network warn policy", () => {
  it("U14/AC-14.1: 'warn' policy allows loopback delivery", async () => {
    const bodies: any[] = [];
    const server = await okServer(bodies);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-warn-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const agent0Dir = path.join(vaultRoot, "agent0");
      fs.mkdirSync(agent0Dir, { recursive: true });
      fs.writeFileSync(path.join(agent0Dir, "identity.yaml"), yamlDump({
        id: "agent0",
        allow_loopback: false, // must NOT force allow
        transports: { hermes_webhook: { url: `${server.url}/mesh/receive`, auth: { public_key: "" } } },
      }));
      const peer = resolvePeer(vaultRoot, "agent0")!;
      const extra = { privateKeyPath: path.join(tmp, "k.pem"), privateNetworkPolicy: "warn", deliveryRetries: 2, deliveryBackoffMs: 0 };
      const result = await sendToAgent("emts", peer, "ping", "do", "yes", "u14-1", { pluginConfig: extra });
      assert.equal(result.ok, true, `warn should allow: ${result.error}`);
      assert.equal(bodies.length, 1);
    } finally {
      await server.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U14/AC-14.2: 'deny' still denies loopback delivery", async () => {
    const bodies: any[] = [];
    const server = await okServer(bodies);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-deny-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const agent0Dir = path.join(vaultRoot, "agent0");
      fs.mkdirSync(agent0Dir, { recursive: true });
      fs.writeFileSync(path.join(agent0Dir, "identity.yaml"), yamlDump({
        id: "agent0",
        allow_loopback: false,
        transports: { hermes_webhook: { url: `${server.url}/mesh/receive`, auth: { public_key: "" } } },
      }));
      const peer = resolvePeer(vaultRoot, "agent0")!;
      const extra = { privateKeyPath: path.join(tmp, "k.pem"), privateNetworkPolicy: "deny", deliveryRetries: 2, deliveryBackoffMs: 0 };
      const result = await sendToAgent("emts", peer, "ping", "do", "yes", "u14-2", { pluginConfig: extra });
      assert.equal(result.ok, false);
      assert.equal(bodies.length, 0, "deny blocks the loopback delivery");
    } finally {
      await server.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U15 — unified routing resolution
// ---------------------------------------------------------------------------
describe("U15 unified routing resolution", () => {
  it("U15/AC-15.1: MESH_AGENT_NAME=envagent routes inbound [to:envagent]", async () => {
    const { handler, privateKey, inboxFile, tmp, restoreAgentEnv } = setupWire();
    const saved = process.env.MESH_AGENT_NAME;
    process.env.MESH_AGENT_NAME = "envagent";
    try {
      const wireText = "[mesh][v:1][from:agent0][to:envagent][id:u15-1][action:do][reply:yes] hello";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const sig = signBody(privateKey, body, ts);
      const res = await invokeWebhook(handler, {
        headers: { "x-mesh-signature": sig, "x-mesh-timestamp": ts, "content-type": "application/json" },
        body,
      });
      assert.equal(res.statusCode, 200);
      assert.notEqual(res.json.note, "not-addressed-to-me", "envelope addressed to envagent must be routed");
      const records = readInbox(inboxFile);
      assert.equal(records.length, 1);
      assert.ok(records[0].text.includes("[to:envagent]"));
    } finally {
      restoreAgentEnv();
      fs.rmSync(tmp, { recursive: true, force: true });
      if (saved === undefined) delete process.env.MESH_AGENT_NAME;
      else process.env.MESH_AGENT_NAME = saved;
    }
  });

  it("U15/AC-15.2: default routing agent unchanged (emts)", async () => {
    const { handler, privateKey, inboxFile, tmp, restoreAgentEnv } = setupWire();
    const wireText = "[mesh][v:1][from:agent0][to:emts][id:u15-2][action:do][reply:yes] hello";
    const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
    const ts = currentTs();
    const sig = signBody(privateKey, body, ts);
    const res = await invokeWebhook(handler, {
      headers: { "x-mesh-signature": sig, "x-mesh-timestamp": ts, "content-type": "application/json" },
      body,
    });
    assert.equal(res.statusCode, 200);
    assert.notEqual(res.json.note, "not-addressed-to-me");
    assert.equal(readInbox(inboxFile).length, 1);
    restoreAgentEnv();
    fs.rmSync(tmp, { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
// U16 — inbox write failure
// ---------------------------------------------------------------------------
describe("U16 inbox write failure", () => {
  it("U16/AC-16.1: unwritable inbox → webhook returns non-200", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-inbox-fail-"));
    try {
      const { handler, privateKey } = setupWire({
        pluginConfig: { inboxPath: path.join(tmp, "no-such-dir", "inbox.jsonl"), dsnEnabled: false },
      });
      const wireText = "[mesh][v:1][from:agent0][to:emts][id:u16-1][action:do][reply:yes] hello";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const sig = signBody(privateKey, body, ts);
      const res = await invokeWebhook(handler, {
        headers: { "x-mesh-signature": sig, "x-mesh-timestamp": ts, "content-type": "application/json" },
        body,
      });
      assert.equal(res.statusCode, 500);
      assert.match(res.body, /inbox write failed/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U16/AC-16.2: writable inbox → unchanged (200)", async () => {
    const { handler, privateKey, inboxFile, tmp } = setupWire();
    try {
      const wireText = "[mesh][v:1][from:agent0][to:emts][id:u16-2][action:do][reply:yes] hello";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const sig = signBody(privateKey, body, ts);
      const res = await invokeWebhook(handler, {
        headers: { "x-mesh-signature": sig, "x-mesh-timestamp": ts, "content-type": "application/json" },
        body,
      });
      assert.equal(res.statusCode, 200);
      assert.equal(readInbox(inboxFile).length, 1);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U17 — key path sanitization
// ---------------------------------------------------------------------------
describe("U17 key path sanitization", () => {
  it("U17/AC-17.1: path-traversal key names → rejected", () => {
    assert.throws(() => getPrivateKeyPath("../../etc/owned"), /Invalid key name/);
    assert.throws(() => getPrivateKeyPath("a/b"), /Invalid key name/);
    assert.throws(() => getPrivateKeyPath("a\\b"), /Invalid key name/);
  });

  it("U17/AC-17.2: valid key names unchanged", () => {
    const p = getPrivateKeyPath("agent0");
    assert.ok(p.endsWith(`${path.sep}agent0.pem`), p);
  });
});

// ---------------------------------------------------------------------------
// U18 — parametrize outbox dir
// ---------------------------------------------------------------------------
describe("U18 parametrize outbox dir", () => {
  const ENV = "OPENCLAW_MESH_OUTBOX_DIR";
  const STATE = "OPENCLAW_STATE_DIR";
  const saved = process.env[ENV];
  const savedState = process.env[STATE];

  it("U18/AC-18.1: env override honored", () => {
    process.env[ENV] = "/tmp/oc-outbox-test";
    try {
      assert.equal(resolveOutboxDir({}), "/tmp/oc-outbox-test");
      assert.equal(resolveOutboxDir({ outboxDir: "/cfg/outbox" }), "/cfg/outbox");
    } finally {
      if (saved === undefined) delete process.env[ENV];
      else process.env[ENV] = saved;
    }
  });

  it("U18/AC-18.2: neutral default when nothing overrides", () => {
    delete process.env[ENV];
    delete process.env[STATE];
    try {
      assert.equal(resolveOutboxDir({}), DEFAULT_OUTBOX_DIR);
      // the default must never name a specific agent
      assert.ok(!/workspaces[\\/][a-z0-9_-]+[\\/]mesh/.test(DEFAULT_OUTBOX_DIR), DEFAULT_OUTBOX_DIR);
    } finally {
      if (saved === undefined) delete process.env[ENV];
      else process.env[ENV] = saved;
      if (savedState === undefined) delete process.env[STATE];
      else process.env[STATE] = savedState;
    }
  });

  it("U18/AC-18.3: per-agent state dir wins over the neutral default", () => {
    delete process.env[ENV];
    process.env[STATE] = path.join(path.sep, "tmp", "oc-state-kore");
    try {
      assert.equal(resolveOutboxDir({}), path.join(path.sep, "tmp", "oc-state-kore", "mesh", "outbox"));
      // an explicit config still outranks the state dir
      assert.equal(resolveOutboxDir({ outboxDir: "/cfg/outbox" }), "/cfg/outbox");
    } finally {
      if (savedState === undefined) delete process.env[STATE];
      else process.env[STATE] = savedState;
    }
  });
});

// ---------------------------------------------------------------------------
// U19 — null-body guard
// ---------------------------------------------------------------------------
describe("U19 null-body guard", () => {
  it("U19/AC-19.1: JSON null body → 400 (not 500)", async () => {
    const { handler, tmp } = setupWire();
    try {
      const body = Buffer.from("null");
      const ts = currentTs();
      const res = await invokeWebhook(handler, {
        headers: { "x-mesh-signature": "x", "x-mesh-timestamp": ts, "content-type": "application/json" },
        body,
      });
      assert.equal(res.statusCode, 400);
      assert.equal(res.json.reason, "invalid-payload");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U19/AC-19.2: valid body unchanged", async () => {
    const { handler, privateKey, inboxFile, tmp } = setupWire();
    try {
      const wireText = "[mesh][v:1][from:agent0][to:emts][id:u19-1][action:do][reply:yes] hello";
      const body = Buffer.from(JSON.stringify({ from: "agent0", text: wireText }));
      const ts = currentTs();
      const sig = signBody(privateKey, body, ts);
      const res = await invokeWebhook(handler, {
        headers: { "x-mesh-signature": sig, "x-mesh-timestamp": ts, "content-type": "application/json" },
        body,
      });
      assert.equal(res.statusCode, 200);
      assert.equal(readInbox(inboxFile).length, 1);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U20 — register input validation
// ---------------------------------------------------------------------------
describe("U20 register input validation", () => {
  it("U20/AC-20.1: '.' name → rejected", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-dot-name-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      fs.mkdirSync(vaultRoot, { recursive: true });
      assert.throws(
        () => registerAgent(vaultRoot, ".", "http://default", { privateKeyPath: path.join(tmp, "k.pem") } as any),
        /must not contain '\.' or whitespace|Invalid agent name/,
      );
      // also ".."
      assert.throws(() => registerAgent(vaultRoot, "..", "http://default", { privateKeyPath: path.join(tmp, "k.pem") } as any));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U20/AC-20.2: invalid public_key → rejected", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-badkey-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      fs.mkdirSync(vaultRoot, { recursive: true });
      assert.throws(
        () => registerAgent(vaultRoot, "newbie", "http://default", { public_key: "not-a-real-key" } as any),
        /invalid public_key/,
      );
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U20/AC-20.3: valid register unchanged", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-valid-reg-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      fs.mkdirSync(vaultRoot, { recursive: true });
      const { publicKey } = generateKeyPair();
      const r = registerAgent(vaultRoot, "newbie", "http://default", { public_key: publicKey } as any);
      assert.equal(r.name, "newbie");
      assert.equal(r.public_key, publicKey);
      assert.ok(fs.existsSync(r.path));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U21 — 409 replay-detected on our OWN send means "already delivered"
// ---------------------------------------------------------------------------
// The replay window correctly refuses a second injection of an envelope id it
// has already processed (U6). But the sender's own retry loop re-POSTs the
// IDENTICAL signed body/id, so when attempt 1 lands and its response is lost,
// attempt 2 looks byte-identical to an attack and draws a 409. The receiver is
// right; the sender must read that 409 as "my earlier attempt landed", not as a
// failure — otherwise it retries further and/or writes a phantom outbox entry,
// and the operator's reflex is to resend, duplicating the message.
describe("U21 duplicate-suppressed delivery", () => {
  it("U21/AC-21.1: 409 replay-detected → ok:true, duplicate:true, no outbox, no retry", async () => {
    const bodies: any[] = [];
    const server = await startServer((req, res, body) => {
      bodies.push({ method: req.method, url: req.url, body });
      res.writeHead(409, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "rejected", reason: "replay-detected" }));
    });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-dup-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const agent0Dir = path.join(vaultRoot, "agent0");
      fs.mkdirSync(agent0Dir, { recursive: true });
      fs.writeFileSync(path.join(agent0Dir, "identity.yaml"), yamlDump({
        id: "agent0",
        allow_loopback: true,
        transports: { hermes_webhook: { url: `${server.url}/mesh/receive`, auth: { public_key: "" } } },
      }));
      const outboxDir = path.join(tmp, "outbox");
      const peer = resolvePeer(vaultRoot, "agent0")!;
      const extra = { privateKeyPath: path.join(tmp, "k.pem"), outboxDir, deliveryRetries: 3, deliveryBackoffMs: 0 };
      const result = await sendToAgent("emts", peer, "ack", "info", "no", "mesh-ack-1", { pluginConfig: extra });
      assert.equal(result.ok, true, "409 replay-detected must not be reported as a failure");
      assert.equal(result.duplicate, true);
      assert.equal(result.status, 409);
      assert.equal(bodies.length, 1, "no further attempts after a duplicate-suppressed response");
      assert.equal(listOutbox(outboxDir).length, 0, "a duplicate is not written to the outbox");
    } finally {
      await server.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U21/AC-21.2: non-replay 409 is still a failure (discriminator)", async () => {
    const bodies: any[] = [];
    const server = await startServer((req, res, body) => {
      bodies.push({ method: req.method, url: req.url, body });
      res.writeHead(409, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "conflict", reason: "some-other-conflict" }));
    });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-dup-neg-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const agent0Dir = path.join(vaultRoot, "agent0");
      fs.mkdirSync(agent0Dir, { recursive: true });
      fs.writeFileSync(path.join(agent0Dir, "identity.yaml"), yamlDump({
        id: "agent0",
        allow_loopback: true,
        transports: { hermes_webhook: { url: `${server.url}/mesh/receive`, auth: { public_key: "" } } },
      }));
      const outboxDir = path.join(tmp, "outbox");
      const peer = resolvePeer(vaultRoot, "agent0")!;
      const extra = { privateKeyPath: path.join(tmp, "k.pem"), outboxDir, deliveryRetries: 3, deliveryBackoffMs: 0 };
      const result = await sendToAgent("emts", peer, "hi", "do", "yes", "x-1", { pluginConfig: extra });
      assert.equal(result.ok, false, "a 409 with an unrelated reason is not a duplicate");
      assert.equal(result.duplicate, undefined);
      assert.equal(bodies.length, 3, "all retry attempts used for a genuine failure");
      assert.equal(listOutbox(outboxDir).length, 1, "genuine failure is written to the outbox");
    } finally {
      await server.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("U21/AC-21.3: attempt-1 lost (503) then attempt-2 409 → ok:true, no outbox", async () => {
    let n = 0;
    const server = await startServer((req, res, _body) => {
      n++;
      if (n === 1) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: "error" }));
        return;
      }
      res.writeHead(409, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "rejected", reason: "replay-detected" }));
    });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-dup-retry-"));
    try {
      const vaultRoot = path.join(tmp, "mesh", "agents");
      const agent0Dir = path.join(vaultRoot, "agent0");
      fs.mkdirSync(agent0Dir, { recursive: true });
      fs.writeFileSync(path.join(agent0Dir, "identity.yaml"), yamlDump({
        id: "agent0",
        allow_loopback: true,
        transports: { hermes_webhook: { url: `${server.url}/mesh/receive`, auth: { public_key: "" } } },
      }));
      const outboxDir = path.join(tmp, "outbox");
      const peer = resolvePeer(vaultRoot, "agent0")!;
      const extra = { privateKeyPath: path.join(tmp, "k.pem"), outboxDir, deliveryRetries: 3, deliveryBackoffMs: 0 };
      const result = await sendToAgent("emts", peer, "reply text", "do", "yes", "t-1", { pluginConfig: extra });
      assert.equal(result.ok, true, "the 409 on retry proves attempt 1 already landed");
      assert.equal(result.duplicate, true);
      assert.equal(n, 2, "one failed attempt, one duplicate-suppressed attempt");
      assert.equal(listOutbox(outboxDir).length, 0, "no phantom outbox entry for a delivered message");
    } finally {
      await server.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// U22 — key-trap guard: never mint a keypair over an existing identity
// ---------------------------------------------------------------------------
// michi's catch, 2026-10-09 (her Mac cutover): mesh_register with an explicit
// a2a_url but no public_key derived the key NAME from the URL hostname; that
// file was absent on her new host, so the code GENERATED a fresh keypair and
// wrote its public key into the vault — a silent identity rotation that breaks
// every peer holding the old key. Mirror of hermes-mesh f01ffd6: load the
// existing local keypair; REFUSE when an identity exists but its keypair is
// missing; generate only for a brand-new agent (the legitimate bootstrap).
describe("U22 key-trap guard", () => {
  function withTempHome<T>(fn: (tmp: string) => T): T {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-kt-"));
    const original = process.env.HOME;
    process.env.HOME = tmp;
    try {
      return fn(tmp);
    } finally {
      if (original !== undefined) process.env.HOME = original;
      else delete process.env.HOME;
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }

  it("U22/AC-22.1: brand-new agent, no keypair → generates (bootstrap)", () => {
    withTempHome((tmp) => {
      const vaultRoot = path.join(tmp, "vault", "agents");
      fs.mkdirSync(vaultRoot, { recursive: true });
      const r = registerAgent(vaultRoot, "fresh", "http://127.0.0.1:18860", {});
      assert.ok(r.public_key.includes("BEGIN PUBLIC KEY"));
      assert.ok(fs.existsSync(path.join(tmp, ".mesh", "keys", "fresh.pem")), "bootstrap minted the agent-named key");
    });
  });

  it("U22/AC-22.2: existing identity + missing keypair → REFUSED, no mint, no write", () => {
    withTempHome((tmp) => {
      const vaultRoot = path.join(tmp, "vault", "agents");
      fs.mkdirSync(vaultRoot, { recursive: true });
      // seed an identity WITHOUT a local keypair (explicit public_key path)
      const { publicKey } = generateKeyPair();
      const seeded = registerAgent(vaultRoot, "victim", "http://127.0.0.1:18860", { public_key: publicKey });
      const before = fs.readFileSync(seeded.path, "utf-8");
      assert.throws(
        () => registerAgent(vaultRoot, "victim", "http://127.0.0.1:18860", {}),
        /existing mesh identity but no local keypair/,
      );
      assert.ok(!fs.existsSync(path.join(tmp, ".mesh", "keys", "victim.pem")), "refusal did not mint a key");
      assert.equal(fs.readFileSync(seeded.path, "utf-8"), before, "identity untouched");
    });
  });

  it("U22/AC-22.3: re-register loads the existing keypair — pubkey stable, URL updated", () => {
    withTempHome((tmp) => {
      const vaultRoot = path.join(tmp, "vault", "agents");
      fs.mkdirSync(vaultRoot, { recursive: true });
      const first = registerAgent(vaultRoot, "steady", "http://127.0.0.1:18870", {});
      const keyPath = path.join(tmp, ".mesh", "keys", "steady.pem");
      const keyBefore = fs.readFileSync(keyPath, "utf-8");
      const second = registerAgent(vaultRoot, "steady", "http://127.0.0.1:18870", { a2a_url: "http://127.0.0.1:18899" });
      assert.equal(second.public_key, first.public_key, "pubkey stable across re-register");
      assert.equal(fs.readFileSync(keyPath, "utf-8"), keyBefore, "key file untouched");
      const peer = resolvePeer(vaultRoot, "steady")!;
      assert.equal(peer.a2a_url, "http://127.0.0.1:18899", "URL updated");
    });
  });

  it("U22/AC-22.4: delete key then re-register → REFUSED, no re-mint", () => {
    withTempHome((tmp) => {
      const vaultRoot = path.join(tmp, "vault", "agents");
      fs.mkdirSync(vaultRoot, { recursive: true });
      const r = registerAgent(vaultRoot, "gone", "http://127.0.0.1:18860", {});
      const before = fs.readFileSync(r.path, "utf-8");
      fs.rmSync(path.join(tmp, ".mesh", "keys", "gone.pem"));
      assert.throws(
        () => registerAgent(vaultRoot, "gone", "http://127.0.0.1:18860", {}),
        /existing mesh identity but no local keypair/,
      );
      assert.ok(!fs.existsSync(path.join(tmp, ".mesh", "keys", "gone.pem")), "no re-mint after key loss");
      assert.equal(fs.readFileSync(r.path, "utf-8"), before, "identity untouched");
    });
  });

  it("U22/AC-22.5: a2a_url cannot switch key identity (michi replay)", () => {
    withTempHome((tmp) => {
      const vaultRoot = path.join(tmp, "vault", "agents");
      fs.mkdirSync(vaultRoot, { recursive: true });
      const first = registerAgent(vaultRoot, "michi", "http://127.0.0.1:18870", {});
      // re-register with the NEW URL — pre-fix this derived key name
      // "192.168.1.79", minted a fresh keypair and rotated the vault key.
      const second = registerAgent(vaultRoot, "michi", "http://127.0.0.1:18870", { a2a_url: "http://192.168.1.79:18869" });
      assert.equal(second.public_key, first.public_key, "key identity unchanged by URL change");
      assert.ok(!fs.existsSync(path.join(tmp, ".mesh", "keys", "192.168.1.79.pem")), "no hostname-derived key minted");
    });
  });
});

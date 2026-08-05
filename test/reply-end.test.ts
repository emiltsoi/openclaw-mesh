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
import { injectIntoSession } from "../src/injector.js";
import { makeOutboundPayload, registerMeshTools, resolvePeer, sendToAgent } from "../src/discovery.js";
import type { MeshEnvelope } from "../src/envelope.js";

function generateKeyPair() {
  return crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

describe("inbound terminal reply", () => {
  it("parses an inbound [reply:end] envelope from the wire", () => {
    const wireText = "[mesh][v:1][from:agent0][to:emts][id:thread-1][action:do][reply:end] wrap it up";
    const env = parseMeshEnvelope(wireText);
    assert.ok(env, "wire text parses to an envelope");
    assert.equal(env.from, "agent0");
    assert.equal(env.to, "emts");
    assert.equal(env.id, "thread-1");
    assert.equal(env.action, "do");
    assert.equal(env.reply, "end");
  });

  it("injectIntoSession preserves [reply:end] in the inbox record", async () => {
    const inboxDir = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-inbox-"));
    const inboxFile = path.join(inboxDir, "mesh-inbox.jsonl");
    const api: any = {
      pluginConfig: {
        inboxPath: inboxFile,
        mirrorInbound: "none",
        targetSessionKey: "agent:main:main",
      },
      config: {},
      runtime: {},
    };
    const wireText = "[mesh][v:1][from:agent0][to:emts][id:thread-1][action:do][reply:end] wrap it up";
    const envelope = parseMeshEnvelope(wireText);
    assert.ok(envelope, "wire text parses to an envelope");
    assert.equal(envelope.reply, "end");
    // Type-surface pin: MeshEnvelope.reply must accept "end" at compile time —
    // if the union regresses to "yes" | "no", this line fails typecheck.
    const typedEnd: MeshEnvelope = { from: "agent0", to: "emts", id: "thread-1", action: "do", reply: "end" };
    void typedEnd;
    try {
      await injectIntoSession(api, "wrap it up", envelope);
      const lines = fs.readFileSync(inboxFile, "utf-8").trim().split("\n").filter(Boolean);
      assert.equal(lines.length, 1, "exactly one inbox record delivered");
      const record = JSON.parse(lines[0]);
      assert.equal(record.sessionKey, "agent:main:main");
      assert.ok(record.text.startsWith("[mesh][from:agent0][to:emts]"));
      assert.ok(record.text.includes("[reply:end]"), `inbox text preserves reply=end: ${record.text}`);
    } finally {
      fs.rmSync(inboxDir, { recursive: true, force: true });
    }
  });
});

describe("mesh_send tool schema reply enum", () => {
  it("registers reply enum containing 'end'", () => {
    const tools: any[] = [];
    const api: any = {
      registerTool: (def: any) => {
        tools.push(def);
      },
    };
    registerMeshTools(api);
    const meshSend = tools.find((t) => t && t.name === "mesh_send");
    assert.ok(meshSend, "mesh_send tool registered");
    const reply = meshSend?.parameters?.properties?.reply;
    assert.ok(reply, "mesh_send defines a reply parameter");
    assert.ok(Array.isArray(reply.enum), "reply has an enum");
    assert.deepEqual(reply.enum, ["yes", "no", "end"]);
    assert.match(reply.description, /terminal reply/);
    assert.match(reply.description, /ref=<anchor>/);
  });
});

describe("outbound terminal reply", () => {
  it("makeOutboundPayload accepts reply=end and carries ref", () => {
    const payload = makeOutboundPayload("emts", "agent0", "closing thread", "do", "end", "msg-9", "anchor-1");
    assert.ok(payload.startsWith("[mesh][v:1][from:emts][to:agent0]"));
    assert.ok(payload.includes("[reply:end]"), `payload carries [reply:end]: ${payload}`);
    assert.ok(payload.includes("[ref:anchor-1]"), `payload carries [ref:anchor-1]: ${payload}`);
  });

  it("sendToAgent signs and POSTs a reply=end payload with ref", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-vault-"));
    const agentsRoot = path.join(tmp, "mesh", "agents");
    const agent0Dir = path.join(agentsRoot, "agent0");
    fs.mkdirSync(agent0Dir, { recursive: true });

    const captured: { body?: string } = {};
    const server = http.createServer((req, res) => {
      let body = "";
      req.setEncoding("utf-8");
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        captured.body = body;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: "ok" }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const serverUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}/mesh/receive`;

    const keyFile = path.join(tmp, "emts.pem");
    const { privateKey } = generateKeyPair();
    fs.writeFileSync(keyFile, privateKey, { mode: 0o600 });
    const senderPublic = crypto.createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();

    fs.writeFileSync(
      path.join(agent0Dir, "identity.yaml"),
      yamlDump({
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
      }),
    );

    try {
      const peer = resolvePeer(agentsRoot, "agent0")!;
      const extra = { privateKeyPath: keyFile };
      const result = await sendToAgent("emts", peer, "closing thread", "do", "end", "msg-9", { pluginConfig: extra }, "anchor-1", false);
      assert.equal(result.ok, true);
      assert.ok(captured.body, "request body was captured");
      const payload = JSON.parse(captured.body);
      assert.ok(payload.text.includes("[action:do][reply:end]"), `outbound payload carries [reply:end]: ${payload.text}`);
      assert.ok(payload.text.includes("[ref:anchor-1]"), `outbound payload carries [ref:anchor-1]: ${payload.text}`);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

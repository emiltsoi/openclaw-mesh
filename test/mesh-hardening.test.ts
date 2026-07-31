/// <reference types="node" />
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { makeOutboundPayload, sendToAgent } from "../src/discovery.js";
import { parseMeshEnvelope, validateTimestamp } from "../src/envelope.js";
import { extractMessageText } from "../src/index.js";
import { createDebugLogger, setDebugEnabled } from "../src/logging.js";
import { recordMetric, getMetric, getAllMetrics, resetMetrics } from "../src/metrics.js";
import { appendToOutbox, listOutbox, cleanOutbox } from "../src/outbox.js";
import { createReplayWindow } from "../src/replay.js";
import { signMessage, verifyMessage } from "../src/registry.js";

function generateKeyPair() {
  return crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

describe("parseMeshEnvelope ref", () => {
  it("parses a [ref:...] envelope", () => {
    const env = parseMeshEnvelope("[mesh][from:agent0][to:emts][id:123][action:do][reply:yes][ref:thread-1] Hello");
    assert.equal(env?.from, "agent0");
    assert.equal(env?.to, "emts");
    assert.equal(env?.id, "123");
    assert.equal(env?.action, "do");
    assert.equal(env?.reply, "yes");
    assert.equal(env?.ref, "thread-1");
  });

  it("returns undefined ref when absent", () => {
    const env = parseMeshEnvelope("[mesh][from:agent0][to:emts][id:123] Hello");
    assert.equal(env?.ref, undefined);
  });
});

describe("makeOutboundPayload ref", () => {
  it("emits a [ref:...] header when ref is provided", () => {
    const payload = makeOutboundPayload("emts", "agent0", "ping", "do", "yes", "abc", "thread-1");
    assert.ok(payload.startsWith("[mesh][v:1][from:emts][to:agent0]"));
    assert.ok(payload.includes("[ref:thread-1]"));
    assert.ok(payload.includes("[action:do][reply:yes]"));
    assert.ok(payload.endsWith(" ping"));
  });

  it("skips [ref:...] when ref is empty", () => {
    const payload = makeOutboundPayload("emts", "agent0", "ping");
    assert.equal(payload.includes("[ref:"), false);
  });
});

describe("extractMessageText ref", () => {
  it("reconstructs an envelope with ref from payload.envelope", () => {
    const text = extractMessageText({
      envelope: {
        from: "agent0",
        to: "emts",
        id: "123",
        action: "do",
        reply: "yes",
        ref: "thread-1",
      },
      message: "hello",
    });
    assert.equal(text, "[mesh][from:agent0][to:emts][id:123][action:do][reply:yes][ref:thread-1] hello");
  });
});

describe("validateTimestamp", () => {
  it("accepts a current timestamp", () => {
    const now = String(Math.floor(Date.now() / 1000));
    const result = validateTimestamp({ "x-mesh-timestamp": now });
    assert.equal(result.ok, true);
  });

  it("rejects a missing timestamp", () => {
    const result = validateTimestamp({});
    assert.equal(result.ok, false);
    assert.equal(result.reason, "missing x-mesh-timestamp");
  });

  it("rejects a NaN timestamp", () => {
    const result = validateTimestamp({ "x-mesh-timestamp": "not-a-number" });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "invalid x-mesh-timestamp");
  });

  it("rejects a stale timestamp", () => {
    const stale = String(Math.floor(Date.now() / 1000) - 400);
    const result = validateTimestamp({ "x-mesh-timestamp": stale });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "x-mesh-timestamp outside replay window");
  });
});

describe("Ed25519 signature round-trip", () => {
  it("signs and verifies a payload", () => {
    const { privateKey, publicKey } = generateKeyPair();
    const body = Buffer.from(JSON.stringify({ from: "agent0", text: "[mesh][from:agent0][to:emts][id:1] hi" }));
    const sig = signMessage(privateKey, body);
    const badSig = crypto.randomBytes(64).toString("base64");
    assert.equal(verifyMessage(publicKey, body, sig), true);
    assert.equal(verifyMessage(publicKey, body, badSig), false);
  });

  it("verifies a timestamped signature", () => {
    const { privateKey, publicKey } = generateKeyPair();
    const ts = String(Math.floor(Date.now() / 1000));
    const body = Buffer.from(JSON.stringify({ from: "agent0", text: "hi" }));
    const signed = `${ts}\n${body}`;
    const sig = signMessage(privateKey, Buffer.from(signed, "utf-8"));
    assert.equal(verifyMessage(publicKey, Buffer.from(signed, "utf-8"), sig), true);
    assert.equal(verifyMessage(publicKey, body, sig), false);
  });
});

describe("replay window", () => {
  it("tracks and dedups ids within the TTL", () => {
    const window = createReplayWindow({ ttlMs: 1000, maxSize: 100 });
    assert.equal(window.has("id-1"), false);
    window.add("id-1");
    assert.equal(window.has("id-1"), true);
    assert.equal(window.has("id-2"), false);
  });

  it("evicts ids after the TTL", async () => {
    const window = createReplayWindow({ ttlMs: 50, maxSize: 100 });
    window.add("id-1");
    assert.equal(window.has("id-1"), true);
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(window.has("id-1"), false);
  });
});

describe("metrics", () => {
  it("records and reads counters", () => {
    resetMetrics();
    recordMetric("send", "success");
    recordMetric("send", "success");
    recordMetric("send", "failure");
    assert.equal(getMetric("send", "success"), 2);
    assert.equal(getMetric("send", "failure"), 1);
    const all = getAllMetrics();
    assert.equal(all["send:success"], 2);
    assert.equal(all["send:failure"], 1);
  });
});

describe("outbox", () => {
  it("appends and lists failed send/receive entries", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-outbox-"));
    const now = Date.now();
    appendToOutbox({ direction: "send", ts: now - 1, peer: "agent0", text: "ping", error: "timeout" }, dir);
    appendToOutbox({ direction: "receive", ts: now, peer: "agent0", text: "pong", error: "injection failed" }, dir);
    const entries = listOutbox(dir);
    assert.equal(entries.length, 2);
    assert.equal(entries[0].direction, "receive");
    assert.equal(entries[1].direction, "send");
    const removed = cleanOutbox(-1, dir);
    assert.equal(removed, 1);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

describe("debug logger redaction", () => {
  it("redacts telegram tokens", () => {
    const logger = createDebugLogger("/tmp/openclaw-mesh-test-redact.log");
    setDebugEnabled(true);
    let captured = "";
    const original = console.error;
    console.error = (msg: any) => {
      captured += msg;
    };
    try {
      logger("bot123456:ABC-DEF token and 00112233445566778899aabbccddeeff");
    } finally {
      console.error = original;
      setDebugEnabled(false);
    }
    assert.ok(captured.includes("***telegram-bot-token***"));
  });
});

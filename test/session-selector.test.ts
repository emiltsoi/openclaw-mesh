import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseMeshEnvelope, validateMeshToken } from "../src/envelope.js";
import { makeOutboundPayload } from "../src/discovery.js";

describe("session-selector parseMeshEnvelope (0.1.8 canonical vectors)", () => {
  it("parses [session] + [from_session] tokens", () => {
    const env = parseMeshEnvelope(
      "[mesh][from:vesper][to:vera][id:m1][session:review][from_session:chat][action:do][reply:yes] Hello"
    );
    assert.ok(env);
    assert.equal(env.session, "review");
    assert.equal(env.fromSession, "chat");
    assert.equal(env.action, "do");
    assert.equal(env.reply, "yes");
    assert.equal(env.body, "Hello");
  });

  it("parses absent session tokens as undefined (backward-compatible)", () => {
    const env = parseMeshEnvelope(
      "[mesh][from:hermes-0][to:diploid-0][id:m2][action:do][reply:yes] Hello"
    );
    assert.ok(env);
    assert.equal(env.session, undefined);
    assert.equal(env.fromSession, undefined);
  });

  it("parses session-only (no from_session)", () => {
    const env = parseMeshEnvelope(
      "[mesh][from:a][to:b][id:m3][session:review][action:info][reply:no] Hi"
    );
    assert.ok(env);
    assert.equal(env.session, "review");
    assert.equal(env.fromSession, undefined);
  });

  it("validates session tokens against the alphabet (rejects #)", () => {
    assert.throws(() =>
      parseMeshEnvelope("[mesh][from:a][to:b][id:m4][session:rev#iew][action:do][reply:yes]")
    );
  });

  it("validates from_session tokens against the alphabet", () => {
    assert.throws(() =>
      parseMeshEnvelope("[mesh][from:a][to:b][id:m5][from_session:bad space][action:do][reply:yes]")
    );
  });
});

describe("session-selector makeOutboundPayload (0.1.8)", () => {
  it("emits session + from_session in canonical order after [id]", () => {
    const text = makeOutboundPayload(
      "vesper", "vera", "Hello", "do", "yes", "m6", undefined,
      "review", "chat"
    );
    // Canonical: [from][to][id][session][from_session][action][reply]
    assert.ok(text.includes("[to:vera][id:m6][session:review][from_session:chat][action:do]"), text);
    // Round-trip parses back.
    const env = parseMeshEnvelope(text);
    assert.ok(env);
    assert.equal(env.session, "review");
    assert.equal(env.fromSession, "chat");
  });

  it("omits session tokens when absent (backward-compatible)", () => {
    const text = makeOutboundPayload("a", "b", "Hi", "info", "no");
    assert.ok(!text.includes("[session:"));
    assert.ok(!text.includes("[from_session:"));
  });

  it("validates session tokens (rejects invalid)", () => {
    assert.throws(() =>
      makeOutboundPayload("a", "b", "Hi", "do", "yes", "m7", undefined, "bad#session")
    );
  });

  it("reply swap: caller passes the originating session as its session", () => {
    // The reply to a message that carried [from_session:chat] sends
    // [session:chat] (landing in the originating session).
    const reply = makeOutboundPayload(
      "vera", "vesper", "Pong", "do", "yes", "m8", "m1",
      "chat" // swapped: the original's from_session becomes the reply's session
    );
    assert.ok(reply.includes("[session:chat]"), reply);
    assert.ok(reply.includes("[ref:m1]"), reply);
  });
});

describe("session-selector validateMeshToken", () => {
  it("accepts valid session names (letters, digits, dots, colons)", () => {
    assert.equal(validateMeshToken("review", "session"), "review");
    assert.equal(validateMeshToken("review:gate", "session"), "review:gate");
    assert.equal(validateMeshToken("session-1.2", "session"), "session-1.2");
  });

  it("rejects # (not in the shared alphabet)", () => {
    assert.throws(() => validateMeshToken("rev#iew", "session"));
  });
});

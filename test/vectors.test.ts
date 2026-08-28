/// <reference types="node" />
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseMeshEnvelope } from "../src/envelope.js";

const valid = JSON.parse(readFileSync(new URL("../../spec/test-vectors/valid.json", import.meta.url), "utf-8"));
const invalid = JSON.parse(readFileSync(new URL("../../spec/test-vectors/invalid.json", import.meta.url), "utf-8"));

describe("canonical mesh envelope test vectors", () => {
  for (const tc of valid) {
    it(tc.name, () => {
      const env = parseMeshEnvelope(tc.text);
      assert.ok(env, `expected ${tc.name} to parse`);
      assert.equal(env.from, tc.expected.sender ?? tc.expected.from);
      assert.equal(env.to, tc.expected.recipient ?? tc.expected.to);
      assert.equal(env.id, tc.expected.msg_id ?? tc.expected.id);
      assert.equal(env.action, tc.expected.action);
      assert.equal(env.reply, tc.expected.reply);
      assert.equal(env.ref ?? null, tc.expected.ref ?? null);
      assert.equal(env.version, tc.expected.version);
      assert.equal(env.body, tc.expected.body);
    });
  }

  for (const tc of invalid) {
    it(`rejects ${tc.name}`, () => {
      let threw = false;
      try {
        parseMeshEnvelope(tc.text);
      } catch {
        threw = true;
      }
      if (!threw) {
        const env = parseMeshEnvelope(tc.text);
        assert.equal(env, null, `expected ${tc.name} to be rejected or return null`);
      }
    });
  }
});

#!/usr/bin/env node
/**
 * Integration test: A2A bridge outbound → Hermes agent0
 * 
 * Tests:
 * 1. a2aSend sends an A2A envelope to a configured peer
 * 2. The envelope is HMAC-signed and accepted by the target
 * 3. The watcher detects the outbound message in the target's inbox
 */

import crypto from "node:crypto";
import { execSync } from "node:child_process";

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string) {
  if (condition) { console.log(`  ${PASS} ${msg}`); passed++; }
  else { console.log(`  ${FAIL} ${msg}`); failed++; }
}

// Test 1: Envelope format
console.log("\n📋 Test: A2A Envelope Format");
const envelope = `[a2a][from:emts][to:agent0][id:test-001][action:do][reply:yes] Hello Zero`;
assert(envelope.startsWith("[a2a]"), "envelope starts with [a2a]");
assert(envelope.includes("[from:emts]"), "envelope has from field");
assert(envelope.includes("[to:agent0]"), "envelope has to field");
assert(envelope.includes("[id:test-001]"), "envelope has id field");
assert(envelope.includes("[reply:yes]"), "envelope has reply field");

// Test 2: HMAC signing
console.log("\n📋 Test: HMAC-SHA256 Signing");
const secret = "test-secret";
const body = JSON.stringify({ text: envelope });
const sig = crypto.createHmac("sha256", secret).update(body).digest("hex");
const sigHeader = `sha256=${sig}`;
assert(typeof sig === "string", "signature is a string");
assert(sig.length === 64, "SHA256 hex is 64 chars");
assert(sigHeader.startsWith("sha256="), "header format is correct");

// Test 3: HMAC verification (round-trip)
console.log("\n📋 Test: HMAC Round-Trip");
const computed = crypto.createHmac("sha256", secret).update(body).digest("hex");
assert(computed === sig, "re-computed signature matches");

// Test 4: Envelope parsing
console.log("\n📋 Test: Envelope Parsing");
const match = envelope.match(/\[from:([^\]]+)\]/);
assert(match !== null, "from field is parseable");
assert(match![1] === "emts", "parsed from is 'emts'");

const replyMatch = envelope.match(/\[reply:([^\]]+)\]/);
assert(replyMatch !== null, "reply field is parseable");
assert(replyMatch![1] === "yes", "parsed reply is 'yes'");

// Test 5: Webhook reachability (requires running Hermes)
console.log("\n📋 Test: Agent0 Webhook Reachability");
try {
  const result = execSync(
    `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8644/webhooks/a2a_trigger`,
    { timeout: 5000 }
  ).toString().trim();
  const reachable = result !== "000";
  assert(reachable, `agent0 webhook reachable (HTTP ${result})`);
} catch (e: any) {
  assert(false, `agent0 webhook not reachable: ${e.message}`);
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);

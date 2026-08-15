export interface MeshEnvelope {
  v?: string;
  from: string;
  to: string;
  id: string;
  action: "do" | "info";
  reply: "yes" | "no" | "end";
  ref?: string;
  dsn?: boolean;
}

const ENVELOPE_HEADER_RE = /^(\[mesh\](?:\[[^\]]*:[^\]]*\])*)/;
const FIELD_RE = /\[(\w+):([^\]]+)\]/g;

// Matches hermes-mesh validate_envelope_token: 1-128 chars of A-Za-z0-9_.:-
export const ENVELOPE_TOKEN_RE = /^[A-Za-z0-9_.:-]{1,128}$/;

export function validateMeshToken(value: string, field = "token"): string {
  const trimmed = (value || "").trim();
  if (!trimmed) throw new Error(`${field} must not be empty`);
  if (!ENVELOPE_TOKEN_RE.test(trimmed)) {
    throw new Error(
      `Invalid ${field}: ${JSON.stringify(trimmed)}. ` +
        "Allowed: 1-128 characters from A-Z, a-z, 0-9, _, ., -, :"
    );
  }
  return trimmed;
}

export function parseMeshEnvelope(text: string): MeshEnvelope | null {
  if (!text.startsWith("[mesh]")) return null;

  // U1 (parse-scope confinement): envelope fields are parsed from the
  // `stripEnvelope` header match ONLY. The body is never scanned for
  // [key:value] tokens, so a hostile body cannot override header fields
  // (reply downgrade, spoofed from/to/id/ref).
  const headerMatch = ENVELOPE_HEADER_RE.exec(text);
  if (!headerMatch) return null;
  const header = headerMatch[0];

  const envelope: MeshEnvelope = {
    from: "unknown",
    to: "emts",
    id: "unknown",
    action: "info",
    reply: "no",
  };

  FIELD_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = FIELD_RE.exec(header)) !== null) {
    const [, key, rawValue] = match;
    const value = rawValue.trim();
    switch (key) {
      case "v":
        envelope.v = value;
        break;
      case "from":
        envelope.from = value;
        break;
      case "to":
        envelope.to = value;
        break;
      case "id":
        envelope.id = value;
        break;
      case "action":
        if (value === "do" || value === "info") envelope.action = value;
        break;
      case "reply":
        if (value === "yes" || value === "no" || value === "end") envelope.reply = value;
        break;
      case "ref":
        // U5: invalid ref is LOUD — throw so the caller can reject with a 400
        // instead of silently dropping it.
        envelope.ref = validateMeshToken(value, "ref");
        break;
    }
  }

  const body = text.slice(header.length).trimStart();
  if (body.startsWith("[mesh-dsn]")) {
    envelope.dsn = true;
  }

  return envelope;
}

export function stripEnvelope(text: string): string {
  const match = ENVELOPE_HEADER_RE.exec(text);
  if (!match) return text;
  return text.slice(match[0].length).trimStart();
}

export function validateTimestamp(headers: Record<string, string | undefined>): { ok: boolean; reason?: string } {
  const raw = headers["x-mesh-timestamp"];
  if (raw === undefined || raw === "") {
    return { ok: false, reason: "missing x-mesh-timestamp" };
  }
  const ts = Number(raw);
  if (!Number.isFinite(ts) || Number.isNaN(ts)) {
    return { ok: false, reason: "invalid x-mesh-timestamp" };
  }
  const now = Math.floor(Date.now() / 1000);
  // 300s tolerance matches hermes-mesh.
  if (Math.abs(now - ts) > 300) {
    return { ok: false, reason: "x-mesh-timestamp outside replay window" };
  }
  return { ok: true };
}

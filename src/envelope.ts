export interface MeshEnvelope {
  v?: string;
  from: string;
  to: string;
  id: string;
  action: "do" | "info";
  reply: "yes" | "no";
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

  const envelope: MeshEnvelope = {
    from: "unknown",
    to: "emts",
    id: "unknown",
    action: "info",
    reply: "no",
  };

  let match: RegExpExecArray | null;
  while ((match = FIELD_RE.exec(text)) !== null) {
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
        if (value === "yes" || value === "no") envelope.reply = value;
        break;
      case "ref":
        try {
          envelope.ref = validateMeshToken(value, "ref");
        } catch {
          // Drop an invalid ref instead of failing the whole message.
          envelope.ref = undefined;
        }
        break;
    }
  }

  const body = stripEnvelope(text);
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

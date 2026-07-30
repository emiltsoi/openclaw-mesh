export interface MeshEnvelope {
  from: string;
  to: string;
  id: string;
  action: "do" | "info";
  reply: "yes" | "no";
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
    }
  }

  return envelope;
}

export function stripEnvelope(text: string): string {
  const match = ENVELOPE_HEADER_RE.exec(text);
  if (!match) return text;
  return text.slice(match[0].length).trimStart();
}

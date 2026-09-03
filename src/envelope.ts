export interface MeshEnvelope {
  version?: string;
  from: string;
  to: string;
  id: string;
  action: "do" | "info";
  reply: "yes" | "no" | "end";
  ref?: string;
  session?: string;
  fromSession?: string;
  dsn?: boolean;
  body: string;
}

// Canonical mesh envelope header pattern, kept in sync with
// mesh-peer-registry/spec/envelope.schema.json.
// Order is strict: [mesh] [v:?] [from] [to] [id] [session?] [from_session?] [action:?] [reply:?] [ref:?]
const MESH_ENVELOPE_RE =
  /^\s*\[mesh\](?:\[v:([^\]]+)\])?\[from:([^\]]+)\]\[to:([^\]]+)\]\[id:([^\]]+)\](?:\[session:([^\]]+)\])?(?:\[from_session:([^\]]+)\])?(?:\[action:([^\]]+)\])?(?:\[reply:([^\]]+)\])?(?:\[ref:([^\]]+)\])?/;

// Loose header matcher used only by stripEnvelope. It removes any bracketed
// [key:value] tokens after [mesh] without validating them, so callers that
// already received a well-formed envelope can extract the body text.
const ENVELOPE_HEADER_RE = /^(\[mesh\](?:\[[^\]]*:[^\]]*\])*)/;

const VALID_ACTIONS = new Set<"do" | "info">(["do", "info"]);
const VALID_REPLIES = new Set<"yes" | "no" | "end">(["yes", "no", "end"]);

// Matches mesh_core.validate_envelope_token: 1-128 chars of A-Za-z0-9_.:-
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

export class MeshEnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MeshEnvelopeError";
  }
}

/**
 * Parse a bracketed [mesh] envelope.
 *
 * - Returns null for text that does not start with a [mesh] header at all.
 * - Throws MeshEnvelopeError for text that starts with [mesh] but is malformed
 *   or contains invalid tokens/values. This lets callers distinguish a non-mesh
 *   payload (200 ignored) from a bad mesh payload (400 bad-request).
 *
 * Missing action/reply default to the conservative values info/no, matching
 * mesh_core.parse_envelope.
 */
export function parseMeshEnvelope(text: string): MeshEnvelope | null {
  if (!text.startsWith("[mesh]")) return null;

  const m = MESH_ENVELOPE_RE.exec(text);
  if (!m) {
    throw new MeshEnvelopeError("Malformed mesh envelope header");
  }

  const [
    ,
    rawVersion,
    rawFrom,
    rawTo,
    rawId,
    rawSession,
    rawFromSession,
    rawAction,
    rawReply,
    rawRef,
  ] = m;

  const version = rawVersion ? validateMeshToken(rawVersion, "version") : undefined;
  const from = validateMeshToken(rawFrom, "from");
  const to = validateMeshToken(rawTo, "to");
  const id = validateMeshToken(rawId, "id");

  const session = rawSession ? validateMeshToken(rawSession, "session") : undefined;
  const fromSession = rawFromSession
    ? validateMeshToken(rawFromSession, "from_session")
    : undefined;

  const actionRaw = (rawAction ?? "info").trim();
  if (!VALID_ACTIONS.has(actionRaw as any)) {
    throw new MeshEnvelopeError(`Invalid action: ${JSON.stringify(actionRaw)}; must be 'do' or 'info'`);
  }
  const action: "do" | "info" = actionRaw as any;

  const replyRaw = (rawReply ?? "no").trim();
  if (!VALID_REPLIES.has(replyRaw as any)) {
    throw new MeshEnvelopeError(`Invalid reply: ${JSON.stringify(replyRaw)}; must be 'yes', 'no', or 'end'`);
  }
  const reply: "yes" | "no" | "end" = replyRaw as any;

  const ref = rawRef ? validateMeshToken(rawRef, "ref") : undefined;

  const body = text.slice(m[0].length).trimStart();
  const dsn = body.startsWith("[mesh-dsn]");

  return {
    version,
    from,
    to,
    id,
    action,
    reply,
    ref,
    session,
    fromSession,
    dsn,
    body,
  };
}

export function stripEnvelope(text: string): string {
  const m = ENVELOPE_HEADER_RE.exec(text);
  if (!m) return text;
  return text.slice(m[0].length).trimStart();
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

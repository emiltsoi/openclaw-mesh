export interface A2AEnvelope {
  from: string;
  to: string;
  id: string;
  action: "do" | "info";
  reply: "yes" | "no";
}

export function parseA2AEnvelope(text: string): A2AEnvelope | null {
  if (!text.startsWith("[a2a]")) return null;
  const defaults: A2AEnvelope = { from: "unknown", to: "emts", id: "unknown", action: "info", reply: "no" };
  const regex = /\[(\w+):([^\]]+)\]/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(text)) !== null) {
    const [, key, rawValue] = match;
    const value = rawValue.trim();
    switch (key) {
      case "from": defaults.from = value; break;
      case "to": defaults.to = value; break;
      case "id": defaults.id = value; break;
      case "action": if (value === "do" || value === "info") defaults.action = value; break;
      case "reply": if (value === "yes" || value === "no") defaults.reply = value; break;
    }
  }
  return defaults;
}

export function stripEnvelope(text: string): string {
  const lastBracket = text.lastIndexOf("]");
  if (lastBracket === -1) return text;
  return text.slice(lastBracket + 1).trimStart();
}

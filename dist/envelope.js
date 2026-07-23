"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseA2AEnvelope = parseA2AEnvelope;
exports.stripEnvelope = stripEnvelope;
function parseA2AEnvelope(text) {
    if (!text.startsWith("[a2a]"))
        return null;
    const defaults = { from: "unknown", to: "emts", id: "unknown", action: "info", reply: "no" };
    const regex = /\[(\w+):([^\]]+)\]/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
        const [, key, rawValue] = match;
        const value = rawValue.trim();
        switch (key) {
            case "from":
                defaults.from = value;
                break;
            case "to":
                defaults.to = value;
                break;
            case "id":
                defaults.id = value;
                break;
            case "action":
                if (value === "do" || value === "info")
                    defaults.action = value;
                break;
            case "reply":
                if (value === "yes" || value === "no")
                    defaults.reply = value;
                break;
        }
    }
    return defaults;
}
function stripEnvelope(text) {
    const lastBracket = text.lastIndexOf("]");
    if (lastBracket === -1)
        return text;
    return text.slice(lastBracket + 1).trimStart();
}

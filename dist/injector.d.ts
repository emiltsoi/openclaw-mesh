/**
 * injectIntoSession — inject A2A inbound messages into the OpenClaw agent session
 * via the Gateway RPC client (replacing the broken SDK + hooks/wake approach).
 */
import type { A2AEnvelope } from "./envelope.js";
export declare let cachedBotToken: string;
export declare let cachedChatId: string;
export declare function injectIntoSession(api: any, messageText: string, envelope: A2AEnvelope): Promise<void>;

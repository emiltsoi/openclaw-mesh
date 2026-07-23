import type { A2AEnvelope } from "./envelope.js";
export declare let cachedBotToken: string;
export declare let cachedChatId: string;
export declare function injectIntoSession(api: any, messageText: string, envelope: A2AEnvelope): Promise<void>;

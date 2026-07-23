/**
 * Send an A2A message to a Hermes peer.
 * Uses the hermes-mesh webhook protocol (same envelope format + HMAC-SHA256).
 */
export declare function a2aSend(api: any, params: {
    target: string;
    message: string;
    action?: "do" | "info";
    replyExpected?: boolean;
}): Promise<string>;

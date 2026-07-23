/**
 * Lightweight GatewayRpcClient — connection/auth/dispatch only.
 *
 * Extracted from the a2a-gateway plugin executor. Handles:
 * - WebSocket connect to the OpenClaw Gateway
 * - connect.challenge nonce → device identity signing
 * - `connect` RPC auth
 * - `agent` RPC dispatch (fire-and-forget: open, send, close per message)
 *
 * Node 22 built-in WebSocket is used (no ws package dependency).
 */
export interface GatewayRpcClientConfig {
    wsUrl: string;
    gatewayToken?: string;
    password?: string;
    agentResponseTimeoutMs?: number;
}
export interface AgentDispatchParams {
    agentId: string;
    sessionKey: string;
    message: string;
    idempotencyKey: string;
    deliver?: boolean;
}
export declare class GatewayRpcClient {
    private wsUrl;
    private gatewayToken;
    private password;
    private agentResponseTimeoutMs;
    constructor(config: GatewayRpcClientConfig);
    dispatchAgentMessage(sessionKey: string, message: string): Promise<void>;
    dispatch(agentId: string, sessionKey: string, message: string, idempotencyKey: string, deliver?: boolean): Promise<void>;
    private openConnect;
    private request;
    private buildConnectParams;
    private closeSocket;
}

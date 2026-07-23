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
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { v4 as uuidv4 } from "uuid";
// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const CONNECT_TIMEOUT_MS = 10_000;
const CHALLENGE_TIMEOUT_MS = 2_000;
const REQUEST_TIMEOUT_MS = 10_000;
let _deviceIdentity = null;
function getOrCreateDeviceIdentity() {
    if (_deviceIdentity)
        return _deviceIdentity;
    const openclawHome = process.env.OPENCLAW_HOME || path.join(os.homedir(), ".openclaw");
    const deviceJsonPath = path.join(openclawHome, "identity", "device.json");
    try {
        const raw = fs.readFileSync(deviceJsonPath, "utf-8");
        const json = JSON.parse(raw);
        if (json.deviceId && json.publicKeyPem && json.privateKeyPem) {
            const privateKey = crypto.createPrivateKey(json.privateKeyPem);
            const publicKey = crypto.createPublicKey(json.publicKeyPem);
            const publicKeyRaw = publicKey.export({ type: "spki", format: "der" });
            const rawBytes = publicKeyRaw.subarray(12);
            const publicKeyB64Url = rawBytes.toString("base64url");
            _deviceIdentity = { publicKey: publicKeyB64Url, privateKey, deviceId: json.deviceId };
            return _deviceIdentity;
        }
    }
    catch {
        // Fall through to ephemeral key generation
    }
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyRaw = publicKey.export({ type: "spki", format: "der" });
    const rawBytes = publicKeyRaw.subarray(12);
    const publicKeyB64Url = rawBytes.toString("base64url");
    const deviceId = crypto.createHash("sha256").update(rawBytes).digest("hex");
    _deviceIdentity = { publicKey: publicKeyB64Url, privateKey, deviceId };
    return _deviceIdentity;
}
// ---------------------------------------------------------------------------
// GatewayRpcClient
// ---------------------------------------------------------------------------
export class GatewayRpcClient {
    wsUrl;
    gatewayToken;
    password;
    agentResponseTimeoutMs;
    constructor(config) {
        if (!config.wsUrl)
            throw new Error("GatewayRpcClient: wsUrl is required");
        this.wsUrl = config.wsUrl;
        this.gatewayToken = config.gatewayToken ?? "";
        this.password = config.password ?? "";
        this.agentResponseTimeoutMs = config.agentResponseTimeoutMs ?? 300_000;
    }
    async dispatchAgentMessage(sessionKey, message) {
        const idempotencyKey = "a2a-" + crypto.randomUUID();
        await this.dispatch("main", sessionKey, message, idempotencyKey);
    }
    async dispatch(agentId, sessionKey, message, idempotencyKey, deliver = false) {
        const { socket, challengeNonce } = await this.openConnect();
        try {
            const params = {
                agentId,
                sessionKey,
                message,
                deliver,
                idempotencyKey,
            };
            await this.request(socket, "agent", params, this.agentResponseTimeoutMs);
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            throw new Error("Gateway dispatch failed: " + msg);
        }
        finally {
            this.closeSocket(socket);
        }
    }
    async openConnect() {
        const ctor = globalThis.WebSocket;
        if (!ctor) {
            throw new Error("GatewayRpcClient: WebSocket runtime unavailable (Node 22+ required)");
        }
        const socket = new ctor(this.wsUrl);
        await new Promise((resolve, reject) => {
            let settled = false;
            const cleanup = () => {
                socket.removeEventListener("open", onOpen);
                socket.removeEventListener("error", onError);
                socket.removeEventListener("close", onClose);
            };
            const settle = (err) => {
                if (settled)
                    return;
                settled = true;
                clearTimeout(timer);
                cleanup();
                if (err) {
                    reject(err);
                    return;
                }
                resolve();
            };
            const onOpen = () => settle(null);
            const onError = () => settle(new Error("Failed to open Gateway WebSocket"));
            const onClose = () => settle(new Error("Gateway WebSocket closed during connect"));
            const timer = setTimeout(() => settle(new Error("Gateway WebSocket connect timed out")), CONNECT_TIMEOUT_MS);
            socket.addEventListener("open", onOpen);
            socket.addEventListener("error", onError);
            socket.addEventListener("close", onClose);
        });
        let challengeNonce = "";
        await new Promise((resolve, reject) => {
            let settled = false;
            const timer = setTimeout(() => { if (!settled) {
                settled = true;
                reject(new Error("Gateway connect.challenge timed out"));
            } }, CHALLENGE_TIMEOUT_MS);
            const onMessage = (event) => {
                const raw = typeof event.data === "string" ? event.data : "";
                if (!raw)
                    return;
                try {
                    const frame = JSON.parse(raw);
                    if (frame?.type === "event" && frame?.event === "connect.challenge") {
                        const nonce = (frame?.payload?.nonce ?? "").trim();
                        if (nonce) {
                            challengeNonce = nonce;
                            socket.removeEventListener("message", onMessage);
                            clearTimeout(timer);
                            settled = true;
                            resolve();
                        }
                    }
                }
                catch { /* skip */ }
            };
            const onClose = () => { if (!settled) {
                settled = true;
                reject(new Error("Gateway WebSocket closed before challenge"));
            } };
            socket.addEventListener("message", onMessage);
            socket.addEventListener("close", onClose);
        });
        await this.request(socket, "connect", this.buildConnectParams(challengeNonce), CONNECT_TIMEOUT_MS);
        return { socket, challengeNonce };
    }
    request(socket, method, params, timeoutMs) {
        const id = uuidv4();
        const frame = { type: "req", id, method, params };
        const payload = JSON.stringify(frame);
        if (socket.readyState !== WebSocket.OPEN) {
            return Promise.reject(new Error("Gateway WebSocket not open (readyState=" + socket.readyState + ")"));
        }
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                reject(new Error("Gateway request timed out: " + method));
            }, timeoutMs);
            const onMessage = (event) => {
                const raw = typeof event.data === "string" ? event.data : "";
                if (!raw)
                    return;
                try {
                    const res = JSON.parse(raw);
                    if (res?.type === "res" && res?.id === id) {
                        socket.removeEventListener("message", onMessage);
                        socket.removeEventListener("close", onClose);
                        clearTimeout(timer);
                        if (res.ok === true) {
                            resolve(res.payload);
                        }
                        else {
                            const errMsg = res?.error?.message || ("Gateway method failed: " + method);
                            reject(new Error(errMsg));
                        }
                    }
                }
                catch { /* skip */ }
            };
            const onClose = () => {
                socket.removeEventListener("message", onMessage);
                clearTimeout(timer);
                reject(new Error("Gateway WebSocket closed during request"));
            };
            socket.addEventListener("message", onMessage);
            socket.addEventListener("close", onClose);
            try {
                socket.send(payload);
            }
            catch (sendErr) {
                socket.removeEventListener("message", onMessage);
                socket.removeEventListener("close", onClose);
                clearTimeout(timer);
                reject(sendErr instanceof Error ? sendErr : new Error(String(sendErr)));
            }
        });
    }
    buildConnectParams(nonce) {
        const auth = {};
        if (this.gatewayToken)
            auth.token = this.gatewayToken;
        if (this.password)
            auth.password = this.password;
        const role = "operator";
        const scopes = [
            "operator.admin",
            "operator.read",
            "operator.write",
            "operator.approvals",
            "operator.pairing",
        ];
        const params = {
            minProtocol: 3,
            maxProtocol: 3,
            client: {
                id: "cli",
                version: "a2a-bridge",
                platform: process.platform,
                mode: "cli",
                instanceId: uuidv4(),
            },
            role,
            scopes,
        };
        if (Object.keys(auth).length > 0) {
            params.auth = auth;
        }
        if (nonce) {
            const identity = getOrCreateDeviceIdentity();
            const signedAtMs = Date.now();
            const payloadParts = [
                "v3",
                identity.deviceId,
                "cli",
                "cli",
                role,
                scopes.join(","),
                String(signedAtMs),
                this.gatewayToken || "",
                nonce,
                process.platform,
                "",
            ];
            const payload = payloadParts.join("|");
            const signature = crypto.sign(null, Buffer.from(payload), identity.privateKey);
            const signatureB64Url = signature.toString("base64url");
            params.device = {
                id: identity.deviceId,
                publicKey: identity.publicKey,
                signedAt: signedAtMs,
                nonce,
                signature: signatureB64Url,
            };
        }
        return params;
    }
    closeSocket(socket) {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
            socket.close();
        }
    }
}

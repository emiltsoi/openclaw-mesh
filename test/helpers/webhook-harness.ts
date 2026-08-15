/**
 * Wire-shaped webhook test harness for openclaw-mesh.
 *
 * The plugin's webhook handler is registered through the openclaw SDK's
 * registerPluginHttpRoute. The SDK only exposes withPluginHttpRouteRegistry
 * (the AsyncLocalStorage scope that lets us capture routes) from its internal
 * built bundle, so we reach in via a relative path — the sibling
 * plugin-runtime.d.ts provides the type surface.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import crypto from "node:crypto";
import plugin from "../../src/index.js";
import { signMessage } from "../../src/registry.js";

// The openclaw package does not re-export withPluginHttpRouteRegistry from any
// public subpath. Reach into the built bundle relative to this module's actual
// location (import.meta.url) so the same relative path works from dist-test.
const sdk: any = await import(
  new URL("../../../node_modules/openclaw/dist/plugin-sdk/plugin-runtime.js", import.meta.url).href
);
const { withPluginHttpRouteRegistry } = sdk;

export interface WebhookRoute {
  path: string;
  handler: (req: any, res: any) => Promise<boolean>;
}

/** Run plugin.register inside an SDK route-registry scope and capture routes. */
export function registerPlugin(api: any): WebhookRoute[] {
  const registry: any = { httpRoutes: [] };
  withPluginHttpRouteRegistry(registry, () => {
    plugin.register(api);
  });
  return registry.httpRoutes as WebhookRoute[];
}

export function findWebhookHandler(routes: WebhookRoute[]) {
  return routes.find((r) => r.path === "/plugins/openclaw-mesh/webhook")?.handler;
}

export function makeApi(opts: { pluginConfig?: any; config?: any; tools?: any[]; runtime?: any } = {}): any {
  const tools = opts.tools || [];
  const api: any = {
    registrationMode: "full",
    registerTool: (def: any) => {
      tools.push(def);
    },
    on: () => {},
    resolvePath: undefined,
    pluginConfig: {
      mirrorInbound: "none",
      ...(opts.pluginConfig || {}),
    },
    config: opts.config || {},
    runtime: opts.runtime || {},
  };
  return api;
}

export interface InvokeResult {
  statusCode: number;
  body: string;
  json: any;
}

function makeReq(headers: Record<string, string>, body: Buffer): any {
  let sent = false;
  const req: any = {
    headers,
    [Symbol.asyncIterator]() {
      return {
        next: async () => {
          if (sent) return { done: true, value: undefined };
          sent = true;
          return { done: false, value: body };
        },
      };
    },
  };
  return req;
}

export async function invokeWebhook(
  handler: (req: any, res: any) => Promise<boolean>,
  opts: { headers: Record<string, string>; body: Buffer },
): Promise<InvokeResult> {
  const req = makeReq(opts.headers, opts.body);
  const res: any = {
    statusCode: 0,
    body: "",
    end(chunk: any) {
      res.body = String(chunk || "");
      return res;
    },
  };
  await handler(req as unknown as IncomingMessage, res as unknown as ServerResponse);
  let json: any = undefined;
  try {
    json = JSON.parse(res.body);
  } catch {
    // non-JSON body
  }
  return { statusCode: res.statusCode, body: res.body, json };
}

export function generateKeyPair() {
  return crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

/** Sign a webhook body over `"<ts>\n<body>"`, matching verifyEd25519Signature. */
export function signBody(privateKeyPem: string, body: Buffer, ts: string): string {
  return signMessage(privateKeyPem, Buffer.from(`${ts}\n${body.toString("utf-8")}`, "utf-8"));
}

export function currentTs(): string {
  return String(Math.floor(Date.now() / 1000));
}

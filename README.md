# openclaw-mesh

Stateful, Ed25519-signed agent-to-agent mesh messaging for OpenClaw. Use it to let one OpenClaw agent send messages to another OpenClaw agent, or to bridge OpenClaw agents to [Hermes](https://github.com/emiltsoi/hermes-mesh) mesh peers. All traffic is carried over the `[mesh]` envelope format with Ed25519 signatures, durable inbox persistence, and SSRF-protected outbound delivery.

## What it does

`openclaw-mesh` turns an OpenClaw agent into a mesh peer:

- **Inbound:** receives a `[mesh]` webhook, verifies the sender's Ed25519 `X-Mesh-Signature`, writes the message to a durable inbox, and triggers an in-process OpenClaw agent turn in the configured session.
- **Outbound:** exposes the `mesh_send` tool so the agent can Ed25519-sign and POST `[mesh]` envelopes to any peer discovered from the shared mesh vault.
- **Discovery:** exposes `mesh_list`, `mesh_register`, `mesh_deregister`, `mesh_sync`, and `mesh_publish` so agents can discover, register, and deregister themselves without leaving the chat.

Because both OpenClaw and Hermes agents can share the same mesh vault and envelope format, the plugin works in two modes:

1. **OpenClaw-only mesh** — two or more OpenClaw agents register in the same vault and send `[mesh]` envelopes to each other.
2. **Hermes bridge** — OpenClaw agents exchange envelopes with Hermes mesh peers.

## Architecture

```
OpenClaw agent A                     OpenClaw agent B (this plugin)
    │ mesh_send(to=B)                    │
    │  [mesh] envelope + Ed25519 sig     │
    └───────────────webhook──────────────▶│
                                           ├─ verify Ed25519 against sender's public_key
                                           ├─ write to mesh-inbox.jsonl
                                           ├─ optional mirror (telegram/cli)
                                           └─ runEmbeddedAgent(target session)
```

The same flow works when the sender is a Hermes mesh agent.

The plugin:

1. Verifies the inbound `X-Mesh-Signature` and `X-Mesh-Timestamp` headers using the sender's cached `public_key` from the mesh vault (falling back to the optional `mesh-peer-registry`).
2. Parses and validates the `[mesh][from:...][to:...][id:...][action:...][reply:...]` envelope.
3. Writes the message to a durable inbox (`/tmp/openclaw-mesh/mesh-inbox.jsonl` by default).
4. Optionally mirrors the inbound message to `telegram` or `cli`.
5. Calls `api.runtime.agent.runEmbeddedAgent(...)` so the configured session wakes and processes the turn.

## Installation

Published on ClawHub:

```bash
openclaw plugins install clawhub:@emiltsoi/openclaw-mesh
```

Or install from the local checkout for development:

```bash
cp -r /path/to/openclaw-mesh ~/.openclaw/workspaces/<agent>/plugins/openclaw-mesh
npm install
npm run build
```

Then enable it in `~/.openclaw/workspaces/<agent>/openclaw-<agent>.json`:

```json
{
  "plugins": {
    "load": {
      "paths": [
        "/home/emil/.openclaw/workspaces/<agent>/plugins/openclaw-mesh"
      ]
    },
    "entries": {
      "openclaw-mesh": {
        "enabled": true,
        "config": {
          "routingAgent": "emts",
          "targetSessionKey": "agent:main:main",
          "targetAgentId": "main",
          "sourceChannel": "mesh",
          "sourceTo": "",
          "meshVaultPath": "",
          "mirrorInbound": "none",
          "mirrorOutbound": "none",
          "debug": false,
          "allowLoopback": false,
          "deliveryRetries": 3,
          "deliveryBackoffMs": 1000,
          "deliveryTimeoutMs": 15000
        }
      }
    }
  }
}
```

Restart the OpenClaw gateway after changing source or `openclaw.plugin.json`.

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `routingAgent` | `emts` | Mesh agent name this instance accepts messages for. |
| `targetSessionKey` | `agent:main:main` | Target OpenClaw session key. |
| `targetAgentId` | `main` | Target OpenClaw agent ID. |
| `sourceChannel` | `mesh` | Channel attributed to the injected turn. |
| `sourceTo` | `envelope.from` | Channel target/to for the injected turn. |
| `model` | `config.agents.defaults.model.primary` or `deepseek/deepseek-v4-pro` | Optional `provider/model` override for the embedded run. |
| `meshVaultPath` | `$OPENCLAW_STATE_DIR/mesh` or `/tmp/openclaw-mesh` | Path to the mesh vault root (the directory that contains `mesh/agents`). |
| `inboxPath` | `/tmp/openclaw-mesh/mesh-inbox.jsonl` | Durable inbox file path. |
| `mirrorInbound` | `none` | Where to mirror inbound mesh messages: `none`, `telegram`, or `cli`. |
| `mirrorOutbound` | `none` | Where to mirror outbound mesh messages: `none`, `telegram`, or `cli`. |
| `debug` | `false` | Emit verbose debug logs to stderr and `/tmp/openclaw-mesh-debug.log`. |
| `allowLoopback` | `false` | Allow outbound webhook deliveries to loopback/private addresses. |
| `privateNetworkPolicy` | `deny` | Override for private network handling. Set to `allow`, `warn`, or `deny`. If `allowLoopback` is `true`, loopback deliveries are allowed regardless of this value. |
| `deliveryRetries` | `3` | Number of outbound webhook delivery attempts. |
| `deliveryBackoffMs` | `1000` | Initial retry backoff in milliseconds. |
| `deliveryTimeoutMs` | `15000` | Per-attempt delivery timeout in milliseconds. |
| `registryUrl` | — | URL of the mesh-peer-registry server (e.g. `https://registry.example.com`). Used by `mesh_sync` and `mesh_publish`. |
| `privateKeyPath` | `~/.mesh/keys/<routingAgent>.pem` | Path to the Ed25519 private key PEM. Generated on first use if missing. |
| `signTimestamp` | `true` | Include `X-Mesh-Timestamp` in the signed outbound payload. |
| `allowInsecureRegistry` | `false` | Allow `http://` registry URLs. Not recommended for production. |
| `registryPin` | — | SHA-256 hex digest of the registry server certificate SPKI for TLS pinning. |
| `auditLogPath` | — | Optional JSON-lines audit log file for mesh traffic. Falls back to `OPENCLAW_MESH_AUDIT_LOG`. |

The Ed25519 private key is loaded in this order:

1. `pluginConfig.privateKeyPath`
2. `MESH_PRIVATE_KEY_PATH` environment variable
3. `~/.mesh/keys/<routingAgent>.pem` (generated on first use)

## Inbound / Outbound Mirroring

Mirroring lets you observe mesh traffic without opening the session transcript. It is controlled independently per direction:

- `mirrorInbound` — applied when a mesh webhook is received.
- `mirrorOutbound` — applied when `mesh_send` posts to a peer webhook.

Supported values:

| Value | Behaviour |
|-------|-----------|
| `none` | No mirroring (default). |
| `telegram` | Send via the Telegram Bot API using `config.channels.telegram.botToken` / `chatId`. |
| `cli` | Write to `stdout`, which appears in the gateway logs. |

## Mesh Vault Discovery

The plugin can discover peers from a **file-based mesh vault** (default) or from an optional [`mesh-peer-registry`](https://github.com/emiltsoi/mesh-peer-registry) server.

```
$OPENCLAW_STATE_DIR/mesh/mesh/agents/
├── agent0/
│   └── identity.yaml
├── emts/
│   └── identity.yaml
└── linda/
    └── identity.yaml
```

Five tools are exposed:

- **`mesh_list`** — list discoverable peers with `name`, `platform`, `a2a_url`, `webhook_url`, and `public_key`. No secrets are leaked.
- **`mesh_send(agent, message, action?, reply?, id?, thread_id?)`** — resolve a peer, Ed25519-sign a `{"from": "<routingAgent>", "text": "[mesh][from:...]..."}` payload with the sender's private key, and POST it to the peer's `hermes_webhook` URL. Use `id` or `thread_id` to preserve the mesh thread id on replies.
- **`mesh_register(name?, description?, role?, platform?, a2a_url?, webhook_url?, public_key?, allow_loopback?)`** — write or update this agent's `identity.yaml` in the mesh vault so peers can discover it. Defaults are derived from `routingAgent`, the OpenClaw gateway config, and a generated Ed25519 keypair.
- **`mesh_deregister(name?, force?)`** — remove this agent from the local vault and, if configured, from the mesh-peer-registry.
- **`mesh_sync(name?, registry_url?)`** — fetch a peer (or all peers) from the mesh-peer-registry and cache it in the local vault.
- **`mesh_publish(name?, url, role?, description?, ttl?, registry_url?)`** — publish this agent's webhook URL and Ed25519 public key to the mesh-peer-registry.

### Agent listing

`mesh_list` returns a JSON object like:

```json
{
  "count": 2,
  "peers": [
    {
      "name": "agent0",
      "platform": "hermes",
      "a2a_url": "http://127.0.0.1:41808/a2a",
      "webhook_url": "http://127.0.0.1:8645/mesh/receive",
      "public_key": "-----BEGIN PUBLIC KEY-----\n...",
      "description": "Hermes agent zero",
      "role": "operator"
    },
    {
      "name": "emts",
      "platform": "openclaw",
      "a2a_url": "http://127.0.0.1:18860",
      "webhook_url": "http://127.0.0.1:18860/plugins/openclaw-mesh/webhook",
      "public_key": "-----BEGIN PUBLIC KEY-----\n...",
      "description": "OpenClaw mesh peer",
      "role": "mesh_peer"
    }
  ]
}
```

Private keys are never exposed in the listing; they are only used internally when `mesh_send` signs an outbound message.

`meshVaultPath` is path-neutral: `~` and relative paths are resolved through OpenClaw's `api.resolvePath` or manual `~` expansion, so you can point the plugin at any vault on any system. It points to the **mesh vault root** (the directory that contains `mesh/agents`), and the plugin appends `mesh/agents` internally.

It resolves in this order:

1. `pluginConfig.meshVaultPath` — mesh vault root (supports `~` and relative paths)
2. `MESH_VAULT_PATH` environment variable — mesh vault root (supports `~` and relative paths)
3. `HERMES_HOME` (with `/profiles/<name>` stripped) + `/fleet/mesh/agents`
4. Fallback to `$OPENCLAW_STATE_DIR/mesh` (or `/tmp/openclaw-mesh` if `OPENCLAW_STATE_DIR` is not set)

### Mesh Peer Registry

For a centralized, multi-host discovery backend you can use [`mesh-peer-registry`](https://github.com/emiltsoi/mesh-peer-registry) (also on [PyPI](https://pypi.org/project/mesh-peer-registry/)):

```bash
pip install mesh-peer-registry
mesh-peer-registry --port 8646 --store ~/.mesh/registry.sqlite
```

Then point `openclaw-mesh` at it:

```json
{
  "registryUrl": "https://registry.example.com",
  "privateKeyPath": "~/.mesh/keys/emts.pem",
  "registryPin": "sha256-hex-of-server-certificate-spki"
}
```

The registry is **optional**: the local vault is the runtime source of truth. `mesh_sync` pulls peers from the registry into the vault, and `mesh_publish` pushes this peer's public key and webhook URL to the registry.

The registry is language-agnostic: Hermes peers and OpenClaw peers can share the same `mesh-peer-registry` instance. See the [mesh-peer-registry README](https://github.com/emiltsoi/mesh-peer-registry/blob/main/README.md) for API details.

## Registering an OpenClaw agent

### Agent-friendly way: `mesh_register`

The agent can register itself by calling the `mesh_register` tool. In most cases just call:

```
mesh_register()
```

The plugin fills in:

- `name` from `routingAgent` (or `MESH_AGENT_NAME`, defaulting to `emts`)
- `a2a_url` from the OpenClaw gateway config (`http://127.0.0.1:<port>`)
- `webhook_url` as `<a2a_url>/plugins/openclaw-mesh/webhook`
- `public_key` from a generated or reused Ed25519 keypair at `privateKeyPath`

Optional overrides:

```
mesh_register(name="emts", description="OpenClaw mesh peer", role="mesh_peer", platform="openclaw")
```

`mesh_register` is idempotent — calling it again overwrites the same `identity.yaml` with updated values. The vault directory is created with `0o700` permissions and the `identity.yaml` file with `0o600` permissions.

### Manual way

If you prefer to write the file outside the agent turn, create a directory and `identity.yaml` under `<mesh-vault-root>/mesh/agents/<agent-name>/`:

```bash
mkdir -p $OPENCLAW_STATE_DIR/mesh/mesh/agents/emts
```

Then write `$OPENCLAW_STATE_DIR/mesh/mesh/agents/emts/identity.yaml`:

```yaml
id: emts
name: emts
kind: openclaw-agent
role: mesh_peer
description: OpenClaw mesh peer
a2a_url: http://127.0.0.1:18860
webhook_url: http://127.0.0.1:18860/plugins/openclaw-mesh/webhook
allow_loopback: true
transports:
  hermes_webhook:
    protocol: hermes-webhook
    url: http://127.0.0.1:18860/plugins/openclaw-mesh/webhook
    auth:
      public_key: |
        -----BEGIN PUBLIC KEY-----
        <sender's-ed25519-public-key>
        -----END PUBLIC KEY-----
```

Set `allow_loopback: true` when the peer runs on the same host and you want the plugin to allow deliveries to `127.0.0.1`/private addresses.

## Envelope Format

The `[mesh]` envelope is shared with `hermes-mesh`:

```
[mesh][from:<sender>][to:<recipient>][id:<uuid>][action:do|info][reply:yes|no] <message>
```

Messages not addressed to the configured `routingAgent` (or `*`) are silently ignored. Brackets inside the message body are preserved when the envelope header is stripped.

## Security Notes

- **SSRF protection:** outbound deliveries use OpenClaw's `fetchWithSsrFGuard` with per-peer `allow_loopback` and the configurable `allowLoopback` / `privateNetworkPolicy` settings. By default private/loopback targets are rejected. Set `allowLoopback: true` to allow loopback deliveries regardless of the `privateNetworkPolicy` default, or use `privateNetworkPolicy: "allow"` / `"warn"` for more control. As a break-glass, set `OPENCLAW_MESH_ALLOW_LOOPBACK=1`.
- **Ed25519 signatures:** outbound messages are signed with the sender's private key. Inbound messages are verified with the sender's cached public key from the mesh vault or the optional mesh-peer-registry.
- **HMAC removed:** the previous HMAC-SHA256 (`X-Hub-Signature-256`) mode is no longer supported. Existing deployments must re-register agents to generate Ed25519 keys.
- **Certificate pinning:** when using a registry over HTTPS, set `registryPin` to the SHA-256 hex digest of the server certificate's SPKI, or set `MESH_REGISTRY_PIN`.
- **Envelope token validation:** `from`, `to`, `id`, `action`, and `reply` fields are validated to keep the header well-formed.
- **Debug logging:** gated by `config.debug` or `OPENCLAW_MESH_DEBUG`; private keys and tokens are redacted from logs.

## Development

```bash
npm run typecheck   # TypeScript type check only
npm run build       # Compile src/ → dist/
npm test            # Run unit tests with node:test
```

CI is configured in `.github/workflows/ci.yml` and runs `typecheck`, `build`, and `test` on every push and pull request to `main`.

## Platform Pairing

| Platform | Mesh Repo |
|----------|-----------|
| Hermes | [hermes-mesh](https://github.com/emiltsoi/hermes-mesh) |
| OpenClaw | openclaw-mesh (this repo) |
| Shared registry | [mesh-peer-registry](https://github.com/emiltsoi/mesh-peer-registry) / [PyPI](https://pypi.org/project/mesh-peer-registry/) |

Hermes and OpenClaw use the same `[mesh]` envelope format and Ed25519 signatures.

## License

MIT

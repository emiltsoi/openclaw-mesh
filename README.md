# openclaw-mesh

Stateful, signed agent-to-agent mesh messaging for OpenClaw. Use it to let one OpenClaw agent send messages to another OpenClaw agent, or to bridge OpenClaw agents to [Hermes](https://github.com/emiltsoi/hermes-mesh) mesh peers. All traffic is carried over the `[mesh]` envelope format with per-agent HMAC-SHA256 signatures, durable inbox persistence, and SSRF-protected outbound delivery.

## What it does

`openclaw-mesh` turns an OpenClaw agent into a mesh peer:

- **Inbound:** receives a `[mesh]` webhook, verifies the sender's HMAC signature, writes the message to a durable inbox, and triggers an in-process OpenClaw agent turn in the configured session.
- **Outbound:** exposes the `mesh_send` tool so the agent can HMAC-sign and POST `[mesh]` envelopes to any peer discovered from the shared mesh vault.
- **Discovery:** exposes `mesh_list` and `mesh_register` so agents can discover each other and register themselves without leaving the chat.

Because both OpenClaw and Hermes agents can share the same mesh vault, envelope format, and HMAC scheme, the plugin works in two modes:

1. **OpenClaw-only mesh** — two or more OpenClaw agents register in the same vault and send `[mesh]` envelopes to each other.
2. **Hermes bridge** — OpenClaw agents exchange envelopes with Hermes mesh peers.

## Architecture

```
OpenClaw agent A                     OpenClaw agent B (this plugin)
    │ mesh_send(to=B)                    │
    │  [mesh] envelope + HMAC            │
    └───────────────webhook──────────────▶│
                                          ├─ verify HMAC against sender's secret
                                          ├─ write to mesh-inbox.jsonl
                                          ├─ optional mirror (telegram/cli)
                                          └─ runEmbeddedAgent(target session)
```

The same flow works when the sender is a Hermes mesh agent.

The plugin:

1. Verifies the inbound `X-Hub-Signature-256` HMAC header using the sender's secret from the mesh vault.
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
          "secretEnvVar": "OPENCLAW_MESH_SECRET",
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
| `secret` | — | HMAC-SHA256 shared secret (prefer `secretEnvVar`). |
| `secretEnvVar` | `OPENCLAW_MESH_SECRET` | Environment variable holding the secret. |
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

The shared secret is resolved in this order:

1. `pluginConfig.secret` (not recommended — OpenClaw strips sensitive fields)
2. `config.plugins.entries["openclaw-mesh"].config.secret`
3. Environment variable named by `secretEnvVar` (default: `OPENCLAW_MESH_SECRET`)

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

The plugin reads a file-based mesh vault. Each agent has a directory with an `identity.yaml` file under `<vault-root>/mesh/agents`, e.g.:

```
$OPENCLAW_STATE_DIR/mesh/mesh/agents/
├── agent0/
│   └── identity.yaml
├── emts/
│   └── identity.yaml
└── linda/
    └── identity.yaml
```

Three tools are exposed:

- **`mesh_list`** — list discoverable peers with `name`, `platform`, `a2a_url`, and `webhook_url`. No secrets are leaked.
- **`mesh_send(agent, message, action?, reply?, id?, thread_id?)`** — resolve a peer, HMAC-sign a `{"from": "<routingAgent>", "text": "[mesh][from:...]..."}` payload with the sender's own `webhook_secret`, and POST it to the peer's `hermes_webhook` URL. Use `id` or `thread_id` to preserve the mesh thread id on replies.
- **`mesh_register(name?, description?, role?, platform?)`** — write or update this agent's `identity.yaml` in the mesh vault so peers can discover it. Defaults are derived from `routingAgent`, the OpenClaw gateway config, and the plugin `secret`.

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
      "description": "Hermes agent zero",
      "role": "operator"
    },
    {
      "name": "emts",
      "platform": "openclaw",
      "a2a_url": "http://127.0.0.1:18860",
      "webhook_url": "http://127.0.0.1:18860/plugins/openclaw-mesh/webhook",
      "description": "OpenClaw mesh peer",
      "role": "mesh_peer"
    }
  ]
}
```

`webhook_secret` is never exposed in the listing; it is only used internally when `mesh_send` signs an outbound message.

`meshVaultPath` is path-neutral: `~` and relative paths are resolved through OpenClaw's `api.resolvePath` or manual `~` expansion, so you can point the plugin at any vault on any system. It points to the **mesh vault root** (the directory that contains `mesh/agents`), and the plugin appends `mesh/agents` internally.

It resolves in this order:

1. `pluginConfig.meshVaultPath` — mesh vault root (supports `~` and relative paths)
2. `MESH_VAULT_PATH` environment variable — mesh vault root (supports `~` and relative paths)
3. `HERMES_HOME` (with `/profiles/<name>` stripped) + `/fleet/mesh/agents`
4. Fallback to `$OPENCLAW_STATE_DIR/mesh` (or `/tmp/openclaw-mesh` if `OPENCLAW_STATE_DIR` is not set)

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
- `webhook_secret` from the plugin's configured `secret`

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
webhook_secret: <same-secret-as-openclaw-mesh-config>
allow_loopback: true
transports:
  hermes_webhook:
    protocol: hermes-webhook
    url: http://127.0.0.1:18860/plugins/openclaw-mesh/webhook
    auth:
      type: hmac-sha256
      secret: <same-secret-as-openclaw-mesh-config>
      header: X-Hub-Signature-256
      prefix: sha256=
```

The `webhook_secret` (and `transports.hermes_webhook.auth.secret`) must match the `secret` configured for `openclaw-mesh` so inbound HMAC signatures verify. Set `allow_loopback: true` when the peer runs on the same host and you want the plugin to allow deliveries to `127.0.0.1`/private addresses.

## Envelope Format

The `[mesh]` envelope is shared with `hermes-mesh`:

```
[mesh][from:<sender>][to:<recipient>][id:<uuid>][action:do|info][reply:yes|no] <message>
```

Messages not addressed to the configured `routingAgent` (or `*`) are silently ignored. Brackets inside the message body are preserved when the envelope header is stripped.

## Security Notes

- **SSRF protection:** outbound deliveries use OpenClaw's `fetchWithSsrFGuard` with per-peer `allow_loopback` and the configurable `allowLoopback` / `privateNetworkPolicy` settings. By default private/loopback targets are rejected. Set `allowLoopback: true` to allow loopback deliveries regardless of the `privateNetworkPolicy` default, or use `privateNetworkPolicy: "allow"` / `"warn"` for more control. As a break-glass, set `OPENCLAW_MESH_ALLOW_LOOPBACK=1`.
- **Per-agent HMAC:** outbound messages are signed with the sender's own `webhook_secret` from the vault. Inbound messages are verified with the sender's secret. A shared-secret fallback is supported for backward compatibility.
- **Envelope token validation:** `from`, `to`, `id`, `action`, and `reply` fields are validated to keep the header well-formed.
- **Debug logging:** gated by `config.debug` or `OPENCLAW_MESH_DEBUG`; secrets are redacted from logs.

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

Both sides use the same envelope format and HMAC scheme.

## License

MIT

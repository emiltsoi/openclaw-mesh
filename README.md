# openclaw-mesh

OpenClaw fleet mesh relay — the OpenClaw counterpart to [hermes-mesh](https://github.com/emiltsoi/hermes-mesh). Enables A2A webhook reception, HMAC-verified envelope parsing, session injection, and Telegram float for OpenClaw agents.

## Architecture

```
Hermes fleet ──A2A webhook──→ a2a-bridge plugin ──→ OpenClaw session
                                                    └──→ Telegram float (Emil)
                                                    └──→ agent_end hook (reply back)
```

The a2a-bridge plugin receives A2A messages from the Hermes mesh via HMAC-SHA256 secured webhooks, parses the envelope (`[a2a][from:linda][to:emts]...`), injects the message into the OpenClaw agent session, forwards a notification to Telegram, and hooks the agent reply for the return path.

## Quick Start

```bash
# Install in your OpenClaw workspace
cp -r plugins/a2a-bridge ~/.openclaw/workspaces/<agent>/plugins/

# Configure (in openclaw-<agent>.json)
{
  "plugins": {
    "entries": {
      "a2a-bridge": {
        "enabled": true,
        "config": {
          "secret": "<shared-hmac-secret>",
          "targetSessionKey": "agent:main:main",
          "targetAgentId": "main"
        }
      }
    }
  }
}
```

## Envelope Format

The plugin parses the same envelope format as hermes-agent-a2a:

```
[a2a][from:<sender>][to:<recipient>][id:<uuid>][action:do|info][reply:yes|no] <message>
```

Messages not addressed to the configured agent (or `*`) are silently ignored.

## Platform Pairing

| Platform | Mesh Repo |
|----------|-----------|
| Hermes | [hermes-mesh](https://github.com/emiltsoi/hermes-mesh) |
| OpenClaw | openclaw-mesh (this repo) |

Both sides use the same envelope format and HMAC scheme. One webhook, two platforms, one mesh.

## License

MIT

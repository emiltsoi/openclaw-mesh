# Mesh specification fixtures

These JSON files are copied from [`mesh-peer-registry/spec`](https://github.com/emiltsoi/mesh-peer-registry/tree/main/spec) and serve as the single source of truth for mesh wire formats.

- `envelope.schema.json` — JSON Schema for the bracketed `[mesh]` envelope header and parsed envelope object.
- `identity.schema.json` — JSON Schema for an agent `identity.yaml` stored in the mesh vault.
- `test-vectors/valid.json` — canonical valid envelope parse cases.
- `test-vectors/invalid.json` — canonical malformed/invalid envelope cases.

When the canonical spec changes, these fixtures should be re-synced and the OpenClaw implementation re-validated.

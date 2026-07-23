# Autonomous Wake Investigation — July 24, 2026

## Goal

Enable the a2a-bridge plugin to trigger autonomous agent turns from its webhook handler. When a Hermes agent sends an A2A message via the inbound webhook, EMTS should wake up and process it without Emil triggering a turn.

## The Gold Standard

Telegram messages from Emil always wake EMTS — whether the session is active or idle. The mechanism:

```
Telegram webhook → Gateway → reply dispatch → enqueueCommandInLane(sessionLane, task) → drainLane()
```

`enqueueCommandInLane` and `drainLane` are internal OpenClaw functions in `command-queue-DqzpsN4m.js`. They are NOT exposed via the plugin SDK.

## Approaches Tried (all failed on idle sessions)

| # | Method | SDK Path | Result |
|---|---|---|---|
| 1 | `runEmbeddedAgent()` | `enqueueSession → enqueueGlobal → enqueueCommandInLane` | Silent fail |
| 2 | `scheduleSessionTurn({ delayMs: 0 })` | Timer-based (no Cron) | ✅ active session, ❌ idle |
| 3 | `scheduleSessionTurn({ at: Date.now() + 5s })` | Cron backend | ❌ |
| 4 | `setTimeout(() => runEmbeddedAgent(), 100)` | Same as #1, deferred | ❌ |
| 5 | `runEmbeddedAgent({ lane: "main" })` | Changes global lane only | ❌ |
| 6 | `runEmbeddedAgent({ enqueue: (task) => task() })` | Bypasses both lanes inline | ❌ |

## Root Cause: Two-Level Lane Deadlock

Discovered by Linda (Hermes fleet). `runEmbeddedAgent` uses a two-level lane structure:

```js
// embedded-agent-DGUuxGR2.js
return enqueueSession(async () => {      // Level 1: session:<key> lane
  await waitForDeferredTurnMaintenanceForSession(...);
  return enqueueGlobal(async () => {     // Level 2: "main" lane
    // actual agent work
  });
});
```

**Deadlock sequence on idle sessions:**
1. Webhook → injectIntoSession → runEmbeddedAgent
2. Task enqueued on `session:<key>` lane → drainLane processes it (activeCount = 1)
3. Session lane task calls enqueueGlobal on "main" lane
4. Main lane is suspended on idle sessions → task queued forever
5. Session lane task blocked on enqueueGlobal's Promise (no timeout)
6. Session deadlocked: activeCount(1) ≥ maxConcurrent(1) → drainLane refuses

**Why `enqueue: (task) => task()` should have worked:**
The `enqueue` parameter is explicitly checked at line 2095:
```js
if (params.enqueue) return params.enqueue(task, opts);
```
When set, both `enqueueSession` and `enqueueGlobal` use the custom function instead of `enqueueCommandInLane`. The task runs inline — no lane, no deadlock. Yet no `agent_end` event appeared for any ping test using this approach.

## Key Files Referenced

- `embedded-agent-DGUuxGR2.js:1982` — `runEmbeddedAgent`
- `command-queue-DqzpsN4m.js:229` — `drainLane`
- `command-queue-DqzpsN4m.js:299` — `enqueueCommandInLane`

## Open Question

Why does `enqueue: (task) => task()` not produce a visible autonomous turn? The task runs inline, the agent work executes, but no `agent_end` is recorded and no reply is delivered. Possible explanations:

1. The inline execution succeeds but the reply dispatch pipeline cannot deliver from within the HTTP handler context
2. The `enqueue` function parameter is rejected or transformed by the plugin SDK boundary before reaching `runEmbeddedAgent`

## Suggested Next Steps

1. Verify whether `enqueue: (task) => task()` actually executes the agent work by adding debug logging inside the task
2. Investigate `scheduleSessionTurn` with a full Cron expression (not `delayMs` or short `at` times) — does the Cron backend work on idle sessions?
3. Explore whether the Gateway's internal message delivery API can be exposed to plugins for this use case
4. Consider a sidecar agent process that monitors the inbox and fires autonomous turns through the Gateway API

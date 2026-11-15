# Hermuse privacy router

This directory adapts the 9Router fork for three configurable routes. It is a small, dependency-free policy front door; the existing 9Router handles subscription authentication, protocol translation, tools and streaming behind it.

| Route | Default target | Privacy rule |
|---|---|---|
| ordinary | `cx/gpt-6-luna` through the ChatGPT subscription | Finance/private checks run first |
| hard | `cx/gpt-6.1-sol` through the same subscription | Explicit selection or configurable difficulty threshold |
| privacy / finance | `openai/gpt-6-luna` through OpenRouter, strict eligible Azure endpoints | ZDR always required; no subscription fallback |
| routing decision | pinned `nace-ai/drex-max-20261016` through OpenRouter Decisions, DeepInfra US | The same strict ZDR checks; never uses the subscription |

## Boundaries

The policy gateway listens on `127.0.0.1:20129`; 9Router stays on `127.0.0.1:20128`. Private prompts bypass 9Router, its request logs, its optional compression services and its automatic fallback engine. Only the OpenRouter inference API receives private requests.

Each private request overwrites provider preferences with `zdr:true`, `data_collection:"deny"`, `allow_fallbacks:false`, `require_parameters:true` and an explicit eligible provider allowlist. Caller-provided providers, presets, plugins, transforms and fallback models cannot change that. A failed private request stops. It never retries on the subscription or on a non-ZDR endpoint.

Eligible endpoints come from OpenRouter's live ZDR catalog and must have **`safety_retention:false` explicitly**. Missing or ambiguous policy data is rejected. The cache is short-lived; expired metadata is never reused after a refresh failure. Every reconfigured model must pass the same checks.

OpenRouter's account/key guardrail must also be configured **ZDR only**, with Safety Retention excluded. `account_zdr_only_verified` remains false until that setup has been checked, so private calls cannot run before provisioning is complete. It records an operator verification, not an independent API attestation: do not loosen the account policy afterward. ZDR is the provider's published inference policy, including its stated legal exceptions; it does not mean that local agent memory, integrations, or tools have no retention. No OpenRouter server tools/plugins are enabled by this gateway.

### Conversation privacy

`X-Hermuse-Session` identifies a conversation. Missing metadata forces the private route, covering auxiliary clients that skip middleware; malformed metadata is rejected. Once a conversation is private, a keyed digest is saved durably before the upstream request and the conversation can never downgrade, even after restart or context compaction. Changing API client keys does not reset it. The state file must be explicitly initialized; missing/corrupt state blocks requests. Changing the session HMAC key also fails closed against the old state.

The included Hermes middleware plugin supplies a stable, profile-scoped root conversation identifier, following the local session database's compaction lineage. Auxiliary calls or unresolved lineage are forced private. Hermes middleware itself is fail-open, so the independent gateway forces privacy if the plugin fails to attach an identity.

Use an isolated Hermes privacy profile with the **private client key** for finance/private work. That key forces every call private, even if a caller names the default or hard alias. Keep that profile's local memories and history separate from the ordinary profile. Finance tools/credentials must not be available to the ordinary profile before the later integration gates.

Automatic topic detection is not a proof of subject matter. Local finance rules and an optional ZDR-only classification call add conservative detection before subscription inference. An uncertain, oversized or non-text input goes private; classifier failure blocks the call. A classifier can still misunderstand an ambiguous phrase. Explicit private mode, isolated profiles and finance tool access controls are the enforceable boundary. Do not promise universal semantic detection.

### Automatic and explicit routing

Virtual model aliases are `hermuse-auto`, `hermuse-default`, `hermuse-hard`, `hermuse-private`, `hermuse-finance`. Unknown/raw model names are rejected. A hard/default preference can never override privacy. Clients may additionally set `X-Hermuse-Privacy: required` or `metadata.hermuse.privacy:true` / `finance:true`.

`classification.mode:"zdr"` makes a strict-ZDR typed decision call for otherwise ordinary input. The actual answer/work still runs on the subscription. The decision model is separate from the private answer model. It answers three probability questions for privacy, finance and difficulty. Privacy probabilities at or above the conservative configured threshold force the private route. Missing probabilities, unexpected types or a different returned build stop the request.

OpenRouter currently lists Drex Max as `nace-ai/drex-max`, canonical build `nace-ai/drex-max-20261016`; it does not expose the vendor's v1.1 label. That exact catalog build is pinned rather than claiming a version mapping that the catalog cannot prove. SubQ Snap 1.2 was not listed in OpenRouter's decision catalog at provisioning. To change the classifier, choose a listed decision model, pin its dated build, set its catalog ID and allowed provider tags, and rerun the routing probes. Endpoint metadata must identify that exact build and explicitly exclude Safety Retention. See the [OpenRouter Decisions reference](https://github.com/OpenRouterTeam/skills/blob/main/skills/openrouter-decisions/references/decisions-api.md).

Both classifier and private completions stop on failures. The classifier mode is fixed to `zdr`; ordinary traffic cannot bypass the privacy gate through configuration. Generic system-policy wording is excluded from keyword matching, while the ZDR classifier still inspects all system content and memories.

## Configuration and operation

Copy `policy.example.json` outside Git, review it, then initialize once:

```sh
node hermuse/init.mjs /home/hermes/.config/hermuse-router/policy.json
node hermuse/server.mjs /home/hermes/.config/hermuse-router/policy.json
```

Initialization prints no secrets and refuses to overwrite existing credentials/state. Fill the OpenRouter and backend keys privately; never put them in this repository. Config and credentials reload on every request. Invalid edits stop requests instead of silently keeping a previous policy. Listening-address changes require a service restart. Model, classifier threshold, timeout, allowlist and detector changes need no code changes; ZDR requirements cannot be disabled through configuration.

The gateway accepts the OpenAI **Chat Completions** API with streaming and tool calls. Other inference protocols are explicitly rejected; configure Hermes to use Chat Completions. A future client must supply a stable conversation header. Arbitrary endpoints and upstream model IDs are not passed through.

Decision logs contain only route/model/provider, a keyed session digest, a fixed reason code and a request ID. They contain no prompt, response, tool arguments, raw session ID or authentication header. Request failures and stream failures never cause a provider downgrade.

Tests (no credentials or network):

```sh
node --test hermuse/test/*.test.mjs
```

The main 9Router application remains upstream-compatible. This policy package does not require rebuilding its web dashboard. The original host Docker agent is outside this installation and stays running until Jake explicitly requests its shutdown.

# Hermuse operations

## Configuration

Keep `policy.json` and `credentials.json` outside Git. Start from `policy.example.json`; `init.mjs` creates credentials and privacy state once and refuses to overwrite either. Configuration and credentials reload per request. Invalid or unreadable files fail closed. Changing the listener address or port requires a restart.

Supported policy changes include subscription models/timeouts, private answer models and provider tags, pinned classifier build and provider tags, thresholds, local detection rules, request limits, and file paths. The validator permanently requires private requests to use `zdr: true`, `data_collection: "deny"`, and `allow_fallbacks: false`; do not weaken these checks. `account_zdr_only_verified` must remain false until an operator has verified the OpenRouter account/key is set to ZDR only with Safety Retention excluded. It is an operator attestation, not an API proof.

## Strict ZDR and model changes

Private completions and classification select endpoints from OpenRouter's live ZDR endpoint catalog. An endpoint qualifies only when the exact catalog model matches, `safety_retention` is explicitly `false`, `status` is `0`, and its provider tag is allowlisted. Missing, stale, or ambiguous metadata blocks the request. Each call pins an explicit provider list and disables fallbacks; errors stop without switching to a subscription model.

The classifier must use a dated build ID ending in `-YYYYMMDD` and a separate catalog model ID. The current example pins `nace-ai/drex-max-20261016`; the catalog's current model slug is `nace-ai/drex-max` and does not establish the vendor's v1.1 mapping. SubQ Snap 1.2 was not in OpenRouter's decision catalog at the time of provisioning. For any model/provider change, confirm the exact build and strict endpoint metadata first, update the IDs and allowlist together, then rerun routing probes. Do not use an alias where a dated build is required.

Keep the OpenRouter key restricted to the required ZDR policy. If the key has limited credits or is rejected, treat that as a stopped private route: restore quota or correct the key/account policy. Do not add a subscription or non-ZDR fallback.

## Privacy state, logging, and profiles

Audit records contain only routing metadata and a keyed session digest; never add prompts, responses, tool arguments, raw session IDs, authorization headers, or keys to logs. Provisioning's loopback callback suppresses HTTP access logs so authorization codes are not printed. Keep service and reverse-proxy access logging from recording callback query strings.

Private conversation state is monotonic and durable. Back up and restore `private-sessions.json` together with the exact `session_hmac_key` from the matching credentials file. They are one recovery unit: changing the HMAC key without migrating/reinitializing state deliberately makes the service fail closed. Protect both files and backups as secrets. Do not edit or delete the state file during routine reconfiguration.

Run one gateway process per state file. The keyed request locks and state cache are process-local; multiple workers can race and undermine conversation ordering. Keep the ordinary Hermes profile separate from the private profile, with separate history/memory. Use the private client key for private-profile work; keep finance tools and credentials unavailable to the ordinary profile until its integration gates are explicitly completed. The plugin only tags metadata and is fail-open; the gateway's forced-private handling of missing metadata and durable ancestry state enforce the boundary.

## Optional credential provisioning

`provision.py` is an optional, one-time loopback PKCE helper for OpenRouter or Codex. It prints the callback port and authorization URL only; it does not print credential values. Run it with a protected credentials file outside Git. For Codex, supply the dashboard password via a separate protected file; the helper logs in to the local 9Router API, exchanges the callback code through `/api/oauth/codex/exchange`, then stores the returned backend key. The browser owner must approve the OAuth request. Do not paste tokens into shell arguments, issue logs, or chat. Never commit the credentials file. The normal Hermuse runtime reads credentials locally and does not run this provisioning flow.

## Staged rollout and rollback

Do not treat provisioning or a successful health check as a completed production rollout. In particular, this guide does not assert that a later deployment phase has completed.

1. Back up the policy, credentials, and matching privacy state securely. Record current service configuration and keep the existing route available.
2. Validate the policy and credential file permissions offline. Verify account ZDR/Safety Retention settings and endpoint eligibility before setting `account_zdr_only_verified` true.
3. Start the gateway on loopback alongside 9Router. Check `GET /healthz` and `GET /v1/models`; confirm only the documented aliases are exposed.
4. From a protected client, verify the supported protocol with a harmless synthetic Chat Completions request. Check response status and `X-Hermuse-Route`, `X-Hermuse-Model`, and `X-Hermuse-Provider`. Confirm unsupported paths/protocols such as Responses are rejected. Exercise ordinary, hard, and explicit private routes; validate the private endpoint selection and a deliberate ZDR/key failure. A failed private call must stop without reaching 9Router/subscription.
5. Canary the Hermes profile configuration, confirming session ancestry metadata and the isolated private profile. Only after checks pass should clients switch to the gateway URL and keys. Monitor metadata-only audit events and errors.

To revert, point clients back to the recorded prior route/config and disable the Hermuse service. Do not delete or regenerate privacy state as part of rollback; retain it securely for a later restart. A rollback must not route private-profile traffic through an ordinary subscription route. If protocol checks fail, leave activation disabled and fix the client configuration: this gateway currently accepts OpenAI Chat Completions only, at `POST /v1/chat/completions`, with session metadata; missing metadata forces privacy.


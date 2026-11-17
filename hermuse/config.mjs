import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

export class PolicyError extends Error {
  constructor(code, status = 503) { super(code); this.code = code; this.status = status; }
}
export const OPENROUTER_CHAT = 'https://openrouter.ai/api/v1/chat/completions';
export const OPENROUTER_ZDR = 'https://openrouter.ai/api/v1/endpoints/zdr';
export const OPENROUTER_DECISIONS = 'https://openrouter.ai/api/alpha/decisions';
export const ALIASES = ['hermuse-auto', 'hermuse-auto-terra', 'hermuse-auto-luna', 'hermuse-default', 'hermuse-hard', 'hermuse-private', 'hermuse-finance'];
export function expand(p) { return p.startsWith('~/') ? path.join(os.homedir(), p.slice(2)) : path.resolve(p); }
function requireCondition(ok, code = 'invalid_policy') { if (!ok) throw new PolicyError(code); }
function integer(n, min, max) { return Number.isInteger(n) && n >= min && n <= max; }
function exactKeys(o, keys) { requireCondition(o && typeof o === 'object' && !Array.isArray(o) && Object.keys(o).every(k => keys.includes(k))); }
export function validatePolicy(c) {
  exactKeys(c, ['version','listen','credentials_file','state_file','audit_file','subscription','privacy','classification','limits','rules','default_reasoning_effort','ordinary_direct_terra']);
  requireCondition(c.version === 1);
  if (c.ordinary_direct_terra !== undefined) requireCondition(typeof c.ordinary_direct_terra === 'boolean', 'invalid_direct_terra_setting');
  if (c.default_reasoning_effort !== undefined) requireCondition(['none','minimal','low','medium','high','xhigh','max','ultra'].includes(c.default_reasoning_effort), 'invalid_default_reasoning_effort');
  exactKeys(c.listen, ['host','port']);
  requireCondition(c.listen.host === '127.0.0.1' && integer(c.listen.port, 1, 65535));
  for (const k of ['credentials_file','state_file','audit_file']) requireCondition(typeof c[k] === 'string' && c[k].length > 0);
  exactKeys(c.subscription, ['url','default_model','hard_model','terra_model','luna_model','timeout_ms']);
  const url = new URL(c.subscription.url);
  requireCondition(url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.pathname === '/v1/chat/completions' && !url.username && !url.password && !url.search && !url.hash);
  for (const k of ['default_model','hard_model']) requireCondition(/^cx\/[a-zA-Z0-9._-]+$/.test(c.subscription[k]), 'subscription_must_use_codex');
  if (c.subscription.terra_model !== undefined) requireCondition(/^cx\/[a-zA-Z0-9._-]+$/.test(c.subscription.terra_model), 'subscription_must_use_codex');
  if (c.subscription.luna_model !== undefined) requireCondition(/^cx\/[a-zA-Z0-9._-]+$/.test(c.subscription.luna_model), 'subscription_must_use_codex');
  requireCondition(integer(c.subscription.timeout_ms, 1000, 300000));
  exactKeys(c.privacy, ['models','providers','zdr','data_collection','allow_fallbacks','account_zdr_only_verified','endpoint_cache_ms','timeout_ms']);
  requireCondition(c.privacy.zdr === true && c.privacy.data_collection === 'deny' && c.privacy.allow_fallbacks === false, 'zdr_cannot_be_disabled');
  requireCondition(typeof c.privacy.account_zdr_only_verified === 'boolean');
  requireCondition(Array.isArray(c.privacy.models) && c.privacy.models.length > 0 && c.privacy.models.length <= 5);
  for (const model of c.privacy.models) requireCondition(/^[a-z0-9_-]+\/[a-zA-Z0-9._-]+$/.test(model) && !model.startsWith('openrouter/'), 'invalid_private_model');
  requireCondition(Array.isArray(c.privacy.providers) && c.privacy.providers.length > 0 && c.privacy.providers.length <= 20);
  for (const provider of c.privacy.providers) requireCondition(/^[a-z0-9_-]+(?:\/[a-z0-9_-]+)*$/.test(provider));
  requireCondition(integer(c.privacy.endpoint_cache_ms, 0, 60000) && integer(c.privacy.timeout_ms, 1000, 300000));
  exactKeys(c.classification, ['mode','model','catalog_model','providers','private_threshold','hard_threshold','max_chars','timeout_ms']);
  requireCondition(c.classification.mode === 'zdr', 'zdr_privacy_gate_required');
  for (const k of ['model','catalog_model']) requireCondition(/^[a-z0-9_-]+\/[a-zA-Z0-9._-]+$/.test(c.classification[k]) && !c.classification[k].startsWith('openrouter/'), 'invalid_classifier_model');
  requireCondition(c.classification.model.startsWith(c.classification.catalog_model + '-') && /-\d{8}$/.test(c.classification.model), 'classifier_build_must_be_pinned');
  requireCondition(Array.isArray(c.classification.providers) && c.classification.providers.length > 0 && c.classification.providers.length <= 20);
  for (const provider of c.classification.providers) requireCondition(/^[a-z0-9_-]+(?:\/[a-z0-9_-]+)*$/.test(provider));
  requireCondition(Number.isFinite(c.classification.private_threshold) && c.classification.private_threshold > 0 && c.classification.private_threshold <= 0.5);
  requireCondition(Number.isFinite(c.classification.hard_threshold) && c.classification.hard_threshold >= 0 && c.classification.hard_threshold <= 1);
  requireCondition(integer(c.classification.max_chars, 1000, 100000) && integer(c.classification.timeout_ms, 1000, 60000));
  exactKeys(c.limits, ['body_bytes','max_concurrency']);
  requireCondition(integer(c.limits.body_bytes, 1024, 16777216) && integer(c.limits.max_concurrency, 1, 32));
  exactKeys(c.rules, ['finance','privacy','hard']);
  for (const kind of ['finance','privacy','hard']) {
    requireCondition(Array.isArray(c.rules[kind]) && c.rules[kind].length > 0 && c.rules[kind].length <= 100);
    for (const pattern of c.rules[kind]) { requireCondition(typeof pattern === 'string' && pattern.length < 2000); new RegExp(pattern, 'iu'); }
  }
  return c;
}
export async function loadPolicy(file) {
  try { return validatePolicy(JSON.parse(await readFile(file, 'utf8'))); }
  catch (e) { if (e instanceof PolicyError) throw e; throw new PolicyError('invalid_policy'); }
}
export async function loadCredentials(file) {
  try {
    const resolved = expand(file);
    const info = await stat(resolved);
    requireCondition(os.platform() === 'win32' || (info.mode & 0o077) === 0, 'unsafe_credential_permissions');
    const c = JSON.parse(await readFile(resolved, 'utf8'));
    exactKeys(c, ['clients','session_hmac_key','backend_key','openrouter_key']);
    requireCondition(typeof c.session_hmac_key === 'string' && c.session_hmac_key.length >= 32);
    requireCondition(Array.isArray(c.clients) && c.clients.length > 0);
    for (const client of c.clients) {
      exactKeys(client, ['id','key','force_private']);
      requireCondition(/^[a-zA-Z0-9_-]{1,64}$/.test(client.id) && typeof client.key === 'string' && client.key.length >= 32 && typeof client.force_private === 'boolean');
    }
    requireCondition(new Set(c.clients.map(x => x.key)).size === c.clients.length);
    requireCondition(typeof c.backend_key === 'string' && typeof c.openrouter_key === 'string');
    return c;
  } catch (e) { if (e instanceof PolicyError) throw e; throw new PolicyError('credentials_unavailable'); }
}

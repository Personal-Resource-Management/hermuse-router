import { createHmac, createHash, timingSafeEqual, randomUUID } from 'node:crypto';
import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { ALIASES, PolicyError, expand, loadPolicy, loadCredentials } from './config.mjs';
import { PrivacyState } from './state.mjs';
import { ZdrTransport, CHAT_FIELDS } from './zdr.mjs';

function secureEqual(a, b) {
  return timingSafeEqual(createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest());
}
export function authenticate(header, credentials) {
  const token = typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) throw new PolicyError('unauthorized', 401);
  const client = credentials.clients.find(c => secureEqual(token, c.key));
  if (!client) throw new PolicyError('unauthorized', 401);
  return client;
}
export function inspect(body, headers, policy) {
  if (!body || !ALIASES.includes(body.model) || !Array.isArray(body.messages) || !body.messages.length) throw new PolicyError('invalid_chat_request', 400);
  const suppliedSession = headers.get('x-hermuse-session');
  if (suppliedSession && !/^[a-zA-Z0-9_.:/-]{1,256}$/.test(suppliedSession)) throw new PolicyError('invalid_session_metadata', 400);
  // Some Hermes auxiliary clients skip middleware. Missing identity is never
  // permission to use the subscription: group it into a forced-private bucket.
  const session = suppliedSession || 'unidentified-auxiliary';
  let sessions = [session];
  const lineage = headers.get('x-hermuse-lineage');
  if (lineage) {
    try { sessions = JSON.parse(lineage); } catch { throw new PolicyError('invalid_session_lineage',400); }
    if (!suppliedSession || !Array.isArray(sessions) || sessions.length < 1 || sessions.length > 64 || sessions[0] !== session || new Set(sessions).size !== sessions.length || sessions.some(s => typeof s !== 'string' || !/^[a-zA-Z0-9_.:/-]{1,256}$/.test(s))) throw new PolicyError('invalid_session_lineage',400);
  }
  if (body.messages.some(m => !m || !['system','developer','user','assistant','tool'].includes(m.role))) throw new PolicyError('unsupported_message_role', 400);
  if (body.tools !== undefined && !Array.isArray(body.tools)) throw new PolicyError('invalid_tools',400);
  let nonText = false;
  const messageParts = body.messages.map(m => {
    let value = '';
    if (typeof m.content === 'string') value = m.content;
    else if (Array.isArray(m.content)) value = m.content.map(p => {
      if (p?.type === 'text' && typeof p.text === 'string') return p.text;
      nonText = true; return '[non-text content]';
    }).join('\n');
    else if (m.content != null) nonText = true;
    return `${m.role}: ${value}\n${m.tool_calls ? JSON.stringify(m.tool_calls) : ''}`;
  });
  const normalize = text => text.normalize('NFKC').replace(/[\u200B-\u200D\uFEFF]/g, '');
  const messageText = normalize(messageParts.join('\n'));
  // Stock system instructions mention finances/privacy even for an ordinary
  // greeting. The ZDR classifier still inspects ALL system content and memories.
  // Deterministic topic rules apply to conversation content rather than policy prose.
  const topicText = normalize(messageParts.filter((_,i) => !['system','developer'].includes(body.messages[i].role)).join('\n'));
  const toolNames = (body.tools || []).map(t => t?.function?.name || t?.name || '').join(' ');
  const match = (kind, text) => policy.rules[kind].some(p => new RegExp(p, 'iu').test(text));
  const metadata = body.metadata?.hermuse;
  if (metadata != null && (typeof metadata !== 'object' || Array.isArray(metadata))) throw new PolicyError('invalid_routing_metadata', 400);
  if (metadata?.privacy !== undefined && typeof metadata.privacy !== 'boolean') throw new PolicyError('invalid_routing_metadata', 400);
  if (metadata?.finance !== undefined && typeof metadata.finance !== 'boolean') throw new PolicyError('invalid_routing_metadata', 400);
  const privateReason = !suppliedSession ? 'missing_session_metadata'
    : ['hermuse-private','hermuse-finance'].includes(body.model) ? 'explicit_private'
    : headers.get('x-hermuse-privacy') === 'required' || metadata?.privacy === true ? 'explicit_private'
    : metadata?.finance === true || match('finance', topicText) || match('finance', toolNames) || /[$€£]\s*\d/.test(messageText) ? 'finance_rule'
    : match('privacy', topicText) ? 'privacy_rule'
    : nonText ? 'uninspected_attachment'
    : messageText.length > policy.classification.max_chars ? 'uninspected_large_context'
    : null;
  return { session, sessions, text:messageText, privateReason, hard:body.model === 'hermuse-hard' || match('hard',topicText), explicitDefault:body.model === 'hermuse-default' };
}

export class PolicyEngine {
  constructor({ policyFile, fetchImpl = fetch, load = loadPolicy, credentials = loadCredentials, audit = null } = {}) {
    this.policyFile = policyFile; this.fetch = fetchImpl; this.load = load; this.credentials = credentials;
    this.zdr = new ZdrTransport({ fetchImpl }); this.states = new Map(); this.locks = new Map(); this.audit = audit;
  }
  state(file, keyId) { const p = expand(file); const cacheKey=`${p}:${keyId}`; if (!this.states.has(cacheKey)) this.states.set(cacheKey,new PrivacyState(p,keyId)); return this.states.get(cacheKey); }
  async locked(key, action) {
    const prior = this.locks.get(key) || Promise.resolve();
    const task = prior.catch(() => {}).then(action);
    this.locks.set(key, task);
    try { return await task; } finally { if (this.locks.get(key) === task) this.locks.delete(key); }
  }
  async log(policy, event) {
    if (this.audit) return this.audit(event);
    const p = expand(policy.audit_file);
    await mkdir(path.dirname(p), { recursive:true, mode:0o700 });
    await appendFile(p, JSON.stringify(event)+'\n', { mode:0o600 });
  }
  async handle(body, headers, abortSignal) {
    const policy = await this.load(this.policyFile);
    const credentials = await this.credentials(policy.credentials_file);
    const client = authenticate(headers.get('authorization'), credentials);
    const info = inspect(body, headers, policy);
    const keys = info.sessions.map(s => createHmac('sha256',credentials.session_hmac_key).update(s).digest('hex'));
    const key = keys.at(-1); // one lock and audit identity for the root conversation
    return this.locked(key, async () => {
      const state = this.state(policy.state_file,createHash('sha256').update(credentials.session_hmac_key).digest('hex'));
      let privateReason = client.force_private ? 'private_client_key' : info.privateReason;
      for (const digest of keys) if (await state.isPrivate(digest)) { privateReason = 'private_conversation'; break; }
      let hard = info.hard;
      if (!privateReason && policy.classification.mode === 'zdr') {
        const verdict = await this.zdr.classify(policy,credentials,info.text,abortSignal);
        if (verdict.private || verdict.finance) privateReason = 'zdr_classification';
        hard ||= verdict.complexity >= policy.classification.hard_threshold;
      }
      const route = privateReason ? 'privacy' : hard && !info.explicitDefault ? 'hard' : 'default';
      if (route === 'privacy') for (const digest of keys) await state.markPrivate(digest); // durable BEFORE any upstream call
      // Audit failure is fail-closed. It never causes a fallback to a different provider.
      const model = route === 'privacy' ? policy.privacy.models[0] : policy.subscription[route === 'hard' ? 'hard_model' : 'default_model'];
      const event = { time:new Date().toISOString(), request_id:randomUUID(), session:key, route, model, provider:route === 'privacy'?'openrouter-zdr':'subscription', reason:privateReason || (hard&&!info.explicitDefault?'complexity':'ordinary') };
      try { await this.log(policy,event); } catch { throw new PolicyError('decision_log_unavailable'); }
      let result;
      if (route === 'privacy') result = await this.zdr.send(policy,credentials,body,{signal:abortSignal});
      else {
        const payload = { model };
        for (const k of CHAT_FIELDS) if (body[k] !== undefined) payload[k]=body[k];
        let response;
        try {
          response = await this.fetch(policy.subscription.url, { method:'POST',redirect:'error',
            headers:{ Authorization:`Bearer ${credentials.backend_key}`,'Content-Type':'application/json','X-Session-Id':info.session,'X-Token-Saver':'off' },
            body:JSON.stringify(payload), signal:AbortSignal.any([AbortSignal.timeout(policy.subscription.timeout_ms), ...(abortSignal?[abortSignal]:[])]) });
        } catch { throw new PolicyError('subscription_unavailable'); }
        if (!response.ok) { await response.body?.cancel(); throw new PolicyError('subscription_rejected'); }
        result = { response,model,provider:'subscription' };
      }
      return { ...result,route,requestId:event.request_id };
    });
  }
}

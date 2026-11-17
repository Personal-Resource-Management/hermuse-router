import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { validatePolicy, PolicyError, loadCredentials } from '../config.mjs';
import { PrivacyState, initializeState } from '../state.mjs';
import { PolicyEngine, authenticate, applyReasoningDefault } from '../engine.mjs';

async function lineageTest(t) {
  const dir = await sandbox(t);
  const calls=[];
  const engine=await engineFor(dir,{fetchImpl:async url=>{
    calls.push(String(url));
    return String(url).endsWith('/endpoints/zdr') ? Response.json({data:[{model_id:template.privacy.models[0],safety_retention:false,status:0,tag:'azure'}]}) : Response.json({choices:[{message:{content:'ok'}}]});
  }});
  const first=headers(credentials.clients[0],'child');first.set('x-hermuse-privacy','required');
  assert.equal((await engine.handle(request(),first)).route,'privacy');
  const resolved=headers(credentials.clients[0],'child');resolved.set('x-hermuse-lineage',JSON.stringify(['child','parent']));
  assert.equal((await engine.handle(request('hermuse-default'),resolved)).route,'privacy');
  const compressed=headers(credentials.clients[0],'compacted');compressed.set('x-hermuse-lineage',JSON.stringify(['compacted','parent']));
  assert.equal((await engine.handle(request('hermuse-hard'),compressed)).route,'privacy');
  assert.equal(calls.some(url=>url.includes('20128')),false);
}

const template = JSON.parse(await readFile(new URL('../policy.example.json', import.meta.url), 'utf8'));
const credentials = {
  clients: [
    { id: 'ordinary', key: 'ordinary-client-key-'.padEnd(40, 'x'), force_private: false },
    { id: 'private', key: 'private-client-key-'.padEnd(40, 'x'), force_private: true },
  ],
  session_hmac_key: 'session-hmac-key-'.padEnd(40, 's'),
  backend_key: 'backend-test-key', openrouter_key: 'openrouter-test-key',
};
const request = (model = 'hermuse-auto', extra = {}) => ({
  model, messages: [{ role: 'user', content: 'hello' }], ...extra,
});
const headers = (client = credentials.clients[0], session = 'session-1') => new Headers({
  authorization: `Bearer ${client.key}`, 'x-hermuse-session': session,
});
test('compaction ancestry preserves privacy and unresolved child taint propagates to root', lineageTest);
test('Terra auto preserves complexity routing and fails closed for finance', async t => {
  const dir = await sandbox(t), sent = [];
  const engine = await engineFor(dir, { fetchImpl: async (url, options = {}) => {
    if (String(url).endsWith('/endpoints/zdr')) return Response.json({data:[{model_id:template.privacy.models[0],safety_retention:false,status:0,tag:'azure'}]});
    sent.push({url:String(url), body:JSON.parse(options.body)});
    return Response.json({choices:[{message:{content:'ok'}}]});
  }});
  const normal = await engine.handle(request('hermuse-auto-terra'), headers(credentials.clients[0], 'terra-normal'));
  const hard = await engine.handle(request('hermuse-auto-terra', {messages:[{role:'user',content:'formal verification'}]}), headers(credentials.clients[0], 'terra-hard'));
  const finance = await engine.handle(request('hermuse-auto-terra', {messages:[{role:'user',content:'show my finance'}]}), headers(credentials.clients[0], 'terra-private'));
  assert.equal(normal.model, template.subscription.terra_model);
  assert.equal(hard.model, template.subscription.hard_model);
  assert.equal(finance.route, 'privacy');
  assert.equal(sent[2].body.provider.zdr, true);
  assert.equal(sent[2].body.provider.allow_fallbacks, false);
});
test('Luna comparison is selectable but cannot override strict privacy', async t => {
  const dir = await sandbox(t);
  const engine = await engineFor(dir, { fetchImpl: async url => String(url).endsWith('/endpoints/zdr')
    ? Response.json({data:[{model_id:template.privacy.models[0],safety_retention:false,status:0,tag:'azure'}]})
    : Response.json({choices:[{message:{content:'ok'}}]}) });
  assert.equal((await engine.handle(request('hermuse-auto'), headers(credentials.clients[0],'terra-default'))).model,template.subscription.terra_model);
  assert.equal((await engine.handle(request('hermuse-auto-luna'), headers(credentials.clients[0],'luna-comparison'))).model,template.subscription.luna_model);
  assert.equal((await engine.handle(request('hermuse-auto-luna'), headers(credentials.clients[1],'luna-private'))).route,'privacy');
});
test('direct Terra bypasses classification and model escalation but preserves explicit and existing privacy', async t => {
  const dir = await sandbox(t), sent = [];
  const engine = await engineFor(dir, { policyPatch:{ordinary_direct_terra:true}, fetchImpl: async (url, options = {}) => {
    const dest = String(url);
    if (dest.endsWith('/endpoints/zdr')) return Response.json({data:[{model_id:template.privacy.models[0],safety_retention:false,status:0,tag:'azure'}]});
    if (dest.endsWith('/decisions')) throw new Error('Classifier must not run in direct mode');
    sent.push({url:dest,body:JSON.parse(options.body)});
    return Response.json({choices:[{message:{content:'ok'}}]});
  }});
  const fresh = headers(credentials.clients[0], 'fresh-direct');
  const result = await engine.handle(request('hermuse-hard', {messages:[{role:'user',content:'finance and complex reasoning'}]}), fresh);
  assert.equal(result.route,'default');
  assert.equal(result.model,template.subscription.terra_model);
  assert.equal(sent.at(-1).body.model,template.subscription.terra_model);
  const pinned = headers(credentials.clients[0], 'previous-private');
  pinned.set('x-hermuse-privacy','required');
  assert.equal((await engine.handle(request(),pinned)).route,'privacy');
  const inherited = await engine.handle(request(),headers(credentials.clients[0],'previous-private'));
  assert.equal(inherited.route,'privacy');
  assert.equal(sent.at(-1).body.provider.zdr,true);
  assert.equal((await engine.handle(request(),headers(credentials.clients[1],'private-key'))).route,'privacy');
});
test('reasoning defaults high, remains configurable and preserves explicit effort or budgets', () => {
  assert.equal(applyReasoningDefault({}, {}).reasoning_effort, 'high');
  assert.equal(applyReasoningDefault({}, {default_reasoning_effort:'low'}).reasoning_effort, 'low');
  for (const body of [{reasoning_effort:'low'}, {reasoning:{effort:'medium'}}, {reasoning:{enabled:false}}, {reasoning:{max_tokens:1000}}]) {
    assert.deepEqual(applyReasoningDefault(body, {}), body);
  }
  assert.equal(applyReasoningDefault({reasoning_effort:''}, {}).reasoning_effort, 'high');
  assert.throws(() => validatePolicy({...structuredClone(template),default_reasoning_effort:'invalid'}), errCode('invalid_default_reasoning_effort'));
});
test('high default reaches ordinary, hard and ZDR answer transports without changing privacy', async t => {
  const dir = await sandbox(t), sent=[];
  const engine=await engineFor(dir,{fetchImpl:async (url, options={})=>{
    if (String(url).endsWith('/endpoints/zdr')) return Response.json({data:[{model_id:template.privacy.models[0],safety_retention:false,status:0,tag:'azure'}]});
    sent.push({url:String(url),body:JSON.parse(options.body)});
    return Response.json({choices:[{message:{content:'ok'}}]});
  }});
  for (const [i,alias] of ['hermuse-default','hermuse-hard','hermuse-private'].entries()) await engine.handle(request(alias),headers(credentials.clients[0],'reasoning-'+i));
  assert.deepEqual(sent.map(c=>c.body.reasoning_effort),['high','high','high']);
  assert.equal(sent[2].body.provider.zdr,true);
  assert.equal(sent[2].body.provider.allow_fallbacks,false);
  assert.equal(sent[2].url.includes('openrouter.ai'),true);
});
function errCode(code) {
  return (error) => error instanceof PolicyError && error.code === code;
}
async function sandbox(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hermuse-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
async function engineFor(dir, { fetchImpl = async () => new Response('{}'), policyPatch = {}, audit = async () => {} } = {}) {
  const policy = structuredClone(template);
  policy.classification.mode = 'local';
  policy.privacy.account_zdr_only_verified = true;
  policy.credentials_file = path.join(dir, 'credentials.json');
  policy.state_file = path.join(dir, 'private-sessions.json');
  policy.audit_file = path.join(dir, 'audit.jsonl');
  Object.assign(policy, policyPatch);
  await initializeState(policy.state_file, (await import('node:crypto')).createHash('sha256').update(credentials.session_hmac_key).digest('hex'));
  return new PolicyEngine({
    policyFile: 'unused-injected-policy', fetchImpl,
    load: async () => policy,
    credentials: async () => credentials,
    audit,
  });
}

test('policy validation rejects unsafe routing and privacy weakening', () => {
  assert.deepEqual(validatePolicy(structuredClone(template)), template);
  for (const mutate of [
    p => { p.listen.host = '0.0.0.0'; },
    p => { p.subscription.url = 'https://example.test/v1/chat/completions'; },
    p => { p.subscription.default_model = 'openai/gpt'; },
    p => { p.privacy.zdr = false; },
    p => { p.privacy.allow_fallbacks = true; },
    p => { p.privacy.models = ['openrouter/auto']; },
    p => { p.classification.extra = true; },
    p => { p.classification.mode = 'local'; },
  ]) {
    const candidate = structuredClone(template);
    mutate(candidate);
    assert.throws(() => validatePolicy(candidate), PolicyError);
  }
});

test('credentials reject duplicate client keys and weak key material', async t => {
  const dir = await sandbox(t);
  const file = path.join(dir, 'credentials.json');
  const dupe = structuredClone(credentials);
  dupe.clients[1].key = dupe.clients[0].key;
  await writeFile(file, JSON.stringify(dupe));
  await assert.rejects(loadCredentials(file), PolicyError);
  const weak = structuredClone(credentials);
  weak.session_hmac_key = 'short';
  await writeFile(file, JSON.stringify(weak));
  await assert.rejects(loadCredentials(file), PolicyError);
});

test('private state survives reload and rejects missing, mismatched, or corrupt state', async t => {
  const dir = await sandbox(t);
  const file = path.join(dir, 'state.json');
  await initializeState(file, 'key-id');
  const state = new PrivacyState(file, 'key-id');
  const digest = 'a'.repeat(64);
  assert.equal(await state.isPrivate(digest), false);
  await state.markPrivate(digest);
  assert.equal(await new PrivacyState(file, 'key-id').isPrivate(digest), true);
  await assert.rejects(new PrivacyState(file, 'different-key-id').isPrivate(digest), errCode('privacy_state_unavailable'));
  await writeFile(file, '{broken');
  await assert.rejects(state.isPrivate(digest), errCode('privacy_state_unavailable'));
  await assert.rejects(new PrivacyState(path.join(dir, 'missing.json'), 'key-id').isPrivate(digest), errCode('privacy_state_unavailable'));
});

test('private client forces ZDR and ZDR failure never falls back to subscription', async t => {
  const dir = await sandbox(t);
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith('/endpoints/zdr')) return Response.json({ data: [{ model_id: template.privacy.models[0], safety_retention: false, status: 0, tag: 'azure' }] });
    throw new Error('simulated private upstream outage');
  };
  const engine = await engineFor(dir, { fetchImpl });
  await assert.rejects(engine.handle(request('hermuse-default'), headers(credentials.clients[1]), undefined), errCode('private_upstream_unavailable'));
  assert.equal(calls.length, 2);
  const payload = JSON.parse(calls[1].options.body);
  assert.equal(payload.provider.zdr, true);
  assert.equal(payload.provider.data_collection, 'deny');
  assert.equal(payload.provider.allow_fallbacks, false);
  assert.equal(payload.provider.require_parameters, true);
  assert.equal(calls.some(c => c.url.includes('20128')), false);
  assert.equal(await engine.state(path.join(dir, 'private-sessions.json'), (await import('node:crypto')).createHash('sha256').update(credentials.session_hmac_key).digest('hex')).isPrivate((await import('node:crypto')).createHmac('sha256', credentials.session_hmac_key).update('session-1').digest('hex')), true);
});

test('conversation stays private across requests after private trigger', async t => {
  const dir = await sandbox(t);
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push(String(url));
    if (String(url).endsWith('/endpoints/zdr')) return Response.json({ data: [{ model_id: template.privacy.models[0], safety_retention: false, status: 0, tag: 'azure' }] });
    return Response.json({ choices: [{ message: { content: 'ok' } }] });
  };
  const engine = await engineFor(dir, { fetchImpl });
  const privateHeaders = headers(credentials.clients[0], 'sticky');
  privateHeaders.set('x-hermuse-privacy', 'required');
  assert.equal((await engine.handle(request(), privateHeaders)).route, 'privacy');
  assert.equal((await engine.handle(request('hermuse-default'), headers(credentials.clients[0], 'sticky'))).route, 'privacy');
  assert.equal(calls.filter(url => url.includes('20128')).length, 0);
  assert.equal(calls.filter(url => url.endsWith('/chat/completions')).length, 2);
});

test('authentication uses exact bearer token and rejects malformed or unknown credentials', () => {
  assert.equal(authenticate(`Bearer ${credentials.clients[0].key}`, credentials), credentials.clients[0]);
  for (const header of [undefined, '', `bearer ${credentials.clients[0].key}`, 'Bearer wrong']) {
    assert.throws(() => authenticate(header, credentials), errCode('unauthorized'));
  }
});

test('subscription errors are surfaced without trying a privacy or alternate route', async t => {
  const dir = await sandbox(t);
  const calls = [];
  const engine = await engineFor(dir, { fetchImpl: async (url) => { calls.push(String(url)); return new Response('rejected', { status: 503 }); } });
  await assert.rejects(engine.handle(request('hermuse-default'), headers(), undefined), errCode('subscription_rejected'));
  assert.deepEqual(calls, [template.subscription.url]);
});


test('independent ordinary work on one root conversation dispatches in parallel after its decisions commit', async t => {
  const dir = await sandbox(t);
  let releaseFirst;
  const firstReleased = new Promise(resolve => { releaseFirst = resolve; });
  let sawFirst;
  const firstStarted = new Promise(resolve => { sawFirst = resolve; });
  let sawSecond;
  const secondStarted = new Promise(resolve => { sawSecond = resolve; });
  let subscriptionCalls = 0;
  const engine = await engineFor(dir, { fetchImpl: async (url) => {
    assert.equal(String(url), template.subscription.url);
    subscriptionCalls += 1;
    if (subscriptionCalls === 1) {
      sawFirst();
      await firstReleased;
    } else {
      sawSecond();
    }
    return Response.json({ choices: [{ message: { content: 'ok' } }] });
  } });
  const first = engine.handle(request(), headers(credentials.clients[0], 'parallel-root'));
  await firstStarted;
  const second = engine.handle(request(), headers(credentials.clients[0], 'parallel-root'));
  try {
    await Promise.race([
      secondStarted,
      new Promise((_, reject) => setTimeout(() => reject(new Error('second ordinary dispatch waited behind model inference')), 1_000)),
    ]);
  } finally {
    releaseFirst();
  }
  await Promise.all([first, second]);
  assert.equal(subscriptionCalls, 2);
});

test('a committed private decision taints a sibling before either private response finishes', async t => {
  const dir = await sandbox(t);
  let releaseFirst;
  const firstReleased = new Promise(resolve => { releaseFirst = resolve; });
  let sawFirstPrivateCall;
  const firstPrivateCall = new Promise(resolve => { sawFirstPrivateCall = resolve; });
  let privateCalls = 0;
  let subscriptionCalls = 0;
  const engine = await engineFor(dir, { fetchImpl: async (url) => {
    const value = String(url);
    if (value.endsWith('/endpoints/zdr')) {
      return Response.json({ data: [{ model_id: template.privacy.models[0], safety_retention: false, status: 0, tag: 'azure' }] });
    }
    if (value.endsWith('/chat/completions')) {
      privateCalls += 1;
      if (privateCalls === 1) {
        sawFirstPrivateCall();
        await firstReleased;
      }
      return Response.json({ choices: [{ message: { content: 'ok' } }] });
    }
    subscriptionCalls += 1;
    return Response.json({ choices: [{ message: { content: 'ordinary' } }] });
  } });
  const privateHeaders = headers(credentials.clients[0], 'tainted-root');
  privateHeaders.set('x-hermuse-privacy', 'required');
  const first = engine.handle(request(), privateHeaders);
  await firstPrivateCall;
  const sibling = engine.handle(request(), headers(credentials.clients[0], 'tainted-root'));
  try {
    const result = await Promise.race([
      sibling,
      new Promise((_, reject) => setTimeout(() => reject(new Error('tainted sibling waited behind private model inference')), 1_000)),
    ]);
    assert.equal(result.route, 'privacy');
  } finally {
    releaseFirst();
  }
  await first;
  assert.equal(subscriptionCalls, 0);
  assert.equal(privateCalls, 2);
});

test('ZDR catalog accepts only explicitly safe, active, allowlisted matching endpoints', async () => {
  const { ZdrTransport } = await import('../zdr.mjs');
  const invalid = [
    { model_id: template.privacy.models[0], safety_retention: true, status: 0, tag: 'azure' },
    { model_id: template.privacy.models[0], status: 0, tag: 'azure' },
    { model_id: template.privacy.models[0], safety_retention: false, status: 1, tag: 'azure' },
    { model_id: template.privacy.models[0], safety_retention: false, status: 0, tag: 'other' },
  ];
  const transport = new ZdrTransport({ fetchImpl: async () => Response.json({ data: invalid }) });
  await assert.rejects(transport.select(template), errCode('no_strict_zdr_endpoint'));
  const good = new ZdrTransport({ fetchImpl: async () => Response.json({ data: [
    ...invalid,
    { model_id: template.privacy.models[0], safety_retention: false, status: 0, tag: 'azure' },
  ] }) });
  assert.deepEqual(await good.select(template), { model: template.privacy.models[0], providers: ['azure'] });
});

test('expired ZDR catalog is not reused after refresh failure', async () => {
  const { ZdrTransport } = await import('../zdr.mjs');
  let now = 0;
  let calls = 0;
  const transport = new ZdrTransport({ now: () => now, fetchImpl: async () => {
    calls++;
    if (calls === 1) return Response.json({ data: [{ model_id: template.privacy.models[0], safety_retention: false, status: 0, tag: 'azure' }] });
    throw new Error('offline');
  } });
  await transport.select(template);
  now = template.privacy.endpoint_cache_ms + 1;
  await assert.rejects(transport.select(template), errCode('zdr_catalog_unavailable'));
  assert.equal(calls, 2);
});

function decisionResult({ model = template.classification.model, privateP = 0.01, financeP = 0.01, hardP = 0.01 } = {}) {
  return Response.json({ model, answers: {
    private: { type: 'noul', noul: privateP },
    finance: { type: 'noul', noul: financeP },
    hard: { type: 'noul', noul: hardP },
  } });
}
function decisionCatalog(entries = []) {
  return Response.json({ data: entries });
}
const classifierCatalogEntry = (overrides = {}) => ({
  model_id: template.classification.catalog_model,
  name: `SystemOne | ${template.classification.model}`,
  safety_retention: false, status: 0, tag: template.classification.providers[0],
  ...overrides,
});

test('decision request pins a matching catalog build and strips caller routing controls', async () => {
  const { ZdrTransport } = await import('../zdr.mjs');
  const calls = [];
  const transport = new ZdrTransport({ fetchImpl: async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith('/endpoints/zdr')) return decisionCatalog([
      classifierCatalogEntry({ name: `SystemOne | ${template.classification.model}-other` }),
      classifierCatalogEntry(),
    ]);
    return decisionResult();
  } });
  const policy = structuredClone(template); policy.privacy.account_zdr_only_verified = true;
  await transport.classify(policy, credentials, 'routine request');
  const call = calls.find(x => x.url.endsWith('/decisions'));
  assert.ok(call);
  const body = JSON.parse(call.options.body);
  assert.equal(body.model, template.classification.model);
  assert.deepEqual(body.provider, { only: [template.classification.providers[0]], allow_fallbacks: false, require_parameters: true, data_collection: 'deny', zdr: true });
  assert.deepEqual(Object.keys(body).sort(), ['model', 'provider', 'questions', 'state']);
  assert.equal(call.options.redirect, 'error');
  assert.equal(call.options.headers['X-OpenRouter-Cache'], 'false');
});

test('classifier rejects a mismatched build and invalid probability', async () => {
  const { ZdrTransport } = await import('../zdr.mjs');
  for (const response of [
    decisionResult({ model: 'other/model-20260101' }),
    decisionResult({ financeP: 1.5 }),
  ]) {
    const transport = new ZdrTransport({ fetchImpl: async url => String(url).endsWith('/endpoints/zdr')
      ? decisionCatalog([classifierCatalogEntry()]) : response });
    const policy = structuredClone(template); policy.privacy.account_zdr_only_verified = true;
    await assert.rejects(transport.classify(policy, credentials, 'routine'), PolicyError);
  }
  const wrongBuild = new ZdrTransport({ fetchImpl: async url => String(url).endsWith('/endpoints/zdr')
    ? decisionCatalog([classifierCatalogEntry({ name: `DeepInfra | ${template.classification.catalog_model}-20260101` })])
    : decisionResult() });
  const policy = structuredClone(template); policy.privacy.account_zdr_only_verified = true;
  await assert.rejects(wrongBuild.classify(policy, credentials, 'routine'), errCode('no_strict_zdr_endpoint'));
});

test('automatic finance decision routes privately; ordinary and hard decisions use subscription', async t => {
  const routeTest = async ({ privateP = 0.01, financeP = 0.01, hardP = 0.01 } = {}) => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'hermuse-route-'));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const calls = [];
    const fetchImpl = async (url, options = {}) => {
      calls.push({ url: String(url), options });
      if (String(url).endsWith('/endpoints/zdr')) return decisionCatalog([
        classifierCatalogEntry(),
        { model_id: template.privacy.models[0], safety_retention: false, status: 0, tag: 'azure' },
      ]);
      if (String(url).endsWith('/decisions')) return decisionResult({ privateP, financeP, hardP });
      return Response.json({ choices: [{ message: { content: 'ok' } }] });
    };
    const engine = await engineFor(dir, { fetchImpl, policyPatch: { classification: { ...template.classification, mode: 'zdr' } } });
    const result = await engine.handle(request(), headers(credentials.clients[0], `decision-${Math.random()}`));
    return { result, calls };
  };
  const finance = await routeTest({ financeP: 0.9 });
  assert.equal(finance.result.route, 'privacy');
  assert.ok(finance.calls.some(c => c.url.endsWith('/chat/completions') && c.url.includes('openrouter.ai')));
  assert.equal(finance.calls.some(c => c.url.includes('20128')), false);
  const ordinary = await routeTest();
  assert.equal(ordinary.result.route, 'default');
  assert.ok(ordinary.calls.some(c => c.url.includes('20128')));
  const hard = await routeTest({ hardP: 0.9 });
  assert.equal(hard.result.route, 'hard');
  assert.ok(hard.calls.some(c => c.url.includes('20128')));
});

test('classifier failure blocks subscription inference', async t => {
  const dir = await sandbox(t);
  const calls = [];
  const fetchImpl = async url => {
    calls.push(String(url));
    if (String(url).endsWith('/endpoints/zdr')) return decisionCatalog([classifierCatalogEntry()]);
    throw new Error('decision service unavailable');
  };
  const engine = await engineFor(dir, { fetchImpl, policyPatch: { classification: { ...template.classification, mode: 'zdr' } } });
  await assert.rejects(engine.handle(request(), headers(credentials.clients[0], 'classifier-fail')), errCode('private_upstream_unavailable'));
  assert.equal(calls.some(url => url.includes('20128')), false);
});


const { createPolicyServer } = await import('../server.mjs');
const httpPolicy = () => ({ listen: { host: '127.0.0.1', port: 20129 }, limits: { max_concurrency: 4, body_bytes: 4096 } });
async function withHttpServer(t, { loadPolicy = httpPolicy(), handle } = {}) {
  const startup = httpPolicy();
  const engine = {
    policyFile: 'injected',
    load: async () => loadPolicy,
    handle: handle || (async () => ({
      response: new Response('ok'), route: 'default', model: 'cx/test', provider: 'subscription', requestId: 'request-test',
    })),
  };
  const server = createPolicyServer(engine, startup);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(() => resolve()));
  });
  return { server, origin: `http://127.0.0.1:${address.port}`, engine };
}
const httpPayload = (extra = {}) => ({ model: 'hermuse-auto', messages: [{ role: 'user', content: 'hello' }], ...extra });

test('HTTP server preserves SSE body and routing headers', async t => {
  const sse = 'data: {"choices":[{"delta":{"content":"hello"}}]}\n\ndata: [DONE]\n\n';
  const { origin } = await withHttpServer(t, { handle: async () => ({
    response: new Response(sse, { headers: { 'content-type': 'text/event-stream; charset=utf-8' } }),
    route: 'hard', model: 'cx/test-hard', provider: 'subscription', requestId: 'req-sse',
  }) });
  const response = await fetch(`${origin}/v1/chat/completions`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(httpPayload({ stream: true })),
  });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /^text\/event-stream/);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('x-accel-buffering'), 'no');
  assert.equal(response.headers.get('x-hermuse-route'), 'hard');
  assert.equal(response.headers.get('x-hermuse-model'), 'cx/test-hard');
  assert.equal(response.headers.get('x-hermuse-provider'), 'subscription');
  assert.equal(response.headers.get('x-request-id'), 'req-sse');
  assert.equal(await response.text(), sse);
});

test('HTTP server rejects unsupported inference endpoints without calling engine', async t => {
  let called = false;
  const { origin } = await withHttpServer(t, { handle: async () => { called = true; throw new Error('should not reach engine'); } });
  const response = await fetch(`${origin}/v1/responses`, { method: 'POST', body: '{}' });
  const data = await response.json();
  assert.equal(response.status, 404);
  assert.equal(data.error.code, 'unsupported_endpoint');
  assert.equal(called, false);
});

test('HTTP server reports malformed JSON without exposing parser details', async t => {
  let called = false;
  const { origin } = await withHttpServer(t, { handle: async () => { called = true; } });
  const response = await fetch(`${origin}/v1/chat/completions`, { method: 'POST', body: '{"private-secret":' });
  const body = await response.text();
  assert.equal(response.status, 400);
  assert.match(body, /invalid_json/);
  assert.doesNotMatch(body, /private-secret|SyntaxError|Unexpected end/);
  assert.equal(called, false);
});

test('HTTP server requires restart when reloaded listen policy changes', async t => {
  const changed = httpPolicy(); changed.listen.port++;
  let called = false;
  const { origin } = await withHttpServer(t, { loadPolicy: changed, handle: async () => { called = true; } });
  const response = await fetch(`${origin}/v1/chat/completions`, {
    method: 'POST', body: JSON.stringify(httpPayload()), headers: { 'content-type': 'application/json' },
  });
  const data = await response.json();
  assert.equal(response.status, 503);
  assert.equal(data.error.code, 'listen_change_requires_restart');
  assert.equal(called, false);
});

test('HTTP server never echoes raw upstream errors or secret text from engine failures', async t => {
  const secret = 'upstream-secret-prompt-fragment';
  const { origin } = await withHttpServer(t, { handle: async () => { throw new Error(`upstream rejected: ${secret}`); } });
  const response = await fetch(`${origin}/v1/chat/completions`, {
    method: 'POST', body: JSON.stringify(httpPayload()), headers: { 'content-type': 'application/json' },
  });
  const body = await response.text();
  assert.equal(response.status, 503);
  assert.match(body, /router_error/);
  assert.doesNotMatch(body, /upstream rejected|upstream-secret-prompt-fragment/);
});

test('missing session metadata forces all aliases private without classification or subscription', async t => {
  const dir = await sandbox(t);
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith('/endpoints/zdr')) return Response.json({ data: [
      { model_id: template.privacy.models[0], safety_retention: false, status: 0, tag: 'azure' },
    ] });
    return Response.json({ choices: [{ message: { content: 'ok' } }] });
  };
  const engine = await engineFor(dir, { fetchImpl, policyPatch: { classification: { ...template.classification, mode: 'zdr' } } });
  const noIdentity = new Headers({ authorization: `Bearer ${credentials.clients[0].key}` });
  for (const alias of ['hermuse-auto', 'hermuse-hard']) {
    const result = await engine.handle(request(alias), noIdentity);
    assert.equal(result.route, 'privacy');
  }
  assert.equal(calls.some(call => call.url.endsWith('/decisions')), false);
  assert.equal(calls.some(call => call.url.includes('20128')), false);
  assert.equal(calls.filter(call => call.url.endsWith('/chat/completions')).length, 2);
});

test('malformed nonempty session metadata is rejected before any upstream call', async t => {
  const dir = await sandbox(t);
  let calls = 0;
  const engine = await engineFor(dir, { fetchImpl: async () => { calls++; return Response.json({}); } });
  const badHeaders = new Headers({ authorization: `Bearer ${credentials.clients[0].key}`, 'x-hermuse-session': 'bad session value' });
  await assert.rejects(engine.handle(request('hermuse-default'), badHeaders), errCode('invalid_session_metadata'));
  assert.equal(calls, 0);
});

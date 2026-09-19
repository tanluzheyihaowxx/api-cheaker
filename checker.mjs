import { performance } from 'node:perf_hooks';

export function maskKey(key) {
  return key.length > 12 ? `${key.slice(0, 5)}…${key.slice(-4)}` : '••••••';
}
export function redact(text, keys = []) {
  let value = String(text ?? '');
  for (const key of [...keys].sort((a, b) => b.length - a.length)) {
    if (key) value = value.split(key).join('[REDACTED]');
  }
  return value.replace(/Bearer\s+[^\s"',;]+/gi, 'Bearer [REDACTED]')
    .replace(/sk-[A-Za-z0-9_-]+/g, '[REDACTED]').slice(0, 600);
}
export function parseLines(text, allowHttp = false) {
  if (typeof text !== 'string' || text.length > 500_000) throw new Error('输入过大或格式不正确');
  const entries = [], errors = [], seen = new Set();
  let duplicates = 0;
  for (const [index, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (entries.length + errors.length >= 500) throw new Error('单次最多 500 组，请分批检测');
    const match = line.match(/^baseurl\s*:\s*(.*?)\s*[;；]\s*apikey\s*:\s*(\S+)\s*$/i);
    if (!match) { errors.push({ line: index + 1, status: 'invalid_input', detail: '格式应为 baseurl:https://example.com/v1;apikey:你的密钥' }); continue; }
    try {
      const url = new URL(match[1]);
      if (!['https:', 'http:'].includes(url.protocol)) throw new Error('仅支持 https:// 或 http://');
      if (url.protocol === 'http:' && !allowHttp) throw new Error('HTTP 会明文发送密钥；如确需使用，请勾选允许 HTTP');
      if (url.username || url.password || url.search || url.hash) throw new Error('baseurl 不可包含用户名、密码、查询参数或 # 片段');
      let path = url.pathname.replace(/\/+$/, '');
      if (/\/(chat\/completions|responses|models)$/.test(path)) throw new Error('请输入接口根路径（例如 /v1），不要附带 /chat/completions、/responses 或 /models');
      if (!path) path = '/v1';
      const baseurl = url.origin + path;
      const key = match[2];
      const unique = JSON.stringify([baseurl, key]);
      if (seen.has(unique)) { duplicates++; continue; }
      seen.add(unique);
      entries.push({ line: index + 1, baseurl, key });
    } catch (error) {
      errors.push({ line: index + 1, status: 'invalid_input', detail: error instanceof TypeError ? 'baseurl 必须为完整的 http(s) URL' : error.message });
    }
  }
  return { entries, errors, duplicates };
}

function description(data, fallback) {
  return data?.error?.message || (typeof data?.error === 'string' ? data.error : '') || data?.message || fallback;
}
function classify(status, data) {
  const message = `${data?.error?.code ?? ''} ${data?.error?.type ?? ''} ${description(data, '')}`;
  if (/insufficient_quota|credit.*balance|balance.*insufficient|quota.*exceed|余额不足|额度不足/i.test(message)) return 'quota';
  if (status === 401) return 'auth_failed';
  if (status === 403) return 'forbidden';
  if (status === 429) return 'rate_limited';
  if (status >= 500) return 'server_error';
  if (status === 404 || status === 405) return 'not_supported';
  return 'request_failed';
}
async function request(url, key, body, options) {
  const timeout = AbortSignal.timeout(options.timeout * 1000);
  const signal = options.signal ? AbortSignal.any([timeout, options.signal]) : timeout;
  try {
    const response = await fetch(url, {
      method: body ? 'POST' : 'GET',
      headers: { Authorization: `Bearer ${key}`, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      redirect: 'manual', signal,
    });
    // Never forward credentials to redirected hosts, and bound untrusted response size.
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      return { ok: false, status: 'redirect', http: response.status, detail: '接口返回重定向，已停止，避免密钥被转发。请填写最终 API 地址。' };
    }
    const reader = response.body?.getReader();
    const chunks = []; let size = 0;
    if (reader) {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 2_000_000) { await reader.cancel(); return { ok: false, status: 'invalid_response', http: response.status, detail: '响应超过 2 MB，已停止读取' }; }
        chunks.push(Buffer.from(value));
      }
    }
    let data;
    try { data = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { return { ok: false, status: response.ok ? 'invalid_response' : classify(response.status), http: response.status, detail: '响应不是 JSON，可能填写了网站首页或遇到网关/WAF 页面' }; }
    if (!response.ok || data?.error) return { ok: false, status: classify(response.status, data), http: response.status, detail: description(data, `HTTP ${response.status}`) };
    return { ok: true, http: response.status, data };
  } catch (error) {
    if (options.signal?.aborted) return { ok: false, status: 'cancelled', detail: '已取消' };
    if (timeout.aborted) return { ok: false, status: 'timeout', detail: `单次请求超过 ${options.timeout} 秒` };
    return { ok: false, status: 'network_error', detail: `连接失败：${error.cause?.code || error.message}` };
  }
}
function candidateModels(data) {
  if (!Array.isArray(data?.data)) return [];
  return [...new Set(data.data.map(item => item?.id).filter(id => typeof id === 'string' && id.length < 200))]
    .filter(id => !/embed|rerank|whisper|tts|dall-e|image|realtime|audio|moderation|sora|transcri/i.test(id))
    .sort((a, b) => score(b) - score(a) || a.localeCompare(b)).slice(0, 3);
}
function score(id) {
  return (/mini|flash|haiku|small/i.test(id) ? 20 : 0) + (/gpt|chat|instruct|claude|deepseek|qwen|llama|gemini/i.test(id) ? 10 : 0) - (/reason|thinking|pro|^o[134]/i.test(id) ? 10 : 0);
}
function extractText(data, protocol) {
  if (protocol === 'chat') {
    const content = data?.choices?.[0]?.message?.content;
    if (typeof content === 'string') return content.trim();
    if (Array.isArray(content)) return content.map(x => typeof x?.text === 'string' ? x.text : '').join('').trim();
    return '';
  }
  return (Array.isArray(data?.output) ? data.output : []).flatMap(item => item?.type === 'message' && Array.isArray(item.content) ? item.content : [])
    .filter(item => item?.type === 'output_text' && typeof item.text === 'string').map(item => item.text).join('').trim();
}

export async function checkEntry(entry, options) {
  const started = performance.now();
  const result = { line: entry.line, baseurl: entry.baseurl, key: maskKey(entry.key), status: 'unverified', model: '', endpoint: '', detail: '', attempts: [] };
  const finish = (status, detail) => ({ ...result, status, detail: redact(detail, options.keys ?? [entry.key]), elapsedMs: Math.round(performance.now() - started) });
  const record = (endpoint, model, response) => result.attempts.push({ endpoint, model, http: response.http, status: response.ok ? 'http_ok' : response.status, detail: redact(response.detail || '', options.keys ?? [entry.key]) });
  let models = options.model ? [options.model] : [];
  if (!models.length) {
    const listing = await request(`${entry.baseurl}/models`, entry.key, undefined, options);
    record('models', '', listing);
    if (!listing.ok) {
      const status = ['auth_failed', 'forbidden', 'quota', 'rate_limited', 'cancelled', 'timeout', 'network_error', 'server_error', 'redirect'].includes(listing.status) ? listing.status : 'unverified';
      return finish(status, `获取模型列表失败：${listing.detail}；可填写模型名后重试，跳过 /models。`);
    }
    models = candidateModels(listing.data);
    if (!models.length) return finish('unverified', '模型列表没有可探测的文本模型；请手动填写模型名。获取列表成功不代表可正常调用。');
  }
  const protocols = options.protocol === 'auto' ? ['chat', 'responses'] : [options.protocol];
  let last = { status: 'unverified', detail: '未完成验证' };
  for (const model of models) {
    for (const protocol of protocols) {
      if (options.signal?.aborted) return finish('cancelled', '已取消');
      const endpoint = protocol === 'chat' ? 'chat/completions' : 'responses';
      result.model = model; result.endpoint = endpoint;
      const body = protocol === 'chat'
        ? { model, messages: [{ role: 'user', content: 'Reply with OK.' }], max_completion_tokens: 64, stream: false }
        : { model, input: 'Reply with OK.', max_output_tokens: 64, stream: false, store: false };
      let response = await request(`${entry.baseurl}/${endpoint}`, entry.key, body, options);
      record(endpoint, model, response);
      // Legacy compatible servers may only accept max_tokens. Retry only this explicit schema mismatch.
      if (protocol === 'chat' && response.http === 400 && /max_completion_tokens/i.test(response.detail || '') && /unsupported|unknown|unrecognized|not.*support|not.*permitted|extra|不支持/i.test(response.detail || '')) {
        delete body.max_completion_tokens; body.max_tokens = 64;
        response = await request(`${entry.baseurl}/${endpoint}`, entry.key, body, options);
        record(endpoint, model, response);
      }
      if (response.ok) {
        if (extractText(response.data, protocol)) return finish('usable', '实际调用成功，已收到非空文本回复。');
        last = { status: 'unverified', detail: 'HTTP 成功但没有非空文本回复（可能 token 上限不足或响应格式不兼容）；不判定可用。' };
        result.attempts[result.attempts.length - 1].status = 'no_text';
      } else {
        last = response;
        if (['auth_failed', 'forbidden', 'quota', 'rate_limited', 'timeout', 'network_error', 'cancelled', 'redirect', 'server_error'].includes(response.status)) return finish(response.status, response.detail);
      }
    }
  }
  return finish(last.status, `${last.detail}（仅代表本次所测模型/接口未成功，不代表所有模型均不可用）`);
}

export async function runBatch(entries, options, onResult) {
  let cursor = 0;
  const workers = Array.from({ length: Math.min(options.concurrency, entries.length) }, async () => {
    while (cursor < entries.length && !options.signal?.aborted) {
      const entry = entries[cursor++];
      try { onResult(await checkEntry(entry, options)); }
      catch { onResult({ line: entry.line, baseurl: entry.baseurl, key: maskKey(entry.key), status: 'internal_error', detail: '检测异常，请重试' }); }
    }
  });
  await Promise.all(workers);
}

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { parseLines, runBatch, redact } from './checker.mjs';

export async function createApp() {
  const token = randomBytes(32).toString('hex');
  const template = await readFile(new URL('./public/index.html', import.meta.url), 'utf8');
  let busy = false;
  const server = http.createServer(async (req, res) => {
    const address = server.address();
    const origin = `http://127.0.0.1:${address.port}`;
    const headers = {
      'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'none'; script-src 'nonce-" + token + "'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    };
    const reply = (code, text) => { res.writeHead(code, { ...headers, 'Content-Type': 'text/plain; charset=utf-8' }); res.end(text); };
    // Bind to loopback and reject DNS rebinding / cross-origin submissions.
    if (req.headers.host !== `127.0.0.1:${address.port}`) return reply(403, '仅允许通过本机 127.0.0.1 访问');
    if (req.method === 'GET' && req.url === '/') {
      res.writeHead(200, { ...headers, 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(template.replaceAll('__TOKEN__', token));
    }
    if (req.method === 'GET' && req.url === '/favicon.ico') { res.writeHead(204); return res.end(); }
    if (req.method !== 'POST' || req.url !== '/api/check') return reply(404, 'Not found');
    const supplied = Buffer.from(String(req.headers['x-local-token'] || ''));
    if (req.headers.origin !== origin || supplied.length !== token.length || !timingSafeEqual(supplied, Buffer.from(token))) return reply(403, '本地校验失败，请刷新页面');
    if (!String(req.headers['content-type']).startsWith('application/json')) return reply(415, '需要 JSON 请求');
    if (busy) return reply(409, '已有检测任务正在运行，请等待完成或停止任务');
    busy = true;
    const controller = new AbortController();
    res.on('close', () => controller.abort());
    try {
      const chunks = []; let bytes = 0;
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > 1_000_000) { reply(413, '输入过大'); return; }
        chunks.push(chunk);
      }
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return reply(400, '无效 JSON'); }
      if (!body || typeof body !== 'object') return reply(400, '无效请求');
      const concurrency = Number(body.concurrency ?? 3), timeout = Number(body.timeout ?? 20);
      const protocol = body.protocol ?? 'auto';
      const model = typeof body.model === 'string' ? body.model.trim() : '';
      if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 10 || !Number.isInteger(timeout) || timeout < 3 || timeout > 120 || !['auto', 'chat', 'responses'].includes(protocol) || model.length > 200 || /[\r\n]/.test(model)) return reply(400, '参数超出范围');
      let parsed;
      try { parsed = parseLines(body.text, body.allowHttp === true); }
      catch (error) { return reply(400, error.message); }
      if (!parsed.entries.length && !parsed.errors.length) return reply(400, '请输入至少一组 baseurl 和 apikey');
      const keys = parsed.entries.map(e => e.key);
      const clean = value => typeof value === 'string' ? redact(value, keys) : Array.isArray(value) ? value.map(clean) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([k, v]) => [k, clean(v)])) : value;
      res.writeHead(200, { ...headers, 'Content-Type': 'application/x-ndjson; charset=utf-8', 'X-Accel-Buffering': 'no' });
      const send = event => { if (!res.destroyed) res.write(JSON.stringify(clean(event)) + '\n'); };
      send({ type: 'start', total: parsed.entries.length + parsed.errors.length, duplicates: parsed.duplicates });
      for (const error of parsed.errors) send({ type: 'result', result: error });
      await runBatch(parsed.entries, { concurrency, timeout, protocol, model, signal: controller.signal, keys }, result => send({ type: 'result', result }));
      send({ type: 'done' });
      res.end();
    } catch {
      if (!res.headersSent) reply(500, '本地服务处理失败');
      else res.end();
    } finally { busy = false; }
  });
  server.requestTimeout = 30_000;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = await createApp();
  const port = Number(process.env.PORT || 0);
  server.on('error', error => { console.error(`启动失败：${error.code || error.message}`); process.exitCode = 1; });
  server.listen(port, '127.0.0.1', () => {
    const url = `http://127.0.0.1:${server.address().port}`;
    console.log(`\nAPI 批量检测器已启动\n\n  ${url}\n\n仅监听本机。按 Ctrl+C 停止服务。\n不记录密钥，不自动跟随重定向。\n`);
    if (!process.argv.includes('--no-open')) {
      const program = process.platform === 'win32' ? 'rundll32.exe' : process.platform === 'darwin' ? 'open' : 'xdg-open';
      const args = process.platform === 'win32' ? ['url.dll,FileProtocolHandler', url] : [url];
      const child = spawn(program, args, { windowsHide: true, stdio: 'ignore' });
      child.on('error', () => console.log('请手动打开上面的本地地址。'));
      child.unref();
    }
  });
}


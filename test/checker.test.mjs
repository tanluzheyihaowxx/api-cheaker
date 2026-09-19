import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { parseLines, checkEntry, runBatch, redact } from '../checker.mjs';
import { createApp } from '../server.mjs';

async function fixture(handler, run) {
  const server = http.createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    let body; try { body = JSON.parse(Buffer.concat(chunks).toString()); } catch {}
    const send = (status, data) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); };
    await handler(req, res, body, send);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await run(`http://127.0.0.1:${server.address().port}/v1`); }
  finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}
const entry = baseurl => ({ line: 1, baseurl, key: 'sk-test-secret-123456' });
const options = extra => ({ timeout: 3, concurrency: 3, protocol: 'auto', model: '', ...extra });
const chat = { choices: [{ message: { role: 'assistant', content: 'OK' } }] };

test('parse: URL normalization, Chinese separator, dedup, input errors', () => {
  const parsed = parseLines('baseurl:https://example.com;apikey:sk-aaa\nbaseurl:https://example.com/v1/；apikey:sk-aaa\n# note\nwrong\nbaseurl:https://example.com/custom/v1;apikey:abc');
  assert.equal(parsed.entries.length, 2);assert.equal(parsed.duplicates, 1);assert.equal(parsed.errors.length, 1);
  assert.equal(parsed.entries[0].baseurl, 'https://example.com/v1');assert.equal(parsed.entries[1].line, 5);
});
test('parse: reject unsafe URL forms and require HTTP opt-in', () => {
  for (const url of ['ftp://example.com', 'https://u:p@example.com', 'https://example.com?key=abc', 'https://example.com/#x', 'https://example.com/v1/chat/completions', 'http://localhost:3000', 'not-a-url']) {
    assert.equal(parseLines(`baseurl:${url};apikey:secret`).errors.length, 1, url);
  }
  assert.equal(parseLines('baseurl:http://127.0.0.1:3000;apikey:secret', true).entries.length, 1);
});
test('parse: bound number of entries', () => {
  assert.throws(() => parseLines(Array.from({length:501},(_,i)=>`baseurl:https://host${i}.example/v1;apikey:key`).join('\n')));
});
test('chat: list models then verify real inference', async () => {
  const calls=[];
  await fixture((req,res,body,send)=>{calls.push(req.url);assert.equal(req.headers.authorization,'Bearer sk-test-secret-123456');if(req.url==='/v1/models')send(200,{data:[{id:'embedding-model'},{id:'chat-mini'}]});else{assert.equal(body.model,'chat-mini');send(200,chat);}},async baseurl=>{
    const result=await checkEntry(entry(baseurl),options());assert.equal(result.status,'usable');assert.equal(result.model,'chat-mini');assert.equal(result.attempts.length,2);assert.ok(!JSON.stringify(result).includes(entry(baseurl).key));
  });
  assert.deepEqual(calls,['/v1/models','/v1/chat/completions']);
});
test('explicit model bypasses unsupported model listing', async () => {
  await fixture((req,res,body,send)=>{assert.equal(req.url,'/v1/chat/completions');send(200,chat);},async baseurl=>assert.equal((await checkEntry(entry(baseurl),options({model:'custom'}))).status,'usable'));
});
test('responses: automatic fallback from chat 404', async () => {
  await fixture((req,res,body,send)=>{
    if(req.url.endsWith('/chat/completions'))send(404,{error:{message:'not found'}});
    else{assert.equal(body.store,false);send(200,{output:[{type:'message',content:[{type:'output_text',text:'OK'}]}]});}
  },async baseurl=>{const r=await checkEntry(entry(baseurl),options({model:'model'}));assert.equal(r.status,'usable');assert.equal(r.endpoint,'responses');});
});
test('legacy max_tokens retry only for explicit unsupported parameter', async () => {
  let calls=0;
  await fixture((req,res,body,send)=>{calls++;if(body.max_completion_tokens)send(400,{error:{message:'Unsupported parameter: max_completion_tokens'}});else{assert.equal(body.max_tokens,64);send(200,chat);}},async baseurl=>assert.equal((await checkEntry(entry(baseurl),options({model:'legacy',protocol:'chat'}))).status,'usable'));
  assert.equal(calls,2);
});
for(const [code,data,status] of [[401,{error:{message:'bad key'}},'auth_failed'],[403,{error:{message:'no access'}},'forbidden'],[429,{error:{message:'too many requests'}},'rate_limited'],[429,{error:{code:'insufficient_quota',message:'insufficient credits'}},'quota'],[503,{error:{message:'unavailable'}},'server_error']]){
  test(`classify ${status}, do not retry`,async()=>{let calls=0;await fixture((req,res,body,send)=>{calls++;send(code,data);},async baseurl=>assert.equal((await checkEntry(entry(baseurl),options({model:'x'}))).status,status));assert.equal(calls,1);});
}
test('HTML 200 is not a success',async()=>{
  await fixture((req,res)=>{res.writeHead(200);res.end('<html>landing page</html>');},async baseurl=>assert.equal((await checkEntry(entry(baseurl),options({model:'x',protocol:'chat'}))).status,'invalid_response'));
});
test('empty model reply is unverified, not success',async()=>{
  await fixture((req,res,body,send)=>send(200,{choices:[{message:{content:''}}]}),async baseurl=>assert.equal((await checkEntry(entry(baseurl),options({model:'x',protocol:'chat'}))).status,'unverified'));
});
test('public models list is not sufficient for success',async()=>{
  await fixture((req,res,body,send)=>send(200,{data:[{id:'embedding-only'}]}),async baseurl=>assert.equal((await checkEntry(entry(baseurl),options())).status,'unverified'));
});
test('redirect not followed (credentials stay at configured host)',async()=>{
  let count=0;
  await fixture((req,res)=>{count++;res.writeHead(302,{Location:'/elsewhere'});res.end();},async baseurl=>assert.equal((await checkEntry(entry(baseurl),options({model:'x'}))).status,'redirect'));assert.equal(count,1);
});
test('redact secrets echoed by gateway',async()=>{
  await fixture((req,res,body,send)=>send(401,{error:{message:'Invalid sk-test-secret-123456 Bearer abc-private'}}),async baseurl=>{const r=await checkEntry(entry(baseurl),options({model:'x'}));assert.ok(!JSON.stringify(r).includes('sk-test-secret-123456'));assert.ok(!JSON.stringify(r).includes('abc-private'));});
  assert.equal(redact('KEY-PRIVATE',['KEY-PRIVATE']),'[REDACTED]');
});
test('timeout and user cancellation are distinguished',async()=>{
  await fixture(()=>{},async baseurl=>{
    const timed=await checkEntry(entry(baseurl),options({model:'x',timeout:.03}));assert.equal(timed.status,'timeout');
    const controller=new AbortController();controller.abort();const cancelled=await checkEntry(entry(baseurl),options({model:'x',signal:controller.signal}));assert.equal(cancelled.status,'cancelled');
  });
});
test('batch respects concurrency limit',async()=>{
  let active=0,maxActive=0;const results=[];
  await fixture(async(req,res,body,send)=>{active++;maxActive=Math.max(maxActive,active);await new Promise(r=>setTimeout(r,20));active--;send(200,chat);},async baseurl=>await runBatch(Array.from({length:7},(_,i)=>({...entry(baseurl),line:i+1})),options({model:'x',concurrency:2}),r=>results.push(r)));
  assert.equal(results.length,7);assert.ok(maxActive<=2);assert.equal(maxActive,2);
});
test('server authenticates local submissions, streams sanitized results, no credentials returned',async()=>{
  const app=await createApp();await new Promise(resolve=>app.listen(0,'127.0.0.1',resolve));const origin=`http://127.0.0.1:${app.address().port}`;
  try{
    const page=await fetch(origin);assert.equal(page.status,200);const html=await page.text();assert.ok(page.headers.get('content-security-policy').includes("frame-ancestors 'none'"));
    const token=html.match(/nonce="([a-f0-9]+)"/)[1];
    assert.equal((await fetch(origin+'/api/check',{method:'POST',body:'{}'})).status,403);
    assert.equal((await fetch(origin+'/api/check',{method:'POST',headers:{Origin:'https://evil.example','X-Local-Token':token,'Content-Type':'application/json'},body:'{}'})).status,403);
    await fixture((req,res,body,send)=>send(200,chat),async baseurl=>{
      const response=await fetch(origin+'/api/check',{method:'POST',headers:{Origin:origin,'X-Local-Token':token,'Content-Type':'application/json'},body:JSON.stringify({text:`baseurl:${baseurl};apikey:sk-test-secret-123456`,model:'x',allowHttp:true})});
      assert.equal(response.status,200);const text=await response.text();assert.ok(!text.includes('sk-test-secret-123456'));const events=text.trim().split('\n').map(JSON.parse);assert.equal(events[0].type,'start');assert.equal(events[1].result.status,'usable');assert.equal(events.at(-1).type,'done');
    });
  }finally{app.closeAllConnections();await new Promise(resolve=>app.close(resolve));}
});
test('frontend JavaScript parses without syntax errors',async()=>{
  const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');const script=html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];assert.doesNotThrow(()=>new vm.Script(script));
});

test('oversized gateway response is rejected',async()=>{
  await fixture((req,res)=>{res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({message:'x'.repeat(2_100_000)}));},async baseurl=>assert.equal((await checkEntry(entry(baseurl),options({model:'x',protocol:'chat'}))).status,'invalid_response'));
});
test('disconnection stops active requests and releases batch lock',async()=>{
  const app=await createApp();await new Promise(resolve=>app.listen(0,'127.0.0.1',resolve));const origin=`http://127.0.0.1:${app.address().port}`;
  try{
    const html=await(await fetch(origin)).text(),token=html.match(/nonce="([a-f0-9]+)"/)[1];
    const headers={Origin:origin,'X-Local-Token':token,'Content-Type':'application/json'};
    await fixture(()=>{},async baseurl=>{
      const controller=new AbortController();
      const body=JSON.stringify({text:`baseurl:${baseurl};apikey:fake-test-only`,model:'x',allowHttp:true});
      const response=await fetch(origin+'/api/check',{method:'POST',headers,body,signal:controller.signal});
      const reader=response.body.getReader();await reader.read();
      const overlapping=await fetch(origin+'/api/check',{method:'POST',headers,body});assert.equal(overlapping.status,409);await overlapping.text();
      controller.abort();
      // Allow the close event to propagate, then ensure a new batch can start.
      await new Promise(resolve=>setTimeout(resolve,60));
      const after=await fetch(origin+'/api/check',{method:'POST',headers,body:JSON.stringify({text:'bad format'})});assert.equal(after.status,200);assert.match(await after.text(),/invalid_input/);
    });
  }finally{app.closeAllConnections();await new Promise(resolve=>app.close(resolve));}
});

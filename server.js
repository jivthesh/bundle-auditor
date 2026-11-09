import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { audit } from './audit.js';
import { allow, clientIp } from './limit.js';

const PORT = process.env.PORT || 3000;
const file = (p) => readFile(new URL(p, import.meta.url));
const [html, examples] = await Promise.all([file('./public/index.html'), file('./public/examples.json')]);
const json = (res, code, body) => res.writeHead(code, { 'content-type': 'application/json' }).end(JSON.stringify(body));

http
  .createServer(async (req, res) => {
    const path = new URL(req.url, 'http://x').pathname;
    if (req.method === 'GET' && path === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(html);
      return;
    }
    if (req.method === 'GET' && path === '/examples.json') {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600' }).end(examples);
      return;
    }
    if (req.method === 'POST' && path === '/api/audit') {
      let raw = '';
      for await (const c of req) {
        raw += c;
        if (raw.length > 2048) return res.writeHead(413).end();
      }
      try {
        const { url, confirmOwner } = JSON.parse(raw);
        if (confirmOwner !== true) throw new Error('Confirm you own or are authorized to scan this site');
        const gate = allow(clientIp(req));
        if (!gate.ok) return json(res, 429, { error: gate.reason });
        json(res, 200, await audit(url));
      } catch (e) {
        json(res, 400, { error: e.message });
      }
      return;
    }
    res.writeHead(404).end();
  })
  .listen(PORT, () => console.log(`http://localhost:${PORT}`));

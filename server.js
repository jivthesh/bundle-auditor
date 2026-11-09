import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { audit } from './audit.js';

const PORT = process.env.PORT || 3000;
const html = await readFile(new URL('./public/index.html', import.meta.url));

http
  .createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(html);
      return;
    }
    if (req.method === 'POST' && req.url === '/api/audit') {
      let raw = '';
      for await (const c of req) {
        raw += c;
        if (raw.length > 2048) return res.writeHead(413).end();
      }
      try {
        const { url, confirmOwner } = JSON.parse(raw);
        if (confirmOwner !== true) throw new Error('Confirm you own or are authorized to scan this site');
        const report = await audit(url);
        res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(report));
      } catch (e) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(JSON.stringify({ error: e.message }));
      }
      return;
    }
    res.writeHead(404).end();
  })
  .listen(PORT, () => console.log(`http://localhost:${PORT}`));

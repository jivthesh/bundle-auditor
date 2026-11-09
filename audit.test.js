import test from 'node:test';
import assert from 'node:assert/strict';
import { isPrivateIp, scanSecrets, audit } from './audit.js';

test('private IPs blocked, public allowed', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.1', '172.20.0.1', '169.254.169.254', '::1', '::ffff:127.0.0.1', 'fd00::1'])
    assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ['8.8.8.8', '172.32.0.1', '93.184.216.34'])
    assert.equal(isPrivateIp(ip), false, ip);
});

test('secret scanner finds keys and masks them', () => {
  const hits = scanSecrets('x="AKIAABCDEFGHIJKLMNOP"; y="AIza' + 'a'.repeat(35) + '"');
  assert.deepEqual(hits.map((h) => h.type), ['AWS access key', 'Google API key']);
  assert.ok(hits.every((h) => !h.preview.includes('ABCDEFGHIJKLMNOP')));
});

test('audit rejects localhost and non-http', async () => {
  await assert.rejects(audit('http://127.0.0.1:3000'), /Private/);
  await assert.rejects(audit('file:///etc/passwd'), /Only http/);
});

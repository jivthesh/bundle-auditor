import test from 'node:test';
import assert from 'node:assert/strict';
import { allow, clientIp, FREE_PER_DAY } from './limit.js';

test('free limit per IP per day, resets next day', () => {
  const t = Date.parse('2026-01-01T10:00:00Z');
  for (let i = 0; i < FREE_PER_DAY; i++) assert.equal(allow('1.1.1.1', t).ok, true);
  assert.equal(allow('1.1.1.1', t).ok, false);
  assert.equal(allow('2.2.2.2', t).ok, true);
  assert.equal(allow('1.1.1.1', t + 24 * 3600 * 1000).ok, true);
});

test('clientIp uses last forwarded entry only when proxy is trusted', () => {
  const req = { headers: { 'x-forwarded-for': '6.6.6.6, 9.9.9.9' }, socket: { remoteAddress: '127.0.0.1' } };
  assert.equal(clientIp(req, '1'), '9.9.9.9');
  assert.equal(clientIp(req, ''), '127.0.0.1');
});

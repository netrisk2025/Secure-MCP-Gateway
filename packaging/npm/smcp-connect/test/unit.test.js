'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { PassThrough } = require('node:stream');

const credentials = require('../lib/credentials');
const oauth = require('../lib/oauth');
const { parseArgs } = require('../lib/index');
const { Relay } = require('../lib/relay');

test('credential file round trip and Go-written form', () => {
  const goText = `# header
[gateway]
url = 'https://gw.example/mcp'
ca_file = "/tmp/ca.crt"

[client]
id = "smcp-dcr-1"

[session]
access_token = "a\\"b"
issued_at = 2026-10-16T21:00:00Z
expires_in = 900
`;
  const doc = credentials.parse(goText);
  assert.equal(doc.gateway.url, 'https://gw.example/mcp');
  assert.equal(doc.session.access_token, 'a"b');
  assert.equal(doc.session.issued_at, '2026-10-16T21:00:00Z');
  assert.equal(doc.session.expires_in, 900);
  const again = credentials.parse(credentials.format(doc));
  assert.deepEqual(again, doc);
  assert.match(credentials.format(doc), /issued_at = 2026-10-16T21:00:00Z\n/);
});

test('refuses a credential file other users can read', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'smcp-'));
  const f = path.join(dir, 'credentials.toml');
  credentials.save(f, { gateway: { url: 'https://x/mcp' }, client: {}, session: {} });
  assert.equal(fs.statSync(f).mode & 0o777, 0o600);
  fs.chmodSync(f, 0o644);
  assert.throws(() => credentials.load(f), /chmod 600/);
});

test('freshness is half the access-token lifetime', () => {
  const now = Date.parse('2026-10-16T21:00:00Z');
  const s = { access_token: 'x', issued_at: '2026-10-16T20:55:00Z', expires_in: 900 };
  assert.equal(oauth.fresh(s, now), true);
  assert.equal(oauth.fresh({ ...s, issued_at: '2026-10-16T20:50:00Z' }, now), false);
  assert.throws(() => oauth.originOf('http://gw.example/mcp'), /https/);
});

test('argument parsing', () => {
  const o = parseArgs(['login', '--url', 'https://a/mcp', '--scope=smcp:template:remote']);
  assert.equal(o.mode, 'login');
  assert.equal(o.url, 'https://a/mcp');
  assert.equal(o.scope, 'smcp:template:remote');
  assert.throws(() => parseArgs(['--bogus']), /unknown argument/);
});

test('relay answers an undeliverable request with a JSON-RPC error', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let out = '';
  output.on('data', (c) => { out += c; });
  const relay = new Relay({
    url: 'https://127.0.0.1:1/mcp', agent: undefined, input, output, log: () => {},
    tokens: { token: async () => 't', invalidate() {} },
  });
  const done = relay.run();
  input.end('{"jsonrpc":"2.0","id":7,"method":"tools/list"}\n{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
  await done;
  const lines = out.trim().split('\n');
  assert.equal(lines.length, 1);
  const msg = JSON.parse(lines[0]);
  assert.equal(msg.id, 7);
  assert.equal(msg.error.code, -32000);
});

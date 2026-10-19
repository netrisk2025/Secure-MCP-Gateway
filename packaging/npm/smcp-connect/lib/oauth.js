'use strict';
// OAuth for smcp-connect: metadata discovery (RFC 9728, RFC 8414), dynamic
// registration that waits for operator approval (RFC 7591, FR-16.5), the
// device authorization grant (RFC 8628) and refresh. Credentials are only
// ever sent to the Gateway's own origin.

const os = require('node:os');
const { getJSON, postForm, request } = require('./http');
const { save } = require('./credentials');

const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
const VERSION = require('../package.json').version;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pollScale = () => Number(process.env.SMCP_CONNECT_POLL_MS || 1000);

function originOf(mcpURL) {
  const u = new URL(mcpURL);
  if (u.protocol !== 'https:') throw new Error(`gateway url ${mcpURL} must use https`);
  return `${u.protocol}//${u.host}`;
}

async function discover(agent, mcpURL) {
  const origin = originOf(mcpURL);
  const path = new URL(mcpURL).pathname;
  const prm = await getJSON(agent, `${origin}/.well-known/oauth-protected-resource${path}`);
  const as = (prm.authorization_servers || [])[0] || '';
  if (as.replace(/\/$/, '') !== origin) throw new Error(`authorization server ${as} is not the Gateway origin ${origin}`);
  const md = await getJSON(agent, `${origin}/.well-known/oauth-authorization-server`);
  for (const e of [md.token_endpoint, md.registration_endpoint, md.device_authorization_endpoint]) {
    if (e && !e.startsWith(origin + '/')) throw new Error(`endpoint ${e} is not on the Gateway origin`);
  }
  if (!md.token_endpoint || !md.device_authorization_endpoint) {
    throw new Error('the Gateway does not offer the device authorization grant (is remote access enabled?)');
  }
  return md;
}

async function register(agent, md, creds, file, log) {
  if (!md.registration_endpoint) {
    throw new Error('no client ID in the credential file and the Gateway offers no registration endpoint; ask the operator for a pre-registered client');
  }
  const body = JSON.stringify({
    client_name: `smcp-connect (npm) on ${os.hostname()}`,
    grant_types: [DEVICE_GRANT, 'refresh_token'],
    token_endpoint_auth_method: 'none',
    software_id: 'smcp-connect',
    software_version: VERSION,
  });
  const r = await request(agent, 'POST', md.registration_endpoint, { headers: { 'Content-Type': 'application/json' }, body, timeoutMs: 30000 });
  const json = JSON.parse(r.body.toString('utf8') || '{}');
  if (r.status !== 201 || !json.client_id) throw new Error(`registration: ${json.error || r.status}: ${json.error_description || ''}`);
  creds.client.id = json.client_id;
  save(file, creds);
  log(`smcp-connect: registered as client ${json.client_id}`);
}

function storeTokens(creds, file, t) {
  creds.session = {
    id: t.session_id || '',
    access_token: t.access_token,
    refresh_token: t.refresh_token || '',
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expires_in: t.expires_in || 0,
  };
  save(file, creds);
}

async function login(agent, creds, file, { scope = '', log }) {
  const md = await discover(agent, creds.gateway.url);
  if (!creds.client.id) await register(agent, md, creds, file, log);
  let pendingShown = false;
  for (;;) {
    const da = await postForm(agent, md.device_authorization_endpoint, { scope }, creds.client.id, creds.client.secret);
    if (da.status === 401 && /pending operator approval/.test(da.json.error_description || '')) {
      if (!pendingShown) {
        log(`smcp-connect: client ${creds.client.id} is waiting for operator approval. On the Gateway host run:\n  smcpctl clients approve ${creds.client.id}`);
        pendingShown = true;
      }
      await sleep(10 * pollScale());
      continue;
    }
    if (da.status === 429) {
      await sleep(10 * pollScale());
      continue;
    }
    if (da.status !== 200) throw new Error(`device authorization: ${da.json.error}: ${da.json.error_description || ''}`);
    const d = da.json;
    log(`smcp-connect: to sign in, open ${d.verification_uri} and enter the code ${d.user_code}\n  (or open ${d.verification_uri_complete})`);
    let interval = Math.max(d.interval || 5, 5);
    for (;;) {
      await sleep(interval * pollScale());
      const t = await postForm(agent, md.token_endpoint, { grant_type: DEVICE_GRANT, device_code: d.device_code }, creds.client.id, creds.client.secret);
      if (t.status === 200) {
        storeTokens(creds, file, t.json);
        log('smcp-connect: signed in');
        return md;
      }
      const err = t.json.error;
      if (err === 'authorization_pending') continue;
      if (err === 'slow_down' || t.status === 429) {
        interval += 5;
        continue;
      }
      if (err === 'expired_token') break;
      throw new Error(`device token: ${err}: ${t.json.error_description || ''}`);
    }
    log('smcp-connect: the code expired; requesting a new one');
  }
}

async function refresh(agent, tokenEndpoint, creds, file) {
  const t = await postForm(agent, tokenEndpoint, { grant_type: 'refresh_token', refresh_token: creds.session.refresh_token }, creds.client.id, creds.client.secret);
  if (t.status !== 200) throw new Error(`refresh: ${t.json.error}: ${t.json.error_description || ''}`);
  storeTokens(creds, file, t.json);
}

function fresh(session, now = Date.now()) {
  if (!session || !session.access_token || !session.issued_at || !session.expires_in) return false;
  return now < Date.parse(session.issued_at) + (session.expires_in * 1000) / 2;
}

module.exports = { discover, login, refresh, fresh, originOf, DEVICE_GRANT };

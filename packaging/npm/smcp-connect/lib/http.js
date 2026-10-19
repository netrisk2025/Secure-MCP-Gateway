'use strict';
// Minimal HTTPS client over node:https so a private CA can be trusted
// (--ca) without dependencies. Responses are buffered up to a bound, or
// streamed when the caller asks for the response object.

const https = require('node:https');
const fs = require('node:fs');

const MAX_BODY = 16 * 1024 * 1024;

function agentFor(caFile) {
  const opts = { keepAlive: true, minVersion: 'TLSv1.2' };
  if (caFile) opts.ca = fs.readFileSync(caFile);
  return new https.Agent(opts);
}

function request(agent, method, url, { headers = {}, body, stream = false, timeoutMs = 0 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    if (u.protocol !== 'https:') {
      reject(new Error(`refusing non-https URL ${url}`));
      return;
    }
    const req = https.request(u, { method, headers, agent }, (res) => {
      if (stream) {
        resolve(res);
        return;
      }
      const chunks = [];
      let n = 0;
      res.on('data', (c) => {
        n += c.length;
        if (n > MAX_BODY) {
          req.destroy(new Error('response too large'));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    if (timeoutMs) req.setTimeout(timeoutMs, () => req.destroy(new Error('request timed out')));
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

async function getJSON(agent, url) {
  const r = await request(agent, 'GET', url, { timeoutMs: 15000 });
  if (r.status !== 200) throw new Error(`GET ${url}: HTTP ${r.status}`);
  return JSON.parse(r.body.toString('utf8'));
}

async function postForm(agent, url, form, clientId, secret) {
  const params = new URLSearchParams(form);
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (secret) headers.Authorization = 'Basic ' + Buffer.from(`${clientId}:${secret}`).toString('base64');
  else if (clientId) params.set('client_id', clientId);
  const r = await request(agent, 'POST', url, { headers, body: params.toString(), timeoutMs: 30000 });
  let json = {};
  try {
    json = JSON.parse(r.body.toString('utf8'));
  } catch {
    json = { error: 'http_error', error_description: r.body.toString('utf8').slice(0, 200) };
  }
  return { status: r.status, json };
}

module.exports = { agentFor, request, getJSON, postForm };

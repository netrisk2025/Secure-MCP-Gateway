'use strict';
// Stdio-to-Streamable-HTTP relay. Each newline-delimited JSON-RPC message
// from standard input is POSTed unchanged; Mcp-Protocol-Version comes from
// the message's _meta (2026-07-28 era) or the version initialize
// negotiated (2025-11-25 era), and Mcp-Method/Mcp-Name from the body.

const { request } = require('./http');

const META_VERSION = 'io.modelcontextprotocol/protocolVersion';
const MAX_LINE = 16 * 1024 * 1024;

class Relay {
  constructor({ url, agent, tokens, input, output, log }) {
    Object.assign(this, { url, agent, tokens, input, output, log });
    this.negotiated = '';
    this.sessionId = '';
    this.inflight = new Set();
  }

  write(text) {
    let line = String(text).trim();
    if (!line) return;
    if (/[\r\n]/.test(line)) {
      try {
        line = JSON.stringify(JSON.parse(line));
      } catch {
        line = line.replace(/[\r\n]+/g, ' ');
      }
    }
    this.output.write(line + '\n');
  }

  writeError(id, code, message) {
    if (id === undefined || id === null) return;
    this.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }));
  }

  run() {
    return new Promise((resolve) => {
      let buf = '';
      this.input.setEncoding('utf8');
      this.input.on('data', (chunk) => {
        buf += chunk;
        if (buf.length > MAX_LINE && !buf.includes('\n')) {
          this.log('smcp-connect: message longer than 16 MiB dropped');
          buf = '';
          return;
        }
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i).trim();
          buf = buf.slice(i + 1);
          if (line) this.track(this.forward(line));
        }
      });
      this.input.on('end', async () => {
        if (buf.trim()) this.track(this.forward(buf.trim()));
        while (this.inflight.size) await Promise.allSettled([...this.inflight]);
        resolve();
      });
    });
  }

  track(p) {
    this.inflight.add(p);
    p.finally(() => this.inflight.delete(p));
  }

  async forward(line) {
    let env = {};
    try {
      env = JSON.parse(line) || {};
    } catch {
      // The Gateway answers malformed input itself.
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      let status;
      try {
        status = await this.post(line, env);
      } catch (e) {
        this.log(`smcp-connect: request failed: ${e.message}`);
        this.writeError(env.id, -32000, `smcp-connect: ${e.message}`);
        return;
      }
      if (status !== 401) return;
      this.tokens.invalidate();
    }
    this.writeError(env.id, -31006, 'smcp-connect: the Gateway refused the session (HTTP 401) after a refresh; sign in again with smcp-connect login');
  }

  async post(line, env) {
    const token = await this.tokens.token();
    const params = env.params || {};
    const headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      Authorization: `Bearer ${token}`,
    };
    const meta = params._meta || {};
    const version = meta[META_VERSION] || (env.method === 'initialize' ? '' : this.negotiated);
    if (version) headers['Mcp-Protocol-Version'] = version;
    if (env.method) {
      headers['Mcp-Method'] = env.method;
      if ((env.method === 'tools/call' || env.method === 'prompts/get') && params.name) headers['Mcp-Name'] = params.name;
      if (env.method === 'resources/read' && params.uri) headers['Mcp-Name'] = params.uri;
    }
    if (this.sessionId) headers['Mcp-Session-Id'] = this.sessionId;
    const res = await request(this.agent, 'POST', this.url, { headers, body: line, stream: true });
    if (res.headers['mcp-session-id']) this.sessionId = res.headers['mcp-session-id'];
    const type = String(res.headers['content-type'] || '').split(';')[0].trim();
    if (res.statusCode === 401 || res.statusCode === 202) {
      res.resume();
      return res.statusCode;
    }
    if (type === 'text/event-stream') {
      await this.relayStream(res, env);
      return res.statusCode;
    }
    const body = await readAll(res);
    if (type === 'application/json') {
      this.noteInitialize(env, body);
      if (!body.trim()) throw new Error(`empty response (HTTP ${res.statusCode})`);
      this.write(body);
      return res.statusCode;
    }
    throw new Error(`gateway answered HTTP ${res.statusCode}: ${body.slice(0, 200).trim()}`);
  }

  noteInitialize(env, body) {
    if (env.method !== 'initialize') return;
    try {
      const v = JSON.parse(body).result.protocolVersion;
      if (v) this.negotiated = v;
    } catch {
      // not an initialize result
    }
  }

  relayStream(res, env) {
    return new Promise((resolve, reject) => {
      let buf = '';
      let data = [];
      const flush = () => {
        if (data.length) {
          const msg = data.join('\n');
          this.noteInitialize(env, msg);
          this.write(msg);
          data = [];
        }
      };
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        buf += chunk;
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i).replace(/\r$/, '');
          buf = buf.slice(i + 1);
          if (line === '') flush();
          else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
        }
      });
      res.on('end', () => {
        flush();
        resolve();
      });
      res.on('error', reject);
    });
  }
}

function readAll(res) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    res.on('error', reject);
  });
}

module.exports = { Relay };

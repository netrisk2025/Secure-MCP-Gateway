'use strict';
// smcp-connect: a stdio MCP server that relays to a Secure MCP Gateway
// Remote Access URL (SRS FR-16.9). Same behaviour and credential file as
// the Go release binary of the same name.

const credentials = require('./credentials');
const oauth = require('./oauth');
const { agentFor } = require('./http');
const { Relay } = require('./relay');

const USAGE = `usage: smcp-connect [login|logout] [--url URL] [--credentials FILE] [--ca FILE]
                    [--client-id ID] [--scope SCOPE] [-v]

  (no command)  relay standard input/output to the Gateway, signing in first if needed
  login         sign in (device code) and exit
  logout        remove the stored tokens

Environment: SMCP_URL, SMCP_CREDENTIALS, SMCP_CLIENT_SECRET (pre-registered confidential client).
`;

function parseArgs(argv) {
  const o = { mode: 'relay', url: process.env.SMCP_URL || '', credentials: credentials.defaultPath(), ca: '', clientId: '', scope: '', verbose: false };
  const args = [...argv];
  if (args[0] === 'login' || args[0] === 'logout') o.mode = args.shift();
  while (args.length) {
    const a = args.shift();
    const val = () => {
      if (!args.length) throw new Error(`${a} needs a value`);
      return args.shift();
    };
    const [flag, inline] = a.includes('=') ? a.split(/=(.*)/s) : [a, undefined];
    const v = () => (inline !== undefined ? inline : val());
    switch (flag) {
      case '--url': o.url = v(); break;
      case '--credentials': o.credentials = v(); break;
      case '--ca': o.ca = v(); break;
      case '--client-id': o.clientId = v(); break;
      case '--scope': o.scope = v(); break;
      case '-v': o.verbose = true; break;
      case '-h': case '--help': o.mode = 'help'; break;
      default: throw new Error(`unknown argument ${a}`);
    }
  }
  return o;
}

async function main(argv, { stdin = process.stdin, stdout = process.stdout, stderr = process.stderr } = {}) {
  const log = (m) => stderr.write(m + '\n');
  let o;
  try {
    o = parseArgs(argv);
  } catch (e) {
    log(`smcp-connect: ${e.message}\n${USAGE}`);
    return 2;
  }
  if (o.mode === 'help') {
    stdout.write(USAGE);
    return 0;
  }
  try {
    const creds = credentials.loadOrNew(o.credentials);
    creds.gateway = creds.gateway || {};
    creds.client = creds.client || {};
    creds.session = creds.session || {};
    if (o.mode === 'logout') {
      creds.session = {};
      credentials.save(o.credentials, creds);
      log(`smcp-connect: tokens removed from ${o.credentials}`);
      return 0;
    }
    if (o.url && creds.gateway.url && o.url !== creds.gateway.url) {
      log(`smcp-connect: ${o.credentials} is for ${creds.gateway.url}; use --credentials with another file for ${o.url}`);
      return 1;
    }
    if (o.url) creds.gateway.url = o.url;
    if (o.ca) creds.gateway.ca_file = o.ca;
    if (o.clientId) creds.client.id = o.clientId;
    if (process.env.SMCP_CLIENT_SECRET) creds.client.secret = process.env.SMCP_CLIENT_SECRET;
    if (!creds.gateway.url) {
      log('smcp-connect: --url is required on first use');
      return 2;
    }
    oauth.originOf(creds.gateway.url);
    const agent = agentFor(creds.gateway.ca_file);
    let md;
    if (o.mode === 'login' || (!creds.session.access_token && !creds.session.refresh_token)) {
      md = await oauth.login(agent, creds, o.credentials, { scope: o.scope, log });
      if (o.mode === 'login') {
        agent.destroy();
        return 0;
      }
    } else {
      md = await oauth.discover(agent, creds.gateway.url);
    }
    let pending = null;
    const tokens = {
      async token() {
        if (oauth.fresh(creds.session)) return creds.session.access_token;
        if (!pending) {
          pending = (async () => {
            if (!creds.session.refresh_token) throw new Error('no session; run smcp-connect login');
            await oauth.refresh(agent, md.token_endpoint, creds, o.credentials);
          })().finally(() => {
            pending = null;
          });
        }
        await pending;
        return creds.session.access_token;
      },
      invalidate() {
        creds.session.access_token = '';
      },
    };
    const relay = new Relay({ url: creds.gateway.url, agent, tokens, input: stdin, output: stdout, log: o.verbose ? log : () => {} });
    await relay.run();
    agent.destroy();
    return 0;
  } catch (e) {
    log(`smcp-connect: ${e.message}`);
    return 1;
  }
}

module.exports = { main, parseArgs, USAGE };

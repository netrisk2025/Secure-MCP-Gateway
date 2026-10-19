'use strict';
// CP-43 credential file: the same TOML file the Go adapters read and write.
// Only the subset the adapters use is supported: [section] headers and
// key = value lines whose values are basic strings, integers or offset
// date-times. The file must be mode 0600 (SR-2.3-2).

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function defaultPath() {
  if (process.env.SMCP_CREDENTIALS) return process.env.SMCP_CREDENTIALS;
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  return path.join(base, 'smcp', 'credentials.toml');
}

class PermissionError extends Error {}

function checkMode(file) {
  const st = fs.statSync(file);
  if (process.platform !== 'win32' && (st.mode & 0o066) !== 0) {
    throw new PermissionError(
      `${file} (mode ${(st.mode & 0o777).toString(8).padStart(4, '0')}): credential file is readable or writable by other users; run chmod 600 on it`);
  }
}

function unquote(v) {
  // TOML basic strings use JSON-compatible escapes for what we write.
  return JSON.parse(v.replace(/\\U([0-9A-Fa-f]{8})/g, (_, h) => String.fromCodePoint(parseInt(h, 16)).replace(/"/g, '\\"')));
}

function parse(text) {
  const out = {};
  let section = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const sec = /^\[([A-Za-z0-9_.-]+)\]$/.exec(line);
    if (sec) {
      section = sec[1];
      out[section] = out[section] || {};
      continue;
    }
    const kv = /^([A-Za-z0-9_-]+)\s*=\s*(.*)$/.exec(line);
    if (!kv) throw new Error(`unsupported TOML line: ${line}`);
    let v = kv[2].trim();
    if (v.startsWith('"')) v = unquote(v);
    else if (v.startsWith("'")) v = v.slice(1, -1);
    else if (/^-?\d+$/.test(v)) v = Number(v);
    else if (v === 'true' || v === 'false') v = v === 'true';
    // Offset date-times stay strings.
    const target = section ? out[section] : out;
    target[kv[1]] = v;
  }
  return out;
}

function quote(s) {
  return JSON.stringify(String(s));
}

function format(doc) {
  let s = '# Secure MCP Gateway adapter credentials (CP-43). Keep this file mode 0600.\n';
  for (const section of ['gateway', 'client', 'session']) {
    const t = doc[section] || {};
    s += `\n[${section}]\n`;
    for (const [k, v] of Object.entries(t)) {
      if (v === undefined || v === null || v === '') continue;
      if (typeof v === 'number' || typeof v === 'boolean') s += `${k} = ${v}\n`;
      else if (k === 'issued_at') s += `${k} = ${v}\n`;
      else s += `${k} = ${quote(v)}\n`;
    }
  }
  return s;
}

function load(file) {
  checkMode(file);
  return parse(fs.readFileSync(file, 'utf8'));
}

function loadOrNew(file) {
  try {
    return load(file);
  } catch (e) {
    if (e.code === 'ENOENT') return { gateway: {}, client: {}, session: {} };
    throw e;
  }
}

function save(file, doc) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = path.join(dir, `.credentials-${process.pid}-${Date.now()}`);
  fs.writeFileSync(tmp, format(doc), { mode: 0o600 });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
}

module.exports = { defaultPath, checkMode, parse, format, load, loadOrNew, save, PermissionError };

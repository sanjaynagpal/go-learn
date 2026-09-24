#!/usr/bin/env node
// inspect-jwt.mjs - decode and display the contents of a JWT (JSON Web Token).
//
// Splits the token into header, payload and signature, Base64Url-decodes the
// header and payload, pretty-prints them as JSON, and interprets the common time
// claims (exp, iat, nbf, auth_time) as readable UTC/local dates with an expiry
// status.
//
// It does NOT verify the signature. Do not trust the output for security decisions.
//
// Requires Node.js 16+ and no npm packages.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const USAGE = `Usage: node inspect-jwt.mjs [--raw] [--no-color] [TOKEN]

Decodes a JWT and prints its header, payload, a claim summary and expiry status.
The signature is NOT verified.

The token is read from, in order:
  1. the command-line arguments ("Bearer " / "Authorization: Bearer " is stripped)
  2. standard input, when it is piped
  3. the clipboard

Options:
  -r, --raw       print only the decoded header and payload JSON
      --no-color  disable coloured output (also honoured: NO_COLOR env var)
  -h, --help      show this help
`;

const CLAIM_LABELS = [
  ['iss', 'Issuer'], ['sub', 'Subject'], ['aud', 'Audience'], ['azp', 'Authorized party'],
  ['jti', 'Token ID'], ['scope', 'Scope'], ['scp', 'Scopes'], ['roles', 'Roles'],
  ['name', 'Name'], ['email', 'Email'], ['upn', 'UPN'], ['preferred_username', 'Username'],
  ['tid', 'Tenant ID'], ['oid', 'Object ID'], ['client_id', 'Client ID'], ['appid', 'App ID'],
];
const TIME_LABELS = [['iat', 'Issued at'], ['nbf', 'Not before'], ['exp', 'Expires'], ['auth_time', 'Auth time']];

// --- Options -----------------------------------------------------------------

let raw = false;
let color = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
const tokenArgs = [];
for (const a of process.argv.slice(2)) {
  if (a === '-r' || a === '--raw') raw = true;
  else if (a === '--no-color') color = false;
  else if (a === '-h' || a === '--help') { process.stdout.write(USAGE); process.exit(0); }
  else tokenArgs.push(a);
}

const paint = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const c = { cyan: paint(36), green: paint(32), yellow: paint(33), red: paint(31), dim: paint(90) };

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

// --- Getting the token -------------------------------------------------------

function readClipboard() {
  const candidates = {
    win32: [['powershell', ['-NoProfile', '-Command', 'Get-Clipboard -Raw']]],
    darwin: [['pbpaste', []]],
  }[process.platform] ?? [
    ['wl-paste', ['--no-newline']],
    ['xclip', ['-o', '-selection', 'clipboard']],
    ['xsel', ['--clipboard', '--output']],
    ['powershell.exe', ['-NoProfile', '-Command', 'Get-Clipboard -Raw']], // WSL
  ];
  for (const [cmd, args] of candidates) {
    try {
      return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    } catch {
      // tool missing or failed - try the next one
    }
  }
  return '';
}

function readToken() {
  if (tokenArgs.length > 0) return tokenArgs.join(' ');
  if (!process.stdin.isTTY) {
    const text = readFileSync(0, 'utf8');
    if (text.trim()) return text;
  }
  const text = readClipboard();
  if (!text.trim()) fail('No token supplied. Pass it as an argument, pipe it in, or copy it to the clipboard.');
  console.error(c.dim('(Token read from clipboard)'));
  return text;
}

// Strip "Bearer " / "Authorization: Bearer ", surrounding quotes and all whitespace.
function cleanToken(token) {
  return token
    .trim()
    .replace(/^(authorization:\s*)?bearer\s+/i, '')
    .trim()
    .replace(/^["']+|["']+$/g, '')
    .replace(/\s+/g, '');
}

// --- Decoding ---------------------------------------------------------------

function decodeJsonSegment(segment, name) {
  const s = segment.replace(/=+$/, '');
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) fail(`Could not decode ${name}: invalid Base64Url.`);
  let value;
  try {
    value = JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
  } catch (e) {
    fail(`Could not decode ${name}: ${e.message}`);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${name[0].toUpperCase()}${name.slice(1)} is not a JSON object.`);
  }
  return value;
}

const pretty = (obj) => JSON.stringify(obj, null, 2);

// Strings unquoted, arrays joined with ", ", anything else as compact JSON.
const display = (v) => (typeof v === 'string' ? v : Array.isArray(v) ? v.map(display).join(', ') : JSON.stringify(v));

const pad2 = (n) => String(n).padStart(2, '0');

function formatDate(d, utc) {
  const [y, mo, day, h, mi, s] = utc
    ? [d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate(), d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds()]
    : [d.getFullYear(), d.getMonth() + 1, d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()];
  return `${y}-${pad2(mo)}-${pad2(day)} ${pad2(h)}:${pad2(mi)}:${pad2(s)}`;
}

// Seconds -> "[Nd ]HH:MM:SS" (sign dropped).
function formatDuration(seconds) {
  let s = Math.abs(Math.trunc(seconds));
  const days = Math.floor(s / 86400);
  s %= 86400;
  const hms = `${pad2(Math.floor(s / 3600))}:${pad2(Math.floor((s % 3600) / 60))}:${pad2(s % 60)}`;
  return days > 0 ? `${days}d ${hms}` : hms;
}

const row = (label, value) => console.log(`${(label + ':').padEnd(18)} ${value}`);

// --- Output -----------------------------------------------------------------

function printSummary(payload) {
  for (const [key, label] of CLAIM_LABELS) {
    if (key in payload) row(label, display(payload[key]));
  }

  const times = {};
  for (const [key, label] of TIME_LABELS) {
    if (!(key in payload)) continue;
    const ts = Math.trunc(Number(payload[key]));
    const d = new Date(ts * 1000);
    if (typeof payload[key] !== 'number' || Number.isNaN(d.getTime())) {
      row(label, `${display(payload[key])} (unparseable)`);
      continue;
    }
    times[key] = ts;
    row(label, `${formatDate(d, true)} UTC  (${formatDate(d, false)} local)`);
  }

  if ('iat' in times && 'exp' in times) row('Lifetime', formatDuration(times.exp - times.iat));

  const now = Math.floor(Date.now() / 1000);
  console.log();
  if ('nbf' in times && times.nbf > now) {
    console.log(c.yellow(`STATUS: NOT YET VALID (valid in ${formatDuration(times.nbf - now)})`));
  } else if ('exp' in times && times.exp <= now) {
    console.log(c.red(`STATUS: EXPIRED (${formatDuration(now - times.exp)} ago)`));
  } else if ('exp' in times) {
    console.log(c.green(`STATUS: VALID (expires in ${formatDuration(times.exp - now)})`));
  } else {
    console.log(c.yellow("STATUS: No 'exp' claim - token does not expire."));
  }
}

const parts = cleanToken(readToken()).split('.');
if (parts.length === 5) {
  console.log(c.yellow('WARNING: Token has 5 parts - this looks like an encrypted JWE. Only the header can be decoded.'));
} else if (parts.length !== 3) {
  fail(`Invalid JWT: expected 3 dot-separated parts, found ${parts.length}.`);
}

const header = decodeJsonSegment(parts[0], 'header');
const payload = parts.length === 3 ? decodeJsonSegment(parts[1], 'payload') : null;

if (raw) {
  console.log(pretty(header));
  if (payload) console.log(pretty(payload));
  process.exit(0);
}

console.log();
console.log(c.cyan('=== HEADER ==='));
console.log(pretty(header));

if (payload) {
  console.log();
  console.log(c.cyan('=== PAYLOAD ==='));
  console.log(pretty(payload));
  console.log();
  console.log(c.cyan('=== SUMMARY ==='));
  printSummary(payload);
}

console.log();
console.log(c.cyan('=== SIGNATURE ==='));
const alg = display(header.alg ?? '');
row('Algorithm', alg);
if ('kid' in header) row('Key ID (kid)', display(header.kid));
if (alg.toLowerCase() === 'none') console.log(c.red("WARNING: alg is 'none' - token is unsigned!"));
row('Signature length', `${parts[parts.length - 1].length} chars (Base64Url)`);
console.log(c.dim('Signature NOT verified by this script.'));
console.log();

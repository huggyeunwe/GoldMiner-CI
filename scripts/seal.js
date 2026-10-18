'use strict';
// seal.js - chunked AES-256-GCM sealing for build inputs and outputs.
//
// Two modes:
//   symmetric  - shared 32-byte key (base64), used for build inputs.
//   recipient  - X25519 public key; only the holder of the matching private key can open.
//                Used for build outputs, so the build machine never holds a key that opens them.
//
// File layout:
//   "GMS1" | mode (1 byte: 1 = symmetric, 2 = recipient) | [mode 2: ephemeral public key, 32 bytes] | salt (16 bytes)
//   then chunks: u32 BE length (top bit set on the last chunk) | ciphertext | 16-byte tag
// Per-chunk nonce = 4 zero bytes | u64 BE chunk index. AAD = header | u32 BE chunk index | final flag.
// Any flipped byte, reordered or dropped chunk, or missing final chunk makes open() throw.
//
// Key strings:
//   symmetric key   "GMSS1-<base64url 32 bytes>"
//   public key      "GMSP1-<base64url x>"
//   private key     "GMSK1-<base64url d>-<base64url x>"
const fs = require('fs');
const crypto = require('crypto');

const MAGIC = Buffer.from('GMS1');
const CHUNK = 4 * 1024 * 1024;
const FINAL = 0x80000000;

const b64u = (b) => Buffer.from(b).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
const unb64u = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

function newSymmetricKey() { return 'GMSS1-' + b64u(crypto.randomBytes(32)); }

function newKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const pub = publicKey.export({ format: 'jwk' });
  const priv = privateKey.export({ format: 'jwk' });
  return { publicKey: 'GMSP1-' + pub.x, privateKey: 'GMSK1-' + priv.d + '-' + priv.x };
}

function parseSym(s) {
  const m = /^GMSS1-([A-Za-z0-9_-]{43})$/.exec(String(s).trim());
  if (!m) throw new Error('bad symmetric key');
  const k = unb64u(m[1]);
  if (k.length !== 32) throw new Error('bad symmetric key length');
  return k;
}
function parsePub(s) {
  const m = /^GMSP1-([A-Za-z0-9_-]{43})$/.exec(String(s).trim());
  if (!m) throw new Error('bad public key');
  return { x: m[1], key: crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: m[1] }, format: 'jwk' }) };
}
function parsePriv(s) {
  const m = /^GMSK1-([A-Za-z0-9_-]{43})-([A-Za-z0-9_-]{43})$/.exec(String(s).trim());
  if (!m) throw new Error('bad private key');
  return { x: m[2], key: crypto.createPrivateKey({ key: { kty: 'OKP', crv: 'X25519', d: m[1], x: m[2] }, format: 'jwk' }) };
}

function deriveSym(key, salt) {
  return Buffer.from(crypto.hkdfSync('sha256', key, salt, Buffer.from('gms1-sym'), 32));
}
function deriveX(shared, salt, ephX, recipX) {
  return Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.concat([Buffer.from('gms1-x25519'), unb64u(ephX), unb64u(recipX)]), 32));
}

function nonceOf(i) { const n = Buffer.alloc(12); n.writeBigUInt64BE(BigInt(i), 4); return n; }
function aadOf(header, i, final) { const t = Buffer.alloc(5); t.writeUInt32BE(i, 0); t[4] = final ? 1 : 0; return Buffer.concat([header, t]); }

// opts: { key: 'GMSS1-...' } or { recipient: 'GMSP1-...' }
function sealHeader(opts) {
  const salt = crypto.randomBytes(16);
  if (opts.key) {
    return { header: Buffer.concat([MAGIC, Buffer.from([1]), salt]), aesKey: deriveSym(parseSym(opts.key), salt) };
  }
  if (opts.recipient) {
    const recip = parsePub(opts.recipient);
    const eph = crypto.generateKeyPairSync('x25519');
    const ephX = eph.publicKey.export({ format: 'jwk' }).x;
    const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recip.key });
    return { header: Buffer.concat([MAGIC, Buffer.from([2]), unb64u(ephX), salt]), aesKey: deriveX(shared, salt, ephX, recip.x) };
  }
  throw new Error('seal needs key or recipient');
}

// opts: { key } or { identity: 'GMSK1-...' }; reads the header from fd/buffer reader
function openHeader(read, opts) {
  const magic = read(5);
  if (magic.length !== 5 || !magic.subarray(0, 4).equals(MAGIC)) throw new Error('not a sealed file');
  const mode = magic[4];
  if (mode === 1) {
    if (!opts.key) throw new Error('sealed with a symmetric key');
    const salt = read(16);
    if (salt.length !== 16) throw new Error('truncated header');
    return { header: Buffer.concat([magic, salt]), aesKey: deriveSym(parseSym(opts.key), salt) };
  }
  if (mode === 2) {
    if (!opts.identity) throw new Error('sealed to a recipient key');
    const ephRaw = read(32); const salt = read(16);
    if (ephRaw.length !== 32 || salt.length !== 16) throw new Error('truncated header');
    const me = parsePriv(opts.identity);
    const ephX = b64u(ephRaw);
    const ephKey = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: ephX }, format: 'jwk' });
    const shared = crypto.diffieHellman({ privateKey: me.key, publicKey: ephKey });
    return { header: Buffer.concat([magic, ephRaw, salt]), aesKey: deriveX(shared, salt, ephX, me.x) };
  }
  throw new Error('unknown seal mode');
}

function sealChunk(aesKey, header, i, plain, final) {
  const c = crypto.createCipheriv('aes-256-gcm', aesKey, nonceOf(i));
  c.setAAD(aadOf(header, i, final));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  const len = Buffer.alloc(4); len.writeUInt32BE(((ct.length + 16) | (final ? FINAL : 0)) >>> 0, 0);
  return Buffer.concat([len, ct, c.getAuthTag()]);
}
function openChunk(aesKey, header, i, body, final) {
  if (body.length < 16) throw new Error('truncated chunk');
  const d = crypto.createDecipheriv('aes-256-gcm', aesKey, nonceOf(i));
  d.setAAD(aadOf(header, i, final));
  d.setAuthTag(body.subarray(body.length - 16));
  return Buffer.concat([d.update(body.subarray(0, body.length - 16)), d.final()]);
}

function sealBuffer(plain, opts) {
  const { header, aesKey } = sealHeader(opts);
  const parts = [header];
  let i = 0;
  for (let off = 0; ; off += CHUNK, i++) {
    const end = Math.min(off + CHUNK, plain.length);
    const final = end >= plain.length;
    parts.push(sealChunk(aesKey, header, i, plain.subarray(off, end), final));
    if (final) break;
  }
  return Buffer.concat(parts);
}

function openBuffer(sealed, opts) {
  let pos = 0;
  const read = (n) => { const b = sealed.subarray(pos, pos + n); pos += b.length; return b; };
  const { header, aesKey } = openHeader(read, opts);
  const out = [];
  for (let i = 0; ; i++) {
    const lb = read(4);
    if (lb.length !== 4) throw new Error('missing final chunk');
    const word = lb.readUInt32BE(0);
    const final = (word & FINAL) !== 0;
    const len = word & ~FINAL;
    if (len < 16 || len > CHUNK + 16) throw new Error('bad chunk length');
    const body = read(len);
    if (body.length !== len) throw new Error('truncated chunk');
    out.push(openChunk(aesKey, header, i, body, final));
    if (final) { if (pos !== sealed.length) throw new Error('trailing data'); return Buffer.concat(out); }
  }
}

function sealFile(inPath, outPath, opts) {
  const { header, aesKey } = sealHeader(opts);
  const size = fs.statSync(inPath).size;
  const fin = fs.openSync(inPath, 'r');
  const fout = fs.openSync(outPath, 'w');
  try {
    fs.writeSync(fout, header);
    const buf = Buffer.alloc(CHUNK);
    let off = 0; let i = 0;
    do {
      const n = fs.readSync(fin, buf, 0, CHUNK, off);
      if (n === 0 && off < size) throw new Error('file shrank while sealing');
      off += n;
      fs.writeSync(fout, sealChunk(aesKey, header, i++, buf.subarray(0, n), off >= size));
    } while (off < size);
  } finally { fs.closeSync(fin); fs.closeSync(fout); }
}

function openFile(inPath, outPath, opts) {
  const fin = fs.openSync(inPath, 'r');
  const size = fs.fstatSync(fin).size;
  let pos = 0;
  const read = (n) => { const b = Buffer.alloc(n); const got = fs.readSync(fin, b, 0, n, pos); pos += got; return b.subarray(0, got); };
  const tmp = outPath + '.part';
  const fout = fs.openSync(tmp, 'w');
  let ok = false;
  try {
    const { header, aesKey } = openHeader(read, opts);
    for (let i = 0; ; i++) {
      const lb = read(4);
      if (lb.length !== 4) throw new Error('missing final chunk');
      const word = lb.readUInt32BE(0);
      const final = (word & FINAL) !== 0;
      const len = word & ~FINAL;
      if (len < 16 || len > CHUNK + 16) throw new Error('bad chunk length');
      const body = read(len);
      if (body.length !== len) throw new Error('truncated chunk');
      fs.writeSync(fout, openChunk(aesKey, header, i, body, final));
      if (final) { if (pos !== size) throw new Error('trailing data'); break; }
    }
    ok = true;
  } finally {
    fs.closeSync(fin); fs.closeSync(fout);
    if (ok) fs.renameSync(tmp, outPath); else fs.rmSync(tmp, { force: true });
  }
}

module.exports = { newSymmetricKey, newKeyPair, sealBuffer, openBuffer, sealFile, openFile, CHUNK };

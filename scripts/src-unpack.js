#!/usr/bin/env node
'use strict';
// src-unpack.js - rebuild a minimal git checkout from sealed git packs.
//
// Input directory holds:
//   m-<commit>.gs   sealed manifest: { v, sha, skeleton, sparse: [patterns], units: [{ name, ... }] }
//   sk-<commit>.gs  sealed pack: the commit and all of its tree objects
//   u-<name>.gs     sealed packs with file contents, one per unit
// Result: <dest> is a shallow git repository whose HEAD is exactly <commit>, with only the
// sparse paths checked out. `git status --porcelain` must come out empty.
//
// Usage: node src-unpack.js --in=<dir> --sha=<commit> --dest=<dir>   (key from GMCI_INPUT_KEY)
// Prints nothing but a short status line; all git output goes to <log> if given (--log=<file>).
const fs = require('fs');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const seal = require('./seal.js');

function main() {
  const argv = process.argv.slice(2);
  const opt = (k, d) => { const a = argv.find((x) => x.startsWith('--' + k + '=')); return a ? a.slice(k.length + 3) : d; };
  const inDir = path.resolve(opt('in', 'in'));
  const sha = opt('sha', '');
  const dest = path.resolve(opt('dest', 'src'));
  const log = opt('log', '');
  const key = process.env.GMCI_INPUT_KEY || '';
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error('bad commit id');
  if (!key) throw new Error('missing input key');
  const say = (s) => { if (log) fs.appendFileSync(log, s + '\n'); };
  const git = (args, input) => {
    const r = spawnSync('git', ['-C', dest].concat(args), { input, encoding: input === undefined ? 'utf8' : undefined, maxBuffer: 256 << 20 });
    if (log) fs.appendFileSync(log, '$ git ' + args.join(' ') + '\n' + (r.stdout || '') + (r.stderr || ''));
    if (r.status !== 0) throw new Error('git ' + args[0] + ' failed');
    return typeof r.stdout === 'string' ? r.stdout : String(r.stdout || '');
  };

  const manifest = JSON.parse(seal.openBuffer(fs.readFileSync(path.join(inDir, 'm-' + sha + '.gs')), { key }).toString('utf8'));
  if (manifest.v !== 1 || manifest.sha !== sha) throw new Error('manifest does not match commit');

  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(dest, { recursive: true });
  execFileSync('git', ['init', '-q', dest]);
  git(['config', 'core.autocrlf', 'false']);
  git(['config', 'core.sparseCheckout', 'true']);

  const names = [manifest.skeleton].concat(manifest.units.map((u) => 'u-' + u.name));
  for (const n of names) {
    const pack = seal.openBuffer(fs.readFileSync(path.join(inDir, n + '.gs')), { key });
    git(['index-pack', '--stdin', '--fix-thin'], pack);
    say('unpacked ' + n + ' (' + pack.length + ' bytes)');
  }
  // The commit's parents are not shipped: mark it shallow so git never looks for them.
  fs.writeFileSync(path.join(dest, '.git', 'shallow'), sha + '\n');
  git(['update-ref', 'refs/heads/build', sha]);
  git(['symbolic-ref', 'HEAD', 'refs/heads/build']);
  fs.mkdirSync(path.join(dest, '.git', 'info'), { recursive: true });
  fs.writeFileSync(path.join(dest, '.git', 'info', 'sparse-checkout'), manifest.sparse.join('\n') + '\n');
  git(['read-tree', '-m', '-u', 'HEAD']);

  const head = git(['rev-parse', 'HEAD']).trim();
  if (head !== sha) throw new Error('HEAD does not match');
  const dirty = git(['status', '--porcelain']).trim();
  if (dirty) throw new Error('checkout is not clean');
  console.log('source ready');
}

try { main(); } catch (e) { console.error('unpack failed: ' + e.message); process.exit(1); }

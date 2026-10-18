#!/usr/bin/env node
'use strict';
// run.js - build bootstrap.
//
// 1. Read the job id and the sealed grant from the workflow event file (never from step env, so they
//    are not echoed into the log), and open the grant with the repository secret GMCI_INPUT_KEY.
//    The grant carries the commit, the channel, the list of input files, and short-lived tokens.
// 2. Download the input files (retrying), rebuild the source checkout (src-unpack.js).
// 3. Run the build driver that ships inside that source checkout, with a clean environment and a time limit.
// 4. Stop anything the build left running, then seal the build log to the recipient key from the grant;
//    that sealed file is the only artifact.
//
// The console only ever shows fixed step names. Everything else goes to the sealed log.
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const seal = require('./seal.js');

const TEMP = process.env.RUNNER_TEMP || require('os').tmpdir();
const ROOT = path.join(TEMP, 'w');
const LOG = path.join(ROOT, 'build.log');
const OUT = path.join(TEMP, 'out');
const API = 'https://api.github.com';
// The job is cut off at 45 minutes. Everything this script starts must end by DEADLINE, which leaves
// time to stop leftovers and seal the log before that.
const DEADLINE = Date.now() + 41 * 60 * 1000;
const timeLeft = (reserve) => Math.max(60 * 1000, DEADLINE - Date.now() - reserve);
// The only words the console may use for build steps.
const STEP_WORDS = Object.assign(Object.create(null), {
  materials: 'prepare inputs', deps: 'install dependencies', guard: 'native component', pits: 'native tests',
  build: 'package', verify: 'verify package', stage: 'stage package', publish: 'upload package',
});

const say = (s) => process.stdout.write(s + '\n');
const log = (s) => { try { fs.appendFileSync(LOG, s + '\n'); } catch (e) { /* nothing else to do */ } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Children get a copy of the environment without the input key, the workflow file-command
// variables, or anything the bootstrap was given; each child gets back only what it needs.
function cleanEnv(extra) {
  const env = Object.assign({}, process.env);
  for (const k of ['GMCI_INPUT_KEY', 'GITHUB_EVENT_PATH', 'GITHUB_STEP_SUMMARY', 'GITHUB_OUTPUT', 'GITHUB_ENV', 'GITHUB_PATH', 'GITHUB_STATE']) delete env[k];
  return Object.assign(env, extra || {});
}

async function gh(token, url, accept) {
  for (let k = 0; ; k++) {
    let r = null;
    try {
      r = await fetch(url.startsWith('http') ? url : API + url, {
        headers: { Authorization: 'Bearer ' + token, Accept: accept || 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'build' },
        redirect: 'follow',
      });
    } catch (e) { r = null; }
    if (r && r.ok) return r;
    if (k >= 3 || (r && r.status < 500 && r.status !== 429)) throw new Error('request failed ' + (r ? r.status : 'network'));
    await sleep(3000 * Math.pow(2, k));
  }
}

// files: "tag/name"; returns { tag: dir } with each tag's files downloaded into its own directory
async function download(read, rawRoot) {
  const byTag = {};
  for (const f of read.files) {
    const [tag, name, extra] = f.split('/');
    if (extra !== undefined || !/^[a-z]+$/.test(tag || '') || !/^[\w-]+(\.[\w-]+)+$/.test(name || '')) throw new Error('bad input name');
    (byTag[tag] = byTag[tag] || []).push(name);
  }
  const dirs = {};
  for (const [tag, names] of Object.entries(byTag)) {
    const dir = path.join(rawRoot, tag); fs.mkdirSync(dir, { recursive: true }); dirs[tag] = dir;
    const rel = await (await gh(read.token, '/repos/' + read.repo + '/releases/tags/' + tag)).json();
    const assets = [];
    for (let page = 1; ; page++) {
      const batch = await (await gh(read.token, '/repos/' + read.repo + '/releases/' + rel.id + '/assets?per_page=100&page=' + page)).json();
      assets.push(...batch);
      if (batch.length < 100) break;
    }
    for (const n of names) {
      const a = assets.find((x) => x.name === n && x.state === 'uploaded');
      if (!a) throw new Error('missing input');
      // Retry the whole download (request, body, and length check): large files most often break mid-body.
      for (let k = 0; ; k++) {
        let buf = null;
        try {
          const r = await gh(read.token, '/repos/' + read.repo + '/releases/assets/' + a.id, 'application/octet-stream');
          buf = Buffer.from(await r.arrayBuffer());
        } catch (e) { buf = null; }
        if (buf && buf.length === a.size) { fs.writeFileSync(path.join(dir, n), buf); break; }
        if (k >= 3) throw new Error('download failed');
        await sleep(3000 * Math.pow(2, k));
      }
    }
    // Large inputs arrive split as <name>.p000, .p001, ...: join them back in order.
    const parts = {};
    for (const n of fs.readdirSync(dir)) { const m = /^(.+)\.p(\d{3})$/.exec(n); if (m) (parts[m[1]] = parts[m[1]] || []).push(n); }
    for (const [base, list] of Object.entries(parts)) {
      const fd = fs.openSync(path.join(dir, base), 'w');
      for (const p of list.sort()) { fs.writeSync(fd, fs.readFileSync(path.join(dir, p))); fs.rmSync(path.join(dir, p)); }
      fs.closeSync(fd);
    }
    log('downloaded ' + names.length + ' files from ' + tag);
  }
  return dirs;
}

function node(args, env, timeout) {
  const r = spawnSync(process.execPath, ['--no-warnings'].concat(args), { env, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, windowsHide: true, timeout });
  log('$ node ' + path.basename(args[0]) + (r.error ? ' (' + r.error.code + ')' : '') + '\n' + (r.stdout || '') + (r.stderr || ''));
  return r.status === 0;
}

// Stop anything the build left behind (processes started from the work directory, and the usual
// compiler helpers), so nothing is left for the runner to list when the job ends.
function stopLeftovers() {
  if (process.platform !== 'win32') return;
  const ps = "$root=$env:W_ROOT; if (-not $root -or $root.Length -le 3) { exit }; $names=@('mspdbsrv.exe','VBCSCompiler.exe','MSBuild.exe'); Get-CimInstance Win32_Process | Where-Object { ($_.ProcessId -ne " + process.pid + ") -and ((($_.ExecutablePath) -and $_.ExecutablePath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) -or ($names -contains $_.Name)) } | ForEach-Object { 'stop ' + $_.Name; Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }";
  const r = spawnSync('powershell', ['-NoProfile', '-Command', ps], { env: cleanEnv({ W_ROOT: ROOT }), encoding: 'utf8', windowsHide: true, timeout: 60000 });
  log('$ cleanup\n' + (r.stdout || '') + (r.stderr || ''));
}

async function main() {
  fs.mkdirSync(ROOT, { recursive: true });
  fs.mkdirSync(OUT, { recursive: true });
  const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const job = String((event.inputs && event.inputs.job) || '');
  if (!/^[0-9a-f]{16}$/.test(job)) throw new Error('bad job');
  const key = process.env.GMCI_INPUT_KEY || '';
  const sealed = Buffer.from(String((event.inputs && event.inputs.grant) || '').replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const g = JSON.parse(seal.openBuffer(sealed, { key }).toString('utf8'));
  for (const t of [g.read && g.read.token, g.store && g.store.token, g.tools && g.tools.token]) if (t) say('::add-mask::' + t);
  if (g.v !== 1 || g.job !== job) throw new Error('grant does not match job');
  if (!(Date.parse(g.exp) > Date.now())) throw new Error('grant expired');
  if (!/^[0-9a-f]{40}$/.test(g.sha) || !/^(ea|demo)$/.test(g.channel)) throw new Error('bad grant');
  const recipient = g.recipient;

  const ok = { fetch: false, unpack: false, build: false };
  let stage = 'fetch';
  try {
    const raw = path.join(ROOT, 'raw'); const plain = path.join(ROOT, 'in'); const src = path.join(ROOT, 'src');
    fs.mkdirSync(plain, { recursive: true });
    const dirs = await download(g.read, raw);
    // Source pieces (tag src) stay sealed for src-unpack.js; the seeds file stays sealed for the driver;
    // everything else is opened here.
    let seedsSealed = '';
    for (const [tag, dir] of Object.entries(dirs)) {
      if (tag === 'src') continue;
      for (const n of fs.readdirSync(dir)) {
        if (!n.endsWith('.gs')) throw new Error('unexpected input');
        if (n === 'seeds.json.gs') { seedsSealed = path.join(dir, n); continue; }
        seal.openFile(path.join(dir, n), path.join(plain, n.slice(0, -3)), { key });
      }
    }
    ok.fetch = true; say('fetch ok');
    stage = 'unpack';
    ok.unpack = !!dirs.src && node([path.join(__dirname, 'src-unpack.js'), '--in=' + dirs.src, '--sha=' + g.sha, '--dest=' + src, '--log=' + LOG],
      cleanEnv({ GMCI_INPUT_KEY: key }), Math.min(10 * 60 * 1000, timeLeft(3 * 60 * 1000)));
    say('unpack ' + (ok.unpack ? 'ok' : 'failed'));
    if (ok.unpack) {
      stage = 'build';
      const driver = path.join(src, 'infra', 'cloud-test', 'gmci', 'driver', 'build.js');
      const extra = { GMCI_INPUT_KEY: key, GMCI_STORE_TOKEN: g.store.token, GMCI_STORE_REPO: g.store.repo };
      if (g.tools) Object.assign(extra, { GMCI_TOOLS_TOKEN: g.tools.token, GMCI_TOOLS_REPO: g.tools.repo });
      if (seedsSealed) extra.GMCI_SEEDS_SEALED = seedsSealed;
      ok.build = node([driver, '--src=' + src, '--in=' + plain, '--work=' + path.join(ROOT, 'work'), '--sha=' + g.sha, '--channel=' + g.channel,
        '--log=' + LOG, '--result=' + path.join(ROOT, 'result.json')], cleanEnv(extra), timeLeft(2 * 60 * 1000));
      // Show what the build did, in neutral words only: each step name goes through a fixed list.
      try {
        const r = JSON.parse(fs.readFileSync(path.join(ROOT, 'result.json'), 'utf8'));
        for (const s of r.steps || []) say((STEP_WORDS[String(s.name)] || 'step') + ' ' + (s.ok ? 'ok' : 'failed') + ' (' + (Number(s.sec) | 0) + ' s)');
      } catch (e) { /* no result file */ }
      say('build ' + (ok.build ? 'ok' : 'failed'));
    }
  } catch (e) {
    log('bootstrap error: ' + e.message);
    say(stage + ' failed');
  } finally {
    stopLeftovers();
    let result = null;
    try { result = JSON.parse(fs.readFileSync(path.join(ROOT, 'result.json'), 'utf8')); } catch (e) { result = null; }
    let text = '';
    try { text = fs.readFileSync(LOG, 'utf8'); } catch (e) { text = ''; }
    fs.writeFileSync(path.join(OUT, 'log.gs'), seal.sealBuffer(Buffer.from(JSON.stringify({ job, ok, result, log: text })), { recipient }));
  }
  if (!ok.build) process.exitCode = 1;
}

main().catch(() => { say('setup failed'); process.exitCode = 1; });

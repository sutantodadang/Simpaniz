// Simpaniz Web Console — vanilla JS, no dependencies.
// Implements AWS SigV4 in the browser via Web Crypto so the existing S3 API
// can be reused unchanged.

(() => {
  'use strict';

  // ── State ─────────────────────────────────────────────────────────────
  const state = {
    creds: null,        // { access, secret, region, anon }
    buckets: [],
    bucket: null,
    prefix: '',         // current prefix inside the bucket (no leading slash)
  };

  const $ = (id) => document.getElementById(id);

  // ── SigV4 ─────────────────────────────────────────────────────────────
  const enc = new TextEncoder();

  async function sha256Hex(data) {
    const buf = typeof data === 'string' ? enc.encode(data) : data;
    const h = await crypto.subtle.digest('SHA-256', buf);
    return toHex(h);
  }

  function toHex(buf) {
    const b = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
  }

  async function hmac(key, msg) {
    const keyBuf = typeof key === 'string' ? enc.encode(key) : key;
    const k = await crypto.subtle.importKey(
      'raw', keyBuf, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    return await crypto.subtle.sign('HMAC', k, enc.encode(msg));
  }

  // RFC 3986 percent-encoding used by AWS canonical request.
  // `encodeSlash` controls whether `/` is escaped (false for path, true for query).
  function awsEncode(s, encodeSlash) {
    let out = '';
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      const ch = s[i];
      const unreserved =
        (c >= 0x30 && c <= 0x39) || // 0-9
        (c >= 0x41 && c <= 0x5a) || // A-Z
        (c >= 0x61 && c <= 0x7a) || // a-z
        ch === '-' || ch === '_' || ch === '.' || ch === '~';
      if (unreserved) { out += ch; continue; }
      if (ch === '/' && !encodeSlash) { out += '/'; continue; }
      // Encode as UTF-8 bytes.
      const bytes = enc.encode(ch);
      for (const b of bytes) out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
    }
    return out;
  }

  function canonicalQuery(q) {
    if (!q) return '';
    const pairs = [];
    for (const part of q.split('&')) {
      if (!part) continue;
      const eq = part.indexOf('=');
      const k = eq < 0 ? part : part.slice(0, eq);
      const v = eq < 0 ? '' : part.slice(eq + 1);
      // Decode then re-encode per AWS rules.
      const kDec = decodeURIComponent(k);
      const vDec = decodeURIComponent(v);
      pairs.push([awsEncode(kDec, true), awsEncode(vDec, true)]);
    }
    pairs.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
    return pairs.map(([k, v]) => `${k}=${v}`).join('&');
  }

  function amzDate() {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}T` +
           `${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
  }

  // Build the request URL+headers, signing if creds are present.
  // Returns { url, headers }.
  async function signedRequest({ method, path, query = '', body = null, headers = {} }) {
    const url = `${location.origin}${path}${query ? '?' + query : ''}`;

    if (state.creds.anon) {
      return { url, headers };
    }

    const now = amzDate();
    const region = state.creds.region;
    const host = location.host;
    // Always send UNSIGNED-PAYLOAD: avoids hashing potentially-huge upload
    // bodies in the browser. The server accepts this as the canonical
    // payload hash so the signature still verifies.
    const payloadHash = 'UNSIGNED-PAYLOAD';

    const allHeaders = {
      ...headers,
      'host': host,
      'x-amz-date': now,
      'x-amz-content-sha256': payloadHash,
    };

    // Canonical headers (lower-cased names, trimmed values, sorted).
    const lowered = {};
    for (const k of Object.keys(allHeaders)) lowered[k.toLowerCase()] = String(allHeaders[k]).trim();
    const sortedNames = Object.keys(lowered).sort();
    const canonHeaders = sortedNames.map(n => `${n}:${lowered[n]}\n`).join('');
    const signedHeaders = sortedNames.join(';');

    // Canonical URI: path, percent-encoded but `/` preserved.
    // Path segments must be encoded; we re-encode per-segment so existing %xx
    // sequences in `path` aren't double-encoded.
    const canonPath = '/' + path.split('/').filter(Boolean).map(seg => awsEncode(decodeURIComponent(seg), true)).join('/');
    const finalCanonPath = path === '/' ? '/' : canonPath + (path.endsWith('/') ? '/' : '');

    const canonQuery = canonicalQuery(query);

    const canonReq = [
      method, finalCanonPath, canonQuery, canonHeaders, signedHeaders, payloadHash,
    ].join('\n');

    const date = now.slice(0, 8);
    const scope = `${date}/${region}/s3/aws4_request`;
    const sts = ['AWS4-HMAC-SHA256', now, scope, await sha256Hex(canonReq)].join('\n');

    const kDate = await hmac(`AWS4${state.creds.secret}`, date);
    const kRegion = await hmac(kDate, region);
    const kService = await hmac(kRegion, 's3');
    const kSigning = await hmac(kService, 'aws4_request');
    const sig = toHex(await hmac(kSigning, sts));

    const auth =
      `AWS4-HMAC-SHA256 Credential=${state.creds.access}/${scope}, ` +
      `SignedHeaders=${signedHeaders}, Signature=${sig}`;

    // Browser disallows JS setting `host`; the rest are fine.
    const sendHeaders = { ...headers,
      'x-amz-date': now,
      'x-amz-content-sha256': payloadHash,
      'Authorization': auth,
    };
    return { url, headers: sendHeaders };
  }

  async function s3({ method, path, query = '', body = null, headers = {}, raw = false }) {
    const { url, headers: signed } = await signedRequest({ method, path, query, body, headers });
    const resp = await fetch(url, { method, headers: signed, body });
    if (!resp.ok && resp.status !== 404) {
      const text = await resp.text().catch(() => '');
      throw new Error(`${method} ${path}: HTTP ${resp.status} — ${parseS3Error(text) || resp.statusText}`);
    }
    if (raw) return resp;
    const text = await resp.text();
    return { status: resp.status, text, headers: resp.headers };
  }

  function parseS3Error(xml) {
    try {
      const doc = new DOMParser().parseFromString(xml, 'text/xml');
      const code = doc.querySelector('Code')?.textContent;
      const msg = doc.querySelector('Message')?.textContent;
      return [code, msg].filter(Boolean).join(': ');
    } catch { return ''; }
  }

  // ── S3 operations ─────────────────────────────────────────────────────
  async function listBuckets() {
    const { text } = await s3({ method: 'GET', path: '/' });
    const doc = new DOMParser().parseFromString(text, 'text/xml');
    return Array.from(doc.querySelectorAll('Bucket')).map(b => ({
      name: b.querySelector('Name')?.textContent || '',
      created: b.querySelector('CreationDate')?.textContent || '',
    }));
  }

  async function createBucket(name) {
    await s3({ method: 'PUT', path: '/' + encodeURIComponent(name) });
  }

  async function deleteBucket(name) {
    await s3({ method: 'DELETE', path: '/' + encodeURIComponent(name) });
  }

  async function listObjects(bucket, prefix) {
    const params = new URLSearchParams();
    params.set('list-type', '2');
    params.set('delimiter', '/');
    if (prefix) params.set('prefix', prefix);
    const { text } = await s3({
      method: 'GET',
      path: '/' + encodeURIComponent(bucket),
      query: params.toString(),
    });
    const doc = new DOMParser().parseFromString(text, 'text/xml');
    const objects = Array.from(doc.querySelectorAll('Contents')).map(c => ({
      key: c.querySelector('Key')?.textContent || '',
      size: parseInt(c.querySelector('Size')?.textContent || '0', 10),
      modified: c.querySelector('LastModified')?.textContent || '',
    }));
    const prefixes = Array.from(doc.querySelectorAll('CommonPrefixes > Prefix')).map(p => p.textContent || '');
    return { objects, prefixes };
  }

  function encodeKeyPath(key) {
    // Encode each segment but preserve `/`.
    return key.split('/').map(encodeURIComponent).join('/');
  }

  async function uploadObject(bucket, key, file) {
    await s3({
      method: 'PUT',
      path: '/' + encodeURIComponent(bucket) + '/' + encodeKeyPath(key),
      body: file,
      headers: { 'Content-Type': file.type || 'application/octet-stream' },
      raw: true,
    });
  }

  async function deleteObject(bucket, key) {
    await s3({
      method: 'DELETE',
      path: '/' + encodeURIComponent(bucket) + '/' + encodeKeyPath(key),
    });
  }

  async function downloadObject(bucket, key) {
    const resp = await s3({
      method: 'GET',
      path: '/' + encodeURIComponent(bucket) + '/' + encodeKeyPath(key),
      raw: true,
    });
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = key.split('/').pop();
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ── UI helpers ────────────────────────────────────────────────────────
  function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let v = n / 1024, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`;
  }

  function fmtDate(s) {
    if (!s) return '';
    const d = new Date(s);
    if (isNaN(d)) return s;
    return d.toLocaleString();
  }

  let toastTimer = 0;
  function toast(msg, kind = '') {
    const t = $('toast');
    t.textContent = msg;
    t.className = 'toast ' + kind;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.add('hidden'), 4000);
  }

  // ── Rendering ─────────────────────────────────────────────────────────
  function showLogin() {
    $('login-view').classList.remove('hidden');
    $('app-view').classList.add('hidden');
  }
  function showApp() {
    $('login-view').classList.add('hidden');
    $('app-view').classList.remove('hidden');
    $('who').textContent = state.creds.anon
      ? 'anonymous'
      : `${state.creds.access} · ${state.creds.region}`;
  }

  function renderBuckets() {
    const ul = $('bucket-list');
    ul.innerHTML = '';
    for (const b of state.buckets) {
      const li = document.createElement('li');
      li.textContent = b.name;
      if (b.name === state.bucket) li.classList.add('active');
      li.addEventListener('click', () => selectBucket(b.name));
      ul.appendChild(li);
    }
  }

  function renderCrumbs() {
    const c = $('crumbs');
    c.innerHTML = '';
    const root = document.createElement('a');
    root.textContent = state.bucket;
    root.addEventListener('click', () => navigate(''));
    c.appendChild(root);
    if (!state.prefix) return;
    const segs = state.prefix.replace(/\/$/, '').split('/');
    let acc = '';
    for (const seg of segs) {
      acc += seg + '/';
      const sep = document.createElement('span');
      sep.className = 'sep';
      sep.textContent = '/';
      c.appendChild(sep);
      const a = document.createElement('a');
      a.textContent = seg;
      const target = acc;
      a.addEventListener('click', () => navigate(target));
      c.appendChild(a);
    }
  }

  function renderObjects({ objects, prefixes }) {
    const tbody = $('object-rows');
    tbody.innerHTML = '';
    const empty = $('empty-objects');
    if (objects.length === 0 && prefixes.length === 0) {
      empty.classList.remove('hidden');
    } else {
      empty.classList.add('hidden');
    }

    // Folders first.
    for (const p of prefixes) {
      const tr = document.createElement('tr');
      const name = p.slice(state.prefix.length).replace(/\/$/, '');
      tr.innerHTML = `<td><span class="icon">📁</span><a class="name"></a></td><td class="muted">—</td><td class="muted">—</td><td></td>`;
      const a = tr.querySelector('a.name');
      a.textContent = name + '/';
      a.addEventListener('click', () => navigate(p));
      tbody.appendChild(tr);
    }
    for (const o of objects) {
      // Filter "self" entries (some servers list the prefix itself).
      if (o.key === state.prefix) continue;
      const tr = document.createElement('tr');
      const name = o.key.slice(state.prefix.length);
      tr.innerHTML = `
        <td><span class="icon">📄</span><a class="name"></a></td>
        <td>${fmtBytes(o.size)}</td>
        <td>${fmtDate(o.modified)}</td>
        <td class="actions-cell">
          <button class="link dl">Download</button>
          <button class="link del" style="color:var(--danger)">Delete</button>
        </td>`;
      const a = tr.querySelector('a.name');
      a.textContent = name;
      a.addEventListener('click', () => downloadObject(state.bucket, o.key).catch(e => toast(e.message, 'err')));
      tr.querySelector('.dl').addEventListener('click', () => downloadObject(state.bucket, o.key).catch(e => toast(e.message, 'err')));
      tr.querySelector('.del').addEventListener('click', async () => {
        if (!confirm(`Delete ${o.key}?`)) return;
        try {
          await deleteObject(state.bucket, o.key);
          toast(`Deleted ${o.key}`, 'ok');
          await refresh();
        } catch (e) { toast(e.message, 'err'); }
      });
      tbody.appendChild(tr);
    }
  }

  // ── Actions ───────────────────────────────────────────────────────────
  async function refreshBuckets() {
    try {
      state.buckets = await listBuckets();
      renderBuckets();
    } catch (e) { toast(e.message, 'err'); }
  }

  async function refresh() {
    if (!state.bucket) return;
    try {
      const data = await listObjects(state.bucket, state.prefix);
      renderObjects(data);
      renderCrumbs();
    } catch (e) { toast(e.message, 'err'); }
  }

  function navigate(prefix) {
    state.prefix = prefix;
    refresh();
  }

  async function selectBucket(name) {
    state.bucket = name;
    state.prefix = '';
    $('empty-main').classList.add('hidden');
    $('browser').classList.remove('hidden');
    renderBuckets();
    await refresh();
  }

  // ── Login flow ────────────────────────────────────────────────────────
  function loadCreds() {
    try {
      const raw = sessionStorage.getItem('simpaniz.creds');
      if (raw) return JSON.parse(raw);
    } catch {}
    return null;
  }
  function saveCreds(c) {
    sessionStorage.setItem('simpaniz.creds', JSON.stringify(c));
  }
  function clearCreds() {
    sessionStorage.removeItem('simpaniz.creds');
  }

  async function tryLogin(creds) {
    state.creds = creds;
    // Validate by listing buckets.
    state.buckets = await listBuckets();
    saveCreds(creds);
    showApp();
    renderBuckets();
  }

  // ── Wire up ───────────────────────────────────────────────────────────
  function init() {
    $('login-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      $('login-error').textContent = '';
      const anon = $('login-anon').checked;
      const creds = {
        access: $('login-access').value.trim(),
        secret: $('login-secret').value,
        region: $('login-region').value.trim() || 'us-east-1',
        anon,
      };
      if (!anon && (!creds.access || !creds.secret)) {
        $('login-error').textContent = 'Access key and secret key are required.';
        return;
      }
      try {
        await tryLogin(creds);
      } catch (err) {
        clearCreds();
        $('login-error').textContent = err.message;
      }
    });

    $('login-anon').addEventListener('change', (e) => {
      const dis = e.target.checked;
      $('login-access').disabled = dis;
      $('login-secret').disabled = dis;
    });

    $('logout').addEventListener('click', () => {
      clearCreds();
      state.creds = null; state.buckets = []; state.bucket = null; state.prefix = '';
      showLogin();
    });

    $('new-bucket').addEventListener('click', async () => {
      const name = prompt('Bucket name (lowercase, 3–63 chars, no slashes):');
      if (!name) return;
      try {
        await createBucket(name);
        toast(`Created ${name}`, 'ok');
        await refreshBuckets();
      } catch (e) { toast(e.message, 'err'); }
    });

    $('delete-bucket').addEventListener('click', async () => {
      if (!state.bucket) return;
      if (!confirm(`Delete bucket "${state.bucket}"? It must be empty.`)) return;
      try {
        await deleteBucket(state.bucket);
        toast(`Deleted ${state.bucket}`, 'ok');
        state.bucket = null; state.prefix = '';
        $('browser').classList.add('hidden');
        $('empty-main').classList.remove('hidden');
        await refreshBuckets();
      } catch (e) { toast(e.message, 'err'); }
    });

    $('upload-input').addEventListener('change', async (e) => {
      const files = Array.from(e.target.files || []);
      if (!files.length || !state.bucket) return;
      const status = $('upload-status');
      status.innerHTML = '';
      for (const f of files) {
        const row = document.createElement('div');
        row.className = 'row';
        row.textContent = `Uploading ${f.name} (${fmtBytes(f.size)})…`;
        status.appendChild(row);
        try {
          await uploadObject(state.bucket, state.prefix + f.name, f);
          row.innerHTML = `<span class="ok">✓</span> ${f.name} uploaded.`;
        } catch (err) {
          row.innerHTML = `<span class="err">✗</span> ${f.name}: ${err.message}`;
        }
      }
      e.target.value = '';
      await refresh();
    });

    // Boot.
    const saved = loadCreds();
    if (saved) {
      tryLogin(saved).catch(() => { clearCreds(); showLogin(); });
    } else {
      showLogin();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

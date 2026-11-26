import { VaultSession } from './session.js';
import { deriveRawBits, DEFAULT_KDF } from './kdf.js';
import { b64, unb64 } from './vaultCrypto.js';
import { loadEnvelope, getMeta, setMeta } from './db.js';

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; a.forEach((x) => { o.set(x, i); i += x.length; }); return o; };
const toB64Url = (u8) => b64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64Url = (s) => {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/');
  return unb64(pad + '='.repeat((4 - (pad.length % 4)) % 4));
};
const te = new TextEncoder(), td = new TextDecoder();
const root = $('#app'), fmt = (d) => (d ? new Date(d).toLocaleString('id-ID') : 'Belum pernah');
const S = new VaultSession({ onLock: () => login() });
let view = 'dash', q = '', fcat = '', shown = new Set(), last = Date.now();

function toast(m) { const t = $('#toast'); t.textContent = m; t.className = 'on'; clearTimeout(toast.t); toast.t = setTimeout(() => (t.className = ''), 2400); }
async function copy(t) { await navigator.clipboard.writeText(t); toast('Disalin — clipboard dihapus otomatis 20 dtk'); clearTimeout(copy.t); copy.t = setTimeout(() => navigator.clipboard.writeText(' ').catch(() => {}), 20000); }
function dl(name, text) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 5000); }

// ---- Secret Key (128-bit, tidak pernah disimpan di file backup) ----
const genSK = () => [...rand(16)].map((x) => x.toString(16).padStart(2, '0')).join('').toUpperCase().match(/.{4}/g).join('-');
const parseSK = (s) => { const h = (s || '').replace(/[^0-9a-f]/gi, ''); if (h.length !== 32) throw new Error('Secret Key harus 32 karakter hex'); return Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16))); };

// ---- Encode & Decode ringkas terikat situs + kunci privat vault ----
async function getVaultEncSecret() {
  if (!S.data.encSecret) {
    S.data.encSecret = b64(rand(32));
    await S.save();
  }
  return unb64(S.data.encSecret);
}

async function deriveEncodeKeys(encodePw, nonce) {
  const vaultSecret = await getVaultEncSecret();
  const domainTag = `DINO1|${window.location.origin}`;
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', cat(te.encode(`${domainTag}|`), nonce)));
  const raw = await deriveRawBits(encodePw, salt, DEFAULT_KDF, vaultSecret);
  let hkdf;
  try {
    hkdf = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
  } finally {
    raw.fill(0);
    vaultSecret.fill(0);
  }
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(domainTag) },
    hkdf,
    512
  ));
  try {
    const aesKey = await crypto.subtle.importKey('raw', bits.slice(0, 32), { name: 'AES-CTR' }, false, ['encrypt', 'decrypt']);
    const macKey = await crypto.subtle.importKey('raw', bits.slice(32, 64), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return { aesKey, macKey, domainTag };
  } finally {
    bits.fill(0);
  }
}

// ---- Generator (CSPRNG, tanpa modulo bias) ----
function randInt(n) { const lim = Math.floor(2 ** 32 / n) * n; let x; do { x = crypto.getRandomValues(new Uint32Array(1))[0]; } while (x >= lim); return x % n; }
function gen(len, o) {
  const amb = o.amb ? /[Il1O0o]/g : /$^/;
  const sets = [[o.up, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'], [o.lo, 'abcdefghijklmnopqrstuvwxyz'], [o.nu, '0123456789'], [o.sy, '!@#$%^&*()-_=+[]{};:,.?']]
    .filter((s) => s[0]).map((s) => s[1].replace(amb, ''));
  if (!sets.length) return '';
  const pool = sets.join(''), out = sets.map((s) => s[randInt(s.length)]);
  while (out.length < len) out.push(pool[randInt(pool.length)]);
  for (let i = out.length - 1; i > 0; i--) { const j = randInt(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
  return out.slice(0, len).join('');
}
const classes = (p) => [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
const level = (p) => (p.length >= 14 && classes(p) >= 3 ? 'strong' : p.length < 10 || classes(p) < 2 ? 'weak' : 'medium');
const E = () => S.data.entries;
function an() {
  const c = {}; E().forEach((e) => (c[e.password] = (c[e.password] || 0) + 1));
  const L = E().map((e) => ({ e, l: level(e.password), d: c[e.password] > 1 }));
  return { n: L.length, strong: L.filter((x) => x.l === 'strong').length, medium: L.filter((x) => x.l === 'medium').length, weak: L.filter((x) => x.l === 'weak'), dup: L.filter((x) => x.d) };
}

// ---- Layar autentikasi ----
async function login() {
  shown.clear(); try { $('#dlg').close(); } catch {}
  const env = await loadEnvelope(); if (!env) return setup();
  const saved = await getMeta('sk'), needSk = Boolean(env?.kdf?.sk && !saved);
  root.className = '';
  root.innerHTML = `<div class="auth card"><h1>DINO<span>SITIVE</span></h1><p class="mut">Brankas terkunci. Masukkan kredensial Anda.</p>
  <input id="pw" type="password" placeholder="Master Password" autocomplete="current-password">
  ${needSk ? '<input id="sk" placeholder="Secret Key (XXXX-XXXX-…)" autocomplete="off" spellcheck="false"><label class="chk"><input id="rem" type="checkbox">Ingat Secret Key di perangkat ini</label>' : ''}
  <button class="btn gold" id="go" style="width:100%">Buka Akses</button><p id="err" class="err"></p></div>`;
  const go = async () => {
    const b = $('#go'), err = $('#err'); b.disabled = true; err.textContent = 'Memverifikasi…';
    try {
      await S.unlock($('#pw').value, env?.kdf?.sk ? parseSK(needSk ? $('#sk').value : saved) : null);
      if (needSk && $('#rem').checked) await setMeta('sk', $('#sk').value);
      login.f = 0; shell();
    } catch (e) {
      login.f = (login.f || 0) + 1;
      err.textContent = e.code === 'DECRYPT_FAILED' ? 'Master Password atau Secret Key salah.' : e.message;
      await new Promise((r) => setTimeout(r, Math.min(30, 2 ** (login.f - 1)) * 1000)); b.disabled = false;
    }
  };
  $('#go').onclick = go;
  $('#pw').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !$('#go').disabled) go(); });
  if (needSk) $('#sk').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !$('#go').disabled) go(); });
  $('#pw').focus();
}

function restoreFromSetup() {
  root.className = '';
  root.innerHTML = `<div class="auth card"><h1>DINO<span>SITIVE</span></h1><p class="mut">Pulihkan data dari perangkat lain menggunakan file backup (.dvault / .pvault), Master Password, dan Secret Key lama Anda.</p>
  <input id="r_file" type="file" accept=".dvault,.pvault,.json">
  <input id="r_pw" type="password" placeholder="Master Password lama" autocomplete="current-password">
  <input id="r_sk" placeholder="Secret Key (XXXX-XXXX-…)" autocomplete="off" spellcheck="false">
  <label class="chk"><input id="r_rem" type="checkbox">Ingat Secret Key di perangkat ini</label>
  <button class="btn gold" id="r_go" style="width:100%">Pulihkan & Masuk</button>
  <button id="r_back" style="width:100%;margin-top:8px">Kembali</button>
  <p id="err" class="err"></p></div>`;
  $('#r_back').onclick = setup;
  $('#r_go').onclick = async () => {
    const b = $('#r_go'), err = $('#err');
    b.disabled = true; err.textContent = 'Memverifikasi backup…';
    try {
      const f = $('#r_file').files[0]; if (!f) throw new Error('Pilih file backup terlebih dahulu');
      let env; try { env = JSON.parse(await f.text()); } catch { throw new Error('File bukan backup DINOSITIVE yang valid'); }
      const skStr = $('#r_sk').value;
      await S.importEnvelope(env, $('#r_pw').value, env?.kdf?.sk ? parseSK(skStr) : null);
      if (env?.kdf?.sk && $('#r_rem').checked) await setMeta('sk', skStr);
      toast('Backup berhasil dipulihkan');
      shell();
    } catch (e) {
      err.textContent = e.code === 'DECRYPT_FAILED' ? 'Master Password atau Secret Key salah.' : (e.message || 'Gagal memulihkan backup');
      b.disabled = false;
    }
  };
}

function setup() {
  root.className = '';
  root.innerHTML = `<div class="auth card"><h1>DINO<span>SITIVE</span></h1><p class="mut">Buat Master Password baru (minimal 12 karakter) untuk perangkat ini. Untuk masuk dari perangkat lama, gunakan tombol Pulihkan dari Backup.</p>
  <input id="pw" type="password" placeholder="Master Password" autocomplete="new-password"><input id="pw2" type="password" placeholder="Ulangi Master Password" autocomplete="new-password">
  <button class="btn gold" id="go" style="width:100%">Lanjutkan</button>
  <button id="hasbak" style="width:100%;margin-top:8px">Sudah punya backup? Pulihkan dari file</button>
  <p id="err" class="err"></p></div>`;
  $('#hasbak').onclick = restoreFromSetup;
  $('#go').onclick = () => {
    const pw = $('#pw').value; if (pw.length < 12) return ($('#err').textContent = 'Minimal 12 karakter.');
    if (pw !== $('#pw2').value) return ($('#err').textContent = 'Konfirmasi tidak cocok.');
    const sk = genSK();
    root.innerHTML = `<div class="auth card"><h2>Simpan Secret Key Anda</h2><p class="mut">Secret Key + Master Password dibutuhkan untuk membuka data di perangkat baru maupun saat restore. Tidak disimpan di server dan tidak ada di file backup — simpan di tempat terpisah (kertas/brankas).</p>
    <div class="card"><code style="font-size:17px">${sk}</code></div><div class="acts"><button id="kit">Unduh Emergency Kit</button></div><br>
    <label class="chk"><input id="ack" type="checkbox">Saya sudah menyimpan Secret Key</label><button class="btn gold" id="ok" style="width:100%" disabled>Aktifkan Sekarang</button><p id="err" class="err"></p></div>`;
    $('#kit').onclick = () => dl('DINOSITIVE-Emergency-Kit.txt', `DINOSITIVE — Emergency Kit\nSecret Key: ${sk}\n\nSimpan terpisah dari Master Password. Jangan bagikan.\nMaster Password TIDAK tercantum di sini.\n`);
    $('#ack').onchange = (e) => ($('#ok').disabled = !e.target.checked);
    $('#ok').onclick = async () => { $('#ok').disabled = true; $('#err').textContent = 'Membuat brankas…'; try { await S.create(pw, parseSK(sk)); shell(); } catch (e) { $('#err').textContent = e.message; $('#ok').disabled = false; } };
  };
}

// ---- Shell & tampilan ----
const NAV = [['dash', 'Dashboard', '◈'], ['vault', 'Password Vault', '▤'], ['gen', 'Password Generator', '✱'], ['enc', 'Encode & Decode', '⇄'], ['sec', 'Security Center', '⛨'], ['bak', 'Backup & Restore', '⇪'], ['set', 'Settings', '☰']];
function shell() {
  root.className = 'shell';
  root.innerHTML = `<aside><div class="logo">DINO<span>SITIVE</span></div>${NAV.map(([k, l, i]) => `<button class="nv" data-a="nav" data-id="${k}" title="${l}">${i} <span class="t">${l}</span></button>`).join('')}<button class="nv" data-a="lock" title="Lock Now">🔒 <span class="t">Lock Now</span></button></aside><main id="main"></main>`;
  view = 'dash'; render();
}
const st = (l, v, c = '') => `<div class="card"><div class="mut">${l}</div><div class="big ${c}">${v}</div></div>`;
async function render() {
  if (!S.isUnlocked) return;
  document.querySelectorAll('.nv[data-id]').forEach((b) => b.classList.toggle('on', b.dataset.id === view));
  $('#main').innerHTML = await V[view](); if (view === 'gen') A.gen();
}
const card = (e) => `<div class="card"><b>${esc(e.platform)}</b> <span class="tag">${esc(e.category || 'Umum')}</span><div class="mut">${esc(e.username)}${e.url ? ' · ' + esc(e.url) : ''}</div><code>${shown.has(e.id) ? esc(e.password) : '••••••••••'}</code>
<div class="acts"><button data-a="tog" data-id="${e.id}">${shown.has(e.id) ? 'Sembunyikan' : 'Lihat'}</button><button data-a="cu" data-id="${e.id}">Salin User</button><button data-a="cp" data-id="${e.id}">Salin Password</button><button data-a="ed" data-id="${e.id}">Edit</button><button data-a="del" data-id="${e.id}">Hapus</button></div></div>`;
const listHtml = () => { const l = E().filter((e) => (!fcat || e.category === fcat) && (!q || [e.platform, e.username, e.url, e.notes].join(' ').toLowerCase().includes(q.toLowerCase()))); return l.length ? l.map(card).join('') : '<p class="mut">Tidak ada akun.</p>'; };
const V = {
  dash() { const a = an(); return `<h2>Dashboard</h2><div class="grid">${st('Total akun', a.n)}${st('Password kuat', a.strong, 'ok')}${st('Password lemah', a.weak.length, a.weak.length ? 'bad' : '')}${st('Password duplikat', a.dup.length, a.dup.length ? 'bad' : '')}${st('Status database', 'Terenkripsi', 'gt')}${st('Backup terakhir', `<span style="font-size:16px">${fmt(localStorage.getItem('lb'))}</span>`)}</div><p class="mut">AES-256-GCM · Argon2id · Secret Key aktif.</p>`; },
  vault() { const cats = [...new Set(E().map((e) => e.category).filter(Boolean))]; return `<h2>Password Vault</h2><div class="bar"><input id="q" placeholder="Cari akun…" value="${esc(q)}"><select id="cat"><option value="">Semua kategori</option>${cats.map((c) => `<option value="${esc(c)}" ${c === fcat ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select><button class="btn gold" data-a="add">+ Tambah</button></div><div id="list">${listHtml()}</div>`; },
  gen() { return `<h2>Password Generator</h2><div class="card"><label>Panjang: <b id="g_n">20</b><input id="g_len" type="range" min="8" max="64" value="20"></label>${[['up', 'Huruf besar'], ['lo', 'Huruf kecil'], ['nu', 'Angka'], ['sy', 'Simbol'], ['amb', 'Hindari karakter ambigu (Il1O0o)']].map(([k, l]) => `<label class="chk"><input id="g_${k}" type="checkbox" checked>${l}</label>`).join('')}<input id="g_out" readonly><div class="acts"><button class="btn gold" data-a="gen">Generate</button><button data-a="gcopy">Copy</button></div><p id="g_s" class="mut"></p></div>`; },
  enc() { return `<h2>Encode & Decode</h2><div class="card"><p class="mut">Format ringkas <code>DN1.</code> (AES-256-CTR + HMAC-SHA256 + Argon2id) yang terikat langsung ke <b>kunci privat akun Anda</b> dan domain <code>${esc(window.location.origin)}</code>. Kode tidak dapat didecode di situs atau akun lain, meski password encode diketahui.</p><label>Password asli (untuk Encode) atau kode <code>DN1.…</code> (untuk Decode)<textarea id="e_in" rows="2"></textarea></label><label>Password Encode<input id="e_pw" type="password" autocomplete="off" placeholder="Masukkan password untuk mengunci/membuka kode"></label><div class="acts"><button class="btn gold" data-a="enc">Encode</button><button data-a="dec">Decode</button><button data-a="ocopy">Copy hasil</button></div><label>Hasil<textarea id="e_out" rows="2" readonly></textarea></label></div>`; },
  sec() { const a = an(), li = (x) => x.map((y) => `<li>${esc(y.e.platform)} — ${esc(y.e.username)}</li>`).join('') || '<li class="mut">Tidak ada</li>';
    return `<h2>Security Center</h2><div class="grid">${st('Enkripsi', 'AES-256-GCM', 'ok')}${st('KDF', 'Argon2id', 'ok')}${st('Integritas database', 'Tag GCM valid', 'ok')}${st('Auto-lock', (S.autoLockMs / 1000) + ' dtk', 'ok')}</div><div class="card"><h3>Password lemah (${a.weak.length})</h3><ul>${li(a.weak)}</ul><h3>Password duplikat (${a.dup.length})</h3><ul>${li(a.dup)}</ul><p class="mut">Kuat: ${a.strong} · Sedang: ${a.medium}. Penilaian berdasarkan panjang dan variasi karakter. Aplikasi ini TIDAK memeriksa kebocoran di internet.</p></div>`; },
  bak() { return `<h2>Backup & Restore</h2><div class="card"><h3>Export</h3><p class="mut">File backup (.dvault) tetap terenkripsi dan berisi kunci privat Encode Anda agar kode tetap bisa dibuka di perangkat lain. Terakhir: ${fmt(localStorage.getItem('lb'))}</p><button class="btn gold" data-a="export">Unduh Backup</button></div><div class="card"><h3>Restore dari file</h3><p class="mut">Mengganti data saat ini. Butuh Master Password & Secret Key milik file tersebut.</p><input id="i_file" type="file" accept=".dvault,.pvault,.json"><input id="i_pw" type="password" placeholder="Master Password file"><input id="i_sk" placeholder="Secret Key (jika ada)"><button data-a="import">Pulihkan</button></div>`; },
  async set() { const sk = await getMeta('sk'); return `<h2>Settings</h2><div class="card"><label>Auto-lock<select id="s_al">${[[30, '30 detik'], [60, '1 menit'], [120, '2 menit'], [300, '5 menit']].map(([s, l]) => `<option value="${s}" ${s * 1000 === S.autoLockMs ? 'selected' : ''}>${l}</option>`).join('')}</select></label><button data-a="lock">Lock Now</button></div><div class="card"><h3>Secret Key di perangkat ini</h3><p class="mut">${sk ? 'Tersimpan (siapa pun yang memegang perangkat + Master Password bisa masuk).' : 'Tidak tersimpan — diminta setiap membuka aplikasi.'}</p>${sk ? '<button data-a="forget">Hapus dari perangkat</button>' : ''}</div><div class="card"><h3 class="bad">Zona bahaya</h3><button data-a="wipe">Hapus seluruh data di perangkat ini</button></div>`; },
};

// ---- Aksi ----
const A = {
  nav: (t, id) => { view = id; render(); }, lock: () => S.lock(),
  tog: (t, id) => { shown.has(id) ? shown.delete(id) : shown.add(id); $('#list').innerHTML = listHtml(); },
  cu: (t, id) => copy(E().find((e) => e.id === id).username), cp: (t, id) => copy(E().find((e) => e.id === id).password),
  add: () => form(), ed: (t, id) => form(id),
  async del(t, id) { if (!confirm('Hapus akun ini?')) return; S.data.entries = E().filter((e) => e.id !== id); await S.save(); render(); },
  fx: () => $('#dlg').close(), fshow: () => { const i = $('#f_password'); i.type = i.type === 'password' ? 'text' : 'password'; },
  fgen: () => { $('#f_password').value = gen(20, { up: 1, lo: 1, nu: 1, sy: 1, amb: 1 }); $('#f_password').type = 'text'; },
  async fsave(t, id) {
    const v = (k) => $('#f_' + k).value.trim(), pass = $('#f_password').value;
    if (!v('platform') || !pass) throw new Error('Nama platform & password wajib diisi');
    const now = new Date().toISOString(), f = { platform: v('platform'), url: v('url'), username: v('username'), password: pass, category: v('category'), notes: v('notes') };
    const e = id && E().find((x) => x.id === id);
    if (e) Object.assign(e, f, { updatedAt: now }); else E().push({ id: crypto.randomUUID(), createdAt: now, updatedAt: now, ...f });
    await S.save(); $('#dlg').close(); render();
  },
  gen() {
    const o = {}; ['up', 'lo', 'nu', 'sy', 'amb'].forEach((k) => (o[k] = $('#g_' + k).checked)); const n = +$('#g_len').value; $('#g_n').textContent = n;
    const p = gen(n, o); $('#g_out').value = p; $('#g_s').textContent = p ? 'Kekuatan: ' + { strong: 'Kuat', medium: 'Sedang', weak: 'Lemah' }[level(p)] : 'Pilih minimal satu jenis karakter';
  },
  gcopy: () => copy($('#g_out').value), ocopy: () => $('#e_out').value && copy($('#e_out').value),
  async enc() {
    const m = $('#e_in').value, pw = $('#e_pw').value;
    if (!m || !pw) throw new Error('Isi password asli dan Password Encode');
    toast('Memproses…');
    const nonce = rand(6);
    const { aesKey, macKey, domainTag } = await deriveEncodeKeys(pw, nonce);
    const ctr = cat(nonce, new Uint8Array(10));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CTR', counter: ctr, length: 64 }, aesKey, te.encode(m)));
    const fullMac = new Uint8Array(await crypto.subtle.sign('HMAC', macKey, cat(te.encode(`${domainTag}|`), nonce, ct)));
    const tag = fullMac.slice(0, 8);
    $('#e_out').value = 'DN1.' + toB64Url(cat(nonce, tag, ct));
  },
  async dec() {
    const s = $('#e_in').value.trim(), pw = $('#e_pw').value;
    if (!s.startsWith('DN1.') || !pw) throw new Error('Masukkan kode DN1.… dan Password Encode');
    toast('Memproses…');
    try {
      const b = fromB64Url(s.slice(4));
      if (b.length < 15) throw 0;
      const nonce = b.slice(0, 6), tag = b.slice(6, 14), ct = b.slice(14);
      const { aesKey, macKey, domainTag } = await deriveEncodeKeys(pw, nonce);
      const expectedMac = new Uint8Array(await crypto.subtle.sign('HMAC', macKey, cat(te.encode(`${domainTag}|`), nonce, ct)));
      let diff = 0;
      for (let i = 0; i < 8; i++) diff |= tag[i] ^ expectedMac[i];
      if (diff !== 0) throw 0;
      const ctr = cat(nonce, new Uint8Array(10));
      $('#e_out').value = td.decode(await crypto.subtle.decrypt({ name: 'AES-CTR', counter: ctr, length: 64 }, aesKey, ct));
    } catch {
      $('#e_out').value = '';
      throw new Error('Password salah, kode rusak, atau kode bukan berasal dari situs & akun ini');
    }
  },
  export() { dl(`dinositive-${new Date().toISOString().slice(0, 10)}.dvault`, JSON.stringify(S.exportEnvelope(), null, 1)); localStorage.setItem('lb', new Date().toISOString()); toast('Backup terenkripsi diunduh'); render(); },
  async import() {
    const f = $('#i_file').files[0]; if (!f) throw new Error('Pilih file backup');
    let env; try { env = JSON.parse(await f.text()); } catch { throw new Error('File bukan JSON backup DINOSITIVE yang valid'); }
    if (!confirm('Data saat ini akan DIGANTI oleh isi file backup. Lanjutkan?')) return;
    await S.importEnvelope(env, $('#i_pw').value, env?.kdf?.sk ? parseSK($('#i_sk').value) : null); await setMeta('sk', null); toast('Restore berhasil'); render();
  },
  async forget() { await setMeta('sk', null); render(); },
  async wipe() { if (prompt('Ketik HAPUS untuk menghapus semua data lokal (pastikan sudah backup)') !== 'HAPUS') return; S.lock(); indexedDB.deleteDatabase('privy-vault'); localStorage.clear(); location.reload(); },
};
function form(id) {
  const e = E().find((x) => x.id === id) || {};
  $('#dlg').innerHTML = `<h3>${id ? 'Edit' : 'Tambah'} Akun</h3>${[['platform', 'Nama platform'], ['url', 'URL website'], ['username', 'Username / email'], ['password', 'Password'], ['category', 'Kategori']].map(([k, l]) => `<label>${l}<input id="f_${k}" value="${esc(e[k])}" ${k === 'password' ? 'type="password" autocomplete="off"' : 'autocomplete="off"'}></label>`).join('')}<label>Catatan<textarea id="f_notes" rows="2">${esc(e.notes)}</textarea></label><div class="acts"><button data-a="fgen">Generate</button><button data-a="fshow">Lihat</button><button class="btn gold" data-a="fsave" data-id="${id || ''}">Simpan</button><button data-a="fx">Batal</button></div>`;
  $('#dlg').showModal();
}

document.addEventListener('click', async (ev) => { const t = ev.target.closest('[data-a]'); if (!t) return; try { await A[t.dataset.a](t, t.dataset.id); } catch (e) { toast(e.message || 'Terjadi kesalahan'); } });
document.addEventListener('input', (e) => { if (e.target.id === 'q') { q = e.target.value; $('#list').innerHTML = listHtml(); } else if (e.target.id?.startsWith('g_')) A.gen(); });
document.addEventListener('change', async (e) => {
  if (e.target.id === 'cat') { fcat = e.target.value; $('#list').innerHTML = listHtml(); }
  if (e.target.id === 's_al') { S.autoLockMs = +e.target.value * 1000; await setMeta('autolock', S.autoLockMs); S.touch(); }
});
['pointerdown', 'keydown', 'scroll'].forEach((ev) => addEventListener(ev, () => { if (S.isUnlocked) { S.touch(); last = Date.now(); } }, { passive: true }));
document.addEventListener('visibilitychange', () => { if (!document.hidden && S.isUnlocked && Date.now() - last > S.autoLockMs) S.lock(); });

function showFatal(msg) {
  if (!root || S.isUnlocked) return;
  root.className = '';
  root.innerHTML = `<div class="auth card"><h1>DINO<span>SITIVE</span></h1><p class="err">${esc(msg)}</p><button class="btn gold" onclick="location.reload()">Muat Ulang</button></div>`;
}

window.addEventListener('error', (e) => {
  if (!root.querySelector('input') && !S.isUnlocked) showFatal(e.message || 'Terjadi kesalahan saat memuat aplikasi.');
});
window.addEventListener('unhandledrejection', (e) => {
  if (!root.querySelector('input') && !S.isUnlocked) showFatal(e.reason?.message || 'Gagal menjalankan aplikasi.');
});

(async () => {
  try {
    S.autoLockMs = (await getMeta('autolock')) || 60000;
  } catch {
    S.autoLockMs = 60000;
  }
  if ('serviceWorker' in navigator) {
    const inIframe = (() => { try { return window.self !== window.top; } catch { return true; } })();
    const isViteDev = Boolean(typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.DEV);
    if (!isViteDev && !inIframe) {
      navigator.serviceWorker.register('./sw.js', { updateViaCache: 'none' })
        .then((reg) => reg.update().catch(() => {}))
        .catch(() => {});
    } else {
      navigator.serviceWorker.getRegistrations().then((regs) => regs.forEach((r) => r.unregister())).catch(() => {});
    }
  }
  try {
    await login();
  } catch (err) {
    showFatal(`Gagal memuat penyimpanan lokal (${err?.message || 'IndexedDB tidak tersedia'}). Pastikan browser mengizinkan IndexedDB / tidak dalam mode terblokir.`);
  }
})();

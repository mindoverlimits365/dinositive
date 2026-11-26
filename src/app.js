import { VaultSession } from './session.js';
import { deriveKey, DEFAULT_KDF } from './kdf.js';
import { b64, unb64 } from './vaultCrypto.js';
import { loadEnvelope, getMeta, setMeta } from './db.js';

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
const te = new TextEncoder(), td = new TextDecoder();
const root = $('#app'), fmt = (d) => (d ? new Date(d).toLocaleString('id-ID') : 'Belum pernah');
const S = new VaultSession({ onLock: () => login() });
let view = 'enc', last = Date.now();

function toast(m) { const t = $('#toast'); t.textContent = m; t.className = 'on'; clearTimeout(toast.t); toast.t = setTimeout(() => (t.className = ''), 2400); }
async function copy(t) { await navigator.clipboard.writeText(t); toast('Disalin — clipboard dihapus otomatis 20 dtk'); clearTimeout(copy.t); copy.t = setTimeout(() => navigator.clipboard.writeText(' ').catch(() => {}), 20000); }
function dl(name, text) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 5000); }

// ---- Secret Key manual 7 kata (atau kompatibel 32 hex lama) ----
const normalizeWords = (s) => String(s || '').trim().toLowerCase().split(/[\s,-]+/).filter(Boolean);
async function parseSK(s) {
  const words = normalizeWords(s);
  if (words.length === 7) {
    const hash = await crypto.subtle.digest('SHA-256', te.encode(`DINOSITIVE-SK|${words.join('-')}`));
    return new Uint8Array(hash);
  }
  const h = (s || '').replace(/[^0-9a-f]/gi, '');
  if (h.length === 32) return Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
  throw new Error('Secret Key harus 7 kata (contoh: panda-ayam-kucing-kopi-langit-laut-bulan)');
}

// ---- Token Encode 7 karakter (CSPRNG tanpa karakter ambigu) ----
const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
function randInt(n) { const lim = Math.floor(2 ** 32 / n) * n; let x; do { x = crypto.getRandomValues(new Uint32Array(1))[0]; } while (x >= lim); return x % n; }
function genShortCode(len = 7) {
  let out = '';
  for (let i = 0; i < len; i++) out += CODE_CHARS[randInt(CODE_CHARS.length)];
  return out;
}

async function ensureEncodeStore() {
  let changed = false;
  if (!S.data.encSecret) { S.data.encSecret = b64(rand(32)); changed = true; }
  if (!S.data.encodeMap || typeof S.data.encodeMap !== 'object') { S.data.encodeMap = {}; changed = true; }
  if (changed) await S.save();
}

const encodeAAD = (code) => te.encode(`DINO7|${window.location.origin}|${code}`);

// ---- Layar autentikasi ----
async function login() {
  try { $('#dlg').close(); } catch {}
  const env = await loadEnvelope(); if (!env) return setup();
  const saved = await getMeta('sk'), needSk = Boolean(env?.kdf?.sk && !saved);
  root.className = '';
  root.innerHTML = `<div class="auth card"><h1>DINO<span>SITIVE</span></h1><p class="mut">Akses terkunci. Masukkan kredensial Anda.</p>
  <label>Master Password<input id="pw" type="password" placeholder="Masukkan Master Password" autocomplete="current-password"></label>
  ${needSk ? '<label>Secret Key (7 kata)<input id="sk" placeholder="Masukkan 7 kata Secret Key" autocomplete="off" spellcheck="false"></label><label class="chk"><input id="rem" type="checkbox">Ingat Secret Key di perangkat ini</label>' : ''}
  <button class="btn gold" id="go" style="width:100%">Buka Akses</button><p id="err" class="err"></p></div>`;
  const go = async () => {
    const b = $('#go'), err = $('#err'); b.disabled = true; err.textContent = 'Memverifikasi…';
    try {
      const skBytes = env?.kdf?.sk ? await parseSK(needSk ? $('#sk').value : saved) : null;
      await S.unlock($('#pw').value, skBytes);
      if (needSk && $('#rem').checked) await setMeta('sk', normalizeWords($('#sk').value).join('-'));
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

const SK_COUNT = 7;

function setup(tab = 'in') {
  root.className = '';
  const tabs = `<div class="seg"><button type="button" id="t_in" class="${tab === 'in' ? 'on' : ''}">Masuk</button><button type="button" id="t_new" class="${tab === 'new' ? 'on' : ''}">Buat Baru</button></div>`;
  if (tab === 'in') {
    root.innerHTML = `<div class="auth card"><h1>DINO<span>SITIVE</span></h1>${tabs}
    <label>File Backup (.dvault)<input id="r_file" type="file" accept=".dvault,.pvault,.json"></label>
    <label>Master Password<input id="r_pw" type="password" placeholder="Masukkan Master Password" autocomplete="current-password"></label>
    <label>Secret Key (7 kata)<input id="r_sk" placeholder="Masukkan 7 kata Secret Key" autocomplete="off" spellcheck="false"></label>
    <label class="chk"><input id="r_rem" type="checkbox">Ingat Secret Key di perangkat ini</label>
    <button class="btn gold" id="r_go" style="width:100%">Buka Akses</button>
    <p id="err" class="err"></p></div>`;
    $('#t_new').onclick = () => setup('new');
    const doLogin = async () => {
      const b = $('#r_go'), err = $('#err');
      b.disabled = true; err.textContent = 'Memverifikasi…';
      try {
        const f = $('#r_file').files[0]; if (!f) throw new Error('Pilih file backup (.dvault) dari perangkat sebelumnya');
        let env; try { env = JSON.parse(await f.text()); } catch { throw new Error('File backup tidak valid'); }
        const skStr = $('#r_sk').value;
        const skBytes = env?.kdf?.sk ? await parseSK(skStr) : null;
        await S.importEnvelope(env, $('#r_pw').value, skBytes);
        if (env?.kdf?.sk && $('#r_rem').checked) await setMeta('sk', normalizeWords(skStr).join('-'));
        shell();
      } catch (e) {
        err.textContent = e.code === 'DECRYPT_FAILED' ? 'Master Password atau Secret Key salah.' : (e.message || 'Gagal masuk');
        b.disabled = false;
      }
    };
    $('#r_go').onclick = doLogin;
    $('#r_sk').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !$('#r_go').disabled) doLogin(); });
    return;
  }

  root.innerHTML = `<div class="auth card"><h1>DINO<span>SITIVE</span></h1>${tabs}
  <p class="mut">Buat Master Password baru (minimal 12 karakter).</p>
  <label>Master Password<input id="pw" type="password" placeholder="Minimal 12 karakter" autocomplete="new-password"></label>
  <label>Ulangi Master Password<input id="pw2" type="password" placeholder="Ketik ulang Master Password" autocomplete="new-password"></label>
  <button class="btn gold" id="go" style="width:100%">Lanjutkan</button>
  <p id="err" class="err"></p></div>`;
  $('#t_in').onclick = () => setup('in');
  $('#go').onclick = () => {
    const pw = $('#pw').value; if (pw.length < 12) return ($('#err').textContent = 'Minimal 12 karakter.');
    if (pw !== $('#pw2').value) return ($('#err').textContent = 'Konfirmasi tidak cocok.');
    root.innerHTML = `<div class="auth card"><h2>Buat 7 Kata Secret Key</h2><p class="mut">Isi manual 7 kata unik pilihan Anda. Gabungan kata ini bersama Master Password dipakai untuk membuka akses.</p>
    <div class="sk-grid">${Array.from({ length: SK_COUNT }, (_, idx) => `<div class="sk-item${idx === 6 ? ' full' : ''}"><label>Kata ${idx + 1}<input id="sk_${idx}" autocomplete="off" spellcheck="false"></label></div>`).join('')}</div>
    <div class="sk-preview"><code id="sk_prev">Isi 7 kata di atas…</code></div>
    <div style="margin-bottom:12px"><button id="kit" style="width:100%">Unduh Emergency Kit</button></div>
    <label class="chk"><input id="ack" type="checkbox">Saya sudah mencatat 7 kata Secret Key ini</label>
    <button class="btn gold" id="ok" style="width:100%" disabled>Aktifkan Sekarang</button>
    <p id="err" class="err"></p></div>`;

    const readWords = () => Array.from({ length: SK_COUNT }, (_, i) => $(`#sk_${i}`).value.trim().toLowerCase().replace(/[\s,]+/g, ''));
    const getSKString = () => {
      const w = readWords();
      return w.every(Boolean) ? w.join('-') : '';
    };
    const updatePreview = () => {
      const w = readWords();
      const filled = w.filter(Boolean);
      $('#sk_prev').textContent = filled.length ? w.map((x) => x || '…').join('-') : 'Isi 7 kata di atas…';
      $('#ok').disabled = !($('#ack').checked && w.every(Boolean));
    };

    Array.from({ length: SK_COUNT }).forEach((_, i) => {
      $(`#sk_${i}`).addEventListener('input', updatePreview);
    });
    $('#ack').onchange = updatePreview;
    $('#kit').onclick = () => {
      const sk = getSKString();
      if (!sk) return ($('#err').textContent = 'Lengkapi seluruh 7 kata Secret Key terlebih dahulu.');
      $('#err').textContent = '';
      dl('DINOSITIVE-Emergency-Kit.txt', `DINOSITIVE — Emergency Kit\nSecret Key: ${sk}\n\nSimpan terpisah dari Master Password. Jangan bagikan.\nMaster Password TIDAK tercantum di sini.\n`);
    };
    $('#ok').onclick = async () => {
      const sk = getSKString();
      if (!sk) return ($('#err').textContent = 'Lengkapi seluruh 7 kata Secret Key terlebih dahulu.');
      $('#ok').disabled = true; $('#err').textContent = 'Membuat brankas…';
      try {
        await S.create(pw, await parseSK(sk));
        shell();
      } catch (e) {
        $('#err').textContent = e.message;
        updatePreview();
      }
    };
    $('#sk_0').focus();
  };
}

// ---- Ikon SVG & navigasi ----
const ICONS = {
  enc: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 3l4 4-4 4"/><path d="M20 7H4"/><path d="M8 21l-4-4 4-4"/><path d="M4 17h16"/></svg>',
  bak: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
  set: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9c.26.6.79 1 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
};

const NAV = [
  ['enc', 'Encode & Decode', 'Encode'],
  ['bak', 'Backup', 'Backup'],
  ['set', 'Settings', 'Settings'],
];

function shell() {
  root.className = 'shell';
  root.innerHTML = `<header class="mob-bar"><div class="logo">DINO<span>SITIVE</span></div><button class="mob-lock" data-a="lock">${ICONS.lock}<span>Lock</span></button></header><aside><div class="logo">DINO<span>SITIVE</span></div>${NAV.map(([k, l, m]) => `<button class="nv" data-a="nav" data-id="${k}" title="${l}">${ICONS[k]}<span class="t">${m}</span></button>`).join('')}<button class="nv desk-lock" data-a="lock" title="Lock Now">${ICONS.lock}<span class="t">Lock Now</span></button></aside><main id="main"></main>`;
  view = 'enc'; render();
}

async function render() {
  if (!S.isUnlocked) return;
  document.querySelectorAll('.nv[data-id]').forEach((b) => b.classList.toggle('on', b.dataset.id === view));
  $('#main').innerHTML = await V[view]();
}

const V = {
  enc() {
    return `<h2>Encode & Decode</h2><div class="card"><label>Password asli / Kode 7 karakter<input id="e_in" autocomplete="off" spellcheck="false" placeholder="Masukkan password asli atau kode 7 karakter"></label><label>Password Encode<input id="e_pw" type="password" autocomplete="off" placeholder="Masukkan password pengunci"></label><div class="acts"><button class="btn gold" data-a="enc">Encode</button><button data-a="dec">Decode</button><button data-a="ocopy">Copy Hasil</button></div><label>Hasil<input id="e_out" readonly placeholder="Kode 7 karakter atau password asli"></label></div>`;
  },
  bak() {
    return `<h2>Backup</h2><div class="card"><h3>Export Backup</h3><p class="mut">Unduh file backup terenkripsi (.dvault). Terakhir: ${fmt(localStorage.getItem('lb'))}</p><button class="btn gold" style="width:100%" data-a="export">Unduh Backup</button></div>`;
  },
  async set() {
    const sk = await getMeta('sk');
    return `<h2>Settings</h2><div class="card"><label>Auto-lock<select id="s_al">${[[30, '30 detik'], [60, '1 menit'], [120, '2 menit'], [300, '5 menit']].map(([s, l]) => `<option value="${s}" ${s * 1000 === S.autoLockMs ? 'selected' : ''}>${l}</option>`).join('')}</select></label><button data-a="lock" style="width:100%">Lock Now</button></div><div class="card"><h3>Secret Key di perangkat ini</h3><p class="mut">${sk ? 'Tersimpan di perangkat ini.' : 'Tidak tersimpan — diminta setiap membuka aplikasi.'}</p>${sk ? '<button data-a="forget" style="width:100%">Hapus dari perangkat</button>' : ''}</div><div class="card"><h3 class="bad">Zona bahaya</h3><button data-a="wipe" style="width:100%">Hapus seluruh data di perangkat ini</button></div>`;
  },
};

// ---- Aksi ----
const A = {
  nav: (t, id) => { view = id; render(); },
  lock: () => S.lock(),
  ocopy: () => $('#e_out').value && copy($('#e_out').value),
  async enc() {
    const m = $('#e_in').value, pw = $('#e_pw').value;
    if (!m || !pw) throw new Error('Isi password asli dan Password Encode');
    toast('Memproses…');
    await ensureEncodeStore();
    let code = genShortCode(7);
    while (S.data.encodeMap[code]) code = genShortCode(7);
    const salt = rand(16), iv = rand(12);
    const key = await deriveKey(pw, salt, DEFAULT_KDF, unb64(S.data.encSecret));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: encodeAAD(code), tagLength: 128 },
      key,
      te.encode(m)
    ));
    S.data.encodeMap[code] = { s: b64(salt), i: b64(iv), c: b64(ct) };
    await S.save();
    $('#e_out').value = code;
    toast('Kode 7 karakter dibuat');
  },
  async dec() {
    const code = $('#e_in').value.trim(), pw = $('#e_pw').value;
    if (!code || code.length > 7 || !pw) throw new Error('Masukkan kode maksimal 7 karakter dan Password Encode');
    const rec = S.data.encodeMap?.[code];
    if (!rec || !S.data.encSecret) {
      $('#e_out').value = '';
      throw new Error('Kode tidak ditemukan di akun/situs ini');
    }
    toast('Memproses…');
    try {
      const key = await deriveKey(pw, unb64(rec.s), DEFAULT_KDF, unb64(S.data.encSecret));
      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: unb64(rec.i), additionalData: encodeAAD(code), tagLength: 128 },
        key,
        unb64(rec.c)
      );
      $('#e_out').value = td.decode(pt);
    } catch {
      $('#e_out').value = '';
      throw new Error('Password Encode salah atau kode tidak berlaku di situs ini');
    }
  },
  export() {
    dl(`dinositive-${new Date().toISOString().slice(0, 10)}.dvault`, JSON.stringify(S.exportEnvelope(), null, 1));
    localStorage.setItem('lb', new Date().toISOString());
    toast('Backup terenkripsi diunduh');
    render();
  },
  async forget() { await setMeta('sk', null); render(); },
  async wipe() {
    if (prompt('Ketik HAPUS untuk menghapus semua data lokal (pastikan sudah backup)') !== 'HAPUS') return;
    S.lock(); indexedDB.deleteDatabase('privy-vault'); localStorage.clear(); location.reload();
  },
};

document.addEventListener('click', async (ev) => { const t = ev.target.closest('[data-a]'); if (!t) return; try { await A[t.dataset.a](t, t.dataset.id); } catch (e) { toast(e.message || 'Terjadi kesalahan'); } });
document.addEventListener('change', async (e) => {
  if (e.target.id === 's_al') { S.autoLockMs = +e.target.value * 1000; await setMeta('autolock', S.autoLockMs); S.touch(); }
});
['pointerdown', 'keydown', 'scroll'].forEach((ev) => addEventListener(ev, () => { if (S.isUnlocked) { S.touch(); last = Date.now(); } }, { passive: true }));
document.addEventListener('visibilitychange', () => { if (!document.hidden && S.isUnlocked && Date.now() - last > S.autoLockMs) S.lock(); });

function showFatal(msg) {
  if (!root || S.isUnlocked) return;
  root.className = '';
  root.innerHTML = `<div class="auth card"><h1>DINO<span>SITIVE</span></h1><p class="err">${esc(msg)}</p><button class="btn gold" style="width:100%" onclick="location.reload()">Muat Ulang</button></div>`;
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

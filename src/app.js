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

// ---- Secret Key (128-bit, tidak pernah disimpan di file backup) ----
const genSK = () => [...rand(16)].map((x) => x.toString(16).padStart(2, '0')).join('').toUpperCase().match(/.{4}/g).join('-');
const parseSK = (s) => { const h = (s || '').replace(/[^0-9a-f]/gi, ''); if (h.length !== 32) throw new Error('Secret Key harus 32 karakter hex'); return Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16))); };

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
const NAV = [
  ['enc', 'Encode & Decode', '⇄'],
  ['bak', 'Backup & Restore', '⇪'],
  ['set', 'Settings', '☰'],
];

function shell() {
  root.className = 'shell';
  root.innerHTML = `<aside><div class="logo">DINO<span>SITIVE</span></div>${NAV.map(([k, l, i]) => `<button class="nv" data-a="nav" data-id="${k}" title="${l}">${i} <span class="t">${l}</span></button>`).join('')}<button class="nv" data-a="lock" title="Lock Now">🔒 <span class="t">Lock Now</span></button></aside><main id="main"></main>`;
  view = 'enc'; render();
}

async function render() {
  if (!S.isUnlocked) return;
  document.querySelectorAll('.nv[data-id]').forEach((b) => b.classList.toggle('on', b.dataset.id === view));
  $('#main').innerHTML = await V[view]();
}

const V = {
  enc() {
    const count = Object.keys(S.data.encodeMap || {}).length;
    return `<h2>Encode & Decode</h2><div class="card"><p class="mut">Menghasilkan kode pendek <b>7 karakter</b> yang terenkripsi (AES-256-GCM + Argon2id) dan terikat khusus ke akun serta domain <code>${esc(window.location.origin)}</code>. Kode tidak dapat didecode di situs atau akun lain, meskipun password encode diketahui. (${count} kode tersimpan)</p><label>Password asli (untuk Encode) atau kode 7 karakter (untuk Decode)<input id="e_in" autocomplete="off" spellcheck="false" placeholder="Masukkan password asli atau kode 7 karakter"></label><label>Password Encode<input id="e_pw" type="password" autocomplete="off" placeholder="Masukkan password pengunci"></label><div class="acts"><button class="btn gold" data-a="enc">Encode</button><button data-a="dec">Decode</button><button data-a="ocopy">Copy hasil</button></div><label>Hasil<input id="e_out" readonly placeholder="Hasil kode (7 karakter) atau password asli"></label></div>`;
  },
  bak() {
    return `<h2>Backup & Restore</h2><div class="card"><h3>Export</h3><p class="mut">File backup (.dvault) tetap terenkripsi dan menyimpan seluruh kode 7 karakter Anda agar bisa didecode di perangkat lain. Terakhir: ${fmt(localStorage.getItem('lb'))}</p><button class="btn gold" data-a="export">Unduh Backup</button></div><div class="card"><h3>Restore dari file</h3><p class="mut">Mengganti data saat ini. Butuh Master Password & Secret Key milik file tersebut.</p><input id="i_file" type="file" accept=".dvault,.pvault,.json"><input id="i_pw" type="password" placeholder="Master Password file"><input id="i_sk" placeholder="Secret Key (jika ada)"><button data-a="import">Pulihkan</button></div>`;
  },
  async set() {
    const sk = await getMeta('sk');
    return `<h2>Settings</h2><div class="card"><label>Auto-lock<select id="s_al">${[[30, '30 detik'], [60, '1 menit'], [120, '2 menit'], [300, '5 menit']].map(([s, l]) => `<option value="${s}" ${s * 1000 === S.autoLockMs ? 'selected' : ''}>${l}</option>`).join('')}</select></label><button data-a="lock">Lock Now</button></div><div class="card"><h3>Secret Key di perangkat ini</h3><p class="mut">${sk ? 'Tersimpan (siapa pun yang memegang perangkat + Master Password bisa masuk).' : 'Tidak tersimpan — diminta setiap membuka aplikasi.'}</p>${sk ? '<button data-a="forget">Hapus dari perangkat</button>' : ''}</div><div class="card"><h3 class="bad">Zona bahaya</h3><button data-a="wipe">Hapus seluruh data di perangkat ini</button></div>`;
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
    await render();
    $('#e_in').value = m;
    $('#e_pw').value = pw;
    $('#e_out').value = code;
    toast('Kode 7 karakter dibuat & disimpan terenkripsi');
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
  async import() {
    const f = $('#i_file').files[0]; if (!f) throw new Error('Pilih file backup');
    let env; try { env = JSON.parse(await f.text()); } catch { throw new Error('File bukan JSON backup DINOSITIVE yang valid'); }
    if (!confirm('Data saat ini akan DIGANTI oleh isi file backup. Lanjutkan?')) return;
    await S.importEnvelope(env, $('#i_pw').value, env?.kdf?.sk ? parseSK($('#i_sk').value) : null);
    await setMeta('sk', null);
    toast('Restore berhasil');
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

// Format envelope DINOSITIVE v1 + AES-256-GCM.
import { deriveKey, DEFAULT_KDF } from './kdf.js';

export const MAGIC = 'DINOSITIVE', VERSION = 1;
const ACCEPTED_MAGIC = new Set(['DINOSITIVE', 'PRIVYVAULT']);
const enc = new TextEncoder(), dec = new TextDecoder();
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
export const b64 = (u8) => { let s = ''; for (const b of u8) s += String.fromCharCode(b); return btoa(s); };
export const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export class VaultError extends Error {
  constructor(code, msg) { super(msg || code); this.code = code; }
}

// Seluruh header ikut diautentikasi (AAD): mengubah parameter KDF/salt/versi => dekripsi gagal.
const aad = (e) => enc.encode(JSON.stringify(
  [e.magic, e.version, e.kdf.alg, e.kdf.m, e.kdf.t, e.kdf.p, e.kdf.hashLen, e.kdf.salt, !!e.kdf.sk, e.cipher.alg]));

export function validateEnvelope(e) {
  const bad = (m) => { throw new VaultError('INVALID_FILE', m); };
  if (!e || !ACCEPTED_MAGIC.has(e.magic)) bad('Bukan file backup DINOSITIVE yang valid');
  if (e.version !== VERSION) bad('Versi format tidak didukung: ' + e.version);
  const k = e.kdf || {};
  if (k.alg !== 'argon2id') bad('KDF tidak didukung');
  // Batas atas mencegah file berbahaya menghabiskan memori perangkat.
  if (!(k.m >= 1024 && k.m <= 262144 && k.t >= 1 && k.t <= 10 && k.p >= 1 && k.p <= 4 && k.hashLen === 32)) bad('Parameter KDF tidak valid');
  if (typeof k.salt !== 'string' || unb64(k.salt).length < 16) bad('Salt tidak valid');
  if (!e.cipher || e.cipher.alg !== 'AES-256-GCM' || unb64(e.cipher.iv || '').length !== 12) bad('Parameter cipher tidak valid');
  if (typeof e.ciphertext !== 'string' || unb64(e.ciphertext).length < 16) bad('Ciphertext tidak valid');
}

export async function seal(envelope, key, data) {
  const iv = rand(12); // nonce 96-bit acak baru di SETIAP enkripsi
  const base = { ...envelope, cipher: { alg: 'AES-256-GCM', iv: b64(iv) } };
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad(base), tagLength: 128 }, key, enc.encode(JSON.stringify(data)));
  return { ...base, ciphertext: b64(new Uint8Array(ct)), updatedAt: new Date().toISOString() };
}

export async function createVault(masterPassword, secret, data = { entries: [] }, kdfParams = DEFAULT_KDF) {
  const kdf = { ...kdfParams, sk: !!secret, salt: b64(rand(32)) }; // salt unik per database
  const now = new Date().toISOString();
  const skeleton = { magic: MAGIC, version: VERSION, kdf, cipher: { alg: 'AES-256-GCM', iv: b64(rand(12)) },
    ciphertext: b64(rand(16)), createdAt: now, updatedAt: now };
  validateEnvelope(skeleton);
  const key = await deriveKey(masterPassword, unb64(kdf.salt), kdf, secret);
  return { key, envelope: await seal(skeleton, key, data) };
}

export async function unlock(envelope, masterPassword, secret) {
  validateEnvelope(envelope);
  if (!!envelope.kdf.sk !== !!secret) throw new VaultError('SECRET_KEY', envelope.kdf.sk ? 'Secret Key diperlukan' : 'Vault ini tidak memakai Secret Key');
  const key = await deriveKey(masterPassword, unb64(envelope.kdf.salt), envelope.kdf, secret);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64(envelope.cipher.iv), additionalData: aad(envelope), tagLength: 128 },
      key, unb64(envelope.ciphertext));
    return { key, data: JSON.parse(dec.decode(pt)) };
  } catch {
    // Password salah dan data dimanipulasi sengaja tidak dibedakan.
    throw new VaultError('DECRYPT_FAILED', 'Master Password salah atau data rusak/dimanipulasi');
  }
}

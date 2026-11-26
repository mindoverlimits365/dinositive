// Sesi vault di memori. Kunci tidak pernah dipersist; Lock menghapus semua referensi.
import { createVault, unlock, seal, validateEnvelope } from './vaultCrypto.js';
import { loadEnvelope, saveEnvelope } from './db.js';

export class VaultSession {
  #key = null; #data = null; #env = null; #timer = null;
  constructor({ autoLockMs = 60_000, onLock = () => {} } = {}) { this.autoLockMs = autoLockMs; this.onLock = onLock; }
  get isUnlocked() { return this.#key !== null; }
  async exists() { return !!(await loadEnvelope()); }
  async create(pw, sk, kdfParams) {
    const { key, envelope } = await createVault(pw, sk, { entries: [] }, kdfParams);
    await saveEnvelope(envelope); this.#open(key, { entries: [] }, envelope);
  }
  async unlock(pw, sk) {
    const env = await loadEnvelope(); if (!env) throw new Error('Vault belum dibuat');
    const { key, data } = await unlock(env, pw, sk); this.#open(key, data, env);
  }
  get data() { this.#need(); this.touch(); return this.#data; }
  async save() { // enkripsi ulang dengan nonce baru lalu simpan
    this.#need(); this.#env = await seal(this.#env, this.#key, this.#data); await saveEnvelope(this.#env);
  }
  exportEnvelope() { this.#need(); return structuredClone(this.#env); } // sudah terenkripsi
  async importEnvelope(env, pw, sk) { // validasi + dekripsi dulu; gagal => data lama utuh
    validateEnvelope(env); const { key, data } = await unlock(env, pw, sk);
    await saveEnvelope(env); this.#open(key, data, env);
  }
  lock() { this.#key = this.#data = this.#env = null; clearTimeout(this.#timer); this.onLock(); }
  touch() { clearTimeout(this.#timer); if (this.#key) this.#timer = setTimeout(() => this.lock(), this.autoLockMs); }
  #open(k, d, e) { this.#key = k; this.#data = d; this.#env = e; this.touch(); }
  #need() { if (!this.#key) throw new Error('Vault terkunci'); }
}

// IndexedDB: hanya menyimpan envelope TERENKRIPSI + metadata non-rahasia.
const DB = 'privy-vault', V = 1;
const open = () => new Promise((res, rej) => {
  if (typeof indexedDB === 'undefined') return rej(new Error('IndexedDB tidak didukung'));
  let done = false;
  const timer = setTimeout(() => {
    if (!done) { done = true; rej(new Error('IndexedDB timeout')); }
  }, 3000);
  const r = indexedDB.open(DB, V);
  r.onupgradeneeded = () => { r.result.createObjectStore('vault'); r.result.createObjectStore('meta'); };
  r.onsuccess = () => { if (!done) { done = true; clearTimeout(timer); res(r.result); } else { r.result.close(); } };
  r.onerror = () => { if (!done) { done = true; clearTimeout(timer); rej(r.error || new Error('Gagal membuka IndexedDB')); } };
  r.onblocked = () => { if (!done) { done = true; clearTimeout(timer); rej(new Error('IndexedDB diblokir')); } };
});
async function tx(store, mode, fn) {
  const db = await open();
  return new Promise((res, rej) => {
    const t = db.transaction(store, mode); const req = fn(t.objectStore(store));
    t.oncomplete = () => { db.close(); res(req?.result); };
    t.onerror = t.onabort = () => { try { db.close(); } catch {} rej(t.error); };
  });
}
export const loadEnvelope = () => tx('vault', 'readonly', (s) => s.get('main'));
export const saveEnvelope = (env) => tx('vault', 'readwrite', (s) => s.put(env, 'main'));
export const deleteVault = () => tx('vault', 'readwrite', (s) => s.clear());
export const getMeta = (k) => tx('meta', 'readonly', (s) => s.get(k));
export const setMeta = (k, v) => tx('meta', 'readwrite', (s) => s.put(v, k)); // mis. lastBackupAt

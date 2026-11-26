// Argon2id (hash-wasm) -> CryptoKey AES-GCM non-extractable.
// Input Argon2 = UTF8(NFKC(master)) || SecretKey(16 byte, opsional). Secret Key berukuran tetap => tidak ambigu.
import { argon2id } from 'hash-wasm';
export const DEFAULT_KDF = Object.freeze({ alg: 'argon2id', m: 65536, t: 3, p: 1, hashLen: 32 });

export async function deriveKey(masterPassword, salt, kdf, secret) {
  const pw = new TextEncoder().encode(masterPassword.normalize('NFKC'));
  const input = new Uint8Array(pw.length + (secret ? secret.length : 0));
  input.set(pw); if (secret) input.set(secret, pw.length);
  const raw = await argon2id({ password: input, salt, parallelism: kdf.p, iterations: kdf.t,
    memorySize: kdf.m, hashLength: kdf.hashLen, outputType: 'binary' });
  input.fill(0);
  try { return await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']); }
  finally { raw.fill(0); }
}

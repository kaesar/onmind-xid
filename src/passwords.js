// Passwords reales (bcrypt, formato compatible TinyAuth `$2b$`) para el segundo
// dato de xusers.txt. WebCrypto no tiene bcrypt y `Bun.password` no existe en
// Workers: bcryptjs (JS puro) es la única vía común a Bun + Workers.
// El hash incluye salt y costo; la CLI hashea al guardar (el txt nunca lleva
// claro si se usa el CLI). Legado `email:key` en claro → SHA-256 (users.js).

import bcrypt from 'bcryptjs'
import { kvIncr } from './kv.js'

export const BCRYPT_COST = 10
const PW_RATE_MAX = 10
const PW_RATE_WINDOW = 900 // s (15 min)

export function isBcryptHash(value) {
  return /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(String(value || ''))
}

export async function hashPassword(password) {
  return bcrypt.hash(String(password), BCRYPT_COST)
}

export async function verifyPassword(password, hash) {
  if (!password || typeof password !== 'string' || !hash) return false
  try {
    return await bcrypt.compare(password, hash)
  } catch {
    return false
  }
}

// Freno anti-adivinanza online (además del costo bcrypt): 10 intentos / 15 min.
export async function checkPasswordRateLimit(env, email) {
  const count = await kvIncr(env, `rl:pw:${email}`, PW_RATE_WINDOW)
  return count <= PW_RATE_MAX
}

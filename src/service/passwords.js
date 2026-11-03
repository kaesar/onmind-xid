// Real passwords (bcrypt, TinyAuth `$2b$` compatible format) for the second
// field of xusers.txt. WebCrypto has no bcrypt and `Bun.password` does not exist
// in Workers: bcryptjs (pure JS) is the only path common to Bun + Workers.
// The hash includes salt and cost; the CLI hashes on save (the txt never holds
// a clear password when the CLI is used). Legacy `email:key` in clear → SHA-256 (users.js).

import bcrypt from 'bcryptjs'
import { kvIncr } from '../store/kv.js'

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

// Online anti-guessing brake (in addition to the bcrypt cost): 10 attempts / 15 min.
export async function checkPasswordRateLimit(env, email) {
  const count = await kvIncr(env, `rl:pw:${email}`, PW_RATE_WINDOW)
  return count <= PW_RATE_MAX
}

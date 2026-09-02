import net from 'node:net'
import { constantTimeEqual, generateOtp, sha256Hex } from './util.js'
import { kvDelete, kvGet, kvPut } from './kv.js'

// OTP de 6 dígitos, un solo uso, TTL ~5 min, máx 5 intentos.
// En KV o en memoria (adapter kv.js). El código nunca viaja en el Session JWT.

const OTP_TTL = 300 // s
const MAX_ATTEMPTS = 5

const otpKey = (email) => `otp:${email}`

export async function startOtp(env, email) {
  const code = generateOtp()
  const hash = await sha256Hex(code)
  await kvPut(env, otpKey(email), { hash, attempts: 0 }, OTP_TTL)
  return { code, hash }
}

export async function clearOtp(env, email) {
  await kvDelete(env, otpKey(email))
}

// Verifica un código contra el OTP almacenado o contra el key estático del usuario.
// Devuelve true solo en acierto (un solo uso, borra el OTP) o false si falla.
export async function verifyOtp(env, email, code, user) {
  if (!code || typeof code !== 'string') return false

  // Key estático dev: hash en tiempo constante, sin gastar OTP ni intentos.
  if (user?.otpKeyHash) {
    const keyHash = await sha256Hex(code.trim())
    if (constantTimeEqual(keyHash, user.otpKeyHash)) return true
  }

  const record = await kvGet(env, otpKey(email))
  if (!record) return false
  if (record.attempts >= MAX_ATTEMPTS) return false

  const codeHash = await sha256Hex(code.trim())
  if (!constantTimeEqual(codeHash, record.hash)) {
    record.attempts += 1
    await kvPut(env, otpKey(email), record, OTP_TTL)
    return false
  }

  await clearOtp(env, email)
  return true
}

export async function otpAttemptsLeft(env, email) {
  const record = await kvGet(env, otpKey(email))
  if (!record) return MAX_ATTEMPTS
  return Math.max(0, MAX_ATTEMPTS - (record.attempts || 0))
}
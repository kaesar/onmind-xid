import { constantTimeEqual, generateOtp, sha256Hex } from '../util/common.js'
import { kvDelete, kvGet, kvPut } from '../store/kv.js'

// 6-digit OTP, single use, TTL ~5 min, max 5 attempts.
// In KV or memory (kv.js adapter). The code never travels in the Session JWT.

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

// Verifies a code against the stored OTP or the user's static key.
// Returns true only on success (single use, clears the OTP) or false on failure.
export async function verifyOtp(env, email, code, user) {
  if (!code || typeof code !== 'string') return false

  // Dev static key: constant-time hash, without consuming OTP or attempts.
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
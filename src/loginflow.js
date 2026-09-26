// Login flow shared by the Cognito and Entra facades.
// Common orchestration (lookup → OTP session → password/legacy/OTP+mail branch,
// session + password/code verification). Each facade maps the `reason`s to its
// own format (Cognito JSON vs Entra HTML forms).
//
// beginLogin passwordRequested:
//   true      → password only, no mail (password_disabled error if no hash)
//   false     → OTP with mail, unless legacy (static key, no mail)
//   undefined → auto: password si hay hash, legacy si hay key, OTP resto
// Note: legacy + passwordRequested=false sends no mail (the static key is enough).
// If mail sending fails (no SES/SMTP in prod, e.g. Lambda) →
// reason 'mail_unavailable' with passwordEnabled (whether the user has a hash).

import { getUser } from './users.js'
import { issueOtpSession, verifyOtpSession } from './session.js'
import { startOtp, verifyOtp, otpAttemptsLeft, clearOtp } from './otp.js'
import { verifyPassword, checkPasswordRateLimit } from './passwords.js'
import { sendMail, makeOtpMessage } from './mail.js'
import { normalizeEmail, sleep } from './util.js'

const hasSecret = (v) => v !== undefined && v !== null && v !== ''

// Step 1: resolve user, issue otp_session and (only in otp mode) generate and
// send the code by mail. Never sends mail in password or legacy mode.
export async function beginLogin(env, rawEmail, { passwordRequested, lang = 'en' } = {}) {
  const email = normalizeEmail(rawEmail)
  if (!email) return { ok: false, reason: 'invalid_email' }

  const user = await getUser(env, email)
  await sleep(180 + Math.floor(Math.random() * 220))
  if (!user) return { ok: false, reason: 'unknown_user' }

  const legacy = !!user.otpKeyHash && !user.passwordHash
  if (passwordRequested === true) {
    if (!user.passwordHash) return { ok: false, reason: 'password_disabled' }
    const session = await issueOtpSession(env, email)
    return { ok: true, email, user, session, mode: 'password' }
  }
  if (passwordRequested === undefined && user.passwordHash) {
    const session = await issueOtpSession(env, email)
    return { ok: true, email, user, session, mode: 'password' }
  }
  const session = await issueOtpSession(env, email)
  if (legacy) return { ok: true, email, user, session, mode: 'legacy' }
  const { code } = await startOtp(env, email)
  const msg = makeOtpMessage(code, email, lang)
  try {
    await sendMail(env, { to: email, subject: msg.subject, text: msg.text, code: msg.code })
  } catch {
    await clearOtp(env, email)
    return { ok: false, reason: 'mail_unavailable', email, passwordEnabled: !!user.passwordHash }
  }
  return { ok: true, email, user, session, mode: 'otp' }
}

// Step 2: verify the session and the password (bcrypt) or the OTP code.
export async function finishLogin(env, { email, session, code = '', password = '' } = {}) {
  const emailN = normalizeEmail(email)
  const user = await getUser(env, emailN)
  if (!user) return { ok: false, reason: 'unknown_user' }

  const payload = await verifyOtpSession(env, session)
  if (!payload || payload.sub !== emailN) return { ok: false, reason: 'bad_session' }

  if (hasSecret(password)) {
    if (!user.passwordHash) return { ok: false, reason: 'password_disabled' }
    if (!(await checkPasswordRateLimit(env, emailN))) return { ok: false, reason: 'password_locked' }
    if (!(await verifyPassword(password, user.passwordHash))) return { ok: false, reason: 'bad_password' }
    return { ok: true, email: emailN, user, via: 'password' }
  }

  const ok = await verifyOtp(env, emailN, code, user)
  if (!ok) {
    const attemptsLeft = await otpAttemptsLeft(env, emailN)
    return { ok: false, reason: 'bad_code', attemptsLeft }
  }
  return { ok: true, email: emailN, user, via: 'otp' }
}

export { hasSecret }

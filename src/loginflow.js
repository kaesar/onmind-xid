// Flujo de login compartido por las fachadas Cognito y Entra.
// Orquestación común (lookup → sesión OTP → rama password/legacy/OTP+mail,
// verificación de sesión + password/código). Cada fachada mapea los `reason`
// a su propio formato (JSON Cognito vs formularios HTML Entra).
//
// beginLogin passwordRequested:
//   true      → solo password, sin mail (error password_disabled si no hay hash)
//   false     → OTP con mail, salvo legacy (key estático, sin mail)
//   undefined → auto: password si hay hash, legacy si hay key, OTP resto
// Nota: legacy + passwordRequested=false no envía mail (la key estática basta).

import { getUser } from './users.js'
import { issueOtpSession, verifyOtpSession } from './session.js'
import { startOtp, verifyOtp, otpAttemptsLeft } from './otp.js'
import { verifyPassword, checkPasswordRateLimit } from './passwords.js'
import { sendMail, makeOtpMessage } from './mail.js'
import { normalizeEmail, sleep } from './util.js'

const hasSecret = (v) => v !== undefined && v !== null && v !== ''

// Paso 1: resuelve usuario, emite otp_session y (solo en modo otp) genera y
// envía el código por mail. Nunca envía mail en modo password o legacy.
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
  await sendMail(env, { to: email, subject: msg.subject, text: msg.text, code: msg.code })
  return { ok: true, email, user, session, mode: 'otp' }
}

// Paso 2: verifica la sesión y el password (bcrypt) o el código OTP.
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

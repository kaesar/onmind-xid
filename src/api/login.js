// Generic HTML login page (OTP / bcrypt password) for the Cognito facade.
// It is the default target of forward-auth and keeps the browser-side flow
// self-contained: no app page is required. Sets the same `xid_session` cookie
// as the JSON API, then redirects to `next` (or `/`).
//
// GET  /login?next=/path          → email form (or redirect if already signed in)
// POST /login                     → start login: OTP code form or password form
// POST /login (code|password)     → verify, set the cookie, redirect to next

import { issueTokens, verifyAccessToken } from '../auth/session.js'
import { beginLogin, finishLogin, checkLoginRateLimit } from '../auth/loginflow.js'
import { emailForm, codeForm, passwordForm, pickLang, t, esc, pageShell } from './ui.js'
import { cookieValue, sessionCookie } from '../auth/cookies.js'
import { normalizeEmail, isValidEmail, maskEmail, safeNext, readBodyParams } from '../util/common.js'

const clientIdFrom = (env) => env?.XID_CLIENT_ID || process.env.XID_CLIENT_ID || 'pub-xid'

function modeOf(value) {
  return value === 'password' || value === 'otp' ? value : ''
}

function loginUrl(params) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v)
  const s = qs.toString()
  return s ? `/login?${s}` : '/login'
}

// Login CSRF guard: a cross-site form post must not silently sign the visitor
// into the attacker's account. Modern browsers send Origin on form POSTs.
function sameOrigin(request) {
  const origin = request.headers.get('origin')
  if (!origin) return true
  try {
    const o = new URL(origin)
    const host = (request.headers.get('x-forwarded-host') || request.headers.get('host') || '')
      .split(',')[0]
      .trim()
    return !!host && o.host === host
  } catch {
    return false
  }
}

function errorPage(lang, key, env) {
  return pageShell(t(lang, 'error_title'), `<h1>${esc(t(lang, key))}</h1>`, env, lang)
}

export async function handleLoginGet(c) {
  const env = c.env || {}
  const q = c.req.query()
  const lang = pickLang(c.req.raw, q)
  const next = safeNext(q.next)
  const params = { next, mode: modeOf(q.mode), ui_locales: q.ui_locales || '' }

  const token = cookieValue(c.req.raw, 'xid_session')
  const payload = token ? await verifyAccessToken(env, token) : null
  c.header('Cache-Control', 'no-store')
  if (payload) return c.redirect(next || '/', 302)

  const prefill = normalizeEmail(q.email)
  return c.html(
    emailForm(params, {
      email: isValidEmail(prefill) ? prefill : '',
      env,
      lang,
    })
  )
}

export async function handleLoginPost(c) {
  const env = c.env || {}
  const body = await readBodyParams(c)
  const lang = pickLang(c.req.raw, body)
  const next = safeNext(body.next)
  const params = { next, mode: modeOf(body.mode), ui_locales: body.ui_locales || '' }
  const email = normalizeEmail(body.email)
  const code = typeof body.code === 'string' ? body.code.trim() : ''
  const password = typeof body.password === 'string' ? body.password : ''
  const otpSession = typeof body.otp_session === 'string' ? body.otp_session : ''

  c.header('Cache-Control', 'no-store')
  if (!sameOrigin(c.req.raw)) return c.html(errorPage(lang, 'err_not_authorized', env), 403)
  if (!isValidEmail(email)) {
    return c.html(emailForm(params, { errorKey: 'err_invalid_email', email, env, lang }), 400)
  }

  // Step 1: email only → resolve the user and choose password / OTP / legacy.
  if (!code && !password) {
    if (!(await checkLoginRateLimit(env, email, c.req.raw))) {
      return c.html(emailForm(params, { errorKey: 'err_rate', email, env, lang }), 429)
    }
    const requested = params.mode === 'password' ? true : params.mode === 'otp' ? false : undefined
    const started = await beginLogin(env, email, { passwordRequested: requested, lang })
    if (!started.ok) {
      if (started.reason === 'mail_unavailable') {
        return c.html(emailForm(params, { errorKey: 'err_mail_unavailable', email, env, lang }), 400)
      }
      if (started.reason === 'password_disabled') {
        return c.html(emailForm(params, { errorKey: 'err_not_authorized', email, env, lang }), 403)
      }
      return c.html(emailForm(params, { errorKey: 'err_not_allowlisted', email, env, lang }), 403)
    }
    if (started.mode === 'password') {
      return c.html(
        passwordForm(params, {
          email,
          otpSession: started.session,
          switchUrl: loginUrl({ ...params, mode: 'otp', email }),
          env,
          lang,
        })
      )
    }
    return c.html(
      codeForm(params, {
        email,
        otpSession: started.session,
        sentTo: maskEmail(email),
        switchUrl: started.user.passwordHash
          ? loginUrl({ ...params, mode: 'password', email })
          : '',
        env,
        lang,
      })
    )
  }

  // Step 2: verify code or password, then issue the access token cookie.
  const done = await finishLogin(env, { email, session: otpSession, code, password })
  if (!done.ok) {
    const user = done.user || null
    const switchToPassword = user?.passwordHash
      ? loginUrl({ ...params, mode: 'password', email })
      : ''
    const switchToOtp = user?.passwordHash
      ? loginUrl({ ...params, mode: 'otp', email })
      : ''
    if (done.reason === 'bad_session') {
      return c.html(codeForm(params, { errorKey: 'err_session_expired', email, env, lang }), 400)
    }
    if (done.reason === 'bad_code') {
      const errorKey = done.attemptsLeft <= 0 ? 'err_attempts' : 'err_code_invalid'
      return c.html(codeForm(params, { errorKey, email, otpSession, switchUrl: switchToPassword, env, lang }), 400)
    }
    if (done.reason === 'password_locked') {
      return c.html(passwordForm(params, { errorKey: 'err_attempts', email, otpSession, switchUrl: switchToOtp, env, lang }), 400)
    }
    if (done.reason === 'bad_password') {
      return c.html(passwordForm(params, { errorKey: 'err_invalid_password', email, otpSession, switchUrl: switchToOtp, env, lang }), 400)
    }
    if (done.reason === 'password_disabled') {
      return c.html(passwordForm(params, { errorKey: 'err_not_authorized', email, otpSession, switchUrl: switchToOtp, env, lang }), 400)
    }
    return c.html(emailForm(params, { errorKey: 'err_not_authorized', email, env, lang }), 403)
  }

  const { AccessToken } = await issueTokens(env, done.email, clientIdFrom(env))
  const cookie = sessionCookie(AccessToken, env)
  if (cookie) c.header('Set-Cookie', cookie)
  return c.redirect(next || '/', 302)
}

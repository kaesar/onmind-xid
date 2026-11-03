// Microsoft Entra ID simulation facade (OAuth2 v2.0 + OIDC) over the XID core.
// Alternative to cognito.js for the same scenario: email OTP against the allowlist.
// Login orchestration lives in loginflow.js (shared with Cognito); here only
// HTML form rendering and auth code/token issuance.
// Reuses: loginflow (begin/finish steps), users, session, kv, keys.
//
// Endpoints (tenant = path param; 'common'/'organizations'/'consumers' → configured tid):
//   GET  /.well-known/openid-configuration
//   GET  /{tenant}/v2.0/.well-known/openid-configuration
//   GET  /{tenant}/oauth2/v2.0/authorize (+ POST forms OTP)
//   POST /{tenant}/oauth2/v2.0/token
//   GET  /{tenant}/discovery/v2.0/keys
//   GET  /{tenant}/openid/userinfo
//   GET  /{tenant}/oauth2/v2.0/logout
//
// Documented deviations from real Entra:
//   - sub = email (stable); plus oid = sha256(email), tid, preferred_username.
//   - interactive = public clients (no secret); B2B = client_credentials with
//     secret (registry xclients.txt / KV XID_CLIENTS, sub = client_id, no id_token).
//   - PKCE S256 optional but verified when the authorize request sent it.
//   - No SAML/WS-Fed or device_code.

import { kvGet, kvPut, kvConsume } from '../store/kv.js'
import { getUser } from '../service/users.js'
import { beginLogin, finishLogin } from '../auth/loginflow.js'
import { verifyAccessToken, denyJti } from '../auth/session.js'
import { getRole } from '../service/users.js'
import { normalizeEmail, isValidEmail, maskEmail, sha256Hex, readBodyParams } from '../util/common.js'
import { signRs256, verifyRs256, getPublicJwk } from '../auth/keys.js'
import { esc, pageShell, emailForm, codeForm, passwordForm, pickLang, t } from './ui.js'
import {
  getClient,
  verifyClientSecret,
  parseScopes,
  scopesAllowed,
  checkM2mRateLimit,
  ipOf,
  parseBasicAuth,
  issueMachineToken,
} from '../service/clients.js'

const AUTH_CODE_TTL = 600 // s (10 min, single use)
const REFRESH_TTL = 86400 // s (24 h, rotated on every use)
const ACCESS_TTL = 3600 // s (1 h, same as Cognito)

const codeKey = (code) => `entra-code:${code}`
const refreshKey = (token) => `entra-refresh:${token}`

// ---------------- helpers ----------------

function configuredTid(env) {
  return env?.XID_TENANT_ID || process.env.XID_TENANT_ID || 'xid'
}

function cleanTenant(raw, env) {
  const t = String(raw || '').trim()
  if (/^[A-Za-z0-9._-]{1,64}$/.test(t)) return t
  return configuredTid(env)
}

function effectiveTid(env, tenant) {
  if (['common', 'organizations', 'consumers'].includes(tenant)) return configuredTid(env)
  return tenant
}

function originOf(request, env) {
  const fwdHost = String(request.headers.get('x-forwarded-host') || '')
    .split(',')[0]
    .trim()
  const fwdProto = String(request.headers.get('x-forwarded-proto') || '')
    .split(',')[0]
    .trim()
  if (fwdHost || fwdProto) {
    const url = new URL(request.url)
    return `${fwdProto || url.protocol.replace(':', '')}://${fwdHost || url.host}`
  }
  const configured = String(env?.XID_PUBLIC_URL || process.env.XID_PUBLIC_URL || '')
    .trim()
    .replace(/\/+$/, '')
  return configured || new URL(request.url).origin
}

function redirectAllowlist(env) {
  const raw = env?.XID_REDIRECT_ALLOWLIST || process.env.XID_REDIRECT_ALLOWLIST || ''
  return raw.split(',').map((s) => s.trim()).filter(Boolean)
}

function isProd(env) {
  return (env?.XID_ENV || process.env.XID_ENV || 'dev') === 'production'
}

export function isRedirectAllowed(env, uri) {
  let u
  try {
    u = new URL(uri)
  } catch {
    return false
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false
  const list = redirectAllowlist(env)
  if (!list.length) return !isProd(env) // dev: open; prod: require allowlist
  return list.some((entry) => {
    if (entry.endsWith('*')) return uri.startsWith(entry.slice(0, -1))
    return uri === entry
  })
}

function redirectWithParams(base, params) {
  const u = new URL(base)
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') u.searchParams.set(k, v)
  }
  return u.toString()
}

function randomB64Url(nbytes) {
  const bytes = crypto.getRandomValues(new Uint8Array(nbytes))
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function pkceMatches(verifier, challenge, method) {
  if (method === 'plain') return verifier === challenge
  // default S256
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  const bytes = new Uint8Array(digest)
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  const computed = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return computed === challenge
}

// ---------------- tokens ----------------

async function issueEntraTokenSet(env, { email, clientId, scope, nonce, origin, tenant }) {
  const tid = effectiveTid(env, tenant)
  const iss = `${origin}/${tenant}`
  const now = Math.floor(Date.now() / 1000)
  const exp = now + ACCESS_TTL
  const oid = await sha256Hex(email.toLowerCase())
  const jti = typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : randomB64Url(16)
  const scp = scope || 'openid profile email'
  const role = await getRole(env, email)

  const access = await signRs256(env, {
    iss, aud: clientId, sub: email, oid, tid,
    token_use: 'access',
    preferred_username: email, email, email_verified: true,
    role, roles: [role],
    scp, iat: now, exp, jti,
  })
  const idPayload = {
    iss, aud: clientId, sub: email, oid, tid,
    token_use: 'id',
    preferred_username: email, email, email_verified: true,
    role, roles: [role],
    name: email.split('@')[0],
    iat: now, exp,
  }
  if (nonce) idPayload.nonce = nonce
  const id = await signRs256(env, idPayload)

  const refresh = randomB64Url(32)
  await kvPut(env, refreshKey(refresh), { email, clientId, scope: scp }, REFRESH_TTL)
  return { access, id, refresh }
}

// ---------------- discovery / jwks ----------------

function discoveryDoc(origin, tenant) {
  const base = `${origin}/${tenant}`
  return {
    issuer: base,
    authorization_endpoint: `${base}/oauth2/v2.0/authorize`,
    token_endpoint: `${base}/oauth2/v2.0/token`,
    userinfo_endpoint: `${base}/openid/userinfo`,
    jwks_uri: `${base}/discovery/v2.0/keys`,
    end_session_endpoint: `${base}/oauth2/v2.0/logout`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    claims_supported: ['sub', 'oid', 'tid', 'email', 'email_verified', 'preferred_username', 'name', 'iss', 'aud', 'exp', 'iat', 'nonce'],
    code_challenge_methods_supported: ['S256', 'plain'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
  }
}

// A requested scope is valid only if it is a subset of the scope already
// granted to the code/refresh token; omitted scope keeps the stored one.
function scopeSubset(bodyScope, storedScope) {
  if (!bodyScope) return storedScope
  const requested = parseScopes(bodyScope)
  const allowed = parseScopes(storedScope)
  if (!requested.length || !scopesAllowed(requested, allowed)) return null
  return requested.join(' ')
}

function oauthPassthrough(query) {
  return {
    client_id: query.client_id || '',
    redirect_uri: query.redirect_uri || '',
    scope: query.scope || 'openid profile email',
    state: query.state || '',
    nonce: query.nonce || '',
    code_challenge: query.code_challenge || '',
    code_challenge_method: query.code_challenge_method || '',
    response_type: query.response_type || '',
    ui_locales: query.ui_locales || '',
    mode: query.mode === 'password' || query.mode === 'otp' ? query.mode : '',
  }
}

// URL of the authorize request itself for the password ⇄ OTP switch links.
function authorizeUrl(origin, tenant, oauth, overrides = {}) {
  const u = new URL(`${origin}/${tenant}/oauth2/v2.0/authorize`)
  const params = { ...oauth, ...overrides }
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') u.searchParams.set(k, v)
  }
  return u.toString()
}

// ---------------- handlers ----------------

export async function handleDiscovery(c, tenantRaw) {
  const tenant = cleanTenant(tenantRaw, c.env)
  return c.json(discoveryDoc(originOf(c.req.raw, c.env), tenant))
}

export async function handleJwks(c) {
  const jwk = await getPublicJwk(c.env)
  return c.json({ keys: [jwk] })
}

export async function handleAuthorizeGet(c, tenantRaw) {
  const env = c.env || {}
  const tenant = cleanTenant(tenantRaw, env)
  const q = c.req.query()
  const oauth = oauthPassthrough(q)
  const lang = pickLang(c.req.raw, oauth)

  if (!oauth.client_id) {
    return c.html(pageShell(t(lang, 'error_title'), `<h1>${esc(t(lang, 'err_missing_client'))}</h1>`, env, lang), 400)
  }
  if (!oauth.redirect_uri || !isRedirectAllowed(env, oauth.redirect_uri)) {
    return c.html(pageShell(t(lang, 'error_title'), `<h1>${esc(t(lang, 'err_redirect'))}</h1><p class="muted">${esc(t(lang, 'redirect_hint'))}</p>`, env, lang), 400)
  }
  if (oauth.response_type && oauth.response_type !== 'code' && !oauth.response_type.includes('code')) {
    return c.redirect(redirectWithParams(oauth.redirect_uri, { error: 'unsupported_response_type', error_description: 'only code supported', state: oauth.state }), 302)
  }
  const prefill = typeof q.email === 'string' ? normalizeEmail(q.email) : ''
  return c.html(emailForm(oauth, { email: isValidEmail(prefill) ? prefill : '', env, lang }))
}

export async function handleAuthorizePost(c, tenantRaw) {
  const env = c.env || {}
  const tenant = cleanTenant(tenantRaw, env)
  const body = await readBodyParams(c)
  const oauth = oauthPassthrough(body)
  const lang = pickLang(c.req.raw, oauth)
  const origin = originOf(c.req.raw, env)
  const email = normalizeEmail(body.email)
  const code = typeof body.code === 'string' ? body.code.trim() : ''
  const password = typeof body.password === 'string' ? body.password : ''
  const otpSession = typeof body.otp_session === 'string' ? body.otp_session : ''

  if (!oauth.client_id) {
    return c.html(pageShell(t(lang, 'error_title'), `<h1>${esc(t(lang, 'err_missing_client'))}</h1>`, env, lang), 400)
  }
  if (!oauth.redirect_uri || !isRedirectAllowed(env, oauth.redirect_uri)) {
    return c.html(pageShell(t(lang, 'error_title'), `<h1>${esc(t(lang, 'err_redirect'))}</h1>`, env, lang), 400)
  }
  const goError = (error, description) =>
    c.redirect(redirectWithParams(oauth.redirect_uri, { error, error_description: description, state: oauth.state }), 302)

  if (!isValidEmail(email)) return c.html(emailForm(oauth, { errorKey: 'err_invalid_email', email, env, lang }), 400)

  // Step 1: email only → beginLogin picks the mode (password without mail,
  // OTP with mail, legacy without mail). ?mode=password forces password;
  // ?mode=otp forces OTP (legacy sends no mail: the static key is enough).
  if (!code && !password) {
    const requested = oauth.mode === 'password' ? true : oauth.mode === 'otp' ? false : undefined
    const started = await beginLogin(env, email, { passwordRequested: requested, lang })
    if (!started.ok) {
      if (started.reason === 'mail_unavailable') {
        return c.html(emailForm(oauth, { errorKey: 'err_mail_unavailable', email, env, lang }), 400)
      }
      return c.html(emailForm(oauth, { errorKey: 'err_not_allowlisted', email, env, lang }), 403)
    }
    if (started.mode === 'password') {
      return c.html(
        passwordForm(oauth, {
          email,
          otpSession: started.session,
          switchUrl: authorizeUrl(origin, tenant, { ...oauth, mode: 'otp', email }),
          env,
          lang,
        })
      )
    }
    return c.html(
      codeForm(oauth, {
        email,
        otpSession: started.session,
        sentTo: maskEmail(email),
        switchUrl: started.user.passwordHash
          ? authorizeUrl(origin, tenant, { ...oauth, mode: 'password', email })
          : '',
        env,
        lang,
      })
    )
  }

  // Step 2: verify password (bcrypt) or code → issue the authorization code.
  const done = await finishLogin(env, { email, session: otpSession, code, password })
  if (!done.ok) {
    const user = done.user || null
    const switchToPassword = user?.passwordHash
      ? authorizeUrl(origin, tenant, { ...oauth, mode: 'password', email })
      : ''
    const switchToOtp = user?.passwordHash
      ? authorizeUrl(origin, tenant, { ...oauth, mode: 'otp', email })
      : ''
    if (done.reason === 'bad_session') {
      return c.html(codeForm(oauth, { errorKey: 'err_session_expired', email, otpSession: '', switchUrl: switchToPassword, env, lang }), 400)
    }
    if (done.reason === 'bad_code') {
      const errorKey = done.attemptsLeft <= 0 ? 'err_attempts' : 'err_code_invalid'
      return c.html(codeForm(oauth, { errorKey, email, otpSession, switchUrl: switchToPassword, env, lang }), 400)
    }
    if (done.reason === 'password_locked') {
      return c.html(passwordForm(oauth, { errorKey: 'err_attempts', email, otpSession, switchUrl: switchToOtp, env, lang }), 400)
    }
    if (done.reason === 'bad_password') {
      return c.html(passwordForm(oauth, { errorKey: 'err_invalid_password', email, otpSession, switchUrl: switchToOtp, env, lang }), 400)
    }
    if (done.reason === 'password_disabled') {
      return c.html(passwordForm(oauth, { errorKey: 'err_not_authorized', email, otpSession, switchUrl: switchToOtp, env, lang }), 400)
    }
    return c.html(emailForm(oauth, { errorKey: 'err_not_authorized', email, env, lang }), 403)
  }
  const user = done.user
  const switchToPassword = user.passwordHash
    ? authorizeUrl(origin, tenant, { ...oauth, mode: 'password', email })
    : ''
  const switchToOtp = user.passwordHash
    ? authorizeUrl(origin, tenant, { ...oauth, mode: 'otp', email })
    : ''
  const authCode = randomB64Url(32)
  await kvPut(
    env,
    codeKey(authCode),
    {
      email,
      clientId: oauth.client_id,
      redirectUri: oauth.redirect_uri,
      scope: oauth.scope,
      nonce: oauth.nonce,
      codeChallenge: oauth.code_challenge || null,
      codeChallengeMethod: oauth.code_challenge_method || null,
    },
    AUTH_CODE_TTL
  )
  return c.redirect(redirectWithParams(oauth.redirect_uri, { code: authCode, state: oauth.state }), 302)
}

export async function handleToken(c, tenantRaw) {
  const env = c.env || {}
  const tenant = cleanTenant(tenantRaw, env)
  const body = await readBodyParams(c)
  const grant = body.grant_type

  if (grant === 'authorization_code') {
    const stored = body.code ? await kvGet(env, codeKey(body.code)) : null
    if (!stored) return c.json({ error: 'invalid_grant', error_description: 'invalid or expired code' }, 400)
    if (body.redirect_uri && body.redirect_uri !== stored.redirectUri) {
      return c.json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400)
    }
    if (body.client_id && body.client_id !== stored.clientId) {
      return c.json({ error: 'invalid_grant', error_description: 'client_id mismatch' }, 400)
    }
    if (stored.codeChallenge) {
      if (!body.code_verifier) {
        return c.json({ error: 'invalid_grant', error_description: 'code_verifier required' }, 400)
      }
      const method = stored.codeChallengeMethod === 'plain' ? 'plain' : 'S256'
      if (!(await pkceMatches(String(body.code_verifier), stored.codeChallenge, method))) {
        return c.json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, 400)
      }
    }
    const effectiveScope = scopeSubset(body.scope, stored.scope)
    if (effectiveScope === null) {
      return c.json({ error: 'invalid_scope', error_description: 'requested scope exceeds grant' }, 400)
    }
    const user = await getUser(env, stored.email)
    if (!user) return c.json({ error: 'invalid_grant', error_description: 'user no longer authorized' }, 400)
    const consumed = await kvConsume(env, codeKey(body.code))
    if (!consumed) {
      return c.json({ error: 'invalid_grant', error_description: 'invalid or expired code' }, 400)
    }
    const origin = originOf(c.req.raw, env)
    const set = await issueEntraTokenSet(env, {
      email: stored.email,
      clientId: stored.clientId,
      scope: effectiveScope,
      nonce: stored.nonce,
      origin,
      tenant,
    })
    return c.json({
      token_type: 'Bearer',
      scope: effectiveScope,
      expires_in: ACCESS_TTL,
      access_token: set.access,
      id_token: set.id,
      refresh_token: set.refresh,
    })
  }

  if (grant === 'refresh_token') {
    if (!body.refresh_token) {
      return c.json({ error: 'invalid_grant', error_description: 'missing refresh_token' }, 400)
    }
    const stored = await kvGet(env, refreshKey(body.refresh_token))
    if (!stored) return c.json({ error: 'invalid_grant', error_description: 'invalid refresh_token' }, 400)
    if (body.client_id && body.client_id !== stored.clientId) {
      return c.json({ error: 'invalid_grant', error_description: 'client_id mismatch' }, 400)
    }
    const effectiveScope = scopeSubset(body.scope, stored.scope)
    if (effectiveScope === null) {
      return c.json({ error: 'invalid_scope', error_description: 'requested scope exceeds grant' }, 400)
    }
    const user = await getUser(env, stored.email)
    if (!user) return c.json({ error: 'invalid_grant', error_description: 'user no longer authorized' }, 400)
    const consumed = await kvConsume(env, refreshKey(body.refresh_token))
    if (!consumed) {
      return c.json({ error: 'invalid_grant', error_description: 'invalid refresh_token' }, 400)
    }
    const origin = originOf(c.req.raw, env)
    const set = await issueEntraTokenSet(env, {
      email: stored.email,
      clientId: stored.clientId,
      scope: effectiveScope,
      nonce: null,
      origin,
      tenant,
    })
    return c.json({
      token_type: 'Bearer',
      scope: effectiveScope,
      expires_in: ACCESS_TTL,
      access_token: set.access,
      id_token: set.id,
      refresh_token: set.refresh,
    })
  }

  if (grant === 'client_credentials') {
    // B2B machine-to-machine: no user, no OTP. Auth via Basic or body.
    const basic = parseBasicAuth(c.req.raw)
    const clientId = body.client_id || basic?.clientId || ''
    const clientSecret = body.client_secret || basic?.clientSecret || ''
    const client = await getClient(env, clientId)
    if (!(await checkM2mRateLimit(env, clientId || 'unknown', ipOf(c.req.raw)))) {
      return c.json({ error: 'invalid_grant', error_description: 'attempt limit exceeded' }, 400)
    }
    if (!client || !(await verifyClientSecret(client, clientSecret))) {
      return c.json({ error: 'invalid_client', error_description: 'invalid client credentials' }, 401)
    }
    const requested = body.scope ? parseScopes(body.scope) : [...client.scopes]
    if (body.scope && !scopesAllowed(requested, client.scopes)) {
      return c.json({ error: 'invalid_scope', error_description: 'requested scope exceeds grant' }, 400)
    }
    const origin = originOf(c.req.raw, env)
    const issued = await issueMachineToken(env, {
      clientId: client.clientId,
      scope: requested.join(' '),
      iss: `${origin}/${tenant}`,
      tid: effectiveTid(env, tenant),
    })
    return c.json({
      token_type: 'Bearer',
      scope: issued.scope,
      expires_in: issued.expiresIn,
      access_token: issued.token,
    })
  }
  return c.json({ error: 'unsupported_grant_type', error_description: 'use authorization_code, refresh_token or client_credentials' }, 400)
}

async function bearerPayload(env, request) {
  const header = request.headers?.get('authorization') || ''
  const m = /^Bearer\s+(.+)$/i.exec(header)
  if (!m) return null
  const token = m[1]
  const rs = await verifyRs256(env, token)
  if (rs) {
    // Entra/machine tokens carry token_use; legacy access tokens have a jti,
    // legacy ID tokens have neither and must not be accepted as access tokens.
    if (rs.token_use !== 'access' && !(rs.token_use === undefined && rs.jti)) return null
    if (rs.jti && (await kvGet(env, `sess:${rs.jti}`))) return null // revoked via logout
    return rs
  }
  return verifyAccessToken(env, token) // compat: also accepts Cognito HS256
}

export async function handleUserinfo(c) {
  const env = c.env || {}
  const payload = await bearerPayload(env, c.req.raw)
  if (!payload?.sub) {
    return c.json({ error: 'invalid_token', error_description: 'missing or invalid access token' }, 401)
  }
  const user = await getUser(env, payload.sub)
  if (!user) {
    if (payload.client_id && payload.client_id === payload.sub && (await getClient(env, payload.sub))) {
      return c.json({ error: 'invalid_token', error_description: 'machine tokens carry no user identity (present access_token to resource APIs)' }, 401)
    }
    return c.json({ error: 'invalid_token', error_description: 'user no longer authorized' }, 401)
  }
  const email = payload.sub
  const oid = payload.oid || (await sha256Hex(email.toLowerCase()))
  const role = await getRole(env, email)
  return c.json({
    sub: email,
    oid,
    tid: payload.tid || configuredTid(env),
    email,
    email_verified: true,
    preferred_username: email,
    name: email.split('@')[0],
    role,
    roles: [role],
  })
}

export async function handleLogout(c, tenantRaw) {
  const env = c.env || {}
  const tenant = cleanTenant(tenantRaw, env)
  const header = c.req.raw.headers?.get('authorization') || ''
  const m = /^Bearer\s+(.+)$/i.exec(header)
  if (m) {
    const payload = await bearerPayload(env, c.req.raw)
    if (payload?.jti && payload?.exp) await denyJti(env, payload.jti, payload.exp)
  }
  const q = c.req.query()
  const lang = pickLang(c.req.raw, q)
  const postUri = q.post_logout_redirect_uri || ''
  if (postUri) {
    if (!isRedirectAllowed(env, postUri)) {
      return c.html(pageShell(t(lang, 'error_title'), `<h1>${esc(t(lang, 'err_post_logout'))}</h1>`, env, lang), 400)
    }
    const url = redirectWithParams(postUri, { state: q.state || '' })
    return c.redirect(url, 302)
  }
  void tenant
  return c.html(pageShell(t(lang, 'logged_out'), `<h1>${esc(t(lang, 'logged_out'))}</h1><p class="muted">${esc(t(lang, 'session_revoked'))}</p>`, env, lang))
}

// ---------------- registration ----------------

export function registerEntra(app) {
  app.get('/.well-known/openid-configuration', (c) =>
    handleDiscovery(c, configuredTid(c.env || {}))
  )
  app.get('/:tenant/v2.0/.well-known/openid-configuration', (c) =>
    handleDiscovery(c, c.req.param('tenant'))
  )
  app.get('/:tenant/oauth2/v2.0/authorize', (c) =>
    handleAuthorizeGet(c, c.req.param('tenant'))
  )
  app.post('/:tenant/oauth2/v2.0/authorize', (c) =>
    handleAuthorizePost(c, c.req.param('tenant'))
  )
  app.post('/:tenant/oauth2/v2.0/token', (c) =>
    handleToken(c, c.req.param('tenant'))
  )
  app.get('/:tenant/discovery/v2.0/keys', (c) => handleJwks(c))
  app.get('/:tenant/openid/userinfo', (c) => handleUserinfo(c))
  app.get('/:tenant/oauth2/v2.0/logout', (c) =>
    handleLogout(c, c.req.param('tenant'))
  )
}

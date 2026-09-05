// Fachada de simulación Microsoft Entra ID (OAuth2 v2.0 + OIDC) sobre el core XID.
// Alternativa a cognito.js para el mismo escenario: OTP por email contra allowlist.
// Reutiliza: users (allowlist), otp (códigos), session (otp_session + denylist),
// mail (envío), kv (auth codes + refresh tokens).
//
// Endpoints (tenant = path param; 'common'/'organizations'/'consumers' → tid configurado):
//   GET  /.well-known/openid-configuration
//   GET  /{tenant}/v2.0/.well-known/openid-configuration
//   GET  /{tenant}/oauth2/v2.0/authorize (+ POST forms OTP)
//   POST /{tenant}/oauth2/v2.0/token
//   GET  /{tenant}/discovery/v2.0/keys
//   GET  /{tenant}/openid/userinfo
//   GET  /{tenant}/oauth2/v2.0/logout
//
// Desviaciones documentadas vs Entra real:
//   - sub = email (estable); además oid = sha256(email), tid, preferred_username.
//   - Sin client_secret (clientes públicos); si llega se ignora.
//   - PKCE S256 opcional pero verificado cuando el authorize lo envió.
//   - Sin SAML/WS-Fed, device_code ni client_credentials (se rechaza con hint).

import { kvGet, kvPut, kvDelete } from './kv.js'
import { getUser } from './users.js'
import { startOtp, verifyOtp, otpAttemptsLeft } from './otp.js'
import { verifyOtpSession, issueOtpSession, verifyAccessToken, denyJti } from './session.js'
import { sendMail, makeOtpMessage } from './mail.js'
import { normalizeEmail, isValidEmail, maskEmail, sha256Hex, sleep } from './util.js'
import { signRs256, verifyRs256, getPublicJwk } from './entra-keys.js'

const AUTH_CODE_TTL = 600 // s (10 min, un solo uso)
const REFRESH_TTL = 86400 // s (24 h, rotación en cada uso)
const ACCESS_TTL = 3600 // s (1 h, igual que Cognito)

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

function originOf(request) {
  return new URL(request.url).origin
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
  if (!list.length) return !isProd(env) // dev: abierto; prod: exigir allowlist
  return list.some((entry) => {
    if (entry.endsWith('*')) return uri.startsWith(entry.slice(0, -1))
    return uri === entry
  })
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
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

async function readBodyParams(c) {
  const ct = c.req.header('content-type') || ''
  if (ct.includes('application/json')) {
    return c.req.json().catch(() => ({}))
  }
  // form-urlencoded y multipart (Hono parseBody cubre ambos en Bun y Workers)
  try {
    const parsed = await c.req.parseBody()
    const out = {}
    for (const [k, v] of Object.entries(parsed || {})) {
      out[k] = typeof v === 'string' ? v : String(v)
    }
    return out
  } catch {
    return {}
  }
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

  const access = await signRs256(env, {
    iss, aud: clientId, sub: email, oid, tid,
    preferred_username: email, email, email_verified: true,
    scp, iat: now, exp, jti,
  })
  const idPayload = {
    iss, aud: clientId, sub: email, oid, tid,
    preferred_username: email, email, email_verified: true,
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
    grant_types_supported: ['authorization_code', 'refresh_token'],
  }
}

// ---------------- HTML UI (authorize) ----------------

function pageShell(title, inner) {
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>body{font-family:system-ui,sans-serif;max-width:26rem;margin:4rem auto;padding:0 1rem;color:#111}input,button{font-size:1rem;padding:.55rem .7rem;width:100%;box-sizing:border-box}button{cursor:pointer;margin-top:.6rem}label{display:block;margin:.8rem 0 .3rem}.muted{color:#555;font-size:.85rem}.err{background:#fde7e7;border:1px solid #f3b4b4;padding:.6rem .8rem;border-radius:.4rem}</style></head><body>${inner}</body></html>`
}

function hiddenFields(params) {
  return Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join('')
}

function emailForm(oauth, { error = '', email = '' } = {}) {
  return pageShell(
    'Iniciar sesión',
    `<h1>Iniciar sesión</h1>` +
      (error ? `<p class="err">${esc(error)}</p>` : '') +
      `<form method="post">` +
      hiddenFields(oauth) +
      `<label for="email">Email</label><input id="email" name="email" type="email" required autocomplete="email" value="${esc(email)}">` +
      `<button type="submit">Enviar código</button></form>` +
      `<p class="muted">Recibirás un código de 6 dígitos válido 5 min (solo allowlist).</p>`
  )
}

function codeForm(oauth, { error = '', email = '', otpSession = '', sentTo = '' } = {}) {
  return pageShell(
    'Verificar código',
    `<h1>Verificar código</h1>` +
      (error ? `<p class="err">${esc(error)}</p>` : '') +
      (sentTo ? `<p class="muted">Código enviado a ${esc(sentTo)}.</p>` : '') +
      `<form method="post">` +
      hiddenFields({ ...oauth, otp_session: otpSession }) +
      `<label for="email">Email</label><input id="email" name="email" type="email" required value="${esc(email)}" readonly>` +
      `<label for="code">Código de 6 dígitos</label><input id="code" name="code" inputmode="numeric" pattern="[0-9]{6}" required autocomplete="one-time-code">` +
      `<button type="submit">Verificar e iniciar sesión</button></form>`
  )
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
  }
}

// ---------------- handlers ----------------

export async function handleDiscovery(c, tenantRaw) {
  const tenant = cleanTenant(tenantRaw, c.env)
  return c.json(discoveryDoc(originOf(c.req.raw), tenant))
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

  if (!oauth.client_id) return c.html(pageShell('Error', '<h1>Falta client_id</h1>'), 400)
  if (!oauth.redirect_uri || !isRedirectAllowed(env, oauth.redirect_uri)) {
    return c.html(pageShell('Error', '<h1>redirect_uri no permitido</h1><p class="muted">Configura XID_REDIRECT_ALLOWLIST.</p>'), 400)
  }
  if (oauth.response_type && oauth.response_type !== 'code' && !oauth.response_type.includes('code')) {
    return c.redirect(redirectWithParams(oauth.redirect_uri, { error: 'unsupported_response_type', error_description: 'only code supported', state: oauth.state }), 302)
  }
  return c.html(emailForm(oauth))
}

export async function handleAuthorizePost(c, tenantRaw) {
  const env = c.env || {}
  const tenant = cleanTenant(tenantRaw, env)
  const body = await readBodyParams(c)
  const oauth = oauthPassthrough(body)
  const email = normalizeEmail(body.email)
  const code = typeof body.code === 'string' ? body.code.trim() : ''
  const otpSession = typeof body.otp_session === 'string' ? body.otp_session : ''

  if (!oauth.client_id) return c.html(pageShell('Error', '<h1>Falta client_id</h1>'), 400)
  if (!oauth.redirect_uri || !isRedirectAllowed(env, oauth.redirect_uri)) {
    return c.html(pageShell('Error', '<h1>redirect_uri no permitido</h1>'), 400)
  }
  const goError = (error, description) =>
    c.redirect(redirectWithParams(oauth.redirect_uri, { error, error_description: description, state: oauth.state }), 302)

  if (!isValidEmail(email)) return c.html(emailForm(oauth, { error: 'Email inválido.', email }), 400)

  // Paso 1: pide email → genera OTP y muestra form de código.
  if (!code) {
    const user = await getUser(env, email)
    await sleep(180 + Math.floor(Math.random() * 220))
    if (!user) return c.html(emailForm(oauth, { error: 'Email no autorizado (allowlist).', email }), 403)
    if (!user.otpKeyHash) {
      const { code: otp } = await startOtp(env, email)
      const msg = makeOtpMessage(otp, email)
      await sendMail(env, { to: email, subject: msg.subject, text: msg.text, code: msg.code })
    }
    const session = await issueOtpSession(env, email)
    return c.html(codeForm(oauth, { email, otpSession: session, sentTo: maskEmail(email) }))
  }

  // Paso 2: verifica código → emite authorization code y redirige.
  const user = await getUser(env, email)
  if (!user) return c.html(emailForm(oauth, { error: 'Email no autorizado.', email }), 403)
  const sessionPayload = await verifyOtpSession(env, otpSession)
  if (!sessionPayload || sessionPayload.sub !== email) {
    return c.html(codeForm(oauth, { error: 'Sesión expirada. Pide un código nuevo.', email, otpSession: '' }), 400)
  }
  const ok = await verifyOtp(env, email, code, user)
  if (!ok) {
    const left = await otpAttemptsLeft(env, email)
    const msg = left <= 0 ? 'Límite de intentos. Pide un código nuevo.' : 'Código inválido. Inténtalo de nuevo.'
    return c.html(codeForm(oauth, { error: msg, email, otpSession }), 400)
  }
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
    const user = await getUser(env, stored.email)
    if (!user) return c.json({ error: 'invalid_grant', error_description: 'user no longer authorized' }, 400)
    await kvDelete(env, codeKey(body.code))
    const origin = originOf(c.req.raw)
    const set = await issueEntraTokenSet(env, {
      email: stored.email,
      clientId: stored.clientId,
      scope: body.scope || stored.scope,
      nonce: stored.nonce,
      origin,
      tenant,
    })
    return c.json({
      token_type: 'Bearer',
      scope: body.scope || stored.scope,
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
    const user = await getUser(env, stored.email)
    if (!user) return c.json({ error: 'invalid_grant', error_description: 'user no longer authorized' }, 400)
    await kvDelete(env, refreshKey(body.refresh_token)) // rotación
    const origin = originOf(c.req.raw)
    const set = await issueEntraTokenSet(env, {
      email: stored.email,
      clientId: stored.clientId,
      scope: body.scope || stored.scope,
      nonce: null,
      origin,
      tenant,
    })
    return c.json({
      token_type: 'Bearer',
      scope: body.scope || stored.scope,
      expires_in: ACCESS_TTL,
      access_token: set.access,
      id_token: set.id,
      refresh_token: set.refresh,
    })
  }

  if (grant === 'client_credentials') {
    return c.json({ error: 'invalid_grant', error_description: 'client_credentials no soportado: usa authorization_code con OTP (flujo interactivo)' }, 400)
  }
  return c.json({ error: 'unsupported_grant_type', error_description: 'usa authorization_code o refresh_token' }, 400)
}

async function bearerPayload(env, request) {
  const header = request.headers?.get('authorization') || ''
  const m = /^Bearer\s+(.+)$/i.exec(header)
  if (!m) return null
  const token = m[1]
  const rs = await verifyRs256(env, token)
  if (rs) {
    if (rs.jti && (await kvGet(env, `sess:${rs.jti}`))) return null // revocado vía logout
    return rs
  }
  return verifyAccessToken(env, token) // compat: acepta también HS256 de Cognito
}

export async function handleUserinfo(c) {
  const env = c.env || {}
  const payload = await bearerPayload(env, c.req.raw)
  if (!payload?.sub) {
    return c.json({ error: 'invalid_token', error_description: 'missing or invalid access token' }, 401)
  }
  const user = await getUser(env, payload.sub)
  if (!user) return c.json({ error: 'invalid_token', error_description: 'user no longer authorized' }, 401)
  const email = payload.sub
  const oid = payload.oid || (await sha256Hex(email.toLowerCase()))
  return c.json({
    sub: email,
    oid,
    tid: payload.tid || configuredTid(env),
    email,
    email_verified: true,
    preferred_username: email,
    name: email.split('@')[0],
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
  const postUri = q.post_logout_redirect_uri || ''
  if (postUri) {
    if (!isRedirectAllowed(env, postUri)) {
      return c.html(pageShell('Error', '<h1>post_logout_redirect_uri no permitido</h1>'), 400)
    }
    const url = redirectWithParams(postUri, { state: q.state || '' })
    return c.redirect(url, 302)
  }
  void tenant
  return c.html(pageShell('Sesión cerrada', '<h1>Sesión cerrada</h1><p class="muted">Token revocado (si se envió Bearer).</p>'))
}

// ---------------- registro ----------------

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

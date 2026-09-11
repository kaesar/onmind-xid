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
//   - interactivo = clientes públicos (sin secret); B2B = client_credentials con
//     secret (registro xclients.txt / KV XID_CLIENTS, sub = client_id, sin id_token).
//   - PKCE S256 opcional pero verificado cuando el authorize lo envió.
//   - Sin SAML/WS-Fed ni device_code.

import { kvGet, kvPut, kvDelete } from './kv.js'
import { getUser } from './users.js'
import { startOtp, verifyOtp, otpAttemptsLeft } from './otp.js'
import { verifyOtpSession, issueOtpSession, verifyAccessToken, denyJti } from './session.js'
import { sendMail, makeOtpMessage } from './mail.js'
import { normalizeEmail, isValidEmail, maskEmail, sha256Hex, sleep } from './util.js'
import { signRs256, verifyRs256, getPublicJwk } from './entra-keys.js'
import { verifyPassword, checkPasswordRateLimit } from './passwords.js'
import { cuiUrl } from './assets.js'
import {
  getClient,
  verifyClientSecret,
  parseScopes,
  scopesAllowed,
  checkM2mRateLimit,
  ipOf,
  parseBasicAuth,
  issueMachineToken,
} from './clients.js'

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
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
  }
}

// ---------------- HTML UI (English, Español) ---------------------
// `ui_locales` OIDC param → `Accept-Language` header → default `en`

const STRINGS = {
  en: {
    sign_in: 'Sign in',
    verify_code: 'Verify code',
    email: 'Email',
    email_ph: 'you@email.com',
    send_code: 'Send code',
    code_label: '6-digit code',
    code_ph: '123456',
    verify_btn: 'Verify and sign in',
    code_sent_to: 'Code sent to',
    otp_hint: 'You will receive a 6-digit code valid for 5 min.',
    logged_out: 'Signed out',
    session_revoked: 'Token revoked (if Bearer was sent).',
    error_title: 'Error',
    err_invalid_email: 'Invalid email.',
    err_not_allowlisted: 'Email not authorized (allowlist).',
    err_not_authorized: 'Email not authorized.',
    err_session_expired: 'Session expired. Request a new code.',
    err_code_invalid: 'Invalid code. Try again.',
    err_attempts: 'Attempt limit reached. Request a new code.',
    err_missing_client: 'Missing client_id',
    err_redirect: 'redirect_uri not allowed',
    redirect_hint: 'Set XID_REDIRECT_ALLOWLIST.',
    err_post_logout: 'post_logout_redirect_uri not allowed',
    password: 'Password',
    password_ph: 'Your password',
    password_btn: 'Sign in with password',
    password_for: 'Signing in as',
    use_code_link: 'Use email code instead',
    use_password_link: 'Use password instead',
    err_invalid_password: 'Invalid password.',
  },
  es: {
    sign_in: 'Iniciar sesión',
    verify_code: 'Verificar código',
    email: 'Email',
    email_ph: 'tu@email.com',
    send_code: 'Enviar código',
    code_label: 'Código de 6 dígitos',
    code_ph: '123456',
    verify_btn: 'Verificar e iniciar sesión',
    code_sent_to: 'Código enviado a',
    otp_hint: 'Recibirás un código de 6 dígitos válido 5 min.',
    logged_out: 'Sesión cerrada',
    session_revoked: 'Token revocado (si se envió Bearer).',
    error_title: 'Error',
    err_invalid_email: 'Email inválido.',
    err_not_allowlisted: 'Email no autorizado (allowlist).',
    err_not_authorized: 'Email no autorizado.',
    err_session_expired: 'Sesión expirada. Pide un código nuevo.',
    err_code_invalid: 'Código inválido. Inténtalo de nuevo.',
    err_attempts: 'Límite de intentos. Pide un código nuevo.',
    err_missing_client: 'Falta client_id',
    err_redirect: 'redirect_uri no permitido',
    redirect_hint: 'Configura XID_REDIRECT_ALLOWLIST.',
    err_post_logout: 'post_logout_redirect_uri no permitido',
    password: 'Contraseña',
    password_ph: 'Tu contraseña',
    password_btn: 'Entrar con contraseña',
    password_for: 'Iniciando sesión como',
    use_code_link: 'Usar código por email',
    use_password_link: 'Usar contraseña',
    err_invalid_password: 'Contraseña inválida.',
  },
}

function pickLang(request, params) {
  const fromParam = String(params?.ui_locales || '')
    .split(/[\s_+,;]+/)
    .map((s) => s.toLowerCase().split('-')[0])
    .find((s) => s === 'en' || s === 'es')
  if (fromParam) return fromParam
  const header = request?.headers?.get('accept-language') || ''
  for (const part of header.split(',')) {
    const tag = part.split(';')[0].trim().toLowerCase().split('-')[0]
    if (tag === 'en' || tag === 'es') return tag
  }
  return 'en'
}

const t = (lang, key) => (STRINGS[lang] || STRINGS.en)[key] || key

function cuiScript() {
  return `<script type="module" src="${esc(cuiUrl())}"></script>`
}

// Puente mínimo CUI ↔ formulario nativo:
// - `as-input` no es form-associated: al enviar se copian sus valores a hidden.
// - `as-button` emite `button-tap`: dispara el submit del formulario.
// - Fallback: si el bundle CUI no carga, se sustituyen por input/button nativos.
const CUI_BRIDGE = `<script>
(function(){
  function ensureHidden(form, name, value) {
    var h = form.querySelector('input[type="hidden"][name="' + name + '"]');
    if (!h) { h = document.createElement('input'); h.type = 'hidden'; h.name = name; form.appendChild(h); }
    if (value !== undefined) h.value = value;
    return h;
  }
  function sync(form) {
    form.querySelectorAll('as-input[name]').forEach(function (el) {
      ensureHidden(form, el.getAttribute('name'), el.getAttribute('value') || '');
    });
  }
  function fallback() {
    document.querySelectorAll('as-input').forEach(function (el) {
      var i = document.createElement('input');
      i.name = el.getAttribute('name') || ''; i.type = el.getAttribute('kind') || 'text';
      i.placeholder = el.getAttribute('placeholder') || ''; i.value = el.getAttribute('value') || '';
      i.required = true; i.setAttribute('aria-label', el.getAttribute('label') || i.name);
      el.replaceWith(i);
    });
    document.querySelectorAll('as-button').forEach(function (el) {
      var b = document.createElement('button'); b.type = 'submit'; b.textContent = el.getAttribute('label') || 'Enviar';
      el.replaceWith(b);
    });
  }
  function ready() {
    var ok = window.customElements && customElements.get('as-input') && customElements.get('as-button') && customElements.get('as-box');
    if (!ok) { fallback(); return; }
    document.querySelectorAll('form[data-cui]').forEach(function (f) {
      var b = f.querySelector('as-button');
      if (b) b.addEventListener('button-tap', function () { f.requestSubmit(); });
      f.addEventListener('submit', function (ev) {
        sync(f);
        var empty = false;
        f.querySelectorAll('as-input[name]').forEach(function (el) {
          if (!((el.getAttribute('value') || '').trim())) empty = true;
        });
        if (empty) ev.preventDefault();
      });
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { setTimeout(ready, 400); });
  else setTimeout(ready, 400);
})();
</script>`

function pageShell(title, inner, env, lang = 'en') {
  return `<!doctype html><html lang="${lang === 'es' ? 'es' : 'en'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>` +
    cuiScript() +
    `<style>html,body{margin:0;padding:0}body{font-family:system-ui,sans-serif;background:#0f172a;color:#e5e7eb;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem;box-sizing:border-box}.wrap{width:100%;max-width:24rem}as-box h1{font-size:1.25rem;margin:0 0 .25rem;color:#111827}as-box .muted{color:#6b7280;font-size:.85rem}as-box .err{background:#fde7e7;border:1px solid #f3b4b4;color:#7f1d1d;padding:.6rem .8rem;border-radius:.4rem}as-box a{color:#1d4ed8}as-box as-button{display:block;margin-top:.9rem}as-box input[type=text],as-box input[type=email]{font-size:1rem;padding:.55rem .7rem;width:100%;box-sizing:border-box;margin-top:.5rem}as-box button[type=submit]{font-size:1rem;padding:.55rem 1rem;width:100%;box-sizing:border-box;cursor:pointer;margin-top:.9rem}</style></head><body><div class="wrap"><as-box>${inner}</as-box></div>${CUI_BRIDGE}</body></html>`

}

function hiddenFields(params) {
  return Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join('')
}

function emailForm(oauth, { errorKey = '', email = '', env = {}, lang = 'en' } = {}) {
  return pageShell(
    t(lang, 'sign_in'),
    `<h1>${esc(t(lang, 'sign_in'))}</h1>` +
      (errorKey ? `<p class="err">${esc(t(lang, errorKey))}</p>` : '') +
      `<form method="post" data-cui>` +
      hiddenFields(oauth) +
      `<as-input name="email" kind="email" label="${esc(t(lang, 'email'))}" placeholder="${esc(t(lang, 'email_ph'))}" value="${esc(email)}"></as-input>` +
      `<as-button label="${esc(t(lang, 'send_code'))}" variant="primary"></as-button></form>` +
      `<p class="muted">${esc(t(lang, 'otp_hint'))}</p>`,
    env,
    lang
  )
}

// Sin input de email redundante: el email viaja en hidden (prefijado por el
// servidor) y se muestra como texto ("Código enviado a …" / "Code sent to …").
function codeForm(oauth, { errorKey = '', email = '', otpSession = '', sentTo = '', switchUrl = '', env = {}, lang = 'en' } = {}) {
  return pageShell(
    t(lang, 'verify_code'),
    `<h1>${esc(t(lang, 'verify_code'))}</h1>` +
      (errorKey ? `<p class="err">${esc(t(lang, errorKey))}</p>` : '') +
      `<p class="muted">${esc(t(lang, 'code_sent_to'))} ${esc(sentTo || maskEmail(email))}.</p>` +
      `<form method="post" data-cui>` +
      hiddenFields({ ...oauth, otp_session: otpSession }) +
      `<input type="hidden" name="email" value="${esc(email)}">` +
      `<as-input name="code" kind="text" label="${esc(t(lang, 'code_label'))}" placeholder="${esc(t(lang, 'code_ph'))}" value=""></as-input>` +
      `<as-button label="${esc(t(lang, 'verify_btn'))}" variant="primary"></as-button></form>` +
      (switchUrl ? `<p class="muted"><a href="${esc(switchUrl)}">${esc(t(lang, 'use_password_link'))}</a></p>` : ''),
    env,
    lang
  )
}

// Login con password real (bcrypt). Alternativa al OTP; el link cambia a OTP
// (fallback ante olvido) sin perder los parámetros OAuth.
function passwordForm(oauth, { errorKey = '', email = '', otpSession = '', switchUrl = '', env = {}, lang = 'en' } = {}) {
  return pageShell(
    t(lang, 'sign_in'),
    `<h1>${esc(t(lang, 'sign_in'))}</h1>` +
      (errorKey ? `<p class="err">${esc(t(lang, errorKey))}</p>` : '') +
      `<p class="muted">${esc(t(lang, 'password_for'))} ${esc(email)}.</p>` +
      `<form method="post" data-cui>` +
      hiddenFields({ ...oauth, otp_session: otpSession }) +
      `<input type="hidden" name="email" value="${esc(email)}">` +
      `<as-input name="password" kind="password" label="${esc(t(lang, 'password'))}" placeholder="${esc(t(lang, 'password_ph'))}" value=""></as-input>` +
      `<as-button label="${esc(t(lang, 'password_btn'))}" variant="primary"></as-button></form>` +
      (switchUrl ? `<p class="muted"><a href="${esc(switchUrl)}">${esc(t(lang, 'use_code_link'))}</a></p>` : ''),
    env,
    lang
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
    ui_locales: query.ui_locales || '',
    mode: query.mode === 'password' || query.mode === 'otp' ? query.mode : '',
  }
}

// URL del propio authorize para los links de cambio password ⇄ OTP.
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
  const origin = originOf(c.req.raw)
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

  // Paso 1: solo email → según el usuario y el modo: password (sin mail),
  // OTP (con mail) o legado estático (sin mail, sin password).
  if (!code && !password) {
    const user = await getUser(env, email)
    await sleep(180 + Math.floor(Math.random() * 220))
    if (!user) return c.html(emailForm(oauth, { errorKey: 'err_not_allowlisted', email, env, lang }), 403)
    const session = await issueOtpSession(env, email)
    const legacy = !!user.otpKeyHash && !user.passwordHash
    if (legacy) {
      return c.html(codeForm(oauth, { email, otpSession: session, sentTo: maskEmail(email), env, lang }))
    }
    if (user.passwordHash && oauth.mode !== 'otp') {
      return c.html(
        passwordForm(oauth, {
          email,
          otpSession: session,
          switchUrl: authorizeUrl(origin, tenant, { ...oauth, mode: 'otp', email }),
          env,
          lang,
        })
      )
    }
    const { code: otp } = await startOtp(env, email)
    const msg = makeOtpMessage(otp, email, lang)
    await sendMail(env, { to: email, subject: msg.subject, text: msg.text, code: msg.code })
    return c.html(
      codeForm(oauth, {
        email,
        otpSession: session,
        sentTo: maskEmail(email),
        switchUrl: user.passwordHash
          ? authorizeUrl(origin, tenant, { ...oauth, mode: 'password', email })
          : '',
        env,
        lang,
      })
    )
  }

  // Paso 2: verifica password (bcrypt) o código → emite authorization code.
  const user = await getUser(env, email)
  if (!user) return c.html(emailForm(oauth, { errorKey: 'err_not_authorized', email, env, lang }), 403)
  const sessionPayload = await verifyOtpSession(env, otpSession)
  const switchToPassword = user.passwordHash
    ? authorizeUrl(origin, tenant, { ...oauth, mode: 'password', email })
    : ''
  const switchToOtp = user.passwordHash
    ? authorizeUrl(origin, tenant, { ...oauth, mode: 'otp', email })
    : ''
  if (!sessionPayload || sessionPayload.sub !== email) {
    return c.html(codeForm(oauth, { errorKey: 'err_session_expired', email, otpSession: '', switchUrl: switchToPassword, env, lang }), 400)
  }
  if (password) {
    if (!user.passwordHash) {
      return c.html(passwordForm(oauth, { errorKey: 'err_not_authorized', email, otpSession, switchUrl: switchToOtp, env, lang }), 400)
    }
    if (!(await checkPasswordRateLimit(env, email))) {
      return c.html(passwordForm(oauth, { errorKey: 'err_attempts', email, otpSession, switchUrl: switchToOtp, env, lang }), 400)
    }
    if (!(await verifyPassword(password, user.passwordHash))) {
      return c.html(passwordForm(oauth, { errorKey: 'err_invalid_password', email, otpSession, switchUrl: switchToOtp, env, lang }), 400)
    }
  } else {
    const ok = await verifyOtp(env, email, code, user)
    if (!ok) {
      const left = await otpAttemptsLeft(env, email)
      const errorKey = left <= 0 ? 'err_attempts' : 'err_code_invalid'
      return c.html(codeForm(oauth, { errorKey, email, otpSession, switchUrl: switchToPassword, env, lang }), 400)
    }
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
    // B2B máquina-a-máquina: sin usuario, sin OTP. Auth por Basic o body.
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
    const origin = originOf(c.req.raw)
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
  return c.json({ error: 'unsupported_grant_type', error_description: 'usa authorization_code, refresh_token o client_credentials' }, 400)
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
  if (!user) {
    if (payload.client_id && payload.client_id === payload.sub && (await getClient(env, payload.sub))) {
      return c.json({ error: 'invalid_token', error_description: 'machine tokens carry no user identity (present access_token to resource APIs)' }, 401)
    }
    return c.json({ error: 'invalid_token', error_description: 'user no longer authorized' }, 401)
  }
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

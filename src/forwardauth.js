// Forward-auth endpoint for reverse proxies (Caddy `forward_auth`).
// Validates the xid_session cookie (or a Bearer token) and answers:
//   200 + Remote-* headers  -> the proxy copies them to the upstream app
//   401                     -> API clients (no redirect)
//   302 to /login (or XID_LOGIN_URL) -> browsers, with ?next=<path>

import { verifyAccessToken } from './session.js'
import { getUser } from './users.js'
import { defaultRole, isValidRole } from './roles.js'
import { cookieValue } from './cookies.js'
import { safeNext } from './util.js'

function bearerToken(request) {
  const header = request?.headers?.get('authorization') || ''
  const m = /^Bearer\s+(.+)$/i.exec(header)
  return m ? m[1] : null
}

// Header values must never contain CR/LF (response splitting).
function headerSafe(value) {
  return String(value ?? '').replace(/[\r\n]+/g, ' ').trim()
}

function publicOrigin(request) {
  const proto = (request.headers.get('x-forwarded-proto') || 'http').split(',')[0].trim()
  const host = (request.headers.get('x-forwarded-host') || request.headers.get('host') || '')
    .split(',')[0]
    .trim()
  return host ? `${proto}://${host}` : new URL(request.url).origin
}

function loginRedirect(env, request) {
  const base = env.XID_LOGIN_URL || process.env.XID_LOGIN_URL || '/login'
  let target
  try {
    target = new URL(base, publicOrigin(request))
  } catch {
    return null
  }
  const next = safeNext(request.headers.get('x-forwarded-uri'))
  if (next) target.searchParams.set('next', next)
  return target.toString()
}

export async function handleForwardAuth(c) {
  const env = c.env || {}
  const request = c.req.raw
  const token = bearerToken(request) || cookieValue(request, 'xid_session')
  const payload = token ? await verifyAccessToken(env, token) : null
  const user = payload?.sub ? await getUser(env, payload.sub) : null

  if (!user) {
    const accept = request.headers.get('accept') || ''
    const redirect = accept.includes('text/html') ? loginRedirect(env, request) : null
    if (redirect) return c.redirect(redirect, 302)
    return c.json({ error: 'unauthorized' }, 401, { 'WWW-Authenticate': 'Bearer' })
  }

  const role = isValidRole(user.role) ? String(user.role).trim().toLowerCase() : defaultRole(env)
  c.header('Cache-Control', 'no-store')
  c.header('Remote-User', headerSafe(user.email))
  c.header('Remote-Email', headerSafe(user.email))
  c.header('Remote-Name', headerSafe(user.email.split('@')[0]))
  c.header('Remote-Role', headerSafe(role))
  c.header('Remote-Groups', headerSafe(role))
  return c.body(null, 200)
}

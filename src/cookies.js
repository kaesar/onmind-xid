// Session cookie helpers shared by the Cognito API, the login page and
// forward-auth. `XID_COOKIE_DOMAIN` is optional (parent domain for subdomains).

export function cookieDomain(env) {
  const raw = String(env?.XID_COOKIE_DOMAIN || process.env.XID_COOKIE_DOMAIN || '').trim()
  if (!raw) return ''
  const host = raw.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].trim()
  // Keep it to a cookie-domain shape (no CR/LF or header injection).
  return /^\.?[A-Za-z0-9.-]+$/.test(host) ? `; Domain=${host}` : ''
}

export function sessionCookie(token, env) {
  if (!token) return null
  const secure = (env?.XID_ENV || process.env.XID_ENV) === 'production' ? '; Secure' : ''
  return `xid_session=${token}; HttpOnly; SameSite=Lax; Path=/${cookieDomain(env)}; Max-Age=3600${secure}`
}

export function cookieValue(request, name) {
  const cookie = request?.headers?.get('cookie') || ''
  const m = new RegExp(`(?:^|;\\s*)${name}=([^;\\s]+)`).exec(cookie)
  if (!m) return null
  try {
    return decodeURIComponent(m[1])
  } catch {
    return m[1]
  }
}

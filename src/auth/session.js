import { createRequire } from 'node:module'
import { base64UrlDecode, base64urlEncode, constantTimeEqual } from '../util/common.js'
import { kvDelete, kvGet, kvPut } from '../store/kv.js'
import { getRole } from '../service/users.js'
import { signRs256, verifyRs256 } from './keys.js'

const require = createRequire(import.meta.url)

// JWT without libraries (crypto.subtle): access/id RS256 with JWKS, OTP session HMAC.
// RS256 uses XID_RSA_PRIVATE_JWK; XID_JWT_SECRET only signs the OTP session.

const ISS = 'xid'
const ACCESS_TTL = 3600 // s (~1 h)
const OTP_SESSION_TTL = 300 // s

export function requireSecret(env) {
  const secret = (env && env.XID_JWT_SECRET) || process.env.XID_JWT_SECRET
  if (!secret || secret.length < 32) {
    throw new Error('XID_JWT_SECRET must be >= 32 bytes')
  }
  return secret
}

async function hmacBytes(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))
  return new Uint8Array(sig)
}

function b64uDecode(input) {
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

export async function signToken(payload, secret, header) {
  const head = header || { alg: 'HS256', typ: 'JWT' }
  const headB64 = base64urlEncode(JSON.stringify(head))
  const payB64 = base64urlEncode(JSON.stringify(payload))
  const data = `${headB64}.${payB64}`
  const sig = b64uEncode(await hmacBytes(secret, data))
  return `${data}.${sig}`
}

function b64uEncode(bytes) {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function decodeToken(token) {
  const parts = String(token || '').split('.')
  if (parts.length !== 3) return null
  try {
    return JSON.parse(base64UrlDecode(parts[1]))
  } catch {
    return null
  }
}

export async function verifyToken(token, secret) {
  const parts = String(token || '').split('.')
  if (parts.length !== 3) return null
  const data = `${parts[0]}.${parts[1]}`
  const expected = b64uEncode(await hmacBytes(secret, data))
  if (!bytesEqual(b64uDecode(expected), b64uDecode(parts[2]))) return null
  const payload = JSON.parse(base64UrlDecode(parts[1]))
  if (!payload.exp || payload.exp * 1000 <= Date.now()) return null
  return payload
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

export async function issueTokens(env, email, clientId) {
  const now = Math.floor(Date.now() / 1000)
  const exp = now + ACCESS_TOKEN_TTL
  const jti = crypto.randomUUID()
  const role = await getRole(env, email)
  const access = await signRs256(env, {
    sub: email,
    token_use: 'access',
    role,
    roles: [role],
    iss: ISS,
    aud: clientId,
    iat: now,
    exp,
    jti,
  })
  const id = await signRs256(env, {
    sub: email,
    token_use: 'id',
    email,
    email_verified: true,
    role,
    roles: [role],
    iss: ISS,
    aud: clientId,
    iat: now,
    exp,
  })
  return {
    AccessToken: access,
    IdToken: id,
    TokenType: 'Bearer',
    ExpiresIn: ACCESS_TOKEN_TTL,
  }
}

export async function issueOtpSession(env, email) {
  const secret = requireSecret(env)
  const now = Math.floor(Date.now() / 1000)
  return signToken(
    {
      sub: email,
      typ: 'otp_session',
      iss: ISS,
      iat: now,
      exp: now + OTP_SESSION_TTL,
      jti: crypto.randomUUID(),
    },
    secret
  )
}

export async function verifyOtpSession(env, session) {
  const secret = requireSecret(env)
  const payload = await verifyToken(session, secret)
  if (!payload || payload.typ !== 'otp_session') return null
  return payload
}

// Verifies an access token (signature + expiry + denylist) and returns the payload.
// RS256 is the current format; HS256 is accepted for tokens issued before v1.
export async function verifyAccessToken(env, token) {
  const rs = await verifyRs256(env, token)
  if (rs) {
    if (rs.token_use !== 'access') return null
    if (rs.jti && (await kvGet(env, `sess:${rs.jti}`))) return null
    return rs
  }
  let secret
  try {
    secret = requireSecret(env)
  } catch {
    return null
  }
  const payload = await verifyToken(token, secret)
  if (!payload || payload.token_use !== 'access') return null
  const denied = await kvGet(env, `sess:${payload.jti}`)
  if (denied) return null
  return payload
}

export async function denyJti(env, jti, expSec) {
  const ttl = Math.max(0, expSec - Math.floor(Date.now() / 1000))
  if (ttl <= 0) return
  await kvPut(env, `sess:${jti}`, '1', ttl)
}

// ---------------- Refresh tokens (Cognito facade) ----------------
// Opaque (256 bits), single use with rotation on every use, sliding TTL.
// Per-user index so GlobalSignOut can revoke them all (best-effort).

const REFRESH_TOKEN_TTL = 30 * 86400 // 30 d
const MAX_REFRESH_PER_USER = 20

const refreshKey = (token) => `cognito-refresh:${token}`
const refreshIndexKey = (email) => `cognito-refresh-by-user:${email}`

function randomB64Url(nbytes) {
  const bytes = crypto.getRandomValues(new Uint8Array(nbytes))
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function issueRefreshToken(env, email, clientId) {
  const token = randomB64Url(32)
  await kvPut(env, refreshKey(token), { email, clientId }, REFRESH_TOKEN_TTL)
  try {
    const idx = (await kvGet(env, refreshIndexKey(email))) || []
    idx.push(token)
    await kvPut(env, refreshIndexKey(email), idx.slice(-MAX_REFRESH_PER_USER), REFRESH_TOKEN_TTL)
  } catch {
    // best-effort: the individual token was already stored
  }
  return token
}

// Single use: returns { email, clientId } or null (missing or already used).
export async function consumeRefreshToken(env, token) {
  if (!token || typeof token !== 'string') return null
  const rec = await kvGet(env, refreshKey(token))
  if (!rec || !rec.email) return null
  await kvDelete(env, refreshKey(token))
  try {
    const idx = (await kvGet(env, refreshIndexKey(rec.email))) || []
    const rest = idx.filter((t) => t !== token)
    if (rest.length !== idx.length) await kvPut(env, refreshIndexKey(rec.email), rest, REFRESH_TOKEN_TTL)
  } catch {
    // best-effort
  }
  return rec
}

export async function revokeUserRefreshTokens(env, email) {
  if (!email) return
  try {
    const idx = (await kvGet(env, refreshIndexKey(email))) || []
    for (const t of idx) {
      try {
        await kvDelete(env, refreshKey(t))
      } catch {
        // best-effort per token
      }
    }
    await kvDelete(env, refreshIndexKey(email))
  } catch {
    // best-effort: logout must not fail because of this
  }
}

// Full Cognito triple: Access + Id + Refresh (with rotation on every use).
export async function issueTokenSet(env, email, clientId) {
  const base = await issueTokens(env, email, clientId)
  const refreshToken = await issueRefreshToken(env, email, clientId)
  return { ...base, RefreshToken: refreshToken }
}

const ACCESS_TOKEN_TTL = ACCESS_TTL
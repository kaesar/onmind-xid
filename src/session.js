import { createRequire } from 'node:module'
import { base64UrlDecode, base64urlEncode, constantTimeEqual } from './util.js'
import { kvGet, kvPut } from './kv.js'

const require = createRequire(import.meta.url)

// JWT HMAC-SHA256 sin librerías (crypto.subtle, funciona en Bun y Workers).
// Tipos de token: access / id (usuario) y otp_session (challenge).

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
  const secret = requireSecret(env)
  const now = Math.floor(Date.now() / 1000)
  const exp = now + ACCESS_TOKEN_TTL
  const jti = crypto.randomUUID()
  const access = await signToken(
    {
      sub: email,
      token_use: 'access',
      iss: ISS,
      aud: clientId,
      iat: now,
      exp,
      jti,
    },
    secret
  )
  const id = await signToken(
    {
      sub: email,
      token_use: 'id',
      email,
      email_verified: true,
      iss: ISS,
      aud: clientId,
      iat: now,
      exp,
    },
    secret
  )
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

// Verifica un access token (firma + expiración + denylist) y devuelve payload.
export async function verifyAccessToken(env, token) {
  const secret = requireSecret(env)
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

const ACCESS_TOKEN_TTL = ACCESS_TTL
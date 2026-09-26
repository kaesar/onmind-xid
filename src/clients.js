// Shared machine-client registry (B2B, client_credentials) for both facades:
// Entra ID (/{tenant}/oauth2/v2.0/token) and Cognito (POST /oauth2/token).
// Does not touch the user/allowlist registry: different identities (services).
//
// Dual storage, same as users.js:
//   - Local: xclients.txt → `client_id:client_secret:scope1,scope2` (dev secrets).
//   - Prod: KV XID_CLIENTS → { secretHash, scopes } (hashes only, never secrets).
// Hash: sha256(salt + ':' + secret), salt = sha256('xid-client:' + client_id).
// Constant-time comparison; secrets are never logged.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { sha256Hex, constantTimeEqual } from './util.js'
import { kvGet, kvPut, kvIncr } from './kv.js'
import { signRs256 } from './entra-keys.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const defaultsTxtPath = path.resolve(__dirname, '..', 'xclients.txt')

export const FILES_READ_SCOPE = 'files.read'
export const MACHINE_TOKEN_TTL = 3600 // s (1 h, same as user tokens)

const RATE_M2M_PER_CLIENT = 30
const RATE_M2M_PER_IP = 100
const RATE_WINDOW = 900 // s (15 min)

export function isValidClientId(id) {
  return /^[A-Za-z0-9._-]{1,64}$/.test(String(id || ''))
}

export function isValidScope(s) {
  return /^[A-Za-z0-9._:-]{1,64}$/.test(String(s || ''))
}

export function parseScopes(raw) {
  return String(raw || '')
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter((s) => s && isValidScope(s))
}

export async function clientSalt(clientId) {
  return sha256Hex(`xid-client:${String(clientId).trim().toLowerCase()}`)
}

export async function hashSecret(clientId, secret) {
  const salt = await clientSalt(clientId)
  return sha256Hex(`${salt}:${secret}`)
}

async function parseTxt(text) {
  const clients = new Map()
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    const parts = line.split(':')
    if (parts.length < 2) continue
    const id = parts[0].trim()
    const secret = parts[1]
    const scopes = parseScopes(parts.slice(2).join(':'))
    if (!isValidClientId(id) || !secret) continue
    clients.set(id, {
      clientId: id,
      secretHash: await hashSecret(id, secret),
      scopes,
    })
  }
  return clients
}

let txtCache = null
let txtCacheAt = 0

function txtPath(env) {
  const configured = env?.XID_CLIENTS_TXT || process.env.XID_CLIENTS_TXT
  return configured ? path.resolve(configured) : defaultsTxtPath
}

async function loadTxt(env) {
  const file = txtPath(env)
  if (!fs.existsSync(file)) return new Map()
  const stat = fs.statSync(file)
  if (txtCache && txtCache.file === file && stat.mtimeMs <= txtCacheAt) return txtCache.users
  const users = await parseTxt(fs.readFileSync(file, 'utf-8'))
  txtCache = { file, users }
  txtCacheAt = stat.mtimeMs
  return users
}

export async function getClient(env, rawId) {
  const id = String(rawId || '').trim()
  if (!isValidClientId(id)) return null
  const kv = env?.XID_CLIENTS
  if (kv && typeof kv.get === 'function') {
    const raw = await kv.get(id, 'json')
    if (!raw) return null
    return { clientId: raw.clientId || id, secretHash: raw.secretHash || null, scopes: raw.scopes || [] }
  }
  const clients = await loadTxt(env)
  return clients.get(id) || null
}

export async function verifyClientSecret(client, secret) {
  if (!client?.secretHash || typeof secret !== 'string' || !secret) return false
  const hash = await hashSecret(client.clientId, secret)
  return constantTimeEqual(hash, client.secretHash)
}

// Scope subset: everything requested must be granted to the client.
export function scopesAllowed(requested, allowed) {
  const allow = new Set(allowed || [])
  return (requested || []).every((s) => allow.has(s))
}

// Anti-brute-force rate limit on secrets (per client and per IP).
export async function checkM2mRateLimit(env, clientId, ip) {
  const c = await kvIncr(env, `rl:m2m:${clientId}`, RATE_WINDOW)
  const n = await kvIncr(env, `rl:m2mip:${ip || 'local'}`, RATE_WINDOW)
  return c <= RATE_M2M_PER_CLIENT && n <= RATE_M2M_PER_IP
}

export function ipOf(request) {
  const h = request?.headers
  // Cloudflare → cf-connecting-ip; Lambda/API Gateway → first IP of x-forwarded-for.
  return (
    h?.get('cf-connecting-ip') ||
    (h?.get('x-forwarded-for') || '').split(',')[0].trim() ||
    'local'
  )
}

// Basic base64(client_id:client_secret). IDs and secrets are ASCII.
export function parseBasicAuth(request) {
  const header = request?.headers?.get('authorization') || ''
  const m = /^Basic\s+(.+)$/i.exec(header.trim())
  if (!m) return null
  try {
    const bin = atob(m[1].trim())
    const sep = bin.indexOf(':')
    if (sep <= 0) return null
    return { clientId: bin.slice(0, sep), clientSecret: bin.slice(sep + 1) }
  } catch {
    return null
  }
}

function randomJti() {
  return typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : String(Date.now())
}

// Issues the machine access token (RS256). sub = client_id; no user identity.
export async function issueMachineToken(env, { clientId, scope, iss, tid }) {
  const now = Math.floor(Date.now() / 1000)
  const jti = randomJti()
  const scp = scope || ''
  const payload = {
    iss,
    aud: clientId,
    sub: clientId,
    client_id: clientId,
    token_use: 'access',
    scp,
    scope: scp,
    iat: now,
    exp: now + MACHINE_TOKEN_TTL,
    jti,
  }
  if (tid) payload.tid = tid
  return {
    token: await signRs256(env, payload),
    expiresIn: MACHINE_TOKEN_TTL,
    scope: scp,
  }
}

export { parseTxt }

import path from 'node:path'
import { verifyAccessToken } from './session.js'
import { verifyRs256 } from './entra-keys.js'
import { kvGet } from './kv.js'
import { getUser } from './users.js'
import { getClient, FILES_READ_SCOPE } from './clients.js'

// GET autenticado de ficheros de artículos hide:2.
// Auth: Bearer o cookie `xid_session`. Path seguro (rechaza .., absolutos, \).

let fsMod = null
async function lazyFs() {
  if (!fsMod) fsMod = await import('node:fs/promises')
  return fsMod
}

function cookieToken(request) {
  const cookie = request?.headers?.get('cookie') || ''
  const m = /(?:^|;\s*)xid_session=([^;\s]+)/.exec(cookie)
  return m ? decodeURIComponent(m[1]) : null
}

function normalizeRelPath(raw) {
  const decoded = String(raw || '').normalize('NFC').replace(/\\/g, '/')
  const clean = decoded.split('/').map((seg) => decodeURIComponent(seg)).join('/')
  const parts = []
  for (const seg of clean.split('/')) {
    if (!seg || seg === '.') continue
    if (seg === '..') return null
    parts.push(seg)
  }
  const rel = parts.join('/')
  if (!rel || rel.startsWith('/')) return null
  return rel
}

export async function getFileContent(env, request, rawPath) {
  const rel = normalizeRelPath(rawPath)
  if (!rel) return { status: 400, body: { error: 'invalid path' } }

  const token = bearerOrCookie(request)
  const payload = token ? await verifyAnyAccessToken(env, token) : null
  if (!payload) return { status: 401, body: { error: 'unauthorized' } }

  const user = await getUser(env, payload.sub)
  if (!user && !(await canMachineRead(env, payload))) {
    return { status: 403, body: { error: 'forbidden' } }
  }

  const kv = env?.XID_FILES
  if (kv && typeof kv.get === 'function') {
    const value = await kv.get(rel)
    if (value === null || value === undefined) return { status: 404, body: { error: 'not_found' } }
    return { status: 200, body: value, contentType: 'text/markdown; charset=utf-8' }
  }

  const root = path.resolve(env?.XID_FILES_ROOT || process.env.XID_FILES_ROOT || path.join(process.cwd(), 'files'))
  const full = path.resolve(root, rel)
  if (full !== root && !full.startsWith(root + path.sep)) {
    return { status: 404, body: { error: 'not_found' } }
  }
  try {
    const fs = await lazyFs()
    const stat = await fs.stat(full)
    if (!stat.isFile()) return { status: 404, body: { error: 'not_found' } }
    const text = await fs.readFile(full, 'utf-8')
    return { status: 200, body: text, contentType: 'text/markdown; charset=utf-8' }
  } catch (err) {
    if (err && err.code === 'ENOENT') return { status: 404, body: { error: 'not_found' } }
    throw err
  }
}

// Acepta access tokens de ambas fachadas: HS256 (Cognito) y RS256 (Entra).
// En ambos casos sub = email y se respeta la denylist de logout (sess:jti).
async function verifyAnyAccessToken(env, token) {
  try {
    const hs = await verifyAccessToken(env, token)
    if (hs) return hs
  } catch {
    // sin secreto HMAC válido: intenta RS256 igualmente
  }
  const rs = await verifyRs256(env, token)
  if (!rs || rs.sub == null) return null
  if (rs.jti && (await kvGet(env, `sess:${rs.jti}`))) return null
  return rs
}

// B2B: cliente máquina registrado cuyo token porta el scope files.read.
// El token máquina se distingue por client_id === sub (sin identidad de usuario).
function tokenScopes(payload) {
  const raw = payload.scp || payload.scope || ''
  return String(raw).split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
}

async function canMachineRead(env, payload) {
  if (!payload?.client_id || payload.client_id !== payload.sub) return false
  if (!tokenScopes(payload).includes(FILES_READ_SCOPE)) return false
  const client = await getClient(env, payload.sub)
  return !!(client && (client.scopes || []).includes(FILES_READ_SCOPE))
}

function bearerOrCookie(request) {
  const header = request?.headers?.get('authorization') || ''
  const m = /^Bearer\s+(.+)$/i.exec(header)
  if (m) return m[1]
  return cookieToken(request)
}
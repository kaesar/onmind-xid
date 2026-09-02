import path from 'node:path'
import { verifyAccessToken } from './session.js'
import { getUser } from './users.js'

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
  const payload = token ? await verifyAccessToken(env, token) : null
  if (!payload) return { status: 401, body: { error: 'unauthorized' } }

  const user = await getUser(env, payload.sub)
  if (!user) return { status: 403, body: { error: 'forbidden' } }

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

function bearerOrCookie(request) {
  const header = request?.headers?.get('authorization') || ''
  const m = /^Bearer\s+(.+)$/i.exec(header)
  if (m) return m[1]
  return cookieToken(request)
}
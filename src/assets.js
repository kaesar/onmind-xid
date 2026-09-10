// Assets públicos (sin auth) para las páginas de login: bundle OnMind-CUI (cui/).
//   - Local: vendor/cui/
//   - Worker: KV XID_FILES con key `cui/<file>` (misma KV de ficheros).

import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const vendorRoot = path.resolve(__dirname, '..', 'vendor', 'cui')

const CONTENT_TYPES = { '.js': 'text/javascript; charset=utf-8' }

let fsMod = null
async function lazyFs() {
  if (!fsMod) fsMod = await import('node:fs/promises')
  return fsMod
}

function safeRel(raw) {
  const clean = String(raw || '').replace(/\\/g, '/')
  const parts = []
  for (const seg of clean.split('/')) {
    if (!seg || seg === '.') continue
    if (seg === '..') return null
    parts.push(seg)
  }
  const rel = parts.join('/')
  if (!rel || rel.startsWith('/') || !rel.startsWith('cui/')) return null
  return rel
}

export const CUI_URL = '/cui/onmind-cui-v3.js'

export function cuiUrl() {
  return CUI_URL
}

export async function getAsset(env, rawPath) {
  const rel = safeRel(rawPath)
  if (!rel) return { status: 400, body: 'invalid path' }
  const ext = path.extname(rel)
  const contentType = CONTENT_TYPES[ext]
  if (!contentType) return { status: 404, body: 'not found' }

  const kv = env?.XID_FILES
  if (kv && typeof kv.get === 'function') {
    const value = await kv.get(rel)
    if (value === null || value === undefined) return { status: 404, body: 'not found' }
    return { status: 200, body: value, contentType }
  }
  const full = path.resolve(vendorRoot, rel.replace(/^cui\//, ''))
  if (full !== vendorRoot && !full.startsWith(vendorRoot + path.sep)) {
    return { status: 404, body: 'not found' }
  }
  try {
    const fs = await lazyFs()
    const text = await fs.readFile(full, 'utf-8')
    return { status: 200, body: text, contentType }
  } catch (err) {
    if (err && err.code === 'ENOENT') return { status: 404, body: 'not found' }
    throw err
  }
}

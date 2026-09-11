import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { isValidEmail, normalizeEmail, sha256Hex } from './util.js'
import { isBcryptHash } from './passwords.js'

// Store de usuarios allowlisted:
//  - Cloudflare: KV binding XID_USERS (key = email normalizado)
//  - Local: xusers.txt (cargado a memoria, re-parsed si cambia en disco)

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const defaultsTxtPath = path.resolve(__dirname, '..', 'xusers.txt')

let txtCache = null
let txtCacheAt = 0

async function parseTxt(text) {
  const users = new Map()
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    let emailRaw = line
    let staticKey = null
    const sep = line.indexOf(':')
    if (sep >= 0) {
      emailRaw = line.slice(0, sep)
      staticKey = line.slice(sep + 1)
    }
    const email = normalizeEmail(emailRaw)
    if (!isValidEmail(email)) continue

    // Segundo dato: hash bcrypt `$2b$` = password real (ver passwords.js).
    // cualquier otro valor = clave estática legada dev (SHA-256 al cargar).
    const passwordHash = staticKey && isBcryptHash(staticKey) ? staticKey : null
    users.set(email, {
      email,
      passwordHash,
      otpKeyHash: staticKey && !passwordHash ? await sha256Hex(staticKey) : null,
    })
  }
  return users
}

function txtPath(env) {
  const configured = env?.XID_USERS_TXT || process.env.XID_USERS_TXT
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

export function isKvMode(env) {
  const kv = env?.XID_USERS
  return !!(kv && typeof kv.get === 'function')
}

export async function getUser(env, rawEmail) {
  const email = normalizeEmail(rawEmail)
  const kv = env?.XID_USERS
  if (kv && typeof kv.get === 'function') {
    const raw = await kv.get(email, 'json')
    if (!raw) return null
    return {
      email: raw.email || email,
      passwordHash: raw.passwordHash || null,
      otpKeyHash: raw.otpKeyHash || null,
    }
  }
  const users = await loadTxt(env)
  return users.get(email) || null
}

// Dev: vuelca la allowlist (útil para logs/scripts sin revelar keys en claro).
export async function listUsers(env) {
  if (isKvMode(env)) return null // uso KV; listar requeriría list()
  const users = await loadTxt(env)
  return Array.from(users.values())
}

export { parseTxt }
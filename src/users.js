import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { isValidEmail, normalizeEmail, sha256Hex } from './util.js'
import { isBcryptHash } from './passwords.js'
import { ROLES, isValidRole, defaultRole } from './roles.js'

// Store de usuarios allowlisted:
//  - Cloudflare: KV binding XID_USERS (key = email normalizado)
//  - Local: xusers.txt (cargado a memoria, re-parsed si cambia en disco)
//
// Formato de línea local — `[role] email[:secret]`:
//   alice@example.com                  → OTP; rol por defecto (XID_DEFAULT_ROLE)
//   [owner] alice@example.com          → OTP; rol owner
//   [admin] bob@example.com:$2b$...    → password bcrypt; rol admin
//   [guest] carol@example.com:key      → clave estática dev; rol guest
//
// El tag `[role]` es opcional y va SIEMPRE delante del email, de modo que nunca
// colisiona con el secreto (todo lo que sigue al primer `:` es el secreto). El
// rol queda así en la misma línea que la identidad, igual que el campo `role`
// del registro KV/DynamoDB. Un tag desconocido descarta la línea (fail-soft).

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const defaultsTxtPath = path.resolve(__dirname, '..', 'xusers.txt')
const ROLE_TAG_RE = /^\[([^\]]*)\]\s*/

let txtCache = null
let txtCacheAt = 0

function txtPath(env) {
  const configured = env?.XID_USERS_TXT || process.env.XID_USERS_TXT
  return configured ? path.resolve(configured) : defaultsTxtPath
}

function readLines(file) {
  if (!fs.existsSync(file)) return []
  const lines = fs.readFileSync(file, 'utf-8').split('\n')
  while (lines.length && lines[lines.length - 1] === '') lines.pop()
  return lines
}

function writeAtomic(file, lines) {
  const body = lines.join('\n').replace(/\n+$/, '') + '\n'
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const tmp = `${file}.tmp-${process.pid}-${Date.now()}`
  fs.writeFileSync(tmp, body)
  fs.renameSync(tmp, file)
  txtCache = null
}

/**
 * Parsea `[role] email[:secret]`. Devuelve `{email, secret, role}` o null si la
 * línea es un comentario, está vacía o no es válida. `role` es null sin tag.
 */
export function parseUserLine(rawLine) {
  const line = String(rawLine || '').trim()
  if (!line || line.startsWith('#')) return null

  let rest = line
  let role = null
  const tag = ROLE_TAG_RE.exec(rest)
  if (tag) {
    role = tag[1].trim().toLowerCase()
    rest = rest.slice(tag[0].length).trim()
    if (!isValidRole(role)) return null
  }

  let emailRaw = rest
  let secret = null
  const sep = rest.indexOf(':')
  if (sep >= 0) {
    emailRaw = rest.slice(0, sep)
    secret = rest.slice(sep + 1)
  }
  const email = normalizeEmail(emailRaw)
  if (!isValidEmail(email)) return null
  return { email, secret, role }
}

/** Serializa una línea `[role] email[:secret]` (rol omitido si es falsy). */
export function formatUserLine(email, secret, role) {
  const tag = role ? `[${String(role).trim().toLowerCase()}] ` : ''
  return `${tag}${normalizeEmail(email)}${secret ? `:${secret}` : ''}`
}

async function recordOf({ email, secret, role }, env) {
  // Segundo dato: hash bcrypt `$2b$` = password real (ver passwords.js).
  // cualquier otro valor = clave estática legada dev (SHA-256 al cargar).
  const passwordHash = secret && isBcryptHash(secret) ? secret : null
  return {
    email,
    passwordHash,
    otpKeyHash: secret && !passwordHash ? await sha256Hex(secret) : null,
    role: role || defaultRole(env),
  }
}

async function parseTxt(text, env) {
  const users = new Map()
  for (const rawLine of text.split('\n')) {
    const parsed = parseUserLine(rawLine)
    if (!parsed) continue
    users.set(parsed.email, await recordOf(parsed, env))
  }
  return users
}

async function loadTxt(env) {
  const file = txtPath(env)
  if (!fs.existsSync(file)) return new Map()
  const stat = fs.statSync(file)
  if (txtCache && txtCache.file === file && stat.mtimeMs <= txtCacheAt) return txtCache.users
  const users = await parseTxt(fs.readFileSync(file, 'utf-8'), env)
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
      role: raw.role || null,
    }
  }
  const users = await loadTxt(env)
  return users.get(email) || null
}

// Dev: vuelca la allowlist (útil para logs/scripts sin revelar keys en claro).
export async function listUsers(env) {
  if (isKvMode(env)) return null // uso KV; listar requiere list()
  const users = await loadTxt(env)
  return Array.from(users.values())
}

// ---------------- roles (stored with the identity) ----------------

export async function getRole(env, rawEmail) {
  const email = normalizeEmail(rawEmail)
  if (!isValidEmail(email)) return defaultRole(env)
  const user = await getUser(env, email)
  const role = user?.role
  return isValidRole(role) ? String(role).trim().toLowerCase() : defaultRole(env)
}

export async function setRole(env, rawEmail, rawRole) {
  const email = normalizeEmail(rawEmail)
  const role = String(rawRole || '').trim().toLowerCase()
  if (!isValidEmail(email)) {
    const error = new Error('Invalid email')
    error.status = 400
    throw error
  }
  if (!isValidRole(role)) {
    const error = new Error(`Invalid role (use ${ROLES.join('|')})`)
    error.status = 400
    throw error
  }

  if (isKvMode(env)) {
    const raw = await env.XID_USERS.get(email, 'json')
    if (!raw) return null
    await env.XID_USERS.put(email, JSON.stringify({ ...raw, email, role }))
    return role
  }

  // Local: reescribe el tag de la línea del usuario (comentarios y orden intactos).
  const file = txtPath(env)
  if (!fs.existsSync(file)) return null
  let found = false
  const next = readLines(file).map((line) => {
    const parsed = parseUserLine(line)
    if (!parsed || parsed.email !== email) return line
    found = true
    return formatUserLine(parsed.email, parsed.secret, role)
  })
  if (!found) return null
  writeAtomic(file, next)
  return role
}

export { parseTxt }

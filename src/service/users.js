import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { isValidEmail, normalizeEmail, sha256Hex } from '../util/common.js'
import { isBcryptHash } from './passwords.js'
import { ROLES, isValidRole, defaultRole } from './roles.js'

// Allowlisted user store:
//  - Cloudflare: KV XID_USERS binding (key = normalized email)
//  - Local: xusers.txt (loaded into memory, re-parsed if it changes on disk)
//
// Local line format — `[role] email[:secret]`:
//   alice@example.com                  → OTP; default role (XID_DEFAULT_ROLE)
//   [owner] alice@example.com          → OTP; owner role
//   [admin] bob@example.com:$2b$...    → bcrypt password; admin role
//   [guest] carol@example.com:key      → dev static key; guest role
//
// The `[role]` tag is optional and ALWAYS comes before the email, so it never
// collides with the secret (everything after the first `:` is the secret). The
// role thus stays on the same line as the identity, like the `role` field of
// the KV/DynamoDB record. An unknown tag discards the line (fail-soft).

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const defaultsTxtPath = path.resolve(__dirname, '..', '..', 'xusers.txt')
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
 * Parses `[role] email[:secret]`. Returns `{email, secret, role}` or null if the
 * line is a comment, empty, or invalid. `role` is null without a tag.
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

/** Serializes a `[role] email[:secret]` line (role omitted if falsy). */
export function formatUserLine(email, secret, role) {
  const tag = role ? `[${String(role).trim().toLowerCase()}] ` : ''
  return `${tag}${normalizeEmail(email)}${secret ? `:${secret}` : ''}`
}

async function recordOf({ email, secret, role }, env) {
  // Second field: bcrypt `$2b$` hash = real password (see passwords.js).
  // any other value = legacy dev static key (SHA-256 on load).
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

// Dev: dumps the allowlist (useful for logs/scripts without revealing plaintext keys).
export async function listUsers(env) {
  if (isKvMode(env)) return null // KV mode; listing requires list()
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

  // Local: rewrites the user's line tag (comments and order preserved).
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

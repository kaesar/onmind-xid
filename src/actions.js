// Admin storage helpers for the /admin API (users + machine clients).
//
// Same dual backend as users.js / clients.js:
//   - Local: xusers.txt / xclients.txt (comments preserved, atomic rewrite).
//     A user's role is the optional `[role]` tag of its xusers.txt line.
//   - KV (Cloudflare) or DynamoDB: bindings XID_USERS / XID_CLIENTS (`role` is
//     a field of the user record).
//
// This module never exposes secrets: user records carry hashes only, and client
// secrets are returned once by admin.js at creation/rotation time.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { isValidEmail, normalizeEmail } from './util.js'
import {
  hashSecret,
  isValidClientId,
  isValidScope,
  parseScopes,
} from './clients.js'
import { defaultRole } from './roles.js'
import { listUsers, parseUserLine } from './users.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const defaultUsersPath = path.resolve(__dirname, '..', 'xusers.txt')
const defaultClientsPath = path.resolve(__dirname, '..', 'xclients.txt')

function usersPath(env) {
  const configured = env?.XID_USERS_TXT || process.env.XID_USERS_TXT
  return configured ? path.resolve(configured) : defaultUsersPath
}

function clientsPath(env) {
  const configured = env?.XID_CLIENTS_TXT || process.env.XID_CLIENTS_TXT
  return configured ? path.resolve(configured) : defaultClientsPath
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
}

function userLineEmail(line) {
  return parseUserLine(line)?.email || null
}

function clientLineId(line) {
  const trimmed = line.trim()
  if (!trimmed || trimmed.startsWith('#')) return null
  const parts = trimmed.split(':')
  if (parts.length < 2) return null
  const id = parts[0].trim()
  return isValidClientId(id) ? id : null
}

/**
 * Generic KV listing that works with Cloudflare KV (`list({prefix,cursor})`)
 * and with our DynamoDB adapter (same duck-typed contract).
 */
async function kvListKeys(binding, prefix = '') {
  const keys = []
  let cursor
  do {
    const page = await binding.list(cursor ? { prefix, cursor } : { prefix })
    for (const key of page?.keys || []) keys.push(typeof key === 'string' ? key : key.name)
    cursor = page?.list_complete === false ? page.cursor : undefined
  } while (cursor)
  return keys
}

function hasKvBinding(env, name) {
  const binding = env?.[name]
  return !!(binding && typeof binding.get === 'function' && typeof binding.put === 'function')
}

// ---------------- users ----------------

export async function listAdminUsers(env) {
  if (hasKvBinding(env, 'XID_USERS')) {
    const binding = env.XID_USERS
    const keys = await kvListKeys(binding)
    const users = []
    for (const key of keys.sort()) {
      const raw = await binding.get(key, 'json')
      if (!raw) continue
      users.push({
        email: raw.email || key,
        role: raw.role || defaultRole(env),
        passwordEnabled: !!raw.passwordHash,
        otpKeyEnabled: !!raw.otpKeyHash,
      })
    }
    return users
  }

  const users = []
  for (const user of (await listUsers(env)) || []) {
    if (!isValidEmail(user.email)) continue
    users.push({
      email: user.email,
      role: user.role || defaultRole(env),
      passwordEnabled: !!user.passwordHash,
      otpKeyEnabled: !!user.otpKeyHash,
    })
  }
  users.sort((a, b) => a.email.localeCompare(b.email))
  return users
}

export async function addAdminUser(env, rawEmail) {
  const email = normalizeEmail(rawEmail)
  if (!isValidEmail(email)) {
    const e = new Error('Invalid email')
    e.status = 400
    throw e
  }

  if (hasKvBinding(env, 'XID_USERS')) {
    const binding = env.XID_USERS
    if (await binding.get(email, 'json')) {
      const e = new Error(`${email} already exists`)
      e.status = 409
      throw e
    }
    const role = defaultRole(env)
    await binding.put(email, JSON.stringify({ email, passwordHash: null, otpKeyHash: null, role }))
    return { email, role, passwordEnabled: false, otpKeyEnabled: false }
  }

  const file = usersPath(env)
  const lines = readLines(file)
  if (lines.some((line) => userLineEmail(line) === email)) {
    const e = new Error(`${email} already exists`)
    e.status = 409
    throw e
  }
  lines.push(email)
  writeAtomic(file, lines)
  return { email, role: defaultRole(env), passwordEnabled: false, otpKeyEnabled: false }
}

export async function removeAdminUser(env, rawEmail) {
  const email = normalizeEmail(rawEmail)
  if (!isValidEmail(email)) {
    const e = new Error('Invalid email')
    e.status = 400
    throw e
  }

  if (hasKvBinding(env, 'XID_USERS')) {
    const binding = env.XID_USERS
    if (!(await binding.get(email))) return false
    await binding.delete(email)
    return true
  }

  const file = usersPath(env)
  const lines = readLines(file)
  const kept = lines.filter((line) => userLineEmail(line) !== email)
  if (kept.length === lines.length) return false
  writeAtomic(file, kept)
  return true
}

// ---------------- clients ----------------

function normalizeScopes(raw) {
  if (raw === undefined) return []
  if (!Array.isArray(raw)) {
    const e = new Error('scopes must be an array of strings')
    e.status = 400
    throw e
  }
  const scopes = parseScopes(raw.join(' '))
  if (scopes.length !== raw.length || !scopes.every(isValidScope)) {
    const e = new Error('Invalid scope')
    e.status = 400
    throw e
  }
  return scopes
}

export function generateClientSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  let bin = ''
  for (const byte of bytes) bin += String.fromCharCode(byte)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function listAdminClients(env) {
  if (hasKvBinding(env, 'XID_CLIENTS')) {
    const binding = env.XID_CLIENTS
    const keys = await kvListKeys(binding)
    const clients = []
    for (const key of keys.sort()) {
      const raw = await binding.get(key, 'json')
      if (!raw) continue
      clients.push({ clientId: raw.clientId || key, scopes: raw.scopes || [] })
    }
    return clients
  }

  const clients = []
  for (const line of readLines(clientsPath(env))) {
    const id = clientLineId(line)
    if (!id) continue
    const parts = line.trim().split(':')
    clients.push({ clientId: id, scopes: parseScopes(parts.slice(2).join(':')) })
  }
  clients.sort((a, b) => a.clientId.localeCompare(b.clientId))
  return clients
}

export async function createAdminClient(env, body = {}) {
  const clientId = String(body.clientId || '').trim()
  if (!isValidClientId(clientId)) {
    const e = new Error('Invalid clientId')
    e.status = 400
    throw e
  }
  const scopes = normalizeScopes(body.scopes)
  const secret = body.secret === undefined || body.secret === '' ? generateClientSecret() : String(body.secret)
  if (typeof secret !== 'string' || secret.length < 1) {
    const e = new Error('Invalid secret')
    e.status = 400
    throw e
  }

  if (hasKvBinding(env, 'XID_CLIENTS')) {
    const binding = env.XID_CLIENTS
    if (await binding.get(clientId, 'json')) {
      const e = new Error(`Client ${clientId} already exists`)
      e.status = 409
      throw e
    }
    const secretHash = await hashSecret(clientId, secret)
    await binding.put(clientId, JSON.stringify({ clientId, secretHash, scopes }))
    return { clientId, scopes, secret }
  }

  const file = clientsPath(env)
  const lines = readLines(file)
  if (lines.some((line) => clientLineId(line) === clientId)) {
    const e = new Error(`Client ${clientId} already exists`)
    e.status = 409
    throw e
  }
  lines.push([clientId, secret, scopes.join(',')].join(':'))
  writeAtomic(file, lines)
  return { clientId, scopes, secret }
}

export async function updateAdminClientScopes(env, clientId, rawScopes) {
  const scopes = normalizeScopes(rawScopes)

  if (hasKvBinding(env, 'XID_CLIENTS')) {
    const binding = env.XID_CLIENTS
    const raw = await binding.get(clientId, 'json')
    if (!raw) return null
    await binding.put(clientId, JSON.stringify({ ...raw, clientId, scopes }))
    return { clientId, scopes }
  }

  const file = clientsPath(env)
  const lines = readLines(file)
  let found = false
  const next = lines.map((line) => {
    if (clientLineId(line) !== clientId) return line
    found = true
    const parts = line.trim().split(':')
    return [parts[0].trim(), parts[1], scopes.join(',')].join(':')
  })
  if (!found) return null
  writeAtomic(file, next)
  return { clientId, scopes }
}

export async function rotateAdminClientSecret(env, clientId) {
  const secret = generateClientSecret()

  if (hasKvBinding(env, 'XID_CLIENTS')) {
    const binding = env.XID_CLIENTS
    const raw = await binding.get(clientId, 'json')
    if (!raw) return null
    const secretHash = await hashSecret(clientId, secret)
    await binding.put(clientId, JSON.stringify({ ...raw, clientId, secretHash }))
    return { clientId, scopes: raw.scopes || [], secret }
  }

  const file = clientsPath(env)
  const lines = readLines(file)
  let found = null
  const next = lines.map((line) => {
    if (clientLineId(line) !== clientId) return line
    found = line
    const parts = line.trim().split(':')
    return [parts[0].trim(), secret, parts.slice(2).join(':')].join(':')
  })
  if (!found) return null
  writeAtomic(file, next)
  const scopes = parseScopes(found.trim().split(':').slice(2).join(':'))
  return { clientId, scopes, secret }
}

export async function removeAdminClient(env, clientId) {
  if (hasKvBinding(env, 'XID_CLIENTS')) {
    const binding = env.XID_CLIENTS
    if (!(await binding.get(clientId))) return false
    await binding.delete(clientId)
    return true
  }

  const file = clientsPath(env)
  const lines = readLines(file)
  const kept = lines.filter((line) => clientLineId(line) !== clientId)
  if (kept.length === lines.length) return false
  writeAtomic(file, kept)
  return true
}

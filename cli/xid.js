#!/usr/bin/env bun
// Management CLI for OnMind-XID: users (xusers.txt) and machine clients
// (xclients.txt). Accepts arguments and, when missing, asks interactively
// with @clack/prompts. Never prints secrets except when creating/rotating.
// Usage:
//   bun cli/xid.js user add alice@example.com [--key abc123]
//   bun cli/xid.js user key bob@example.com --key new [--remove-key]
//   bun cli/xid.js user rm alice@example.com [--yes]
//   bun cli/xid.js user list
//   bun cli/xid.js client add svc-billing [--scopes files.read] [--secret ...]
//   bun cli/xid.js client scopes svc-billing --scopes files.read,other
//   bun cli/xid.js client rotate svc-billing
//   bun cli/xid.js client rm svc-billing [--yes]
//   bun cli/xid.js client list
// Global flags: --users <path> (def. XID_USERS_TXT or ./xusers.txt),
//   --clients <path> (def. XID_CLIENTS_TXT or ./xclients.txt).

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'
import * as p from '@clack/prompts'
import { hashPassword } from '../src/passwords.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(__dirname, '..')

// Without a TTY there is nothing to ask: fail fast instead of hanging.
const INTERACTIVE = !!process.stdin.isTTY

const isEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v || '').trim())
const isClientId = (v) => /^[A-Za-z0-9._-]{1,64}$/.test(String(v || '').trim())
const isScope = (v) => /^[A-Za-z0-9._:-]{1,64}$/.test(String(v || '').trim())

function parseArgv(argv) {
  const out = { _: [], flags: {} }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      const eq = a.indexOf('=')
      if (eq >= 0) out.flags[a.slice(2, eq)] = a.slice(eq + 1)
      else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) out.flags[a.slice(2)] = argv[++i]
      else out.flags[a.slice(2)] = true
    } else out._.push(a)
  }
  return out
}

function resolveFile(flag, envKey, def) {
  return path.resolve(flag || process.env[envKey] || path.join(root, def))
}

function readLines(file) {
  if (!fs.existsSync(file)) return []
  const lines = fs.readFileSync(file, 'utf-8').split('\n')
  // El '\n' final del archivo genera un elemento '' fantasma al partir;
  // sin quitarlo, cada inserción deja una línea en blanco intermedia.
  while (lines.length && lines[lines.length - 1] === '') lines.pop()
  return lines
}

function writeLines(file, lines) {
  const body = lines.join('\n').replace(/\n+$/, '') + '\n'
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, body)
}

async function askMissing(value, opts) {
  if (value !== undefined && value !== null && value !== '') return value
  if (!INTERACTIVE) fail(`Missing argument (non-interactive mode): ${opts.message}`)
  const res = await p.text(opts)
  if (p.isCancel(res)) {
    p.cancel('Cancelled.')
    process.exit(1)
  }
  return res
}

function fail(msg) {
  p.log.error(msg)
  process.exit(1)
}

// ---------------- users (xusers.txt: `email` or `email:key`) ----------------

function findUser(lines, email) {
  const norm = email.trim().toLowerCase()
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line || line.startsWith('#')) continue
    const id = line.split(':')[0].trim().toLowerCase()
    if (id === norm) return i
  }
  return -1
}

async function userCmd(action, args, flags) {
  const file = resolveFile(flags.users, 'XID_USERS_TXT', 'xusers.txt')
  const lines = readLines(file)

  if (action === 'list') {
    const users = lines.filter((l) => l.trim() && !l.trim().startsWith('#'))
    if (!users.length) p.log.info(`No users in ${file}.`)
    else for (const u of users) p.log.message(u.trim().replace(/:.*$/, ':***'))
    return
  }

  if (action === 'add' || action === 'key' || action === 'password') {
    let email = await askMissing(args[0], { message: 'User email:' })
    email = String(email).trim().toLowerCase()
    if (!isEmail(email)) fail('Invalid email.')
    const idx = findUser(lines, email)
    if (action === 'add' && idx >= 0) fail(`${email} already exists (use: user key|password).`)
    if ((action === 'key' || action === 'password') && idx < 0) fail(`${email} does not exist (use: user add).`)
    if (flags.key !== undefined && flags.password !== undefined) {
      fail('Use --key or --password, not both.')
    }
    let line = email
    if (flags['remove-key'] || flags['remove-password']) {
      // OTP only: drop any second field.
    } else if (flags.password !== undefined || action === 'password') {
      let pw = flags.password
      if (pw === undefined) {
        if (!INTERACTIVE) fail('Missing --password (non-interactive mode).')
        pw = await p.password({ message: 'Password (bcrypt, never stored in clear):' })
        if (p.isCancel(pw) || !pw) fail('Empty password.')
      }
      line = `${email}:${await hashPassword(pw)}`
    } else {
      let key = flags.key
      if (key === undefined) {
        if (!INTERACTIVE) {
          key = ''
          p.log.info('No --key: OTP only (non-interactive mode).')
        } else {
          key = await p.text({ message: 'Static dev key (empty = OTP only):', defaultValue: '' })
        }
        if (p.isCancel(key)) {
          p.cancel('Cancelled.')
          process.exit(1)
        }
      }
      if (key) line = `${email}:${key}`
    }
    if (idx >= 0) lines[idx] = line
    else lines.push(line)
    writeLines(file, lines)
    p.log.success(`${action === 'add' ? 'Added' : 'Updated'} ${email} in ${file}.`)
    return
  }

  if (action === 'rm') {
    const email = String((await askMissing(args[0], { message: 'Email to remove:' })).trim().toLowerCase())
    const idx = findUser(lines, email)
    if (idx < 0) fail(`${email} does not exist.`)
    if (!flags.yes && !flags.y) {
      if (!INTERACTIVE) fail('Requires --yes in non-interactive mode.')
      const ok = await p.confirm({ message: `Remove ${email}?` })
      if (p.isCancel(ok) || !ok) {
        p.cancel('Cancelled.')
        process.exit(1)
      }
    }
    lines.splice(idx, 1)
    writeLines(file, lines)
    p.log.success(`Removed ${email} from ${file}.`)
    return
  }

  fail(`Unknown user action: ${action || '(empty)'} (add|key|password|rm|list).`)
}

// ---------------- clients (xclients.txt: `id:secret:scopes`) ----------------

function findClient(lines, id) {
  const norm = id.trim()
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line || line.startsWith('#')) continue
    if (line.split(':')[0].trim() === norm) return i
  }
  return -1
}

function splitScopes(raw) {
  return String(raw || '')
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

async function clientCmd(action, args, flags) {
  const file = resolveFile(flags.clients, 'XID_CLIENTS_TXT', 'xclients.txt')
  const lines = readLines(file)

  if (action === 'list') {
    const rows = lines.filter((l) => l.trim() && !l.trim().startsWith('#'))
    if (!rows.length) p.log.info(`No clients in ${file}.`)
    else {
      for (const r of rows) {
        const [id, , ...rest] = r.trim().split(':')
        p.log.message(`${id}  scopes=[${splitScopes(rest.join(':')).join(',')}]`)
      }
    }
    return
  }

  if (action === 'add') {
    let id = await askMissing(args[0], { message: 'client_id ([A-Za-z0-9._-]):' })
    id = String(id).trim()
    if (!isClientId(id)) fail('Invalid client_id.')
    if (findClient(lines, id) >= 0) fail(`${id} already exists (use: client scopes|rotate).`)
    let scopes = flags.scopes !== undefined ? splitScopes(flags.scopes) : null
    if (!scopes) {
      const raw = await askMissing(undefined, { message: 'Scopes (comma/space):', defaultValue: 'files.read' })
      scopes = splitScopes(raw)
    }
    if (!scopes.length || !scopes.every(isScope)) fail('Invalid scopes.')
    let secret = flags.secret
    if (secret === undefined && (flags.gen || !INTERACTIVE)) {
      secret = randomBytes(32).toString('base64url')
      if (!INTERACTIVE) p.log.info('Auto-generated secret (non-interactive mode, use --secret to set it).')
    }
    if (secret === undefined) {
      const choice = await p.select({
        message: 'Client secret:',
        options: [
          { value: 'gen', label: 'Generate random (recommended)' },
          { value: 'manual', label: 'Type it manually' },
        ],
      })
      if (p.isCancel(choice)) {
        p.cancel('Cancelled.')
        process.exit(1)
      }
      secret =
        choice === 'gen'
          ? randomBytes(32).toString('base64url')
          : await p.password({ message: 'Secret:' })
      if (p.isCancel(secret) || !secret) fail('Empty secret.')
    }
    lines.push(`${id}:${secret}:${scopes.join(',')}`)
    writeLines(file, lines)
    p.log.success(`Added ${id} in ${file}.`)
    p.log.warn('Save the secret (it will not be shown again):')
    console.log(secret)
    return
  }

  const id = String(await askMissing(args[0], { message: 'client_id:' })).trim()
  const idx = findClient(lines, id)
  if (idx < 0) fail(`${id} does not exist.`)

  if (action === 'scopes') {
    let scopes = flags.scopes !== undefined ? splitScopes(flags.scopes) : null
    if (!scopes) {
      const cur = lines[idx].trim().split(':')
      const raw = await askMissing(undefined, {
        message: 'Scopes (comma/space):',
        defaultValue: splitScopes(cur.slice(2).join(':')).join(','),
      })
      scopes = splitScopes(raw)
    }
    if (!scopes.length || !scopes.every(isScope)) fail('Invalid scopes.')
    const secret = lines[idx].trim().split(':')[1]
    lines[idx] = `${id}:${secret}:${scopes.join(',')}`
    writeLines(file, lines)
    p.log.success(`${id} scopes=[${scopes.join(',')}] in ${file}.`)
    return
  }

  if (action === 'rotate') {
    const secret = randomBytes(32).toString('base64url')
    const parts = lines[idx].trim().split(':')
    lines[idx] = `${id}:${secret}:${splitScopes(parts.slice(2).join(':')).join(',')}`
    writeLines(file, lines)
    p.log.success(`Secret rotated for ${id} in ${file}.`)
    p.log.warn('New secret (it will not be shown again):')
    console.log(secret)
    return
  }

  if (action === 'rm') {
    if (!flags.yes && !flags.y) {
      if (!INTERACTIVE) fail('Requires --yes in non-interactive mode.')
      const ok = await p.confirm({ message: `Remove ${id}?` })
      if (p.isCancel(ok) || !ok) {
        p.cancel('Cancelled.')
        process.exit(1)
      }
    }
    lines.splice(idx, 1)
    writeLines(file, lines)
    p.log.success(`Removed ${id} from ${file}.`)
    return
  }

  fail(`Unknown client action: ${action || '(empty)'} (add|scopes|rotate|rm|list).`)
}

// ---------------- main ----------------

const { _, flags } = parseArgv(process.argv.slice(2))
const [domain, action, ...rest] = _

if (flags.help || flags.h || (!domain && !INTERACTIVE)) {
  console.log(`xid CLI — manages xusers.txt and xclients.txt
Usage: bun cli/xid.js <user|client> <action> [args] [--flags]
  user   add <email> [--key k|--password p] | key <email> [--key k|--remove-key] | password <email> [--password p|--remove-password] | rm <email> [--yes] | list
  client add <id> [--scopes s] [--secret s|--gen] | scopes <id> [--scopes s] | rotate <id> | rm <id> [--yes] | list
Globals: --users <path> --clients <path> --yes --help
No args opens the interactive menu (clack); same when the action is missing.
Any other missing required argument is asked interactively (clack).`)
  process.exit(domain ? 1 : 0)
}

async function pickMenu() {
  let d = domain
  if (!d) {
    if (!INTERACTIVE) fail('No arguments and no TTY: pass <user|client> <action> (see --help).')
    d = await p.select({
      message: 'What do you want to manage?',
      options: [
        { value: 'user', label: 'Users', hint: 'xusers.txt' },
        { value: 'client', label: 'Machine clients', hint: 'xclients.txt' },
      ],
    })
    if (p.isCancel(d)) {
      p.cancel('Cancelled.')
      process.exit(1)
    }
  }
  let a = action
  if (!a) {
    if (!INTERACTIVE) fail('No action and no TTY: pass <action> (see --help).')
    const opts =
      d === 'user'
        ? [
            { value: 'add', label: 'Add user' },
            { value: 'key', label: 'Set/change dev key' },
            { value: 'password', label: 'Set/change password (bcrypt)' },
            { value: 'rm', label: 'Remove user' },
            { value: 'list', label: 'List users' },
          ]
        : [
            { value: 'add', label: 'Add client' },
            { value: 'scopes', label: 'Change scopes' },
            { value: 'rotate', label: 'Rotate secret' },
            { value: 'rm', label: 'Remove client' },
            { value: 'list', label: 'List clients' },
          ]
    a = await p.select({ message: 'Which action?', options: opts })
    if (p.isCancel(a)) {
      p.cancel('Cancelled.')
      process.exit(1)
    }
  }
  return [d, a]
}

p.intro('OnMind-XID')
try {
  const [d, a] = await pickMenu()
  if (d === 'user') await userCmd(a, rest, flags)
  else if (d === 'client') await clientCmd(a, rest, flags)
  else fail(`Unknown domain: ${d} (user|client).`)
  p.outro('Done.')
} catch (err) {
  fail(err?.message || String(err))
}

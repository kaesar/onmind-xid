#!/usr/bin/env bun
// Bootstrap: xusers.txt → KV XID_USERS (one-shot).
// Usage:
//   bun scripts/bootstrap-kv.js --apply [--include-dev-keys]
// Without --apply it prints the entries that would be written. `--include-dev-keys` also
// uploads the `otpKeyHash` dev keys (NOT recommended in production: they are static keys).

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseTxt } from '../src/service/users.js'
import { defaultRole } from '../src/service/roles.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const txtPath = path.resolve(process.env.XID_USERS_TXT || path.join(__dirname, '..', 'xusers.txt'))

const includeDevKeys = process.argv.includes('--include-dev-keys')
const apply = process.argv.includes('--apply')

if (!fs.existsSync(txtPath)) {
  console.error(`xusers.txt not found: ${txtPath}`)
  process.exit(1)
}

const users = await parseTxt(fs.readFileSync(txtPath, 'utf-8'), process.env)
const entries = []
for (const user of users.values()) {
  const value = { email: user.email, role: user.role || defaultRole(process.env) }
  if (user.passwordHash) value.passwordHash = user.passwordHash // bcrypt: legitimate verifier, always uploaded
  if (includeDevKeys && user.otpKeyHash) value.otpKeyHash = user.otpKeyHash
  entries.push({ key: user.email, value: JSON.stringify(value), email: user.email })
}

if (!apply) {
  for (const entry of entries) {
    console.log(`${entry.key} → ${entry.value}`)
  }
  console.log(`\n${entries.length} users. Run with --apply to write to KV.`)
  process.exit(0)
}

// uses `wrangler kv key put --binding=XID_USERS` with a plain message
const { execSync } = await import('node:child_process')
for (const entry of entries) {
  execSync(
    `npx wrangler kv key put --binding=XID_USERS "${entry.key}" ${JSON.stringify(entry.value)} --local`,
    { stdio: 'inherit' }
  )
}
console.log(`\nWrote ${entries.length} users to KV XID_USERS.`)
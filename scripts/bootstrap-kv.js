#!/usr/bin/env bun
// Bootstrap: xusers.txt → KV XID_USERS (one-shot).
// Uso:
//   bun scripts/bootstrap-kv.js --apply [--include-dev-keys]
// Sin --apply imprime las entradas que se escribirían. `--include-dev-keys` sube
// también los `otpKeyHash` de dev (NO recomendado en producción: son claves estáticas).

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseTxt } from '../src/users.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const txtPath = path.resolve(process.env.XID_USERS_TXT || path.join(__dirname, '..', 'xusers.txt'))

const includeDevKeys = process.argv.includes('--include-dev-keys')
const apply = process.argv.includes('--apply')

if (!fs.existsSync(txtPath)) {
  console.error(`xusers.txt not found: ${txtPath}`)
  process.exit(1)
}

const users = await parseTxt(fs.readFileSync(txtPath, 'utf-8'))
const entries = []
for (const user of users.values()) {
  const value = { email: user.email }
  if (user.passwordHash) value.passwordHash = user.passwordHash // bcrypt: verificador legítimo, siempre se sube
  if (includeDevKeys && user.otpKeyHash) value.otpKeyHash = user.otpKeyHash
  entries.push({ key: user.email, value: JSON.stringify(value), email: user.email })
}

if (!apply) {
  for (const entry of entries) {
    console.log(`${entry.key} → ${entry.value}`)
  }
  console.log(`\n${entries.length} usuarios. Ejecuta con --apply para escribir en KV.`)
  process.exit(0)
}

// usa `wrangler kv key put --binding=XID_USERS` con mensaje plano
const { execSync } = await import('node:child_process')
for (const entry of entries) {
  execSync(
    `npx wrangler kv key put --binding=XID_USERS "${entry.key}" ${JSON.stringify(entry.value)} --local`,
    { stdio: 'inherit' }
  )
}
console.log(`\nEscritos ${entries.length} usuarios en KV XID_USERS.`)
#!/usr/bin/env bun
// Bootstrap: clients.txt → KV XID_CLIENTS (one-shot, hashes only).
// Uso:
//   bun scripts/bootstrap-clients.js --apply
// Sin --apply imprime las entradas que se escribirían (sin secretos).
// Los secretos en claro NUNCA se suben: solo { secretHash, scopes }.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseTxt } from '../src/clients.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const txtPath = path.resolve(process.env.XID_CLIENTS_TXT || path.join(__dirname, '..', 'clients.txt'))

const apply = process.argv.includes('--apply')

if (!fs.existsSync(txtPath)) {
  console.error(`clients.txt not found: ${txtPath}`)
  process.exit(1)
}

const clients = await parseTxt(fs.readFileSync(txtPath, 'utf-8'))
const entries = []
for (const client of clients.values()) {
  const value = { clientId: client.clientId, secretHash: client.secretHash, scopes: client.scopes }
  entries.push({ key: client.clientId, value: JSON.stringify(value), scopes: client.scopes })
}

if (!apply) {
  for (const entry of entries) {
    console.log(`${entry.key} scopes=[${entry.scopes.join(',')}] → ${entry.value.slice(0, 80)}...`)
  }
  console.log(`\n${entries.length} clientes. Ejecuta con --apply para escribir en KV (hashes, sin secretos).`)
  process.exit(0)
}

const { execSync } = await import('node:child_process')
for (const entry of entries) {
  execSync(
    `npx wrangler kv key put --binding=XID_CLIENTS "${entry.key}" '${entry.value}'`,
    { stdio: 'inherit' }
  )
}
console.log(`\nEscritos ${entries.length} clientes en KV XID_CLIENTS (hashes).`)

#!/usr/bin/env bun
// Bootstrap: xclients.txt → KV XID_CLIENTS (one-shot, hashes only).
// Usage:
//   bun scripts/bootstrap-clients.js --apply
// Without --apply it prints the entries that would be written (no secrets).
// Clear-text secrets are NEVER uploaded: only { secretHash, scopes }.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseTxt } from '../src/service/clients.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const txtPath = path.resolve(process.env.XID_CLIENTS_TXT || path.join(__dirname, '..', 'xclients.txt'))

const apply = process.argv.includes('--apply')

if (!fs.existsSync(txtPath)) {
  console.error(`xclients.txt not found: ${txtPath}`)
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
  console.log(`\n${entries.length} clients. Run with --apply to write to KV (hashes, no secrets).`)
  process.exit(0)
}

const { execSync } = await import('node:child_process')
for (const entry of entries) {
  execSync(
    `npx wrangler kv key put --binding=XID_CLIENTS "${entry.key}" '${entry.value}'`,
    { stdio: 'inherit' }
  )
}
console.log(`\nWrote ${entries.length} clients to KV XID_CLIENTS (hashes).`)

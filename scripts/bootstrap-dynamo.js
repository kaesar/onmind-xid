#!/usr/bin/env bun
// Bootstrap: xusers.txt + xclients.txt → DynamoDB (for AWS Lambda).
// Usage:
//   bun scripts/bootstrap-dynamo.js --create            # create tables xusers/xclients/xmeta (TTL on xmeta)
//   bun scripts/bootstrap-dynamo.js --apply [--include-dev-keys]
// Without --apply it prints the entries that would be written (no secrets).
// Requires AWS credentials + AWS_REGION (env). Table names:
// XID_USERS_TABLE / XID_CLIENTS_TABLE / XID_META_TABLE (defaults: xusers/xclients/xmeta).

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import dynamodb from '@aws-sdk/client-dynamodb' // CJS: default import (Bun cannot resolve named)
const { DynamoDBClient, CreateTableCommand, DescribeTableCommand, UpdateTimeToLiveCommand } = dynamodb
import { createDynamoBindings, resolveTableNames } from '../src/dynamo.js'
import { parseTxt as parseUsers } from '../src/users.js'
import { parseTxt as parseClients } from '../src/clients.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const args = process.argv.slice(2)
const apply = args.includes('--apply')
const create = args.includes('--create')
const includeDevKeys = args.includes('--include-dev-keys')

const env = process.env
const usersTxt = path.resolve(env.XID_USERS_TXT || path.join(__dirname, '..', 'xusers.txt'))
const clientsTxt = path.resolve(env.XID_CLIENTS_TXT || path.join(__dirname, '..', 'xclients.txt'))
const client = new DynamoDBClient(env.XID_DYNAMO_ENDPOINT ? { endpoint: env.XID_DYNAMO_ENDPOINT } : {})
const names = resolveTableNames(env)
const bindings = createDynamoBindings(env, { client })

// ---------------- --create: tables (PAY_PER_REQUEST, TTL on xmeta) ----------------
if (create) {
  const specs = [names.users, names.clients, names.meta].filter(Boolean)
  for (const table of specs) {
    try {
      await client.send(
        new CreateTableCommand({
          TableName: table,
          AttributeDefinitions: [{ AttributeName: 'pk', AttributeType: 'S' }],
          KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }],
          BillingMode: 'PAY_PER_REQUEST',
        })
      )
      console.log(`created table ${table}`)
    } catch (err) {
      if (err?.name === 'ResourceInUseException') console.log(`table ${table} already exists`)
      else throw err
    }
  }
  // wait for ACTIVE (writes fail while creating)
  for (const table of specs) {
    for (let i = 0; i < 60; i++) {
      const d = await client.send(new DescribeTableCommand({ TableName: table }))
      if (d.Table?.TableStatus === 'ACTIVE') break
      if (i === 59) throw new Error(`timeout waiting for ${table} ACTIVE`)
      await new Promise((r) => setTimeout(r, 2000))
    }
    console.log(`table ${table} ACTIVE`)
  }
  if (names.meta) {
    try {
      await client.send(
        new UpdateTimeToLiveCommand({
          TableName: names.meta,
          TimeToLiveSpecification: { AttributeName: 'ttl', Enabled: true },
        })
      )
      console.log(`TTL enabled on ${names.meta} (attribute "ttl")`)
    } catch (err) {
      if (err?.name === 'TimeToLiveAlreadyEnabledException') console.log(`TTL already enabled on ${names.meta}`)
      else throw err
    }
  }
  if (!apply) process.exit(0)
}

// ---------------- entries ----------------
const userEntries = []
if (fs.existsSync(usersTxt)) {
  const users = await parseUsers(fs.readFileSync(usersTxt, 'utf-8'))
  for (const user of users.values()) {
    const value = { email: user.email }
    if (user.passwordHash) value.passwordHash = user.passwordHash // bcrypt: always uploaded
    if (includeDevKeys && user.otpKeyHash) value.otpKeyHash = user.otpKeyHash
    userEntries.push({ key: user.email, value: JSON.stringify(value) })
  }
}

const clientEntries = []
if (fs.existsSync(clientsTxt)) {
  const clients = await parseClients(fs.readFileSync(clientsTxt, 'utf-8'))
  for (const c of clients.values()) {
    clientEntries.push({
      key: c.clientId,
      value: JSON.stringify({ clientId: c.clientId, secretHash: c.secretHash, scopes: c.scopes }),
      scopes: c.scopes,
    })
  }
}

if (!apply) {
  for (const e of userEntries) console.log(`users  ${e.key} → ${e.value}`)
  for (const e of clientEntries) console.log(`client ${e.key} scopes=[${e.scopes.join(',')}] → ${e.value.slice(0, 80)}...`)
  console.log(
    `\n${userEntries.length} users, ${clientEntries.length} clients. Run with --apply to write to DynamoDB (run --create first if the tables do not exist).`
  )
  process.exit(0)
}

if (!bindings.XID_USERS && userEntries.length) fail('XID_USERS_TABLE disabled (none).')
if (!bindings.XID_CLIENTS && clientEntries.length) fail('XID_CLIENTS_TABLE disabled (none).')

for (const e of userEntries) await bindings.XID_USERS.put(e.key, e.value)
for (const e of clientEntries) await bindings.XID_CLIENTS.put(e.key, e.value)
console.log(
  `Wrote ${userEntries.length} users to ${names.users} and ${clientEntries.length} clients to ${names.clients} (hashes only, no secrets).`
)

function fail(msg) {
  console.error(msg)
  process.exit(1)
}

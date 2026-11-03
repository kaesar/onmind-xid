// DynamoDB adapter exposing the SAME duck-typed interface as the Cloudflare KV
// binding, so kv.js / users.js / clients.js stay unchanged:
//   get(key)            → string | null     (kv.js parses it as JSON)
//   get(key, 'json')    → object | null     (users.js / clients.js)
//   put(key, value, { expirationTtl })      (TTL in seconds, min. 60)
//   delete(key)
//
// Tables (one per namespace, name configurable via env):
//   XID_META_TABLE   (default xmeta)   → ephemeral state: otp:, sess:, rl:, refresh
//   XID_USERS_TABLE  (default xusers)  → allowlist, key = email
//   XID_CLIENTS_TABLE(default xclients)→ B2B clients (hashes only)
//
// Item: { pk (S) = key, v (S) = value, ttl (N) = optional epoch seconds }.
// DynamoDB TTL is lazy (deletion up to ~48 h late), so expiry is ALSO enforced
// ON READ (ttl <= now → null + best-effort delete) — OTP/refresh really expire
// at 5 min / 30 d.

// Default import + destructuring: the SDK ships as CJS and Bun cannot resolve
// ESM named imports from dist-cjs (in Node ESM default = module.exports).
import dynamodb from '@aws-sdk/client-dynamodb'
const { DynamoDBClient, GetItemCommand, PutItemCommand, DeleteItemCommand, ScanCommand } = dynamodb

const MIN_TTL = 60 // s, same minimum as Cloudflare KV

function marshalValue(value) {
  return typeof value === 'string' ? value : JSON.stringify(value)
}

export class DynamoKV {
  constructor({ client, tableName }) {
    if (!client || !tableName) throw new Error('DynamoKV: client and tableName are required')
    this.client = client
    this.tableName = tableName
  }

  key(key) {
    return { pk: { S: String(key) } }
  }

  async get(key, type) {
    const res = await this.client.send(
      new GetItemCommand({
        TableName: this.tableName,
        Key: this.key(key),
        ProjectionExpression: '#v, #ttl',
        ExpressionAttributeNames: { '#v': 'v', '#ttl': 'ttl' },
      })
    )
    const item = res?.Item
    if (!item) return null

    const ttl = item.ttl?.N ? Number(item.ttl.N) : 0
    if (ttl && ttl <= Math.floor(Date.now() / 1000)) {
      // expired (DynamoDB TTL is lazy): invalidate on read
      this.client.send(new DeleteItemCommand({ TableName: this.tableName, Key: this.key(key) })).catch(() => {})
      return null
    }

    const raw = item.v?.S
    if (raw === undefined || raw === null) return null
    if (type === 'json') {
      try {
        return JSON.parse(raw)
      } catch {
        return null
      }
    }
    return raw
  }

  async put(key, value, opts) {
    const item = { pk: this.key(key).pk, v: { S: marshalValue(value) } }
    const ttlSec = opts?.expirationTtl
    if (ttlSec) {
      const ttl = Math.floor(Date.now() / 1000) + Math.max(MIN_TTL, Math.round(ttlSec))
      item.ttl = { N: String(ttl) }
    }
    await this.client.send(new PutItemCommand({ TableName: this.tableName, Item: item }))
  }

  async delete(key) {
    await this.client.send(new DeleteItemCommand({ TableName: this.tableName, Key: this.key(key) }))
  }

  // Atomic single-use: delete only if the item exists and return the old value.
  async consume(key) {
    let res
    try {
      res = await this.client.send(
        new DeleteItemCommand({
          TableName: this.tableName,
          Key: this.key(key),
          ConditionExpression: 'attribute_exists(pk)',
          ReturnValues: 'ALL_OLD',
        })
      )
    } catch (err) {
      if (err?.name === 'ConditionalCheckFailedException') return null
      throw err
    }
    const item = res?.Attributes
    if (!item) return null
    const ttl = item.ttl?.N ? Number(item.ttl.N) : 0
    if (ttl && ttl <= Math.floor(Date.now() / 1000)) return null
    const raw = item.v?.S
    if (raw === undefined || raw === null) return null
    try {
      return JSON.parse(raw)
    } catch {
      return raw
    }
  }

  // Minimal KV-compatible list used by the admin API (allowlist/client tables
  // are small). Scan + begins_with(pk, prefix), with cursor pagination.
  async list(opts = {}) {
    const prefix = String(opts.prefix || '')
    const params = {
      TableName: this.tableName,
      ProjectionExpression: '#pk',
      ExpressionAttributeNames: { '#pk': 'pk' },
    }
    if (opts.cursor) {
      try { params.ExclusiveStartKey = JSON.parse(opts.cursor) } catch { /* ignore */ }
    }
    if (prefix) {
      params.FilterExpression = 'begins_with(#pk, :prefix)'
      params.ExpressionAttributeValues = { ':prefix': { S: prefix } }
    }
    const res = await this.client.send(new ScanCommand(params))
    const keys = (res.Items || []).map((item) => ({ name: item.pk?.S })).filter((x) => x.name)
    return {
      keys,
      list_complete: !res.LastEvaluatedKey,
      cursor: res.LastEvaluatedKey ? JSON.stringify(res.LastEvaluatedKey) : undefined,
    }
  }
}

function tableNameOf(env, varName, def) {
  const v = env?.[varName] ?? process.env[varName]
  if (v === '' || v === 'none' || v === '-') return null // disabled → FS/mem adapter
  return v || def
}

// Effective table names (env → default; null = disabled).
export function resolveTableNames(env = {}) {
  return {
    meta: tableNameOf(env, 'XID_META_TABLE', 'xmeta'),
    users: tableNameOf(env, 'XID_USERS_TABLE', 'xusers'),
    clients: tableNameOf(env, 'XID_CLIENTS_TABLE', 'xclients'),
  }
}

// Builds the three bindings for the Lambda env (or tests with a fake client).
// A disabled table (`XID_*_TABLE=none`) leaves the binding undefined and the
// code falls back to the matching local adapter (txt / Map / FS).
export function createDynamoBindings(env = {}, { client = null } = {}) {
  const c =
    client ||
    new DynamoDBClient(env?.XID_DYNAMO_ENDPOINT ? { endpoint: env.XID_DYNAMO_ENDPOINT } : {})
  const names = resolveTableNames(env)
  const binding = (table) => (table ? new DynamoKV({ client: c, tableName: table }) : undefined)
  return {
    XID_META: binding(names.meta),
    XID_USERS: binding(names.users),
    XID_CLIENTS: binding(names.clients),
  }
}

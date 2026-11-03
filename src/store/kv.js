// KV adapter: namespace XID_META (Cloudflare) or in-memory Map (dev `bun run dev`).
// Values are stored as JSON strings, same as Cloudflare KV.

const mem = new Map() // key -> { value, expiresAt }

function memRead(key) {
  const entry = mem.get(key)
  if (!entry) return null
  if (entry.expiresAt && entry.expiresAt <= Date.now()) {
    mem.delete(key)
    return null
  }
  return entry.value
}

function parseRaw(raw) {
  if (raw === null || raw === undefined) return null
  try { return JSON.parse(raw) } catch { return raw }
}

export async function kvGet(env, key) {
  const kv = env?.XID_META
  if (kv && typeof kv.get === 'function') {
    return parseRaw(await kv.get(key))
  }
  return parseRaw(memRead(key))
}

export async function kvPut(env, key, value, ttlSec) {
  const raw = typeof value === 'string' ? value : JSON.stringify(value)
  const kv = env?.XID_META
  if (kv && typeof kv.put === 'function') {
    const opts = ttlSec ? { expirationTtl: Math.max(60, Math.round(ttlSec)) } : undefined
    return kv.put(key, raw, opts)
  }
  mem.set(key, {
    value: raw,
    expiresAt: ttlSec ? Date.now() + ttlSec * 1000 : 0,
  })
}

export async function kvDelete(env, key) {
  const kv = env?.XID_META
  if (kv && typeof kv.delete === 'function') {
    return kv.delete(key)
  }
  mem.delete(key)
}

// Atomic single-use (DynamoDB). Cloudflare KV has no atomic consume: best-effort,
// so a concurrent replay may succeed; use a Durable Object for strict single-use.
export async function kvConsume(env, key) {
  const kv = env?.XID_META
  if (kv && typeof kv.consume === 'function') return kv.consume(key)
  if (kv && typeof kv.get === 'function') {
    const raw = await kv.get(key)
    if (raw === null || raw === undefined) return null
    await kv.delete(key)
    return parseRaw(raw)
  }
  const raw = memRead(key)
  if (raw === null || raw === undefined) return null
  mem.delete(key) // no await between read and delete
  return parseRaw(raw)
}

// Read-modify-write increment (not atomic on KV; enough for the MVP rate limit).
export async function kvIncr(env, key, ttlSec) {
  const prev = (await kvGet(env, key)) || { count: 0, resetAt: 0 }
  const count = (prev.count || 0) + 1
  const resetAt = prev.resetAt || Date.now() + ttlSec * 1000
  await kvPut(env, key, { count, resetAt }, ttlSec)
  return count
}
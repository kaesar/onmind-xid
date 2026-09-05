// Claves RS256 para la fachada Entra ID (simulación OIDC).
// - Producción: secreto XID_RSA_PRIVATE_JWK (JWK privada JSON con kid, alg RS256).
// - Dev: si falta, se genera un par efímero en memoria (igual que XID_JWT_SECRET en dev.js).
// Solo usa WebCrypto (Bun + Workers), sin dependencias.

let cachedPrivateJwk = null
let cachedPrivateKey = null
let cachedPublicKey = null
let warnedEphemeral = false

function envVal(env, key) {
  const v = env?.[key] ?? process.env?.[key]
  return typeof v === 'string' && v.length ? v : null
}

function b64uEncodeBytes(bytes) {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64uDecodeBytes(input) {
  const b64 = String(input || '').replace(/-/g, '+').replace(/_/g, '/')
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4))
  const bin = atob(b64 + pad)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

function b64uEncodeString(str) {
  return b64uEncodeBytes(new TextEncoder().encode(str))
}

async function importPrivateJwk(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['sign']
  )
}

async function importPublicJwk(jwk) {
  const pub = { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }
  return crypto.subtle.importKey(
    'jwk',
    pub,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['verify']
  )
}

export async function ensureRsaKeys(env) {
  if (cachedPrivateKey && cachedPrivateJwk && cachedPublicKey) return cachedPrivateJwk
  const raw = envVal(env, 'XID_RSA_PRIVATE_JWK')
  if (raw) {
    try {
      const jwk = JSON.parse(raw)
      if (jwk?.kty !== 'RSA' || !jwk.n || !jwk.d) throw new Error('bad JWK')
      if (!jwk.kid) jwk.kid = 'xid-1'
      cachedPrivateJwk = jwk
      cachedPrivateKey = await importPrivateJwk(jwk)
      cachedPublicKey = await importPublicJwk(jwk)
      return cachedPrivateJwk
    } catch (err) {
      throw new Error(`XID_RSA_PRIVATE_JWK inválido: ${err.message}`)
    }
  }
  // Dev efímero (aviso una vez, como el secreto HMAC en dev.js).
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  )
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(4)), (b) =>
    b.toString(16).padStart(2, '0')
  ).join('')
  jwk.kid = `xid-dev-${rand}`
  jwk.alg = 'RS256'
  jwk.use = 'sig'
  cachedPrivateJwk = jwk
  cachedPrivateKey = pair.privateKey
  cachedPublicKey = pair.publicKey
  if (!warnedEphemeral) {
    warnedEphemeral = true
    console.log('[xid:entra] sin XID_RSA_PRIVATE_JWK: usando par RSA efímero (dev). Fija el secreto en prod.')
  }
  return cachedPrivateJwk
}

export async function getPublicJwk(env) {
  const priv = await ensureRsaKeys(env)
  return { kty: 'RSA', use: 'sig', alg: 'RS256', kid: priv.kid, n: priv.n, e: priv.e }
}

export function getKidSync() {
  return cachedPrivateJwk?.kid || null
}

export async function signRs256(env, payload) {
  const priv = await ensureRsaKeys(env)
  if (!cachedPrivateKey) {
    cachedPrivateKey = await importPrivateJwk(priv)
    cachedPublicKey = await importPublicJwk(priv)
  }
  const headB64 = b64uEncodeString(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: priv.kid }))
  const payB64 = b64uEncodeString(JSON.stringify(payload))
  const data = `${headB64}.${payB64}`
  const sig = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    cachedPrivateKey,
    new TextEncoder().encode(data)
  )
  return `${data}.${b64uEncodeBytes(new Uint8Array(sig))}`
}

export async function verifyRs256(env, token) {
  const parts = String(token || '').split('.')
  if (parts.length !== 3) return null
  try {
    await ensureRsaKeys(env)
    const data = `${parts[0]}.${parts[1]}`
    const sig = b64uDecodeBytes(parts[2])
    const ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      cachedPublicKey,
      sig,
      new TextEncoder().encode(data)
    )
    if (!ok) return null
    const payload = JSON.parse(new TextDecoder().decode(b64uDecodeBytes(parts[1])))
    if (!payload.exp || payload.exp * 1000 <= Date.now()) return null
    return payload
  } catch {
    return null
  }
}

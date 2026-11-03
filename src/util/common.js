const enc = new TextEncoder()
const dec = new TextDecoder()

export function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase()
}

export function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

// Only same-origin relative paths are valid in ?next= (no open redirects).
// Reject backslashes and percent-encoded // or \ (browsers normalize them).
export function safeNext(value) {
  const s = String(value || '').trim()
  if (!s.startsWith('/') || s.startsWith('//') || /[\\\r\n]/.test(s)) return ''
  let decoded = s
  try {
    decoded = decodeURIComponent(s)
  } catch {
    return ''
  }
  if (!decoded.startsWith('/') || decoded.startsWith('//') || /[\\\r\n]/.test(decoded)) return ''
  return s
}

// Form body parser shared by the HTML facades (urlencoded, multipart, JSON).
export async function readBodyParams(c) {
  const ct = c.req.header('content-type') || ''
  if (ct.includes('application/json')) {
    return c.req.json().catch(() => ({}))
  }
  try {
    const parsed = await c.req.parseBody()
    const out = {}
    for (const [k, v] of Object.entries(parsed || {})) {
      out[k] = typeof v === 'string' ? v : String(v)
    }
    return out
  } catch {
    return {}
  }
}

export function maskEmail(email) {
  const [local, domain] = email.split('@')
  if (!domain) return email
  const head = local.slice(0, Math.max(1, Math.ceil(local.length / 2)))
  return `${head}***@${domain}`
}

export async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(value))
  const bytes = new Uint8Array(digest)
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}

function bytesToB64Url(bytes) {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64UrlToBytes(input) {
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

export function base64urlEncode(str) {
  return bytesToB64Url(enc.encode(str))
}

export function base64UrlDecode(str) {
  return dec.decode(b64UrlToBytes(str))
}

export function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

export function generateOtp() {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000
  return String(n).padStart(6, '0')
}
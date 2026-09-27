#!/usr/bin/env bun
// In-process e2e smoke test (no ports, no network): exercises app.fetch directly.
// Uses the dev fixtures xusers.txt (bob: password abc123, carol: static key)
// and xclients.txt (svc-demo / svc-noscope). Sends no mail (SMTP disabled).
// Usage: bun scripts/smoke.js   (exit != 0 if anything fails)

import { app } from '../src/index.js'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const env = {
  ...process.env,
  XID_ENV: 'dev',
  XID_SMTP_DISABLED: '1',
  XID_JWT_SECRET: '0123456789abcdef0123456789abcdef',
}
process.env.XID_SMTP_DISABLED = '1'  // mail.js reads process.env (deterministic), even if OnMind-XIN is running
const ORIGIN = 'http://localhost:8787'
const BASIC = (id, secret) => 'Basic ' + Buffer.from(`${id}:${secret}`).toString('base64')

let pass = 0
let fail = 0
function check(name, cond, extra = '') {
  if (cond) {
    pass++
    console.log(`ok   ${name}`)
  } else {
    fail++
    console.log(`FAIL ${name}${extra ? ' :: ' + extra : ''}`)
  }
}

async function call(method, p, { query = '', form = null, json = null, headers = {} } = {}) {
  const h = { ...headers }
  let body
  if (form) {
    h['Content-Type'] = 'application/x-www-form-urlencoded'
    body = new URLSearchParams(form).toString()
  } else if (json) {
    h['Content-Type'] = 'application/json'
    body = JSON.stringify(json)
  }
  const res = await app.fetch(new Request(ORIGIN + p + query, { method, headers: h, body }), env, {})
  const text = await res.text()
  let data = null
  try {
    data = JSON.parse(text)
  } catch {
    /* HTML */
  }
  return { status: res.status, headers: res.headers, text, json: data }
}

// Files: temp root with a secret (removed at the end).
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'xid-smoke-'))
fs.mkdirSync(path.join(tmpRoot, 'docs'), { recursive: true })
fs.writeFileSync(path.join(tmpRoot, 'docs', 'secret.md'), '# Secreto\n')
env.XID_FILES_ROOT = tmpRoot

try {
  // ---- base smoke ----
  let r = await call('GET', '/health')
  check('health', r.status === 200 && r.json?.ok === true, r.text.slice(0, 80))

  // ---- Cognito: real password (bob, bcrypt) ----
  r = await call('POST', '/auth/otp/start', { json: { email: 'bob@example.com' } })
  check('cognito start', r.status === 200 && r.json?.ChallengeName === 'EMAIL_OTP', r.text.slice(0, 80))
  const sess = r.json?.Session
  r = await call('POST', '/cognito/RespondToAuthChallenge', {
    json: { Session: sess, ChallengeResponses: { USERNAME: 'bob@example.com', PASSWORD: 'abc123' } },
  })
  check('cognito password verify', r.status === 200 && !!r.json?.AuthenticationResult?.AccessToken, r.text.slice(0, 80))
  const cognitoAT = r.json?.AuthenticationResult?.AccessToken
  const cognitoRT = r.json?.AuthenticationResult?.RefreshToken
  check('cognito login returns refresh', !!cognitoRT, r.text.slice(0, 80))
  r = await call('POST', '/auth/refresh', { json: { refreshToken: cognitoRT } })
  check('cognito refresh ok', r.status === 200 && !!r.json?.AuthenticationResult?.AccessToken, r.text.slice(0, 80))
  const cognitoAT2 = r.json?.AuthenticationResult?.AccessToken
  const cognitoRT2 = r.json?.AuthenticationResult?.RefreshToken
  check('cognito refresh rotates', !!cognitoRT2 && cognitoRT2 !== cognitoRT, r.text.slice(0, 80))
  r = await call('POST', '/auth/refresh', { json: { refreshToken: cognitoRT } })
  check('cognito refresh reuse 400', r.status === 400, r.text.slice(0, 80))
  r = await call('POST', '/auth/refresh', { json: { refreshToken: 'bogus' } })
  check('cognito refresh bogus 400', r.status === 400, r.text.slice(0, 80))
  r = await call('POST', '/auth/logout', { headers: { Authorization: `Bearer ${cognitoAT2}` } })
  check('cognito logout 200', r.status === 200, r.text.slice(0, 80))
  r = await call('POST', '/auth/refresh', { json: { refreshToken: cognitoRT2 } })
  check('cognito refresh revoked after logout', r.status === 400, r.text.slice(0, 80))
  r = await call('GET', '/auth/me', { headers: { Authorization: `Bearer ${cognitoAT2}` } })
  check('cognito me denied after logout', r.status === 400, r.text.slice(0, 80))
  r = await call('GET', '/auth/me', { headers: { Authorization: `Bearer ${cognitoAT}` } })
  check('cognito me', r.status === 200 && r.json?.Username === 'bob@example.com', r.text.slice(0, 80))
  r = await call('POST', '/cognito/RespondToAuthChallenge', {
    json: { Session: sess, ChallengeResponses: { USERNAME: 'bob@example.com', PASSWORD: 'wrong' } },
  })
  check('cognito wrong password 400', r.status === 400, r.text.slice(0, 80))
  r = await call('POST', '/cognito/RespondToAuthChallenge', {
    json: { Session: sess, ChallengeResponses: { USERNAME: 'carol@example.com', PASSWORD: 'x' } },
  })
  check('cognito password not enabled 400', r.status === 400, r.text.slice(0, 80))
  // ---- Cognito: static legacy (carol, no mail) + OTP with mail (alice) ----
  r = await call('POST', '/auth/otp/start', { json: { email: 'carol@example.com' } })
  const sessC = r.json?.Session
  r = await call('POST', '/auth/otp/verify', { json: { session: sessC, email: 'carol@example.com', code: 'staticdev' } })
  check('cognito legacy static', r.status === 200 && !!r.json?.AuthenticationResult?.AccessToken, r.text.slice(0, 80))
  r = await call('POST', '/auth/otp/start', { json: { email: 'alice@example.com' } })
  check('cognito otp mail challenge', r.status === 200 && !!r.json?.Session, r.text.slice(0, 80))
  r = await call('POST', '/auth/otp/start', { json: { email: 'nadie@example.com' } })
  check('cognito unknown 400', r.status === 400 && r.json?.__type === 'NotAuthorizedException', r.text.slice(0, 80))

  // ---- Entra discovery/JWKS ----
  r = await call('GET', '/xid/v2.0/.well-known/openid-configuration')
  check('discovery', r.status === 200 && r.json?.issuer === `${ORIGIN}/xid`, r.text.slice(0, 80))
  check('discovery advertisements', JSON.stringify(r.json?.grant_types_supported)?.includes('client_credentials'), '')
  r = await call('GET', '/xid/discovery/v2.0/keys')
  check('jwks', r.status === 200 && r.json?.keys?.[0]?.kty === 'RSA', r.text.slice(0, 80))

  // ---- Entra interactive + PKCE S256 (RFC 7636 vector) ----
  const OAUTH = {
    client_id: 'pub-xid', redirect_uri: 'http://localhost:5173/cb', response_type: 'code',
    scope: 'openid profile email', state: 's1', nonce: 'n1',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
  }
  r = await call('GET', '/xid/oauth2/v2.0/authorize', { query: '?' + new URLSearchParams(OAUTH).toString() })
  check('authorize form (en default)', r.status === 200 && r.text.includes('Sign in') && r.text.includes('lang="en"'), '')
  r = await call('GET', '/xid/oauth2/v2.0/authorize', { query: '?' + new URLSearchParams({ ...OAUTH, ui_locales: 'es' }).toString() })
  check('authorize form es (ui_locales)', r.status === 200 && r.text.includes('Iniciar sesión') && r.text.includes('lang="es"'), '')
  r = await call('GET', '/xid/oauth2/v2.0/authorize', {
    query: '?' + new URLSearchParams(OAUTH).toString(), headers: { 'Accept-Language': 'es-ES,es;q=0.9' },
  })
  check('authorize form es (accept-language)', r.status === 200 && r.text.includes('Enviar código'), '')
  r = await call('POST', '/xid/oauth2/v2.0/authorize', { form: { ...OAUTH, email: 'bob@example.com' } })
  const otpSess = /name="otp_session" value="([^"]+)"/.exec(r.text)?.[1]
  check('authorize password step', r.status === 200 && !!otpSess && r.text.includes('kind="password"'), r.text.slice(0, 80))
  r = await call('POST', '/xid/oauth2/v2.0/authorize', {
    form: { ...OAUTH, email: 'bob@example.com', password: 'nope', otp_session: otpSess },
  })
  check('authorize wrong password', r.status === 400 && r.text.includes('Invalid password'), r.text.slice(0, 80))
  r = await call('POST', '/xid/oauth2/v2.0/authorize', {
    form: { ...OAUTH, email: 'bob@example.com', password: 'abc123', otp_session: otpSess },
  })
  const loc = r.headers.get('location') || ''
  const code = new URL(loc, ORIGIN).searchParams.get('code')
  check('authorize code 302', r.status === 302 && !!code, loc.slice(0, 80))
  r = await call('POST', '/xid/oauth2/v2.0/authorize', { form: { ...OAUTH, mode: 'otp', email: 'bob@example.com' } })
  check('authorize otp mode toggle', r.status === 200 && r.text.includes('Code sent to') && r.text.includes('mode=password'), r.text.slice(0, 120))
  const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
  r = await call('POST', '/xid/oauth2/v2.0/token', {
    form: { grant_type: 'authorization_code', code, redirect_uri: OAUTH.redirect_uri, client_id: 'pub-xid', code_verifier: VERIFIER },
  })
  check('token pkce', r.status === 200 && !!r.json?.access_token && !!r.json?.refresh_token, r.text.slice(0, 120))
  const entraAT = r.json?.access_token
  const entraRT = r.json?.refresh_token
  r = await call('GET', '/xid/openid/userinfo', { headers: { Authorization: `Bearer ${entraAT}` } })
  check('userinfo', r.status === 200 && r.json?.sub === 'bob@example.com', r.text.slice(0, 80))
  r = await call('POST', '/xid/oauth2/v2.0/token', {
    form: { grant_type: 'refresh_token', refresh_token: entraRT, client_id: 'pub-xid' },
  })
  check('refresh rotates', r.status === 200 && r.json?.refresh_token !== entraRT, r.text.slice(0, 80))
  r = await call('POST', '/xid/oauth2/v2.0/token', {
    form: { grant_type: 'refresh_token', refresh_token: entraRT, client_id: 'pub-xid' },
  })
  check('refresh reuse 400', r.status === 400, r.text.slice(0, 80))

  // ---- B2B client_credentials (both facades) ----
  r = await call('POST', '/xid/oauth2/v2.0/token', {
    form: { grant_type: 'client_credentials', client_id: 'svc-demo', client_secret: 'dev-secret-change-me' },
  })
  check('entra CC body', r.status === 200 && !r.json?.id_token && !r.json?.refresh_token, r.text.slice(0, 120))
  const m2m = r.json?.access_token
  r = await call('POST', '/oauth2/token', {
    form: { grant_type: 'client_credentials' }, headers: { Authorization: BASIC('svc-demo', 'dev-secret-change-me') },
  })
  check('cognito CC basic', r.status === 200 && !!r.json?.access_token, r.text.slice(0, 120))
  const m2mCog = r.json?.access_token
  r = await call('POST', '/oauth2/token', {
    form: { grant_type: 'client_credentials', client_id: 'svc-demo', client_secret: 'bad' },
  })
  check('cognito bad secret 401', r.status === 401 && !!r.headers.get('www-authenticate'), r.text.slice(0, 80))
  r = await call('POST', '/xid/oauth2/v2.0/token', {
    form: { grant_type: 'client_credentials', client_id: 'svc-noscope', client_secret: 'dev-secret-change-me', scope: 'files.read' },
  })
  check('entra scope exceeds 400', r.status === 400 && r.json?.error === 'invalid_scope', r.text.slice(0, 80))

  // ---- files with machine tokens ----
  r = await call('GET', '/v1/files', { query: '?path=docs/secret.md', headers: { Authorization: `Bearer ${m2m}` } })
  check('files entra-m2m 200', r.status === 200 && r.text.includes('Secreto'), `${r.status} ${r.text.slice(0, 60)}`)
  r = await call('GET', '/v1/files', { query: '?path=docs/secret.md', headers: { Authorization: `Bearer ${m2mCog}` } })
  check('files cognito-m2m 200', r.status === 200, `${r.status} ${r.text.slice(0, 60)}`)
  r = await call('GET', '/xid/openid/userinfo', { headers: { Authorization: `Bearer ${m2m}` } })
  check('userinfo m2m 401', r.status === 401, r.text.slice(0, 80))
  r = await call('GET', '/xid/oauth2/v2.0/logout', { headers: { Authorization: `Bearer ${m2m}` } })
  r = await call('GET', '/v1/files', { query: '?path=docs/secret.md', headers: { Authorization: `Bearer ${m2m}` } })
  check('logout revokes m2m', r.status === 401, `${r.status} ${r.text.slice(0, 60)}`)
} finally {
  fs.rmSync(tmpRoot, { recursive: true, force: true })
}

// ---- DynamoDB adapter (same duck-typed interface as the Cloudflare KV) ----
const { DynamoKV, createDynamoBindings } = await import('../src/dynamo.js')
const { beginLogin } = await import('../src/loginflow.js')
const { parseTxt } = await import('../src/users.js')

function fakeDynamoClient() {
  const tables = new Map()
  return {
    tables,
    async send(cmd) {
      const i = cmd.input
      const name = cmd.constructor.name
      const table = () => {
        if (!tables.has(i.TableName)) tables.set(i.TableName, new Map())
        return tables.get(i.TableName)
      }
      if (name === 'GetItemCommand') return { Item: table().get(i.Key.pk.S) }
      if (name === 'PutItemCommand') {
        table().set(i.Item.pk.S, i.Item)
        return {}
      }
      if (name === 'DeleteItemCommand') {
        table().delete(i.Key.pk.S)
        return {}
      }
      throw new Error(`fake dynamo: unsupported command ${name}`)
    },
  }
}

const fake = fakeDynamoClient()
const dkv = new DynamoKV({ client: fake, tableName: 'xmeta' })
await dkv.put('k1', '{"x":1}', { expirationTtl: 300 })
check('dynamo get string', (await dkv.get('k1')) === '{"x":1}')
check('dynamo get json', (await dkv.get('k1', 'json'))?.x === 1)
fake.tables.get('xmeta').get('k1').ttl = { N: String(Math.floor(Date.now() / 1000) - 1) }
check('dynamo ttl expired → null', (await dkv.get('k1')) === null)
await new Promise((res) => setTimeout(res, 0))
check('dynamo ttl expired → delete', !fake.tables.get('xmeta').has('k1'))
await dkv.put('k2', 'v2')
await dkv.delete('k2')
check('dynamo delete', (await dkv.get('k2')) === null)

// ---- e2e login with DynamoDB bindings (fake client, no AWS) ----
const dyn = createDynamoBindings({}, { client: fakeDynamoClient() })
const usersMap = await parseTxt(fs.readFileSync(path.join(import.meta.dir, '..', 'xusers.txt'), 'utf-8'))
for (const u of usersMap.values()) {
  const value = { email: u.email }
  if (u.passwordHash) value.passwordHash = u.passwordHash
  if (u.otpKeyHash) value.otpKeyHash = u.otpKeyHash
  await dyn.XID_USERS.put(u.email, JSON.stringify(value))
}
const envDyn = { ...env, XID_META: dyn.XID_META, XID_USERS: dyn.XID_USERS, XID_CLIENTS: dyn.XID_CLIENTS }
const dynFetch = (p, body) =>
  app.fetch(
    new Request(ORIGIN + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
    envDyn,
    {}
  )
let dr = await dynFetch('/auth/otp/start', { email: 'bob@example.com', password: 'abc123' })
let dj = await dr.json()
check(
  'dynamo start password',
  dr.status === 200 && !!dj?.Session && dj?.ChallengeParameters?.PASSWORD_ENABLED === 'true',
  `${dr.status} ${JSON.stringify(dj).slice(0, 80)}`
)
dr = await dynFetch('/auth/otp/verify', { session: dj.Session, email: 'bob@example.com', password: 'abc123' })
dj = await dr.json()
check(
  'dynamo password login',
  dr.status === 200 && !!dj?.AuthenticationResult?.AccessToken && !!dj?.AuthenticationResult?.RefreshToken,
  `${dr.status} ${JSON.stringify(dj).slice(0, 80)}`
)
dr = await dynFetch('/auth/otp/start', { email: 'bob@example.com', password: 'mala' })
dj = await dr.json()
dr = await dynFetch('/auth/otp/verify', { session: dj.Session, email: 'bob@example.com', password: 'mala' })
check('dynamo wrong password 400', dr.status === 400, String(dr.status))

// ---- no mail transport (e.g. Lambda without SES): clear 400, not 500 ----
const mu = await beginLogin({ ...env, XID_ENV: 'production' }, 'alice@example.com', { passwordRequested: false })
check(
  'mail unavailable → reason',
  mu.ok === false && mu.reason === 'mail_unavailable' && mu.passwordEnabled === false,
  JSON.stringify(mu)
)

// ---- mail via XIN over HTTP (XID_XIN_URL): stubbed fetch, no network ----
const { sendMail, xinSend } = await import('../src/mail.js')
const realFetch = globalThis.fetch
let seen = null
globalThis.fetch = async (url, opts) => {
  seen = { url: String(url), opts }
  return { ok: true, status: 200, json: async () => ({ messageId: 'xin-m1' }) }
}
const xid = await xinSend({ base: 'http://xin.local:8788', apiKey: 'k', from: 'n@x.io', to: 'a@x.io', subject: 's', text: 't' })
check(
  'xin send posts /send',
  xid === 'xin-m1' &&
    seen.url === 'http://xin.local:8788/send' &&
    seen.opts.headers['x-api-key'] === 'k' &&
    JSON.parse(seen.opts.body).to === 'a@x.io',
  seen.url
)
const via = await sendMail(
  { XID_ENV: 'dev', XID_XIN_URL: 'http://xin.local:8788/', XID_XIN_API_KEY: 'k' },
  { to: 'a@x.io', subject: 's', text: 't' }
)
check(
  'sendmail via xin (trailing slash stripped)',
  via.via === 'xin' && via.messageId === 'xin-m1' && seen.url === 'http://xin.local:8788/send',
  JSON.stringify(via)
)
globalThis.fetch = async () => {
  throw new Error('xin down')
}
const _log = console.log
console.log = () => {}
let fb
try {
  fb = await sendMail({ XID_ENV: 'dev', XID_XIN_URL: 'http://xin.local:8788' }, { to: 'a@x.io', subject: 's', text: 't', code: '123456' })
} finally {
  console.log = _log
}
check('xin down → console fallback (dev)', fb?.via === 'console', JSON.stringify(fb))
globalThis.fetch = realFetch

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)

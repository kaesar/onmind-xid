#!/usr/bin/env bun
// Humo e2e en proceso (sin puertos ni red): ejerce app.fetch directamente.
// Usa los fixtures dev userbase.txt (bob@example.com:abc123) y clients.txt
// (svc-demo / svc-noscope). No envía mail (SMTP desactivado).
// Uso: bun scripts/smoke.js   (exit != 0 si algo falla)

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

// Ficheros: root temporal con un secreto (se borra al final).
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'xid-smoke-'))
fs.mkdirSync(path.join(tmpRoot, 'docs'), { recursive: true })
fs.writeFileSync(path.join(tmpRoot, 'docs', 'secret.md'), '# Secreto\n')
env.XID_FILES_ROOT = tmpRoot

try {
  // ---- humo base ----
  let r = await call('GET', '/health')
  check('health', r.status === 200 && r.json?.ok === true, r.text.slice(0, 80))

  // ---- Cognito OTP ----
  r = await call('POST', '/auth/otp/start', { json: { email: 'bob@example.com' } })
  check('cognito start', r.status === 200 && r.json?.ChallengeName === 'EMAIL_OTP', r.text.slice(0, 80))
  const sess = r.json?.Session
  r = await call('POST', '/auth/otp/verify', { json: { session: sess, email: 'bob@example.com', code: 'abc123' } })
  check('cognito verify', r.status === 200 && !!r.json?.AuthenticationResult?.AccessToken, r.text.slice(0, 80))
  const cognitoAT = r.json?.AuthenticationResult?.AccessToken
  r = await call('GET', '/auth/me', { headers: { Authorization: `Bearer ${cognitoAT}` } })
  check('cognito me', r.status === 200 && r.json?.Username === 'bob@example.com', r.text.slice(0, 80))
  r = await call('POST', '/auth/otp/start', { json: { email: 'nadie@example.com' } })
  check('cognito unknown 400', r.status === 400 && r.json?.__type === 'NotAuthorizedException', r.text.slice(0, 80))

  // ---- Entra discovery/JWKS ----
  r = await call('GET', '/xid/v2.0/.well-known/openid-configuration')
  check('discovery', r.status === 200 && r.json?.issuer === `${ORIGIN}/xid`, r.text.slice(0, 80))
  check('discovery advertisements', JSON.stringify(r.json?.grant_types_supported)?.includes('client_credentials'), '')
  r = await call('GET', '/xid/discovery/v2.0/keys')
  check('jwks', r.status === 200 && r.json?.keys?.[0]?.kty === 'RSA', r.text.slice(0, 80))

  // ---- Entra interactivo + PKCE S256 (vector RFC 7636) ----
  const OAUTH = {
    client_id: 'pub-xid', redirect_uri: 'http://localhost:5173/cb', response_type: 'code',
    scope: 'openid profile email', state: 's1', nonce: 'n1',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
  }
  r = await call('GET', '/xid/oauth2/v2.0/authorize', { query: '?' + new URLSearchParams(OAUTH).toString() })
  check('authorize form', r.status === 200 && r.text.includes('Iniciar sesi'), '')
  r = await call('POST', '/xid/oauth2/v2.0/authorize', { form: { ...OAUTH, email: 'bob@example.com' } })
  const otpSess = /name="otp_session" value="([^"]+)"/.exec(r.text)?.[1]
  check('authorize otp step', r.status === 200 && !!otpSess, r.text.slice(0, 80))
  r = await call('POST', '/xid/oauth2/v2.0/authorize', {
    form: { ...OAUTH, email: 'bob@example.com', code: 'abc123', otp_session: otpSess },
  })
  const loc = r.headers.get('location') || ''
  const code = new URL(loc, ORIGIN).searchParams.get('code')
  check('authorize code 302', r.status === 302 && !!code, loc.slice(0, 80))
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

  // ---- B2B client_credentials (ambas fachadas) ----
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

  // ---- files con tokens máquina ----
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

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)

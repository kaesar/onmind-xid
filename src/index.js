import { Hono } from 'hono'
import { initiateAuth, respondToAuthChallenge, getUserOp, globalSignOut, signUpStub, oauthToken } from './cognito.js'
import { getFileContent } from './files.js'
import { getAsset } from './assets.js'
import { registerEntra } from './entra.js'

const app = new Hono()

// ---------------- CORS (allowlist, no `*`) ----------------
function allowedOrigins(env) {
  const configured = (env?.XID_CORS_ORIGINS || process.env.XID_CORS_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  if (configured.length) return configured
  if ((env?.XID_ENV || process.env.XID_ENV || 'dev') === 'dev') {
    return ['http://localhost:5173', 'http://localhost:5174', 'http://localhost:8787']
  }
  return []
}

function corsHeaders(origin, env) {
  const origins = allowedOrigins(env)
  const allow = origins.includes(origin) ? origin : null
  return {
    'Access-Control-Allow-Origin': allow || '',
    Vary: 'Origin',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Amz-Target',
    'Access-Control-Max-Age': '86400',
  }
}

app.use('*', async (c, next) => {
  const origin = c.req.header('origin')
  if (origin) {
    const headers = corsHeaders(origin, c.env)
    for (const [k, v] of Object.entries(headers)) if (v) c.header(k, v)
  }
  if (c.req.method === 'OPTIONS') return c.body(null, 204)
  return next()
})

// ---------------- Health ----------------
app.get('/health', (c) => {
  const env = c.env || {}
  return c.json({ ok: true, env: env.XID_ENV || process.env.XID_ENV || 'dev' })
})

// Raíz informativa (evita 404 al abrir http://localhost:8787 en el navegador).
app.get('/', (c) => {
  const env = c.env || {}
  return c.json({
    name: 'onmind-xid',
    ok: true,
    env: env.XID_ENV || process.env.XID_ENV || 'dev',
    endpoints: [
      'POST /auth/otp/start',
      'POST /auth/otp/verify',
      'GET /auth/me',
      'POST /auth/logout',
      'GET /v1/files?path=',
      'POST / (Cognito X-Amz-Target)',
      'POST /oauth2/token (Cognito client_credentials B2B)',
      'GET /{tenant}/v2.0/.well-known/openid-configuration (Entra)',
      'GET|POST /{tenant}/oauth2/v2.0/authorize (Entra OTP)',
      'POST /{tenant}/oauth2/v2.0/token (Entra)',
      'GET /{tenant}/discovery/v2.0/keys (Entra JWKS)',
      'GET /{tenant}/openid/userinfo (Entra)',
    ],
  })
})

// ---------------- Adaptadores de contexto ----------------
function ctxOf(c) {
  return { request: c.req.raw, env: c.env }
}

function sendResult(c, result, cookie) {
  if (result && result.__type) {
    return c.json({ __type: result.__type, message: result.message }, result.status || 400)
  }
  const headers = {}
  if (cookie) headers['Set-Cookie'] = cookie
  return c.json(result, 200, headers)
}

const COGNITO_TARGETS = [
  ['InitiateAuth', initiateAuth],
  ['RespondToAuthChallenge', respondToAuthChallenge],
  ['GetUser', getUserOp],
  ['GlobalSignOut', globalSignOut],
  ['SignUp', signUpStub],
]
const OP_INDEX = Object.fromEntries(COGNITO_TARGETS)

function authCookie(result, env) {
  const token = result?.AuthenticationResult?.AccessToken
  if (!token) return null
  const secure = (env.XID_ENV || process.env.XID_ENV) === 'production' ? '; Secure' : ''
  return `xid_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600${secure}`
}

async function callAuth(c, fn) {
  const ct = c.req.header('content-type') || ''
  let body = {}
  if (ct.includes('application/json') || ct.includes('x-amz-json')) {
    body = await c.req.json().catch(() => ({}))
  }
  const result = await fn(c.env, ctxOf(c), body)
  const cookie = authCookie(result, c.env || {})
  return sendResult(c, result, cookie)
}

// ---------------- Cognito subset: POST / (X-Amz-Target) ----------------
app.post('/', async (c) => {
  const op = /AWSCognitoIdentityProviderService\.(\w+)/.exec(c.req.header('x-amz-target') || '')
  const fn = op ? OP_INDEX[op[1]] : null
  if (!fn) return c.json({ __type: 'UnknownOperationException', message: 'Unknown operation' }, 400)
  return callAuth(c, fn)
})

// ---------------- Alias REST ----------------
app.post('/cognito/:op', async (c) => {
  const fn = OP_INDEX[c.req.param('op')]
  if (!fn) return c.json({ __type: 'UnknownOperationException', message: 'Unknown operation' }, 400)
  return callAuth(c, fn)
})

const tolerantBody = (body) => body || {}

app.post('/auth/otp/start', (c) =>
  callAuth(c, async (env, ctx, body) => {
    const b = tolerantBody(body)
    return initiateAuth(env, ctx, {
      AuthFlow: 'USER_AUTH',
      AuthParameters: { USERNAME: b.email || b.AuthParameters?.USERNAME },
    })
  })
)

app.post('/auth/otp/verify', (c) =>
  callAuth(c, async (env, ctx, body) => {
    const b = tolerantBody(body)
    const responses = {
      ...(b.ChallengeResponses || {}),
      USERNAME: b.email || b.ChallengeResponses?.USERNAME,
      EMAIL_OTP_CODE: b.code ?? b.ChallengeResponses?.EMAIL_OTP_CODE,
    }
    return respondToAuthChallenge(env, ctx, {
      Session: b.session || b.Session,
      ChallengeResponses: responses,
    })
  })
)

app.get('/auth/me', (c) => callAuth(c, (env, ctx) => getUserOp(env, ctx, {})))

app.post('/auth/logout', (c) => callAuth(c, (env, ctx, body) => globalSignOut(env, ctx, tolerantBody(body))))

// ---------------- OAuth hosted-UI style (B2B client_credentials, forma Cognito) ----------------
app.post('/oauth2/token', (c) => oauthToken(c))

// ---------------- Ficheros (Iteration 2) ----------------
async function sendFile(c, rel) {
  const res = await getFileContent(c.env, c.req.raw, rel)
  if (res.status !== 200) return c.json(res.body, res.status)
  return new Response(res.body, {
    status: 200,
    headers: { 'Content-Type': res.contentType },
  })
}

app.get('/v1/files', (c) => {
  const pathParam = c.req.query('path')
  if (!pathParam) return c.json({ error: 'missing path' }, 400)
  return sendFile(c, pathParam)
})

app.get('/files/*', (c) => sendFile(c, c.req.path.replace(/^\/files\//, '')))

// ---------------- Assets públicos del login (bundle CUI, sin auth) ----------------
app.get('/cui/*', async (c) => {
  const res = await getAsset(c.env, c.req.path.replace(/^\//, ''))
  if (res.status !== 200) return c.text(res.body, res.status)
  return new Response(res.body, {
    status: 200,
    headers: { 'Content-Type': res.contentType, 'Cache-Control': 'public, max-age=3600' },
  })
})

// ---------------- Fachada Entra ID (simulación OIDC sobre el mismo core) ----------------
registerEntra(app)

// ---------------- Error handling ----------------
app.onError((err, c) => {
  const env = c.env || {}
  const isProd = (env.XID_ENV || process.env.XID_ENV) === 'production'
  if (isProd) {
    console.error('[xid:error]', err && err.stack ? err.stack : err)
    return c.json({ __type: 'InternalServerError', message: 'Internal server error' }, 500)
  }
  return c.json(
    { __type: 'InternalServerError', message: String((err && (err.code || err.message)) || err) },
    500
  )
})

export { app }
export default {
  fetch: (request, env, ctx) => app.fetch(request, env, ctx),
}
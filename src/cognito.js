import { kvIncr } from './kv.js'
import { getUser } from './users.js'
import { issueTokenSet, consumeRefreshToken, revokeUserRefreshTokens, denyJti, verifyAccessToken } from './session.js'
import { beginLogin, finishLogin, hasSecret } from './loginflow.js'
import { maskEmail, normalizeEmail } from './util.js'
import {
  getClient,
  verifyClientSecret,
  parseScopes,
  scopesAllowed,
  checkM2mRateLimit,
  ipOf as m2mIpOf,
  parseBasicAuth,
  issueMachineToken,
} from './clients.js'

// Subconjunto de Cognito Identity Provider + alias REST (ver xid/PLAN.md).
// Contrato: los handlers devuelven o bien la respuesta JSON de éxito, o bien
// { __type, message, status } que index.js convierte a HTTP 4xx igual que IdP.

const RATE_INITIATE_PER_EMAIL = 5
const RATE_INITIATE_PER_IP = 20
const RATE_WINDOW = 900 // s (15 min)

function clientIdFrom(body, env) {
  return body?.ClientId || env?.XID_CLIENT_ID || process.env.XID_CLIENT_ID || 'pub-xid'
}

function ipOf(request) {
  return request?.headers?.get('cf-connecting-ip') || 'local'
}

function bearerToken(request) {
  const header = request?.headers?.get('authorization') || ''
  const m = /^Bearer\s+(.+)$/i.exec(header)
  return m ? m[1] : null
}

export async function initiateAuth(env, ctx, body) {
  // Refresh (AuthFlow Cognito estándar): token opaco de un solo uso, con
  // rotación. No requiere USERNAME; el email sale del propio refresh token.
  if (body?.AuthFlow === 'REFRESH_TOKEN_AUTH') {
    const rec = await consumeRefreshToken(env, body?.AuthParameters?.REFRESH_TOKEN)
    if (!rec) return { __type: 'NotAuthorizedException', message: 'Invalid refresh token.', status: 400 }
    const user = await getUser(env, rec.email)
    if (!user) return { __type: 'NotAuthorizedException', message: 'Invalid refresh token.', status: 400 }
    const clientId = rec.clientId || clientIdFrom(body, env)
    return { AuthenticationResult: await issueTokenSet(env, rec.email, clientId) }
  }

  const email = normalizeEmail(body?.AuthParameters?.USERNAME)
  if (!email) return { __type: 'NotAuthorizedException', message: 'Incorrect username or password.', status: 400 }

  const emailCount = await kvIncr(env, `rl:email:${email}`, RATE_WINDOW)
  const ipCount = await kvIncr(env, `rl:ip:${ipOf(ctx?.request)}`, RATE_WINDOW)
  if (emailCount > RATE_INITIATE_PER_EMAIL || ipCount > RATE_INITIATE_PER_IP) {
    return { __type: 'TooManyRequestsException', message: 'Attempt limit exceeded, please try again later.', status: 400 }
  }

  // Sin PASSWORD → rama OTP clásica (con mail, fallback para usuarios con
  // password). Con PASSWORD → sesión sin generar ni enviar OTP (sin mail).
  const started = await beginLogin(env, email, {
    passwordRequested: hasSecret(body?.AuthParameters?.PASSWORD) ? true : false,
  })
  if (!started.ok) {
    if (started.reason === 'password_disabled') {
      return { __type: 'NotAuthorizedException', message: 'Password login not enabled for this user.', status: 400 }
    }
    return { __type: 'NotAuthorizedException', message: 'Incorrect username or password.', status: 400 }
  }

  const params = {
    USERNAME: started.email,
    CODE_DELIVERY_DELIVERYMEDIUM: 'EMAIL',
    CODE_DELIVERY_DESTINATION: maskEmail(started.email),
  }
  if (started.mode === 'password') params.PASSWORD_ENABLED = 'true'
  return { ChallengeName: 'EMAIL_OTP', Session: started.session, ChallengeParameters: params }
}

export async function respondToAuthChallenge(env, ctx, body) {
  const done = await finishLogin(env, {
    email: body?.ChallengeResponses?.USERNAME,
    session: body?.Session,
    code: body?.ChallengeResponses?.EMAIL_OTP_CODE ?? body?.ChallengeResponses?.ANSWER,
    password: body?.ChallengeResponses?.PASSWORD,
  })
  if (!done.ok) {
    switch (done.reason) {
      case 'password_disabled':
        return { __type: 'NotAuthorizedException', message: 'Password login not enabled for this user.', status: 400 }
      case 'password_locked':
        return { __type: 'TooManyRequestsException', message: 'Attempt limit exceeded, please try again later.', status: 400 }
      case 'bad_password':
        return { __type: 'NotAuthorizedException', message: 'Incorrect username or password.', status: 400 }
      case 'bad_code': {
        const message = done.attemptsLeft <= 0
          ? 'Attempt limit exceeded, please try again later.'
          : 'Invalid verification code provided, please try again.'
        return { __type: 'CodeMismatchException', message, status: 400 }
      }
      default:
        return { __type: 'NotAuthorizedException', message: 'Invalid session or username.', status: 400 }
    }
  }

  const clientId = clientIdFrom(body, env)
  const authResult = await issueTokenSet(env, done.email, clientId)
  return { AuthenticationResult: authResult }
}

export async function getUserOp(env, ctx, body) {
  const token = body?.AccessToken || bearerToken(ctx?.request)
  const payload = await verifyAccessToken(env, token)
  if (!payload) return { __type: 'NotAuthorizedException', message: 'Invalid access token.', status: 400 }

  const user = await getUser(env, payload.sub)
  if (!user) return { __type: 'NotAuthorizedException', message: 'Invalid access token.', status: 400 }

  return {
    Username: payload.sub,
    UserAttributes: [
      { Name: 'email', Value: payload.sub },
      { Name: 'email_verified', Value: 'true' },
    ],
  }
}

export async function globalSignOut(env, ctx, body) {
  const token = body?.AccessToken || bearerToken(ctx?.request)
  const payload = await verifyAccessToken(env, token)
  if (payload) {
    await denyJti(env, payload.jti, payload.exp)
    await revokeUserRefreshTokens(env, payload.sub)
  }
  return {}
}

export function signUpStub(env, ctx) {
  return { __type: 'NotAuthorizedException', message: 'Sign up is not allowed.', status: 403 }
}

// OAuth hosted-UI style token endpoint (B2B): POST /oauth2/token.
// Como el Cognito real, NO va por X-Amz-Target: Basic (o body) + solo
// grant_type=client_credentials. Respuesta y errores en forma OAuth (minúsculas).
// Requiere Hono `c` (status + headers como WWW-Authenticate), no el shape IdP.
export async function oauthToken(c) {
  const env = c.env || {}
  const ct = c.req.header('content-type') || ''
  let body = {}
  if (ct.includes('application/json')) {
    body = await c.req.json().catch(() => ({}))
  } else {
    try {
      const parsed = await c.req.parseBody()
      for (const [k, v] of Object.entries(parsed || {})) body[k] = typeof v === 'string' ? v : String(v)
    } catch {
      body = {}
    }
  }
  const oauthError = (error, description, status = 400, headers = {}) =>
    c.json({ error, error_description: description }, status, headers);

  if (body.grant_type !== 'client_credentials') {
    return oauthError('unsupported_grant_type', 'only client_credentials is supported here')
  }
  const basic = parseBasicAuth(c.req.raw)
  const clientId = body.client_id || basic?.clientId || ''
  const clientSecret = body.client_secret || basic?.clientSecret || ''
  const client = await getClient(env, clientId)
  if (!(await checkM2mRateLimit(env, clientId || 'unknown', m2mIpOf(c.req.raw)))) {
    return oauthError('invalid_grant', 'attempt limit exceeded')
  }
  if (!client || !(await verifyClientSecret(client, clientSecret))) {
    return oauthError('invalid_client', 'invalid client credentials', 401, {
      'WWW-Authenticate': 'Basic realm="xid"',
    })
  }
  const requested = body.scope ? parseScopes(body.scope) : [...client.scopes]
  if (body.scope && !scopesAllowed(requested, client.scopes)) {
    return oauthError('invalid_scope', 'requested scope exceeds grant')
  }
  const iss = new URL(c.req.raw.url).origin
  const issued = await issueMachineToken(env, {
    clientId: client.clientId,
    scope: requested.join(' '),
    iss,
  })
  return c.json({
    access_token: issued.token,
    expires_in: issued.expiresIn,
    token_type: 'Bearer',
    scope: issued.scope,
  })
}

export { clientIdFrom, bearerToken }
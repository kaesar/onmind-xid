// Admin API for OnMind-XID (users + machine clients + roles).
//
// Mounted by index.js. Two authentication modes:
//   1. `x-api-key: XID_ADMIN_API_KEY` for scripts / CI / bootstrap.
//   2. `Authorization: Bearer <access token>` of an active user whose *current*
//      role is `admin`. This lets a trusted BFF call the API with the user's
//      token, without sharing a static key.
//
// Users:
//   GET    /admin/users
//   POST   /admin/users {email}
//   DELETE /admin/users/:email
//   PUT    /admin/users/:email/role {role}
// Clients:
//   GET    /admin/clients
//   POST   /admin/clients {clientId, scopes?, secret?}
//   PUT    /admin/clients/:clientId {scopes}
//   POST   /admin/clients/:clientId/rotate
//   DELETE /admin/clients/:clientId

import { constantTimeEqual, sha256Hex } from '../util/common.js'
import { getRole, getUser, setRole } from '../service/users.js'
import { verifyAccessToken } from '../auth/session.js'
import {
  addAdminUser,
  createAdminClient,
  listAdminClients,
  listAdminUsers,
  removeAdminClient,
  removeAdminUser,
  rotateAdminClientSecret,
  updateAdminClientScopes,
} from '../service/actions.js'

function error(c, message, status, extra = {}) {
  return c.json({ message, ...extra }, status)
}

function bearerToken(c) {
  const header = c.req.header('authorization') || ''
  const match = /^Bearer\s+(.+)$/i.exec(header)
  return match ? match[1] : null
}

async function authenticate(c) {
  const expected = c.env?.XID_ADMIN_API_KEY || process.env.XID_ADMIN_API_KEY || ''
  const apiKey = c.req.header('x-api-key') || ''

  if (expected && apiKey) {
    const [a, b] = await Promise.all([sha256Hex(apiKey), sha256Hex(expected)])
    if (constantTimeEqual(a, b)) return null
    return error(c, 'Forbidden.', 403)
  }

  const token = bearerToken(c)
  if (token) {
    const payload = await verifyAccessToken(c.env, token)
    if (!payload?.sub) return error(c, 'Invalid access token.', 401)
    const user = await getUser(c.env, payload.sub)
    if (!user) return error(c, 'User is no longer authorized.', 401)
    const role = await getRole(c.env, payload.sub)
    if (role !== 'admin') return error(c, 'Admin role required.', 403)
    return null
  }

  return error(c, 'Admin authentication required.', 401)
}

export function registerAdmin(app) {
  app.use('/admin/*', async (c, next) => {
    const denied = await authenticate(c)
    if (denied) return denied
    await next()
  })

  app.get('/admin/users', async (c) => {
    return c.json({ users: await listAdminUsers(c.env) })
  })

  app.post('/admin/users', async (c) => {
    const body = await c.req.json().catch(() => ({}))
    try {
      const user = await addAdminUser(c.env, body.email)
      return c.json(user, 201)
    } catch (e) {
      return error(c, e.message || 'Bad request', e.status || 400)
    }
  })

  app.delete('/admin/users/:email', async (c) => {
    try {
      const removed = await removeAdminUser(c.env, c.req.param('email'))
      if (!removed) return error(c, 'User not found.', 404)
      return c.body(null, 204)
    } catch (e) {
      return error(c, e.message || 'Bad request', e.status || 400)
    }
  })

  app.put('/admin/users/:email/role', async (c) => {
    const body = await c.req.json().catch(() => ({}))
    try {
      const role = await setRole(c.env, c.req.param('email'), body.role)
      if (!role) return error(c, 'User not found.', 404)
      return c.json({ email: c.req.param('email'), role })
    } catch (e) {
      return error(c, e.message || 'Bad request', e.status || 400)
    }
  })

  app.get('/admin/clients', async (c) => {
    return c.json({ clients: await listAdminClients(c.env) })
  })

  app.post('/admin/clients', async (c) => {
    const body = await c.req.json().catch(() => ({}))
    try {
      const client = await createAdminClient(c.env, body)
      return c.json(client, 201)
    } catch (e) {
      return error(c, e.message || 'Bad request', e.status || 400)
    }
  })

  app.put('/admin/clients/:clientId', async (c) => {
    const body = await c.req.json().catch(() => ({}))
    try {
      const client = await updateAdminClientScopes(c.env, c.req.param('clientId'), body.scopes)
      if (!client) return error(c, 'Client not found.', 404)
      return c.json(client)
    } catch (e) {
      return error(c, e.message || 'Bad request', e.status || 400)
    }
  })

  app.post('/admin/clients/:clientId/rotate', async (c) => {
    const client = await rotateAdminClientSecret(c.env, c.req.param('clientId'))
    if (!client) return error(c, 'Client not found.', 404)
    return c.json(client)
  })

  app.delete('/admin/clients/:clientId', async (c) => {
    const removed = await removeAdminClient(c.env, c.req.param('clientId'))
    if (!removed) return error(c, 'Client not found.', 404)
    return c.body(null, 204)
  })
}

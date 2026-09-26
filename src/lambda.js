// AWS Lambda entrypoint (Function URL or API Gateway HTTP API, v2 payload).
// Runtime nodejs22.x; handler = `src/lambda.handler` (ESM, "type": "module").
//
// App env = process.env (XID_JWT_SECRET, tables, CORS…) + the three DynamoDB
// bindings (XID_META / XID_USERS / XID_CLIENTS) exposing the same KV interface
// as Cloudflare — kv.js/users.js/clients.js do not care about the runtime.
//
// No SES for now: OTP by mail is unavailable (a passwordless request fails
// fast with 400 "Email delivery is not configured"); login on Lambda uses the
// bcrypt password from the xusers table. XID_ENV defaults to `production`.

import { handle } from 'hono/aws-lambda'
import { app } from './index.js'
import { createDynamoBindings } from './dynamo.js'

const env = {
  ...process.env,
  XID_ENV: process.env.XID_ENV || 'production',
  ...createDynamoBindings(process.env),
}

// hono/aws-lambda calls app.fetch(req, executionCtx); we intercept to inject
// our env (bindings) as the second argument of app.fetch.
export const handler = handle({
  fetch: (request, executionCtx) => app.fetch(request, env, executionCtx),
})

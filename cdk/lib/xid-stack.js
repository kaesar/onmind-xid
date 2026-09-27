// OnMind-XID stack: one Lambda (Hono app) fronted by an HTTP API (API Gateway v2)
// backed by three DynamoDB tables. The Lambda code is an ASSET of the REPO ROOT
// (the same tree the Cloudflare Worker and the Bun container run), so
// `src/lambda.handler` + node_modules ship as-is — no bundling step.
//
// Config is CDK context (cdk.json defaults, overridable with -c key=value):
//   jwtSecret        REQUIRED: XID_JWT_SECRET (>=32 chars). Prefer the
//                    XID_JWT_SECRET env var so the secret never hits argv/shell
//                    history. NOTE: embedded in the Lambda environment (CFN
//                    template in cdk.out, git-ignored); rotate to Secrets
//                    Manager for long-lived prod.
//   removalPolicy    retain (default, prod) | destroy (throwaway/Floci envs)
//   deletionProtection  true (default) | false — blocks even explicit
//                    DeleteTable while the stack exists
//   pointInTimeRecovery true (default) | false — 35-day PITR
//   tablePrefix      prepended to xusers/xclients/xmeta (multi-env accounts)
//   xidEnv           XID_ENV for the app (default production)
//   corsOrigins      comma list → XID_CORS_ORIGINS
//   redirectAllowlist comma list → XID_REDIRECT_ALLOWLIST
//   tenantId/clientId → XID_TENANT_ID / XID_CLIENT_ID
//   xinUrl           base URL of OnMind-XIN → XID_XIN_URL (OTP mail via
//                    POST /send; the only mail transport that works on Lambda)
//   xinApiKey        optional XIN key → XID_XIN_API_KEY. Prefer the
//                    XID_XIN_API_KEY env var (same secrecy caveat as jwtSecret)
//   localEndpoint    emulator URL (Floci/LocalStack) → AWS_ENDPOINT_URL +
//                    XID_DYNAMO_ENDPOINT inside the Lambda
'use strict'
const path = require('node:path')
const cdk = require('aws-cdk-lib')
const lambda = require('aws-cdk-lib/aws-lambda')
const dynamodb = require('aws-cdk-lib/aws-dynamodb')
const apigwv2 = require('aws-cdk-lib/aws-apigatewayv2')
const { HttpLambdaIntegration } = require('aws-cdk-lib/aws-apigatewayv2-integrations')
const logs = require('aws-cdk-lib/aws-logs')

const REPO_ROOT = path.join(__dirname, '..', '..')

function ctx(stack, key, def = '') {
  const v = stack.node.tryGetContext(key)
  return v === undefined || v === null || v === '' ? def : v
}

function ctxBool(stack, key, def) {
  const v = stack.node.tryGetContext(key)
  if (v === undefined || v === null || v === '') return def
  return v === true || v === 'true'
}

function ctxList(stack, key) {
  return String(ctx(stack, key, ''))
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

class XidStack extends cdk.Stack {
  constructor(scope, id, props = {}) {
    super(scope, id, props)

    const tablePrefix = String(ctx(this, 'tablePrefix', ''))
    const removal =
      String(ctx(this, 'removalPolicy', 'retain')).toLowerCase() === 'destroy'
        ? cdk.RemovalPolicy.DESTROY
        : cdk.RemovalPolicy.RETAIN
    const deletionProtection = ctxBool(this, 'deletionProtection', true)
    const pitr = ctxBool(this, 'pointInTimeRecovery', true)

    // ---------- DynamoDB ----------
    // Schema must match src/dynamo.js + scripts/bootstrap-dynamo.js:
    // pk (S) = key, v (S) = value, ttl (N) = optional epoch seconds (xmeta only).
    const table = (short, { ttl = false } = {}) =>
      new dynamodb.Table(this, `${short}Table`, {
        tableName: `${tablePrefix}${short}`,
        partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
        billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
        pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: pitr },
        timeToLiveAttribute: ttl ? 'ttl' : undefined,
        removalPolicy: removal,
        deletionProtection,
      })

    const usersTable = table('xusers') // allowlist: email → password hash / OTP key
    const clientsTable = table('xclients') // B2B clients (hashes only)
    const metaTable = table('xmeta', { ttl: true }) // otp:/sess:/rl:/refresh (TTL)

    // ---------- Lambda env ----------
    const jwtSecret = process.env.XID_JWT_SECRET || String(ctx(this, 'jwtSecret', ''))
    if (!jwtSecret || jwtSecret.length < 32) {
      throw new Error(
        'XID_JWT_SECRET (>= 32 chars) is required: export XID_JWT_SECRET=... ' +
          '(recommended) or deploy with -c jwtSecret=...'
      )
    }

    const fnEnv = {
      XID_ENV: String(ctx(this, 'xidEnv', 'production')),
      XID_JWT_SECRET: jwtSecret,
      XID_USERS_TABLE: usersTable.tableName,
      XID_CLIENTS_TABLE: clientsTable.tableName,
      XID_META_TABLE: metaTable.tableName,
    }
    const cors = ctxList(this, 'corsOrigins')
    if (cors.length) fnEnv.XID_CORS_ORIGINS = cors.join(',')
    const redirects = ctxList(this, 'redirectAllowlist')
    if (redirects.length) fnEnv.XID_REDIRECT_ALLOWLIST = redirects.join(',')
    const tenantId = String(ctx(this, 'tenantId', ''))
    if (tenantId) fnEnv.XID_TENANT_ID = tenantId
    const clientId = String(ctx(this, 'clientId', ''))
    if (clientId) fnEnv.XID_CLIENT_ID = clientId

    // Mail via XIN over HTTP (works on Lambda; plain SMTP has no listener there
    // unless XIN runs as a container). Secret: prefer the env var.
    const xinUrl = String(ctx(this, 'xinUrl', '') || process.env.XID_XIN_URL || '')
    if (xinUrl) fnEnv.XID_XIN_URL = xinUrl
    const xinApiKey = process.env.XID_XIN_API_KEY || String(ctx(this, 'xinApiKey', ''))
    if (xinApiKey) fnEnv.XID_XIN_API_KEY = xinApiKey

    // Floci/LocalStack: SDK v3 resolves AWS_ENDPOINT_URL globally; dynamo.js
    // additionally honours XID_DYNAMO_ENDPOINT (both set for belt and braces).
    const localEndpoint = String(ctx(this, 'localEndpoint', ''))
    if (localEndpoint) {
      fnEnv.AWS_ENDPOINT_URL = localEndpoint
      fnEnv.XID_DYNAMO_ENDPOINT = localEndpoint
    }

    // ---------- Lambda ----------
    const xidFn = new lambda.Function(this, 'XidFunction', {
      description: 'OnMind-XID identity provider (Hono)',
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'src/lambda.handler',
      // Repo-root asset: keep in sync with the tree the CF Worker runs.
      code: lambda.Code.fromAsset(REPO_ROOT, {
        exclude: [
          '.git',
          '.github',
          '.wrangler',
          'cdk', // this CDK app + its node_modules
          'PLAN.md',
          'xusers.txt', // never ship local secrets in the package
          'xclients.txt',
          '.dev.vars',
          'files', // local demo uploads; re-include deliberately if needed
          '*.log',
          'bun.lock',
        ],
      }),
      memorySize: 512,
      timeout: cdk.Duration.seconds(30),
      environment: fnEnv,
      // Explicit log group (retention set here; `logRetention` is deprecated).
      // The AWSLambdaBasicExecutionRole policy covers logs on arn:aws:logs:*:*:*.
      logGroup: new logs.LogGroup(this, 'XidLogs', {
        retention: logs.RetentionDays.TWO_WEEKS,
        removalPolicy: removal,
      }),
    })

    // ---------- HTTP API ----------
    // Single public front door for the apps (PUB/web/AI/M2M) and xid itself:
    // ANY / and ANY /{proxy+} → Lambda. CORS/origin allowlisting is enforced by
    // the app (XID_CORS_ORIGINS), so the gateway stays out of the way.
    const api = new apigwv2.HttpApi(this, 'XidHttpApi', {
      apiName: `${tablePrefix}xid-api`,
      description: 'OnMind-XID API (apps & xid)',
    })

    const integration = new HttpLambdaIntegration('LambdaIntegration', xidFn)
    api.addRoutes({ path: '/{proxy+}', methods: [apigwv2.HttpMethod.ANY], integration })
    api.addRoutes({ path: '/', methods: [apigwv2.HttpMethod.ANY], integration })

    // ---------- Outputs ----------
    new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: api.apiEndpoint,
      description: 'Base URL (XID_URL / apps entry point)',
    })
    new cdk.CfnOutput(this, 'FunctionName', { value: xidFn.functionName })
    new cdk.CfnOutput(this, 'UsersTable', { value: usersTable.tableName })
    new cdk.CfnOutput(this, 'ClientsTable', { value: clientsTable.tableName })
    new cdk.CfnOutput(this, 'MetaTable', { value: metaTable.tableName })
  }
}

module.exports = { XidStack }

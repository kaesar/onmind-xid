#!/usr/bin/env bun
// Genera un par RSA-2048 y emite la JWK privada (con kid) para XID_RSA_PRIVATE_JWK.
// Uso:
//   bun scripts/gen-rsa-jwk.js [--kid xid-1]
// Guarda la salida como secreto: `npx wrangler secret put XID_RSA_PRIVATE_JWK < jwk.json`
// (nunca en wrangler.toml ni en git).

const kidArg = process.argv.indexOf('--kid')
const kid = kidArg >= 0 && process.argv[kidArg + 1] ? process.argv[kidArg + 1] : 'xid-1'

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
jwk.kid = kid
jwk.alg = 'RS256'
jwk.use = 'sig'
console.log(JSON.stringify(jwk))

// Local development entrypoint (Bun).
// Usage: `bun src/dev.js` (native hot reload: reuses the socket). Listens on PORT || 8787.
// Does not export a default `{ fetch }`, so Bun does not auto-serve on 3000: there is a single server.
import { app } from './index.js'

const port = Number(process.env.PORT || 8787)
const envDev = { ...process.env }
if (!envDev.XID_JWT_SECRET) {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  envDev.XID_JWT_SECRET = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  console.log('[xid] dev: no XID_JWT_SECRET set, using ephemeral dev secret')
}

console.log(`[xid] listening on http://localhost:${port}`)
const server = Bun.serve({
  port,
  fetch: (request) => app.fetch(request, envDev, { waitUntil: () => {} }),
  development: true, // hot reload: reuses the socket; does not close the port between reloads
})
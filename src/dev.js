// Entrypoint de desarrollo local (Bun).
// Uso: `bun src/dev.js` (hot reload nativo: reusa el socket). Escucha en PORT || 8787.
// No exporta default `{ fetch }`, así Bun no auto-sirve en 3000: hay un solo servidor.
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
  development: true, // hot reload: reusa el socket; no cierra el puerto entre recargas
})
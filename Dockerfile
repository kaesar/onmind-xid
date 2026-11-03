# OnMind-XID in a container (VM scenario, alternative to Cloudflare Worker).
# Without KV: uses FS adapters (xusers.txt/xclients.txt, XID_FILES_ROOT) and
# memory for OTP/rate-limit/codes. Intended for 1 replica (see README).
FROM oven/bun:1-slim

WORKDIR /app

COPY package.json ./
RUN bun install --production

COPY src/ ./src/
COPY vendor/ ./vendor/
COPY xusers.txt.example ./xusers.txt.example
COPY xclients.txt.example ./xclients.txt.example
COPY cli/ ./cli/

RUN useradd -m -u 10001 xid && \
    mkdir -p /data/files && \
    chown -R xid:xid /app /data/files
USER xid

ENV PORT=8787 \
    XID_ENV=production \
    XID_USERS_TXT=/data/xusers.txt \
    XID_CLIENTS_TXT=/data/xclients.txt \
    XID_FILES_ROOT=/data/files

VOLUME /data
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["bun", "-e", "fetch('http://localhost:'+(process.env.PORT||8787)+'/health').then(r=>{if(!r.ok)process.exit(1)})"]

CMD ["bun", "src/dev.js"]

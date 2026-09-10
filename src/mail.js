// Transportes de mail:
//  1. Cloudflare Email Service  → binding send_email `env.MAIL.send(...)`
//  2. SMTP (Mailpit en dev)     → host/puerto por env, default 127.0.0.1:1025
//  3. Consola (fallback)        → solo si XID_ENV=dev

export async function sendMail(env, { to, from, subject, text, code }) {
  const envResolved = env || {}
  const fromAddr = from || envResolved.XID_MAIL_FROM || 'noreply@localhost'

  if (envResolved.MAIL && typeof envResolved.MAIL.send === 'function') {
    await envResolved.MAIL.send({ to, from: fromAddr, subject, text })
    return { via: 'cloudflare' }
  }

  const host = envResolved.XID_SMTP_HOST || process.env.XID_SMTP_HOST || '127.0.0.1'
  const port = Number(envResolved.XID_SMTP_PORT || process.env.XID_SMTP_PORT || 1025)
  if (process.env.XID_SMTP_DISABLED !== '1') {
    try {
      const smtp = await import('node:net')
      await smtpSend(smtp, { host, port, from: fromAddr, to, subject, text })
      return { via: 'smtp', host, port }
    } catch (err) {
      if (envResolved.XID_ENV === 'production') throw err
      // dev: cae al fallback consola
    }
  }

  if (envResolved.XID_ENV === 'production') {
    throw new Error('mail: no transport available')
  }
  const codeLine = code ? `   OTP-Code: ${code}` : ''
  console.log(`[xid:mail:console] to=${to}\n${codeLine}\n${text}`)
  return { via: 'console' }
}

export function makeOtpMessage(code, email, lang = 'en') {
  if (lang === 'es') {
    return {
      subject: 'Tu código de acceso',
      text: `Tu código de acceso OnMind es ${code}\n\nVence en 5 minutos. Si no lo solicitaste, ignora este mensaje.\n`,
      code,
    }
  }
  return {
    subject: 'Your login code',
    text: `Your OnMind login code is ${code}\n\nIt expires in 5 minutes. If you did not request it, ignore this message.\n`,
    code,
  }
}

function smtpSend(net, { host, port, from, to, subject, text }) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port })
    let buffer = ''
    const pending = []

    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1')
      let m
      while ((m = /^(\d{3})([ -])([^\r\n]*)\r?\n/m.exec(buffer))) {
        buffer = buffer.slice(m.index + m[0].length)
        if (m[2] === ' ') {
          const cb = pending.shift()
          if (cb) cb(Number(m[1]), m[3])
        }
      }
    })

    const expect = (code) =>
      new Promise((res, rej) => {
        pending.push((got, msg) => {
          if (got === code) res(msg)
          else rej(new Error(`smtp ${got} ${msg}`))
        })
      })
    const send = (cmd) => socket.write(cmd + '\r\n')

    socket.on('error', reject)
    socket.on('close', () => reject(new Error('smtp connection closed')))

    ;(async () => {
      try {
        await expect(220)
        send('EHLO xid.local')
        await expect(250)
        send(`MAIL FROM:<${from}>`)
        await expect(250)
        send(`RCPT TO:<${to}>`)
        await expect(250)
        send('DATA')
        await expect(354)
        const body =
          `From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${text}`
            .split('\n').map((l) => l.startsWith('.') ? '.' + l : l).join('\r\n')
        socket.write(body + '\r\n.\r\n')
        await expect(250)
        send('QUIT')
        await expect(221)
        socket.end()
        resolve()
      } catch (err) {
        socket.destroy()
        reject(err)
      }
    })()
  })
}
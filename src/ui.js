// Shared HTML UI for the Entra facade and the generic /login page.
// Forms are plain POSTs (no JS required); the CUI bundle is progressive
// enhancement, with a native fallback when it fails to load.

import { maskEmail } from './util.js'
import { cuiUrl } from './assets.js'

// ---------------- strings (English default, Spanish) ----------------

const STRINGS = {
  en: {
    sign_in: 'Sign in',
    verify_code: 'Verify code',
    email: 'Email',
    email_ph: 'you@email.com',
    send_code: 'Send code',
    code_label: '6-digit code',
    code_ph: '123456',
    verify_btn: 'Verify and sign in',
    code_sent_to: 'Code sent to',
    otp_hint: 'You will receive a 6-digit code valid for 5 min.',
    logged_out: 'Signed out',
    session_revoked: 'Token revoked (if Bearer was sent).',
    error_title: 'Error',
    err_invalid_email: 'Invalid email.',
    err_not_allowlisted: 'Email not authorized (allowlist).',
    err_not_authorized: 'Email not authorized.',
    err_session_expired: 'Session expired. Request a new code.',
    err_code_invalid: 'Invalid code. Try again.',
    err_attempts: 'Attempt limit reached. Request a new code.',
    err_rate: 'Too many attempts. Try again later.',
    err_missing_client: 'Missing client_id',
    err_redirect: 'redirect_uri not allowed',
    redirect_hint: 'Set XID_REDIRECT_ALLOWLIST.',
    err_post_logout: 'post_logout_redirect_uri not allowed',
    password: 'Password',
    password_ph: 'Your password',
    password_btn: 'Sign in with password',
    password_for: 'Signing in as',
    use_code_link: 'Use email code instead',
    use_password_link: 'Use password instead',
    err_invalid_password: 'Invalid password.',
    err_mail_unavailable: 'Email delivery not configured; password login required.',
  },
  es: {
    sign_in: 'Iniciar sesión',
    verify_code: 'Verificar código',
    email: 'Email',
    email_ph: 'tu@email.com',
    send_code: 'Enviar código',
    code_label: 'Código de 6 dígitos',
    code_ph: '123456',
    verify_btn: 'Verificar e iniciar sesión',
    code_sent_to: 'Código enviado a',
    otp_hint: 'Recibirás un código de 6 dígitos válido 5 min.',
    logged_out: 'Sesión cerrada',
    session_revoked: 'Token revocado (si se envió Bearer).',
    error_title: 'Error',
    err_invalid_email: 'Email inválido.',
    err_not_allowlisted: 'Email no autorizado (allowlist).',
    err_not_authorized: 'Email no autorizado.',
    err_session_expired: 'Sesión expirada. Pide un código nuevo.',
    err_code_invalid: 'Código inválido. Inténtalo de nuevo.',
    err_attempts: 'Límite de intentos. Pide un código nuevo.',
    err_rate: 'Demasiados intentos. Inténtalo más tarde.',
    err_missing_client: 'Falta client_id',
    err_redirect: 'redirect_uri no permitido',
    redirect_hint: 'Configura XID_REDIRECT_ALLOWLIST.',
    err_post_logout: 'post_logout_redirect_uri no permitido',
    password: 'Contraseña',
    password_ph: 'Tu contraseña',
    password_btn: 'Entrar con contraseña',
    password_for: 'Iniciando sesión como',
    use_code_link: 'Usar código por email',
    use_password_link: 'Usar contraseña',
    err_invalid_password: 'Contraseña inválida.',
    err_mail_unavailable: 'Envío de email no configurado; se requiere contraseña.',
  },
}

export function pickLang(request, params) {
  const fromParam = String(params?.ui_locales || '')
    .split(/[\s_+,;]+/)
    .map((s) => s.toLowerCase().split('-')[0])
    .find((s) => s === 'en' || s === 'es')
  if (fromParam) return fromParam
  const header = request?.headers?.get('accept-language') || ''
  for (const part of header.split(',')) {
    const tag = part.split(';')[0].trim().toLowerCase().split('-')[0]
    if (tag === 'en' || tag === 'es') return tag
  }
  return 'en'
}

export const t = (lang, key) => (STRINGS[lang] || STRINGS.en)[key] || key

export function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

// ---------------- page shell ----------------

function cuiScript() {
  return `<script type="module" src="${esc(cuiUrl())}"></script>`
}

// Minimal CUI ↔ native form bridge:
// - `as-input` is not form-associated: on submit its values are copied to hidden.
// - `as-button` emits `button-tap`: triggers the form submit.
// - Fallback: if the CUI bundle fails to load, native input/button replace them.
const CUI_BRIDGE = `<script>
(function(){
  function ensureHidden(form, name, value) {
    var h = form.querySelector('input[type="hidden"][name="' + name + '"]');
    if (!h) { h = document.createElement('input'); h.type = 'hidden'; h.name = name; form.appendChild(h); }
    if (value !== undefined) h.value = value;
    return h;
  }
  function sync(form) {
    form.querySelectorAll('as-input[name]').forEach(function (el) {
      ensureHidden(form, el.getAttribute('name'), el.getAttribute('value') || '');
    });
  }
  function fallback() {
    document.querySelectorAll('as-input').forEach(function (el) {
      var i = document.createElement('input');
      i.name = el.getAttribute('name') || ''; i.type = el.getAttribute('kind') || 'text';
      i.placeholder = el.getAttribute('placeholder') || ''; i.value = el.getAttribute('value') || '';
      i.required = true; i.setAttribute('aria-label', el.getAttribute('label') || i.name);
      el.replaceWith(i);
    });
    document.querySelectorAll('as-button').forEach(function (el) {
      var b = document.createElement('button'); b.type = 'submit'; b.textContent = el.getAttribute('label') || 'Submit';
      el.replaceWith(b);
    });
  }
  function ready() {
    var ok = window.customElements && customElements.get('as-input') && customElements.get('as-button') && customElements.get('as-box');
    if (!ok) { fallback(); return; }
    document.querySelectorAll('form[data-cui]').forEach(function (f) {
      var b = f.querySelector('as-button');
      if (b) b.addEventListener('button-tap', function () { f.requestSubmit(); });
      f.addEventListener('submit', function (ev) {
        sync(f);
        var empty = false;
        f.querySelectorAll('as-input[name]').forEach(function (el) {
          if (!((el.getAttribute('value') || '').trim())) empty = true;
        });
        if (empty) ev.preventDefault();
      });
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { setTimeout(ready, 400); });
  else setTimeout(ready, 400);
})();
</script>`

export function pageShell(title, inner, env, lang = 'en') {
  return `<!doctype html><html lang="${lang === 'es' ? 'es' : 'en'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>` +
    cuiScript() +
    `<style>html,body{margin:0;padding:0}body{font-family:system-ui,sans-serif;background:#0f172a;color:#e5e7eb;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem;box-sizing:border-box}.wrap{width:100%;max-width:24rem}as-box h1{font-size:1.25rem;margin:0 0 .25rem;color:#111827}as-box .muted{color:#6b7280;font-size:.85rem}as-box .err{background:#fde7e7;border:1px solid #f3b4b4;color:#7f1d1d;padding:.6rem .8rem;border-radius:.4rem}as-box a{color:#1d4ed8}as-box as-button{display:block;margin-top:.9rem}as-box input[type=text],as-box input[type=email]{font-size:1rem;padding:.55rem .7rem;width:100%;box-sizing:border-box;margin-top:.5rem}as-box button[type=submit]{font-size:1rem;padding:.55rem 1rem;width:100%;box-sizing:border-box;cursor:pointer;margin-top:.9rem}</style></head><body><div class="wrap"><as-box>${inner}</as-box></div>${CUI_BRIDGE}</body></html>`
}

export function hiddenFields(params) {
  return Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join('')
}

// ---------------- forms ----------------

export function emailForm(params, { errorKey = '', email = '', env = {}, lang = 'en' } = {}) {
  return pageShell(
    t(lang, 'sign_in'),
    `<h1>${esc(t(lang, 'sign_in'))}</h1>` +
      (errorKey ? `<p class="err">${esc(t(lang, errorKey))}</p>` : '') +
      `<form method="post" data-cui>` +
      hiddenFields(params) +
      `<as-input name="email" kind="email" autofocus label="${esc(t(lang, 'email'))}" placeholder="${esc(t(lang, 'email_ph'))}" value="${esc(email)}"></as-input>` +
      `<as-button label="${esc(t(lang, 'send_code'))}" variant="primary"></as-button></form>` +
      `<p class="muted">${esc(t(lang, 'otp_hint'))}</p>`,
    env,
    lang
  )
}

// No redundant email input: the email travels in a hidden field (server-set)
// and is shown as text ("Code sent to …").
export function codeForm(params, { errorKey = '', email = '', otpSession = '', sentTo = '', switchUrl = '', env = {}, lang = 'en' } = {}) {
  return pageShell(
    t(lang, 'verify_code'),
    `<h1>${esc(t(lang, 'verify_code'))}</h1>` +
      (errorKey ? `<p class="err">${esc(t(lang, errorKey))}</p>` : '') +
      `<p class="muted">${esc(t(lang, 'code_sent_to'))} ${esc(sentTo || maskEmail(email))}.</p>` +
      `<form method="post" data-cui>` +
      hiddenFields({ ...params, otp_session: otpSession }) +
      `<input type="hidden" name="email" value="${esc(email)}">` +
      `<as-input name="code" kind="text" autofocus label="${esc(t(lang, 'code_label'))}" placeholder="${esc(t(lang, 'code_ph'))}" value=""></as-input>` +
      `<as-button label="${esc(t(lang, 'verify_btn'))}" variant="primary"></as-button></form>` +
      (switchUrl ? `<p class="muted"><a href="${esc(switchUrl)}">${esc(t(lang, 'use_password_link'))}</a></p>` : ''),
    env,
    lang
  )
}

// Real password (bcrypt) login. Alternative to OTP; the link switches to OTP
// (fallback when forgotten) without losing the form parameters.
export function passwordForm(params, { errorKey = '', email = '', otpSession = '', switchUrl = '', env = {}, lang = 'en' } = {}) {
  return pageShell(
    t(lang, 'sign_in'),
    `<h1>${esc(t(lang, 'sign_in'))}</h1>` +
      (errorKey ? `<p class="err">${esc(t(lang, errorKey))}</p>` : '') +
      `<p class="muted">${esc(t(lang, 'password_for'))} ${esc(email)}.</p>` +
      `<form method="post" data-cui>` +
      hiddenFields({ ...params, otp_session: otpSession }) +
      `<input type="hidden" name="email" value="${esc(email)}">` +
      `<as-input name="password" kind="password" autofocus label="${esc(t(lang, 'password'))}" placeholder="${esc(t(lang, 'password_ph'))}" value=""></as-input>` +
      `<as-button label="${esc(t(lang, 'password_btn'))}" variant="primary"></as-button></form>` +
      (switchUrl ? `<p class="muted"><a href="${esc(switchUrl)}">${esc(t(lang, 'use_code_link'))}</a></p>` : ''),
    env,
    lang
  )
}

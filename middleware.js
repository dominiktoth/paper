// Jelszavas védelem az egész oldalra (Vercel Edge Middleware, függőség nélkül).
// A jelszó a Vercel projekt SITE_PASSWORD környezeti változója — a repóban NINCS benne.
// Sikeres belépés után 1 évig érvényes süti, tehát eszközönként egyszer kell beírni.
export const config = { matcher: '/((?!favicon.ico).*)' };

const COOKIE = 'paper_auth';
const YEAR = 60 * 60 * 24 * 365;

async function token(pw) {
  const data = new TextEncoder().encode('paper-site-v1:' + pw);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function same(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function page(error) {
  const html = `<!doctype html><html lang="hu"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Belépés</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0e1116;color:#e8eaed;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
form{width:min(320px,calc(100vw - 32px));display:grid;gap:12px}
h1{font-size:20px;margin:0 0 4px;font-weight:600}
input,button{font:inherit;padding:12px 14px;border-radius:8px;border:1px solid #2b313b;background:#161a21;color:inherit}
input:focus-visible,button:focus-visible{outline:2px solid #7aa2f7;outline-offset:2px}
button{background:#2f6feb;border-color:#2f6feb;color:#fff;cursor:pointer}
p{margin:0;color:#f28b82;min-height:1.5em}
</style></head><body><form method="post" action="/__login">
<h1>Belépés</h1>
<label for="pw">Jelszó</label>
<input id="pw" name="password" type="password" autocomplete="current-password" autofocus required>
<button type="submit">Belépés</button>
<p role="alert">${error ? 'Hibás jelszó.' : ''}</p>
</form></body></html>`;
  return new Response(html, { status: 401, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

export default async function middleware(request) {
  const pw = process.env.SITE_PASSWORD;
  // Amíg a SITE_PASSWORD nincs beállítva, az oldal védelem nélkül megy tovább (nem áll le); a fejléc jelzi.
  if (!pw) return new Response(null, { headers: { 'x-middleware-next': '1', 'x-site-protection': 'off' } });
  const good = await token(pw);
  const url = new URL(request.url);

  if (url.pathname === '/__login' && request.method === 'POST') {
    const form = await request.formData();
    const given = await token(String(form.get('password') || ''));
    if (!same(given, good)) return page(true);
    return new Response(null, {
      status: 303,
      headers: {
        location: '/',
        'set-cookie': `${COOKIE}=${good}; Path=/; Max-Age=${YEAR}; HttpOnly; Secure; SameSite=Lax`,
      },
    });
  }

  const m = (request.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + COOKIE + '=([a-f0-9]{64})'));
  if (m && same(m[1], good)) return new Response(null, { headers: { 'x-middleware-next': '1' } });
  return page(false);
}

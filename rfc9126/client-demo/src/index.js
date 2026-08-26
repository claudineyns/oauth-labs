const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { createSession, getSession, updateSession, destroySession } = require('./store');
const { homePage, dashboardPage, clientCredentialsResultPage, errorPage } = require('./views');
const { captureInbound, instrumentedFetch } = require('./events');

const PORT = process.env.PORT || 3200;
const AS_BASE_URL = process.env.AS_BASE_URL; // uso interno (container-to-container)
const AS_PUBLIC_BASE_URL = process.env.AS_PUBLIC_BASE_URL; // uso no browser (redirects)
const RS_BASE_URL = process.env.RS_BASE_URL;
const CLIENT_ID = process.env.DEMO_CLIENT_ID;
const CLIENT_SECRET = process.env.DEMO_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
// observabilidade: toda requisicao recebida aqui vem do browser
app.use(captureInbound('client', 'browser'));

function basicAuthHeader() {
  return 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
}

function session(req) {
  return getSession(req.cookies.sid);
}

async function callResourceServer(token, via, path) {
  let url = `${RS_BASE_URL}${path}`;
  const init = { method: via === 'body' ? 'POST' : 'GET', headers: {} };
  if (via === 'header') {
    init.headers.Authorization = `Bearer ${token}`;
  } else if (via === 'body') {
    init.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    init.body = new URLSearchParams({ access_token: token });
  } else if (via === 'query') {
    url += `?access_token=${encodeURIComponent(token)}`;
  }
  const r = await instrumentedFetch('client', 'resource-server', url, init);
  const wwwAuthenticate = r.headers.get('www-authenticate');
  const body = await r.json().catch(() => ({}));
  return { via, status: r.status, wwwAuthenticate, body };
}

app.get('/', (req, res) => {
  const sess = session(req);
  if (sess && sess.accessToken) return res.redirect('/dashboard');
  res.send(homePage({ clientId: CLIENT_ID }));
});

// RFC 9126 — antes de tocar o browser, empurra os parametros da authorization
// request via POST autenticado e recebe uma referencia opaca (request_uri).
app.get('/login', async (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  res.cookie('oauth_state', state, { httpOnly: true, maxAge: 5 * 60 * 1000, sameSite: 'lax' });

  const parRes = await instrumentedFetch('client', 'authorization-server', `${AS_BASE_URL}/par`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basicAuthHeader() },
    body: new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'profile email',
      state,
    }),
  });
  const parBody = await parRes.json();
  if (!parRes.ok) return res.send(errorPage(`Falha ao empurrar a authorization request (PAR): ${JSON.stringify(parBody)}`));

  const url = new URL(`${AS_PUBLIC_BASE_URL}/authorize`);
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('request_uri', parBody.request_uri);
  res.redirect(url.toString());
});

app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.send(errorPage(`Autorização negada ou falhou: ${error}`));
  if (!state || state !== req.cookies.oauth_state) {
    return res.send(errorPage('state inválido — possível CSRF, fluxo abortado.'));
  }
  res.clearCookie('oauth_state');

  const tokenRes = await instrumentedFetch('client', 'authorization-server', `${AS_BASE_URL}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basicAuthHeader() },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI }),
  });
  const tokenBody = await tokenRes.json();
  if (!tokenRes.ok) return res.send(errorPage(`Falha ao trocar code por token: ${JSON.stringify(tokenBody)}`));

  const sid = createSession({
    accessToken: tokenBody.access_token,
    refreshToken: tokenBody.refresh_token,
    scope: tokenBody.scope,
    expiresIn: tokenBody.expires_in,
    obtainedAt: Date.now(),
  });
  res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax' });
  res.redirect('/dashboard');
});

app.get('/dashboard', (req, res) => {
  const sess = session(req);
  if (!sess) return res.redirect('/');
  res.send(dashboardPage(sess));
});

app.post('/action/call', async (req, res) => {
  const sid = req.cookies.sid;
  const sess = getSession(sid);
  if (!sess) return res.redirect('/');
  const { via } = req.body;
  const result = await callResourceServer(sess.accessToken, via, '/api/profile');
  updateSession(sid, { lastResult: result });
  res.redirect('/dashboard');
});

app.post('/action/invalid-token', async (req, res) => {
  const sid = req.cookies.sid;
  const sess = getSession(sid);
  if (!sess) return res.redirect('/');
  const result = await callResourceServer('0'.repeat(48), 'header', '/api/profile');
  updateSession(sid, { lastResult: result });
  res.redirect('/dashboard');
});

app.post('/action/refresh', async (req, res) => {
  const sid = req.cookies.sid;
  const sess = getSession(sid);
  if (!sess) return res.redirect('/');

  const tokenRes = await instrumentedFetch('client', 'authorization-server', `${AS_BASE_URL}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basicAuthHeader() },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: sess.refreshToken }),
  });
  const body = await tokenRes.json();

  if (tokenRes.ok) {
    updateSession(sid, {
      accessToken: body.access_token,
      refreshToken: body.refresh_token,
      scope: body.scope,
      expiresIn: body.expires_in,
      obtainedAt: Date.now(),
      lastResult: { via: 'refresh_token', status: tokenRes.status, body },
    });
  } else {
    updateSession(sid, { lastResult: { via: 'refresh_token', status: tokenRes.status, body } });
  }
  res.redirect('/dashboard');
});

app.post('/action/client-credentials', async (req, res) => {
  const tokenRes = await instrumentedFetch('client', 'authorization-server', `${AS_BASE_URL}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basicAuthHeader() },
    body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'service' }),
  });
  const body = await tokenRes.json();

  let rsResult = null;
  if (tokenRes.ok) {
    rsResult = await callResourceServer(body.access_token, 'header', '/api/service-info');
  }
  res.send(clientCredentialsResultPage({ tokenRes: { status: tokenRes.status, body }, rsResult }));
});

app.get('/logout', (req, res) => {
  if (req.cookies.sid) destroySession(req.cookies.sid);
  res.clearCookie('sid');
  res.redirect('/');
});

app.get('/healthz', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`[client-demo] ouvindo em :${PORT}`));

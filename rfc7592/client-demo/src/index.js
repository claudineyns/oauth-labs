const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { createSession, getSession, updateSession, destroySession } = require('./store');
const { homePage, dashboardPage, clientCredentialsResultPage, registrationResultPage, errorPage } = require('./views');
const { captureInbound, instrumentedFetch } = require('./events');

const PORT = process.env.PORT || 3300;
const AS_BASE_URL = process.env.AS_BASE_URL; // uso interno (container-to-container)
const AS_PUBLIC_BASE_URL = process.env.AS_PUBLIC_BASE_URL; // uso no browser (redirects)
const RS_BASE_URL = process.env.RS_BASE_URL;
const REDIRECT_URI = process.env.REDIRECT_URI;

const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
// observabilidade: toda requisicao recebida aqui vem do browser
app.use(captureInbound('client', 'browser'));

// Preenchido só quando o usuário aciona "Registrar client agora" na home —
// registro deixou de acontecer sozinho na inicialização (ver /action/register
// abaixo) e vira uma ação manual e visível. Enquanto reg for null, nenhuma
// outra funcionalidade fica disponível (ver requireRegistration).
let reg = null;

function basicAuthHeader() {
  return 'Basic ' + Buffer.from(`${reg.client_id}:${reg.client_secret}`).toString('base64');
}

function session(req) {
  return getSession(req.cookies.sid);
}

// Login, chamadas ao RS e gerenciamento do registro exigem um client_id
// válido — sem isso, mandam de volta para a home, onde o único botão
// disponível é o de registro.
function requireRegistration(req, res, next) {
  if (!reg) return res.redirect('/');
  next();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// RFC 8414 — descobre os endpoints do AS a partir de um unico documento,
// em vez de tudo hardcoded. Repete algumas vezes caso o AS ainda esteja subindo.
async function discoverMetadata(retries = 10) {
  for (let i = 0; i < retries; i += 1) {
    try {
      const res = await fetch(`${AS_BASE_URL}/.well-known/oauth-authorization-server`);
      if (res.ok) return res.json();
    } catch (err) {
      // AS ainda nao respondeu — tenta de novo
    }
    console.log(`[client-demo] aguardando o Authorization Server (metadata) — tentativa ${i + 1}/${retries}`);
    await sleep(1000);
  }
  throw new Error('nao foi possivel obter a metadata do AS apos varias tentativas');
}

// RFC 7591 — se registra dinamicamente usando o registration_endpoint
// descoberto via metadata, em vez de credenciais pre-semeadas fora de banda.
async function registerClient(metadata) {
  const res = await fetch(metadata.registration_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      redirect_uris: [REDIRECT_URI],
      client_name: 'Client Demo (RFC 7592)',
      grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: 'profile email service',
    }),
  });
  const body = await res.json();
  if (!res.ok) throw new Error(`registro rejeitado pelo AS: ${res.status} ${JSON.stringify(body)}`);
  return body;
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
  if (!reg) return res.send(homePage({ registered: false }));
  const sess = session(req);
  if (sess && sess.accessToken) return res.redirect('/dashboard');
  res.send(homePage({
    registered: true,
    clientId: reg.client_id,
    clientName: reg.client_name,
    issuedAt: reg.client_id_issued_at,
    registrationEndpoint: reg.metadata.registration_endpoint,
  }));
});

// RFC 7591 — ação manual: só a partir daqui existe um client_id válido, e só
// a partir daqui as demais rotas (guardadas por requireRegistration) liberam.
app.post('/action/register', async (req, res) => {
  try {
    const metadata = await discoverMetadata();
    const registration = await registerClient(metadata);
    reg = { ...registration, metadata };
    console.log(`[client-demo] registrado dinamicamente: client_id=${reg.client_id}`);
  } catch (err) {
    return res.send(errorPage(`Falha ao registrar no AS: ${err.message}`));
  }
  res.redirect('/');
});

app.get('/login', requireRegistration, (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  res.cookie('oauth_state', state, { httpOnly: true, maxAge: 5 * 60 * 1000, sameSite: 'lax' });
  const url = new URL(`${AS_PUBLIC_BASE_URL}/authorize`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', reg.client_id);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('scope', 'profile email');
  url.searchParams.set('state', state);
  res.redirect(url.toString());
});

app.get('/callback', requireRegistration, async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.send(errorPage(`Autorização negada ou falhou: ${error}`));
  if (!state || state !== req.cookies.oauth_state) {
    return res.send(errorPage('state inválido — possível CSRF, fluxo abortado.'));
  }
  res.clearCookie('oauth_state');

  const tokenRes = await instrumentedFetch('client', 'authorization-server', reg.metadata.token_endpoint, {
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

app.post('/action/call', requireRegistration, async (req, res) => {
  const sid = req.cookies.sid;
  const sess = getSession(sid);
  if (!sess) return res.redirect('/');
  const { via } = req.body;
  const result = await callResourceServer(sess.accessToken, via, '/api/profile');
  updateSession(sid, { lastResult: result });
  res.redirect('/dashboard');
});

app.post('/action/invalid-token', requireRegistration, async (req, res) => {
  const sid = req.cookies.sid;
  const sess = getSession(sid);
  if (!sess) return res.redirect('/');
  const result = await callResourceServer('0'.repeat(48), 'header', '/api/profile');
  updateSession(sid, { lastResult: result });
  res.redirect('/dashboard');
});

app.post('/action/refresh', requireRegistration, async (req, res) => {
  const sid = req.cookies.sid;
  const sess = getSession(sid);
  if (!sess) return res.redirect('/');

  const tokenRes = await instrumentedFetch('client', 'authorization-server', reg.metadata.token_endpoint, {
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

app.post('/action/client-credentials', requireRegistration, async (req, res) => {
  const tokenRes = await instrumentedFetch('client', 'authorization-server', reg.metadata.token_endpoint, {
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

// --- RFC 7592 — gerenciamento do proprio registro ---

app.post('/action/registration/read', requireRegistration, async (req, res) => {
  const r = await instrumentedFetch('client', 'authorization-server', reg.registration_client_uri, {
    method: 'GET',
    headers: { Authorization: `Bearer ${reg.registration_access_token}` },
  });
  const body = await r.json().catch(() => ({}));
  res.send(registrationResultPage({ action: 'Consultar registro (GET)', status: r.status, body }));
});

app.post('/action/registration/update', requireRegistration, async (req, res) => {
  const newName = `Client Demo (RFC 7592) — atualizado ${new Date().toLocaleTimeString('pt-BR')}`;
  const r = await instrumentedFetch('client', 'authorization-server', reg.registration_client_uri, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${reg.registration_access_token}` },
    body: JSON.stringify({
      client_id: reg.client_id,
      redirect_uris: [REDIRECT_URI],
      client_name: newName,
      grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: 'profile email service',
    }),
  });
  const body = await r.json().catch(() => ({}));
  if (r.ok) {
    reg.client_name = body.client_name;
    // RFC 7592 §2.2 — o AS rotaciona o registration_access_token a cada PUT.
    if (body.registration_access_token) reg.registration_access_token = body.registration_access_token;
  }
  res.send(registrationResultPage({ action: 'Atualizar registro (PUT)', status: r.status, body }));
});

app.post('/action/registration/delete', requireRegistration, async (req, res) => {
  const r = await instrumentedFetch('client', 'authorization-server', reg.registration_client_uri, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${reg.registration_access_token}` },
  });
  const body = r.status === 204 ? { info: 'registro apagado (204 No Content) — client_id e client_secret nao valem mais. A home volta a exigir um novo registro manual.' } : await r.json().catch(() => ({}));
  if (r.status === 204) reg = null; // volta ao estado "nao registrado" — tudo bloqueado ate registrar de novo
  res.send(registrationResultPage({ action: 'Apagar registro (DELETE)', status: r.status, body }));
});

app.get('/logout', (req, res) => {
  if (req.cookies.sid) destroySession(req.cookies.sid);
  res.clearCookie('sid');
  res.redirect('/');
});

app.get('/healthz', (_req, res) => res.json({ ok: true }));

// Sem registro automatico: o servidor sobe imediatamente, sem client_id
// nenhum. So existe um client valido depois que o usuario aciona "Registrar
// client agora" na home (POST /action/register).
app.listen(PORT, () => console.log(`[client-demo] ouvindo em :${PORT}, aguardando registro manual (RFC 7591)`));

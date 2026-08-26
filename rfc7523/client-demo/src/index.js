const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { createSession, getSession, updateSession, destroySession } = require('./store');
const { homePage, dashboardPage, resultPage, clientCredentialsResultPage, errorPage } = require('./views');
const { captureInbound, instrumentedFetch } = require('./events');

const PORT = process.env.PORT || 3400;
const AS_BASE_URL = process.env.AS_BASE_URL; // uso interno (container-to-container)
const AS_PUBLIC_BASE_URL = process.env.AS_PUBLIC_BASE_URL; // uso no browser (redirects)
const RS_BASE_URL = process.env.RS_BASE_URL;
const REDIRECT_URI = process.env.REDIRECT_URI;

const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(captureInbound('client', 'browser'));

// Preenchido na inicializacao: chave RSA propria (nunca sai deste processo) +
// registro dinamico (RFC 7591) com a chave PUBLICA via jwks — sem client_secret.
let reg = null;
let privateKeyPem = null;
let lastAssertion = null; // guardado p/ o demo de replay

function session(req) {
  return getSession(req.cookies.sid);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Gera o par de chaves deste client. A privada nunca trafega — so assina
// localmente; a publica vira parte do jwks enviado no registro.
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  jwk.kid = crypto.randomBytes(8).toString('hex');
  return { privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), jwk };
}

async function discoverMetadata(retries = 30) {
  for (let i = 0; i < retries; i += 1) {
    try {
      const res = await fetch(`${AS_BASE_URL}/.well-known/oauth-authorization-server`);
      if (res.ok) return res.json();
    } catch (err) {
      // AS ainda nao respondeu
    }
    console.log(`[client-demo] aguardando o Authorization Server (metadata) — tentativa ${i + 1}/${retries}`);
    await sleep(1000);
  }
  throw new Error('nao foi possivel obter a metadata do AS apos varias tentativas');
}

async function registerClient(metadata, jwk) {
  const res = await fetch(metadata.registration_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      redirect_uris: [REDIRECT_URI],
      client_name: 'Client Demo (RFC 7523)',
      grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
      response_types: ['code'],
      token_endpoint_auth_method: 'private_key_jwt',
      scope: 'profile email service',
      jwks: { keys: [jwk] },
    }),
  });
  const body = await res.json();
  if (!res.ok) throw new Error(`registro rejeitado pelo AS: ${res.status} ${JSON.stringify(body)}`);
  return body;
}

// RFC 7523 §2.2 — monta e assina o client_assertion para UMA chamada ao
// /token. jti novo a cada vez (permite ao AS detectar reuso); aud precisa
// bater exatamente com o que o AS vai conferir (o proprio host que recebeu
// a requisicao — por isso usamos o issuer/token_endpoint da metadata).
function buildClientAssertion() {
  return jwt.sign(
    { jti: crypto.randomBytes(16).toString('hex') },
    privateKeyPem,
    {
      algorithm: 'RS256',
      issuer: reg.client_id,
      subject: reg.client_id,
      audience: reg.metadata.issuer,
      expiresIn: 60,
      keyid: reg.jwk.kid,
    },
  );
}

async function callToken(extraParams) {
  const assertion = buildClientAssertion();
  lastAssertion = assertion;
  return callTokenWithAssertion(extraParams, assertion);
}

async function callTokenWithAssertion(extraParams, assertion) {
  const body = new URLSearchParams({
    ...extraParams,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: assertion,
  });
  return instrumentedFetch('client', 'authorization-server', reg.metadata.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
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
  res.send(homePage({
    clientId: reg.client_id,
    clientName: reg.client_name,
    issuedAt: reg.client_id_issued_at,
    kid: reg.jwk.kid,
  }));
});

app.get('/login', (req, res) => {
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

app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.send(errorPage(`Autorização negada ou falhou: ${error}`));
  if (!state || state !== req.cookies.oauth_state) {
    return res.send(errorPage('state inválido — possível CSRF, fluxo abortado.'));
  }
  res.clearCookie('oauth_state');

  const tokenRes = await callToken({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI });
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

  const tokenRes = await callToken({ grant_type: 'refresh_token', refresh_token: sess.refreshToken });
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
  const tokenRes = await callToken({ grant_type: 'client_credentials', scope: 'service' });
  const body = await tokenRes.json();

  let rsResult = null;
  if (tokenRes.ok) {
    rsResult = await callResourceServer(body.access_token, 'header', '/api/service-info');
  }
  res.send(clientCredentialsResultPage({ tokenRes: { status: tokenRes.status, body }, rsResult }));
});

app.post('/action/replay', async (req, res) => {
  if (!lastAssertion) {
    return res.send(errorPage('Nenhuma client_assertion foi usada ainda — clique em "Executar chamada machine-to-machine" primeiro.'));
  }
  const tokenRes = await callTokenWithAssertion({ grant_type: 'client_credentials', scope: 'service' }, lastAssertion);
  const body = await tokenRes.json();
  res.send(resultPage({
    title: 'Replay de client_assertion',
    subtitle: 'reenvio proposital do mesmo JWT já usado — RFC 7523 §3 (jti)',
    result: { via: 'client_credentials (assertion reaproveitada)', status: tokenRes.status, body },
  }));
});

app.get('/logout', (req, res) => {
  if (req.cookies.sid) destroySession(req.cookies.sid);
  res.clearCookie('sid');
  res.redirect('/');
});

app.get('/healthz', (_req, res) => res.json({ ok: true }));

(async () => {
  const { privateKeyPem: pk, jwk } = generateKeyPair();
  privateKeyPem = pk;
  const metadata = await discoverMetadata();
  console.log(`[client-demo] metadata descoberta — registration_endpoint=${metadata.registration_endpoint}`);
  const registration = await registerClient(metadata, jwk);
  reg = { ...registration, metadata, jwk };
  console.log(`[client-demo] registrado dinamicamente: client_id=${reg.client_id} (private_key_jwt, kid=${jwk.kid})`);
  app.listen(PORT, () => console.log(`[client-demo] ouvindo em :${PORT}`));
})().catch((err) => {
  console.error('[client-demo] falha na inicializacao:', err.message);
  process.exit(1);
});

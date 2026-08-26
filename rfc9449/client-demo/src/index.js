const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { createSession, getSession, updateSession, destroySession } = require('./store');
const { homePage, dashboardPage, clientCredentialsResultPage, errorPage } = require('./views');
const { captureInbound, instrumentedFetch } = require('./events');
const { buildProof, jwkThumbprint } = require('./dpop');

const PORT = process.env.PORT || 3500;
const AS_BASE_URL = process.env.AS_BASE_URL;
const AS_PUBLIC_BASE_URL = process.env.AS_PUBLIC_BASE_URL;
const RS_BASE_URL = process.env.RS_BASE_URL;
const REDIRECT_URI = process.env.REDIRECT_URI;

const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(captureInbound('client', 'browser'));

// Preenchido na inicializacao: chave DPoP propria (privada nunca sai deste
// processo) + registro dinamico (RFC 7591), como client publico.
let reg = null;
let privateKeyPem = null;
let jwk = null;
let lastRsCall = null; // guarda { via, htu, proof, token } p/ o demo de replay

function session(req) {
  return getSession(req.cookies.sid);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicJwk = publicKey.export({ format: 'jwk' });
  publicJwk.alg = 'RS256';
  publicJwk.use = 'sig';
  return { privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), jwk: publicJwk };
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

async function registerClient(metadata) {
  const res = await fetch(metadata.registration_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      redirect_uris: [REDIRECT_URI],
      client_name: 'Client Demo (RFC 9449)',
      grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      scope: 'profile email service',
    }),
  });
  const body = await res.json();
  if (!res.ok) throw new Error(`registro rejeitado pelo AS: ${res.status} ${JSON.stringify(body)}`);
  return body;
}

// Chamada ao token endpoint, sempre com uma prova DPoP nova (htm=POST,
// htu=token_endpoint, sem ath — ath so entra nas chamadas ao resource server).
async function callToken(extraParams) {
  const htu = reg.metadata.token_endpoint;
  const proof = buildProof({ privateKeyPem, jwk, htm: 'POST', htu });
  const body = new URLSearchParams({ ...extraParams, client_id: reg.client_id });
  return instrumentedFetch('client', 'authorization-server', htu, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', DPoP: proof },
    body,
  });
}

async function callResourceServer(token, path) {
  const htu = `${RS_BASE_URL}${path}`;
  const proof = buildProof({ privateKeyPem, jwk, htm: 'GET', htu, accessToken: token });
  lastRsCall = { htu, htm: 'GET', proof, token };
  const r = await instrumentedFetch('client', 'resource-server', htu, {
    method: 'GET',
    headers: { Authorization: `DPoP ${token}`, DPoP: proof },
  });
  const wwwAuthenticate = r.headers.get('www-authenticate');
  const body = await r.json().catch(() => ({}));
  return { via: 'DPoP', status: r.status, wwwAuthenticate, body };
}

app.get('/', (req, res) => {
  const sess = session(req);
  if (sess && sess.accessToken) return res.redirect('/dashboard');
  res.send(homePage({
    clientId: reg.client_id,
    clientName: reg.client_name,
    issuedAt: reg.client_id_issued_at,
    jkt: jwkThumbprint(jwk),
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
  const result = await callResourceServer(sess.accessToken, '/api/profile');
  updateSession(sid, { lastResult: result });
  res.redirect('/dashboard');
});

// Tenta usar o token vinculado como se fosse um Bearer comum, sem header
// DPoP nenhum — prova que a mesma string de token nao serve sozinha.
app.post('/action/invalid-bearer', async (req, res) => {
  const sid = req.cookies.sid;
  const sess = getSession(sid);
  if (!sess) return res.redirect('/');
  const url = `${RS_BASE_URL}/api/profile`;
  const r = await instrumentedFetch('client', 'resource-server', url, {
    method: 'GET',
    headers: { Authorization: `Bearer ${sess.accessToken}` }, // esquema errado de proposito, sem header DPoP
  });
  const body = await r.json().catch(() => ({}));
  updateSession(sid, { lastResult: { via: 'Bearer (sem prova DPoP)', status: r.status, wwwAuthenticate: r.headers.get('www-authenticate'), body } });
  res.redirect('/dashboard');
});

// Reenvia literalmente a mesma prova (mesmo jti) da ultima chamada bem-sucedida.
app.post('/action/replay', async (req, res) => {
  const sid = req.cookies.sid;
  const sess = getSession(sid);
  if (!sess) return res.redirect('/');
  if (!lastRsCall) {
    updateSession(sid, { lastResult: { via: 'replay', status: 0, body: { info: 'nenhuma chamada anterior para reenviar — use "Com prova DPoP" primeiro' } } });
    return res.redirect('/dashboard');
  }
  const r = await instrumentedFetch('client', 'resource-server', lastRsCall.htu, {
    method: lastRsCall.htm,
    headers: { Authorization: `DPoP ${lastRsCall.token}`, DPoP: lastRsCall.proof },
  });
  const wwwAuthenticate = r.headers.get('www-authenticate');
  const body = await r.json().catch(() => ({}));
  updateSession(sid, { lastResult: { via: 'DPoP (prova reaproveitada)', status: r.status, wwwAuthenticate, body } });
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
    rsResult = await callResourceServer(body.access_token, '/api/service-info');
  }
  res.send(clientCredentialsResultPage({ tokenRes: { status: tokenRes.status, body }, rsResult }));
});

app.get('/logout', (req, res) => {
  if (req.cookies.sid) destroySession(req.cookies.sid);
  res.clearCookie('sid');
  res.redirect('/');
});

app.get('/healthz', (_req, res) => res.json({ ok: true }));

(async () => {
  const generated = generateKeyPair();
  privateKeyPem = generated.privateKeyPem;
  jwk = generated.jwk;
  console.log(`[client-demo] chave DPoP gerada — thumbprint ${jwkThumbprint(jwk)}`);

  const metadata = await discoverMetadata();
  console.log(`[client-demo] metadata descoberta — registration_endpoint=${metadata.registration_endpoint}`);
  const registration = await registerClient(metadata);
  reg = { ...registration, metadata };
  console.log(`[client-demo] registrado dinamicamente: client_id=${reg.client_id} (client publico, token_type=DPoP)`);
  app.listen(PORT, () => console.log(`[client-demo] ouvindo em :${PORT}`));
})().catch((err) => {
  console.error('[client-demo] falha na inicializacao:', err.message);
  process.exit(1);
});

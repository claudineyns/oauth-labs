const express = require('express');
const { redis, connectRedis } = require('./redis');
const { genToken, hashPassword } = require('./tokens');
const { seed } = require('./seed');
const { loginPage, errorPage } = require('./views');
const { captureInbound } = require('./events');

const PORT = process.env.PORT || 3201;
const ACCESS_TOKEN_TTL = 300; // 5 min — curto de proposito, p/ demonstrar refresh
const REFRESH_TOKEN_TTL = 3600; // 1h
const AUTH_CODE_TTL = 60; // 1 min, uso unico
const PAR_TTL = 60; // 1 min, uso unico — RFC 9126 recomenda vida curta

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
// observabilidade: /authorize vem do browser, /par e /token vem do backend do client-demo
app.use(captureInbound('as', (req) => (req.path === '/authorize' ? 'browser' : 'client-demo (backend)')));

async function getClient(clientId) {
  if (!clientId) return null;
  const data = await redis.hGetAll(`client:${clientId}`);
  return Object.keys(data).length ? data : null;
}

function parseClientAuth(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Basic ')) {
    const decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8');
    const idx = decoded.indexOf(':');
    if (idx === -1) return null;
    return { clientId: decoded.slice(0, idx), clientSecret: decoded.slice(idx + 1), viaHeader: true };
  }
  if (req.body.client_id) {
    return { clientId: req.body.client_id, clientSecret: req.body.client_secret, viaHeader: false };
  }
  return null;
}

function requestError(res, status, error, description, usedBasicAuth) {
  if (status === 401 && usedBasicAuth) {
    res.set('WWW-Authenticate', 'Basic realm="oauth-rfc9126-as"');
  }
  res.set('Cache-Control', 'no-store');
  return res.status(status).json({ error, error_description: description });
}

// --- Pushed Authorization Request endpoint (RFC 9126) ---
// O client empurra aqui, autenticado e por back-channel, tudo que antes ia
// na query string do /authorize. Recebe de volta uma referencia opaca e de
// vida curta para usar no lugar dos parametros.

app.post('/par', async (req, res) => {
  const auth = parseClientAuth(req);
  if (!auth || !auth.clientId) {
    return requestError(res, 400, 'invalid_request', 'client_id/client_secret ausentes');
  }
  const client = await getClient(auth.clientId);
  if (!client || client.client_secret !== auth.clientSecret) {
    return requestError(res, 401, 'invalid_client', 'client_id ou client_secret invalidos', auth.viaHeader);
  }

  const { response_type, redirect_uri, scope = '', state } = req.body;
  if (response_type !== 'code' || !redirect_uri || client.redirect_uri !== redirect_uri) {
    return requestError(res, 400, 'invalid_request', 'parametros de authorization request invalidos');
  }

  const parId = genToken();
  await redis.hSet(`par:${parId}`, { client_id: auth.clientId, redirect_uri, response_type, scope, state: state || '' });
  await redis.expire(`par:${parId}`, PAR_TTL);

  res.set('Cache-Control', 'no-store');
  res.status(201).json({
    request_uri: `urn:ietf:params:oauth:request_uri:${parId}`,
    expires_in: PAR_TTL,
  });
});

// --- Authorization endpoint (RFC 6749 §3.1) — agora so aceita via PAR ---

app.get('/authorize', async (req, res) => {
  const { client_id, request_uri } = req.query;
  const client = await getClient(client_id);

  if (!client) {
    return res.status(400).send(errorPage('client_id invalido/nao registrado.'));
  }
  if (!request_uri) {
    return res.status(400).send(errorPage('request_uri ausente — este AS exige Pushed Authorization Requests (RFC 9126); empurre a requisicao via POST /par primeiro.'));
  }

  const parId = request_uri.replace('urn:ietf:params:oauth:request_uri:', '');
  const pushed = await redis.hGetAll(`par:${parId}`);
  if (!Object.keys(pushed).length || pushed.client_id !== client_id) {
    return res.status(400).send(errorPage('request_uri invalido, expirado ou ja utilizado.'));
  }
  await redis.del(`par:${parId}`); // uso unico

  const { redirect_uri, scope, state, response_type } = pushed;
  if (!redirect_uri || client.redirect_uri !== redirect_uri) {
    return res.status(400).send(errorPage('redirect_uri invalido/nao registrado.'));
  }
  if (response_type !== 'code') {
    return res.redirect(`${redirect_uri}?error=unsupported_response_type${state ? `&state=${encodeURIComponent(state)}` : ''}`);
  }

  res.send(loginPage({ clientName: client.name, scope, clientId: client_id, redirectUri: redirect_uri, state }));
});

app.post('/authorize', async (req, res) => {
  const { client_id, redirect_uri, scope = '', state, username, password, decision } = req.body;
  const client = await getClient(client_id);

  if (!client || client.redirect_uri !== redirect_uri) {
    return res.status(400).send(errorPage('client_id ou redirect_uri invalidos.'));
  }

  const withState = (qs) => `${redirect_uri}?${qs}${state ? `&state=${encodeURIComponent(state)}` : ''}`;

  if (decision === 'deny') {
    return res.redirect(withState('error=access_denied'));
  }

  const user = await redis.hGetAll(`user:${username}`);
  if (!Object.keys(user).length || user.password_hash !== hashPassword(password || '')) {
    return res.status(401).send(loginPage({
      clientName: client.name,
      scope,
      clientId: client_id,
      redirectUri: redirect_uri,
      state,
      error: 'Usuário ou senha inválidos.',
    }));
  }

  const code = genToken();
  await redis.hSet(`authcode:${code}`, { client_id, redirect_uri, scope, username });
  await redis.expire(`authcode:${code}`, AUTH_CODE_TTL);

  return res.redirect(withState(`code=${code}`));
});

// --- Token endpoint (RFC 6749 §3.2 / §5) ---

app.post('/token', async (req, res) => {
  const auth = parseClientAuth(req);
  const grantType = req.body.grant_type;

  if (!auth || !auth.clientId) {
    return requestError(res, 400, 'invalid_request', 'client_id/client_secret ausentes');
  }
  const client = await getClient(auth.clientId);
  if (!client || client.client_secret !== auth.clientSecret) {
    return requestError(res, 401, 'invalid_client', 'client_id ou client_secret invalidos', auth.viaHeader);
  }
  const allowedGrants = client.grant_types.split(',');
  if (!allowedGrants.includes(grantType)) {
    return requestError(res, 400, 'unauthorized_client', `client nao autorizado para grant_type=${grantType}`);
  }

  if (grantType === 'authorization_code') {
    const { code, redirect_uri } = req.body;
    const authCode = await redis.hGetAll(`authcode:${code}`);
    if (!Object.keys(authCode).length || authCode.client_id !== auth.clientId || authCode.redirect_uri !== redirect_uri) {
      return requestError(res, 400, 'invalid_grant', 'authorization code invalido, expirado ou ja utilizado');
    }
    await redis.del(`authcode:${code}`); // uso unico
    return issueTokens(res, { clientId: auth.clientId, username: authCode.username, scope: authCode.scope, withRefresh: true });
  }

  if (grantType === 'refresh_token') {
    const { refresh_token } = req.body;
    const stored = await redis.hGetAll(`refresh_token:${refresh_token}`);
    if (!Object.keys(stored).length || stored.client_id !== auth.clientId) {
      return requestError(res, 400, 'invalid_grant', 'refresh_token invalido ou expirado');
    }
    await redis.del(`refresh_token:${refresh_token}`); // rotacao: invalida o antigo
    return issueTokens(res, { clientId: auth.clientId, username: stored.username, scope: stored.scope, withRefresh: true });
  }

  if (grantType === 'client_credentials') {
    const requested = (req.body.scope || client.scope).split(' ').filter(Boolean);
    const allowed = client.scope.split(' ');
    const scope = requested.filter((s) => allowed.includes(s)).join(' ');
    // RFC 6749 §4.4.3 — refresh_token SHOULD NOT ser emitido neste grant.
    return issueTokens(res, { clientId: auth.clientId, username: '', scope, withRefresh: false });
  }

  return requestError(res, 400, 'unsupported_grant_type', `grant_type=${grantType} nao suportado`);
});

async function issueTokens(res, { clientId, username, scope, withRefresh }) {
  const accessToken = genToken();
  await redis.hSet(`access_token:${accessToken}`, { client_id: clientId, username, scope });
  await redis.expire(`access_token:${accessToken}`, ACCESS_TOKEN_TTL);

  const body = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL,
    scope,
  };

  if (withRefresh) {
    const refreshToken = genToken();
    await redis.hSet(`refresh_token:${refreshToken}`, { client_id: clientId, username, scope });
    await redis.expire(`refresh_token:${refreshToken}`, REFRESH_TOKEN_TTL);
    body.refresh_token = refreshToken;
  }

  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  res.json(body);
}

app.get('/healthz', (_req, res) => res.json({ ok: true }));

connectRedis()
  .then(seed)
  .then(() => {
    app.listen(PORT, () => console.log(`[authorization-server] ouvindo em :${PORT}`));
  })
  .catch((err) => {
    console.error('[authorization-server] falha ao iniciar:', err);
    process.exit(1);
  });

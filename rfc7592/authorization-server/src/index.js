const express = require('express');
const { redis, connectRedis } = require('./redis');
const { genToken, genClientId, genClientSecret, hashPassword } = require('./tokens');
const { seed } = require('./seed');
const { loginPage, errorPage } = require('./views');
const { captureInbound } = require('./events');

const PORT = process.env.PORT || 3301;
const ACCESS_TOKEN_TTL = 300; // 5 min — curto de proposito, p/ demonstrar refresh
const REFRESH_TOKEN_TTL = 3600; // 1h
const AUTH_CODE_TTL = 60; // 1 min, uso unico

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
// observabilidade: /authorize vem do browser; /register, /register/:id e /token vem do backend do client-demo
app.use(captureInbound('as', (req) => (req.path === '/authorize' ? 'browser' : 'client-demo (backend)')));

async function getClient(clientId) {
  if (!clientId) return null;
  const data = await redis.hGetAll(`client:${clientId}`);
  return Object.keys(data).length ? data : null;
}

function isValidRedirectUri(client, uri) {
  return !!uri && client.redirect_uri.split(',').includes(uri);
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

function tokenError(res, status, error, description, usedBasicAuth) {
  if (status === 401 && usedBasicAuth) {
    res.set('WWW-Authenticate', 'Basic realm="oauth-rfc7592-as"');
  }
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  return res.status(status).json({ error, error_description: description });
}

// --- RFC 8414 — Authorization Server Metadata ---
// URLs relativas ao Host recebido: quem consulta de dentro da rede do
// projeto (o client-demo) recebe endpoints internos utilizaveis; quem
// consulta de fora (ex.: curl no host, a partir de localhost:3301) recebe
// endpoints publicos igualmente coerentes. O `issuer` sempre bate com o
// host efetivamente usado na consulta.
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const base = `${req.protocol}://${req.get('host')}`;
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    scopes_supported: ['profile', 'email', 'service'],
  });
});

// --- RFC 7591 — Dynamic Client Registration ---
// Deliberadamente aberto (sem initial access token) para manter o lab
// simples — a propria RFC 7591 §3 discute que producao normalmente exigiria
// algum portao aqui (token inicial, aprovacao manual) para evitar abuso.

function clientToMetadata(clientId, client) {
  return {
    client_id: clientId,
    client_id_issued_at: Number(client.client_id_issued_at),
    client_secret_expires_at: 0,
    redirect_uris: client.redirect_uri.split(','),
    client_name: client.name,
    grant_types: client.grant_types.split(','),
    response_types: client.response_types.split(','),
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    scope: client.scope,
  };
}

app.post('/register', async (req, res) => {
  const {
    redirect_uris,
    client_name,
    grant_types = ['authorization_code'],
    response_types = ['code'],
    token_endpoint_auth_method = 'client_secret_basic',
    scope = '',
  } = req.body || {};

  if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris e obrigatorio e deve ser um array nao vazio' });
  }

  const clientId = genClientId();
  const clientSecret = genClientSecret();
  const registrationAccessToken = genToken();
  const issuedAt = Math.floor(Date.now() / 1000);

  await redis.hSet(`client:${clientId}`, {
    client_secret: clientSecret,
    name: client_name || 'Client sem nome',
    redirect_uri: redirect_uris.join(','),
    scope,
    grant_types: grant_types.join(','),
    response_types: response_types.join(','),
    token_endpoint_auth_method,
    registration_access_token: registrationAccessToken,
    client_id_issued_at: String(issuedAt),
  });

  const base = `${req.protocol}://${req.get('host')}`;
  const client = await getClient(clientId);
  res.set('Cache-Control', 'no-store');
  res.status(201).json({
    ...clientToMetadata(clientId, client),
    client_secret: clientSecret,
    registration_access_token: registrationAccessToken,
    registration_client_uri: `${base}/register/${clientId}`,
  });
});

// --- RFC 7592 — Dynamic Client Registration Management ---

function parseRegistrationAuth(req) {
  const auth = req.headers.authorization;
  return auth && auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

// Mesmo erro (401 generico) tanto para client_id inexistente quanto para
// registration_access_token errado — evita servir de oraculo sobre quais
// client_id existem (mesmo principio anti-enumeracao ja visto na RFC 7009).
async function requireRegistrationAuth(req, res) {
  const token = parseRegistrationAuth(req);
  const client = await getClient(req.params.clientId);
  if (!client || !token || client.registration_access_token !== token) {
    res.status(401).json({ error: 'invalid_token', error_description: 'registration_access_token ausente ou invalido' });
    return null;
  }
  return client;
}

app.get('/register/:clientId', async (req, res) => {
  const client = await requireRegistrationAuth(req, res);
  if (!client) return;
  // client_secret nao e reenviado na leitura — so aparece uma vez, na criacao.
  res.json(clientToMetadata(req.params.clientId, client));
});

app.put('/register/:clientId', async (req, res) => {
  const client = await requireRegistrationAuth(req, res);
  if (!client) return;

  const { redirect_uris, client_name, grant_types, response_types, token_endpoint_auth_method, scope } = req.body || {};
  if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris e obrigatorio e deve ser um array nao vazio' });
  }

  // PUT e substituicao completa (nao e um patch parcial) — e rotaciona o
  // registration_access_token a cada atualizacao (RFC 7592 §2.2).
  const newRegToken = genToken();
  await redis.hSet(`client:${req.params.clientId}`, {
    name: client_name || client.name,
    redirect_uri: redirect_uris.join(','),
    scope: scope !== undefined ? scope : client.scope,
    grant_types: (grant_types || client.grant_types.split(',')).join(','),
    response_types: (response_types || client.response_types.split(',')).join(','),
    token_endpoint_auth_method: token_endpoint_auth_method || client.token_endpoint_auth_method,
    registration_access_token: newRegToken,
  });

  const updated = await getClient(req.params.clientId);
  const base = `${req.protocol}://${req.get('host')}`;
  res.json({
    ...clientToMetadata(req.params.clientId, updated),
    registration_access_token: newRegToken,
    registration_client_uri: `${base}/register/${req.params.clientId}`,
  });
});

app.delete('/register/:clientId', async (req, res) => {
  const client = await requireRegistrationAuth(req, res);
  if (!client) return;
  await redis.del(`client:${req.params.clientId}`);
  res.status(204).end();
});

// --- Authorization endpoint (RFC 6749 §3.1) ---

app.get('/authorize', async (req, res) => {
  const { response_type, client_id, redirect_uri, scope = '', state } = req.query;
  const client = await getClient(client_id);

  if (!client || !isValidRedirectUri(client, redirect_uri)) {
    return res.status(400).send(errorPage('client_id ou redirect_uri invalidos/nao registrados — nao e seguro redirecionar o usuario.'));
  }
  if (response_type !== 'code') {
    return res.redirect(`${redirect_uri}?error=unsupported_response_type${state ? `&state=${encodeURIComponent(state)}` : ''}`);
  }

  res.send(loginPage({ clientName: client.name, scope, clientId: client_id, redirectUri: redirect_uri, state }));
});

app.post('/authorize', async (req, res) => {
  const { client_id, redirect_uri, scope = '', state, username, password, decision } = req.body;
  const client = await getClient(client_id);

  if (!client || !isValidRedirectUri(client, redirect_uri)) {
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
    return tokenError(res, 400, 'invalid_request', 'client_id/client_secret ausentes');
  }
  const client = await getClient(auth.clientId);
  if (!client || client.client_secret !== auth.clientSecret) {
    return tokenError(res, 401, 'invalid_client', 'client_id ou client_secret invalidos (ou client nao existe mais)', auth.viaHeader);
  }
  const allowedGrants = client.grant_types.split(',');
  if (!allowedGrants.includes(grantType)) {
    return tokenError(res, 400, 'unauthorized_client', `client nao autorizado para grant_type=${grantType}`);
  }

  if (grantType === 'authorization_code') {
    const { code, redirect_uri } = req.body;
    const authCode = await redis.hGetAll(`authcode:${code}`);
    if (!Object.keys(authCode).length || authCode.client_id !== auth.clientId || authCode.redirect_uri !== redirect_uri) {
      return tokenError(res, 400, 'invalid_grant', 'authorization code invalido, expirado ou ja utilizado');
    }
    await redis.del(`authcode:${code}`); // uso unico
    return issueTokens(res, { clientId: auth.clientId, username: authCode.username, scope: authCode.scope, withRefresh: true });
  }

  if (grantType === 'refresh_token') {
    const { refresh_token } = req.body;
    const stored = await redis.hGetAll(`refresh_token:${refresh_token}`);
    if (!Object.keys(stored).length || stored.client_id !== auth.clientId) {
      return tokenError(res, 400, 'invalid_grant', 'refresh_token invalido ou expirado');
    }
    await redis.del(`refresh_token:${refresh_token}`); // rotacao: invalida o antigo
    return issueTokens(res, { clientId: auth.clientId, username: stored.username, scope: stored.scope, withRefresh: true });
  }

  if (grantType === 'client_credentials') {
    const requested = (req.body.scope || client.scope).split(' ').filter(Boolean);
    const allowed = client.scope.split(' ');
    const scope = requested.filter((s) => allowed.includes(s)).join(' ');
    return issueTokens(res, { clientId: auth.clientId, username: '', scope, withRefresh: false });
  }

  return tokenError(res, 400, 'unsupported_grant_type', `grant_type=${grantType} nao suportado`);
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

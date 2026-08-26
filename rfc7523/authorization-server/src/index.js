const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { redis, connectRedis } = require('./redis');
const { genToken, genClientId, hashPassword } = require('./tokens');
const { seed } = require('./seed');
const { loginPage, errorPage } = require('./views');
const { captureInbound } = require('./events');

const PORT = process.env.PORT || 3401;
const ACCESS_TOKEN_TTL = 300; // 5 min
const REFRESH_TOKEN_TTL = 3600; // 1h
const AUTH_CODE_TTL = 60; // 1 min, uso unico
const ASSERTION_MAX_TTL = 120; // limite superior aceito p/ exp do client_assertion; tambem usado como TTL do jti no Redis

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
// observabilidade: /authorize vem do browser; /register e /token vem do backend do client-demo
app.use(captureInbound('as', (req) => (req.path === '/authorize' ? 'browser' : 'client-demo (backend)')));

async function getClient(clientId) {
  if (!clientId) return null;
  const data = await redis.hGetAll(`client:${clientId}`);
  return Object.keys(data).length ? data : null;
}

function isValidRedirectUri(client, uri) {
  return !!uri && client.redirect_uri.split(',').includes(uri);
}

function tokenError(res, status, error, description) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  return res.status(status).json({ error, error_description: description });
}

// --- RFC 8414 — Authorization Server Metadata ---
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const base = `${req.protocol}://${req.get('host')}`;
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    token_endpoint_auth_methods_supported: ['private_key_jwt'],
    token_endpoint_auth_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['profile', 'email', 'service'],
  });
});

// --- RFC 7591 — Dynamic Client Registration ---
// Este lab so aceita token_endpoint_auth_method=private_key_jwt — sem
// client_secret nenhum. O client precisa registrar sua chave publica (jwks).

function clientToMetadata(clientId, client) {
  return {
    client_id: clientId,
    client_id_issued_at: Number(client.client_id_issued_at),
    redirect_uris: client.redirect_uri.split(','),
    client_name: client.name,
    grant_types: client.grant_types.split(','),
    response_types: client.response_types.split(','),
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    scope: client.scope,
    jwks: JSON.parse(client.jwks),
  };
}

app.post('/register', async (req, res) => {
  const {
    redirect_uris,
    client_name,
    grant_types = ['authorization_code'],
    response_types = ['code'],
    token_endpoint_auth_method,
    scope = '',
    jwks,
  } = req.body || {};

  if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris e obrigatorio e deve ser um array nao vazio' });
  }
  if (token_endpoint_auth_method !== 'private_key_jwt') {
    return res.status(400).json({ error: 'invalid_client_metadata', error_description: 'este AS so aceita token_endpoint_auth_method=private_key_jwt' });
  }
  if (!jwks || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
    return res.status(400).json({ error: 'invalid_client_metadata', error_description: 'jwks com pelo menos uma chave publica e obrigatorio para private_key_jwt' });
  }

  const clientId = genClientId(); // 16 caracteres hex, mesma convencao do projeto
  const issuedAt = Math.floor(Date.now() / 1000);

  await redis.hSet(`client:${clientId}`, {
    name: client_name || 'Client sem nome',
    redirect_uri: redirect_uris.join(','),
    scope,
    grant_types: grant_types.join(','),
    response_types: response_types.join(','),
    token_endpoint_auth_method,
    jwks: JSON.stringify(jwks),
    client_id_issued_at: String(issuedAt),
  });

  const client = await getClient(clientId);
  res.set('Cache-Control', 'no-store');
  res.status(201).json(clientToMetadata(clientId, client));
});

// --- Autenticacao do client via private_key_jwt (RFC 7523 §2.2) ---
// Substitui inteiramente client_secret neste lab — todo grant_type passa por aqui.

async function authenticateClientAssertion(req) {
  const { client_assertion_type, client_assertion } = req.body;
  if (client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' || !client_assertion) {
    return { ok: false, status: 400, error: 'invalid_client', description: 'client_assertion (private_key_jwt) ausente ou client_assertion_type incorreto — RFC 7523 §2.2' };
  }

  let decoded;
  try {
    decoded = jwt.decode(client_assertion, { complete: true, json: true });
  } catch {
    decoded = null;
  }
  if (!decoded || decoded.header.alg !== 'RS256') {
    return { ok: false, status: 400, error: 'invalid_client', description: 'client_assertion malformado ou algoritmo de assinatura nao suportado (so RS256)' };
  }

  const clientId = decoded.payload && decoded.payload.iss;
  const client = await getClient(clientId);
  if (!client || !client.jwks) {
    return { ok: false, status: 401, error: 'invalid_client', description: 'client_id desconhecido ou sem chave publica registrada' };
  }

  let publicKey;
  try {
    const jwk = JSON.parse(client.jwks).keys[0];
    publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch {
    return { ok: false, status: 500, error: 'server_error', description: 'chave publica registrada invalida' };
  }

  const expectedAud = `${req.protocol}://${req.get('host')}`;
  let payload;
  try {
    payload = jwt.verify(client_assertion, publicKey, {
      algorithms: ['RS256'],
      audience: expectedAud,
      issuer: clientId,
      subject: clientId,
      maxAge: ASSERTION_MAX_TTL,
    });
  } catch (err) {
    return { ok: false, status: 401, error: 'invalid_client', description: `client_assertion invalido: ${err.message}` };
  }

  // RFC 7523 §3 — jti evita reapresentacao (replay) da mesma assertion.
  if (!payload.jti) {
    return { ok: false, status: 400, error: 'invalid_client', description: 'client_assertion sem jti — obrigatorio neste lab, usado para detectar replay' };
  }
  const isNew = await redis.set(`used_jti:${payload.jti}`, '1', { NX: true, EX: ASSERTION_MAX_TTL });
  if (!isNew) {
    return { ok: false, status: 401, error: 'invalid_client', description: 'client_assertion ja utilizado antes — replay detectado via jti (RFC 7523 §3)' };
  }

  return { ok: true, clientId, client };
}

// --- Authorization endpoint (RFC 6749 §3.1) — sem mudancas de client auth,
// PKCE ou PAR; so o /token muda de metodo de autenticacao neste lab ---

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

// --- Token endpoint (RFC 6749 §3.2 / §5) — autenticacao via private_key_jwt ---

app.post('/token', async (req, res) => {
  const auth = await authenticateClientAssertion(req);
  if (!auth.ok) return tokenError(res, auth.status, auth.error, auth.description);

  const { clientId, client } = auth;
  const grantType = req.body.grant_type;
  const allowedGrants = client.grant_types.split(',');
  if (!allowedGrants.includes(grantType)) {
    return tokenError(res, 400, 'unauthorized_client', `client nao autorizado para grant_type=${grantType}`);
  }

  if (grantType === 'authorization_code') {
    const { code, redirect_uri } = req.body;
    const authCode = await redis.hGetAll(`authcode:${code}`);
    if (!Object.keys(authCode).length || authCode.client_id !== clientId || authCode.redirect_uri !== redirect_uri) {
      return tokenError(res, 400, 'invalid_grant', 'authorization code invalido, expirado ou ja utilizado');
    }
    await redis.del(`authcode:${code}`);
    return issueTokens(res, { clientId, username: authCode.username, scope: authCode.scope, withRefresh: true });
  }

  if (grantType === 'refresh_token') {
    const { refresh_token } = req.body;
    const stored = await redis.hGetAll(`refresh_token:${refresh_token}`);
    if (!Object.keys(stored).length || stored.client_id !== clientId) {
      return tokenError(res, 400, 'invalid_grant', 'refresh_token invalido ou expirado');
    }
    await redis.del(`refresh_token:${refresh_token}`);
    return issueTokens(res, { clientId, username: stored.username, scope: stored.scope, withRefresh: true });
  }

  if (grantType === 'client_credentials') {
    const requested = (req.body.scope || client.scope).split(' ').filter(Boolean);
    const allowed = client.scope.split(' ');
    const scope = requested.filter((s) => allowed.includes(s)).join(' ');
    return issueTokens(res, { clientId, username: '', scope, withRefresh: false });
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

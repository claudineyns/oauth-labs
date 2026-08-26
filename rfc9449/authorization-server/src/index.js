const express = require('express');
const { redis, connectRedis } = require('./redis');
const { genToken, genClientId, hashPassword } = require('./tokens');
const { seed } = require('./seed');
const { loginPage, errorPage } = require('./views');
const { captureInbound } = require('./events');
const { validateDpopProof } = require('./dpop');

const PORT = process.env.PORT || 3501;
const ACCESS_TOKEN_TTL = 300;
const REFRESH_TOKEN_TTL = 3600;
const AUTH_CODE_TTL = 60;

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
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
    token_endpoint_auth_methods_supported: ['none'],
    dpop_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['profile', 'email', 'service'],
  });
});

// --- RFC 7591 — Dynamic Client Registration ---
// Client publico (token_endpoint_auth_method=none) — sem client_secret e sem
// jwks pre-registrada: a chave do DPoP viaja embutida em cada prova, nao e
// cadastrada de antemao (ver docs/rfcs/rfc9449.md item 1).

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
  } = req.body || {};

  if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris e obrigatorio e deve ser um array nao vazio' });
  }
  if (token_endpoint_auth_method !== 'none') {
    return res.status(400).json({ error: 'invalid_client_metadata', error_description: 'este AS so aceita token_endpoint_auth_method=none (client publico, sender-constraining via DPoP)' });
  }

  const clientId = genClientId();
  const issuedAt = Math.floor(Date.now() / 1000);

  await redis.hSet(`client:${clientId}`, {
    name: client_name || 'Client sem nome',
    redirect_uri: redirect_uris.join(','),
    scope,
    grant_types: grant_types.join(','),
    response_types: response_types.join(','),
    token_endpoint_auth_method,
    client_id_issued_at: String(issuedAt),
  });

  const client = await getClient(clientId);
  res.set('Cache-Control', 'no-store');
  res.status(201).json(clientToMetadata(clientId, client));
});

// --- Authorization endpoint (RFC 6749 §3.1) — sem DPoP; a prova so entra no
// token endpoint e nas chamadas ao resource server ---

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

// --- Token endpoint (RFC 6749 §3.2 / §5) — toda emissao exige prova DPoP,
// que fixa cnf.jkt do token resultante (RFC 9449 §5) ---

app.post('/token', async (req, res) => {
  const clientId = req.body.client_id;
  const grantType = req.body.grant_type;

  const client = await getClient(clientId);
  if (!client) {
    return tokenError(res, 401, 'invalid_client', 'client_id desconhecido');
  }
  const allowedGrants = client.grant_types.split(',');
  if (!allowedGrants.includes(grantType)) {
    return tokenError(res, 400, 'unauthorized_client', `client nao autorizado para grant_type=${grantType}`);
  }

  const tokenEndpointUrl = `${req.protocol}://${req.get('host')}/token`;
  const dpop = await validateDpopProof({ redis, proofCompact: req.headers.dpop, htm: 'POST', htu: tokenEndpointUrl });
  if (!dpop.ok) {
    return tokenError(res, 400, dpop.error, dpop.description);
  }

  if (grantType === 'authorization_code') {
    const { code, redirect_uri } = req.body;
    const authCode = await redis.hGetAll(`authcode:${code}`);
    if (!Object.keys(authCode).length || authCode.client_id !== clientId || authCode.redirect_uri !== redirect_uri) {
      return tokenError(res, 400, 'invalid_grant', 'authorization code invalido, expirado ou ja utilizado');
    }
    await redis.del(`authcode:${code}`);
    return issueTokens(res, { clientId, username: authCode.username, scope: authCode.scope, withRefresh: true, jkt: dpop.jkt });
  }

  if (grantType === 'refresh_token') {
    const { refresh_token } = req.body;
    const stored = await redis.hGetAll(`refresh_token:${refresh_token}`);
    if (!Object.keys(stored).length || stored.client_id !== clientId) {
      return tokenError(res, 400, 'invalid_grant', 'refresh_token invalido ou expirado');
    }
    // RFC 9449 §5 — refresh_token tambem e vinculado; a prova apresentada
    // agora precisa vir da MESMA chave que recebeu esse refresh_token.
    if (stored.cnf_jkt !== dpop.jkt) {
      return tokenError(res, 400, 'invalid_grant', 'a chave da prova DPoP nao corresponde a chave vinculada a este refresh_token');
    }
    await redis.del(`refresh_token:${refresh_token}`);
    return issueTokens(res, { clientId, username: stored.username, scope: stored.scope, withRefresh: true, jkt: dpop.jkt });
  }

  if (grantType === 'client_credentials') {
    const requested = (req.body.scope || client.scope).split(' ').filter(Boolean);
    const allowed = client.scope.split(' ');
    const scope = requested.filter((s) => allowed.includes(s)).join(' ');
    return issueTokens(res, { clientId, username: '', scope, withRefresh: false, jkt: dpop.jkt });
  }

  return tokenError(res, 400, 'unsupported_grant_type', `grant_type=${grantType} nao suportado`);
});

async function issueTokens(res, { clientId, username, scope, withRefresh, jkt }) {
  const accessToken = genToken();
  await redis.hSet(`access_token:${accessToken}`, { client_id: clientId, username, scope, cnf_jkt: jkt });
  await redis.expire(`access_token:${accessToken}`, ACCESS_TOKEN_TTL);

  const body = {
    access_token: accessToken,
    token_type: 'DPoP',
    expires_in: ACCESS_TOKEN_TTL,
    scope,
  };

  if (withRefresh) {
    const refreshToken = genToken();
    await redis.hSet(`refresh_token:${refreshToken}`, { client_id: clientId, username, scope, cnf_jkt: jkt });
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

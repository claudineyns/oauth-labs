const express = require('express');
const { redis, connectRedis } = require('./redis');
const { genToken, hashPassword } = require('./tokens');
const { challengeFromVerifier, genFamilyId } = require('./pkce');
const { seed } = require('./seed');
const { loginPage, errorPage } = require('./views');
const { captureInbound } = require('./events');

const PORT = process.env.PORT || 3101;
const ACCESS_TOKEN_TTL = 300; // 5 min — curto de proposito, p/ demonstrar refresh
const REFRESH_TOKEN_TTL = 3600; // 1h
const AUTH_CODE_TTL = 60; // 1 min, uso unico

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
// observabilidade: /authorize vem do browser, /token e /revoke vem do backend do client-demo
app.use(captureInbound('as', (req) => (req.path === '/authorize' ? 'browser' : 'client-demo (backend)')));

async function getClient(clientId) {
  if (!clientId) return null;
  const data = await redis.hGetAll(`client:${clientId}`);
  return Object.keys(data).length ? data : null;
}

// client.redirect_uri e uma lista separada por virgula (o client-demo deste
// lab registra 2: o callback normal e o do demo de ataque PKCE).
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
    res.set('WWW-Authenticate', 'Basic realm="oauth-rfc7636-as"');
  }
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  return res.status(status).json({ error, error_description: description });
}

// --- Authorization endpoint (RFC 6749 §3.1) + PKCE (RFC 7636) ---

app.get('/authorize', async (req, res) => {
  const { response_type, client_id, redirect_uri, scope = '', state, code_challenge, code_challenge_method } = req.query;
  const client = await getClient(client_id);

  if (!client || !isValidRedirectUri(client, redirect_uri)) {
    return res.status(400).send(errorPage('client_id ou redirect_uri invalidos/nao registrados — nao e seguro redirecionar o usuario.'));
  }
  if (response_type !== 'code') {
    return res.redirect(`${redirect_uri}?error=unsupported_response_type${state ? `&state=${encodeURIComponent(state)}` : ''}`);
  }
  // RFC 7636 exige code_challenge; este lab so aceita o metodo S256 (RFC 9700
  // trata "plain" como pratica obsoleta — ver docs/rfcs/rfc7636.md).
  if (!code_challenge || code_challenge_method !== 'S256') {
    return res.redirect(`${redirect_uri}?error=invalid_request&error_description=${encodeURIComponent('code_challenge (S256) e obrigatorio — RFC 7636')}${state ? `&state=${encodeURIComponent(state)}` : ''}`);
  }

  res.send(loginPage({
    clientName: client.name,
    scope,
    clientId: client_id,
    redirectUri: redirect_uri,
    state,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
  }));
});

app.post('/authorize', async (req, res) => {
  const { client_id, redirect_uri, scope = '', state, username, password, decision, code_challenge, code_challenge_method } = req.body;
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
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      error: 'Usuário ou senha inválidos.',
    }));
  }

  const code = genToken();
  await redis.hSet(`authcode:${code}`, {
    client_id,
    redirect_uri,
    scope,
    username,
    code_challenge,
    code_challenge_method,
  });
  await redis.expire(`authcode:${code}`, AUTH_CODE_TTL);

  return res.redirect(withState(`code=${code}`));
});

// --- Token endpoint (RFC 6749 §3.2 / §5, PKCE RFC 7636 §4.5-4.6) ---

app.post('/token', async (req, res) => {
  const auth = parseClientAuth(req);
  const grantType = req.body.grant_type;

  if (!auth || !auth.clientId) {
    return tokenError(res, 400, 'invalid_request', 'client_id/client_secret ausentes');
  }
  const client = await getClient(auth.clientId);
  if (!client || client.client_secret !== auth.clientSecret) {
    return tokenError(res, 401, 'invalid_client', 'client_id ou client_secret invalidos', auth.viaHeader);
  }
  const allowedGrants = client.grant_types.split(',');
  if (!allowedGrants.includes(grantType)) {
    return tokenError(res, 400, 'unauthorized_client', `client nao autorizado para grant_type=${grantType}`);
  }

  if (grantType === 'authorization_code') {
    const { code, redirect_uri, code_verifier } = req.body;
    const authCode = await redis.hGetAll(`authcode:${code}`);
    if (!Object.keys(authCode).length || authCode.client_id !== auth.clientId || authCode.redirect_uri !== redirect_uri) {
      return tokenError(res, 400, 'invalid_grant', 'authorization code invalido, expirado ou ja utilizado');
    }
    await redis.del(`authcode:${code}`); // uso unico

    // RFC 7636 §4.6 — recalcula o challenge a partir do verifier apresentado
    // agora e compara com o que foi fixado na authorization request. Quem
    // so interceptou o `code` nao tem o verifier e falha aqui.
    if (!code_verifier || challengeFromVerifier(code_verifier) !== authCode.code_challenge) {
      return tokenError(res, 400, 'invalid_grant', 'code_verifier ausente ou nao corresponde ao code_challenge (RFC 7636)');
    }

    return issueTokens(res, {
      clientId: auth.clientId,
      username: authCode.username,
      scope: authCode.scope,
      withRefresh: true,
      familyId: genFamilyId(),
    });
  }

  if (grantType === 'refresh_token') {
    const { refresh_token } = req.body;
    const stored = await redis.hGetAll(`refresh_token:${refresh_token}`);
    if (!Object.keys(stored).length || stored.client_id !== auth.clientId) {
      return tokenError(res, 400, 'invalid_grant', 'refresh_token invalido, expirado ou revogado');
    }
    await redis.del(`refresh_token:${refresh_token}`); // rotacao: invalida o antigo
    await redis.sRem(`family:${stored.family_id}`, `refresh_token:${refresh_token}`);

    return issueTokens(res, {
      clientId: auth.clientId,
      username: stored.username,
      scope: stored.scope,
      withRefresh: true,
      familyId: stored.family_id,
    });
  }

  if (grantType === 'client_credentials') {
    const requested = (req.body.scope || client.scope).split(' ').filter(Boolean);
    const allowed = client.scope.split(' ');
    const scope = requested.filter((s) => allowed.includes(s)).join(' ');
    // RFC 6749 §4.4.3 — refresh_token SHOULD NOT ser emitido neste grant.
    return issueTokens(res, { clientId: auth.clientId, username: '', scope, withRefresh: false, familyId: genFamilyId() });
  }

  return tokenError(res, 400, 'unsupported_grant_type', `grant_type=${grantType} nao suportado`);
});

async function issueTokens(res, { clientId, username, scope, withRefresh, familyId }) {
  const accessToken = genToken();
  const familyKey = `family:${familyId}`;

  await redis.hSet(`access_token:${accessToken}`, { client_id: clientId, username, scope, family_id: familyId });
  await redis.expire(`access_token:${accessToken}`, ACCESS_TOKEN_TTL);
  await redis.sAdd(familyKey, `access_token:${accessToken}`);

  const body = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL,
    scope,
  };

  if (withRefresh) {
    const refreshToken = genToken();
    await redis.hSet(`refresh_token:${refreshToken}`, { client_id: clientId, username, scope, family_id: familyId });
    await redis.expire(`refresh_token:${refreshToken}`, REFRESH_TOKEN_TTL);
    await redis.sAdd(familyKey, `refresh_token:${refreshToken}`);
    body.refresh_token = refreshToken;
  }

  await redis.expire(familyKey, REFRESH_TOKEN_TTL);

  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  res.json(body);
}

// --- Revocation endpoint (RFC 7009) ---

app.post('/revoke', async (req, res) => {
  const auth = parseClientAuth(req);
  const { token, token_type_hint } = req.body;

  if (!auth || !auth.clientId) {
    return tokenError(res, 400, 'invalid_request', 'client_id/client_secret ausentes');
  }
  const client = await getClient(auth.clientId);
  if (!client || client.client_secret !== auth.clientSecret) {
    return tokenError(res, 401, 'invalid_client', 'client_id ou client_secret invalidos', auth.viaHeader);
  }
  if (!token) {
    return tokenError(res, 400, 'invalid_request', 'parametro token ausente');
  }

  const order = token_type_hint === 'access_token' ? ['access_token', 'refresh_token'] : ['refresh_token', 'access_token'];

  for (const kind of order) {
    const key = `${kind}:${token}`;
    const data = await redis.hGetAll(key);
    if (!Object.keys(data).length) continue;

    // RFC 7009 §2.1 — so revoga se o token pertence ao client autenticado;
    // caso contrario, nao faz nada, mas ainda assim responde 200 (ver abaixo)
    // para nao servir de oraculo sobre a existencia/dono do token.
    if (data.client_id !== auth.clientId) break;

    if (kind === 'refresh_token') {
      // §2.1 — revogar o refresh_token revoga em cascata toda a familia
      // (todos os access_tokens emitidos a partir dele).
      const members = await redis.sMembers(`family:${data.family_id}`);
      if (members.length) await redis.del(members);
      await redis.del(`family:${data.family_id}`);
    } else {
      await redis.del(key);
      await redis.sRem(`family:${data.family_id}`, key);
    }
    break;
  }

  // RFC 7009 §2.2 — sempre 200, mesmo se o token nao existia/ja tinha sido
  // revogado/nao pertencia a este client (evita oraculo de enumeracao).
  res.set('Cache-Control', 'no-store');
  res.status(200).end();
});

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

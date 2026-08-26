const express = require('express');
const { redis, connectRedis } = require('./redis');
const { captureInbound } = require('./events');

const PORT = process.env.PORT || 3402;
const REALM = 'oauth-rfc7523-lab';

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(captureInbound('rs', 'client-demo (backend)'));

function wwwAuth(extra = '') {
  return `Bearer realm="${REALM}"${extra}`;
}

function requireBearer(requiredScope) {
  return async (req, res, next) => {
    const headerMatch = /^Bearer (.+)$/i.exec(req.headers.authorization || '');
    const fromHeader = headerMatch ? headerMatch[1] : undefined;
    const fromBody = req.is('application/x-www-form-urlencoded') && req.method !== 'GET' ? req.body.access_token : undefined;
    const fromQuery = req.query.access_token;

    const found = [fromHeader, fromBody, fromQuery].filter(Boolean);

    if (found.length === 0) {
      res.set('WWW-Authenticate', wwwAuth());
      return res.status(401).json({ error_description: 'nenhum access_token informado (header, body ou query) — RFC 6750 §2' });
    }
    if (found.length > 1) {
      res.set('WWW-Authenticate', wwwAuth(', error="invalid_request"'));
      return res.status(400).json({ error: 'invalid_request', error_description: 'access_token informado em mais de um local — RFC 6750 §2 proibe' });
    }

    const token = found[0];
    const via = fromHeader ? 'header' : fromBody ? 'body' : 'query';
    const data = await redis.hGetAll(`access_token:${token}`);

    if (!Object.keys(data).length) {
      res.set('WWW-Authenticate', wwwAuth(', error="invalid_token", error_description="token inexistente ou expirado"'));
      return res.status(401).json({ error: 'invalid_token', error_description: 'token inexistente ou expirado' });
    }

    const scopes = (data.scope || '').split(' ').filter(Boolean);
    if (requiredScope && !scopes.includes(requiredScope)) {
      res.set('WWW-Authenticate', wwwAuth(`, error="insufficient_scope", scope="${requiredScope}"`));
      return res.status(403).json({ error: 'insufficient_scope', error_description: `escopo necessario: ${requiredScope}` });
    }

    req.token = { value: token, via, client_id: data.client_id, username: data.username, scopes };
    next();
  };
}

function sendProfile(req, res) {
  res.json({
    resource: '/api/profile',
    accessed_via: req.token.via,
    client_id: req.token.client_id,
    username: req.token.username || null,
    scope: req.token.scopes,
  });
}

function sendServiceInfo(req, res) {
  res.json({
    resource: '/api/service-info',
    accessed_via: req.token.via,
    client_id: req.token.client_id,
    grant: req.token.username ? 'authorization_code' : 'client_credentials',
    scope: req.token.scopes,
  });
}

app.get('/api/profile', requireBearer('profile'), sendProfile);
app.post('/api/profile', requireBearer('profile'), sendProfile);

app.get('/api/service-info', requireBearer('service'), sendServiceInfo);
app.post('/api/service-info', requireBearer('service'), sendServiceInfo);

app.get('/healthz', (_req, res) => res.json({ ok: true }));

connectRedis()
  .then(() => {
    app.listen(PORT, () => console.log(`[resource-server] ouvindo em :${PORT}`));
  })
  .catch((err) => {
    console.error('[resource-server] falha ao iniciar:', err);
    process.exit(1);
  });

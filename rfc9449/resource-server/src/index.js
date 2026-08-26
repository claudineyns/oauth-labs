const express = require('express');
const { redis, connectRedis } = require('./redis');
const { captureInbound } = require('./events');
const { validateDpopProof } = require('./dpop');

const PORT = process.env.PORT || 3502;
const REALM = 'oauth-rfc9449-lab';

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(captureInbound('rs', 'client-demo (backend)'));

function wwwAuth(extra = '') {
  return `DPoP realm="${REALM}"${extra}`;
}

// Exige Authorization: DPoP <token> + header DPoP com prova valida cuja
// chave bate com o cnf.jkt vinculado ao token (RFC 9449 §7.1).
function requireDpop(requiredScope) {
  return async (req, res, next) => {
    const match = /^DPoP (.+)$/i.exec(req.headers.authorization || '');
    if (!match) {
      res.set('WWW-Authenticate', wwwAuth());
      return res.status(401).json({ error_description: 'nenhum token DPoP informado — esperado "Authorization: DPoP <token>"' });
    }
    const token = match[1];

    const data = await redis.hGetAll(`access_token:${token}`);
    if (!Object.keys(data).length) {
      res.set('WWW-Authenticate', wwwAuth(', error="invalid_token", error_description="token inexistente ou expirado"'));
      return res.status(401).json({ error: 'invalid_token', error_description: 'token inexistente ou expirado' });
    }

    const base = `${req.protocol}://${req.get('host')}`;
    const htu = `${base}${req.path}`;
    const dpop = await validateDpopProof({ redis, proofCompact: req.headers.dpop, htm: req.method, htu, accessToken: token });
    if (!dpop.ok) {
      // error_description completo so no corpo JSON — o header WWW-Authenticate
      // so aceita texto ASCII "seguro" (Node rejeita caracteres como "—").
      res.set('WWW-Authenticate', wwwAuth(`, error="${dpop.error}"`));
      return res.status(401).json({ error: dpop.error, error_description: dpop.description });
    }

    if (dpop.jkt !== data.cnf_jkt) {
      res.set('WWW-Authenticate', wwwAuth(', error="invalid_token", error_description="chave da prova nao corresponde ao token"'));
      return res.status(401).json({ error: 'invalid_token', error_description: 'a chave usada na prova nao corresponde a chave vinculada a este token (cnf.jkt)' });
    }

    const scopes = (data.scope || '').split(' ').filter(Boolean);
    if (requiredScope && !scopes.includes(requiredScope)) {
      res.set('WWW-Authenticate', wwwAuth(`, error="insufficient_scope", scope="${requiredScope}"`));
      return res.status(403).json({ error: 'insufficient_scope', error_description: `escopo necessario: ${requiredScope}` });
    }

    req.token = { value: token, client_id: data.client_id, username: data.username, scopes };
    next();
  };
}

function sendProfile(req, res) {
  res.json({
    resource: '/api/profile',
    client_id: req.token.client_id,
    username: req.token.username || null,
    scope: req.token.scopes,
  });
}

function sendServiceInfo(req, res) {
  res.json({
    resource: '/api/service-info',
    client_id: req.token.client_id,
    grant: req.token.username ? 'authorization_code' : 'client_credentials',
    scope: req.token.scopes,
  });
}

app.get('/api/profile', requireDpop('profile'), sendProfile);
app.get('/api/service-info', requireDpop('service'), sendServiceInfo);

app.get('/healthz', (_req, res) => res.json({ ok: true }));

connectRedis()
  .then(() => {
    app.listen(PORT, () => console.log(`[resource-server] ouvindo em :${PORT}`));
  })
  .catch((err) => {
    console.error('[resource-server] falha ao iniciar:', err);
    process.exit(1);
  });

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Janela de frescor aceita para o `iat` da prova, e tambem o TTL de rastreio
// de `jti` no Redis (um pouco maior, para cobrir a janela inteira).
const FRESHNESS_WINDOW_SECONDS = 60;

function log(...args) {
  console.log('[dpop]', ...args);
}

// RFC 7638 — thumbprint canonico do JWK: membros obrigatorios, ordenados,
// SHA-256, base64url. Mesma chave RSA sempre produz o mesmo thumbprint.
function jwkThumbprint(jwk) {
  const ordered = { e: jwk.e, kty: jwk.kty, n: jwk.n };
  return crypto.createHash('sha256').update(JSON.stringify(ordered)).digest('base64url');
}

// Valida uma prova DPoP recebida no header `DPoP`, passo a passo, logando
// cada checagem — e o motivo exato de rejeicao, quando aplicavel.
// `accessToken`, se informado, ativa a checagem de `ath` (uso em resource
// server; ausente nas provas enviadas ao token endpoint).
async function validateDpopProof({ redis, proofCompact, htm, htu, accessToken }) {
  log(`validando prova — ${htm} ${htu}`);

  if (!proofCompact) {
    log('  header DPoP ausente');
    return { ok: false, error: 'invalid_dpop_proof', description: 'header DPoP ausente' };
  }

  let decoded;
  try {
    decoded = jwt.decode(proofCompact, { complete: true, json: true });
  } catch {
    decoded = null;
  }
  if (!decoded || decoded.header.typ !== 'dpop+jwt') {
    log('  prova malformada ou typ != dpop+jwt');
    return { ok: false, error: 'invalid_dpop_proof', description: 'prova malformada ou typ != dpop+jwt' };
  }

  const jwk = decoded.header.jwk;
  if (!jwk) {
    log('  header da prova sem jwk');
    return { ok: false, error: 'invalid_dpop_proof', description: 'header da prova sem jwk' };
  }

  let publicKey;
  try {
    publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch {
    log('  jwk invalida');
    return { ok: false, error: 'invalid_dpop_proof', description: 'jwk invalida' };
  }

  let payload;
  try {
    payload = jwt.verify(proofCompact, publicKey, { algorithms: ['RS256'] });
  } catch (err) {
    log(`  assinatura invalida: ${err.message}`);
    return { ok: false, error: 'invalid_dpop_proof', description: `assinatura invalida: ${err.message}` };
  }
  log('  assinatura ok / typ=dpop+jwt ok');

  if (payload.htm !== htm) {
    log(`  htm nao confere (esperado "${htm}", veio "${payload.htm}")`);
    return { ok: false, error: 'invalid_dpop_proof', description: 'htm nao confere com a requisicao' };
  }
  if (payload.htu !== htu) {
    log(`  htu nao confere (esperado "${htu}", veio "${payload.htu}")`);
    return { ok: false, error: 'invalid_dpop_proof', description: 'htu nao confere com a requisicao' };
  }
  log('  htm ok / htu ok');

  const now = Math.floor(Date.now() / 1000);
  if (!payload.iat || Math.abs(now - payload.iat) > FRESHNESS_WINDOW_SECONDS) {
    log(`  iat fora da janela de frescor (iat=${payload.iat}, agora=${now})`);
    return { ok: false, error: 'invalid_dpop_proof', description: 'prova fora da janela de frescor (iat)' };
  }
  log(`  iat dentro da janela (${now - payload.iat}s atras)`);

  if (!payload.jti) {
    log('  prova sem jti');
    return { ok: false, error: 'invalid_dpop_proof', description: 'prova sem jti' };
  }
  const isNew = await redis.set(`used_dpop_jti:${payload.jti}`, '1', { NX: true, EX: FRESHNESS_WINDOW_SECONDS * 2 });
  if (!isNew) {
    log(`  jti ja usado antes (${payload.jti}) — replay detectado`);
    return { ok: false, error: 'invalid_dpop_proof', description: 'prova ja utilizada antes — replay detectado via jti' };
  }
  log(`  jti inedito (${payload.jti})`);

  if (accessToken) {
    const expectedAth = crypto.createHash('sha256').update(accessToken).digest('base64url');
    if (payload.ath !== expectedAth) {
      log('  ath nao confere com o access_token apresentado');
      return { ok: false, error: 'invalid_dpop_proof', description: 'ath nao confere com o access_token apresentado' };
    }
    log('  ath confere com o access_token apresentado');
  }

  const jkt = jwkThumbprint(jwk);
  log(`  thumbprint da chave: ${jkt}`);
  log('prova valida');

  return { ok: true, jkt };
}

module.exports = { validateDpopProof, jwkThumbprint, log };

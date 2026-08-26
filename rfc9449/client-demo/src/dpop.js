const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function log(...args) {
  console.log('[dpop]', ...args);
}

// RFC 7638 — mesmo calculo de thumbprint usado pelo AS/RS para conferir.
function jwkThumbprint(jwk) {
  const ordered = { e: jwk.e, kty: jwk.kty, n: jwk.n };
  return crypto.createHash('sha256').update(JSON.stringify(ordered)).digest('base64url');
}

// Monta e assina uma prova DPoP nova para UMA requisicao especifica,
// logando cada peca conforme e montada. `accessToken`, se informado,
// inclui `ath` (uso ao chamar o resource server; ausente no token endpoint).
function buildProof({ privateKeyPem, jwk, htm, htu, accessToken }) {
  log(`montando prova para ${htm} ${htu}`);

  const jti = crypto.randomBytes(16).toString('hex');
  const iat = Math.floor(Date.now() / 1000);
  log(`  htm=${htm}  htu=${htu}`);
  log(`  iat=${iat}  jti=${jti}`);
  log(`  jwk.thumbprint=${jwkThumbprint(jwk)}`);

  const payload = { htm, htu, jti };
  if (accessToken) {
    payload.ath = crypto.createHash('sha256').update(accessToken).digest('base64url');
    log(`  ath=${payload.ath} (hash do access_token apresentado)`);
  }

  // NAO usar noTimestamp:true aqui — essa opcao do jsonwebtoken remove
  // qualquer `iat` do payload (inclusive um setado manualmente) em vez de
  // so pular o auto-preenchimento. Deixamos a biblioteca gerar o iat.
  const proof = jwt.sign(payload, privateKeyPem, {
    algorithm: 'RS256',
    header: { typ: 'dpop+jwt', jwk },
  });

  log(`  prova assinada (RS256): ${proof.slice(0, 48)}...`);
  return proof;
}

module.exports = { buildProof, jwkThumbprint, log };

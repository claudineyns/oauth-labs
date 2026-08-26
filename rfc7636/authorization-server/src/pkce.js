const crypto = require('crypto');

// RFC 7636 §4.2 — S256: BASE64URL(SHA256(code_verifier)). Este lab exige
// S256 sempre (nao aceita "plain") — reflete a pratica atual (ver RFC 9700).
function challengeFromVerifier(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// Identificador da "familia" de tokens de uma mesma concessao — usado para
// revogacao em cascata (RFC 7009 §2.1: revogar o refresh_token deveria
// invalidar os access_tokens derivados dele).
function genFamilyId() {
  return crypto.randomBytes(16).toString('hex');
}

module.exports = { challengeFromVerifier, genFamilyId };

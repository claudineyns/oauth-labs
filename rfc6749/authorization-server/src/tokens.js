const crypto = require('crypto');

const hex = (bytes) => crypto.randomBytes(bytes).toString('hex');

module.exports = {
  genClientId: () => hex(8), // 16 caracteres hex
  genClientSecret: () => hex(16), // 32 caracteres hex
  genToken: () => hex(24), // 48 caracteres hex (access_token / refresh_token / authorization code)
  hashPassword: (password) => crypto.createHash('sha256').update(password).digest('hex'),
};

const { redis } = require('./redis');
const { hashPassword } = require('./tokens');

// Registro do client e do resource owner de demonstracao. Idempotente —
// Dynamic Client Registration (RFC 7591) fica para um laboratorio futuro;
// aqui o registro e feito fora de banda, via variaveis de ambiente.
async function seed() {
  const clientId = process.env.DEMO_CLIENT_ID;
  const clientSecret = process.env.DEMO_CLIENT_SECRET;
  const redirectUri = process.env.DEMO_REDIRECT_URI;

  if (clientId && clientSecret && redirectUri) {
    const exists = await redis.exists(`client:${clientId}`);
    if (!exists) {
      await redis.hSet(`client:${clientId}`, {
        client_secret: clientSecret,
        name: 'Client Demo (RFC 9126)',
        redirect_uri: redirectUri,
        scope: 'profile email service',
        grant_types: 'authorization_code,refresh_token,client_credentials',
      });
      console.log(`[seed] client registrado: ${clientId}`);
    } else {
      console.log(`[seed] client ja registrado: ${clientId}`);
    }
  } else {
    console.warn('[seed] DEMO_CLIENT_ID/SECRET/REDIRECT_URI ausentes — nenhum client registrado');
  }

  const username = 'alice';
  const userExists = await redis.exists(`user:${username}`);
  if (!userExists) {
    await redis.hSet(`user:${username}`, {
      password_hash: hashPassword('wonderland123'),
      name: 'Alice (resource owner)',
    });
    console.log(`[seed] resource owner registrado: ${username} / wonderland123`);
  } else {
    console.log(`[seed] resource owner ja registrado: ${username}`);
  }
}

module.exports = { seed };

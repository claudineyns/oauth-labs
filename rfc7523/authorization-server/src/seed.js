const { redis } = require('./redis');
const { hashPassword } = require('./tokens');

// Diferente dos demais labs, este NAO semeia um client — client registration
// e dinamico (RFC 7591), feito pelo proprio client-demo ao subir. Aqui so
// se semeia o resource owner de demonstracao.
async function seed() {
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

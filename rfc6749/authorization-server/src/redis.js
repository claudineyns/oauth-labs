const { createClient } = require('redis');

const client = createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
client.on('error', (err) => console.error('[redis] erro de conexao:', err.message));

async function connectRedis() {
  if (!client.isOpen) await client.connect();
  return client;
}

module.exports = { redis: client, connectRedis };

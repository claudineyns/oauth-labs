const crypto = require('crypto');

// Sessao em memoria — laboratorio de instancia unica, sem necessidade de
// Redis compartilhado aqui (apenas os endpoints do AS/RS usam Redis).
const sessions = new Map();

function createSession(data) {
  const id = crypto.randomBytes(16).toString('hex');
  sessions.set(id, data);
  return id;
}

function getSession(id) {
  return id ? sessions.get(id) : undefined;
}

function updateSession(id, patch) {
  sessions.set(id, { ...sessions.get(id), ...patch });
}

function destroySession(id) {
  sessions.delete(id);
}

module.exports = { createSession, getSession, updateSession, destroySession };

const express = require('express');

// Observador passivo: os 3 apps do laboratorio (AS, RS, client-demo) enviam
// um evento por requisicao e um por resposta, para todo trafego "interface
// -> server" e "machine -> machine". Este servico apenas formata e imprime
// no proprio log do container (`podman logs -f oauth6749-events`) — sem UI,
// sem persistencia, so a "danca" de HTTP em tempo real.

const PORT = process.env.PORT || 4000;
const app = express();
app.use(express.json({ limit: '256kb' }));

const SERVICE_LABEL = { as: 'AUTHORIZATION SERVER', rs: 'RESOURCE SERVER', client: 'CLIENT DEMO' };
const DIVIDER = '─'.repeat(72);
const IGNORE_PATHS = ['/favicon.ico', '/healthz'];

function fmtTime(ts) {
  const d = new Date(ts);
  return `${d.toLocaleTimeString('pt-BR', { hour12: false })}.${String(ts % 1000).padStart(3, '0')}`;
}

function fmtHeaders(headers) {
  return Object.entries(headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
}

function fmtBody(body) {
  if (body === undefined || body === null) return '';
  return typeof body === 'string' ? body : JSON.stringify(body, null, 2);
}

function indent(text) {
  return text.split('\n').map((l) => `  ${l}`).join('\n');
}

function block(lines) {
  return lines.filter((l) => l !== null && l !== undefined && l !== '').join('\n');
}

app.post('/ingest', (req, res) => {
  const evt = req.body || {};
  if (IGNORE_PATHS.includes(evt.path)) return res.status(204).end();

  const label = SERVICE_LABEL[evt.service] || (evt.service || '?').toUpperCase();
  const time = fmtTime(evt.ts || Date.now());
  const headerText = fmtHeaders(evt.headers);
  const bodyText = fmtBody(evt.body);

  let title;
  let startLine;
  if (evt.kind === 'request') {
    title = `[${time}] ${label} — requisição ${evt.direction === 'in' ? `recebida de ${evt.peer}` : `enviada para ${evt.peer}`}`;
    startLine = `→ ${evt.method} ${evt.path} HTTP/1.1\n  Host: ${evt.host || ''}`;
  } else {
    title = `[${time}] ${label} — resposta ${evt.direction === 'out' ? `enviada para ${evt.peer}` : `recebida de ${evt.peer}`}`;
    startLine = `← HTTP/1.1 ${evt.status}${evt.statusText ? ` ${evt.statusText}` : ''}`;
  }

  console.log(block([
    title,
    startLine,
    headerText ? indent(headerText) : null,
    bodyText ? '' : null,
    bodyText ? indent(bodyText) : null,
  ]));
  console.log(DIVIDER);

  res.status(204).end();
});

app.get('/healthz', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(DIVIDER);
  console.log('  observador de eventos HTTP -- RFC 6749 lab');
  console.log('  aguardando a danca de requisicoes/respostas...');
  console.log(DIVIDER);
});

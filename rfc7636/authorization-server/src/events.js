// Instrumentacao de observabilidade: emite um evento por requisicao recebida
// e um por resposta enviada, para o coletor central (oauth7636-events).
// Fire-and-forget — nunca deve quebrar o fluxo principal do app.
const EVENTS_URL = process.env.EVENTS_URL;

function sendEvent(evt) {
  if (!EVENTS_URL) return;
  fetch(`${EVENTS_URL}/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...evt, ts: Date.now() }),
  }).catch(() => {});
}

function pick(obj, keys) {
  const out = {};
  for (const k of keys) {
    const v = obj && obj[k];
    if (v) out[k] = v;
  }
  return out;
}

function maskBody(body) {
  if (!body || typeof body !== 'object') return body;
  if (Object.keys(body).length === 0) return undefined;
  const clone = { ...body };
  if (clone.password) clone.password = '••••••••';
  if (clone.client_secret) clone.client_secret = '••••••••';
  return clone;
}

// Captura toda comunicacao "interface -> server" (ou "machine -> machine")
// recebida por este servico. `peer` identifica quem esta do outro lado —
// pode ser fixo (string) ou calculado por requisicao (funcao).
function captureInbound(service, peer) {
  const resolvePeer = typeof peer === 'function' ? peer : () => peer;

  return (req, res, next) => {
    const p = resolvePeer(req);

    sendEvent({
      service,
      peer: p,
      kind: 'request',
      direction: 'in',
      method: req.method,
      path: req.originalUrl,
      host: req.headers.host,
      headers: pick(req.headers, ['authorization', 'content-type', 'accept']),
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : maskBody(req.body),
    });

    const originalJson = res.json.bind(res);
    let jsonBody;
    res.json = (payload) => { jsonBody = payload; return originalJson(payload); };

    res.on('finish', () => {
      sendEvent({
        service,
        peer: p,
        kind: 'response',
        direction: 'out',
        path: req.originalUrl,
        status: res.statusCode,
        headers: pick(res.getHeaders(), ['content-type', 'location', 'www-authenticate', 'cache-control']),
        body: jsonBody,
      });
    });

    next();
  };
}

module.exports = { sendEvent, captureInbound };

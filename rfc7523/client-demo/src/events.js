// Instrumentacao de observabilidade: emite um evento por requisicao/resposta,
// tanto para o trafego "interface -> server" recebido do browser quanto para
// as chamadas "machine -> machine" que este app faz ao AS e ao RS. Envia
// para o coletor central (oauth7523-events). Fire-and-forget — nunca deve
// quebrar o fluxo principal do app.
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

// Captura toda requisicao recebida do browser por este servico.
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

// fetch() instrumentado: emite o evento de requisicao ANTES de enviar e o de
// resposta ao receber, preservando o Response original (via clone) para
// quem chamou continuar consumindo o corpo normalmente.
async function instrumentedFetch(service, peer, url, init = {}) {
  const u = new URL(url);

  sendEvent({
    service,
    peer,
    kind: 'request',
    direction: 'out',
    method: init.method || 'GET',
    path: `${u.pathname}${u.search}`,
    host: u.host,
    headers: pick(init.headers || {}, ['authorization', 'content-type']),
    body: init.body instanceof URLSearchParams ? maskBody(Object.fromEntries(init.body)) : undefined,
  });

  const response = await fetch(url, init);

  const contentType = response.headers.get('content-type') || '';
  const body = contentType.includes('application/json') ? await response.clone().json().catch(() => undefined) : undefined;

  sendEvent({
    service,
    peer,
    kind: 'response',
    direction: 'in',
    status: response.status,
    headers: pick(Object.fromEntries(response.headers.entries()), ['content-type', 'www-authenticate', 'cache-control']),
    body,
  });

  return response;
}

module.exports = { sendEvent, captureInbound, instrumentedFetch };

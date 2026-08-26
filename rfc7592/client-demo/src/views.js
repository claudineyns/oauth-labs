const baseStyle = `
  :root { color-scheme: light dark; --accent:#5b6cf9; --bg:#0f1115; --card:#171a21; --text:#e7e9ee; --muted:#9aa0ac; --border:#262b36; --ok:#3ddc97; --err:#ff6b81; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; background:var(--bg); color:var(--text);
         font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         display:flex; align-items:flex-start; justify-content:center; padding:2.5rem 1rem; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:2rem;
          width:100%; max-width:460px; box-shadow:0 10px 30px rgba(0,0,0,.3); }
  .card.wide { max-width:760px; }
  h1 { font-size:1.2rem; margin:0 0 .25rem; }
  .subtitle { color:var(--muted); font-size:.85rem; margin:0 0 1.5rem; }
  section { margin-bottom:1.6rem; }
  section h2 { font-size:.78rem; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); margin:0 0 .6rem; }
  .token { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.78rem; background:#0f1115;
           border:1px solid var(--border); border-radius:8px; padding:.6rem .7rem; word-break:break-all; }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:.6rem; }
  button, .btn { padding:.65rem 1rem; border-radius:8px; border:1px solid var(--border); background:#1d212b;
        color:var(--text); font-size:.82rem; cursor:pointer; width:100%; }
  button.primary { background:var(--accent); color:#fff; border-color:var(--accent); font-weight:600; }
  button.danger { background:transparent; color:var(--err); border-color:#5c2230; }
  form { margin:0; }
  a.btn { display:block; text-align:center; text-decoration:none; box-sizing:border-box; }
  .result { background:#0f1115; border:1px solid var(--border); border-radius:8px; padding:.9rem; font-size:.78rem; }
  .result pre { margin:.4rem 0 0; white-space:pre-wrap; word-break:break-all; }
  .status-ok { color: var(--ok); font-weight:600; }
  .status-err { color: var(--err); font-weight:600; }
  a.link { color: var(--accent); font-size:.82rem; }
`;

const layout = (title, body, wide = false) => `<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>${baseStyle}</style>
</head>
<body><div class="card${wide ? ' wide' : ''}">${body}</div></body>
</html>`;

function homePage({ registered, clientId, clientName, issuedAt, registrationEndpoint }) {
  if (!registered) {
    return layout('OAuth 2.0 — RFC 7592 lab', `
      <h1>Client Demo</h1>
      <p class="subtitle">Este client ainda não está registrado no Authorization Server — nenhuma outra funcionalidade fica disponível até o registro ser concluído.</p>
      <section>
        <h2>Registro dinâmico (RFC 7591)</h2>
        <form method="POST" action="/action/register">
          <button class="primary">Registrar client agora</button>
        </form>
        <p class="subtitle" style="margin-top:.5rem">Ao clicar: descobre os endpoints do AS (RFC 8414) e envia <code>POST /register</code> com a metadata do client. Login, chamadas machine-to-machine e gerenciamento do registro dependem de um <code>client_id</code> válido gerado aqui.</p>
      </section>
    `);
  }

  const issuedStr = new Date(issuedAt * 1000).toLocaleString('pt-BR');
  return layout('OAuth 2.0 — RFC 7592 lab', `
    <h1>Client Demo</h1>
    <p class="subtitle">
      client_id: <span class="token">${clientId}</span><br>
      client_name: ${clientName}<br>
      registrado dinamicamente (RFC 7591) em ${issuedStr}<br>
      via <span class="token">${registrationEndpoint}</span>, descoberto por RFC 8414
    </p>
    <section>
      <h2>Authorization Code Grant</h2>
      <a class="btn primary" href="/login">Login com Authorization Server</a>
    </section>
    <section>
      <h2>Client Credentials Grant</h2>
      <form method="POST" action="/action/client-credentials">
        <button class="primary">Executar chamada machine-to-machine</button>
      </form>
    </section>
    <section>
      <h2>Gerenciar registro (RFC 7592)</h2>
      <div class="grid">
        <form method="POST" action="/action/registration/read"><button>Consultar (GET)</button></form>
        <form method="POST" action="/action/registration/update"><button>Atualizar (PUT)</button></form>
      </div>
      <form method="POST" action="/action/registration/delete" style="margin-top:.6rem">
        <button class="danger">Apagar registro (DELETE)</button>
      </form>
      <p class="subtitle" style="margin-top:.5rem">Depois de apagar, tente "Executar chamada machine-to-machine" acima — o client não existe mais para o AS.</p>
    </section>
  `);
}

function fmtResult(r) {
  if (!r) return '<p class="subtitle">nenhuma chamada realizada ainda.</p>';
  const cls = r.status < 300 ? 'status-ok' : 'status-err';
  return `<div class="result">
    <div>via: <strong>${r.via}</strong> &mdash; status: <span class="${cls}">${r.status}</span></div>
    ${r.wwwAuthenticate ? `<div>WWW-Authenticate: <span class="token">${r.wwwAuthenticate}</span></div>` : ''}
    <pre>${JSON.stringify(r.body, null, 2)}</pre>
  </div>`;
}

function dashboardPage(sess) {
  const expiresAt = new Date(sess.obtainedAt + sess.expiresIn * 1000).toLocaleTimeString('pt-BR');
  return layout('Dashboard', `
    <h1>Dashboard do cliente</h1>
    <p class="subtitle">logado via Authorization Code Grant &middot; <a class="link" href="/logout">sair</a></p>
    <section>
      <h2>Tokens</h2>
      <div class="token">access_token: ${sess.accessToken}</div>
      <div class="token" style="margin-top:.4rem">refresh_token: ${sess.refreshToken}</div>
      <p class="subtitle">escopo: ${sess.scope} &middot; expira ~${expiresAt}</p>
    </section>
    <section>
      <h2>Chamar Resource Server (RFC 6750)</h2>
      <div class="grid">
        <form method="POST" action="/action/call">
          <input type="hidden" name="via" value="header"><input type="hidden" name="endpoint" value="profile">
          <button>Via header Authorization</button>
        </form>
        <form method="POST" action="/action/call">
          <input type="hidden" name="via" value="body"><input type="hidden" name="endpoint" value="profile">
          <button>Via body (POST)</button>
        </form>
        <form method="POST" action="/action/call">
          <input type="hidden" name="via" value="query"><input type="hidden" name="endpoint" value="profile">
          <button>Via query string</button>
        </form>
        <form method="POST" action="/action/invalid-token">
          <button>Simular token inválido</button>
        </form>
      </div>
    </section>
    <section>
      <h2>Renovação</h2>
      <form method="POST" action="/action/refresh"><button class="primary">Renovar via refresh_token</button></form>
    </section>
    <section>
      <h2>Resultado da última chamada</h2>
      ${fmtResult(sess.lastResult)}
    </section>
  `, true);
}

function clientCredentialsResultPage({ tokenRes, rsResult }) {
  return layout('Client Credentials', `
    <h1>Client Credentials Grant</h1>
    <p class="subtitle">chamada machine-to-machine, sem resource owner &mdash; RFC 6749 §4.4</p>
    <section><h2>Resposta do /token</h2>${fmtResult({ via: 'client_credentials', status: tokenRes.status, body: tokenRes.body })}</section>
    ${rsResult ? `<section><h2>Chamada ao Resource Server (/api/service-info)</h2>${fmtResult(rsResult)}</section>` : ''}
    <p><a class="link" href="/">&larr; voltar</a></p>
  `, true);
}

function registrationResultPage({ action, status, body }) {
  return layout('Gerenciamento do registro', `
    <h1>${action}</h1>
    <p class="subtitle">RFC 7592 — Dynamic Client Registration Management</p>
    ${fmtResult({ via: action, status, body })}
    <p><a class="link" href="/">&larr; voltar</a></p>
  `, true);
}

function errorPage(message) {
  return layout('Erro', `<h1>Erro</h1><p class="subtitle">${message}</p><p><a class="link" href="/">&larr; voltar</a></p>`);
}

module.exports = { homePage, dashboardPage, clientCredentialsResultPage, registrationResultPage, errorPage };

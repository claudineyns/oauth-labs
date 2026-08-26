const baseStyle = `
  :root { color-scheme: light dark; --accent:#5b6cf9; --bg:#0f1115; --card:#171a21; --text:#e7e9ee; --muted:#9aa0ac; --border:#262b36; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         background:var(--bg); color:var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:2rem;
          width:100%; max-width:420px; box-shadow:0 10px 30px rgba(0,0,0,.3); }
  h1 { font-size:1.15rem; margin:0 0 .25rem; }
  .subtitle { color:var(--muted); font-size:.85rem; margin:0 0 1.5rem; }
  label { display:block; font-size:.8rem; color:var(--muted); margin:.9rem 0 .3rem; }
  input[type=text], input[type=password] {
    width:100%; padding:.6rem .7rem; border-radius:8px; border:1px solid var(--border);
    background:#0f1115; color:var(--text); font-size:.9rem;
  }
  .scope-list { margin:.8rem 0 0; padding:0; list-style:none; font-size:.82rem; color:var(--muted); }
  .scope-list li { padding:.15rem 0; }
  .actions { display:flex; gap:.6rem; margin-top:1.4rem; }
  button { flex:1; padding:.65rem 1rem; border-radius:8px; border:none; font-size:.9rem; cursor:pointer; font-weight:600; }
  button.allow { background:var(--accent); color:#fff; }
  button.deny { background:transparent; color:var(--muted); border:1px solid var(--border); }
  .error { background:#3a1620; color:#ff9aa8; border:1px solid #5c2230; border-radius:8px; padding:.6rem .8rem; font-size:.82rem; margin-bottom:1rem; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.8rem; word-break:break-all; }
`;

const layout = (title, body) => `<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>${baseStyle}</style>
</head>
<body>
  <div class="card">${body}</div>
</body>
</html>`;

function loginPage({ clientName, scope, clientId, redirectUri, state, error }) {
  const scopes = (scope || '').split(' ').filter(Boolean);
  const body = `
    <h1>${clientName}</h1>
    <p class="subtitle">solicita acesso à sua conta &mdash; RFC 6749, Authorization Code Grant + PAR (RFC 9126)</p>
    ${error ? `<div class="error">${error}</div>` : ''}
    <form method="POST" action="/authorize">
      <input type="hidden" name="client_id" value="${clientId}">
      <input type="hidden" name="redirect_uri" value="${redirectUri}">
      <input type="hidden" name="scope" value="${scope}">
      <input type="hidden" name="state" value="${state || ''}">
      <label>Usuário</label>
      <input type="text" name="username" autocomplete="username" required>
      <label>Senha</label>
      <input type="password" name="password" autocomplete="current-password" required>
      <ul class="scope-list">${scopes.map((s) => `<li>&bull; escopo solicitado: <strong>${s}</strong></li>`).join('')}</ul>
      <div class="actions">
        <button class="deny" name="decision" value="deny" formnovalidate>Negar</button>
        <button class="allow" name="decision" value="allow">Autorizar</button>
      </div>
    </form>`;
  return layout('Autorizar acesso', body);
}

function errorPage(message) {
  return layout('Erro', `<h1>Erro na requisição</h1><p class="subtitle mono">${message}</p>`);
}

module.exports = { loginPage, errorPage };

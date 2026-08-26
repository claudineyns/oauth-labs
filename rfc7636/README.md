# Laboratório RFC 7636 — PKCE (+ RFC 7009 Token Revocation)

Réplica autocontida do laboratório `rfc6749/` (mesma arquitetura, containers e
convenções — ver [[feedback-lab-pattern]] no projeto), incorporando:

- **PKCE (RFC 7636)** no Authorization Code Grant — `code_challenge`/`code_verifier`,
  método `S256` exigido sempre.
- **Token Revocation (RFC 7009)** — endpoint `/revoke` no Authorization Server,
  com revogação em cascata (revogar o `refresh_token` também invalida o
  `access_token` da mesma família).

Este lab **não compartilha nenhum container** com `rfc6749/` — rede, nomes de
container e portas são todos próprios, para poder ficar de pé junto com outro
lab sem conflito.

## Componentes

| Serviço | Porta | Papel |
|---|---|---|
| `oauth7636-redis` | interna (6379) | clients, resource owners, authorization codes, tokens, famílias de tokens |
| `oauth7636-events` | interna (4000) | observador — imprime a dança de HTTP no próprio log |
| `oauth7636-as` (Authorization Server) | 3101 | `/authorize` (login + PKCE), `/token` (emissão + verificação do verifier), `/revoke` |
| `oauth7636-rs` (Resource Server) | 3102 | `/api/profile`, `/api/service-info` — idêntico ao lab da RFC 6749 |
| `oauth7636-client` (Client Demo) | 3100 | gera o par verifier/challenge, inicia os fluxos, chama o RS |

Formatos: `client_id` = 16 hex, `client_secret` = 32 hex, `access_token`/`refresh_token` = 48 hex — mesma convenção do projeto.

## Uso

```bash
./containers/build.sh
./containers/up.sh
```

Abra **http://localhost:3100**. Usuário de teste: `alice` / `wonderland123`.

```bash
./containers/logs.sh events   # a danca de requisicoes/respostas em tempo real
./containers/down.sh
```

## O que observar

- **PKCE funcionando**: no login normal, a tela de autorização do AS mostra o `code_challenge` recebido — o `code_verifier` correspondente nunca aparece em nenhum lugar visível (nem na URL, nem na tela), só existe no cookie do client e no corpo da troca final por token.
- **PKCE protegendo de verdade**: botão "Interceptar code sem o code_verifier" na home — faz um login real, mas na troca final usa um `code_verifier` propositalmente errado (simulando quem só capturou o `code` do redirect). O AS rejeita com `invalid_grant`, mostrado na tela de resultado.
- **Revogação em cascata**: botão "Revogar refresh_token (cascata)" no dashboard — chama `/revoke` no AS; em seguida, qualquer botão "Chamar Resource Server" mostra `401 invalid_token`, provando que o `access_token` (emitido a partir do mesmo `refresh_token`) também morreu, mesmo sem ter sido revogado diretamente.
- **Resposta de revogação sempre 200**: visível no log de eventos (`./containers/logs.sh events`) — o `/revoke` nunca revela se o token existia ou a quem pertencia.

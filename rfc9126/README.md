# Laboratório RFC 9126 — Pushed Authorization Requests (PAR)

Réplica autocontida do laboratório básico `rfc6749/` (mesma arquitetura,
containers e convenções — ver [[feedback-lab-pattern]] no projeto), com o
Authorization Code Grant exigindo **PAR**: nenhum parâmetro da authorization
request trafega mais pela URL do browser.

Este lab **não compartilha nenhum container** com `rfc6749/`/`rfc7636/` —
rede, nomes de container e portas são todos próprios.

## Componentes

| Serviço | Porta | Papel |
|---|---|---|
| `oauth9126-redis` | interna (6379) | clients, resource owners, authorization codes, tokens, requisições empurradas (PAR) |
| `oauth9126-events` | interna (4000) | observador — imprime a dança de HTTP no próprio log |
| `oauth9126-as` (Authorization Server) | 3201 | `/par` (recebe os parâmetros empurrados), `/authorize` (só aceita via `request_uri`), `/token` |
| `oauth9126-rs` (Resource Server) | 3202 | `/api/profile`, `/api/service-info` — idêntico ao lab da RFC 6749 |
| `oauth9126-client` (Client Demo) | 3200 | empurra a authorization request antes de redirecionar o browser |

Formatos: `client_id` = 16 hex, `client_secret` = 32 hex, `access_token`/`refresh_token` = 48 hex — mesma convenção do projeto.

## Uso

```bash
./containers/build.sh
./containers/up.sh
```

Abra **http://localhost:3200**. Usuário de teste: `alice` / `wonderland123`.

```bash
./containers/logs.sh events   # a danca de requisicoes/respostas em tempo real
./containers/down.sh
```

## O que observar

No log de eventos (`./containers/logs.sh events`), ao clicar em "Login com Authorization Server":

1. **`client-demo → authorization-server`**: `POST /par`, autenticado, com **todos** os parâmetros (`response_type`, `redirect_uri`, `scope`, `state`) visíveis no corpo — porque esse é um canal back-channel autenticado, não o browser.
2. Resposta do `/par`: `201` com `request_uri` (`urn:ietf:params:oauth:request_uri:...`) e `expires_in`.
3. **`browser → authorization-server`**: `GET /authorize?client_id=...&request_uri=urn:...` — compare o tamanho e o conteúdo dessa URL com a do lab `rfc6749/` (que carrega `scope`, `redirect_uri` e `state` na própria URL). Aqui, nada sensível passou pelo browser.
4. O `request_uri` é de uso único: o `/authorize` já apaga o registro no Redis assim que o lê — uma segunda tentativa com a mesma referência falha com `request_uri invalido, expirado ou ja utilizado`.

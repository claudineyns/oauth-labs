# Laboratório RFC 7523 — private_key_jwt (+ RFC 8414 + RFC 7591)

Réplica autocontida do laboratório básico `rfc6749/` (Authorization Code +
Client Credentials Grant), substituindo **inteiramente** a autenticação do
client por `private_key_jwt` (RFC 7523 §2.2) — não há `client_secret` em
nenhum lugar deste lab. Só a parte de **autenticação de client** (§2.2) é
implementada; o grant JWT-bearer (§2.1) fica fora, conforme pedido.

Para viabilizar isso sem segredo pré-semeado, o lab também incorpora:
- **RFC 8414** — o AS publica `/.well-known/oauth-authorization-server`.
- **RFC 7591** — o client-demo se registra dinamicamente ao subir, enviando
  sua **chave pública** (`jwks`) em vez de receber um `client_secret`.

Este lab **não compartilha nenhum container** com os demais — rede, nomes de
container e portas são todos próprios.

## Componentes

| Serviço | Porta | Papel |
|---|---|---|
| `oauth7523-redis` | interna (6379) | clients (com `jwks`, sem secret), resource owners, tokens, `jti` já usados |
| `oauth7523-events` | interna (4000) | observador — imprime a dança de HTTP no próprio log |
| `oauth7523-as` (Authorization Server) | 3401 | metadata, `/register`, `/authorize`, `/token` (valida `client_assertion`) |
| `oauth7523-rs` (Resource Server) | 3402 | `/api/profile`, `/api/service-info` — idêntico aos demais labs |
| `oauth7523-client` (Client Demo) | 3400 | gera par de chaves RSA, descobre a metadata, se registra com `jwks` |

Formatos: `client_id` = 16 hex, `access_token`/`refresh_token` = 48 hex. Chave do client: RSA 2048, `RS256`.

## Uso

```bash
./containers/build.sh
./containers/up.sh
```

Abra **http://localhost:3400**. Usuário de teste: `alice` / `wonderland123`.

```bash
./containers/logs.sh events   # a danca de requisicoes/respostas em tempo real
./containers/down.sh
```

## O que observar

- **Nenhum `client_secret` em lugar nenhum**: acompanhe o log de eventos — a chamada `POST /token` nunca carrega `Authorization: Basic` nem `client_secret` no corpo. Em vez disso, carrega `client_assertion_type` + `client_assertion` (um JWT compacto, assinado pela chave privada que só existe dentro do container do client-demo).
- **`jti` impedindo replay**: no dashboard (após login) ou na home (via Client Credentials), use o botão "Reenviar a última client_assertion" — o AS rejeita com `invalid_client`, mesmo a assinatura sendo perfeitamente válida, porque aquele `jti` específico já foi usado (RFC 7523 §3).
- **Registro sem segredo**: o `POST /register` (RFC 7591) leva um `jwks` com a chave pública em vez de receber um `client_secret` de volta — confira a resposta no log de eventos.
- **`aud` amarrado ao host**: como a metadata (RFC 8414) é montada a partir do `Host` da requisição, o `client_assertion` usa `audience = reg.metadata.issuer` — exatamente o valor que o AS vai conferir quando receber a chamada pela mesma rede interna.

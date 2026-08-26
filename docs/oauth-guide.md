# Guia OAuth 2.0 — Recapitulação por RFC

Guia de estudo teórico, um capítulo por RFC, antes da fase prática deste projeto.
RFC 7519 (JWT) é citada como dependência mas não recebe capítulo próprio.

Cada RFC coberta vira um documento próprio em [`rfcs/`](rfcs/), referenciado abaixo.
Este arquivo mantém só o roteiro (índice) e o template.

## Template de cada capítulo

1. Contexto e motivação
2. Terminologia e papéis novos/alterados
3. Fluxo(s) — sequência de mensagens
4. Parâmetros e endpoints normativos
5. Segurança — riscos e mitigações tratados na própria RFC
6. Relação com outras RFCs
7. O que mudou/foi deprecado desde a publicação

## Roteiro (índice)

### 1. Núcleo
- [x] [RFC 6749 — The OAuth 2.0 Authorization Framework](rfcs/rfc6749.md)
- [x] [RFC 6750 — Bearer Token Usage](rfcs/rfc6750.md)

### 2. Segurança — modelo de ameaças e boas práticas
- [x] [RFC 6819 — Threat Model and Security Considerations](rfcs/rfc6819.md)
- [x] [RFC 9700 — Best Current Practice for OAuth 2.0 Security](rfcs/rfc9700.md)
- [x] [RFC 7009 — Token Revocation](rfcs/rfc7009.md)

### 3. Extensões de Grant Type
- [x] [RFC 7636 — PKCE](rfcs/rfc7636.md)
- [x] [RFC 8628 — Device Authorization Grant](rfcs/rfc8628.md)
- [x] [RFC 8693 — Token Exchange](rfcs/rfc8693.md)
- [x] [RFC 9126 — Pushed Authorization Requests (PAR)](rfcs/rfc9126.md)
- [x] [RFC 9101 — JWT-Secured Authorization Request (JAR)](rfcs/rfc9101.md)

### 4. Metadata e registro de clientes
- [x] [RFC 8414 — Authorization Server Metadata](rfcs/rfc8414.md)
- [x] [RFC 7591 — Dynamic Client Registration](rfcs/rfc7591.md)
- [x] [RFC 7592 — Dynamic Client Registration Management](rfcs/rfc7592.md)

### 5. Formato e introspecção de tokens
- [x] [RFC 7523 — JWT Profile for OAuth 2.0](rfcs/rfc7523.md)
- [x] [RFC 7662 — Token Introspection](rfcs/rfc7662.md)
- [x] [RFC 9068 — JWT Profile for Access Tokens](rfcs/rfc9068.md)
- (RFC 7519 — JWT, referenciada como base, sem capítulo dedicado)

### 6. Segurança avançada
- [x] [RFC 8705 — Mutual TLS Client Authentication and Certificate-Bound Tokens](rfcs/rfc8705.md)
- [x] [RFC 9449 — DPoP](rfcs/rfc9449.md)
- [x] [RFC 8707 — Resource Indicators](rfcs/rfc8707.md) — inclui a análise prometida: scope segregado ajuda, mas não substitui audience (ver item 1 do capítulo)
- [x] [RFC 9396 — Rich Authorization Requests (RAR)](rfcs/rfc9396.md)

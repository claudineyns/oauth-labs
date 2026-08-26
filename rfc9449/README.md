# Laboratório RFC 9449 — DPoP (+ RFC 8414 + RFC 7591)

Réplica autocontida do laboratório básico `rfc6749/` (Authorization Code +
Client Credentials Grant), com **todo** access_token e refresh_token
vinculado a uma chave via DPoP — `token_type: DPoP`, não `Bearer`. O client é
**público** (`token_endpoint_auth_method=none`) — sem `client_secret`, sem
`jwks` pré-registrada: a chave viaja embutida em cada prova, não é cadastrada
de antemão (diferença central em relação ao lab da RFC 7523).

Diferente do lab de mTLS (RFC 8705, que exigiria TLS real), este continua
em HTTP puro — DPoP é só um header e um JWT assinado por requisição.

Este lab **não compartilha nenhum container** com os demais — rede, nomes de
container e portas são todos próprios.

## Componentes

| Serviço | Porta | Papel |
|---|---|---|
| `oauth9449-redis` | interna (6379) | clients, resource owners, tokens (com `cnf_jkt`), `jti` de provas já usadas |
| `oauth9449-events` | interna (4000) | observador — imprime a dança de HTTP no próprio log |
| `oauth9449-as` (Authorization Server) | 3501 | metadata, `/register`, `/authorize`, `/token` (valida prova + vincula `cnf.jkt`) |
| `oauth9449-rs` (Resource Server) | 3502 | `/api/profile`, `/api/service-info` — exige `Authorization: DPoP` + prova válida |
| `oauth9449-client` (Client Demo) | 3500 | gera a chave DPoP, descobre a metadata, se registra como client público |

Formatos: `client_id` = 16 hex, `access_token`/`refresh_token` = 48 hex. Chave do client: RSA 2048, `RS256`.

## Uso

```bash
./containers/build.sh
./containers/up.sh
```

Abra **http://localhost:3500**. Usuário de teste: `alice` / `wonderland123`.

Acompanhe em terminais separados:
```bash
./containers/logs.sh client   # montagem de cada prova DPoP, passo a passo
./containers/logs.sh as       # validação da prova na emissão do token
./containers/logs.sh rs       # validação da prova no acesso ao recurso
./containers/logs.sh events   # o envelope HTTP bruto de cada chamada
```

```bash
./containers/down.sh
```

## O que observar

- **Montagem da prova** (`logs.sh client`): a cada chamada ao `/token` ou ao resource server, o client loga `htm`, `htu`, `iat`, `jti`, o thumbprint da chave e (nas chamadas ao RS) o `ath` — tudo antes de assinar.
- **Validação passo a passo** (`logs.sh as` e `logs.sh rs`): assinatura, `typ`, `htm`/`htu`, janela de frescor do `iat`, unicidade do `jti`, `ath` (no RS) e, por fim, a comparação do thumbprint da chave com o `cnf.jkt` gravado no token — com o motivo exato quando algo falha.
- **"Como Bearer simples (sem prova)"**: usa o mesmo token, mas sem header `DPoP` — o RS rejeita antes mesmo de checar a prova, porque o esquema esperado é `DPoP`, não `Bearer`. Mostra na prática que possuir a string do token não basta.
- **"Reenviar a mesma prova (replay)"**: reaproveita literalmente a última prova já usada — rejeitada por `jti` repetido, mesmo com assinatura perfeitamente válida.
- **Renovação vinculada**: o `refresh_token` também carrega `cnf_jkt` — o AS confere que a prova apresentada na renovação vem da mesma chave que recebeu aquele refresh_token.

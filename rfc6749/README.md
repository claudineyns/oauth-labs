# Laboratório RFC 6749 — The OAuth 2.0 Authorization Framework

Fluxo completo em Node.js/Express, empacotado como containers Podman + Redis 8,
ilustrando **Authorization Code Grant** (com interface do resource owner) e
**Client Credentials Grant**. As chamadas ao Resource Server também exercitam
os 3 métodos de transmissão de Bearer token da **RFC 6750**.

Toda comunicação "interface → server" e "machine → machine" é observável em
tempo real via um container coletor de eventos dedicado (veja abaixo).

## Componentes

| Serviço | Porta | Papel |
|---|---|---|
| `oauth6749-redis` | interna (6379) | armazena clients, resource owners, authorization codes e tokens (com TTL nativo) |
| `oauth6749-events` (Events Collector) | interna (4000) | recebe o envelope (headers + payload) de toda requisição/resposta e imprime no próprio log do container — a "dança" de HTTP em tempo real |
| `oauth6749-as` (Authorization Server) | 3001 | `/authorize` (login + consentimento), `/token` (emissão) |
| `oauth6749-rs` (Resource Server) | 3002 | `/api/profile`, `/api/service-info` — validação de Bearer token |
| `oauth6749-client` (Client Demo) | 3000 | app "terceira parte" que inicia os fluxos e chama o RS |

Formatos: `client_id` = 16 hex, `client_secret` = 32 hex, `access_token`/`refresh_token` = 48 hex.

## Uso

```bash
./containers/build.sh   # builda as 4 imagens
./containers/up.sh      # sobe redis + events + as + rs + client (preflight do podman incluso)
```

Abra **http://localhost:3000**. Usuário de teste: `alice` / `wonderland123`.

Em outro terminal, acompanhe a dança de requisições/respostas em tempo real:

```bash
./containers/logs.sh events
```

Cada linha do fluxo (browser → AS, AS → browser, browser → client, client → AS,
client → RS...) aparece como um bloco de requisição/resposta bruta, na ordem em
que acontece — inclusive as chamadas machine-to-machine que o client-demo faz
por trás dos panos. Senhas e `client_secret` em corpo de requisição aparecem
mascarados (`••••••••`); o `client_secret` enviado via HTTP Basic continua
visível como veio na conexão (é o próprio conteúdo do header).

```bash
./containers/logs.sh as   # ou: rs, client, redis, events
./containers/down.sh      # remove os 5 containers (mantém as imagens e a rede)
```

O `client_id`/`client_secret` de demonstração são gerados uma vez em
`.demo-client.env` (na raiz deste laboratório) e reaproveitados nas execuções seguintes.

## O que observar, por seção da RFC

- **§3.1 Authorization endpoint** — `GET /authorize` no AS valida `client_id`/`redirect_uri` antes de exibir a tela de login; nunca redireciona para um `redirect_uri` não registrado.
- **§4.1 Authorization Code Grant** — botão "Login com Authorization Server" no client demo.
- **§4.4 Client Credentials Grant** — botão "Executar chamada machine-to-machine" na home; sem tela de login, sem `refresh_token` na resposta (conforme §4.4.3).
- **§6 Refreshing an Access Token** — botão "Renovar via refresh_token" no dashboard; o `refresh_token` é rotacionado (o antigo é invalidado no Redis).
- **RFC 6750 §2** — os 3 botões "Via header / Via body / Via query" no dashboard mostram o `access_token` sendo transmitido de cada forma, e o RS aceitando todas — mas rejeitando com `invalid_request` se mais de uma for usada simultaneamente.
- **RFC 6750 §3** — botão "Simular token inválido" mostra o `WWW-Authenticate` com `error="invalid_token"`; pedir `/api/profile` sem o escopo `profile` (ex. adaptando o fluxo) mostraria `error="insufficient_scope"`.

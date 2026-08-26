# Laboratório RFC 7592 — Dynamic Client Registration Management (+ RFC 8414 + RFC 7591)

Réplica autocontida do laboratório básico `rfc6749/` (mesma arquitetura,
containers e convenções — ver [[feedback-lab-pattern]] no projeto), substituindo
o registro de client "fora de banda" (script de seed) por:

- **RFC 8414** — o AS publica `/.well-known/oauth-authorization-server`.
- **RFC 7591** — o client-demo **não** se registra sozinho ao subir: a home
  exibe só um botão "Registrar client agora", e nenhuma outra funcionalidade
  (login, chamadas machine-to-machine, gerenciamento do registro) fica
  disponível até essa ação manual ser concluída. Ao clicar, descobre o
  `registration_endpoint` pela metadata (RFC 8414) e envia o `POST /register`.
- **RFC 7592** — o client-demo pode consultar, atualizar e apagar o próprio
  registro em tempo real, usando o `registration_access_token` recebido na
  criação.

Este lab **não compartilha nenhum container** com os demais — rede, nomes de
container e portas são todos próprios.

## Componentes

| Serviço | Porta | Papel |
|---|---|---|
| `oauth7592-redis` | interna (6379) | clients (registrados dinamicamente), resource owners, tokens |
| `oauth7592-events` | interna (4000) | observador — imprime a dança de HTTP no próprio log |
| `oauth7592-as` (Authorization Server) | 3301 | `/.well-known/oauth-authorization-server`, `/register` (+ `/register/:id`), `/authorize`, `/token` |
| `oauth7592-rs` (Resource Server) | 3302 | `/api/profile`, `/api/service-info` — idêntico ao lab da RFC 6749 |
| `oauth7592-client` (Client Demo) | 3300 | sobe sem client_id; registra sob demanda quando o usuário aciona "Registrar client agora" |

Formatos: `client_id` = 16 hex, `client_secret` = 32 hex, `access_token`/`refresh_token`/`registration_access_token` = 48 hex.

## Uso

```bash
./containers/build.sh
./containers/up.sh
```

Abra **http://localhost:3300**. Usuário de teste: `alice` / `wonderland123`.

Também dá para consultar a metadata diretamente no seu próprio browser/curl:
```bash
curl http://localhost:3301/.well-known/oauth-authorization-server
```

```bash
./containers/logs.sh events   # a danca de requisicoes/respostas em tempo real
./containers/down.sh
```

## O que observar

- **Sem seed de client**: diferente dos outros labs, não existe `.demo-client.env` nem `seed-client.sh`, e o registro **não** acontece sozinho na inicialização. Ao subir, a home só mostra o botão "Registrar client agora" — login, Client Credentials e gerenciamento do registro ficam bloqueados (redirecionam para `/`) até essa ação manual acontecer. Clicar nele dispara, na sequência (acompanhe em `./containers/logs.sh events`): `GET /.well-known/oauth-authorization-server` (descoberta) → `POST /register` (registro, corpo `application/json` — o único endpoint do projeto que não usa form-urlencoded) → resposta com `client_id`, `client_secret`, `registration_access_token`, `registration_client_uri`. `client_id`/`client_secret` mudam a cada vez que você registra de novo.
- **Gerenciamento ao vivo** — na home (já registrada), a seção "Gerenciar registro": "Consultar (GET)" mostra a metadata atual (sem o `client_secret` — só aparece uma vez, na criação); "Atualizar (PUT)" reenvia a metadata completa com um `client_name` novo e mostra o `registration_access_token` **rotacionado** na resposta; "Apagar (DELETE)" remove o registro **e** a home volta ao estado "não registrado" — tudo trava de novo até um novo registro manual. Tente "Executar chamada machine-to-machine" logo após apagar: o `/token` rejeita com `invalid_client`, provando que o client não existe mais.
- **`issuer` coerente com quem pergunta**: a metadata é montada a partir do `Host` da própria requisição — buscar via `http://localhost:3301/...` (do seu host) e via `http://oauth7592-as:3301/...` (de dentro da rede do projeto, como o client-demo faz) devolvem `issuer`/endpoints coerentes com cada origem.

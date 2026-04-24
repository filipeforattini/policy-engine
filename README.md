# AuthZ Express + TS (localhost)

Servidor de demonstração com:
- middleware de autorização acumulada (`allow`/`deny`, com `deny` vencendo)
- policies reconfiguráveis em tempo de execução
- painel web para visualizar/editar policies
- emissão de JWT por usuário de demo
- operações sobre recursos (`api` e `apikey`)

## Rodar

```bash
npm install
npm run dev
```

Abra no navegador:

- `http://localhost:3000`

## Usuários demo

- `u1` -> `developer`
- `u2` -> `viewer`
- `admin` -> `admin`

## Fluxo

1. No painel, escolha o usuário e clique em **Pedir novo JWT**.
2. O token é enviado automaticamente nos requests para `/api/*`.
3. Edite policies no painel e clique em **Salvar policies**.
4. Crie/edite APIs e keys no painel.

## Endpoints úteis (API)

- `POST /auth/token` 
  ```json
  { "userId": "u1" }
  ```
- `GET /api/policies`
- `PUT /api/policies`
- `GET /api/resources`
- `GET /api/resources/apis/:apiId`
- `POST /api/resources/apis`
- `PUT /api/resources/apis/:apiId`
- `DELETE /api/resources/apis/:apiId`
- `POST /api/resources/apis/:apiId/keys`
- `PUT /api/resources/apis/:apiId/keys/:keyId`
- `DELETE /api/resources/apis/:apiId/keys/:keyId`

## Regra importante

`freeze-delete-api` (deny) em `api:*` deixa `DELETE /api/resources/apis/:apiId` bloqueado para todos.

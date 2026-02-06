# Guia de Testes - Auth Service + General Portal (Postman)

## 📋 Pré-requisitos

1. **Serviços rodando:**
   - Auth Service na porta `3001`
   - General Portal na porta `4000`
   - Redis rodando
   - PostgreSQL rodando

2. **Postman instalado**

3. **Variáveis de ambiente configuradas**

## 🚀 Passo 1: Configurar os Serviços

### Auth Service
```bash
cd auth-service
npm install
npm run prisma:generate
npm run prisma:migrate
npm run prisma:seed  # Cria usuário demo: demo@example.com / Demo@123
npm run start:dev
```

### General Portal
```bash
cd general-portal
npm install
npm run build
npm run start:dev
```

**Verificar se estão rodando:**
- Auth Service: `http://localhost:3001/health`
- General Portal: `http://localhost:4000/health`

## 📝 Passo 2: Configurar Collection no Postman

### Criar Environment no Postman

Crie um novo Environment chamado "Local Development" com:

| Variable | Initial Value | Current Value |
|----------|---------------|---------------|
| `auth_base_url` | `http://localhost:3001` | `http://localhost:3001` |
| `portal_base_url` | `http://localhost:4000` | `http://localhost:4000` |
| `access_token` | (vazio) | (será preenchido após login) |
| `refresh_token` | (vazio) | (será preenchido após login) |
| `internal_api_key` | `dev-internal-api-key-min-32-chars` | `dev-internal-api-key-min-32-chars` |

## 🔐 Passo 3: Fluxo de Autenticação

### 3.1. Login no Auth Service

**Request:**
```
POST {{auth_base_url}}/api/v1/auth/login
Content-Type: application/json

{
  "email": "demo@example.com",
  "password": "Demo@123"
}
```

**Response esperada:**
```json
{
  "user": {
    "id": "uuid",
    "email": "demo@example.com",
    "firstName": "Demo",
    "lastName": "User"
  },
  "tokens": {
    "accessToken": "eyJhbGc...",
    "refreshToken": "eyJhbGc...",
    "expiresIn": 3600
  }
}
```

**Postman Script (Tests tab):**
```javascript
if (pm.response.code === 200) {
    const jsonData = pm.response.json();
    pm.environment.set("access_token", jsonData.tokens.accessToken);
    pm.environment.set("refresh_token", jsonData.tokens.refreshToken);
    console.log("Tokens salvos no environment");
}
```

### 3.2. Testar Token no Auth Service (Internal API)

**Request:**
```
POST {{auth_base_url}}/api/v1/internal/resolve-context
Content-Type: application/json
X-Internal-Api-Key: {{internal_api_key}}

{
  "accessToken": "{{access_token}}"
}
```

**Response esperada:**
```json
{
  "userId": "uuid",
  "accountId": "uuid",
  "roles": ["admin"],
  "permissions": ["users:view", "users:create", ...]
}
```

## 🌐 Passo 4: Usar o General Portal

### 4.1. Query GraphQL Simples (Meu Perfil)

**Request:**
```
POST {{portal_base_url}}/graphql
Content-Type: application/json
Authorization: Bearer {{access_token}}

{
  "query": "query { me { id email firstName lastName } }"
}
```

**Response esperada:**
```json
{
  "data": {
    "me": {
      "id": "uuid",
      "email": "demo@example.com",
      "firstName": "Demo",
      "lastName": "User"
    }
  }
}
```

### 4.2. Query com Variáveis

**Request:**
```
POST {{portal_base_url}}/graphql
Content-Type: application/json
Authorization: Bearer {{access_token}}

{
  "query": "query GetUsers($limit: Int) { users(limit: $limit) { id email firstName lastName } }",
  "variables": {
    "limit": 10
  }
}
```

### 4.3. Mutation (Exemplo)

**Request:**
```
POST {{portal_base_url}}/graphql
Content-Type: application/json
Authorization: Bearer {{access_token}}

{
  "query": "mutation UpdateProfile($input: UpdateUserInput!) { updateProfile(input: $input) { id email firstName lastName } }",
  "variables": {
    "input": {
      "firstName": "Updated",
      "lastName": "Name"
    }
  }
}
```

## 🔄 Passo 5: Refresh Token

### Quando o Access Token expirar

**Request:**
```
POST {{auth_base_url}}/auth/refresh
Content-Type: application/json

{
  "refreshToken": "{{refresh_token}}"
}
```

**Response:**
```json
{
  "tokens": {
    "accessToken": "novo_token...",
    "refreshToken": "novo_refresh_token...",
    "expiresIn": 3600
  }
}
```

**Postman Script (Tests tab):**
```javascript
if (pm.response.code === 200) {
    const jsonData = pm.response.json();
    pm.environment.set("access_token", jsonData.tokens.accessToken);
    pm.environment.set("refresh_token", jsonData.tokens.refreshToken);
}
```

## 🧪 Passo 6: Testar Endpoints do Auth Service

### 6.1. Listar Usuários (requer autenticação)

**Request:**
```
GET {{auth_base_url}}/api/v1/users
Authorization: Bearer {{access_token}}
```

### 6.2. Obter Meu Perfil

**Request:**
```
GET {{auth_base_url}}/api/v1/users/me
Authorization: Bearer {{access_token}}
```

### 6.3. Logout

**Request:**
```
POST {{auth_base_url}}/api/v1/auth/logout
Authorization: Bearer {{access_token}}
```

## 📊 Passo 7: Testar Queries GraphQL Complexas

### 7.1. Query com Fragmentos

**Request:**
```
POST {{portal_base_url}}/graphql
Content-Type: application/json
Authorization: Bearer {{access_token}}

{
  "query": "query { users { ...UserFields } } fragment UserFields on User { id email firstName lastName roles { name } }"
}
```

### 7.2. Múltiplas Queries

**Request:**
```
POST {{portal_base_url}}/graphql
Content-Type: application/json
Authorization: Bearer {{access_token}}

{
  "query": "query { me { id email } users(limit: 5) { id email } }"
}
```

## 🔍 Passo 8: Debugging

### Verificar se o token está sendo enviado

No Postman, vá em **View > Show Postman Console** para ver:
- Headers enviados
- Response recebida
- Erros de autenticação

### Erros Comuns

**401 Unauthorized:**
- Token expirado → Use refresh token
- Token inválido → Faça login novamente
- Header Authorization ausente → Adicione `Authorization: Bearer {{access_token}}`

**403 Forbidden:**
- Permissões insuficientes → Verifique as permissões do usuário

**500 Internal Server Error:**
- Verifique os logs do Auth Service
- Verifique se o General Portal consegue comunicar com o Auth Service

## 📦 Collection Completa do Postman

### Estrutura Recomendada:

```
📁 Auth Service
  📁 Authentication
    ✅ POST Login
    ✅ POST Register
    ✅ POST Refresh Token
    ✅ POST Logout
    ✅ POST Logout All
  📁 Users
    ✅ GET /users
    ✅ GET /users/me
    ✅ GET /users/:id
  📁 Internal API
    ✅ POST /internal/resolve-context
    ✅ POST /internal/verify-token
    ✅ POST /internal/check-permissions

📁 General Portal
  📁 GraphQL Queries
    ✅ Query: me
    ✅ Query: users
    ✅ Query: accounts
  📁 GraphQL Mutations
    ✅ Mutation: updateProfile
    ✅ Mutation: createUser
```

## 🎯 Exemplos Prontos

### Exemplo 1: Fluxo Completo de Autenticação

1. **Login** → Salva tokens
2. **Query `me`** no Portal → Verifica autenticação
3. **Query `users`** no Portal → Testa autorização
4. **Logout** → Revoga sessão

### Exemplo 2: Teste de Permissões

1. **Login** com usuário específico
2. **Query protegida** → Deve funcionar se tiver permissão
3. **Mutation protegida** → Deve funcionar se tiver permissão

### Exemplo 3: Teste de Refresh Token

1. **Login** → Salva tokens
2. **Esperar expiração** (ou usar token antigo)
3. **Refresh Token** → Obtém novos tokens
4. **Usar novo access token** → Deve funcionar

## 🔐 Segurança

### Headers Importantes

**Para Auth Service:**
- `Authorization: Bearer <access_token>` - Para endpoints protegidos
- `X-Internal-Api-Key: <key>` - Para Internal API

**Para General Portal:**
- `Authorization: Bearer <access_token>` - Para GraphQL queries/mutations
- `Cookie: access_token=<token>` - Alternativa (se configurado)

### Variáveis Sensíveis

⚠️ **NUNCA** commite tokens ou API keys no código
- Use Environment Variables no Postman
- Use `.env` files nos serviços
- Configure `.gitignore` corretamente

## 📚 Recursos Adicionais

- **Swagger Auth Service:** `http://localhost:3001/api/docs`
- **GraphiQL Portal:** `http://localhost:4000/graphql` (se disponível)
- **Health Checks:**
  - Auth: `http://localhost:3001/api/v1/health`
  - Portal: `http://localhost:4000/health` (se disponível)

## 🐛 Troubleshooting

### Portal não consegue comunicar com Auth Service

1. Verifique `AUTH_SERVICE_URL` no `.env` do Portal
2. Verifique se o Auth Service está rodando
3. Verifique `INTERNAL_API_KEY` está correto

### Token não funciona no Portal

1. Verifique se o token está sendo enviado no header
2. Verifique se o Portal está validando via Auth Service
3. Veja os logs do Portal para erros

### GraphQL retorna erro de autenticação

1. Verifique se o contexto está sendo construído corretamente
2. Verifique se o token é válido (teste no Auth Service)
3. Veja os logs do Portal

# 🚀 Quick Start - Testando Auth Service + General Portal no Postman

## ⚡ Setup Rápido (5 minutos)

### 1. Iniciar Serviços

```bash
# Terminal 1 - Auth Service
cd auth-service
npm install
npm run prisma:generate
npm run prisma:migrate
npm run prisma:seed
npm run start:dev

# Terminal 2 - General Portal (se existir)
cd general-portal
npm install
npm run start:dev
```

### 2. Importar Collection no Postman

1. Abra o Postman
2. **Import** → **File** → Selecione `POSTMAN_COLLECTION.json`
3. Crie um **Environment** chamado "Local" com estas variáveis:

| Variable | Value |
|----------|-------|
| `auth_base_url` | `http://localhost:3001` |
| `portal_base_url` | `http://localhost:4000` |
| `access_token` | (deixe vazio) |
| `refresh_token` | (deixe vazio) |
| `internal_api_key` | `dev-internal-api-key-min-32-chars` |

## 🎯 Fluxo de Teste Passo a Passo

### Passo 1: Login

**Request:**
- **Method:** `POST`
- **URL:** `{{auth_base_url}}/api/v1/auth/login`
- **Body (JSON):**
```json
{
  "email": "demo@example.com",
  "password": "Demo@123"
}
```

**✅ O que esperar:**
```json
{
  "user": {
    "id": "...",
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

**💡 Dica:** Use o script na aba "Tests" para salvar automaticamente os tokens:
```javascript
if (pm.response.code === 200) {
    const jsonData = pm.response.json();
    pm.environment.set("access_token", jsonData.tokens.accessToken);
    pm.environment.set("refresh_token", jsonData.tokens.refreshToken);
}
```

### Passo 2: Verificar Token (Internal API)

**Request:**
- **Method:** `POST`
- **URL:** `{{auth_base_url}}/api/v1/internal/resolve-context`
- **Headers:**
  - `Content-Type: application/json`
  - `X-Internal-Api-Key: {{internal_api_key}}`
- **Body (JSON):**
```json
{
  "accessToken": "{{access_token}}"
}
```

**✅ O que esperar:**
```json
{
  "userId": "...",
  "accountId": "...",
  "roles": ["admin"],
  "permissions": ["users:view", "users:create", ...]
}
```

### Passo 3: Usar Token no Portal (GraphQL)

**Request:**
- **Method:** `POST`
- **URL:** `{{portal_base_url}}/graphql`
- **Headers:**
  - `Content-Type: application/json`
  - `Authorization: Bearer {{access_token}}`
- **Body (JSON):**
```json
{
  "query": "query { me { id email firstName lastName } }"
}
```

**✅ O que esperar:**
```json
{
  "data": {
    "me": {
      "id": "...",
      "email": "demo@example.com",
      "firstName": "Demo",
      "lastName": "User"
    }
  }
}
```

## 📋 Checklist de Testes

- [ ] ✅ Login retorna tokens
- [ ] ✅ Tokens são salvos automaticamente
- [ ] ✅ Internal API valida token corretamente
- [ ] ✅ GraphQL Portal aceita token
- [ ] ✅ Query `me` retorna dados do usuário
- [ ] ✅ Refresh token funciona quando access token expira
- [ ] ✅ Logout revoga sessão

## 🔍 Troubleshooting Rápido

### ❌ Erro 401 Unauthorized
- Token expirado? → Use refresh token
- Token inválido? → Faça login novamente
- Header Authorization ausente? → Adicione `Authorization: Bearer {{access_token}}`

### ❌ Erro 403 Forbidden
- Verifique permissões do usuário
- Verifique se o endpoint requer role específica

### ❌ Portal não responde
- Verifique se está rodando na porta 4000
- Verifique `AUTH_SERVICE_URL` no `.env` do Portal
- Verifique logs do Portal

### ❌ Internal API retorna 401
- Verifique `X-Internal-Api-Key` header
- Verifique `INTERNAL_API_KEY` no `.env` do Auth Service

## 🎓 Exemplos Prontos

### Exemplo 1: Query Simples
```json
{
  "query": "query { me { id email } }"
}
```

### Exemplo 2: Query com Variáveis
```json
{
  "query": "query GetUsers($limit: Int) { users(limit: $limit) { id email } }",
  "variables": { "limit": 5 }
}
```

### Exemplo 3: Mutation
```json
{
  "query": "mutation { updateProfile(input: { firstName: \"New\" }) { id firstName } }"
}
```

## 📚 Recursos

- **Swagger:** `http://localhost:3001/api/docs`
- **Health Check:** `http://localhost:3001/api/v1/health`
- **Collection Postman:** Importe `POSTMAN_COLLECTION.json`

## 🎯 Próximos Passos

1. Teste todas as queries GraphQL disponíveis
2. Teste mutations protegidas
3. Teste refresh token automático
4. Configure variáveis de ambiente para diferentes ambientes (dev/staging/prod)

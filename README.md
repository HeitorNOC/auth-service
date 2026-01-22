# Auth Service

Multi-tenant Authentication and Authorization Service for SaaS microservices architecture.

## Stack

- NestJS 10
- Prisma 6+ (with PostgreSQL adapter)
- PostgreSQL 16
- Redis 7
- TypeScript 5
- Docker

## Quick Start

### With Docker

```bash
docker-compose up -d
```

### Local Development

```bash
npm install
cp env.example .env
npx prisma migrate dev
npm run prisma:seed
npm run dev
```

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Login with credentials |
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/google` | Google OAuth |
| POST | `/api/v1/auth/refresh` | Refresh tokens |
| POST | `/api/v1/auth/logout` | Logout |
| POST | `/api/v1/auth/logout/all` | Logout from all devices |

### Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/users/me` | Get current user |
| GET | `/api/v1/users` | List users |
| GET | `/api/v1/users/:id` | Get user by ID |
| POST | `/api/v1/users` | Create user |
| PATCH | `/api/v1/users/:id` | Update user |
| DELETE | `/api/v1/users/:id` | Delete user |

### Roles & Permissions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/roles` | List roles |
| POST | `/api/v1/roles` | Create role |
| GET | `/api/v1/permissions` | List permissions |

### Account

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/account` | Get account |
| PATCH | `/api/v1/account` | Update account |
| POST | `/api/v1/account/invitations` | Create invitation |

### Internal API (GraphQL Portal)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/internal/resolve-context` | Resolve user context |
| POST | `/api/v1/internal/verify-token` | Verify token |
| POST | `/api/v1/internal/check-permissions` | Check permissions |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/health` | Basic health |
| GET | `/api/v1/health/ready` | Readiness check |
| GET | `/api/v1/health/live` | Liveness probe |

## Demo Credentials

| Email | Password | Role |
|-------|----------|------|
| owner@demo.com | Demo@123 | OWNER |
| admin@demo.com | Demo@123 | ADMIN |
| worker@demo.com | Demo@123 | WORKER |

## Environment Variables

See `env.example` for all available configuration options.

## Prisma 7 Configuration

This project uses Prisma 7 with the PostgreSQL adapter. The database URL is configured via `DATABASE_URL` environment variable and passed directly to the PrismaClient via the `pg` adapter.

```typescript
const pool = new Pool({ connectionString });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });
```

## GraphQL Portal Integration

The internal API allows the GraphQL Portal to:

1. Resolve user context from access token
2. Verify tokens
3. Check permissions/roles

Example request:

```bash
curl -X POST http://localhost:3001/api/v1/internal/resolve-context \
  -H "Content-Type: application/json" \
  -H "X-Internal-Api-Key: your-internal-api-key" \
  -d '{"accessToken": "eyJ..."}'
```

Response:

```json
{
  "userId": "uuid",
  "accountId": "uuid",
  "roles": ["ADMIN"],
  "permissions": ["users:view", "users:create"]
}
```

## License

MIT

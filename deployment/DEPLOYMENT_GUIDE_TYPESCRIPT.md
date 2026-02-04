# MCP Server Deployment Guide - TypeScript

**Language-specific deployment guide for TypeScript implementations**

---

## Overview

This guide provides TypeScript-specific instructions for deploying your MCP server using the provided template file. 

**Prerequisites:**
- Reviewed the [Master Deployment Guide](./README.md)
- Node.js 18.x or higher installed
- Template file: [`mcp-server-typescript-template.ts`](../templates/mcp-server-typescript-template.ts)

**Approach:** Start with the template file and modify as needed. This guide only covers TypeScript-specific setup and deviations from the template.

---

## Phase 1: Environment Setup

### 1.1 Generate Security Credentials

**TypeScript-specific method using Node.js crypto:**

```typescript
// generate-secrets.ts
import crypto from 'crypto';

console.log('JWT_SECRET=' + crypto.randomBytes(32).toString('base64'));
console.log('DCR_AUTH_TOKEN=' + crypto.randomBytes(32).toString('hex'));
```

Run: `npx ts-node generate-secrets.ts` or `node --loader ts-node/esm generate-secrets.ts`

**Alternative:** Use OpenSSL commands from Master Deployment Guide.

### 1.2 Install Dependencies

**Create `package.json`:**

```json
{
  "name": "mcp-server-servicenow",
  "version": "1.0.0",
  "type": "module",
  "main": "dist/server.js",
  "scripts": {
    "build": "tsc",
    "start": "node dist/server.js",
    "dev": "tsx watch server.ts",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "express": "^4.18.2",
    "express-rate-limit": "^7.1.5",
    "cors": "^2.8.5",
    "jsonwebtoken": "^9.0.2",
    "bcrypt": "^5.1.1",
    "uuid": "^9.0.1",
    "dotenv": "^16.3.1",
    "redis": "^4.6.11"
  },
  "devDependencies": {
    "@types/express": "^4.17.21",
    "@types/cors": "^2.8.17",
    "@types/jsonwebtoken": "^9.0.5",
    "@types/bcrypt": "^5.0.2",
    "@types/uuid": "^9.0.7",
    "@types/node": "^20.10.6",
    "typescript": "^5.3.3",
    "tsx": "^4.7.0"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
```

**Create `tsconfig.json`:**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "lib": ["ES2022"],
    "moduleResolution": "node",
    "rootDir": ".",
    "outDir": "./dist",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["server.ts", "src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

**Install:**
```bash
npm install
```

### 1.3 Configure Environment Variables

**Create `.env` file (same as JavaScript):**

```bash
# Server Configuration
PORT=8080
NODE_ENV=development

# OAuth 2.1 Configuration
JWT_SECRET=your-generated-jwt-secret-minimum-32-chars
OAUTH_ISSUER=http://localhost:8080
DCR_AUTH_TOKEN=your-generated-dcr-token

# Token Lifetimes (seconds)
ACCESS_TOKEN_LIFETIME=3600
REFRESH_TOKEN_LIFETIME=2592000
AUTHORIZATION_CODE_LIFETIME=600

# Storage Configuration
CLIENT_STORAGE_PATH=./data/registered_clients.json

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,https://your-instance.service-now.com

# Rate Limiting
RATE_LIMIT_OAUTH_WINDOW_MS=900000
RATE_LIMIT_OAUTH_MAX=100
RATE_LIMIT_MCP_WINDOW_MS=60000
RATE_LIMIT_MCP_MAX=60
```

**Important:** Add to `.gitignore`:
```
.env
node_modules/
dist/
data/
*.log
```

### 1.4 Project Structure

TypeScript template includes type definitions. Recommended structure:

```
your-mcp-server/
├── server.ts                    # Main entry (from template)
├── package.json
├── tsconfig.json
├── .env
├── .gitignore
├── dist/                        # Compiled output (created by tsc)
└── data/
    └── registered_clients.json
```

**Optional modular structure** (if refactoring template):
```
├── src/
│   ├── types/
│   │   └── index.ts            # Type definitions
│   ├── config/
│   ├── middleware/
│   ├── oauth/
│   ├── mcp/
│   └── storage/
```

---

## Phase 2: Server Foundation

**Template Coverage:** The template file includes complete server foundation implementation with TypeScript type safety.

### What's Included in Template:
- HTTP server initialization with Express
- Type-safe configuration validation
- Middleware stack with typed request/response
- Storage initialization with interfaces
- Health check endpoint with typed responses
- Graceful shutdown handlers

### Required Changes:

**None required** - the template works as-is with your `.env` configuration.

### TypeScript-Specific Notes:

**Environment Variables:** The template includes type definitions for environment variables:

```typescript
interface Config {
  PORT: number;
  NODE_ENV: string;
  JWT_SECRET: string;
  OAUTH_ISSUER: string;
  // ...
}
```

**Type Safety:** All storage operations are typed:

```typescript
interface OAuthClient {
  client_id: string;
  client_secret_hash: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  created_at: string;
}

interface ClientStorage {
  get(clientId: string): Promise<OAuthClient | null>;
  save(clientId: string, client: OAuthClient): Promise<void>;
}
```

### Optional Enhancements:

**If you need database storage with typed queries:**

```typescript
import { Pool, QueryResult } from 'pg';

async function initializeClientStorage(): Promise<ClientStorage> {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  
  return {
    async get(clientId: string): Promise<OAuthClient | null> {
      const result: QueryResult<OAuthClient> = await pool.query(
        'SELECT * FROM oauth_clients WHERE client_id = $1',
        [clientId]
      );
      return result.rows[0] || null;
    },
    
    async save(clientId: string, client: OAuthClient): Promise<void> {
      await pool.query(
        'INSERT INTO oauth_clients (client_id, data) VALUES ($1, $2) ON CONFLICT (client_id) DO UPDATE SET data = $2',
        [clientId, JSON.stringify(client)]
      );
    }
  };
}
```

---

## Phase 3: MCP Protocol Implementation

**Template Coverage:** The template includes complete MCP protocol implementation with type-safe handlers.

### What's Included in Template:
- `/mcp` endpoint with typed request/response
- MCP protocol types and interfaces
- `initialize`, `tools/list`, `tools/call` handlers
- Typed tool definitions with JSON Schema
- Authentication middleware with typed JWT payload

### Required Changes:

**None required** - basic MCP protocol works out of the box.

### TypeScript Type Definitions:

The template includes comprehensive types:

```typescript
interface MCPRequest {
  jsonrpc: '2.0';
  method: string;
  params?: any;
  id?: string | number;
}

interface MCPResponse {
  jsonrpc: '2.0';
  result?: any;
  error?: MCPError;
  id?: string | number;
}

interface Tool {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, any>;
    required?: string[];
  };
}
```

### Customization: Add Your Tools

**Locate this section in the template:**

```typescript
function getToolDefinitions(): Tool[] {
  return [
    {
      name: 'echo',
      description: 'Echoes back the provided message',
      inputSchema: {
        type: 'object',
        properties: {
          message: { type: 'string', description: 'Message to echo' }
        },
        required: ['message']
      }
    },
    // ADD YOUR TOOLS HERE
  ];
}
```

**Add your tool with type safety:**

```typescript
// Define your tool's argument types
interface YourToolArgs {
  param1: string;
  param2?: number;
}

// Add to tool definitions
{
  name: 'your_tool_name',
  description: 'What your tool does',
  inputSchema: {
    type: 'object',
    properties: {
      param1: { type: 'string', description: 'Parameter description' },
      param2: { type: 'number', description: 'Optional parameter' }
    },
    required: ['param1']
  }
}

// Add typed execution function
async function executeYourTool(args: YourToolArgs): Promise<string> {
  // TypeScript will enforce param1 exists and is string
  const result = /* your logic here */;
  return result;
}
```

**Update the execution router:**

```typescript
async function executeTool(name: string, args: any): Promise<string> {
  switch (name) {
    case 'echo':
      return executeEcho(args);
    case 'your_tool_name':
      return executeYourTool(args as YourToolArgs);  // Type-safe cast
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}
```

---

## Phase 4: OAuth 2.1 Security Layer

**Template Coverage:** The template includes complete OAuth 2.1 + PKCE implementation with full type safety.

### What's Included in Template:
- OAuth metadata endpoints with typed responses
- Dynamic Client Registration (DCR) with type-safe validation
- Authorization endpoint with typed query parameters
- Token endpoint with typed grants
- Token revocation with typed requests
- JWT token creation with typed payloads
- PKCE utilities with type-safe validation

### Required Changes:

**None required** - OAuth implementation is production-ready with type safety.

### TypeScript Type Definitions:

The template includes OAuth-specific types:

```typescript
interface JWTPayload {
  iss: string;
  sub: string;
  client_id: string;
  jti: string;
  exp: number;
  iat: number;
  token_type?: 'refresh';
}

interface AuthorizationCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: 'S256';
  user_id: string;
  expires_at: number;
  used: boolean;
}

interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token: string;
  scope?: string;
}
```

### Type Safety Benefits:

**Compile-time validation:**
```typescript
// TypeScript catches this at compile time
const token: TokenResponse = {
  access_token: 'abc123',
  token_type: 'Bearer',
  expires_in: 3600
  // Error: Property 'refresh_token' is missing
};

// TypeScript enforces PKCE method
const authCode: AuthorizationCode = {
  code_challenge_method: 'plain'  // Error: Type '"plain"' is not assignable to type '"S256"'
};
```

---

## Phase 5: Production Hardening

**Template Coverage:** The template includes production hardening with type-safe implementations.

### What's Included in Template:
- Rate limiting with typed configurations
- Audit logging with typed log entries
- Global error handling with typed error responses
- Configuration validation with typed config object
- Health check with typed health status
- Graceful shutdown with typed cleanup

### Production Configuration Changes:

**Update `.env` for production:**

```bash
NODE_ENV=production
OAUTH_ISSUER=https://your-production-domain.com  # Must be HTTPS
REDIS_HOST=your-redis-host                        # Required for production
ALLOWED_ORIGINS=https://prod-instance.service-now.com
```

**Build for production:**
```bash
npm run build
```

This compiles TypeScript to JavaScript in `dist/` folder.

### TypeScript-Specific Production Setup:

**Type checking in CI/CD:**
```bash
npm run typecheck  # Validates types without emitting files
```

**Production start command:**
```bash
node dist/server.js  # Run compiled JavaScript
```

### Optional: Enhanced Type Safety

**Stricter TypeScript configuration for production:**

```json
{
  "compilerOptions": {
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true
  }
}
```

---

## Validation & Testing

### Build and Start Server

```bash
# Development mode (watch for changes)
npm run dev

# Production build and run
npm run build
npm start
```

**Expected output:**
```
✅ Configuration validated successfully
✅ Redis connected for token blacklist
✅ MCP Server listening on port 8080
📍 OAuth Issuer: http://localhost:8080
🔒 Environment: development
```

### Basic Validation

```bash
# Health check
curl http://localhost:8080/health
# Expected: {"status":"healthy",...}

# OAuth metadata
curl http://localhost:8080/.well-known/oauth-authorization-server
# Expected: OAuth server metadata JSON

# MCP initialize (no auth)
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}},"id":1}'
# Expected: Server capabilities
```

### Complete OAuth Flow Test

**For complete step-by-step OAuth 2.1 + PKCE flow testing:**

See [Master Deployment Guide - Complete OAuth Flow - Executable Commands](./README.md#complete-oauth-flow---executable-commands)

The master guide provides detailed curl commands with expected responses for all 10 steps of the OAuth flow, from DCR registration through token revocation validation.

---

## Troubleshooting

### TypeScript-Specific Issues

**"Cannot find module 'X' or its corresponding type declarations"**
- Install type definitions: `npm install --save-dev @types/X`
- Check `package.json` includes both package and @types package

**"Type 'X' is not assignable to type 'Y'"**
- Review type definitions in template
- Use type assertions carefully: `value as Type`
- Fix type mismatch rather than using `any`

**"Module not found" at runtime after compilation**
- Check `tsconfig.json` `moduleResolution` is set to `"node"`
- Ensure imports use `.js` extension for compiled files (not `.ts`)
- Verify `dist/` folder contains compiled files: `npm run build`

**"Cannot use import statement outside a module"**
- Ensure `package.json` has `"type": "module"`
- Check `tsconfig.json` has `"module": "ESNext"`
- Use `.mjs` extension or configure module system correctly

**ESM vs CommonJS issues**
- Template uses ESM (`import/export`) by default
- If mixing with CommonJS dependencies, may need `esModuleInterop: true`
- Consider using `"type": "module"` in package.json

### Development Issues

**"tsx: command not found" in dev mode**
- Install tsx: `npm install --save-dev tsx`
- Or use ts-node: `npm install --save-dev ts-node`

**Hot reload not working**
- Use `tsx watch server.ts` for development
- Or use `nodemon --exec tsx server.ts`

**TypeScript compilation errors**
- Run `npm run typecheck` to see all errors
- Fix errors before building for production
- Use `// @ts-ignore` sparingly (indicates type system issue)

### General Issues

See [Master Deployment Guide - Troubleshooting](./README.md#troubleshooting) for common OAuth and MCP protocol issues.

---

## Production Deployment

### Pre-Deployment Checklist

**TypeScript-specific:**
- [ ] `npm run typecheck` passes with no errors
- [ ] `npm run build` completes successfully
- [ ] `dist/` folder contains compiled JavaScript
- [ ] Production `.env` has unique JWT_SECRET
- [ ] `NODE_ENV=production` set
- [ ] Redis configured and accessible
- [ ] Process manager configured for `dist/server.js`

### Build Process

```bash
# Clean previous build
rm -rf dist/

# Type check
npm run typecheck

# Compile TypeScript
npm run build

# Verify compilation
ls -la dist/
```

**Deploy only compiled files:**
- Copy `dist/` folder to production server
- Copy `node_modules/` (or run `npm install --production`)
- Copy `.env` file (with production values)
- **Do not deploy** `.ts` files or `src/` folder

### Example PM2 Configuration

**`ecosystem.config.cjs`:**
```javascript
module.exports = {
  apps: [{
    name: 'mcp-server',
    script: './dist/server.js',  // Run compiled JavaScript
    instances: 1,
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production'
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z'
  }]
};
```

Start with: `pm2 start ecosystem.config.cjs`

### Docker Deployment

**Example `Dockerfile`:**
```dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm install

# Copy source
COPY server.ts ./

# Build TypeScript
RUN npm run build

# Remove dev dependencies
RUN npm prune --production

# Expose port
EXPOSE 8080

# Run compiled JavaScript
CMD ["node", "dist/server.js"]
```

Build and run:
```bash
docker build -t mcp-server .
docker run -p 8080:8080 --env-file .env mcp-server
```

---

## Next Steps

**For ServiceNow Integration:**
- Share DCR_AUTH_TOKEN with ServiceNow team (secure channel)
- Provide server URL: `https://your-domain.com`
- Follow [ServiceNow Connection Configuration](../docs/MCP%20Server%20Implementation%20-%20Part%205%20Appendices.md#appendix-d-servicenow-connection-configuration)

**For Custom Tools:**
- Define typed interfaces for tool arguments
- Add type-safe tool definitions to `getToolDefinitions()`
- Implement typed execution functions
- TypeScript will validate types at compile time

**For Type Safety:**
- Review template type definitions
- Add custom types for your business logic
- Use `npm run typecheck` in CI/CD pipeline
- Consider stricter TypeScript compiler options

---

## Reference Documentation

**Master Guide:**
- [Master Deployment Guide](./README.md) - Complete deployment workflow and concepts

**Detailed Implementation:**
- [Part 1: Overview](../docs/MCP%20Server%20Implementation%20-%20Part%201%20Overview.md) - Requirements and scope
- [Part 2: Core Infrastructure](../docs/MCP%20Server%20Implementation%20-%20Part%202%20Core%20Infrastructure.md) - Infrastructure details
- [Part 3: Protocol and Tools](../docs/MCP%20Server%20Implementation%20-%20Part%203%20Protocol%20and%20Tools.md) - Protocol implementation
- [Part 4: OAuth](../docs/MCP%20Server%20Implementation%20-%20Part%204%20OAuth.md) - OAuth 2.1 security details
- [Part 5: Appendices](../docs/MCP%20Server%20Implementation%20-%20Part%205%20Appendices.md) - Storage options and production checklist

**Template:**
- `../templates/mcp-server-typescript-template.ts` - Complete reference implementation

**TypeScript Resources:**
- [TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/intro.html)
- [Express TypeScript Guide](https://expressjs.com/en/starter/installing.html)

---

**Version:** 1.0  
**Last Updated:** February 2026

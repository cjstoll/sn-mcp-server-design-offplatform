# MCP Server Deployment Guide - JavaScript/Node.js

**Language-specific deployment guide for JavaScript/Node.js implementations**

---

## Overview

This guide provides JavaScript/Node.js specific instructions for deploying your MCP server using the provided template file. 

**Prerequisites:**
- Reviewed the [Master Deployment Guide](./README.md)
- Node.js 18.x or higher installed
- Template file: [`mcp-server-javascript-template.js`](../templates/mcp-server-javascript-template.js)

**Approach:** Start with the template file and modify as needed. This guide only covers JavaScript-specific setup and deviations from the template.

---

## Phase 1: Environment Setup

### 1.1 Generate Security Credentials

**JavaScript-specific method using Node.js crypto:**

```javascript
// generate-secrets.js
const crypto = require('crypto');

console.log('JWT_SECRET=' + crypto.randomBytes(32).toString('base64'));
console.log('DCR_AUTH_TOKEN=' + crypto.randomBytes(32).toString('hex'));
```

Run: `node generate-secrets.js`

**Alternative:** Use OpenSSL commands from Master Deployment Guide.

### 1.2 Install Dependencies

**Create `package.json`:**

```json
{
  "name": "mcp-server-servicenow",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
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
  "engines": {
    "node": ">=18.0.0"
  }
}
```

**Install:**
```bash
npm install
```

### 1.3 Configure Environment Variables

**Create `.env` file with JavaScript-specific values:**

```bash
# Server Configuration
PORT=8080
NODE_ENV=development

# OAuth 2.1 Configuration (use generated secrets from step 1.1)
JWT_SECRET=your-generated-jwt-secret-minimum-32-chars
OAUTH_ISSUER=http://localhost:8080
DCR_AUTH_TOKEN=your-generated-dcr-token

# Token Lifetimes (seconds)
ACCESS_TOKEN_LIFETIME=3600
REFRESH_TOKEN_LIFETIME=2592000
AUTHORIZATION_CODE_LIFETIME=600

# Storage Configuration
CLIENT_STORAGE_PATH=./data/registered_clients.json

# Redis Configuration (optional but recommended)
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

**Important:** Add `.env` to `.gitignore`:
```
.env
node_modules/
data/
*.log
```

### 1.4 Project Structure

The template file is monolithic. For production, consider splitting into modules:

```
your-mcp-server/
├── server.js                    # Main entry (from template)
├── package.json
├── .env
├── .gitignore
└── data/
    └── registered_clients.json  # Created automatically
```

**Optional modular structure** (if refactoring template):
```
├── src/
│   ├── config/environment.js
│   ├── middleware/
│   ├── oauth/
│   ├── mcp/
│   └── storage/
```

---

## Phase 2: Server Foundation

**Template Coverage:** The template file includes complete server foundation implementation.

### What's Included in Template:
- HTTP server initialization with Express
- Configuration validation on startup
- Middleware stack (CORS, body parsing, rate limiting)
- Storage initialization (file-based + Redis fallback)
- Health check endpoint
- Graceful shutdown handlers

### Required Changes:

**None required** - the template works as-is with your `.env` configuration.

### Optional Enhancements:

**If you need database storage instead of file-based:**

Replace the `initializeClientStorage()` function:

```javascript
// PostgreSQL example
const { Pool } = require('pg');

async function initializeClientStorage() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  
  return {
    async get(clientId) {
      const result = await pool.query('SELECT * FROM oauth_clients WHERE client_id = $1', [clientId]);
      return result.rows[0] || null;
    },
    async save(clientId, clientData) {
      await pool.query(
        'INSERT INTO oauth_clients (client_id, data) VALUES ($1, $2) ON CONFLICT (client_id) DO UPDATE SET data = $2',
        [clientId, JSON.stringify(clientData)]
      );
    }
  };
}
```

**If Redis connection fails**, the template automatically falls back to in-memory storage with a warning.

---

## Phase 3: MCP Protocol Implementation

**Template Coverage:** The template includes complete MCP protocol implementation.

### What's Included in Template:
- `/mcp` endpoint with conditional authentication
- `initialize` handler
- `notifications/initialized` handler
- `tools/list` handler with example tools
- `tools/call` handler with routing
- Authentication middleware

### Required Changes:

**None required** - basic MCP protocol works out of the box.

### Customization: Add Your Tools

**Locate this section in the template:**

```javascript
function getToolDefinitions() {
  return [
    {
      name: 'echo',
      description: 'Echoes back the provided message',
      inputSchema: { /* ... */ }
    },
    // ADD YOUR TOOLS HERE
  ];
}
```

**Add your tool definition:**

```javascript
{
  name: 'your_tool_name',
  description: 'What your tool does',
  inputSchema: {
    type: 'object',
    properties: {
      param1: { type: 'string', description: 'Parameter description' }
    },
    required: ['param1']
  }
}
```

**Locate this section in the template:**

```javascript
async function executeTool(name, args) {
  switch (name) {
    case 'echo':
      return executeEcho(args);
    // ADD YOUR TOOL EXECUTION HERE
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}
```

**Add your tool execution:**

```javascript
case 'your_tool_name':
  return executeYourTool(args);

// Add implementation function
function executeYourTool(args) {
  // Validate inputs
  if (!args.param1) {
    throw new Error('Missing required parameter: param1');
  }
  
  // Implement tool logic
  const result = /* your logic here */;
  
  return result;
}
```

---

## Phase 4: OAuth 2.1 Security Layer

**Template Coverage:** The template includes complete OAuth 2.1 + PKCE implementation.

### What's Included in Template:
- OAuth metadata endpoints (RFC 8414, RFC 8693)
- Dynamic Client Registration (DCR) endpoint
- Authorization endpoint with PKCE validation
- Token endpoint (authorization code + refresh token grants)
- Token revocation endpoint
- JWT token creation and validation
- PKCE utilities (S256 challenge verification)

### Required Changes:

**None required** - OAuth implementation is production-ready.

### Important Notes:

**DCR Protection:** The template requires `DCR_AUTH_TOKEN` in Authorization header. Share this token securely with ServiceNow administrators:

```bash
# ServiceNow will call:
curl -X POST https://your-server.com/oauth/register \
  -H "Authorization: Bearer YOUR_DCR_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"ServiceNow","redirect_uris":["https://instance.service-now.com/callback"]}'
```

**M2M Authentication:** The template uses simulated user authentication:

```javascript
// In authorization endpoint
const userId = `service_account_${crypto.randomBytes(8).toString('hex')}`;
```

This is correct for ServiceNow M2M integration. ServiceNow handles user authentication; your server authenticates ServiceNow as a client.

**Token Rotation:** The template implements refresh token rotation for security. Old refresh tokens are automatically revoked when new ones are issued.

---

## Phase 5: Production Hardening

**Template Coverage:** The template includes production hardening features.

### What's Included in Template:
- Rate limiting on all endpoint groups
- Audit logging (OAuth events, MCP calls, security events)
- Global error handling
- Configuration validation
- Health check with service status
- Graceful shutdown

### Production Configuration Changes:

**Update `.env` for production:**

```bash
NODE_ENV=production
OAUTH_ISSUER=https://your-production-domain.com  # Must be HTTPS
REDIS_HOST=your-redis-host                        # Required for production
ALLOWED_ORIGINS=https://prod-instance.service-now.com
```

**The template will enforce:**
- HTTPS required (OAUTH_ISSUER must start with `https://`)
- Redis required (will fail without REDIS_HOST in production)
- Generic error messages (no stack traces exposed)

### Optional: Structured Logging

**If you want JSON logs for log aggregation**, modify the logger:

```javascript
// Replace console.log statements with:
function log(level, message, meta = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...meta
  };
  console.log(JSON.stringify(entry));
}
```

### Optional: Custom Rate Limits

**If you need different rate limits**, update these lines in template:

```javascript
const oauthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // Change window
  max: 100,                   // Change max requests
  // ...
});
```

---

## Validation & Testing

### Start Server

```bash
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

- Check `package.json` includes the required package

**"JWT_SECRET must be at least 32 characters"**
- Regenerate using `node generate-secrets.js`
- Check `.env` file JWT_SECRET value

**"Redis connection failed, falling back to in-memory"**
- Verify Redis is running: `redis-cli ping`
- Check REDIS_HOST and REDIS_PORT in `.env`
- Template will continue with in-memory fallback (warning only)

**"Port 8080 already in use"**
- Change PORT in `.env` to available port
- Or stop process using port: `lsof -ti:8080 | xargs kill`

**"Not allowed by CORS"**
- Add origin to ALLOWED_ORIGINS in `.env` (comma-separated)
- Restart server after changing `.env`

### General Issues

See [Master Deployment Guide - Troubleshooting](./README.md#troubleshooting) for common OAuth and MCP protocol issues.

---

## Production Deployment

### Pre-Deployment Checklist

**JavaScript-specific:**
- [ ] `NODE_ENV=production` set in production `.env`
- [ ] Production `.env` has unique JWT_SECRET (not copied from dev)
- [ ] Redis configured and accessible
- [ ] `node_modules/` installed with `npm install --production`
- [ ] Process manager configured (PM2, systemd, etc.)

**Example PM2 configuration (`ecosystem.config.js`):**
```javascript
module.exports = {
  apps: [{
    name: 'mcp-server',
    script: 'server.js',
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

Start with: `pm2 start ecosystem.config.js`

### Deployment Steps

1. Copy files to production server
2. Run `npm install --production`
3. Create production `.env` file
4. Start with process manager: `pm2 start server.js`
5. Verify health: `curl https://your-domain.com/health`
6. Test OAuth flow
7. Configure ServiceNow connection

---

## Next Steps

**For ServiceNow Integration:**
- Share DCR_AUTH_TOKEN with ServiceNow team (secure channel)
- Provide server URL: `https://your-domain.com`
- Follow [ServiceNow Connection Configuration](../docs/MCP%20Server%20Implementation%20-%20Part%205%20Appendices.md#appendix-d-servicenow-connection-configuration)

**For Custom Tools:**
- Add tool definitions to `getToolDefinitions()` in template
- Implement tool execution functions
- Test with `tools/call` before ServiceNow integration

**For Monitoring:**
- Configure log aggregation (Winston, Bunyan, or ELK stack)
- Set up health check monitoring (UptimeRobot, Pingdom)
- Configure alerts for errors and rate limiting

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
- `../templates/mcp-server-javascript-template.js` - Complete reference implementation

---

**Version:** 1.0  
**Last Updated:** February 2026

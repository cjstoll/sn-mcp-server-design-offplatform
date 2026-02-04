# MCP Server Deployment Guide

**Quick-start deployment guide for ServiceNow MCP Server practitioners**

---

## Overview

This guide gets your MCP server deployed and running. For architecture details and implementation guidance, see the [main documentation](./mcp-guide-01-introduction.md).

**Time Estimate:** 2-4 hours  
**Prerequisites:** Familiarity with your chosen language, basic OAuth 2.1 understanding

---

## Language Selection

Choose your implementation path:

| Language | Template File | Deployment Guide |
|----------|--------------|------------------|
| JavaScript | `templates/mcp-server-javascript-template.js` | [JavaScript Guide](./deployment/DEPLOYMENT_GUIDE_JAVASCRIPT.md) |
| TypeScript | `templates/mcp-server-typescript-template.ts` | [TypeScript Guide](./deployment/DEPLOYMENT_GUIDE_TYPESCRIPT.md) |
| Python | `templates/mcp-server-python-template.py` | [Python Guide](./deployment/DEPLOYMENT_GUIDE_PYTHON.md) |
| Other | See [Language Hints](./language-implementation-hints.md) | Adapt from pseudocode |

---

## Quick Start

### 1. Generate Secrets

```bash
# JWT secret (minimum 32 characters)
openssl rand -base64 32

# DCR authorization token
openssl rand -hex 32
```

Save these - you'll need them in your `.env` file.

---

### 2. Set Up Environment

Copy your chosen template and create `.env`:

```bash
# Required
PORT=8080
JWT_SECRET=<your-generated-jwt-secret>
OAUTH_ISSUER=https://your-domain.com
DCR_AUTH_TOKEN=<your-generated-dcr-token>

# Storage (choose one approach)
# Option A: File-based (single server)
CLIENT_STORAGE_PATH=./data/registered_clients.json

# Option B: Redis token blacklist (recommended for production)
REDIS_HOST=localhost
REDIS_PORT=6379

# ServiceNow integration
ALLOWED_ORIGINS=https://your-instance.service-now.com
```

---

### 3. Install Dependencies

**JavaScript/TypeScript:**
```bash
npm install express express-rate-limit cors jsonwebtoken bcrypt uuid
# Optional: redis for token blacklist
npm install redis
```

**Python:**
```bash
pip install fastapi uvicorn pyjwt bcrypt redis python-multipart
```

---

### 4. Configure Storage

**Single Server (File-based):**
- Client storage: File (already configured in template)
- Token blacklist: Redis or in-memory

**Multi-Server (Shared):**
- Client storage: PostgreSQL, MongoDB, or Firestore
- Token blacklist: Redis (required)

See [Storage Options](./mcp-guide-05-appendices.md#appendix-b-alternative-storage-implementations) for implementation details.

---

### 5. Start Server

```bash
# JavaScript/TypeScript
node server.js
# or
npm start

# Python
python server.py
# or
uvicorn server:app --host 0.0.0.0 --port 8080
```

**Verify:**
```bash
curl http://localhost:8080/health
# Expected: {"status":"healthy",...}
```

---

### 6. Test OAuth Flow

**Register test client:**
```bash
curl -X POST http://localhost:8080/oauth/register \
  -H "Authorization: Bearer <DCR_AUTH_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Client",
    "redirect_uris": ["http://localhost:3000/callback"]
  }'
```

Save the `client_id` and `client_secret` from the response.

**Test MCP endpoint:**
```bash
# Initialize (no auth required)
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
    "id": 1
  }'
```

For full OAuth flow testing, see [Validation Section](#validation-checklist) below.

---

## Production Configuration

### Required Changes for Production

1. **HTTPS:** Set `OAUTH_ISSUER=https://your-production-domain.com`
2. **Redis:** Configure Redis for token blacklist (required for persistence)
3. **Storage:** Use database if multi-server deployment
4. **Secrets:** Use environment-specific secrets (never reuse dev secrets)

### Environment Variables

```bash
NODE_ENV=production
PORT=8080
JWT_SECRET=<production-secret>
OAUTH_ISSUER=https://your-domain.com
DCR_AUTH_TOKEN=<production-dcr-token>
REDIS_HOST=<redis-host>
REDIS_PORT=6379
REDIS_PASSWORD=<if-required>
ALLOWED_ORIGINS=https://prod-instance.service-now.com
```

---

## Validation Checklist

### Basic Validation

- [ ] Server starts without errors
- [ ] `/health` endpoint returns healthy status
- [ ] `/.well-known/oauth-authorization-server` returns metadata
- [ ] MCP `initialize` method works (no auth)
- [ ] MCP `tools/list` requires authentication (401 without token)

### OAuth Flow Validation

- [ ] DCR creates client successfully
- [ ] Authorization endpoint generates code with PKCE
- [ ] Token endpoint exchanges code for tokens
- [ ] Access token works with MCP endpoints
- [ ] Refresh token grant issues new tokens
- [ ] Old refresh token is revoked (token rotation)
- [ ] Revoked tokens cannot be used

### Production Validation

- [ ] HTTPS configured (required)
- [ ] Redis connected (persistent token blacklist)
- [ ] Rate limiting enforced on all endpoints
- [ ] CORS allows ServiceNow origin
- [ ] Audit logging tracks OAuth and MCP events
- [ ] Health check validates all services

---

## Common Issues

**"Configuration validation failed"**
- Check JWT_SECRET is minimum 32 characters
- Verify all required environment variables are set

**"Redis connection failed"**
- Confirm Redis is running: `redis-cli ping`
- Check REDIS_HOST and REDIS_PORT in `.env`
- Server will fall back to in-memory (not recommended for production)

**"Invalid token" errors**
- Verify JWT_SECRET matches between token creation and validation
- Check token hasn't expired
- Confirm token isn't in revocation blacklist

**Rate limiting triggered**
- Normal ServiceNow usage is well below limits
- Check for misconfigured polling or loops
- Review audit logs for unusual activity

---

## Next Steps

**For ServiceNow Integration:**
1. Deploy your MCP server with HTTPS
2. Note your DCR_AUTH_TOKEN (share securely with ServiceNow admin)
3. Provide MCP server URL to ServiceNow administrator
4. Follow [ServiceNow Connection Configuration](./mcp-guide-05-appendices.md#appendix-d-servicenow-connection-configuration)

**For Custom Tools:**
1. Add tool definitions to `tools/list` handler
2. Implement tool logic in `tools/call` handler
3. Follow JSON Schema specification for `inputSchema`
4. Test tools before ServiceNow integration

**For Production Deployment:**
1. Review [Production Deployment Checklist](./mcp-guide-05-appendices.md#appendix-c-production-deployment-checklist)
2. Set up monitoring and alerting
3. Configure backup procedures
4. Document rollback plan

---

## Reference Documentation

- [Part 1: Introduction](./mcp-guide-01-introduction.md) - Requirements and scope
- [Part 2: Server Foundation](./mcp-guide-02-server-foundation.md) - Infrastructure details
- [Part 3: MCP Protocol & Tools](./mcp-guide-03-mcp-protocol-tools.md) - Protocol implementation
- [Part 4: OAuth Implementation](./mcp-guide-04-oauth-implementation.md) - Security layer details
- [Part 5: Appendices](./mcp-guide-05-appendices.md) - Storage options, deployment checklist, ServiceNow config

---

**Version:** 1.0  
**Last Updated:** February 2026

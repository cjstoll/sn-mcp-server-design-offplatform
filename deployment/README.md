# MCP Server Deployment Guide

**Practical deployment guide for ServiceNow MCP Server practitioners**

---

## Overview

This guide walks you through deploying a production-ready MCP server with OAuth 2.1 + PKCE authentication. It provides the deployment workflow and decision points, with language-specific implementation details in separate guides.

**Time Estimate:** 4-6 hours for complete deployment  
**Prerequisites:** Familiarity with your chosen language, basic OAuth 2.1 understanding, server administration experience

**What You'll Deploy:**
- MCP server with OAuth 2.1 + PKCE authentication
- Persistent storage for OAuth clients and token management
- Production security (rate limiting, audit logging, error handling)
- Health monitoring and graceful shutdown

---

## Language Selection

Choose your implementation path based on your environment and expertise:

| Language | Template File | Best For | Deployment Guide |
|----------|--------------|----------|------------------|
| **JavaScript** | `templates/mcp-server-javascript-template.js` | Node.js environments, rapid prototyping, local VM deployment | [JavaScript Guide](./deployment/DEPLOYMENT_GUIDE_JAVASCRIPT.md) |
| **TypeScript** | `templates/mcp-server-typescript-template.ts` | Type-safe production systems, cloud deployments | [TypeScript Guide](./deployment/DEPLOYMENT_GUIDE_TYPESCRIPT.md) |
| **Python** | `templates/mcp-server-python-template.py` | Python toolchains, FastAPI/Flask familiarity | [Python Guide](./deployment/DEPLOYMENT_GUIDE_PYTHON.md) |
| **Other** | See [Language Hints](./language-implementation-hints.md) | Go, Java, C#, Rust | Adapt from [Pseudocode Template](./mcp-server-pseudocode-template.md) |

---

## Deployment Workflow

### Phase 1: Environment Setup

**Purpose:** Prepare your development environment and generate the security credentials that will protect your OAuth implementation.

**1.1 Generate Security Credentials**

Generate cryptographically secure secrets for your deployment. These secrets are the foundation of your server's security - JWT_SECRET signs all tokens, and DCR_AUTH_TOKEN protects client registration.

```pseudocode
GENERATE JWT_SECRET (minimum 32 characters):
  USE system crypto library to generate random bytes
  ENCODE as base64 or hex
  STORE securely in environment configuration

GENERATE DCR_AUTH_TOKEN (minimum 32 characters):
  USE system crypto library to generate random bytes
  ENCODE as hex
  STORE securely in environment configuration
  SHARE with ServiceNow administrators via secure channel
```

**1.2 Configure Environment Variables**

Create environment configuration file with these required settings. This configuration tells your server how to authenticate requests, where to store data, and which ServiceNow instances to trust.

```pseudocode
REQUIRED CONFIGURATION:
  PORT = 8080 (or your preferred port)
  JWT_SECRET = <generated-secret-from-step-1.1>
  OAUTH_ISSUER = https://your-domain.com (use http://localhost:PORT for development)
  DCR_AUTH_TOKEN = <generated-token-from-step-1.1>
  
STORAGE CONFIGURATION (choose based on deployment model):
  IF single-server deployment THEN
    CLIENT_STORAGE_TYPE = "file"
    CLIENT_STORAGE_PATH = ./data/registered_clients.json
  ELSE IF multi-server deployment THEN
    CLIENT_STORAGE_TYPE = "database"
    DATABASE_URL = <postgresql-or-mongodb-connection-string>
  END IF
  
TOKEN BLACKLIST (choose based on production requirements):
  IF production OR multi-server THEN
    REDIS_HOST = localhost (or remote Redis host)
    REDIS_PORT = 6379
    REDIS_PASSWORD = <if-required>
  ELSE
    USE_IN_MEMORY_BLACKLIST = true (development only)
  END IF

CORS CONFIGURATION:
  ALLOWED_ORIGINS = https://your-instance.service-now.com
  
OPTIONAL:
  ACCESS_TOKEN_LIFETIME = 3600 (1 hour, in seconds)
  REFRESH_TOKEN_LIFETIME = 2592000 (30 days, in seconds)
  AUTHORIZATION_CODE_LIFETIME = 600 (10 minutes, in seconds)
```

**1.3 Set Up Infrastructure Dependencies**

Install and configure the external services your MCP server needs. Redis provides persistent token revocation storage, and databases enable multi-server deployments.

```pseudocode
INSTALL language runtime (Node.js 18+, Python 3.9+, etc.)

IF using Redis for token blacklist THEN
  INSTALL Redis server
  START Redis service
  VERIFY connection: redis-cli ping (should return PONG)
END IF

IF using database for client storage THEN
  INSTALL database server (PostgreSQL, MongoDB, etc.)
  CREATE database and tables/collections
  VERIFY connection and permissions
END IF

OPTIONAL: Set up reverse proxy (nginx, Apache) for HTTPS termination
```

---

### Phase 2: Server Foundation

**Purpose:** Build the HTTP server infrastructure that handles requests, validates configuration, and manages connections. This is the foundation everything else builds on.

**2.1 Initialize HTTP Server**

Create the HTTP server and configure basic request handling. Configuration validation prevents insecure deployments by failing fast if critical settings are missing or wrong.

```pseudocode
LOAD environment configuration
VALIDATE configuration (fail-fast if misconfigured):
  CHECK JWT_SECRET minimum length (32 characters)
  CHECK required variables present
  IF production THEN
    REQUIRE HTTPS (OAUTH_ISSUER must start with https://)
    FORBID in-memory storage
  END IF

CREATE HTTP server framework
SET request body size limit (10MB for DOS protection)
CONFIGURE server port from environment

ADD health check endpoint (no authentication):
  ENDPOINT: GET /health
  RETURN: server status, timestamp, service health checks
```

**2.2 Configure Middleware Stack**

Set up the request processing pipeline that handles logging, CORS, rate limiting, and errors. Middleware order matters - each layer processes the request before passing it to the next.

```pseudocode
MIDDLEWARE STACK (apply in this order):

1. REQUEST LOGGING:
   LOG timestamp, HTTP method, path, client identifier
   
2. CORS MIDDLEWARE:
   CHECK Origin header against ALLOWED_ORIGINS
   IF origin allowed THEN
     SET Access-Control-Allow-Origin header
     SET Access-Control-Allow-Methods: GET, POST, OPTIONS
     SET Access-Control-Allow-Headers: Content-Type, Authorization
   END IF
   
3. BODY PARSER:
   PARSE JSON request bodies
   ENFORCE size limit (10MB maximum)
   
4. RATE LIMITING (configure per endpoint group):
   OAuth endpoints: 100 requests per 15 minutes
   MCP endpoint: 60 requests per minute
   Health check: 30 requests per minute
   
5. ERROR HANDLER (global):
   CATCH all unhandled errors
   LOG error details for debugging
   IF production THEN
     RETURN generic error message (don't leak internals)
   ELSE
     RETURN detailed error for development
   END IF
```

**2.3 Initialize Storage Layer**

Connect to storage systems for OAuth clients, token blacklist, and authorization codes. Storage choices here determine whether your deployment can scale horizontally and survive restarts.

```pseudocode
INITIALIZE CLIENT STORAGE:
  IF storage_type == "file" THEN
    ENSURE data directory exists
    CREATE file-based storage manager
  ELSE IF storage_type == "database" THEN
    CONNECT to database
    VERIFY schema/collections exist
    CREATE database storage manager
  END IF

INITIALIZE TOKEN BLACKLIST:
  IF Redis configured THEN
    CONNECT to Redis
    TEST connection with PING
    CREATE Redis blacklist manager
  ELSE
    CREATE in-memory blacklist manager
    LOG warning if production environment
  END IF

INITIALIZE AUTHORIZATION CODE STORAGE:
  CREATE in-memory storage (short-lived, acceptable for production)
  SET automatic expiration cleanup

SETUP GRACEFUL SHUTDOWN:
  ON termination signal (SIGTERM, SIGINT):
    STOP accepting new connections
    WAIT for active requests to complete (timeout: 30 seconds)
    CLOSE storage connections (Redis, database)
    EXIT cleanly
```

---

### Phase 3: MCP Protocol Implementation

**Purpose:** Implement the MCP protocol layer that ServiceNow will communicate with. This is what makes your server an "MCP server" - the protocol handlers and tool implementations.

**3.1 Configure MCP Endpoint**

Set up the single `/mcp` endpoint that handles all MCP protocol methods. The conditional authentication allows the `initialize` handshake to work without a token while protecting all other methods.

```pseudocode
ENDPOINT: POST /mcp
AUTHENTICATION: Required for all methods except "initialize"

MIDDLEWARE:
  IF request.method != "initialize" THEN
    REQUIRE Bearer token in Authorization header
    VALIDATE JWT token:
      VERIFY signature with JWT_SECRET
      CHECK expiration (not expired)
      CHECK revocation (not in blacklist)
    EXTRACT client_id and user_id from token
    ATTACH to request context
  END IF

HANDLER:
  PARSE JSON-RPC request
  VALIDATE jsonrpc version (must be "2.0")
  ROUTE based on method:
    "initialize" → handle_initialize()
    "notifications/initialized" → handle_initialized()
    "tools/list" → handle_tools_list()
    "tools/call" → handle_tools_call()
    OTHER → return JSON-RPC error -32601 (method not found)
```

**3.2 Implement MCP Handlers**

Implement the four core MCP protocol methods that ServiceNow expects. These handlers manage the connection lifecycle and tool discovery.

```pseudocode
FUNCTION handle_initialize(params):
  VALIDATE protocol version (support "2025-06-18")
  RETURN server capabilities:
    protocolVersion: "2025-06-18"
    capabilities:
      tools: {listChanged: false}
    serverInfo:
      name: "Your MCP Server"
      version: "1.0.0"

FUNCTION handle_initialized(params):
  LOG "Client initialization complete"
  RETURN empty response (notification, no response required)

FUNCTION handle_tools_list(params):
  BUILD array of tool definitions:
    FOR EACH tool THEN
      name: tool identifier
      description: what the tool does
      inputSchema: JSON Schema defining parameters
        type: "object"
        properties: {parameter definitions}
        required: [required parameter names]
  RETURN {tools: tool_array}

FUNCTION handle_tools_call(params):
  tool_name = params.name
  tool_arguments = params.arguments
  
  ROUTE to tool implementation based on tool_name
  EXECUTE tool with provided arguments
  LOG tool execution (client_id, user_id, tool_name, timestamp)
  
  RETURN result:
    content: [
      {type: "text", text: execution_result}
    ]
```

**3.3 Implement Custom Tools**

Create the actual tools that perform work for ServiceNow AI agents. Tools are where your server's business logic lives - everything from simple utilities to complex integrations.

```pseudocode
DEFINE your custom tools following this pattern:

FUNCTION execute_your_tool(arguments):
  VALIDATE required arguments present
  SANITIZE inputs (prevent injection attacks)
  PERFORM tool logic
  HANDLE errors gracefully
  RETURN result as string
  
BEST PRACTICES:
  - Keep tools focused (single responsibility)
  - Validate all inputs against inputSchema
  - Log tool execution for audit trail
  - Handle errors without exposing internal details
  - Return structured, parseable results
```

---

### Phase 4: OAuth 2.1 Security Layer

**Purpose:** Implement the OAuth 2.1 authorization server that authenticates ServiceNow as a trusted client. This is the "roof" that protects everything - without proper OAuth, your tools are exposed.

**4.1 Implement OAuth Metadata Endpoints**

Publish OAuth server metadata so ServiceNow can discover your endpoints automatically. These endpoints are like a map telling ServiceNow how to authenticate with your server.

```pseudocode
ENDPOINT: GET /.well-known/oauth-authorization-server
NO AUTHENTICATION REQUIRED

RETURN RFC 8414 metadata:
  issuer: OAUTH_ISSUER
  authorization_endpoint: OAUTH_ISSUER + /oauth/authorize
  token_endpoint: OAUTH_ISSUER + /oauth/token
  revocation_endpoint: OAUTH_ISSUER + /oauth/revoke
  registration_endpoint: OAUTH_ISSUER + /oauth/register
  token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"]
  grant_types_supported: ["authorization_code", "refresh_token"]
  response_types_supported: ["code"]
  code_challenge_methods_supported: ["S256"]

ENDPOINT: GET /.well-known/oauth-protected-resource
NO AUTHENTICATION REQUIRED

RETURN RFC 8693 metadata:
  resource: OAUTH_ISSUER
  authorization_servers: [OAUTH_ISSUER]
  bearer_methods_supported: ["header"]
  resource_signing_alg_values_supported: ["HS256"]
```

**4.2 Implement Dynamic Client Registration (DCR)**

Enable ServiceNow to register itself as an OAuth client automatically. DCR eliminates manual credential sharing and enables self-service onboarding - critical for production deployments.

```pseudocode
ENDPOINT: POST /oauth/register
AUTHENTICATION: Require DCR_AUTH_TOKEN in Authorization header
RATE LIMIT: 100 requests per 15 minutes

HANDLER:
  VALIDATE Authorization header:
    EXTRACT Bearer token
    COMPARE with DCR_AUTH_TOKEN
    REJECT if mismatch
  
  VALIDATE request body:
    REQUIRE redirect_uris (at least one)
    OPTIONAL: client_name, grant_types, response_types
  
  GENERATE client credentials:
    client_id = GENERATE_UNIQUE_ID()
    client_secret = GENERATE_SECURE_TOKEN(32)
    client_secret_hash = HASH(client_secret) using bcrypt/argon2
  
  STORE client:
    client_id: generated_id
    client_secret_hash: hashed_secret
    client_name: from request or default
    redirect_uris: from request
    grant_types: ["authorization_code", "refresh_token"]
    response_types: ["code"]
    created_at: current_timestamp
  
  LOG: "Client registered via DCR: {client_id}"
  
  RETURN RFC 7591 response:
    client_id
    client_secret (plaintext - only time visible)
    client_name
    redirect_uris
    grant_types
    response_types
```

**4.3 Implement Authorization Endpoint**

Handle the first step of the OAuth flow where ServiceNow requests permission to access your MCP server. PKCE validation here prevents authorization code interception attacks.

```pseudocode
ENDPOINT: GET /oauth/authorize
RATE LIMIT: 100 requests per 15 minutes

HANDLER:
  EXTRACT query parameters:
    client_id, redirect_uri, response_type, scope, state
    code_challenge, code_challenge_method
  
  VALIDATE required parameters:
    REQUIRE client_id, redirect_uri, response_type
    REQUIRE code_challenge, code_challenge_method (PKCE mandatory)
  
  VALIDATE PKCE:
    REQUIRE code_challenge_method == "S256"
    REJECT if not S256
  
  VALIDATE client:
    LOOKUP client by client_id
    REJECT if not found
    VERIFY redirect_uri in client.redirect_uris
    REJECT if mismatch
  
  USER AUTHENTICATION (M2M pattern):
    In production: display login page or SSO
    For M2M/service-to-service: auto-approve
    GENERATE simulated user_id = "service_account_" + RANDOM()
  
  GENERATE authorization code:
    code = GENERATE_SECURE_TOKEN(32)
    STORE authorization code:
      code: generated_code
      client_id: from request
      redirect_uri: from request
      scope: from request
      code_challenge: from request
      code_challenge_method: from request
      user_id: simulated_user_id
      expires_at: current_time + CODE_LIFETIME
      used: false
  
  REDIRECT to callback:
    URL: redirect_uri + "?code=" + code
    IF state present THEN append "&state=" + state
```

**4.4 Implement Token Endpoint**

Exchange authorization codes for access tokens and refresh expired tokens. This is where the OAuth flow completes and ServiceNow gets credentials to call your MCP endpoints.

```pseudocode
ENDPOINT: POST /oauth/token
RATE LIMIT: 100 requests per 15 minutes

HANDLER:
  AUTHENTICATE client:
    IF Authorization header present (client_secret_basic) THEN
      DECODE Base64(header value)
      EXTRACT client_id, client_secret
    ELSE (client_secret_post)
      EXTRACT client_id, client_secret from body
    END IF
    
    LOOKUP client by client_id
    VERIFY client_secret against stored hash
    REJECT if authentication fails
  
  ROUTE by grant_type:
    "authorization_code" → handle_authorization_code_grant()
    "refresh_token" → handle_refresh_token_grant()
    OTHER → reject with unsupported_grant_type

FUNCTION handle_authorization_code_grant(request, client):
  EXTRACT: code, redirect_uri, code_verifier
  REQUIRE all parameters present
  
  RETRIEVE authorization code from storage
  VALIDATE:
    Code exists and not expired
    Code not already used
    Code issued to authenticated client
    redirect_uri matches stored value
  
  VALIDATE PKCE:
    COMPUTE challenge = Base64URL(SHA256(code_verifier))
    COMPARE with stored code_challenge
    REJECT if mismatch
  
  MARK code as used
  
  GENERATE tokens:
    access_token = CREATE_JWT_TOKEN(
      client_id, user_id, scope,
      expires_in: ACCESS_TOKEN_LIFETIME
    )
    refresh_token = CREATE_JWT_TOKEN(
      client_id, user_id, scope,
      expires_in: REFRESH_TOKEN_LIFETIME,
      token_type: "refresh"
    )
  
  RETURN:
    access_token
    token_type: "Bearer"
    expires_in: ACCESS_TOKEN_LIFETIME
    refresh_token
    scope

FUNCTION handle_refresh_token_grant(request, client):
  EXTRACT refresh_token from request
  
  VALIDATE refresh token:
    VERIFY JWT signature with JWT_SECRET
    CHECK not expired
    CHECK not revoked (not in blacklist)
    VERIFY token_type == "refresh"
    VERIFY client_id matches authenticated client
  
  REVOKE old refresh token (token rotation):
    ADD token jti to blacklist with expiration
  
  GENERATE new tokens (same as authorization code grant)
  
  RETURN new access_token and refresh_token
```

**4.5 Implement Token Revocation Endpoint**

Allow ServiceNow to invalidate tokens immediately rather than waiting for expiration. Essential for security incidents and clean connection teardown.

```pseudocode
ENDPOINT: POST /oauth/revoke
RATE LIMIT: 100 requests per 15 minutes

HANDLER:
  AUTHENTICATE client (same as token endpoint)
  
  EXTRACT token from request body
  DECODE token (without full validation - may be expired)
  
  VALIDATE token ownership:
    VERIFY token.client_id matches authenticated client
    REJECT if mismatch
  
  ADD token to blacklist:
    STORE token.jti with token.exp as TTL
    In Redis: SETEX "revoked:{jti}" TTL "1"
    In database: INSERT with expires_at column
  
  LOG revocation event
  
  RETURN 200 OK (always return success per RFC 7009)
```

**4.6 Implement Authentication Middleware**

Validate JWT tokens on protected endpoints and extract client identity. This middleware runs on every MCP request to ensure only authenticated clients can access your tools.

```pseudocode
FUNCTION authenticate_request(request):
  EXTRACT Authorization header
  REQUIRE "Bearer <token>" format
  EXTRACT token from header
  
  VERIFY JWT token:
    DECODE and verify signature with JWT_SECRET
    CHECK expiration (reject if expired)
    CHECK revocation (reject if in blacklist)
  
  EXTRACT claims:
    client_id, user_id, scope, jti
  
  ATTACH claims to request context
  ALLOW request to proceed

FUNCTION is_token_revoked(jti):
  IF using Redis THEN
    RETURN Redis.EXISTS("revoked:" + jti)
  ELSE IF using database THEN
    QUERY revoked_tokens WHERE jti = {jti} AND expires_at > NOW()
    RETURN query returned results
  ELSE (in-memory)
    RETURN jti IN revoked_tokens_set
  END IF
```

---

### Phase 5: Production Hardening

**Purpose:** Add the operational features that make your server production-ready - rate limiting prevents abuse, audit logging enables compliance, and error handling protects sensitive information.

**5.1 Configure Rate Limiting**

Protect your server from abuse and accidental denial-of-service. Rate limits are tuned to allow normal ServiceNow usage while blocking malicious or misconfigured clients.

```pseudocode
RATE LIMITER CONFIGURATION:

OAuth endpoints (/oauth/*):
  WINDOW: 15 minutes
  MAX_REQUESTS: 100
  MESSAGE: {"error": "too_many_requests"}

MCP endpoint (/mcp):
  WINDOW: 1 minute
  MAX_REQUESTS: 60
  MESSAGE: {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Rate limit exceeded"}}

Health check (/health):
  WINDOW: 1 minute
  MAX_REQUESTS: 30
  MESSAGE: {"error": "too_many_requests"}

IMPLEMENTATION:
  USE sliding window or fixed window counter
  STORE counters in memory (single server) or Redis (multi-server)
  RESET counters at window expiration
  RETURN 429 status code when limit exceeded
```

**5.2 Implement Audit Logging**

Track every OAuth event, MCP tool execution, and security incident. Audit logs provide the paper trail required for compliance and the diagnostics needed for troubleshooting.

```pseudocode
AUDIT LOG STRUCTURE:
  timestamp: ISO 8601 format
  event_type: "oauth" | "mcp" | "security"
  client_id: OAuth client identifier
  user_id: user identifier (simulated for M2M)
  action: specific action taken
  result: "success" | "failure" | "denied"
  details: additional context (optional)

OAUTH EVENTS TO LOG:
  - dcr_registration (client created)
  - authorization_code_issued
  - token_issued (authorization code exchange)
  - token_refreshed
  - token_revoked

MCP EVENTS TO LOG:
  - tools/list request
  - tools/call with tool name
  - Any errors during tool execution

SECURITY EVENTS TO LOG:
  - authentication_failed (invalid token)
  - authorization_failed (forbidden resource)
  - rate_limit_exceeded
  - invalid_pkce_challenge
  - token_validation_failed

LOG FORMAT:
  Development: Human-readable text
  Production: Structured JSON for log aggregation
```

**5.3 Implement Error Handling**

Catch and format all errors consistently while preventing information leakage. Production error handling protects internal implementation details while development mode provides debugging information.

```pseudocode
GLOBAL ERROR HANDLER:
  CATCH all unhandled exceptions
  LOG error with stack trace
  
  DETERMINE error category:
    validation_error → 400 Bad Request
    authentication_error → 401 Unauthorized
    authorization_error → 403 Forbidden
    not_found_error → 404 Not Found
    rate_limit_error → 429 Too Many Requests
    internal_error → 500 Internal Server Error
  
  FORMAT error response:
    OAuth errors: RFC 6749 format
      {error: "error_code", error_description: "message"}
    
    MCP errors: JSON-RPC format
      {jsonrpc: "2.0", error: {code: -32000, message: "error"}, id: request_id}
    
    General errors: Simple JSON
      {error: "error_type", message: "description"}
  
  IF production THEN
    HIDE internal details (no stack traces, database errors)
    RETURN generic error messages
  ELSE
    INCLUDE detailed error information for debugging
  END IF
```

**5.4 Enhance Health Check**

Enable monitoring systems to detect problems before they impact users. Health checks validate that all dependencies (storage, Redis, configuration) are working correctly.

```pseudocode
ENDPOINT: GET /health

HANDLER:
  CHECK server health:
    status: "healthy"
    uptime: process_uptime_seconds
  
  CHECK storage health:
    TRY connect to client storage
    IF success THEN status: "healthy"
    ELSE status: "unhealthy", error: error_message
  
  CHECK Redis health (if configured):
    TRY Redis PING command
    IF success THEN status: "healthy"
    ELSE status: "unhealthy", error: error_message
  
  CHECK configuration health:
    IF production mode THEN
      VERIFY HTTPS configured
      VERIFY no in-memory storage
      LIST any configuration issues
  
  AGGREGATE results:
    overall_status = "healthy" IF all checks pass ELSE "unhealthy"
  
  RETURN:
    status: overall_status
    timestamp: current_time
    version: "1.0.0"
    checks: {detailed_check_results}
  
  STATUS CODE:
    200 OK if healthy
    503 Service Unavailable if unhealthy
```

---

## Validation & Testing

**Purpose:** Verify each component works correctly before connecting to ServiceNow. Testing in isolation makes problems easier to diagnose than waiting for end-to-end integration.

### Basic Validation

Confirm the server foundation is solid - server starts, configuration is valid, and basic endpoints respond.

```pseudocode
TEST: Server starts without errors
VERIFY: Logs show "Server listening on port X"
VERIFY: Configuration validation passes

TEST: Health check endpoint
REQUEST: GET /health
VERIFY: Returns 200 OK
VERIFY: Response contains {"status": "healthy"}

TEST: OAuth metadata endpoints
REQUEST: GET /.well-known/oauth-authorization-server
VERIFY: Returns OAuth server metadata JSON

TEST: MCP initialize (no authentication)
REQUEST: POST /mcp with initialize method
VERIFY: Returns server capabilities
VERIFY: No authentication required

TEST: MCP tools/list (requires authentication)
REQUEST: POST /mcp with tools/list method (no token)
VERIFY: Returns 401 Unauthorized
```

### OAuth Flow Testing

Walk through the complete OAuth 2.1 flow from client registration to token revocation. This validates that ServiceNow will be able to authenticate and maintain a persistent connection.

```pseudocode
TEST: Complete OAuth 2.1 flow with PKCE

STEP 1: Register client via DCR
  REQUEST: POST /oauth/register with DCR_AUTH_TOKEN
  BODY: {client_name, redirect_uris}
  VERIFY: Returns client_id and client_secret
  SAVE: client credentials for subsequent tests

STEP 2: Generate PKCE parameters
  GENERATE: code_verifier (random 43-128 characters)
  COMPUTE: code_challenge = Base64URL(SHA256(code_verifier))
  code_challenge_method = "S256"

STEP 3: Authorization request
  REQUEST: GET /oauth/authorize with parameters:
    client_id, redirect_uri, response_type=code
    code_challenge, code_challenge_method=S256, state
  VERIFY: Redirects to redirect_uri with authorization code
  SAVE: authorization code

STEP 4: Token exchange
  REQUEST: POST /oauth/token
  BODY: grant_type=authorization_code, code, redirect_uri,
        client_id, client_secret, code_verifier
  VERIFY: Returns access_token, refresh_token, expires_in
  SAVE: tokens for subsequent tests

STEP 5: Use access token
  REQUEST: POST /mcp with tools/list method
  HEADER: Authorization: Bearer <access_token>
  VERIFY: Returns tools list (authenticated request succeeds)

STEP 6: Refresh tokens
  REQUEST: POST /oauth/token
  BODY: grant_type=refresh_token, refresh_token,
        client_id, client_secret
  VERIFY: Returns new access_token and refresh_token
  SAVE: new tokens

STEP 7: Verify old refresh token revoked
  REQUEST: POST /oauth/token with old refresh_token
  VERIFY: Returns 400 Bad Request (token rotation works)

STEP 8: Revoke token
  REQUEST: POST /oauth/revoke
  BODY: token=<access_token>, client_id, client_secret
  VERIFY: Returns 200 OK

STEP 9: Verify revoked token blocked
  REQUEST: POST /mcp with revoked access_token
  VERIFY: Returns 401 Unauthorized (token blacklist works)
```

### Production Checklist

Verify production-critical features are configured correctly. These aren't optional - each item on this list prevents a specific category of security or operational problems.

```pseudocode
SECURITY VALIDATION:
  [ ] JWT_SECRET is minimum 32 characters
  [ ] HTTPS configured (OAUTH_ISSUER uses https://)
  [ ] Client secrets stored as hashed (never plaintext)
  [ ] DCR_AUTH_TOKEN secured and shared via secure channel
  [ ] Rate limiting enforced on all endpoints
  [ ] CORS configured with ServiceNow instance URL
  [ ] No secrets in version control (.env in .gitignore)

STORAGE VALIDATION:
  [ ] Client storage initialized and accessible
  [ ] Redis connected (if configured)
  [ ] Token blacklist persists across server restarts
  [ ] Authorization codes expire automatically

FUNCTIONALITY VALIDATION:
  [ ] OAuth metadata endpoints respond
  [ ] DCR creates clients successfully
  [ ] Authorization flow generates codes with PKCE
  [ ] Token endpoint issues valid JWT tokens
  [ ] Refresh token rotation works
  [ ] Token revocation blocks future use
  [ ] MCP initialize works without authentication
  [ ] MCP tools/list requires authentication
  [ ] MCP tools/call executes tools correctly

PRODUCTION READINESS:
  [ ] Health check validates all services
  [ ] Audit logging tracks security events
  [ ] Error handling prevents detail leakage
  [ ] Graceful shutdown cleanup implemented
  [ ] Monitoring configured (logs, metrics, alerts)
```

---

## Storage Decision Guide

**Purpose:** Choose storage solutions based on your deployment architecture. The right storage choices determine whether your server can scale, survive restarts, and share state across instances.

Choose storage based on your deployment architecture:

### Single Server Deployment

```pseudocode
CLIENT STORAGE: File-based
  BENEFITS: Simple, no external dependencies
  IMPLEMENTATION: JSON file with file system locks
  LOCATION: ./data/registered_clients.json

TOKEN BLACKLIST: Redis (recommended) or In-memory
  REDIS:
    BENEFITS: Persists across restarts, automatic TTL
    REQUIREMENT: Redis server running
  IN-MEMORY:
    BENEFITS: No external dependencies
    LIMITATION: Lost on restart (tokens remain valid until expiration)
```

### Multi-Server / Load Balanced

```pseudocode
CLIENT STORAGE: Shared Database (required)
  OPTIONS: PostgreSQL, MongoDB, MySQL
  BENEFITS: Centralized, consistent across servers
  REQUIREMENT: Database cluster or managed service

TOKEN BLACKLIST: Redis (required)
  CONFIGURATION: Redis cluster or managed Redis
  BENEFITS: Shared state, fast lookups, automatic expiration
  CRITICAL: All servers must share same Redis instance
```

### Cloud-Native / Auto-Scaling

```pseudocode
CLIENT STORAGE: Managed Database
  OPTIONS: Firestore, DynamoDB, Cosmos DB
  BENEFITS: Fully managed, auto-scaling, high availability

TOKEN BLACKLIST: In-memory acceptable
  RATIONALE: Ephemeral containers, short token lifetimes
  ALTERNATIVE: Managed Redis for consistency
```

For detailed storage implementation code, see:
- [Part 5, Appendix B: Alternative Storage Implementations](./mcp-guide-05-appendices.md#appendix-b-alternative-storage-implementations)

---

## Production Deployment

**Purpose:** Take your tested server from development to production. This section covers the infrastructure setup, deployment process, and ongoing monitoring needed for reliable operation.

### Pre-Deployment Checklist

Verify everything is ready before deployment. Catching configuration errors before they reach production saves hours of troubleshooting.

```pseudocode
ENVIRONMENT CONFIGURATION:
  [ ] Environment-specific .env file created
  [ ] JWT_SECRET unique per environment
  [ ] HTTPS configured (OAUTH_ISSUER uses https://)
  [ ] Appropriate storage configured (database for multi-server)
  [ ] Redis configured for token blacklist
  [ ] CORS allows production ServiceNow instance

SECURITY:
  [ ] Secrets not committed to version control
  [ ] DCR_AUTH_TOKEN shared securely with ServiceNow team
  [ ] Client secrets will be stored hashed
  [ ] Rate limiting configured
  [ ] Audit logging enabled

INFRASTRUCTURE:
  [ ] Server/VM provisioned with adequate resources
  [ ] Database created and accessible (if using)
  [ ] Redis server running and accessible (if using)
  [ ] Reverse proxy configured for HTTPS (nginx, Apache)
  [ ] Firewall rules allow ServiceNow IP ranges
  [ ] Monitoring and alerting configured
```

### Deployment Steps

Follow these steps in order for a smooth deployment. Each step builds on the previous one, so don't skip ahead.

```pseudocode
1. PROVISION INFRASTRUCTURE:
   CREATE server/VM
   INSTALL language runtime
   INSTALL dependencies (Redis, database if needed)
   CONFIGURE firewall rules

2. DEPLOY APPLICATION:
   COPY application code to server
   INSTALL language-specific dependencies
   CREATE .env file with production configuration
   VERIFY configuration validation passes

3. START SERVICES:
   START Redis (if used)
   START database (if used)
   START MCP server application
   VERIFY process is running
   CHECK health endpoint returns healthy

4. VALIDATE DEPLOYMENT:
   TEST OAuth metadata endpoints accessible
   TEST DCR creates client successfully
   TEST complete OAuth flow with PKCE
   TEST MCP endpoints with valid token
   VERIFY rate limiting enforced
   CHECK audit logs writing correctly

5. CONFIGURE SERVICENOW:
   PROVIDE ServiceNow team:
     - MCP server URL (https://your-domain.com)
     - DCR_AUTH_TOKEN (via secure channel)
   FOLLOW: [ServiceNow Connection Configuration](./mcp-guide-05-appendices.md#appendix-d-servicenow-connection-configuration)
```

### Post-Deployment Monitoring

Watch for problems in production. Good monitoring catches issues before they become outages.

```pseudocode
MONITOR HEALTH:
  CHECK /health endpoint regularly
  ALERT if status becomes "unhealthy"
  MONITOR service uptime

MONITOR LOGS:
  TRACK authentication failures (potential attacks)
  TRACK rate limit exceeded events
  MONITOR token revocations
  REVIEW tool execution patterns

MONITOR PERFORMANCE:
  TRACK response times (should be < 200ms)
  MONITOR token validation speed
  CHECK Redis connection health
  MONITOR storage connection health

MONITOR RESOURCES:
  CPU usage (should be < 50% normally)
  Memory usage
  Storage space (for file-based storage)
  Network bandwidth
```

---

## Troubleshooting

**Purpose:** Diagnose and fix common problems quickly. Most deployment issues fall into these categories - check here before diving into code.

### Configuration Issues

Problems that prevent the server from starting or running correctly.

**Symptom:** Server fails to start with configuration validation error

```pseudocode
DIAGNOSIS:
  CHECK logs for specific validation failure
  COMMON CAUSES:
    - JWT_SECRET too short (< 32 characters)
    - Missing required environment variables
    - Invalid OAUTH_ISSUER format
    - HTTPS not configured in production

SOLUTION:
  REVIEW .env file against required configuration
  VERIFY all required variables present
  CHECK JWT_SECRET length: minimum 32 characters
  VERIFY OAUTH_ISSUER format (https:// for production)
```

**Symptom:** "Redis connection failed" warning

```pseudocode
DIAGNOSIS:
  Server will continue running with in-memory fallback
  CHECK Redis server status
  CHECK Redis connection details (host, port, password)

SOLUTION:
  VERIFY Redis is running: redis-cli ping (should return PONG)
  CHECK REDIS_HOST and REDIS_PORT in .env
  VERIFY firewall allows Redis port
  IF intentional: ignore warning (not recommended for production)
```

### OAuth Flow Issues

Problems during the OAuth authentication process that prevent ServiceNow from getting valid tokens.

**Symptom:** "Invalid client" error during token exchange

```pseudocode
DIAGNOSIS:
  Client authentication failing
  COMMON CAUSES:
    - Incorrect client_id or client_secret
    - Client not registered via DCR
    - Client secret mismatch

SOLUTION:
  VERIFY client registered via DCR
  CHECK client_id matches DCR response
  CHECK client_secret matches DCR response (case-sensitive)
  REVIEW audit logs for registration confirmation
```

**Symptom:** "PKCE validation failed" error

```pseudocode
DIAGNOSIS:
  code_verifier doesn't match original code_challenge
  COMMON CAUSES:
    - code_verifier not stored correctly
    - code_verifier modified between steps
    - Wrong hashing algorithm used

SOLUTION:
  VERIFY code_verifier is exactly as generated
  CHECK using SHA-256 hash algorithm
  VERIFY Base64URL encoding (not standard Base64)
  TEST with known good code_verifier/challenge pair
```

**Symptom:** "Token revoked" error unexpectedly

```pseudocode
DIAGNOSIS:
  Token in blacklist but shouldn't be
  COMMON CAUSES:
    - Token previously revoked manually
    - Refresh token rotated (old token now invalid)
    - Redis contains stale blacklist entries

SOLUTION:
  CHECK audit logs for revocation event
  IF after refresh: use new tokens (old ones auto-revoked)
  VERIFY Redis TTL settings correct
  CLEAR Redis blacklist if in development: redis-cli FLUSHDB
```

### MCP Protocol Issues

Problems with MCP communication that prevent tools from working correctly.

**Symptom:** "Method not found" error

```pseudocode
DIAGNOSIS:
  MCP method not implemented or misspelled
  COMMON CAUSES:
    - Method name typo
    - Method not in routing table
    - Case sensitivity issue

SOLUTION:
  VERIFY exact method name: "initialize", "tools/list", "tools/call"
  CHECK routing implementation includes all methods
  REVIEW logs for actual method received
```

**Symptom:** Tools not appearing in ServiceNow

```pseudocode
DIAGNOSIS:
  tools/list response invalid or tools missing
  COMMON CAUSES:
    - Invalid JSON Schema in inputSchema
    - Missing required fields (name, description)
    - Authentication failing before tools/list

SOLUTION:
  TEST tools/list endpoint directly with valid token
  VALIDATE each tool's inputSchema against JSON Schema spec
  VERIFY all tools have required fields
  CHECK ServiceNow logs for error messages
```

### Performance Issues

Problems that cause slow response times or resource exhaustion.

**Symptom:** Slow response times (> 500ms)

```pseudocode
DIAGNOSIS:
  Performance bottleneck in request processing
  COMMON CAUSES:
    - Slow storage operations
    - Redis connection issues
    - Inefficient tool implementations
    - High server load

SOLUTION:
  CHECK storage response times (should be < 10ms)
  VERIFY Redis connections pooled
  PROFILE tool execution times
  MONITOR server CPU and memory usage
  CONSIDER caching frequently accessed data
```

**Symptom:** Rate limiting triggered unexpectedly

```pseudocode
DIAGNOSIS:
  Legitimate traffic exceeding rate limits
  COMMON CAUSES:
    - ServiceNow polling too frequently
    - Multiple ServiceNow instances sharing credentials
    - Automated testing overwhelming server

SOLUTION:
  REVIEW audit logs for request patterns
  CHECK if multiple ServiceNow instances using same client
  CONSIDER increasing rate limits if justified
  IMPLEMENT per-client rate limiting if needed
```

---

## Next Steps

**Purpose:** Complete your deployment by integrating with ServiceNow, developing custom tools, or preparing for production operations.

### For ServiceNow Integration

Connect your deployed MCP server to ServiceNow. You've built the server - now make it accessible to AI agents.

After successful deployment:

1. **Share connection details with ServiceNow team:**
   - MCP server URL (HTTPS required)
   - DCR_AUTH_TOKEN (secure channel only)
   - Supported OAuth endpoints

2. **ServiceNow team configures MCP connection:**
   - Follow [ServiceNow Connection Configuration](./mcp-guide-05-appendices.md#appendix-d-servicenow-connection-configuration)
   - Test DCR registration
   - Verify OAuth flow completes
   - Confirm tools visible in AI Agent configuration

3. **Validate end-to-end integration:**
   - ServiceNow agent can list tools
   - Tools execute successfully
   - Results return to agent
   - Audit logs show complete trail

### For Custom Tool Development

Extend your server with tools that solve real business problems. The example tools work, but your custom tools provide the real value.

1. **Design tool functionality:**
   - Define clear purpose and scope
   - Identify required parameters
   - Plan error handling

2. **Implement tool:**
   - Add to tools/list response with JSON Schema
   - Implement execution logic in tools/call
   - Validate inputs thoroughly
   - Handle errors gracefully

3. **Test thoroughly:**
   - Unit test tool logic
   - Integration test via MCP protocol
   - Test with ServiceNow agent
   - Verify audit logging

4. **Document tool:**
   - Clear description for AI agent
   - Parameter descriptions and examples
   - Error conditions and handling
   - Security considerations

### For Production Operations

Set up the operational practices that keep your server running reliably. Deployment is just the beginning - operations is forever.

1. **Set up monitoring:**
   - Health check alerts
   - Log aggregation and analysis
   - Performance metrics
   - Security event notifications

2. **Establish procedures:**
   - Deployment process
   - Rollback plan
   - Incident response
   - Backup and recovery

3. **Plan maintenance:**
   - Token rotation schedule
   - Dependency updates
   - Security patching
   - Performance tuning

4. **Documentation:**
   - Runbook for common operations
   - Troubleshooting guide
   - Architecture documentation
   - Contact information

---

## Reference Documentation

For detailed implementation guidance, see:

- **[Part 1: Introduction](./mcp-guide-01-introduction.md)** - Requirements, scope, and ServiceNow integration overview
- **[Part 2: Server Foundation](./mcp-guide-02-server-foundation.md)** - HTTP server setup, middleware, configuration, storage
- **[Part 3: MCP Protocol & Tools](./mcp-guide-03-mcp-protocol-tools.md)** - MCP endpoint implementation and tool development
- **[Part 4: OAuth Implementation](./mcp-guide-04-oauth-implementation.md)** - Complete OAuth 2.1 + PKCE implementation details
- **[Part 5: Appendices](./mcp-guide-05-appendices.md)** - Storage options, deployment checklist, ServiceNow configuration

For language-specific implementation:

- **[JavaScript Deployment Guide](./deployment/DEPLOYMENT_GUIDE_JAVASCRIPT.md)** - Node.js/Express implementation
- **[TypeScript Deployment Guide](./deployment/DEPLOYMENT_GUIDE_TYPESCRIPT.md)** - TypeScript/Node.js implementation
- **[Python Deployment Guide](./deployment/DEPLOYMENT_GUIDE_PYTHON.md)** - Python/FastAPI implementation
- **[Language Implementation Hints](./language-implementation-hints.md)** - Guidance for Go, Java, C#, Rust

---

**Version:** 1.0  
**Last Updated:** February 2026  
**Maintainer:** ServiceNow Agent Fabric Project

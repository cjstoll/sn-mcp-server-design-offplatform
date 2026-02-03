// ============================================================================
// MCP Gateway Server v3.3.0 - Phase 4a Update (Redis Token Blacklist)
// ============================================================================
// 
// CHANGES IN v3.3.0 (Phase 4a):
// 1. Added Redis integration for persistent token blacklist
// 2. Token revocations now survive server restarts
// 3. Scalable token blacklist (no memory bloat)
// 4. Redis connection with error handling
//
// PREVIOUS CHANGES:
// Phase 2 (v3.2.0): Rate limiting on all endpoints
// Phase 1+3 (v3.1.0): Protocol version, OAuth metadata, audit logging
//
// BACKWARD COMPATIBLE: All changes maintain existing OAuth flow and ServiceNow integration
// ============================================================================

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const redis = require('redis'); // PHASE 4a NEW

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// CONFIGURATION
// ============================================================================

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISSUER = process.env.JWT_ISSUER || 'https://mcp.cstollsn.com';
const DCR_AUTH_TOKEN = process.env.DCR_AUTH_TOKEN;
const MCP_API_KEY = process.env.MCP_API_KEY;
const SERVICENOW_INSTANCE = process.env.SERVICENOW_INSTANCE;

// Redis configuration
const REDIS_HOST = process.env.REDIS_HOST || 'localhost';
const REDIS_PORT = process.env.REDIS_PORT || 6379;

// Token lifetimes (in seconds)
const ACCESS_TOKEN_LIFETIME = 3600;        // 1 hour
const REFRESH_TOKEN_LIFETIME = 2592000;    // 30 days
const AUTHORIZATION_CODE_LIFETIME = 600;   // 10 minutes

// In-memory storage
const registeredClients = new Map();
const authorizationCodes = new Map();
// PHASE 4a CHANGE: Removed in-memory revokedTokens Set - now using Redis

// File-based client persistence
const fs = require('fs');
const path = require('path');
const CLIENTS_FILE = path.join(__dirname, 'registered_clients.json');

// ============================================================================
// PHASE 4a NEW: REDIS CLIENT SETUP
// ============================================================================

let redisClient;
let redisConnected = false;

async function initializeRedis() {
  redisClient = redis.createClient({
    socket: {
      host: REDIS_HOST,
      port: REDIS_PORT
    }
  });
  
  redisClient.on('error', (err) => {
    console.error('[REDIS] Connection error:', err);
    redisConnected = false;
  });
  
  redisClient.on('connect', () => {
    console.log('[REDIS] Connected successfully');
    redisConnected = true;
  });
  
  redisClient.on('ready', () => {
    console.log('[REDIS] Ready to accept commands');
    redisConnected = true;
  });
  
  try {
    await redisClient.connect();
    console.log(`[REDIS] Initialized at ${REDIS_HOST}:${REDIS_PORT}`);
  } catch (error) {
    console.error('[REDIS] Failed to connect:', error);
    redisConnected = false;
  }
}

// Initialize Redis on startup
initializeRedis();

// ============================================================================
// PHASE 4a NEW: REDIS TOKEN BLACKLIST FUNCTIONS
// ============================================================================

async function isTokenRevoked(jti) {
  if (!redisConnected) {
    console.warn('[REDIS] Not connected - unable to check revocation status');
    return false; // Fail open if Redis unavailable
  }
  
  try {
    const exists = await redisClient.exists(`revoked:${jti}`);
    return exists === 1;
  } catch (error) {
    console.error('[REDIS] Error checking token revocation:', error);
    return false; // Fail open
  }
}

async function revokeToken(jti, expiresIn) {
  if (!redisConnected) {
    console.warn('[REDIS] Not connected - token revocation not persistent');
    return false;
  }
  
  try {
    // Store with expiration matching token lifetime
    await redisClient.setEx(`revoked:${jti}`, expiresIn, 'revoked');
    console.log(`[REDIS] Token revoked and stored: ${jti.substring(0, 10)}...`);
    return true;
  } catch (error) {
    console.error('[REDIS] Error revoking token:', error);
    return false;
  }
}

// ============================================================================
// RATE LIMITING CONFIGURATION
// ============================================================================

const oauthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: {
    error: 'too_many_requests',
    error_description: 'Too many authentication requests, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

const mcpLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60,
  message: {
    jsonrpc: '2.0',
    error: {
      code: -32000,
      message: 'Rate limit exceeded',
      data: { details: 'Too many requests, please try again later' }
    }
  },
  standardHeaders: true,
  legacyHeaders: false
});

const healthLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  message: {
    error: 'too_many_requests',
    message: 'Too many health check requests'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// ============================================================================
// AUTHORIZATION CODE CLEANUP
// ============================================================================

setInterval(() => {
  const now = Date.now();
  const expirationTime = AUTHORIZATION_CODE_LIFETIME * 1000;
  let cleanedCount = 0;
  
  for (const [code, data] of authorizationCodes.entries()) {
    if (now - data.created > expirationTime) {
      authorizationCodes.delete(code);
      cleanedCount++;
    }
  }
  
  if (cleanedCount > 0) {
    console.log(`[CLEANUP] ${new Date().toISOString()} - Removed ${cleanedCount} expired authorization code(s)`);
  }
}, 3600000);

// ============================================================================
// CLIENT PERSISTENCE FUNCTIONS
// ============================================================================

function loadClientsFromFile() {
  try {
    if (fs.existsSync(CLIENTS_FILE)) {
      const data = fs.readFileSync(CLIENTS_FILE, 'utf8');
      const clients = JSON.parse(data);
      
      for (const [clientId, clientData] of Object.entries(clients)) {
        registeredClients.set(clientId, clientData);
      }
      
      console.log(`[STARTUP] Loaded ${registeredClients.size} registered client(s) from file`);
    }
  } catch (error) {
    console.error('[ERROR] Failed to load clients from file:', error);
  }
}

function saveClientsToFile() {
  try {
    const clients = Object.fromEntries(registeredClients);
    fs.writeFileSync(CLIENTS_FILE, JSON.stringify(clients, null, 2), 'utf8');
    console.log(`[PERSIST] Saved ${registeredClients.size} client(s) to file`);
  } catch (error) {
    console.error('[ERROR] Failed to save clients to file:', error);
  }
}

loadClientsFromFile();

// ============================================================================
// MIDDLEWARE
// ============================================================================

app.use(cors({
  origin: SERVICENOW_INSTANCE,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ============================================================================
// AUDIT LOGGING MIDDLEWARE
// ============================================================================

app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const path = req.path;
  const ip = req.ip || req.connection.remoteAddress;
  const mcpMethod = req.body?.method || 'N/A';
  
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    try {
      const token = req.headers.authorization.substring(7);
      const decoded = jwt.decode(token);
      
      if (decoded) {
        console.log(`[AUDIT] ${timestamp} | User: ${decoded.sub} | Client: ${decoded.client_id} | ${method} ${path} | MCP Method: ${mcpMethod} | IP: ${ip}`);
      } else {
        console.log(`[AUDIT] ${timestamp} | Invalid Token Format | ${method} ${path} | IP: ${ip}`);
      }
    } catch (e) {
      console.log(`[AUDIT] ${timestamp} | Token Decode Error | ${method} ${path} | IP: ${ip}`);
    }
  } else {
    console.log(`[AUDIT] ${timestamp} | Unauthenticated | ${method} ${path} | MCP Method: ${mcpMethod} | IP: ${ip}`);
  }
  
  next();
});

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function generateSecureToken(length = 32) {
  return crypto.randomBytes(length).toString('base64url');
}

function base64UrlEncode(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function validatePKCE(verifier, challenge) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  const computed = base64UrlEncode(hash);
  return computed === challenge;
}

// ============================================================================
// JWT TOKEN FUNCTIONS
// ============================================================================

function createAccessToken(userId, clientId, scope) {
  const payload = {
    sub: userId,
    client_id: clientId,
    scope: scope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_LIFETIME,
    iss: JWT_ISSUER,
    aud: `${JWT_ISSUER}/mcp`,
    jti: uuidv4(),
    type: 'access'
  };
  
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
}

function createRefreshToken(userId, clientId, scope, rotationCount = 0) {
  const payload = {
    sub: userId,
    client_id: clientId,
    scope: scope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + REFRESH_TOKEN_LIFETIME,
    iss: JWT_ISSUER,
    aud: `${JWT_ISSUER}/mcp`,
    jti: uuidv4(),
    type: 'refresh',
    rotation_count: rotationCount
  };
  
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
}

// PHASE 4a CHANGE: Updated to use Redis for revocation check
async function validateToken(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      algorithms: ['HS256']
    });
    
    // PHASE 4a CHANGE: Check Redis instead of in-memory Set
    const revoked = await isTokenRevoked(decoded.jti);
    if (revoked) {
      throw new Error('Token has been revoked');
    }
    
    return decoded;
  } catch (error) {
    console.error('[AUTH] Token validation failed:', error.message);
    return null;
  }
}

// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================

function authenticateRequest(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Missing or invalid Authorization header'
    });
  }
  
  const token = authHeader.substring(7);
  
  // Try JWT validation first (now async due to Redis)
  validateToken(token).then(decoded => {
    if (decoded) {
      req.user = decoded;
      return next();
    }
    
    // Fallback to API key validation
    if (token === MCP_API_KEY) {
      req.user = { sub: 'api-key-user', client_id: 'api-key-client' };
      return next();
    }
    
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid or expired token'
    });
  }).catch(error => {
    console.error('[AUTH] Authentication error:', error);
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication failed'
    });
  });
}

// ============================================================================
// OAUTH 2.1 ENDPOINTS
// ============================================================================

app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer: JWT_ISSUER,
    authorization_endpoint: `${JWT_ISSUER}/oauth/authorize`,
    token_endpoint: `${JWT_ISSUER}/oauth/token`,
    revocation_endpoint: `${JWT_ISSUER}/oauth/revoke`,
    registration_endpoint: `${JWT_ISSUER}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['openid', 'email', 'profile']
  });
});

app.get('/.well-known/oauth-protected-resource', (req, res) => {
  res.json({
    resource: JWT_ISSUER,
    authorization_servers: [JWT_ISSUER],
    scopes_supported: ['openid', 'email', 'profile'],
    bearer_methods_supported: ['header']
  });
});

app.post('/register', oauthLimiter, (req, res) => {
  const authHeader = req.headers.authorization;
  const tokenFromBody = req.body.token_value;
  
  const providedToken = authHeader?.startsWith('Bearer ') 
    ? authHeader.substring(7) 
    : tokenFromBody;
  
  if (!providedToken || providedToken !== DCR_AUTH_TOKEN) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid or missing DCR authorization token'
    });
  }
  
  const {
    client_name,
    redirect_uris,
    grant_types = ['authorization_code', 'refresh_token'],
    response_types = ['code'],
    token_endpoint_auth_method = 'client_secret_post',
    use_pkce = true
  } = req.body;
  
  if (!client_name || !redirect_uris || !Array.isArray(redirect_uris)) {
    return res.status(400).json({
      error: 'invalid_client_metadata',
      error_description: 'Missing or invalid required fields: client_name, redirect_uris'
    });
  }
  
  const clientId = uuidv4();
  const clientSecret = generateSecureToken(32);
  const clientData = {
    clientId,
    clientSecret,
    clientName: client_name,
    redirectUris: redirect_uris,
    grantTypes: grant_types,
    responseTypes: response_types,
    tokenEndpointAuthMethod: token_endpoint_auth_method,
    usePkce: use_pkce,
    createdAt: new Date().toISOString()
  };
  
  registeredClients.set(clientId, clientData);
  saveClientsToFile();
  
  console.log(`[DCR] Registered new client: ${clientId} - ${client_name}`);
  
  res.status(201).json({
    client_id: clientId,
    client_secret: clientSecret,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_secret_expires_at: 0,
    redirect_uris: redirect_uris,
    grant_types: grant_types,
    response_types: response_types,
    token_endpoint_auth_method: token_endpoint_auth_method
  });
});

app.get('/oauth/authorize', oauthLimiter, (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope = 'openid email profile',
    state,
    code_challenge,
    code_challenge_method
  } = req.query;
  
  if (response_type !== 'code') {
    return res.redirect(`${redirect_uri}?error=unsupported_response_type&state=${state}`);
  }
  
  if (!client_id || !redirect_uri || !code_challenge || code_challenge_method !== 'S256') {
    return res.redirect(`${redirect_uri}?error=invalid_request&state=${state}`);
  }
  
  const client = registeredClients.get(client_id);
  if (!client) {
    return res.redirect(`${redirect_uri}?error=unauthorized_client&state=${state}`);
  }
  
  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Invalid redirect_uri'
    });
  }
  
  const userId = uuidv4();
  
  const authCode = generateSecureToken(32);
  authorizationCodes.set(authCode, {
    clientId: client_id,
    redirectUri: redirect_uri,
    scope: scope,
    codeChallenge: code_challenge,
    userId: userId,
    created: Date.now()
  });
  
  console.log(`[OAUTH] Authorization code generated for client: ${client_id}`);
  
  const redirectUrl = `${redirect_uri}?code=${authCode}&state=${state}`;
  res.redirect(redirectUrl);
});

app.post('/oauth/token', oauthLimiter, (req, res) => {
  const {
    grant_type,
    code,
    redirect_uri,
    client_id,
    client_secret,
    code_verifier,
    refresh_token
  } = req.body;
  
  const client = registeredClients.get(client_id);
  if (!client || client.clientSecret !== client_secret) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Invalid client credentials'
    });
  }
  
  if (grant_type === 'authorization_code') {
    const authData = authorizationCodes.get(code);
    
    if (!authData) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code'
      });
    }
    
    if (authData.clientId !== client_id || authData.redirectUri !== redirect_uri) {
      authorizationCodes.delete(code);
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Authorization code validation failed'
      });
    }
    
    if (!validatePKCE(code_verifier, authData.codeChallenge)) {
      authorizationCodes.delete(code);
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'PKCE validation failed'
      });
    }
    
    authorizationCodes.delete(code);
    
    const accessToken = createAccessToken(authData.userId, client_id, authData.scope);
    const newRefreshToken = createRefreshToken(authData.userId, client_id, authData.scope);
    
    console.log(`[OAUTH] Tokens issued for client: ${client_id}`);
    
    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_LIFETIME,
      refresh_token: newRefreshToken,
      scope: authData.scope
    });
  }
  
  // PHASE 4a CHANGE: Handle refresh_token grant (now async due to Redis)
  if (grant_type === 'refresh_token') {
    validateToken(refresh_token).then(decoded => {
      if (!decoded || decoded.type !== 'refresh') {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid refresh token'
        });
      }
      
      if (decoded.client_id !== client_id) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Client mismatch'
        });
      }
      
      // PHASE 4a CHANGE: Revoke old refresh token in Redis
      const tokenExpiry = decoded.exp - Math.floor(Date.now() / 1000);
      revokeToken(decoded.jti, tokenExpiry > 0 ? tokenExpiry : 1);
      
      const newAccessToken = createAccessToken(decoded.sub, client_id, decoded.scope);
      const newRefreshToken = createRefreshToken(
        decoded.sub, 
        client_id, 
        decoded.scope, 
        (decoded.rotation_count || 0) + 1
      );
      
      console.log(`[OAUTH] Tokens refreshed for client: ${client_id}`);
      
      return res.json({
        access_token: newAccessToken,
        token_type: 'Bearer',
        expires_in: ACCESS_TOKEN_LIFETIME,
        refresh_token: newRefreshToken,
        scope: decoded.scope
      });
    }).catch(error => {
      console.error('[OAUTH] Refresh token validation error:', error);
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Token validation failed'
      });
    });
    
    return; // Exit early since we're handling async
  }
  
  return res.status(400).json({
    error: 'unsupported_grant_type',
    error_description: 'Grant type not supported'
  });
});

// PHASE 4a CHANGE: Token revocation now uses Redis
app.post('/oauth/revoke', oauthLimiter, async (req, res) => {
  const { token, client_id, client_secret } = req.body;
  
  if (client_id && client_secret) {
    const client = registeredClients.get(client_id);
    if (!client || client.clientSecret !== client_secret) {
      return res.status(401).json({
        error: 'invalid_client'
      });
    }
  }
  
  try {
    const decoded = jwt.decode(token);
    if (decoded && decoded.jti) {
      const tokenExpiry = decoded.exp - Math.floor(Date.now() / 1000);
      await revokeToken(decoded.jti, tokenExpiry > 0 ? tokenExpiry : 1);
      console.log(`[OAUTH] Token revoked: ${decoded.jti}`);
    }
  } catch (error) {
    // Per RFC 7009, always return 200 OK even if token is invalid
  }
  
  return res.status(200).json({});
});

// ============================================================================
// MCP PROTOCOL ENDPOINTS
// ============================================================================

app.get('/health', healthLimiter, (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '3.3.0',
    services: {
      ollama: 'running',
      mcp_filesystem: 'running',
      oauth_jwt: 'enabled',
      rate_limiting: 'enabled',
      redis: redisConnected ? 'connected' : 'disconnected'
    }
  });
});

app.post('/mcp', mcpLimiter, async (req, res) => {
  const { method, params, id } = req.body;
  
  try {
    if (method === 'initialize') {
      return handleInitialize(req, res);
    }
    
    if (method === 'notifications/initialized') {
      console.log('[MCP] Client sent initialized notification');
      return res.status(200).send();
    }
    
    authenticateRequest(req, res, async () => {
      switch (method) {
        case 'tools/list':
          return handleToolsList(req, res);
        
        case 'tools/call':
          return handleToolsCall(req, res);
        
        default:
          return res.status(200).json({
            jsonrpc: '2.0',
            error: {
              code: -32601,
              message: `Method not found: ${method}`
            },
            id: id
          });
      }
    });
  } catch (error) {
    console.error('[MCP] Error handling request:', error);
    return res.status(500).json({
      jsonrpc: '2.0',
      error: {
        code: -32603,
        message: 'Internal server error',
        data: { details: error.message }
      },
      id: id
    });
  }
});

// ============================================================================
// MCP PROTOCOL HANDLERS
// ============================================================================

function handleInitialize(req, res) {
  const { params } = req.body;
  
  console.log('[MCP] Initialize request received');
  console.log('[MCP] Client info:', params?.clientInfo);
  
  const response = {
    jsonrpc: '2.0',
    result: {
      protocolVersion: '2025-03-26',
      capabilities: {
        tools: {
          listChanged: false
        },
        logging: {}
      },
      serverInfo: {
        name: 'MCP Gateway Server',
        version: '3.3.0'
      }
    },
    id: req.body.id
  };
  
  console.log('[MCP] Initialize response sent');
  res.json(response);
}

async function handleToolsList(req, res) {
  console.log('[MCP] Tools list request');
  
  const tools = [
    {
      name: 'llm_generate',
      description: 'Generate text using local LLM (TinyLlama)',
      inputSchema: {
        type: 'object',
        properties: {
          prompt: {
            type: 'string',
            description: 'The prompt to send to the LLM'
          },
          model: {
            type: 'string',
            description: 'Model to use (default: tinyllama)',
            enum: ['tinyllama', 'phi3'],
            default: 'tinyllama'
          }
        },
        required: ['prompt']
      }
    },
    {
      name: 'file_list',
      description: 'List files in MCP workspace directory',
      inputSchema: {
        type: 'object',
        properties: {},
        required: []
      }
    },
    {
      name: 'file_read',
      description: 'Read contents of a file from MCP workspace',
      inputSchema: {
        type: 'object',
        properties: {
          filename: {
            type: 'string',
            description: 'Name of file to read'
          }
        },
        required: ['filename']
      }
    },
    {
      name: 'file_write',
      description: 'Write content to a file in MCP workspace',
      inputSchema: {
        type: 'object',
        properties: {
          filename: {
            type: 'string',
            description: 'Name of file to write'
          },
          content: {
            type: 'string',
            description: 'Content to write to the file'
          }
        },
        required: ['filename', 'content']
      }
    }
  ];
  
  res.json({
    jsonrpc: '2.0',
    result: {
      tools: tools
    },
    id: req.body.id
  });
}

async function handleToolsCall(req, res) {
  const { params } = req.body;
  const { name, arguments: args } = params;
  
  console.log(`[MCP] Tool call: ${name}`);
  
  try {
    let result;
    
    switch (name) {
      case 'llm_generate':
        result = await executeLLMGenerate(args);
        break;
      
      case 'file_list':
        result = await executeFileList();
        break;
      
      case 'file_read':
        result = await executeFileRead(args);
        break;
      
      case 'file_write':
        result = await executeFileWrite(args);
        break;
      
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
    
    res.json({
      jsonrpc: '2.0',
      result: result,
      id: req.body.id
    });
  } catch (error) {
    console.error(`[MCP] Tool execution error (${name}):`, error);
    res.json({
      jsonrpc: '2.0',
      error: {
        code: -32603,
        message: `Tool execution failed: ${error.message}`
      },
      id: req.body.id
    });
  }
}

// ============================================================================
// TOOL IMPLEMENTATIONS
// ============================================================================

async function executeLLMGenerate(args) {
  const { prompt, model = 'tinyllama' } = args;
  
  if (!prompt) {
    throw new Error('Prompt is required');
  }
  
  console.log(`[LLM] Generating response with model: ${model}`);
  
  try {
    const fetch = (await import('node-fetch')).default;
    const response = await fetch('http://localhost:11434/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: model,
        prompt: prompt,
        stream: false
      })
    });
    
    if (!response.ok) {
      throw new Error(`Ollama API error: ${response.statusText}`);
    }
    
    const data = await response.json();
    
    return {
      content: [
        {
          type: 'text',
          text: data.response || 'No response from LLM'
        }
      ]
    };
  } catch (error) {
    throw new Error(`LLM generation failed: ${error.message}`);
  }
}

async function executeFileList() {
  const workspaceDir = path.join(process.env.HOME, 'mcp-workspace');
  
  try {
    const files = fs.readdirSync(workspaceDir);
    const fileDetails = files.map(filename => {
      const filepath = path.join(workspaceDir, filename);
      const stats = fs.statSync(filepath);
      return {
        name: filename,
        size: stats.size,
        isDirectory: stats.isDirectory(),
        modified: stats.mtime.toISOString()
      };
    });
    
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(fileDetails, null, 2)
        }
      ]
    };
  } catch (error) {
    throw new Error(`Failed to list files: ${error.message}`);
  }
}

async function executeFileRead(args) {
  const { filename } = args;
  
  if (!filename) {
    throw new Error('Filename is required');
  }
  
  const workspaceDir = path.join(process.env.HOME, 'mcp-workspace');
  const filepath = path.join(workspaceDir, filename);
  
  try {
    const content = fs.readFileSync(filepath, 'utf8');
    return {
      content: [
        {
          type: 'text',
          text: content
        }
      ]
    };
  } catch (error) {
    throw new Error(`Failed to read file: ${error.message}`);
  }
}

async function executeFileWrite(args) {
  const { filename, content } = args;
  
  if (!filename || content === undefined) {
    throw new Error('Filename and content are required');
  }
  
  const workspaceDir = path.join(process.env.HOME, 'mcp-workspace');
  const filepath = path.join(workspaceDir, filename);
  
  try {
    fs.writeFileSync(filepath, content, 'utf8');
    return {
      content: [
        {
          type: 'text',
          text: `Successfully wrote to ${filename}`
        }
      ]
    };
  } catch (error) {
    throw new Error(`Failed to write file: ${error.message}`);
  }
}

// ============================================================================
// SERVER STARTUP
// ============================================================================

app.listen(PORT, () => {
  console.log('='.repeat(80));
  console.log('MCP Gateway Server v3.3.0 - Phase 4a (Redis Token Blacklist)');
  console.log('='.repeat(80));
  console.log(`[SERVER] Listening on port ${PORT}`);
  console.log(`[SERVER] Health check: http://localhost:${PORT}/health`);
  console.log(`[SERVER] MCP endpoint: http://localhost:${PORT}/mcp`);
  console.log(`[SERVER] OAuth metadata: http://localhost:${PORT}/.well-known/oauth-authorization-server`);
  console.log(`[SERVER] Resource metadata: http://localhost:${PORT}/.well-known/oauth-protected-resource`);
  console.log(`[SERVER] Protocol version: 2025-03-26 (ServiceNow compatible)`);
  console.log(`[SERVER] Registered clients: ${registeredClients.size}`);
  console.log('='.repeat(80));
  console.log('[FEATURE] Rate Limiting Enabled:');
  console.log('  - OAuth endpoints: 100 requests per 15 minutes');
  console.log('  - MCP endpoint: 60 requests per minute');
  console.log('  - Health endpoint: 30 requests per minute');
  console.log('='.repeat(80));
  console.log('[FEATURE] Redis Token Blacklist:');
  console.log(`  - Host: ${REDIS_HOST}:${REDIS_PORT}`);
  console.log(`  - Status: ${redisConnected ? 'Connected' : 'Connecting...'}`);
  console.log('='.repeat(80));
  console.log('[READY] Server is ready to accept connections');
  console.log('='.repeat(80));
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('[SHUTDOWN] SIGTERM received, saving clients and shutting down...');
  saveClientsToFile();
  if (redisClient) {
    await redisClient.quit();
  }
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('[SHUTDOWN] SIGINT received, saving clients and shutting down...');
  saveClientsToFile();
  if (redisClient) {
    await redisClient.quit();
  }
  process.exit(0);
});

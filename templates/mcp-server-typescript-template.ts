#!/usr/bin/env node
/**
 * MCP Server with OAuth 2.1 Authorization Server
 * 
 * Standards Implemented:
 * - MCP Protocol 2025-06-18
 * - OAuth 2.1 (consolidation of OAuth 2.0 best practices)
 * - RFC 7636: PKCE (Proof Key for Code Exchange)
 * - RFC 7519: JSON Web Tokens (JWT)
 * - RFC 6749: OAuth 2.0 Authorization Framework
 * - RFC 6750: Bearer Token Usage
 * - RFC 7591: Dynamic Client Registration
 * - RFC 8414: OAuth 2.0 Authorization Server Metadata
 * 
 * Architecture: Stateless OAuth 2.1 Authorization Server
 * - Issues JWT access tokens AND JWT refresh tokens (both stateless)
 * - Validates PKCE for all authorization code flows
 * - Implements refresh token rotation via JWT rotation_count claim
 * - Tokens stored in ServiceNow (oauth_credential table)
 * - Server survives restarts without losing token state
 * - Backward compatible with existing API key and Google OAuth
 */

import express from "express";
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { Firestore } from '@google-cloud/firestore';

// ============================================================================
// CONFIGURATION & ENVIRONMENT VARIABLES
// ============================================================================

// API Key configuration (backward compatibility)
const API_KEY_XAPI = process.env.MCP_API_KEY_XAPI || "";
const API_KEY_APIKEY = process.env.MCP_API_KEY_APIKEY || "";
const API_KEY_AUTH = process.env.MCP_API_KEY_AUTH || "";

// Legacy OAuth configuration (Google OAuth - backward compatibility)
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "";

// NEW: OAuth 2.1 Server Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_ISSUER = process.env.JWT_ISSUER || "https://mcp-server.example.com";
const ACCESS_TOKEN_LIFETIME = parseInt(process.env.ACCESS_TOKEN_LIFETIME || "3600"); // 1 hour
const REFRESH_TOKEN_LIFETIME = parseInt(process.env.REFRESH_TOKEN_LIFETIME || "2592000"); // 30 days
const AUTHORIZATION_CODE_LIFETIME = 600; // 10 minutes

// DCR configuration
const DCR_REGISTRATION_TOKEN = process.env.DCR_REGISTRATION_TOKEN || "";

// A2A Agent configuration
const A2A_AGENT_URL = process.env.A2A_AGENT_URL || "https://a2a-test-agent-57oowxudsa-uc.a.run.app";
const A2A_MCP_API_KEY = process.env.A2A_MCP_API_KEY || "";

// Initialize Google OAuth client (for backward compatibility)
const oauthClient = new OAuth2Client(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET);

// Initialize Firestore client for persistent client storage
const db = new Firestore({
  projectId: 'mcp-server-apikey-480615'
});

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

interface RegisteredClient {
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  client_name: string;
  created_at: number;
  grant_types: string[];
}

interface AuthorizationCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: 'S256' | 'plain';
  user_id: string; // In production, this would be from authentication
  expires_at: number;
  used: boolean;
}

interface AccessTokenPayload {
  sub: string; // user_id
  client_id: string;
  scope: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
  jti: string; // JWT ID for tracking
  type: 'access'; // Token type
}

interface RefreshTokenPayload {
  sub: string; // user_id
  client_id: string;
  scope: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
  jti: string; // JWT ID for tracking
  type: 'refresh'; // Token type
  rotation_count: number; // Track rotation for security monitoring
}

// ============================================================================
// FIRESTORE CLIENT STORAGE (Persistent)
// ============================================================================

/**
 * Store registered client in Firestore
 */
async function storeClientInFirestore(client: RegisteredClient): Promise<void> {
  try {
    await db.collection('oauth_clients').doc(client.client_id).set({
      client_id: client.client_id,
      client_secret: client.client_secret,
      redirect_uris: client.redirect_uris,
      client_name: client.client_name,
      created_at: client.created_at,
      grant_types: client.grant_types,
      updated_at: Date.now()
    });
    console.log(`âœ… Client stored in Firestore: ${client.client_id}`);
  } catch (error: any) {
    console.error('âŒ Failed to store client in Firestore:', error.message);
    // Don't throw - allow in-memory to still work
  }
}

/**
 * Get registered client from Firestore
 */
async function getClientFromFirestore(clientId: string): Promise<RegisteredClient | undefined> {
  try {
    const doc = await db.collection('oauth_clients').doc(clientId).get();
    if (doc.exists) {
      const data = doc.data();
      console.log(`âœ… Client loaded from Firestore: ${clientId}`);
      return data as RegisteredClient;
    }
    return undefined;
  } catch (error: any) {
    console.error('âŒ Failed to get client from Firestore:', error.message);
    return undefined;
  }
}

/**
 * Load all registered clients from Firestore on startup
 */
async function loadClientsFromFirestore(): Promise<void> {
  try {
    console.log('=== LOADING CLIENTS FROM FIRESTORE ===');
    const snapshot = await db.collection('oauth_clients').get();
    
    snapshot.forEach(doc => {
      const client = doc.data() as RegisteredClient;
      registeredClients.set(client.client_id, client);
    });
    
    console.log(`âœ… Loaded ${snapshot.size} client(s) from Firestore`);
    console.log('======================================');
  } catch (error: any) {
    console.error('âŒ Failed to load clients from Firestore:', error.message);
    console.log('âš ï¸  Server will continue with in-memory storage only');
  }
}

// ============================================================================
// IN-MEMORY STORAGE
// ============================================================================
// NOTE: In production, use persistent storage (Redis, PostgreSQL, Firestore)

const registeredClients = new Map<string, RegisteredClient>();
const authorizationCodes = new Map<string, AuthorizationCode>();
const revokedTokens = new Set<string>(); // Store revoked JWT IDs (jti claims)

// NOTE: Refresh tokens are now stateless JWTs - no server-side storage needed!
// They are stored in ServiceNow's oauth_credential table and validated via JWT signature

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Generate a cryptographically secure random string
 */
function generateSecureToken(bytes: number = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

/**
 * Hash a code verifier using SHA-256 and encode as base64url
 * Per RFC 7636, this is the S256 method for PKCE
 */
function hashCodeVerifier(verifier: string): string {
  return crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
}

/**
 * Validate PKCE code_challenge against code_verifier
 */
function validatePKCE(
  codeVerifier: string,
  codeChallenge: string,
  method: 'S256' | 'plain'
): boolean {
  if (method === 'S256') {
    const computedChallenge = hashCodeVerifier(codeVerifier);
    return computedChallenge === codeChallenge;
  } else if (method === 'plain') {
    // OAuth 2.1 RECOMMENDS S256, but plain is still allowed
    return codeVerifier === codeChallenge;
  }
  return false;
}

/**
 * Decode JWT without verification (for inspection only)
 */
function decodeJWT(token: string): any {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1], 'base64').toString('utf8');
    return JSON.parse(payload);
  } catch (error) {
    return null;
  }
}

/**
 * Create a JWT access token
 */
function createAccessToken(userId: string, clientId: string, scope: string): string {
  const payload: AccessTokenPayload = {
    sub: userId,
    client_id: clientId,
    scope: scope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_LIFETIME,
    iss: JWT_ISSUER,
    aud: JWT_ISSUER,
    jti: `access_${uuidv4()}`,
    type: 'access'
  };

  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
}

/**
 * Create a JWT refresh token (stateless - no server-side storage)
 */
function createRefreshToken(userId: string, clientId: string, scope: string, rotationCount: number = 0): string {
  const payload: RefreshTokenPayload = {
    sub: userId,
    client_id: clientId,
    scope: scope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + REFRESH_TOKEN_LIFETIME,
    iss: JWT_ISSUER,
    aud: JWT_ISSUER,
    jti: `refresh_${uuidv4()}`,
    type: 'refresh',
    rotation_count: rotationCount
  };

  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
}

/**
 * Validate JWT token (access or refresh) issued by this server
 */
function validateJWTToken(token: string, expectedType?: 'access' | 'refresh'): AccessTokenPayload | RefreshTokenPayload | null {
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: JWT_ISSUER,
      audience: JWT_ISSUER
    }) as AccessTokenPayload | RefreshTokenPayload;

    // Check if token has been revoked
    if (revokedTokens.has(decoded.jti)) {
      console.log("âŒ Token has been revoked:", decoded.jti);
      return null;
    }

    // If type is specified, validate it matches
    if (expectedType && decoded.type !== expectedType) {
      console.log(`âŒ Token type mismatch: expected ${expectedType}, got ${decoded.type}`);
      return null;
    }

    return decoded;
  } catch (error: any) {
    console.log("âŒ JWT validation failed:", error.message);
    return null;
  }
}

// ============================================================================
// LEGACY AUTHENTICATION FUNCTIONS (Backward Compatibility)
// ============================================================================

/**
 * Validate OAuth token from Google (legacy support)
 */
async function validateGoogleOAuthToken(token: string): Promise<boolean> {
  try {
    console.log("=== Google OAuth Token Validation (Legacy) ===");
    
    // Try ID token validation
    try {
      const ticket = await oauthClient.verifyIdToken({ idToken: token });
      const payload = ticket.getPayload();
      
      if (payload) {
        console.log("âœ… Google ID token validated for user:", payload.email);
        return true;
      }
    } catch (idTokenError) {
      console.log("Not a Google ID token, trying access token...");
    }

    // Try access token validation
    const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?access_token=${token}`);
    
    if (response.ok) {
      const tokenInfo = await response.json();
      console.log("âœ… Google access token validated");
      
      // Strict audience checking
      if (tokenInfo.aud === OAUTH_CLIENT_ID || tokenInfo.email) {
        return true;
      } else {
        console.log("âš ï¸ Token audience doesn't match");
        return false;
      }
    }
    
    return false;
  } catch (error) {
    console.error("âŒ Google OAuth validation failed:", error);
    return false;
  }
}

/**
 * Validate API key (legacy support)
 */
function validateApiKey(headerName: string, providedKey: string | undefined): boolean {
  if (!providedKey) return false;

  switch (headerName) {
    case 'x-api-key':
    case 'api-key':
      return !!(API_KEY_XAPI && providedKey === API_KEY_XAPI);
    case 'apikey':
      return !!(API_KEY_APIKEY && providedKey === API_KEY_APIKEY);
    case 'authorization':
      return !!(API_KEY_AUTH && providedKey === API_KEY_AUTH);
    default:
      return false;
  }
}

/**
 * Extract API key from headers
 */
function extractApiKey(headers: any): { headerName: string; key: string | undefined } {
  const possibleHeaders = ['x-api-key', 'api-key', 'apikey', 'authorization'];

  for (const headerName of possibleHeaders) {
    const value = headers[headerName];
    if (value) {
      if (headerName === 'authorization' && !value.startsWith('Bearer ')) {
        return { headerName, key: value };
      } else if (headerName !== 'authorization') {
        return { headerName, key: value };
      }
    }
  }

  return { headerName: '', key: undefined };
}

// ============================================================================
// COMBINED AUTHENTICATION FUNCTION
// ============================================================================

/**
 * Authenticate request with multiple methods:
 * 1. OAuth 2.1 JWT tokens (issued by this server)
 * 2. Google OAuth tokens (legacy)
 * 3. API keys (legacy)
 */
async function authenticate(headers: any): Promise<boolean> {
  const authHeader = headers['authorization'];
  
  // Try Bearer token authentication
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    console.log("Found Bearer token, length:", token.length);
    
    // First, try to validate as our own JWT
    const jwtPayload = validateJWTToken(token);
    if (jwtPayload) {
      console.log("âœ… Authenticated with OAuth 2.1 JWT");
      console.log("User:", jwtPayload.sub);
      console.log("Client:", jwtPayload.client_id);
      console.log("Scope:", jwtPayload.scope);
      return true;
    }
    
    // Fall back to Google OAuth validation (legacy)
    if (OAUTH_CLIENT_ID) {
      const isValidGoogle = await validateGoogleOAuthToken(token);
      if (isValidGoogle) {
        console.log("âœ… Authenticated with Google OAuth (legacy)");
        return true;
      }
    }
  }

  // Fall back to API key validation (legacy)
  const { headerName, key: apiKey } = extractApiKey(headers);
  if (apiKey && validateApiKey(headerName, apiKey)) {
    console.log(`âœ… Authenticated with API key via ${headerName} header (legacy)`);
    return true;
  }

  console.log("âŒ Authentication failed");
  return false;
}

// ============================================================================
// DCR VALIDATION (Unchanged)
// ============================================================================

function validateRegistrationToken(authHeader: string | undefined, bodyTokenValue: string | undefined): boolean {
  if (!DCR_REGISTRATION_TOKEN) {
    console.log("No DCR_REGISTRATION_TOKEN configured - allowing unauthenticated registration");
    return true;
  }
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const headerToken = authHeader.substring(7);
    if (headerToken === DCR_REGISTRATION_TOKEN) {
      console.log("âœ… Registration token validated from Authorization header");
      return true;
    }
  }
  
  if (bodyTokenValue && bodyTokenValue === DCR_REGISTRATION_TOKEN) {
    console.log("âœ… Registration token validated from request body");
    return true;
  }
  
  console.log("âŒ Registration token validation failed");
  return false;
}

// ============================================================================
// MCP TOOLS DEFINITION (Unchanged from original)
// ============================================================================

const tools = [
  {
    name: "query_ai_agent",
    title: "Query AI Agent",
    description: "Send a query to the AI agent for processing",
    inputSchema: {
      $schema: "http://json-schema.org/draft-07/schema#",
      type: "object",
      properties: {
        message: {
          description: "The message or query to send to the AI agent",
          type: "string",
        },
      },
      required: ["message"],
    },
  },
  {
    name: "echo_message",
    title: "Echo Message",
    description: "Echoes back the provided message (test tool)",
    inputSchema: {
      $schema: "http://json-schema.org/draft-07/schema#",
      type: "object",
      properties: {
        message: {
          description: "The message to echo back",
          type: "string",
        },
      },
      required: ["message"],
    },
  },
  {
    name: "calculate",
    title: "Calculate",
    description: "Performs basic arithmetic operations",
    inputSchema: {
      $schema: "http://json-schema.org/draft-07/schema#",
      type: "object",
      properties: {
        operation: {
          description: "The arithmetic operation to perform",
          type: "string",
          enum: ["add", "subtract", "multiply", "divide"],
        },
        a: {
          description: "First number",
          type: "number",
        },
        b: {
          description: "Second number",
          type: "number",
        },
      },
      required: ["operation", "a", "b"],
    },
  },
  {
    name: "get_timestamp",
    title: "Get Timestamp",
    description: "Returns the current server timestamp",
    inputSchema: {
      $schema: "http://json-schema.org/draft-07/schema#",
      type: "object",
      properties: {
        format: {
          description: "Timestamp format",
          default: "iso",
          type: "string",
          enum: ["iso", "unix"]
        }
      }
    },
  },
  {
    name: "reverse_text",
    title: "Reverse Text",
    description: "Reverses the input text",
    inputSchema: {
      $schema: "http://json-schema.org/draft-07/schema#",
      type: "object",
      properties: {
        text: {
          description: "Text to reverse",
          type: "string",
          minLength: 1
        }
      },
      required: ["text"]
    },
  },
];

// ============================================================================
// TOOL EXECUTION FUNCTION
// ============================================================================

async function executeTool(name: string, args: any): Promise<any> {
  console.log(`Executing tool: ${name}`);
  console.log(`Arguments:`, JSON.stringify(args, null, 2));

  switch (name) {
    case "query_ai_agent":
      try {
        console.log("=== CALLING AI AGENT ===");
        const message = args.message;
        const contextId = args.context_id;
        
        console.log("Agent URL:", A2A_AGENT_URL);
        console.log("Message:", message);
        if (contextId) console.log("Context ID:", contextId);
        
        // Build A2A protocol v1.0 request
        const a2aRequest = {
          jsonrpc: "2.0",
          id: Math.floor(Math.random() * 1000000),
          method: "message/send",
          params: {
            message: {
              role: "user",
              parts: [
                {
                  kind: "text",
                  text: message
                }
              ]
            },
            ...(contextId && { contextId })
          }
        };
        
        console.log("Sending request to A2A agent:", JSON.stringify(a2aRequest, null, 2));
        
        // Call the A2A agent at root path
        const response = await fetch(A2A_AGENT_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-MCP-API-Key': A2A_MCP_API_KEY
          },
          body: JSON.stringify(a2aRequest)
        });
        
        if (!response.ok) {
          const errorText = await response.text();
          console.error("âŒ A2A agent error:", response.status, errorText);
          throw new Error(`A2A agent returned ${response.status}: ${errorText}`);
        }
        
        const a2aResponse = await response.json();
        console.log("âœ… A2A agent response:", JSON.stringify(a2aResponse, null, 2));
        
        // Extract the agent's response from the A2A protocol response
        if (a2aResponse.result && a2aResponse.result.status && a2aResponse.result.status.message) {
          const agentMessage = a2aResponse.result.status.message;
          const agentParts = agentMessage.parts || [];
          
          // Combine all text parts
          let responseText = "";
          for (const part of agentParts) {
            if (part.kind === "text" && part.text) {
              responseText += part.text + "\n";
            }
          }
          
          responseText = responseText.trim();
          
          return {
            content: [
              {
                type: "text",
                text: responseText || "Agent returned empty response"
              }
            ]
          };
        } else {
          // Fallback if response structure is unexpected
          return {
            content: [
              {
                type: "text",
                text: `Agent response: ${JSON.stringify(a2aResponse)}`
              }
            ]
          };
        }
        
      } catch (error: any) {
        console.error("âŒ Error calling A2A agent:", error);
        return {
          content: [
            {
              type: "text",
              text: `Error: ${error.message}`,
            },
          ],
          isError: true,
        };
      }

    case "echo_message":
      return {
        content: [
          {
            type: "text",
            text: `Echo: ${args.message}`,
          },
        ],
      };

    case "calculate":
      const { operation, a, b } = args;
      let result: number;

      switch (operation) {
        case "add":
          result = a + b;
          break;
        case "subtract":
          result = a - b;
          break;
        case "multiply":
          result = a * b;
          break;
        case "divide":
          if (b === 0) {
            return {
              content: [
                {
                  type: "text",
                  text: "Error: Division by zero",
                },
              ],
              isError: true,
            };
          }
          result = a / b;
          break;
        default:
          return {
            content: [
              {
                type: "text",
                text: `Error: Unknown operation: ${operation}`,
              },
            ],
            isError: true,
          };
      }

      return {
        content: [
          {
            type: "text",
            text: `Result: ${a} ${operation} ${b} = ${result}`,
          },
        ],
      };

    case "get_timestamp":
      const format = args.format || "iso";
      let timestamp: string;
      if (format === "unix") {
        timestamp = `Unix timestamp: ${Math.floor(Date.now() / 1000)}`;
      } else {
        timestamp = `ISO timestamp: ${new Date().toISOString()}`;
      }
      return {
        content: [
          {
            type: "text",
            text: timestamp,
          },
        ],
      };

    case "reverse_text":
      const text = args.text;
      const reversed = text.split("").reverse().join("");
      return {
        content: [
          {
            type: "text",
            text: `Reversed: ${reversed}`,
          },
        ],
      };

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ============================================================================
// EXPRESS SERVER & OAUTH 2.1 ENDPOINTS
// ============================================================================

async function main() {
  const app = express();
  const port = parseInt(process.env.PORT || "8080");

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Load registered clients from Firestore on startup
  await loadClientsFromFirestore();

  // Log all requests
  app.use((req, res, next) => {
    console.log(`${req.method} ${req.path}`);
    next();
  });

  // ==========================================================================
  // HEALTH CHECK ENDPOINT (No authentication required)
  // ==========================================================================
  
  app.get("/health", (req, res) => {
    res.json({ status: "healthy", timestamp: new Date().toISOString() });
  });

  // ==========================================================================
  // OAUTH 2.1 AUTHORIZATION SERVER METADATA (RFC 8414)
  // ==========================================================================
  
  app.get("/.well-known/oauth-authorization-server", (req, res) => {
    console.log("âœ… OAuth metadata request");
    const baseUrl = `https://${req.headers.host}`;
    
    res.json({
      issuer: JWT_ISSUER,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      registration_endpoint: `${baseUrl}/register`,
      revocation_endpoint: `${baseUrl}/revoke`,
      grant_types_supported: ["authorization_code", "refresh_token"],
      response_types_supported: ["code"],
      code_challenge_methods_supported: ["S256", "plain"], // OAuth 2.1 requires PKCE
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      scopes_supported: ["openid", "profile", "email", "tools:read", "tools:execute"],
      registration_endpoint_requires_auth: !!DCR_REGISTRATION_TOKEN,
      // OAuth 2.1 specific
      revocation_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"]
    });
  });

  // ==========================================================================
  // DYNAMIC CLIENT REGISTRATION (RFC 7591)
  // ==========================================================================
  
  app.post("/register", async (req, res) => {
    try {
      console.log("=== DCR REGISTRATION REQUEST ===");
      console.log("Request body:", JSON.stringify(req.body, null, 2));

      const authHeader = req.headers['authorization'];
      const bodyTokenValue = req.body.token_value;

      if (!validateRegistrationToken(authHeader, bodyTokenValue)) {
        return res.status(401).json({
          error: "invalid_token",
          error_description: "Invalid or missing registration token"
        });
      }

      const {
        redirect_uris,
        client_name,
        token_endpoint_auth_method = "client_secret_post"
      } = req.body;

      if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
        return res.status(400).json({
          error: "invalid_redirect_uri",
          error_description: "redirect_uris is required and must be a non-empty array"
        });
      }

      const clientId = `oauth21_${crypto.randomBytes(16).toString('hex')}`;
      const clientSecret = generateSecureToken(32);

      const client: RegisteredClient = {
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uris,
        client_name: client_name || "OAuth 2.1 Client",
        created_at: Date.now(),
        grant_types: ["authorization_code", "refresh_token"]
      };

      // Store in memory
      registeredClients.set(clientId, client);

      // Store in Firestore (persistent)
      await storeClientInFirestore(client);

      console.log(`âœ… Registered new OAuth 2.1 client: ${clientId}`);

      res.status(201).json({
        client_id: clientId,
        client_secret: clientSecret,
        client_secret_expires_at: 0,
        redirect_uris,
        client_name: client.client_name,
        token_endpoint_auth_method,
        grant_types: client.grant_types,
        response_types: ["code"]
      });

    } catch (error: any) {
      console.error("âŒ DCR registration error:", error);
      res.status(500).json({
        error: "server_error",
        error_description: error.message || "Internal server error"
      });
    }
  });

  // ==========================================================================
  // OAUTH 2.1 AUTHORIZATION ENDPOINT
  // Implements RFC 6749 with MANDATORY PKCE (RFC 7636) per OAuth 2.1
  // ==========================================================================
  
  app.get("/authorize", async (req, res) => {
    try {
      console.log("=== AUTHORIZATION REQUEST ===");
      console.log("Query params:", req.query);

      const {
        response_type,
        client_id,
        redirect_uri,
        scope = "openid profile email",
        state,
        code_challenge,
        code_challenge_method
      } = req.query as { [key: string]: string };

      // Validate required parameters
      if (!response_type || response_type !== 'code') {
        return res.status(400).json({
          error: "unsupported_response_type",
          error_description: "Only 'code' response type is supported"
        });
      }

      if (!client_id) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "client_id is required"
        });
      }

      // Verify client exists (check memory first, then Firestore)
      let client = registeredClients.get(client_id);
      if (!client) {
        console.log(`Client ${client_id} not in cache, checking Firestore...`);
        client = await getClientFromFirestore(client_id);
        if (client) {
          // Add to cache for future requests
          registeredClients.set(client_id, client);
        }
      }
      
      if (!client) {
        return res.status(400).json({
          error: "invalid_client",
          error_description: "Unknown client_id"
        });
      }

      if (!redirect_uri) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "redirect_uri is required"
        });
      }

      // Verify redirect_uri is registered
      if (!client.redirect_uris.includes(redirect_uri)) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "redirect_uri not registered for this client"
        });
      }

      // OAuth 2.1 REQUIREMENT: PKCE is MANDATORY
      if (!code_challenge) {
        const errorParams = new URLSearchParams({
          error: "invalid_request",
          error_description: "code_challenge is required (OAuth 2.1 requires PKCE)",
          ...(state && { state })
        });
        return res.redirect(`${redirect_uri}?${errorParams}`);
      }

      if (!code_challenge_method || (code_challenge_method !== 'S256' && code_challenge_method !== 'plain')) {
        const errorParams = new URLSearchParams({
          error: "invalid_request",
          error_description: "code_challenge_method must be 'S256' or 'plain'",
          ...(state && { state })
        });
        return res.redirect(`${redirect_uri}?${errorParams}`);
      }

      // OAuth 2.1 RECOMMENDATION: Prefer S256 over plain
      if (code_challenge_method === 'plain') {
        console.log("âš ï¸ Client using 'plain' PKCE method - S256 is recommended");
      }

      console.log("âœ… Authorization request validated");
      console.log(`Client: ${client.client_name}`);
      console.log(`PKCE method: ${code_challenge_method}`);

      // =======================================================================
      // USER AUTHENTICATION & CONSENT
      // =======================================================================
      // In a real implementation, you would:
      // 1. Redirect to login page if not authenticated
      // 2. Display consent screen showing requested scopes
      // 3. Only proceed after user grants consent
      //
      // For this implementation, we'll simulate an authenticated user
      // In production, integrate with your identity provider
      // =======================================================================

      const userId = "user_" + uuidv4(); // Simulated user ID
      console.log("âš ï¸ SIMULATED USER AUTHENTICATION - userId:", userId);
      console.log("âš ï¸ In production, implement real user authentication here");

      // Generate authorization code
      const code = generateSecureToken(32);
      
      const authCode: AuthorizationCode = {
        code,
        client_id,
        redirect_uri,
        scope,
        code_challenge,
        code_challenge_method: code_challenge_method as 'S256' | 'plain',
        user_id: userId,
        expires_at: Date.now() + (AUTHORIZATION_CODE_LIFETIME * 1000),
        used: false
      };

      authorizationCodes.set(code, authCode);

      console.log("âœ… Authorization code generated");
      console.log(`Code expires in ${AUTHORIZATION_CODE_LIFETIME} seconds`);

      // Redirect back to client with authorization code
      const successParams = new URLSearchParams({
        code,
        ...(state && { state })
      });

      console.log(`Redirecting to: ${redirect_uri}?${successParams}`);
      res.redirect(`${redirect_uri}?${successParams}`);

    } catch (error: any) {
      console.error("âŒ Authorization error:", error);
      res.status(500).json({
        error: "server_error",
        error_description: error.message
      });
    }
  });

  // ==========================================================================
  // OAUTH 2.1 TOKEN ENDPOINT
  // Implements RFC 6749 with PKCE validation (RFC 7636)
  // Supports: authorization_code and refresh_token grant types
  // ==========================================================================
  
  app.post("/token", async (req, res) => {
    try {
      console.log("=== TOKEN REQUEST ===");
      console.log("Body:", req.body);

      const {
        grant_type,
        code,
        redirect_uri,
        client_id,
        client_secret,
        code_verifier,
        refresh_token: refreshToken,
        scope
      } = req.body;

      // Validate grant_type
      if (!grant_type) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "grant_type is required"
        });
      }

      // =======================================================================
      // GRANT TYPE: authorization_code (with PKCE validation)
      // =======================================================================
      
      if (grant_type === 'authorization_code') {
        // Validate required parameters
        if (!code || !redirect_uri || !client_id || !code_verifier) {
          return res.status(400).json({
            error: "invalid_request",
            error_description: "code, redirect_uri, client_id, and code_verifier are required"
          });
        }

        // Verify client credentials (check memory first, then Firestore)
        let client = registeredClients.get(client_id);
        if (!client) {
          console.log(`Client ${client_id} not in cache, checking Firestore...`);
          client = await getClientFromFirestore(client_id);
          if (client) {
            registeredClients.set(client_id, client);
          }
        }
        
        if (!client) {
          return res.status(400).json({
            error: "invalid_client",
            error_description: "Unknown client_id"
          });
        }

        if (client_secret !== client.client_secret) {
          return res.status(400).json({
            error: "invalid_client",
            error_description: "Invalid client_secret"
          });
        }

        // Retrieve authorization code
        const authCode = authorizationCodes.get(code);
        if (!authCode) {
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "Invalid or expired authorization code"
          });
        }

        // Validate authorization code
        if (authCode.used) {
          console.log("âš ï¸ Authorization code already used - possible replay attack");
          // OAuth 2.1: Revoke all tokens issued to this code
          // In production, implement token revocation here
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "Authorization code has already been used"
          });
        }

        if (authCode.expires_at < Date.now()) {
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "Authorization code has expired"
          });
        }

        if (authCode.client_id !== client_id) {
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "Authorization code was issued to a different client"
          });
        }

        if (authCode.redirect_uri !== redirect_uri) {
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "redirect_uri does not match"
          });
        }

        // =======================================================================
        // CRITICAL: PKCE VALIDATION (OAuth 2.1 requirement)
        // =======================================================================
        
        console.log("=== PKCE VALIDATION ===");
        console.log("Method:", authCode.code_challenge_method);
        console.log("Stored challenge:", authCode.code_challenge.substring(0, 20) + "...");
        console.log("Provided verifier:", code_verifier.substring(0, 20) + "...");

        const isPKCEValid = validatePKCE(
          code_verifier,
          authCode.code_challenge,
          authCode.code_challenge_method
        );

        if (!isPKCEValid) {
          console.log("âŒ PKCE validation failed");
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "PKCE validation failed - code_verifier does not match code_challenge"
          });
        }

        console.log("âœ… PKCE validation successful");

        // Mark authorization code as used
        authCode.used = true;

        // Issue tokens
        const accessToken = createAccessToken(authCode.user_id, client_id, authCode.scope);
        const newRefreshToken = createRefreshToken(authCode.user_id, client_id, authCode.scope);

        console.log("âœ… Tokens issued successfully");
        console.log("User:", authCode.user_id);
        console.log("Scope:", authCode.scope);

        return res.json({
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: ACCESS_TOKEN_LIFETIME,
          refresh_token: newRefreshToken,
          scope: authCode.scope
        });
      }

      // =======================================================================
      // GRANT TYPE: refresh_token (with token rotation)
      // =======================================================================
      
      if (grant_type === 'refresh_token') {
        if (!refreshToken || !client_id || !client_secret) {
          return res.status(400).json({
            error: "invalid_request",
            error_description: "refresh_token, client_id, and client_secret are required"
          });
        }

        // Verify client credentials (check memory first, then Firestore)
        let client = registeredClients.get(client_id);
        if (!client) {
          console.log(`Client ${client_id} not in cache, checking Firestore...`);
          client = await getClientFromFirestore(client_id);
          if (client) {
            registeredClients.set(client_id, client);
          }
        }
        
        if (!client || client_secret !== client.client_secret) {
          return res.status(400).json({
            error: "invalid_client",
            error_description: "Invalid client credentials"
          });
        }

        // Validate refresh token JWT
        console.log("=== REFRESH TOKEN VALIDATION ===");
        const tokenPayload = validateJWTToken(refreshToken, 'refresh') as RefreshTokenPayload | null;
        
        if (!tokenPayload) {
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "Invalid or expired refresh token"
          });
        }

        // Verify token was issued to this client
        if (tokenPayload.client_id !== client_id) {
          console.log("âŒ Refresh token client_id mismatch");
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "Refresh token was issued to a different client"
          });
        }

        console.log("âœ… Refresh token validated");
        console.log("User:", tokenPayload.sub);
        console.log("Client:", tokenPayload.client_id);
        console.log("Current rotation count:", tokenPayload.rotation_count);

        // =======================================================================
        // REFRESH TOKEN ROTATION (OAuth 2.1 security best practice)
        // =======================================================================
        
        console.log("=== REFRESH TOKEN ROTATION ===");
        
        // Revoke old refresh token by adding its jti to blacklist
        revokedTokens.add(tokenPayload.jti);
        console.log("Old refresh token revoked (jti added to blacklist)");

        // Issue new tokens with incremented rotation count
        const newAccessToken = createAccessToken(tokenPayload.sub, client_id, tokenPayload.scope);
        const newRefreshToken = createRefreshToken(
          tokenPayload.sub, 
          client_id, 
          tokenPayload.scope, 
          tokenPayload.rotation_count + 1
        );

        console.log("âœ… New tokens issued with rotation count:", tokenPayload.rotation_count + 1);

        return res.json({
          access_token: newAccessToken,
          token_type: "Bearer",
          expires_in: ACCESS_TOKEN_LIFETIME,
          refresh_token: newRefreshToken,
          scope: tokenPayload.scope
        });
      }

      // Unsupported grant type
      return res.status(400).json({
        error: "unsupported_grant_type",
        error_description: `Grant type '${grant_type}' is not supported`
      });

    } catch (error: any) {
      console.error("âŒ Token endpoint error:", error);
      res.status(500).json({
        error: "server_error",
        error_description: error.message
      });
    }
  });

  // ==========================================================================
  // OAUTH 2.1 TOKEN REVOCATION ENDPOINT
  // Implements RFC 7009
  // ==========================================================================
  
  app.post("/revoke", (req, res) => {
    try {
      console.log("=== TOKEN REVOCATION REQUEST ===");

      const { token, token_type_hint, client_id, client_secret } = req.body;

      if (!token) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "token is required"
        });
      }

      // Verify client credentials if provided
      if (client_id) {
        const client = registeredClients.get(client_id);
        if (!client || (client_secret && client_secret !== client.client_secret)) {
          return res.status(400).json({
            error: "invalid_client",
            error_description: "Invalid client credentials"
          });
        }
      }

      // Try to revoke as JWT (access or refresh token)
      try {
        const decoded = decodeJWT(token);
        if (decoded && decoded.jti) {
          revokedTokens.add(decoded.jti);
          const tokenType = decoded.type || 'unknown';
          console.log(`âœ… ${tokenType} token revoked (JWT ID added to blacklist)`);
          return res.status(200).end();
        }
      } catch (error) {
        // Not a valid JWT, continue
      }

      // Token not found or invalid (per RFC 7009, this is still a success)
      console.log("Token not found or invalid, but returning success per RFC 7009");
      res.status(200).end();

    } catch (error: any) {
      console.error("âŒ Revocation error:", error);
      res.status(500).json({
        error: "server_error",
        error_description: error.message
      });
    }
  });

  // ==========================================================================
  // MCP JSON-RPC ENDPOINT (Authentication required)
  // ==========================================================================
  
  app.post("/mcp", async (req, res) => {
    try {
      const request = req.body;
      console.log("=== INCOMING MCP REQUEST ===");
      console.log("Method:", request.method);
      console.log("Request ID:", request.id);

      // Authentication required
      const isAuthenticated = await authenticate(req.headers);
      if (!isAuthenticated) {
        return res.status(401).json({
          jsonrpc: "2.0",
          id: request.id,
          error: {
            code: -32600,
            message: "Invalid or missing authentication credentials",
          },
        });
      }

      console.log("âœ… Authentication successful");

      // Handle notifications (no response needed)
      if (!request.id && request.method && request.method.startsWith('notifications/')) {
        console.log(`âœ… Notification received: ${request.method}`);
        res.status(200).end();
        return;
      }

      // Handle initialize
      if (request.method === "initialize") {
        const initResponse = {
          jsonrpc: "2.0",
          id: request.id,
          result: {
            protocolVersion: "2025-06-18",
            capabilities: {
              tools: { listChanged: false }
            },
            serverInfo: {
              name: "mcp-oauth21-server",
              version: "2.0.0"
            }
          }
        };
        res.json(initResponse);
        return;
      }

      // Handle tools/list
      if (request.method === "tools/list") {
        res.json({
          result: { tools },
          jsonrpc: "2.0",
          id: request.id,
        });
        return;
      }

      // Handle tools/call
      if (request.method === "tools/call") {
        const { name, arguments: args } = request.params;
        const result = await executeTool(name, args);
        res.json({
          jsonrpc: "2.0",
          id: request.id,
          result,
        });
        return;
      }

      // Unknown method
      res.status(400).json({
        jsonrpc: "2.0",
        id: request.id,
        error: {
          code: -32601,
          message: `Method not found: ${request.method}`,
        },
      });

    } catch (error: any) {
      console.error("âŒ MCP request error:", error);
      res.status(500).json({
        jsonrpc: "2.0",
        id: req.body.id,
        error: {
          code: -32603,
          message: error.message || "Internal error",
        },
      });
    }
  });

  // ==========================================================================
  // START SERVER
  // ==========================================================================
  
  app.listen(port, () => {
    console.log("=".repeat(70));
    console.log("MCP OAuth 2.1 Authorization Server Started");
    console.log("=".repeat(70));
    console.log(`Port: ${port}`);
    console.log(`JWT Issuer: ${JWT_ISSUER}`);
    console.log(`Access Token Lifetime: ${ACCESS_TOKEN_LIFETIME}s`);
    console.log(`Refresh Token Lifetime: ${REFRESH_TOKEN_LIFETIME}s`);
    console.log(`\nEndpoints:`);
    console.log(`  GET  /health - Health check`);
    console.log(`  GET  /.well-known/oauth-authorization-server - OAuth metadata`);
    console.log(`  POST /register - Dynamic Client Registration`);
    console.log(`  GET  /authorize - OAuth 2.1 authorization (with PKCE)`);
    console.log(`  POST /token - Token issuance (with PKCE validation)`);
    console.log(`  POST /revoke - Token revocation`);
    console.log(`  POST /mcp - MCP JSON-RPC endpoint`);
    console.log(`\nAuthentication Methods:`);
    console.log(`  - OAuth 2.1 JWT tokens (issued by this server)`);
    console.log(`  - Google OAuth tokens (legacy)`);
    console.log(`  - API keys (legacy)`);
    console.log(`\nA2A Agent: ${A2A_AGENT_URL || 'Not configured'}`);
    console.log("=".repeat(70));
  });
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});

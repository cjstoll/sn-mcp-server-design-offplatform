"""
MCP Server Implementation - Python/FastAPI Template
OAuth 2.1 with PKCE Authentication

This template provides a production-ready reference implementation for building
an MCP (Model Context Protocol) server with OAuth 2.1 + PKCE authentication using
Python and FastAPI.

Requirements:
- Python 3.9+
- fastapi
- uvicorn[standard]
- pyjwt
- cryptography
- python-multipart

Install dependencies:
    pip install fastapi uvicorn[standard] pyjwt cryptography python-multipart

Run server:
    uvicorn mcp_server_oauth21:app --host 0.0.0.0 --port 3000 --reload

Environment Variables (Required):
- JWT_SECRET: Secret key for signing JWT tokens (minimum 256 bits)
- JWT_ISSUER: Issuer URL (e.g., https://mcp-server.example.com)

Environment Variables (Optional):
- DCR_TOKEN: Authorization token for Dynamic Client Registration endpoint
- SERVER_PORT: Server port (default: 3000)
"""

import hashlib
import base64
import secrets
import time
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from enum import Enum
from uuid import uuid4

from fastapi import FastAPI, Request, Response, HTTPException, Header, Depends, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
import jwt

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

# Server Configuration
SERVER_PORT = int(os.getenv("SERVER_PORT", "3000"))
JWT_ISSUER = os.getenv("JWT_ISSUER", "https://mcp-server.example.com")
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"

# Optional DCR Token
DCR_REGISTRATION_TOKEN = os.getenv("DCR_TOKEN")

# Token Lifetimes (seconds)
AUTHORIZATION_CODE_LIFETIME = 300  # 5 minutes
ACCESS_TOKEN_LIFETIME = 3600  # 1 hour
REFRESH_TOKEN_LIFETIME = 2592000  # 30 days

# Rate Limiting Configuration
RATE_LIMIT_WINDOW = 900  # 15 minutes
RATE_LIMIT_MAX_REQUESTS = 100
OAUTH_RATE_LIMIT_MAX = 10

# MCP Protocol Configuration
MCP_PROTOCOL_VERSION = "2025-06-18"
MCP_SERVER_NAME = "mcp-oauth21-server"
MCP_SERVER_VERSION = "3.3.0"

# PKCE Configuration
SUPPORTED_PKCE_METHODS = ["S256", "plain"]

# Validate required configuration
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable is required")

# ============================================================================
# DATA MODELS (Pydantic)
# ============================================================================

class GrantType(str, Enum):
    """OAuth 2.1 grant types"""
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"

class TokenType(str, Enum):
    """JWT token types"""
    ACCESS = "access"
    REFRESH = "refresh"

# --- Dynamic Client Registration Models ---

class DCRRequest(BaseModel):
    """Dynamic Client Registration request"""
    client_name: Optional[str] = "Unnamed Client"
    redirect_uris: List[str] = Field(..., min_items=1)
    grant_types: Optional[List[str]] = ["authorization_code", "refresh_token"]
    response_types: Optional[List[str]] = ["code"]
    use_pkce: Optional[bool] = False

class DCRResponse(BaseModel):
    """Dynamic Client Registration response (RFC 7591)"""
    client_id: str
    client_secret: str
    client_name: str
    redirect_uris: List[str]
    grant_types: List[str]
    response_types: List[str]
    token_endpoint_auth_method: str = "client_secret_post"

# --- OAuth 2.1 Models ---

class TokenRequest(BaseModel):
    """OAuth 2.1 token request"""
    grant_type: GrantType
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    client_id: str
    client_secret: str
    code_verifier: Optional[str] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None

class TokenResponse(BaseModel):
    """OAuth 2.1 token response"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str
    scope: str

class TokenRevocationRequest(BaseModel):
    """OAuth 2.1 token revocation request (RFC 7009)"""
    token: str
    client_id: Optional[str] = None
    client_secret: Optional[str] = None

# --- MCP Protocol Models ---

class MCPRequest(BaseModel):
    """MCP JSON-RPC 2.0 request"""
    jsonrpc: str = "2.0"
    method: str
    params: Optional[Dict[str, Any]] = None
    id: Optional[str] = None

class MCPError(BaseModel):
    """MCP JSON-RPC 2.0 error"""
    code: int
    message: str
    data: Optional[Any] = None

class MCPResponse(BaseModel):
    """MCP JSON-RPC 2.0 response"""
    jsonrpc: str = "2.0"
    id: Optional[str] = None
    result: Optional[Any] = None
    error: Optional[MCPError] = None

# --- Internal Data Models ---

class ClientRecord(BaseModel):
    """Registered OAuth client"""
    client_id: str
    client_secret: str
    client_name: str
    redirect_uris: List[str]
    grant_types: List[str]
    response_types: List[str]
    use_pkce: bool
    created_at: float

class AuthCodeRecord(BaseModel):
    """Authorization code with PKCE parameters"""
    code: str
    client_id: str
    redirect_uri: str
    scope: str
    code_challenge: str
    code_challenge_method: str
    user_id: str
    expires_at: float
    used: bool = False

class JWTPayload(BaseModel):
    """JWT token payload"""
    sub: str  # user_id
    client_id: str
    scope: str
    type: TokenType
    iat: float
    exp: float
    iss: str
    jti: str
    rotation_count: Optional[int] = None  # For refresh tokens

# ============================================================================
# IN-MEMORY STORAGE
# ============================================================================
# NOTE: Replace with persistent storage in production
# Options: Redis, PostgreSQL, MongoDB, etc.
# See implementation notes at bottom of file for guidance

registered_clients: Dict[str, ClientRecord] = {}
authorization_codes: Dict[str, AuthCodeRecord] = {}
revoked_tokens: Set[str] = set()  # Token JTI blacklist

# Rate limiting storage
rate_limit_store: Dict[str, Dict[str, Any]] = {}

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="MCP OAuth 2.1 Server",
    description="Model Context Protocol server with OAuth 2.1 + PKCE authentication",
    version=MCP_SERVER_VERSION,
)

# Configure CORS (adjust for your deployment)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)

def generate_uuid() -> str:
    """Generate UUID v4"""
    return str(uuid4())

def current_timestamp() -> float:
    """Get current Unix timestamp"""
    return time.time()

def base64url_encode(data: bytes) -> str:
    """Base64 URL-safe encoding (RFC 4648)"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def sha256_hash(data: str) -> bytes:
    """SHA-256 hash"""
    return hashlib.sha256(data.encode('utf-8')).digest()

# ============================================================================
# PKCE VALIDATION
# ============================================================================

def validate_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """
    Validate PKCE code_verifier against stored code_challenge
    
    Args:
        code_verifier: Original random string from client
        code_challenge: Stored challenge from authorization request
        method: Challenge method (S256 or plain)
    
    Returns:
        True if valid, False otherwise
    """
    if method == "S256":
        # Hash the code_verifier using SHA-256
        computed_challenge = base64url_encode(sha256_hash(code_verifier))
        return computed_challenge == code_challenge
    elif method == "plain":
        # Direct comparison (discouraged but allowed)
        return code_verifier == code_challenge
    else:
        return False

# ============================================================================
# JWT TOKEN MANAGEMENT
# ============================================================================

def create_access_token(user_id: str, client_id: str, scope: str) -> str:
    """
    Create JWT access token
    
    Args:
        user_id: User identifier
        client_id: OAuth client identifier
        scope: Token scope
    
    Returns:
        Signed JWT access token
    """
    token_jti = generate_uuid()
    now = current_timestamp()
    
    payload = {
        "sub": user_id,
        "client_id": client_id,
        "scope": scope,
        "type": TokenType.ACCESS.value,
        "iat": now,
        "exp": now + ACCESS_TOKEN_LIFETIME,
        "iss": JWT_ISSUER,
        "jti": token_jti,
    }
    
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def create_refresh_token(
    user_id: str, 
    client_id: str, 
    scope: str, 
    rotation_count: int = 0
) -> str:
    """
    Create JWT refresh token with rotation counter
    
    Args:
        user_id: User identifier
        client_id: OAuth client identifier
        scope: Token scope
        rotation_count: Number of times token has been rotated
    
    Returns:
        Signed JWT refresh token
    """
    token_jti = generate_uuid()
    now = current_timestamp()
    
    payload = {
        "sub": user_id,
        "client_id": client_id,
        "scope": scope,
        "type": TokenType.REFRESH.value,
        "rotation_count": rotation_count,
        "iat": now,
        "exp": now + REFRESH_TOKEN_LIFETIME,
        "iss": JWT_ISSUER,
        "jti": token_jti,
    }
    
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify and decode JWT token
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded token payload if valid, None otherwise
    """
    try:
        # Verify signature, expiration, and issuer
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
        )
        
        # Check if token has been revoked
        if payload.get("jti") in revoked_tokens:
            print(f"âœ— Token has been revoked: {payload.get('jti')}")
            return None
        
        print(f"âœ“ Token validated for client: {payload.get('client_id')}")
        return payload
        
    except jwt.ExpiredSignatureError:
        print("âœ— Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"âœ— Invalid token: {e}")
        return None

# ============================================================================
# TOKEN BLACKLIST MANAGEMENT
# ============================================================================

def add_token_to_blacklist(token_jti: str, expiration: float):
    """
    Add token to revocation blacklist
    
    Args:
        token_jti: Token unique identifier
        expiration: Token expiration timestamp
    
    NOTE: In production, use Redis with TTL for automatic cleanup:
        redis_client.setex(f"revoked:{token_jti}", ttl, "1")
    """
    revoked_tokens.add(token_jti)
    print(f"âœ“ Token blacklisted: {token_jti}")

def is_token_revoked(token_jti: str) -> bool:
    """
    Check if token is revoked
    
    Args:
        token_jti: Token unique identifier
    
    Returns:
        True if revoked, False otherwise
    """
    return token_jti in revoked_tokens

# ============================================================================
# RATE LIMITING
# ============================================================================

async def rate_limit_check(
    request: Request, 
    max_requests: int = RATE_LIMIT_MAX_REQUESTS
):
    """
    Rate limiting middleware
    
    Args:
        request: FastAPI request object
        max_requests: Maximum requests per window
    
    Raises:
        HTTPException: If rate limit exceeded
    
    NOTE: In production, use Redis for distributed rate limiting:
        pipe = redis_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, RATE_LIMIT_WINDOW)
        count, _ = pipe.execute()
    """
    # Identify client by IP address
    client_ip = request.client.host
    client_key = f"ip:{client_ip}"
    
    now = current_timestamp()
    
    if client_key not in rate_limit_store:
        # Start new window
        rate_limit_store[client_key] = {
            "count": 1,
            "reset_time": now + RATE_LIMIT_WINDOW
        }
        return
    
    record = rate_limit_store[client_key]
    
    if now >= record["reset_time"]:
        # Window expired, start new window
        rate_limit_store[client_key] = {
            "count": 1,
            "reset_time": now + RATE_LIMIT_WINDOW
        }
        return
    
    # Increment counter
    record["count"] += 1
    
    if record["count"] > max_requests:
        # Rate limit exceeded
        print(f"âš ï¸ Rate limit exceeded for: {client_key}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={
                "X-RateLimit-Limit": str(max_requests),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(record["reset_time"])),
                "Retry-After": str(int(record["reset_time"] - now)),
            }
        )

# ============================================================================
# AUTHENTICATION MIDDLEWARE
# ============================================================================

async def verify_bearer_token(authorization: str = Header(...)) -> Dict[str, Any]:
    """
    Verify Bearer token from Authorization header
    
    Args:
        authorization: Authorization header value
    
    Returns:
        Decoded token payload
    
    Raises:
        HTTPException: If token is invalid or missing
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format",
        )
    
    token = authorization[7:]  # Remove "Bearer "
    payload = verify_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    
    return payload

# ============================================================================
# OAUTH 2.1 ENDPOINTS
# ============================================================================

@app.post("/register", response_model=DCRResponse, status_code=201)
async def dynamic_client_registration(
    request: DCRRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Dynamic Client Registration (RFC 7591)
    
    Allows clients to self-register and obtain OAuth credentials.
    Optionally protected by DCR authorization token.
    """
    print("=== DCR REQUEST ===")
    
    # Optional: Validate DCR authorization token
    if DCR_REGISTRATION_TOKEN:
        if not authorization:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authorization header",
            )
        
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization format",
            )
        
        provided_token = authorization[7:]
        if provided_token != DCR_REGISTRATION_TOKEN:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid registration token",
            )
        
        print("âœ“ DCR token validated")
    
    # Generate unique client credentials
    client_id = generate_uuid()
    client_secret = generate_secure_token(32)
    
    # Create client record
    client = ClientRecord(
        client_id=client_id,
        client_secret=client_secret,
        client_name=request.client_name,
        redirect_uris=request.redirect_uris,
        grant_types=request.grant_types,
        response_types=request.response_types,
        use_pkce=request.use_pkce,
        created_at=current_timestamp(),
    )
    
    # Store client
    # NOTE: In production, store in database with proper indexing
    registered_clients[client_id] = client
    
    print(f"âœ“ Client registered: {client_id}")
    print(f"Client name: {request.client_name}")
    print(f"PKCE enabled: {request.use_pkce}")
    
    return DCRResponse(
        client_id=client_id,
        client_secret=client_secret,
        client_name=request.client_name,
        redirect_uris=request.redirect_uris,
        grant_types=request.grant_types,
        response_types=request.response_types,
    )

@app.get("/oauth/authorize")
async def authorization_endpoint(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid email profile",
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
):
    """
    OAuth 2.1 Authorization Endpoint
    
    Initiates authorization code flow with PKCE.
    In production, this should display user consent screen.
    """
    print("=== AUTHORIZATION REQUEST ===")
    
    # Validate response_type
    if response_type != "code":
        return RedirectResponse(
            url=f"{redirect_uri}?error=unsupported_response_type&state={state or ''}"
        )
    
    # PKCE is mandatory in OAuth 2.1
    if not code_challenge or not code_challenge_method:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="PKCE required: code_challenge and code_challenge_method must be provided",
        )
    
    # Validate PKCE method
    if code_challenge_method not in SUPPORTED_PKCE_METHODS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"code_challenge_method must be one of: {SUPPORTED_PKCE_METHODS}",
        )
    
    # Validate client exists
    if client_id not in registered_clients:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Client not found",
        )
    
    client = registered_clients[client_id]
    print(f"âœ“ Client validated: {client_id}")
    
    # Validate redirect_uri is registered
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="redirect_uri not registered for this client",
        )
    
    print("âœ“ Redirect URI validated")
    print("âœ“ PKCE parameters validated")
    print(f"Method: {code_challenge_method}")
    
    # NOTE: In production, display user consent screen here
    # For service-to-service, auto-approve with simulated user
    user_id = generate_uuid()
    
    print(f"âš ï¸ SIMULATED USER AUTHENTICATION - user_id: {user_id}")
    print("âš ï¸ In production, implement real user authentication here")
    
    # Generate authorization code
    auth_code = generate_secure_token(32)
    
    # Store authorization code with PKCE parameters
    code_record = AuthCodeRecord(
        code=auth_code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        user_id=user_id,
        expires_at=current_timestamp() + AUTHORIZATION_CODE_LIFETIME,
        used=False,
    )
    
    # NOTE: In production, use Redis with automatic expiration
    # redis_client.setex(f"authcode:{auth_code}", AUTHORIZATION_CODE_LIFETIME, code_record.json())
    authorization_codes[auth_code] = code_record
    
    print(f"âœ“ Authorization code generated")
    print(f"Code expires in {AUTHORIZATION_CODE_LIFETIME} seconds")
    
    # Redirect back to client with authorization code
    redirect_url = f"{redirect_uri}?code={auth_code}"
    if state:
        redirect_url += f"&state={state}"
    
    print(f"Redirecting to: {redirect_url}")
    return RedirectResponse(url=redirect_url)

@app.post("/oauth/token", response_model=TokenResponse)
async def token_endpoint(
    request: Request,
    token_request: TokenRequest,
):
    """
    OAuth 2.1 Token Endpoint
    
    Handles authorization_code and refresh_token grants.
    Validates PKCE for authorization code flow.
    Implements token rotation for refresh tokens.
    """
    print("=== TOKEN REQUEST ===")
    print(f"Grant type: {token_request.grant_type}")
    
    # Apply stricter rate limiting for OAuth endpoints
    await rate_limit_check(request, OAUTH_RATE_LIMIT_MAX)
    
    # Validate client credentials
    if token_request.client_id not in registered_clients:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )
    
    client = registered_clients[token_request.client_id]
    if client.client_secret != token_request.client_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )
    
    print(f"âœ“ Client authenticated: {token_request.client_id}")
    
    # Route to appropriate grant handler
    if token_request.grant_type == GrantType.AUTHORIZATION_CODE:
        return await handle_authorization_code_grant(token_request, client)
    elif token_request.grant_type == GrantType.REFRESH_TOKEN:
        return await handle_refresh_token_grant(token_request, client)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported grant_type",
        )

async def handle_authorization_code_grant(
    token_request: TokenRequest, 
    client: ClientRecord
) -> TokenResponse:
    """Handle authorization_code grant with PKCE validation"""
    print("=== AUTHORIZATION CODE GRANT ===")
    
    # Validate required parameters
    if not token_request.code or not token_request.redirect_uri or not token_request.code_verifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required parameters: code, redirect_uri, code_verifier",
        )
    
    # Retrieve authorization code
    if token_request.code not in authorization_codes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code not found",
        )
    
    auth_record = authorization_codes[token_request.code]
    
    # Check if code has been used
    if auth_record.used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code already used",
        )
    
    # Check if code has expired
    if current_timestamp() > auth_record.expires_at:
        del authorization_codes[token_request.code]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code expired",
        )
    
    # Validate client_id matches
    if auth_record.client_id != token_request.client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code was issued to a different client",
        )
    
    # Validate redirect_uri matches
    if auth_record.redirect_uri != token_request.redirect_uri:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="redirect_uri does not match",
        )
    
    print("âœ“ Authorization code validated")
    
    # PKCE VALIDATION
    print("=== PKCE VALIDATION ===")
    print(f"Method: {auth_record.code_challenge_method}")
    print(f"Stored challenge: {auth_record.code_challenge}")
    
    is_valid = validate_pkce(
        token_request.code_verifier,
        auth_record.code_challenge,
        auth_record.code_challenge_method,
    )
    
    if not is_valid:
        print("âœ— PKCE validation failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid code_verifier",
        )
    
    print("âœ“ PKCE validation successful")
    
    # Mark authorization code as used and delete
    auth_record.used = True
    del authorization_codes[token_request.code]
    
    # Issue tokens
    access_token = create_access_token(
        auth_record.user_id,
        token_request.client_id,
        auth_record.scope,
    )
    
    refresh_token = create_refresh_token(
        auth_record.user_id,
        token_request.client_id,
        auth_record.scope,
        rotation_count=0,
    )
    
    print("âœ“ Tokens issued successfully")
    
    return TokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=ACCESS_TOKEN_LIFETIME,
        refresh_token=refresh_token,
        scope=auth_record.scope,
    )

async def handle_refresh_token_grant(
    token_request: TokenRequest,
    client: ClientRecord
) -> TokenResponse:
    """Handle refresh_token grant with token rotation"""
    print("=== REFRESH TOKEN GRANT ===")
    
    if not token_request.refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing refresh_token",
        )
    
    # Validate refresh token
    payload = verify_token(token_request.refresh_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token",
        )
    
    # Verify token type
    if payload.get("type") != TokenType.REFRESH.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is not a refresh token",
        )
    
    # Validate client_id matches
    if payload.get("client_id") != token_request.client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token was issued to a different client",
        )
    
    print("âœ“ Refresh token validated")
    
    # Revoke old refresh token (token rotation)
    add_token_to_blacklist(payload["jti"], payload["exp"])
    print("âœ“ Old refresh token revoked")
    
    # Issue new tokens with incremented rotation count
    new_access_token = create_access_token(
        payload["sub"],
        token_request.client_id,
        token_request.scope or payload["scope"],
    )
    
    new_refresh_token = create_refresh_token(
        payload["sub"],
        token_request.client_id,
        token_request.scope or payload["scope"],
        rotation_count=payload.get("rotation_count", 0) + 1,
    )
    
    print(f"âœ“ New tokens issued (rotation count: {payload.get('rotation_count', 0) + 1})")
    
    return TokenResponse(
        access_token=new_access_token,
        token_type="Bearer",
        expires_in=ACCESS_TOKEN_LIFETIME,
        refresh_token=new_refresh_token,
        scope=token_request.scope or payload["scope"],
    )

@app.post("/oauth/revoke", status_code=200)
async def token_revocation(revocation: TokenRevocationRequest):
    """
    OAuth 2.1 Token Revocation Endpoint (RFC 7009)
    
    Revokes access or refresh tokens.
    Always returns 200 OK per RFC 7009.
    """
    print("=== TOKEN REVOCATION REQUEST ===")
    
    # Optional: Validate client credentials
    if revocation.client_id and revocation.client_secret:
        if revocation.client_id not in registered_clients:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client credentials",
            )
        
        client = registered_clients[revocation.client_id]
        if client.client_secret != revocation.client_secret:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client credentials",
            )
        
        print("âœ“ Client authenticated")
    
    # Decode token to get jti (without verification)
    try:
        payload = jwt.decode(
            revocation.token,
            options={"verify_signature": False},
        )
        
        if payload.get("jti"):
            add_token_to_blacklist(payload["jti"], payload.get("exp", 0))
            print(f"âœ“ Token revoked: {payload['jti']}")
    except Exception as e:
        # Token might be malformed, but still return 200 per RFC 7009
        print(f"âš ï¸ Could not decode token: {e}")
    
    # Always return 200 OK per RFC 7009
    return {"status": "ok"}

# ============================================================================
# MCP PROTOCOL ENDPOINTS
# ============================================================================

@app.post("/mcp", response_model=MCPResponse)
async def mcp_endpoint(
    request: Request,
    mcp_request: MCPRequest,
    token_payload: Dict[str, Any] = Depends(verify_bearer_token),
):
    """
    MCP Protocol Endpoint (JSON-RPC 2.0)
    
    Handles all MCP protocol methods:
    - initialize
    - tools/list
    - tools/call
    - resources/list (optional)
    - resources/read (optional)
    - prompts/list (optional)
    - prompts/get (optional)
    - notifications/* (no response)
    """
    print("=== INCOMING MCP REQUEST ===")
    print(f"Method: {mcp_request.method}")
    print(f"Request ID: {mcp_request.id}")
    
    # Apply rate limiting
    await rate_limit_check(request)
    
    # Validate JSON-RPC version
    if mcp_request.jsonrpc != "2.0":
        return MCPResponse(
            id=mcp_request.id,
            error=MCPError(
                code=-32600,
                message="Invalid JSON-RPC version",
            ),
        )
    
    try:
        # Handle notifications (no response needed)
        if not mcp_request.id and mcp_request.method.startswith("notifications/"):
            print(f"âœ“ Notification received: {mcp_request.method}")
            return Response(status_code=200)
        
        # Route to appropriate handler
        if mcp_request.method == "initialize":
            result = await handle_initialize(mcp_request.params or {})
        elif mcp_request.method == "tools/list":
            result = await handle_tools_list(mcp_request.params or {})
        elif mcp_request.method == "tools/call":
            result = await handle_tools_call(mcp_request.params or {})
        elif mcp_request.method == "resources/list":
            result = await handle_resources_list(mcp_request.params or {})
        elif mcp_request.method == "resources/read":
            result = await handle_resources_read(mcp_request.params or {})
        elif mcp_request.method == "prompts/list":
            result = await handle_prompts_list(mcp_request.params or {})
        elif mcp_request.method == "prompts/get":
            result = await handle_prompts_get(mcp_request.params or {})
        else:
            # Unknown method
            return MCPResponse(
                id=mcp_request.id,
                error=MCPError(
                    code=-32601,
                    message=f"Method not found: {mcp_request.method}",
                ),
            )
        
        return MCPResponse(
            id=mcp_request.id,
            result=result,
        )
        
    except Exception as e:
        print(f"âœ— MCP request error: {e}")
        return MCPResponse(
            id=mcp_request.id,
            error=MCPError(
                code=-32603,
                message=f"Internal error: {str(e)}",
            ),
        )

# --- MCP Protocol Handlers ---

async def handle_initialize(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle MCP initialize method"""
    print("=== INITIALIZE ===")
    print(f"Client protocol version: {params.get('protocolVersion')}")
    
    return {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {
                "listChanged": False,
            },
            "resources": {
                "subscribe": False,
                "listChanged": False,
            },
            "prompts": {
                "listChanged": False,
            },
            "logging": {},
        },
        "serverInfo": {
            "name": MCP_SERVER_NAME,
            "version": MCP_SERVER_VERSION,
        },
    }

async def handle_tools_list(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle MCP tools/list method"""
    print("=== TOOLS/LIST ===")
    
    # Define available tools
    # Replace with your actual tool definitions
    tools = [
        {
            "name": "get_weather",
            "description": "Get current weather for a location",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "City name or coordinates",
                    },
                },
                "required": ["location"],
            },
        },
        {
            "name": "send_email",
            "description": "Send an email message",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": {
                        "type": "string",
                        "description": "Recipient email address",
                    },
                    "subject": {
                        "type": "string",
                        "description": "Email subject",
                    },
                    "body": {
                        "type": "string",
                        "description": "Email body content",
                    },
                },
                "required": ["to", "subject", "body"],
            },
        },
    ]
    
    print(f"Returning {len(tools)} tools")
    
    return {"tools": tools}

async def handle_tools_call(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle MCP tools/call method"""
    print("=== TOOLS/CALL ===")
    
    tool_name = params.get("name")
    tool_args = params.get("arguments", {})
    
    print(f"Executing tool: {tool_name}")
    print(f"Arguments: {tool_args}")
    
    # Route to appropriate tool implementation
    if tool_name == "get_weather":
        result = await execute_get_weather(tool_args)
    elif tool_name == "send_email":
        result = await execute_send_email(tool_args)
    else:
        raise ValueError(f"Unknown tool: {tool_name}")
    
    print("âœ“ Tool execution complete")
    
    return {
        "content": [
            {
                "type": "text",
                "text": result,
            },
        ],
    }

# Example tool implementations
async def execute_get_weather(args: Dict[str, Any]) -> str:
    """Example: Get weather tool implementation"""
    location = args.get("location")
    print(f"Fetching weather for: {location}")
    
    # TODO: Call actual weather API
    # This is a placeholder implementation
    return f"Weather in {location}: Sunny, 72Â°F"

async def execute_send_email(args: Dict[str, Any]) -> str:
    """Example: Send email tool implementation"""
    to = args.get("to")
    subject = args.get("subject")
    body = args.get("body")
    
    print(f"Sending email to: {to}")
    
    # TODO: Call actual email service
    # This is a placeholder implementation
    return f"Email sent successfully to {to}"

async def handle_resources_list(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle MCP resources/list method (optional)"""
    print("=== RESOURCES/LIST ===")
    
    resources = [
        {
            "uri": "file:///config/settings.json",
            "name": "Server Configuration",
            "description": "Current server configuration settings",
            "mimeType": "application/json",
        },
    ]
    
    print(f"Returning {len(resources)} resources")
    
    return {"resources": resources}

async def handle_resources_read(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle MCP resources/read method (optional)"""
    print("=== RESOURCES/READ ===")
    
    resource_uri = params.get("uri")
    print(f"Reading resource: {resource_uri}")
    
    # TODO: Implement resource reading logic
    content = '{"example": "data"}'
    
    return {
        "contents": [
            {
                "uri": resource_uri,
                "mimeType": "application/json",
                "text": content,
            },
        ],
    }

async def handle_prompts_list(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle MCP prompts/list method (optional)"""
    print("=== PROMPTS/LIST ===")
    
    prompts = [
        {
            "name": "code_review",
            "description": "Review code for quality and security",
            "arguments": [
                {
                    "name": "code",
                    "description": "Code to review",
                    "required": True,
                },
                {
                    "name": "language",
                    "description": "Programming language",
                    "required": False,
                },
            ],
        },
    ]
    
    print(f"Returning {len(prompts)} prompts")
    
    return {"prompts": prompts}

async def handle_prompts_get(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle MCP prompts/get method (optional)"""
    print("=== PROMPTS/GET ===")
    
    prompt_name = params.get("name")
    prompt_args = params.get("arguments", {})
    
    print(f"Getting prompt: {prompt_name}")
    
    if prompt_name == "code_review":
        code = prompt_args.get("code")
        language = prompt_args.get("language", "unknown")
        
        messages = [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": f"Please review the following {language} code for quality, security, and best practices:\n\n{code}",
                },
            },
        ]
        
        return {"messages": messages}
    else:
        raise ValueError(f"Unknown prompt: {prompt_name}")

# ============================================================================
# METADATA ENDPOINTS
# ============================================================================

@app.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():
    """RFC 8414 - Authorization Server Metadata"""
    print("=== AUTHORIZATION SERVER METADATA REQUEST ===")
    
    return {
        "issuer": JWT_ISSUER,
        "authorization_endpoint": f"{JWT_ISSUER}/oauth/authorize",
        "token_endpoint": f"{JWT_ISSUER}/oauth/token",
        "revocation_endpoint": f"{JWT_ISSUER}/oauth/revoke",
        "registration_endpoint": f"{JWT_ISSUER}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "code_challenge_methods_supported": SUPPORTED_PKCE_METHODS,
        "scopes_supported": ["openid", "email", "profile"],
        "service_documentation": "https://github.com/your-org/mcp-server",
    }

@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    """RFC 8414 - Protected Resource Metadata"""
    print("=== PROTECTED RESOURCE METADATA REQUEST ===")
    
    return {
        "resource": JWT_ISSUER,
        "authorization_servers": [JWT_ISSUER],
        "scopes_supported": ["openid", "email", "profile"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://github.com/your-org/mcp-server",
    }

# ============================================================================
# HEALTH CHECK ENDPOINT
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": current_timestamp(),
        "version": MCP_SERVER_VERSION,
    }

# ============================================================================
# STARTUP EVENT
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Server startup initialization"""
    print("=" * 80)
    print("MCP OAuth 2.1 Server Starting")
    print(f"Issuer: {JWT_ISSUER}")
    print(f"Protocol Version: {MCP_PROTOCOL_VERSION}")
    print(f"Server Version: {MCP_SERVER_VERSION}")
    print("=" * 80)

# ============================================================================
# IMPLEMENTATION NOTES
# ============================================================================

"""
STORAGE MIGRATION GUIDE
=======================

This template uses in-memory storage for simplicity. For production deployment,
migrate to persistent storage as follows:

1. CLIENT REGISTRY (registered_clients)
   
   PostgreSQL Example:
   -------------------
   CREATE TABLE clients (
       client_id VARCHAR(255) PRIMARY KEY,
       client_secret VARCHAR(255) NOT NULL,
       client_name VARCHAR(255),
       redirect_uris JSONB NOT NULL,
       grant_types JSONB NOT NULL,
       response_types JSONB NOT NULL,
       use_pkce BOOLEAN DEFAULT false,
       created_at TIMESTAMP DEFAULT NOW()
   );
   
   # Use SQLAlchemy or asyncpg for database operations
   from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
   
   engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/mcp")

2. AUTHORIZATION CODES (authorization_codes)
   
   Redis Example (with automatic expiration):
   ------------------------------------------
   import aioredis
   
   redis = await aioredis.create_redis_pool('redis://localhost')
   
   # Store with TTL
   await redis.setex(
       f"authcode:{code}",
       AUTHORIZATION_CODE_LIFETIME,
       code_record.json()
   )
   
   # Retrieve
   data = await redis.get(f"authcode:{code}")
   if data:
       code_record = AuthCodeRecord.parse_raw(data)

3. TOKEN BLACKLIST (revoked_tokens)
   
   Redis Example (with TTL for automatic cleanup):
   -----------------------------------------------
   # Add token to blacklist
   ttl = int(expiration - current_timestamp())
   await redis.setex(f"revoked:{token_jti}", ttl, "1")
   
   # Check if revoked
   exists = await redis.exists(f"revoked:{token_jti}")
   return bool(exists)

4. RATE LIMITING (rate_limit_store)
   
   Redis Example (distributed rate limiting):
   ------------------------------------------
   key = f"ratelimit:{client_key}"
   
   # Increment counter with expiry
   pipe = redis.pipeline()
   pipe.incr(key)
   pipe.expire(key, RATE_LIMIT_WINDOW)
   count, _ = await pipe.execute()
   
   if count > max_requests:
       raise HTTPException(status_code=429)

SECURITY CHECKLIST
==================

[ ] Generate cryptographically secure JWT_SECRET (minimum 256 bits)
[ ] Use HTTPS/TLS in production (required for OAuth 2.1)
[ ] Configure CORS appropriately for your deployment
[ ] Implement proper user authentication for authorization endpoint
[ ] Store client_secret hashed (bcrypt/argon2) in database
[ ] Add request validation and sanitization
[ ] Implement audit logging for security events
[ ] Set up monitoring and alerting
[ ] Regular security updates for dependencies
[ ] Implement token cleanup jobs for expired entries

DEPLOYMENT RECOMMENDATIONS
===========================

1. Use environment variables for all secrets
2. Deploy behind reverse proxy (nginx/traefik)
3. Use process manager (systemd/supervisor/PM2)
4. Set up log aggregation (ELK/Loki)
5. Configure health checks for load balancer
6. Implement graceful shutdown handling
7. Use Redis Sentinel/Cluster for HA
8. Database connection pooling
9. Rate limiting per client_id when available
10. Regular backups of client registry

TESTING
=======

Run with pytest:
    pip install pytest pytest-asyncio httpx
    pytest test_mcp_server.py

Example test:
    @pytest.mark.asyncio
    async def test_oauth_flow():
        async with AsyncClient(app=app, base_url="http://test") as client:
            # Test DCR
            response = await client.post("/register", json={
                "client_name": "Test Client",
                "redirect_uris": ["http://localhost/callback"]
            })
            assert response.status_code == 201
"""

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "mcp_server_oauth21:app",
        host="0.0.0.0",
        port=SERVER_PORT,
        reload=True,
        log_level="info",
    )

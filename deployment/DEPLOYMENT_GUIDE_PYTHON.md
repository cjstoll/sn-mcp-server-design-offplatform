# MCP Server Deployment Guide - Python

**Language-specific deployment guide for Python implementations**

---

## Overview

This guide provides Python-specific instructions for deploying your MCP server using the provided template file. 

**Prerequisites:**
- Reviewed the [Master Deployment Guide](./README.md)
- Python 3.9 or higher installed
- Template file: `../templates/mcp-server-python-template.py`

**Approach:** Start with the template file and modify as needed. This guide only covers Python-specific setup and deviations from the template.

---

## Phase 1: Environment Setup

### 1.1 Generate Security Credentials

**Python-specific method using secrets module:**

```python
# generate_secrets.py
import secrets

# Generate JWT_SECRET (minimum 32 characters)
jwt_secret = secrets.token_urlsafe(32)
print(f'JWT_SECRET={jwt_secret}')

# Generate DCR_AUTH_TOKEN
dcr_token = secrets.token_hex(32)
print(f'DCR_AUTH_TOKEN={dcr_token}')
```

Run: `python generate_secrets.py`

**Alternative:** Use OpenSSL commands from Master Deployment Guide.

### 1.2 Create Virtual Environment

**Create and activate virtual environment:**

```bash
# Create virtual environment
python -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate
```

### 1.3 Install Dependencies

**Create `requirements.txt`:**

```txt
fastapi==0.109.0
uvicorn[standard]==0.27.0
python-jose[cryptography]==3.3.0
python-multipart==0.0.6
bcrypt==4.1.2
redis==5.0.1
python-dotenv==1.0.0
```

**Install:**
```bash
pip install -r requirements.txt
```

**For development:**
```bash
pip install -r requirements.txt
pip install watchfiles  # For auto-reload
```

### 1.4 Configure Environment Variables

**Create `.env` file:**

```bash
# Server Configuration
PORT=8080
ENVIRONMENT=development

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
RATE_LIMIT_OAUTH_WINDOW=900
RATE_LIMIT_OAUTH_MAX=100
RATE_LIMIT_MCP_WINDOW=60
RATE_LIMIT_MCP_MAX=60
```

**Important:** Add to `.gitignore`:
```
.env
venv/
__pycache__/
*.pyc
data/
*.log
```

### 1.5 Project Structure

Python template is self-contained. Recommended structure:

```
your-mcp-server/
├── server.py                    # Main entry (from template)
├── requirements.txt
├── .env
├── .gitignore
├── venv/                        # Virtual environment
└── data/
    └── registered_clients.json
```

**Optional modular structure** (if refactoring template):
```
├── src/
│   ├── config.py
│   ├── middleware.py
│   ├── oauth.py
│   ├── mcp.py
│   └── storage.py
```

---

## Phase 2: Server Foundation

**Template Coverage:** The template file includes complete server foundation implementation using FastAPI.

### What's Included in Template:
- FastAPI application initialization
- Pydantic models for request/response validation
- Configuration validation on startup
- Middleware stack (CORS, rate limiting)
- Storage initialization (file-based + Redis fallback)
- Health check endpoint
- Graceful shutdown handlers
- Lifespan events for startup/shutdown

### Required Changes:

**None required** - the template works as-is with your `.env` configuration.

### Python-Specific Notes:

**FastAPI vs Flask:** The template uses FastAPI because:
- Built-in Pydantic validation
- Automatic OpenAPI documentation
- Native async/await support
- Better performance for concurrent requests

**Pydantic Models:** The template includes data validation:

```python
from pydantic import BaseModel

class MCPRequest(BaseModel):
    jsonrpc: str = "2.0"
    method: str
    params: dict = {}
    id: Optional[Union[str, int]] = None

class OAuthClient(BaseModel):
    client_id: str
    client_secret_hash: str
    client_name: str
    redirect_uris: List[str]
    grant_types: List[str]
    created_at: str
```

FastAPI automatically validates requests against these models.

### Optional Enhancements:

**If you need database storage:**

```python
from sqlalchemy import create_engine, Column, String, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class OAuthClientDB(Base):
    __tablename__ = 'oauth_clients'
    client_id = Column(String, primary_key=True)
    data = Column(JSON)

engine = create_engine(os.getenv('DATABASE_URL'))
SessionLocal = sessionmaker(bind=engine)

async def get_client(client_id: str) -> Optional[dict]:
    session = SessionLocal()
    try:
        result = session.query(OAuthClientDB).filter_by(client_id=client_id).first()
        return result.data if result else None
    finally:
        session.close()
```

---

## Phase 3: MCP Protocol Implementation

**Template Coverage:** The template includes complete MCP protocol implementation with FastAPI.

### What's Included in Template:
- `/mcp` endpoint with conditional authentication
- Pydantic models for MCP requests/responses
- `initialize`, `tools/list`, `tools/call` handlers
- Typed tool definitions with JSON Schema
- Authentication dependency injection

### Required Changes:

**None required** - basic MCP protocol works out of the box.

### Python-Specific Features:

**Dependency Injection:** FastAPI uses dependencies for authentication:

```python
from fastapi import Depends, HTTPException

async def verify_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing token")
    # Validate token...
    return client_id

@app.post("/mcp")
async def mcp_endpoint(
    request: MCPRequest,
    client_id: str = Depends(verify_token)  # Injected automatically
):
    # Handle request with authenticated client_id
    pass
```

**Async/Await:** The template uses async handlers for better concurrency:

```python
async def execute_tool(name: str, args: dict) -> str:
    # Can make async database queries, HTTP calls, etc.
    if name == "echo":
        return f"Echo: {args['message']}"
```

### Customization: Add Your Tools

**Locate this section in the template:**

```python
def get_tool_definitions() -> List[dict]:
    return [
        {
            "name": "echo",
            "description": "Echoes back the provided message",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Message to echo"}
                },
                "required": ["message"]
            }
        },
        # ADD YOUR TOOLS HERE
    ]
```

**Add your tool with Pydantic validation:**

```python
# Define tool arguments with Pydantic
class YourToolArgs(BaseModel):
    param1: str
    param2: Optional[int] = None

# Add to tool definitions
{
    "name": "your_tool_name",
    "description": "What your tool does",
    "inputSchema": {
        "type": "object",
        "properties": {
            "param1": {"type": "string", "description": "Parameter description"},
            "param2": {"type": "integer", "description": "Optional parameter"}
        },
        "required": ["param1"]
    }
}

# Add execution function with type hints
async def execute_your_tool(args: dict) -> str:
    # Validate with Pydantic
    validated_args = YourToolArgs(**args)
    
    # Python enforces types at runtime with Pydantic
    result = f"Processing {validated_args.param1}"
    return result
```

**Update the execution router:**

```python
async def execute_tool(name: str, args: dict) -> str:
    if name == "echo":
        return execute_echo(args)
    elif name == "your_tool_name":
        return await execute_your_tool(args)
    else:
        raise ValueError(f"Unknown tool: {name}")
```

---

## Phase 4: OAuth 2.1 Security Layer

**Template Coverage:** The template includes complete OAuth 2.1 + PKCE implementation with Pydantic validation.

### What's Included in Template:
- OAuth metadata endpoints with FastAPI responses
- Dynamic Client Registration (DCR) with Pydantic models
- Authorization endpoint with query parameter validation
- Token endpoint with form data validation
- Token revocation with request validation
- JWT token creation using python-jose
- PKCE utilities with hashlib (SHA-256)

### Required Changes:

**None required** - OAuth implementation is production-ready.

### Python-Specific Notes:

**JWT Library:** The template uses `python-jose`:

```python
from jose import jwt, JWTError

def create_access_token(client_id: str, user_id: str) -> dict:
    jti = secrets.token_hex(16)
    exp = int(time.time()) + int(os.getenv('ACCESS_TOKEN_LIFETIME'))
    
    payload = {
        'iss': os.getenv('OAUTH_ISSUER'),
        'sub': user_id,
        'client_id': client_id,
        'jti': jti,
        'exp': exp
    }
    
    token = jwt.encode(payload, os.getenv('JWT_SECRET'), algorithm='HS256')
    return {'token': token, 'jti': jti, 'exp': exp}
```

**PKCE Validation:** Uses hashlib for SHA-256:

```python
import hashlib
import base64

def verify_pkce_challenge(verifier: str, challenge: str) -> bool:
    computed = hashlib.sha256(verifier.encode()).digest()
    computed_challenge = base64.urlsafe_b64encode(computed).decode().rstrip('=')
    return computed_challenge == challenge
```

**Password Hashing:** Uses bcrypt:

```python
import bcrypt

def hash_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()

def verify_secret(secret: str, hashed: str) -> bool:
    return bcrypt.checkpw(secret.encode(), hashed.encode())
```

### Pydantic Models for OAuth:

The template includes validation models:

```python
class DCRRequest(BaseModel):
    client_name: str
    redirect_uris: List[str]

class TokenRequest(BaseModel):
    grant_type: str
    code: Optional[str] = None
    code_verifier: Optional[str] = None
    refresh_token: Optional[str] = None
    client_id: str
    client_secret: str
    redirect_uri: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str
    scope: Optional[str] = None
```

FastAPI automatically validates and serializes these models.

---

## Phase 5: Production Hardening

**Template Coverage:** The template includes production hardening with FastAPI middleware.

### What's Included in Template:
- Rate limiting with slowapi
- Audit logging with structured logs
- Exception handlers for FastAPI
- Configuration validation
- Health check with async service checks
- Lifespan events for graceful startup/shutdown

### Production Configuration Changes:

**Update `.env` for production:**

```bash
ENVIRONMENT=production
OAUTH_ISSUER=https://your-production-domain.com  # Must be HTTPS
REDIS_HOST=your-redis-host                        # Required for production
ALLOWED_ORIGINS=https://prod-instance.service-now.com
```

**The template will enforce:**
- HTTPS required (OAUTH_ISSUER must start with `https://`)
- Redis required (will fail without REDIS_HOST in production)
- CORS restricted to ALLOWED_ORIGINS only

### Python-Specific Production Setup:

**Run with Uvicorn:**

```bash
# Development
uvicorn server:app --reload --host 0.0.0.0 --port 8080

# Production
uvicorn server:app --host 0.0.0.0 --port 8080 --workers 4
```

**With Gunicorn (recommended for production):**

```bash
gunicorn server:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8080 \
  --access-logfile - \
  --error-logfile -
```

### Optional: Enhanced Logging

**Structured logging with Python's logging module:**

```python
import logging
import json

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module
        }
        return json.dumps(log_obj)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)
```

---

## Validation & Testing

### Start Server

```bash
# Development mode (auto-reload)
uvicorn server:app --reload --host 0.0.0.0 --port 8080

# Production mode
uvicorn server:app --host 0.0.0.0 --port 8080 --workers 4
```

**Expected output:**
```
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
✅ Configuration validated successfully
✅ Redis connected for token blacklist
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8080
```

### Basic Validation

```bash
# Health check
curl http://localhost:8080/health
# Expected: {"status":"healthy",...}

# OAuth metadata
curl http://localhost:8080/.well-known/oauth-authorization-server
# Expected: OAuth server metadata JSON

# FastAPI automatic documentation
curl http://localhost:8080/docs
# Opens interactive API documentation (Swagger UI)

# MCP initialize (no auth)
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}},"id":1}'
# Expected: Server capabilities
```

### Complete OAuth Flow Test

**Same commands as JavaScript guide** - See [JavaScript Deployment Guide - Validation](./DEPLOYMENT_GUIDE_JAVASCRIPT.md#validation--testing) for complete OAuth flow testing.

### Python-Specific Testing

**Interactive testing with Python:**

```python
import requests

# Test DCR
response = requests.post(
    'http://localhost:8080/oauth/register',
    headers={'Authorization': f'Bearer {DCR_AUTH_TOKEN}'},
    json={
        'client_name': 'Test Client',
        'redirect_uris': ['http://localhost:3000/callback']
    }
)
client = response.json()
print(f"Client ID: {client['client_id']}")
print(f"Client Secret: {client['client_secret']}")

# Test MCP
response = requests.post(
    'http://localhost:8080/mcp',
    headers={'Authorization': f'Bearer {access_token}'},
    json={
        'jsonrpc': '2.0',
        'method': 'tools/list',
        'params': {},
        'id': 1
    }
)
print(response.json())
```

---

## Troubleshooting

### Python-Specific Issues

**"ModuleNotFoundError: No module named 'X'"**
- Activate virtual environment: `source venv/bin/activate`
- Install dependencies: `pip install -r requirements.txt`
- Verify correct Python version: `python --version`

**"ImportError: cannot import name 'X' from 'Y'"**
- Check Python version (minimum 3.9 required)
- Update dependencies: `pip install --upgrade -r requirements.txt`
- Check for circular imports in custom code

**"ValueError: [JWT_SECRET] must be at least 32 characters"**
- Regenerate using `python generate_secrets.py`
- Check `.env` file JWT_SECRET value
- Ensure no whitespace around secret in `.env`

**"redis.exceptions.ConnectionError: Error connecting to Redis"**
- Verify Redis is running: `redis-cli ping`
- Check REDIS_HOST and REDIS_PORT in `.env`
- Template will fall back to in-memory (warning only)

**"uvicorn: command not found"**
- Activate virtual environment
- Install uvicorn: `pip install uvicorn[standard]`

**Port already in use**
- Change PORT in `.env`
- Or kill process: `lsof -ti:8080 | xargs kill -9`

**Pydantic validation errors**
- Check request body matches Pydantic models
- Review FastAPI error response for field details
- Use `/docs` endpoint to see expected schema

### General Issues

See [Master Deployment Guide - Troubleshooting](./README.md#troubleshooting) for common OAuth and MCP protocol issues.

---

## Production Deployment

### Pre-Deployment Checklist

**Python-specific:**
- [ ] Virtual environment created and activated
- [ ] All dependencies installed: `pip install -r requirements.txt`
- [ ] `ENVIRONMENT=production` set in `.env`
- [ ] Production `.env` has unique JWT_SECRET
- [ ] Redis configured and accessible
- [ ] Gunicorn or production ASGI server configured
- [ ] System service or process manager configured

### Systemd Service Configuration

**Create `/etc/systemd/system/mcp-server.service`:**

```ini
[Unit]
Description=MCP Server
After=network.target redis.target

[Service]
Type=notify
User=mcpserver
Group=mcpserver
WorkingDirectory=/opt/mcp-server
Environment="PATH=/opt/mcp-server/venv/bin"
EnvironmentFile=/opt/mcp-server/.env
ExecStart=/opt/mcp-server/venv/bin/gunicorn server:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8080 \
  --access-logfile - \
  --error-logfile -
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable mcp-server
sudo systemctl start mcp-server
sudo systemctl status mcp-server
```

### Supervisor Configuration

**Create `/etc/supervisor/conf.d/mcp-server.conf`:**

```ini
[program:mcp-server]
command=/opt/mcp-server/venv/bin/gunicorn server:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8080
directory=/opt/mcp-server
user=mcpserver
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/mcp-server/out.log
stderr_logfile=/var/log/mcp-server/err.log
environment=PATH="/opt/mcp-server/venv/bin"
```

**Start:**
```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start mcp-server
```

### Docker Deployment

**Example `Dockerfile`:**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY server.py .

# Create data directory
RUN mkdir -p /app/data

# Expose port
EXPOSE 8080

# Run with uvicorn
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4"]
```

**Build and run:**
```bash
docker build -t mcp-server .
docker run -p 8080:8080 --env-file .env mcp-server
```

**Docker Compose:**

```yaml
version: '3.8'

services:
  mcp-server:
    build: .
    ports:
      - "8080:8080"
    env_file:
      - .env
    depends_on:
      - redis
    restart: always

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: always

volumes:
  redis-data:
```

Run: `docker-compose up -d`

---

## Next Steps

**For ServiceNow Integration:**
- Share DCR_AUTH_TOKEN with ServiceNow team (secure channel)
- Provide server URL: `https://your-domain.com`
- Follow [ServiceNow Connection Configuration](../mcp-guide-05-appendices.md#appendix-d-servicenow-connection-configuration)

**For Custom Tools:**
- Define Pydantic models for tool arguments
- Add type-safe tool definitions to `get_tool_definitions()`
- Implement async execution functions
- Use FastAPI's automatic validation

**For Interactive Exploration:**

The Jupyter notebook provides hands-on OAuth flow testing:

**Location:** `../templates/mcp-deployment-exploration.ipynb`

**Usage:**
```bash
# Install Jupyter (if not already installed)
pip install jupyter

# Navigate to templates folder
cd templates/

# Start Jupyter
jupyter notebook mcp-deployment-exploration.ipynb

# Or use in Google Colab:
# 1. Go to https://colab.research.google.com/
# 2. Upload the .ipynb file
# 3. Run cells sequentially
```

**What it covers:**
- Complete OAuth 2.1 + PKCE flow walkthrough
- Interactive token generation and validation
- MCP protocol testing (tools/list, tools/call)
- Token refresh and revocation verification
- Helper functions for reusable testing

**For Monitoring:**
- Configure structured logging (JSON format)
- Set up health check monitoring
- Use FastAPI metrics middleware
- Configure alerts for errors and rate limiting

---

## Reference Documentation

**Master Guide:**
- [Master Deployment Guide](./README.md) - Complete deployment workflow and concepts

**Detailed Implementation:**
- [Part 2: Server Foundation](../mcp-guide-02-server-foundation.md) - Infrastructure details
- [Part 3: MCP Protocol](../mcp-guide-03-mcp-protocol-tools.md) - Protocol implementation
- [Part 4: OAuth Implementation](../mcp-guide-04-oauth-implementation.md) - OAuth 2.1 security details
- [Part 5: Appendices](../mcp-guide-05-appendices.md) - Storage options and production checklist

**Template:**
- `../templates/mcp-server-python-template.py` - Complete reference implementation

**Python Resources:**
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [Uvicorn Documentation](https://www.uvicorn.org/)

---

**Version:** 1.0  
**Last Updated:** February 2026

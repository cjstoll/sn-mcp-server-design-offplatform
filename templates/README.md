# MCP Server Templates

This directory contains production-ready MCP server templates implementing OAuth 2.1 + PKCE authentication for ServiceNow integration.

## 📁 Available Templates

### Production-Ready Implementations

#### JavaScript/Node.js Template
**File:** [`mcp-server-javascript-template.js`](mcp-server-javascript-template.js)  
**Framework:** Express.js  
**Best For:** Local deployments, rapid prototyping, Node.js environments  
**Features:**
- Complete OAuth 2.1 + PKCE flow
- JWT token management
- MCP protocol handlers (initialize, tools)
- Rate limiting and security middleware
- File-based storage (easily adaptable to Redis/database)

**Quick Start:**
```bash
npm install express cors body-parser jsonwebtoken
node mcp-server-javascript-template.js
```

---

#### TypeScript Template
**File:** [`mcp-server-typescript-template.ts`](mcp-server-typescript-template.ts)  
**Framework:** Express.js with TypeScript  
**Best For:** Cloud deployments (Google Cloud, AWS), type-safe implementations  
**Features:**
- Full type safety with TypeScript interfaces
- OAuth 2.1 + PKCE authentication
- JWT token management with proper typing
- MCP protocol compliance
- Production-grade error handling
- Structured for serverless deployment

**Quick Start:**
```bash
npm install express @types/express jsonwebtoken @types/jsonwebtoken typescript
npx ts-node mcp-server-typescript-template.ts
```

---

#### Python/FastAPI Template
**File:** [`mcp-server-python-template.py`](mcp-server-python-template.py)  
**Framework:** FastAPI  
**Best For:** Python environments, microservices, async operations  
**Features:**
- Modern async Python with FastAPI
- OAuth 2.1 + PKCE implementation
- Pydantic models for request/response validation
- Automatic OpenAPI documentation
- Built-in rate limiting
- Production-ready error handling

**Quick Start:**
```bash
pip install fastapi uvicorn pyjwt cryptography python-multipart
uvicorn mcp-server-python-template:app --reload
```

---

### Reference Implementation

#### Pseudocode Template
**File:** [`mcp-server-pseudocode-template.md`](mcp-server-pseudocode-template.md)  
**Purpose:** Language-agnostic reference implementation  
**Best For:** Understanding the complete flow, implementing in other languages  
**Contains:**
- Complete OAuth 2.1 + PKCE flow in pseudocode
- All MCP protocol handlers
- JWT token generation and validation
- PKCE challenge/verifier logic
- Storage patterns for tokens and clients
- Rate limiting algorithms
- Error handling patterns

**Use When:**
- Implementing in Go, Java, C#, Rust, or other languages
- Understanding the complete authentication flow
- Validating your implementation logic
- Teaching or documenting the system

---

## 🎯 Choosing the Right Template

### Use JavaScript Template When:
- Deploying locally on-premise
- Quick prototyping or proof-of-concept
- Team expertise is in Node.js
- Using PM2 or similar process managers
- Need lightweight, fast deployment

### Use TypeScript Template When:
- Deploying to cloud platforms (Google Cloud, AWS, Azure)
- Need type safety and better IDE support
- Building production-grade systems
- Serverless architecture preferred
- Team has TypeScript experience

### Use Python Template When:
- Python is your primary language
- Need async/await patterns
- Want automatic API documentation
- Integrating with Python ML/AI tools
- Team expertise is in Python

### Use Pseudocode Template When:
- Implementing in languages not provided (Go, Java, C#, Rust)
- Need to understand complete logic flow
- Creating custom implementations
- Teaching or documenting the system
- Validating implementation correctness

---

## 🔧 Configuration

All templates require these environment variables:

**Required:**
- `JWT_SECRET` - Secret key for signing JWT tokens (minimum 256 bits)
- `JWT_ISSUER` - Issuer URL (e.g., https://mcp-server.example.com)

**Optional:**
- `DCR_TOKEN` - Authorization token for Dynamic Client Registration
- `SERVER_PORT` - Server port (default: 3000)

**Example `.env` file:**
```bash
JWT_SECRET=your-super-secret-key-min-256-bits
JWT_ISSUER=https://mcp.yourdomain.com
DCR_TOKEN=your-dcr-token-here
SERVER_PORT=3000
```

See [`env.example.txt`](env.example.txt) and [`env.template.txt`](env.template.txt) for complete examples.

---

## 📚 Additional Resources

### Deployment Guides
Language-specific deployment instructions are available in the [`deployment/`](../deployment/) directory:
- [`DEPLOYMENT_GUIDE_JAVASCRIPT.md`](../deployment/DEPLOYMENT_GUIDE_JAVASCRIPT.md)
- [`DEPLOYMENT_GUIDE_TYPESCRIPT.md`](../deployment/DEPLOYMENT_GUIDE_TYPESCRIPT.md)
- [`DEPLOYMENT_GUIDE_PYTHON.md`](../deployment/DEPLOYMENT_GUIDE_PYTHON.md)

### Implementation Documentation
Comprehensive implementation guidance is available in the [`docs/`](../docs/) directory:
- [Part 1: Overview](../docs/MCP%20Server%20Implementation%20-%20Part%201%20Overview.md)
- [Part 2: Core Infrastructure](../docs/MCP%20Server%20Implementation%20-%20Part%202%20Core%20Infrastructure.md)
- [Part 3: Protocol and Tools](../docs/MCP%20Server%20Implementation%20-%20Part%203%20Protocol%20and%20Tools.md)
- [Part 4: OAuth](../docs/MCP%20Server%20Implementation%20-%20Part%204%20OAuth.md)
- [Part 5: Appendices](../docs/MCP%20Server%20Implementation%20-%20Part%205%20Appendices.md)

### Language-Specific Hints
For implementing in Go, Java, C#, or Rust, see:
- [Language Implementation Hints](../docs/MCP%20Server%20Implementation%20-%20Implementation%20Hints.md)

---

## 🚀 Quick Start Workflow

1. **Choose Your Template** based on your language/platform preference
2. **Copy the template** to your project directory
3. **Configure environment variables** (JWT_SECRET, JWT_ISSUER, etc.)
4. **Install dependencies** using the Quick Start commands above
5. **Review deployment guide** for your chosen language
6. **Test locally** before production deployment
7. **Follow security checklist** in [Part 5 Appendices](../docs/MCP%20Server%20Implementation%20-%20Part%205%20Appendices.md)

---

## 🔐 Security Notes

All templates implement:
- ✅ OAuth 2.1 with PKCE (RFC 7636)
- ✅ JWT token-based authentication (RFC 9068)
- ✅ Dynamic Client Registration
- ✅ Rate limiting protection
- ✅ Token rotation and revocation
- ✅ Secure token storage patterns
- ✅ CORS configuration
- ✅ Request validation

**Before Production:**
- Generate strong JWT_SECRET (minimum 256 bits)
- Use HTTPS/TLS for all connections
- Configure proper CORS policies
- Enable rate limiting
- Set up monitoring and logging
- Review security hardening in [Part 4: OAuth](../docs/MCP%20Server%20Implementation%20-%20Part%204%20OAuth.md) documentation

---

## 📖 Template Structure

Each production template follows this structure:

1. **Configuration** - Environment variables and constants
2. **Storage Layer** - Token and client data management
3. **JWT Functions** - Token generation and validation
4. **PKCE Functions** - Challenge/verifier validation
5. **OAuth Endpoints** - DCR, authorize, token, revoke
6. **MCP Endpoint** - Protocol handler for tools/resources
7. **Middleware** - Authentication, rate limiting, error handling
8. **Server Initialization** - HTTP server setup and startup

This consistent structure makes it easy to:
- Understand any template quickly
- Compare implementations across languages
- Adapt templates to your specific needs
- Maintain and extend functionality

---

## 💡 Support

- **Issues:** Report bugs or request features via GitHub Issues
- **Discussions:** Ask questions in GitHub Discussions
- **Documentation:** Full implementation guide in [`docs/`](../docs/)

---

## 📄 License

These templates are part of the ServiceNow MCP Server project and are licensed under the MIT License. See [LICENSE](../LICENSE) for details.

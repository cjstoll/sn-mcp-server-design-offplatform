# MCP Server Reference Templates

This directory contains **reference implementations** demonstrating production-quality code patterns for MCP servers. These templates serve as starting points and learning resources - not complete deployment packages.

## Understanding "Reference Template"

**What These Templates Provide:**
- ✅ Production-quality code demonstrating OAuth 2.1 + PKCE implementation
- ✅ Complete MCP protocol handlers (initialize, tools, notifications)
- ✅ Security best practices (JWT tokens, PKCE validation, rate limiting)
- ✅ Well-structured, documented code you can learn from and adapt

**What You Need to Add:**
- ⚙️ Dependency configuration (`package.json`, `requirements.txt`, etc.) for your environment
- ⚙️ Environment configuration files (`.env`) with your specific settings
- ⚙️ Deployment infrastructure (Dockerfile, systemd units, process management)
- ⚙️ HTTPS/TLS setup (certificates, reverse proxy, load balancer)
- ⚙️ Testing framework and validation scripts
- ⚙️ Monitoring, logging, and operational tooling integration

**Expected Effort to Deploy:**
- Template adaptation: 4-8 hours
- Infrastructure setup: 4-8 hours
- Testing & validation: 2-4 hours

See [Deployment Guides](../deployment/) for platform-specific guidance on completing your deployment.

---

## 📁 Available Templates

### JavaScript Reference Template
**File:** [`mcp-server-javascript-template.js`](mcp-server-javascript-template.js)  
**Target Environment:** Local VM, on-premises deployment  
**Reference Storage:** File-based client registry, Redis token blacklist  
**Reference Tools:** LLM generation (Ollama), file operations

**What's Included:**
- Complete OAuth 2.1 + PKCE implementation
- MCP protocol handlers (initialize, tools/list, tools/call)
- JWT token management with blacklisting
- Rate limiting and audit logging
- Graceful shutdown and error handling

**What You Configure:**
- Create `package.json` with dependencies
- Set up `.env` file with your settings
- Implement HTTPS/TLS (reverse proxy or native)
- Configure storage paths or migrate to database
- Adapt tools to your AI services
- Set up process management (PM2, systemd)

**Best For:** On-premises deployments, Node.js environments, practitioners comfortable with JavaScript async patterns

**Deployment Guide:** [JavaScript Deployment Guide](../deployment/DEPLOYMENT_GUIDE_JAVASCRIPT.md)

---

### TypeScript Reference Template
**File:** [`mcp-server-typescript-template.ts`](mcp-server-typescript-template.ts)  
**Target Environment:** Google Cloud Run, cloud platforms  
**Reference Storage:** Firestore (cloud), in-memory token blacklist  
**Reference Tools:** A2A agent integration, utility tools

**What's Included:**
- Complete OAuth 2.1 + PKCE implementation with TypeScript types
- MCP protocol handlers with full type safety
- JWT token management with typed interfaces
- Type-safe configuration and error handling
- Production-grade async patterns

**What You Configure:**
- Create `package.json` and `tsconfig.json`
- Set up `.env` file or cloud environment variables
- Configure cloud deployment (Cloud Run, AWS Lambda, etc.)
- Adapt storage layer for your cloud provider
- Implement HTTPS/TLS (handled by cloud platform or add reverse proxy)
- Set up CI/CD pipeline for TypeScript compilation

**Best For:** Cloud deployments, type-safe implementations, serverless architectures, teams with TypeScript experience

**Deployment Guide:** [TypeScript Deployment Guide](../deployment/DEPLOYMENT_GUIDE_TYPESCRIPT.md)

---

### Python Reference Template
**File:** [`mcp-server-python-template.py`](mcp-server-python-template.py)  
**Target Environment:** Any Python 3.9+ environment  
**Reference Storage:** In-memory (migration notes provided)  
**Reference Tools:** Example tools included

**What's Included:**
- Complete OAuth 2.1 + PKCE implementation with FastAPI
- MCP protocol handlers with Pydantic models
- JWT token management with python-jose
- Automatic API documentation (OpenAPI/Swagger)
- Async/await patterns throughout

**What You Configure:**
- Create `requirements.txt` with dependencies
- Set up `.env` file with your settings
- Implement persistent storage (migrate from in-memory)
- Configure ASGI server (uvicorn/gunicorn)
- Implement HTTPS/TLS (reverse proxy)
- Adapt tools to your AI services
- Set up process management

**Best For:** Python environments, FastAPI familiarity, async operations, teams with Python expertise

**Deployment Guide:** [Python Deployment Guide](../deployment/DEPLOYMENT_GUIDE_PYTHON.md)

---

### Pseudocode Reference Template
**File:** [`mcp-server-pseudocode-template.md`](mcp-server-pseudocode-template.md)  
**Purpose:** Language-agnostic reference implementation  
**Contains:** Complete logic flow and algorithms

**What's Included:**
- Complete OAuth 2.1 + PKCE flow in pseudocode
- All MCP protocol handlers
- JWT token generation and validation logic
- PKCE challenge/verifier algorithms
- Storage patterns for tokens and clients
- Rate limiting algorithms
- Error handling patterns

**What You Implement:**
- Translate pseudocode to your language (Go, Java, C#, Rust, etc.)
- Create dependency configuration for your ecosystem
- Set up environment configuration
- Choose and configure storage backend
- Implement HTTPS/TLS for your platform
- Add monitoring and logging
- Set up deployment infrastructure

**Best For:** Implementing in languages not provided (Go, Java, C#, Rust), understanding complete logic flow, validating implementation correctness, teaching or documenting the system

**Language-Specific Guidance:** [Implementation Hints](../docs/MCP%20Server%20Implementation%20-%20Implementation%20Hints.md)

---

## 🎯 Choosing the Right Template

### Use JavaScript Template When:
- Deploying locally on-premises
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
3. **Review the deployment guide** for your chosen language
4. **Create dependency configuration** (`package.json`, `requirements.txt`, etc.)
5. **Configure environment variables** (`.env` file)
6. **Implement infrastructure** (HTTPS, storage, monitoring)
7. **Test locally** before production deployment
8. **Follow deployment checklist** from [Part 5](../docs/MCP%20Server%20Implementation%20-%20Part%205%20Appendices.md)

---

## ⚠️ Important Notes

**These are reference implementations:**
- Start with a template as your foundation
- Adapt to your specific requirements
- Complete the infrastructure setup
- Test thoroughly before production use

**Security Considerations:**
- Never commit `.env` files to version control
- Generate unique secrets for each environment
- Use proper secret management in production
- Review [Part 4: OAuth Security](../docs/MCP%20Server%20Implementation%20-%20Part%204%20OAuth.md) before deployment

**Support:**
- **Documentation Questions**: See the [comprehensive documentation](../docs/) or ask in [GitHub Discussions Q&A](https://github.com/cjstoll/sn-mcp-server-design-offplatform/discussions/categories/q-a)
- **Deployment Issues**: Check [deployment guides](../deployment/) or report in [GitHub Issues](https://github.com/cjstoll/sn-mcp-server-design-offplatform/issues)
- **ServiceNow Integration**: See [Part 5 Appendix D](../docs/MCP%20Server%20Implementation%20-%20Part%205%20Appendices.md#appendix-d-servicenow-connection-configuration) or ask on [ServiceNow Community](https://www.servicenow.com/community/)

---

**Ready to build?** Start with [Part 1: Overview](../docs/MCP%20Server%20Implementation%20-%20Part%201%20Overview.md) to understand the architecture, then choose your template and follow the deployment guide.

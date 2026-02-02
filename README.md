# ServiceNow MCP Server

Production-ready Model Context Protocol (MCP) server implementation for ServiceNow integration with locally-hosted AI services and LLMs.

## Overview

This repository provides enterprise-grade MCP server templates that enable secure, high-performance integration between ServiceNow cloud instances and local AI infrastructure. Built for ServiceNow administrators, AI platform developers, and MCP practitioners who need production-quality implementations that follow OAuth 2.1 standards with PKCE authentication.

### What Problem Does This Solve?

ServiceNow's AI Platform enables powerful automation and intelligence capabilities, but many organizations need to:
- Integrate with locally-hosted LLMs for data privacy or cost control
- Connect ServiceNow to on-premises AI infrastructure
- Build custom MCP servers that meet enterprise security standards
- Deploy across multiple environments (local, cloud, hybrid)

This project provides reference implementations that handle the complex authentication, security hardening, and performance optimization required for production deployments.

## Key Features

- **OAuth 2.1 with PKCE**: Industry-standard authentication following machine-to-machine patterns
- **JWT Token Management**: Secure token generation, validation, and blacklisting
- **Production Hardening**: Rate limiting, persistent storage, comprehensive audit logging
- **Multiple Deployment Options**: Local, Google Cloud, and white-label templates
- **Sub-Second Performance**: Optimized for enterprise-scale operations
- **ServiceNow AI Platform Ready**: Compatible with ServiceNow's MCP integration requirements

## Architecture

The MCP server acts as a secure gateway between ServiceNow (authenticated client) and local AI services:

```
ServiceNow Instance → OAuth 2.1 Authentication → MCP Server → Local LLM (Ollama/etc)
                                                     ↓
                                              Redis (token blacklist)
                                              File-based persistence
                                              Rate limiting
                                              Audit logging
```

### Authentication Flow

ServiceNow handles user authentication, while the MCP server manages client authentication:
1. ServiceNow requests access token using client credentials
2. MCP server validates and issues JWT token
3. ServiceNow includes token in subsequent MCP requests
4. MCP server validates token and routes to AI services

## Quick Start

### Prerequisites

Choose your implementation language:
- **JavaScript/Node.js**: Node.js 18+ (local deployment)
- **TypeScript**: Node.js 18+ (Google Cloud Run optimized)
- **Python**: Python 3.9+ (FastAPI-based)

Additional requirements (all implementations):
- Redis (for token blacklist persistence)
- ServiceNow instance with AI Platform enabled
- Local LLM infrastructure (Ollama, llama.cpp, etc.)

### JavaScript/Node.js (Local Deployment)

```bash
# Clone repository
git clone https://github.com/[username]/servicenow-mcp-server.git
cd servicenow-mcp-server

# Install dependencies
cd implementations/javascript-local
npm install

# Configure environment
cp config/template.env .env
# Edit .env with your ServiceNow instance details

# Start server
npm start
```

### TypeScript (Google Cloud Deployment)

See [implementations/typescript-gcp/README.md](implementations/typescript-gcp/README.md) for Cloud Run deployment instructions.

### Python (FastAPI)

```bash
# Clone repository
git clone https://github.com/[username]/servicenow-mcp-server.git
cd servicenow-mcp-server

# Install dependencies
cd implementations/python-fastapi
pip install -r requirements.txt

# Configure environment
cp config/template.env .env
# Edit .env with your ServiceNow instance details

# Start server
uvicorn src.main:app --host 0.0.0.0 --port 3000 --reload
```

## Documentation

### Implementation Guides

- **[5-Part Comprehensive Guide](docs/implementation-guide/)**: Complete implementation walkthrough (7,800 lines)
  - Part 1: Introduction & Requirements
  - Part 2: Server Foundation & Infrastructure
  - Part 3: MCP Protocol & Tools Implementation
  - Part 4: OAuth 2.1 Authentication & Security
  - Part 5: Production Deployment & Operations

### Reference Materials

- **[Pseudocode Template](docs/pseudocode-template.md)**: Language-agnostic reference implementation
- **[Language Implementation Hints](docs/language-hints.md)**: Guidance for Go, Java, C#, Rust
- **[ServiceNow Integration Guide](docs/servicenow-integration.md)**: ServiceNow-specific configuration
- **[FAQ](docs/faq.md)**: Common questions and answers
- **[Architecture Overview](docs/architecture.md)**: System design and components

### Diagrams & Visuals

- **[OAuth Flow Diagram](docs/diagrams/oauth-flow.svg)**: Complete OAuth 2.1 + PKCE flow visualization
- **[Presentation Materials](docs/presentations/)**: Conference and training presentations

## Deployment Options

### Local Infrastructure
- Ubuntu VM with Docker
- Ollama for local LLM inference
- PM2 for process management
- External access via Cloudflare tunnel

### Google Cloud
- Cloud Run for serverless deployment
- Memorystore for Redis
- Secret Manager for credentials
- Cloud Load Balancing

### Hybrid
- Local LLM processing
- Cloud-based MCP gateway
- Cloudflare for DNS and tunneling

## Security Features

- **OAuth 2.1 JWT Authentication**: Industry-standard client authentication
- **Token Blacklisting**: Redis-backed persistent blacklist for revoked tokens
- **Rate Limiting**: express-rate-limit with configurable thresholds
- **Audit Logging**: Comprehensive logging of all authentication and request events
- **HTTPS/TLS**: Encrypted transport for all communications
- **Environment-based Secrets**: No hardcoded credentials

## Performance

Typical response times for production deployment:
- Token generation: <100ms
- Token validation: <50ms
- MCP tool invocation: <500ms
- End-to-end request: <1000ms

## Compatibility

- **ServiceNow**: Tokyo release and later with AI Platform
- **MCP Specification**: JSON-RPC 2.0 protocol
- **Languages**: JavaScript (Node.js 18.x+), TypeScript, Python (3.9+)
- **Storage**: Redis 6.x+, PostgreSQL, Firestore, or file-based
- **Platforms**: Local VMs, Google Cloud Run, AWS, Azure

## Use Cases

- **AI-Powered Service Catalog**: Connect ServiceNow to local LLMs for intelligent catalog item recommendations
- **Automated Incident Classification**: Use custom AI models to categorize and route incidents
- **Knowledge Base Enhancement**: Integrate local vector databases for improved knowledge search
- **Custom Chatbots**: Deploy domain-specific LLMs for ServiceNow virtual agents
- **Compliance & Privacy**: Keep sensitive data processing on-premises while leveraging ServiceNow platform

## Project Status

**Current Version**: 3.3.0 (Production Ready)

✅ OAuth 2.1 with PKCE authentication  
✅ JWT token management with blacklisting  
✅ Rate limiting and security hardening  
✅ Multiple deployment templates  
✅ Comprehensive documentation  
🚧 Community use cases and examples  
🚧 Additional AI service integrations  

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where contributions would be valuable:
- Additional deployment templates (AWS, Azure)
- Integration examples with other LLM frameworks
- Performance optimizations
- Security enhancements
- Documentation improvements

## Support

- **Issues**: Report bugs or request features via GitHub Issues
- **Discussions**: Join conversations in GitHub Discussions
- **Security**: Report vulnerabilities via [SECURITY.md](SECURITY.md)

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Built for the ServiceNow and MCP practitioner communities
- Implements OAuth 2.1 standards per [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068)
- Follows MCP specification from [Model Context Protocol](https://modelcontextprotocol.io/)

## Related Projects

- [Anthropic MCP Specification](https://github.com/anthropics/mcp)
- [ServiceNow Developer Documentation](https://developer.servicenow.com/)
- [Ollama](https://ollama.ai/) - Local LLM runtime

---

**Built with ❤️ for the ServiceNow and AI communities**

For questions or feedback, please open an issue or start a discussion.

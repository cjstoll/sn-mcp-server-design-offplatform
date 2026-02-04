# ServiceNow AI Agent Fabric 
### MCP Server Implementation - Hosted: Off Platform

Production-ready guidance for Model Context Protocol (MCP) server implementation(s) of hosted AI services and LLMs for integration to ServiceNow AI Platform instances.  

💡**NOTE:** This is not about setting up MCP Server(s) within a ServiceNow instance aka ON PLATFORM.

TL;DR - If you are not interested in the creation, thought, and work that went into this then **[Go Here](deployment/DEPLOYMENT_GUIDE.md)** an just dive into the the deployment steps.

---

## Preface

This project represents a collaborative effort between a ServiceNow practitioner and Claude (Anthropic's AI assistant) to create comprehensive, production-ready MCP server implementations for the ServiceNow community.

### How This Project Came Together

The majority of this project's content—including documentation, code templates, implementation guides, and technical specifications—was generated through an iterative collaboration with Claude AI. This work demonstrates how AI can accelerate technical documentation and reference implementation development when guided by domain expertise and real-world implementation experience.

**The Collaboration Process:**
- **Domain Expertise:** Practical ServiceNow and MCP server implementation knowledge, architectural decisions, and production deployment experience
- **Content Generation:** Claude AI generated documentation, code templates, pseudocode implementations, and technical specifications based on requirements and feedback
- **Iterative Refinement:** Multiple review cycles to ensure technical accuracy, completeness, and alignment with production realities
- **Quality Assurance:** Validation against working implementations and ServiceNow AI Platform requirements

### What Makes This Unique

This is not a theoretical guide—it's grounded in actual production deployments:
- All OAuth 2.1 + PKCE patterns have been validated with ServiceNow instances
- Code templates reflect real implementations running in production environments
- Architecture decisions are based on operational experience, not speculation
- Documentation includes lessons learned from actual integration challenges

### A Note on AI-Assisted Development

This project showcases the potential of human-AI collaboration in technical documentation:
- **Speed:** Comprehensive documentation created in days, not weeks
- **Consistency:** Standardized patterns and terminology throughout
- **Completeness:** 7,800+ lines of detailed implementation guidance
- **Multi-language Support:** Templates in JavaScript, TypeScript, Python, plus pseudocode
- **Professional Quality:** Production-ready code and enterprise-grade documentation

**However**, human expertise remains essential:
- Architectural decisions and design choices
- Production validation and testing
- Real-world problem-solving and troubleshooting
- Quality control and accuracy verification
- Community understanding and positioning

### Acknowledgments

**Claude (Anthropic):** Content generation, documentation structure, code template creation, technical writing, and iterative refinement based on feedback.

**Human Contributor:** Domain expertise, architectural guidance, production validation, quality assurance, project vision, and final editorial control.

This collaboration demonstrates that the best technical documentation combines AI's ability to generate comprehensive, well-structured content with human expertise in domain knowledge, real-world validation, and quality assurance.

---

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

## Documentation

### Implementation Guides

Complete implementation walkthrough (7,800 lines across 5 parts):

- **[Part 1: Overview](docs/MCP%20Server%20Implementation%20-%20Part%201%20Overview.md)** - Introduction & Requirements
- **[Part 2: Core Infrastructure](docs/MCP%20Server%20Implementation%20-%20Part%202%20Core%20Infrastructure.md)** - Server Foundation & Infrastructure
- **[Part 3: Protocol and Tools](docs/MCP%20Server%20Implementation%20-%20Part%203%20Protocol%20and%20Tools.md)** - MCP Protocol & Tools Implementation
- **[Part 4: OAuth](docs/MCP%20Server%20Implementation%20-%20Part%204%20OAuth.md)** - OAuth 2.1 Authentication & Security
- **[Part 5: Appendices](docs/MCP%20Server%20Implementation%20-%20Part%205%20Appendices.md)** - Production Deployment & Operations

### Reference Materials

**Code Templates** (all in `templates/` folder)

All templates follow the naming convention: `mcp-server-[language]-template.[ext]`

- **[Pseudocode Template](templates/mcp-server-pseudocode-template.md)**: Language-agnostic reference implementation
- **[JavaScript Template](templates/mcp-server-javascript-template.js)**: Local/VM deployment
- **[TypeScript Template](templates/mcp-server-typescript-template.ts)**: Google Cloud deployment
- **[Python Template](templates/mcp-server-python-template.py)**: FastAPI implementation

**Implementation Hints**

- **[Implementation Hints](docs/MCP%20Server%20Implementation%20-%20Implementation%20Hints.md)**: Guidance for Go, Java, C#, Rust, and other languages

### Diagrams & Visuals

- **[Diagrams](docs/diagrams/)**: OAuth flow diagrams and architecture visuals
- **[Presentation Materials](docs/presentations/)**: Conference and training presentations


## Quick Start

### Prerequisites

ServiceNow instance with AI Platform enabled

Choose your implementation language:
- **JavaScript/Node.js**: Node.js 18+ (local deployment)
- **TypeScript**: Node.js 18+ (Google Cloud Run optimized)
- **Python**: Python 3.9+ (FastAPI-based)

Additional solutions/resources referenced (all implementations):
- Redis (for token blacklist persistence)
- Local LLM infrastructure (Ollama, llama.cpp, etc.)

### JavaScript/Node.js (Local Deployment)

```bash
# Clone repository
git clone https://github.com/[username]/servicenow-mcp-server.git
cd servicenow-mcp-server

# Use the JavaScript template
cp templates/mcp-server-javascript-template.js server.js

# Install dependencies (you'll need to create package.json)
npm install express jsonwebtoken ioredis cors

# Configure environment
# Create .env file with your ServiceNow instance details

# Start server
node server.js
```

### TypeScript (Google Cloud Deployment)

The TypeScript template is optimized for Google Cloud Run. See [Google Cloud Run documentation](https://cloud.google.com/run/docs/quickstarts/deploy-container) for deployment instructions.

```bash
# Use the TypeScript template
cp templates/mcp-server-typescript-template.ts src/index.ts

# Follow Google Cloud Run deployment guide
```

### Python (FastAPI)

```bash
# Clone repository
git clone https://github.com/[username]/servicenow-mcp-server.git
cd servicenow-mcp-server

# Use the Python template
cp templates/mcp-server-python-template.py main.py

# Install dependencies
pip install fastapi uvicorn pyjwt cryptography python-multipart

# Configure environment
# Create .env file with your ServiceNow instance details

# Start server
uvicorn main:app --host 0.0.0.0 --port 3000 --reload
```

## Deployment Options

### Local Infrastructure
- Ubuntu VM with Docker
- Ollama for local LLM inference
- PM2 for process management
- External access via Cloudflare tunnel
- Use the JavaScript template as starting point

### Google Cloud
- Cloud Run for serverless deployment
- Memorystore for Redis
- Secret Manager for credentials
- Cloud Load Balancing
- See [Google Cloud Run documentation](https://cloud.google.com/run/docs) for deployment guide
- Use the TypeScript template as starting point

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

- **ServiceNow**: Yokohama (Patch 9) release and later with AI Platform (latest Zurich release - Recommended)
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

<!--
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

-->

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Built for the ServiceNow and MCP practitioner communities
- Implements OAuth 2.1 standards per [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068)
- Follows MCP specification from [Model Context Protocol](https://modelcontextprotocol.io/)

## Related Content

- [Anthropic MCP Specification](https://github.com/anthropics/mcp)
- [ServiceNow Documentation](https://www.servicenow.com/docs/)
- [ServiceNow Developer Documentation](https://developer.servicenow.com/)
- [Ollama](https://ollama.ai/) - Local LLM runtime

---

**Built with ❤️ for the ServiceNow and AI communities**

For questions or feedback, please open an issue or start a discussion.

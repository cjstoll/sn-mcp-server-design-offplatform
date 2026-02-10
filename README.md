# ServiceNow AI Agent Fabric 


🆘 **DISCLAIMER**: This is not OFFICIAL ServiceNow documentation or guidance. 🆘

🚀 See the [Contributing](#contributing) section to report any Issues or Discuss the content within this repo.

---

### MCP Server Implementation - Hosted: Off Platform

Comprehensive implementation guidance for Model Context Protocol (MCP) server deployment with OAuth 2.1 + PKCE authentication for integration to ServiceNow AI Platform instances.

💡**NOTE:** This is not about setting up MCP Server(s) within a ServiceNow instance aka ON PLATFORM.

## Quick Navigation

- **Experienced Practitioners:** Jump to [Implementation Guide](docs/README.md) or [Templates](templates/README.md)
- **ServiceNow Administrators:** Start with [Part 1: Overview](docs/MCP%20Server%20Implementation%20-%20Part%201%20Overview.md)
- **AI Stewards & Architects:** Review [Architecture & Security](docs/MCP%20Server%20Implementation%20-%20Part%204%20OAuth.md)
- **New to MCP:** Read [Project Overview](#overview) below, then start with Part 1


TL;DR - If you are not interested in the creation, thought, and work that went into this then **[Go Here](deployment/README.md)** and just dive into the deployment steps.

---

## Before You Start

**This repository is a guide, not a deployment package.** 

You will spend:
- **6-12 hours** reading documentation and understanding patterns
- **4-20 hours** configuring deployment infrastructure (depending on platform and experience)
- **2-4 hours** testing ServiceNow integration

If you need a fully-configured deployment solution, this repository provides the foundation but requires infrastructure expertise to complete.

If you want to **learn** how to build production-quality MCP servers with OAuth 2.1 + PKCE, you're in the right place.

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

This repository provides **comprehensive implementation guidance and production-quality reference code** for building secure MCP servers that integrate ServiceNow cloud instances with local AI infrastructure.

**Target Audience:** Experienced practitioners with:
- Development language expertise (JavaScript, TypeScript, Python, or translation skills)
- Deployment infrastructure knowledge (VMs, containers, cloud platforms)
- ServiceNow administration or development experience
- Familiarity with OAuth 2.1 concepts and HTTP/REST APIs

**What This Repository Provides:**
- 7,800+ lines of comprehensive implementation documentation
- Production-quality code templates demonstrating OAuth 2.1 + PKCE patterns
- ServiceNow integration guidance and protocol compliance patterns
- Architecture decision frameworks and security best practices

**What You Bring:**
- Infrastructure provisioning and configuration
- Environment-specific setup (networking, TLS/HTTPS, secrets management)
- Testing frameworks and validation for your environment
- Monitoring, logging, and operational tooling
- CI/CD pipelines tailored to your workflow

### What Problem Does This Solve?

ServiceNow's AI Platform enables powerful automation and intelligence capabilities, but implementing secure MCP servers requires:
- Understanding complex OAuth 2.1 + PKCE authentication patterns
- Implementing MCP protocol correctly for ServiceNow integration
- Making architecture decisions about storage, deployment, and security
- Following production-quality patterns for security hardening

**This repository solves the documentation gap** by providing:
- Clear implementation guidance for OAuth 2.1 + PKCE authentication
- Production-quality code demonstrating security best practices
- ServiceNow-specific integration patterns and protocol compliance
- Architectural decision frameworks for storage and deployment choices
- Multi-language reference implementations with detailed explanations

**What this repository does NOT provide:**
- Turnkey deployment scripts for every infrastructure configuration
- Environment-specific infrastructure setup (your infrastructure, your choices)
- Pre-configured monitoring, logging, or operational tooling
- One-size-fits-all solutions (we provide frameworks; you make decisions)

### Documentation Features

### Implementation Guidance
- **7,800+ lines** of comprehensive documentation across 5 parts
- **Progressive learning path:** Foundation → Infrastructure → Protocol → Security → Deployment
- **Architecture decision frameworks** for storage, scaling, and deployment choices
- **Production patterns** for rate limiting, audit logging, and error handling
- **Clear security rationale** for every authentication and authorization decision

### Reference Code Quality
- **OAuth 2.1 with PKCE**: Complete implementation following machine-to-machine patterns
- **JWT Token Management**: Secure token generation, validation, blacklisting, and rotation
- **MCP Protocol Compliance**: Aligned with MCP specification requirements
- **ServiceNow Integration**: Protocol compliance verified against ServiceNow requirements
- **Multi-Language Support**: JavaScript, TypeScript, Python templates plus language-agnostic pseudocode

### ServiceNow-Specific Guidance
- **Connection Configuration:** Step-by-step ServiceNow MCP client setup
- **Authentication Patterns:** M2M authentication with trust boundary explanation
- **Troubleshooting Guide:** Common integration issues and resolutions
- **Testing Progression:** Connection → Auth → Tools → Integration validation

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

**Note:** This diagram shows reference implementation patterns. Your deployment choices for storage (Redis/file/database), infrastructure (VM/cloud/containers), and tooling will vary based on your requirements. See [Part 2: Core Infrastructure](docs/MCP%20Server%20Implementation%20-%20Part%202%20Core%20Infrastructure.md) for decision frameworks.

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
# Fork repository on GitHub, then clone your fork
git clone https://github.com/YOUR-USERNAME/sn-mcp-server-design-offplatform.git
cd sn-mcp-server-design-offplatform

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
# Fork repository on GitHub, then clone your fork
git clone https://github.com/YOUR-USERNAME/sn-mcp-server-design-offplatform.git
cd sn-mcp-server-design-offplatform

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
- **Languages**: JavaScript (Node.js 18.x+), TypeScript, Python 3.9+

## Contributing

For questions, issues, or contributions:

**Issues** - Report problems or request features:
- [Documentation Issue](https://github.com/cjstoll/sn-mcp-server-design-offplatform/issues/new?labels=documentation) - Documentation errors, unclear instructions, or missing content
- [Feature Request](https://github.com/cjstoll/sn-mcp-server-design-offplatform/issues/new?labels=enhancement) - Suggest new features or improvements
- [Implementation Question](https://github.com/cjstoll/sn-mcp-server-design-offplatform/issues/new?labels=question) - Technical questions about implementation

**Discussions** - Community conversation:
- [General](https://github.com/cjstoll/sn-mcp-server-design-offplatform/discussions/categories/general) - General discussion about the project
- [Ideas](https://github.com/cjstoll/sn-mcp-server-design-offplatform/discussions/categories/ideas) - Share ideas and suggestions
- [Q&A](https://github.com/cjstoll/sn-mcp-server-design-offplatform/discussions/categories/q-a) - Ask questions and help others

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments & Related Content

- Built for the ServiceNow and MCP practitioner communities
- Implements OAuth 2.1 standards per [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068)
- Follows MCP specification from [Model Context Protocol](https://modelcontextprotocol.io/)
- [Anthropic MCP Specification](https://github.com/anthropics/mcp)
- [ServiceNow Documentation](https://www.servicenow.com/docs/)
- [ServiceNow Developer Documentation](https://developer.servicenow.com/)

---

**Built with ❤️ for the ServiceNow and AI communities**

# Contributing to ServiceNow MCP Server

Thank you for your interest in contributing to this project! This guide will help you get started.

## Code of Conduct

This project welcomes contributions from everyone. Please be respectful, constructive, and professional in all interactions.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear description**: What happened vs. what you expected
- **Reproduction steps**: Minimal steps to reproduce the issue
- **Environment details**: OS, Node.js version, deployment type (local/cloud)
- **Logs**: Relevant error messages or stack traces
- **Configuration**: Sanitized configuration (remove secrets!)

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Use case**: What problem does this solve?
- **Proposed solution**: How should it work?
- **Alternatives considered**: What other approaches did you consider?
- **Impact**: Who benefits from this enhancement?

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow existing code style**: Match formatting and conventions
3. **Add tests** if adding new functionality
4. **Update documentation** for any changed behavior
5. **Ensure all tests pass** before submitting
6. **Write clear commit messages** describing what and why

## Development Setup

```bash
# Fork and clone your fork
git clone https://github.com/[your-username]/servicenow-mcp-server.git
cd servicenow-mcp-server

# Add upstream remote
git remote add upstream https://github.com/[original-owner]/servicenow-mcp-server.git

# Choose your implementation language

# For JavaScript/Node.js (local):
cd implementations/javascript-local
npm install
npm test

# For TypeScript (Google Cloud):
cd implementations/typescript-gcp
npm install
npm test

# For Python/FastAPI:
cd implementations/python-fastapi
pip install -r requirements.txt
pytest
```

## Coding Standards

### JavaScript/TypeScript

- Use TypeScript for production implementations where possible
- Follow ESLint configuration (when provided)
- Use meaningful variable and function names
- Add JSDoc comments for public APIs
- Prefer async/await over callbacks
- Handle errors explicitly

### Python

- Follow PEP 8 style guide
- Use type hints (Python 3.9+ syntax)
- Use Pydantic models for data validation
- Add docstrings for all public functions/classes
- Prefer async/await with FastAPI
- Handle exceptions explicitly

### Security

- Never commit secrets, tokens, or credentials
- Use environment variables for configuration
- Validate all inputs
- Follow OAuth 2.1 best practices
- Document security implications of changes

### Documentation

- Update README.md for user-facing changes
- Add inline comments for complex logic
- Include examples in documentation
- Keep documentation in sync with code

## Testing Guidelines

### What to Test

- OAuth authentication flows
- Token validation and blacklisting
- Rate limiting behavior
- Error handling
- MCP protocol compliance

### Running Tests

```bash
# Run all tests
npm test

# Run specific test suite
npm test -- --grep "OAuth"

# Run with coverage
npm run test:coverage
```

## Areas Seeking Contributions

### High Priority

- **AWS Deployment Template**: CloudFormation or CDK implementation
- **Azure Deployment Template**: ARM template or Bicep
- **Kubernetes Deployment**: Helm charts for container orchestration
- **Additional Language Implementations**: Go, Java/Spring Boot, C#/.NET (expand beyond JS/TS/Python)
- **Additional Tests**: Expand test coverage for edge cases

### Medium Priority

- **Integration Examples**: Sample implementations with different LLM frameworks
- **Performance Benchmarks**: Systematic performance testing and optimization
- **Monitoring Templates**: Prometheus, Grafana, or CloudWatch configurations
- **Documentation Improvements**: Tutorials, troubleshooting guides, video walkthroughs

### Community Requested

- **Multi-tenant Support**: Isolate multiple ServiceNow instances
- **Plugin System**: Extensible architecture for custom integrations
- **Admin UI**: Web-based configuration and monitoring
- **Advanced Rate Limiting**: Per-client quotas and burst handling

## Deployment Template Contributions

When adding new deployment templates:

1. **Create directory** under `implementations/[platform-name]`
2. **Include README.md** with deployment instructions
3. **Provide configuration templates** for the platform
4. **Document prerequisites** and dependencies
5. **Add deployment scripts** or automation
6. **Include troubleshooting section**

Example structure:
```
implementations/aws-deployment/
├── README.md
├── cloudformation/
│   └── mcp-server-stack.yaml
├── config/
│   └── template.env
├── scripts/
│   └── deploy.sh
└── src/
    └── index.ts
```

## Documentation Contributions

- **Fix typos and clarity issues**: Always welcome via quick PRs
- **Add examples**: Real-world use cases help others
- **Improve diagrams**: Visual aids enhance understanding
- **Translate**: Internationalization appreciated (coordinate first)

## Commit Message Guidelines

Use clear, concise commit messages:

```
feat: add AWS deployment template
fix: resolve token blacklist race condition
docs: update OAuth flow documentation
refactor: simplify rate limiting logic
test: add token validation test cases
```

Format: `type: description`

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

## Review Process

1. **Automated checks**: CI/CD runs tests and linting
2. **Code review**: Maintainer reviews code quality and design
3. **Documentation review**: Ensure docs are updated
4. **Security review**: Check for security implications
5. **Approval and merge**: Maintainer merges when ready

## Questions?

- Open an issue for general questions
- Use GitHub Discussions for broader topics
- Tag issues with `question` label

## Recognition

Contributors will be recognized in:
- Repository contributors page
- Release notes for significant contributions
- README acknowledgments section

Thank you for contributing to the ServiceNow MCP Server community! 🎉

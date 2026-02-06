# Language Implementation Hints Guide

## Overview

This guide provides language-specific implementation hints for building MCP (Model Context Protocol) servers with OAuth 2.1 + PKCE authentication in **Go**, **Java/Spring Boot**, **C#/.NET**, and **Rust**. 

These hints complement the comprehensive pseudocode template and reference implementations (JavaScript, TypeScript, Python) by highlighting language-specific libraries, patterns, and considerations.

**Target Audience:** Developers who want to implement an MCP server in one of these languages and need guidance on appropriate libraries and language-specific patterns.

**What This Guide Covers:**
- Recommended libraries and frameworks for each language
- OAuth 2.1 + PKCE implementation approaches
- JWT token management patterns
- Storage options for persistent data
- Language-specific best practices
- Common pitfalls and how to avoid them

**What This Guide Does NOT Cover:**
- Complete code implementations (refer to pseudocode template and reference implementations)
- Language syntax tutorials
- Framework-specific tutorials (refer to official documentation)

---

## Table of Contents

1. [Common Patterns Across All Languages](#common-patterns-across-all-languages)
2. [Go Implementation Hints](#go-implementation-hints)
3. [Java/Spring Boot Implementation Hints](#javaspring-boot-implementation-hints)
4. [C#/.NET Implementation Hints](#cnet-implementation-hints)
5. [Rust Implementation Hints](#rust-implementation-hints)
6. [Docker Containerization Hints](#docker-containerization-hints)
7. [Storage Backend Recommendations](#storage-backend-recommendations)
8. [Security Considerations by Language](#security-considerations-by-language)

---

## Common Patterns Across All Languages

Before diving into language-specific hints, here are patterns that apply universally:

### OAuth 2.1 Flow Requirements

All implementations must support:
- **Dynamic Client Registration (RFC 7591)** - `/register` endpoint
- **Authorization Code Flow with PKCE** - `/oauth/authorize` and `/oauth/token` endpoints
- **Token Revocation (RFC 7009)** - `/oauth/revoke` endpoint
- **PKCE Validation** - S256 (SHA-256) and plain methods
- **JWT Token Management** - HS256 or RS256 signing
- **Token Blacklist** - For revoked tokens with automatic cleanup

### MCP Protocol Requirements

All implementations must handle:
- **JSON-RPC 2.0** - Request/response format
- **Protocol Version** - 2025-06-18 or later
- **Methods** - initialize, tools/list, tools/call (minimum)
- **Optional Methods** - resources/list, resources/read, prompts/list, prompts/get
- **Notifications** - Accept but don't respond to notification methods

### Storage Requirements

All implementations need persistent storage for:
- **Client Registry** - OAuth client credentials and metadata
- **Authorization Codes** - Temporary codes with automatic expiration
- **Token Blacklist** - Revoked token identifiers (JTI) with TTL
- **Rate Limiting** - Request counters per client/IP

### Security Requirements

All implementations must include:
- **HTTPS/TLS** - Required for OAuth 2.1 in production
- **PKCE Validation** - Mandatory for authorization code flow
- **Token Rotation** - New refresh token on each use
- **Rate Limiting** - Protect against abuse
- **Audit Logging** - Track security-relevant events

---

### Generating Secure Secrets

All MCP server deployments require cryptographically secure secrets for JWT signing and DCR endpoint protection. Generate these before first deployment.

**Using OpenSSL (Cross-Platform):**
```bash
# Generate JWT_SECRET (base64-encoded, 32 bytes)
openssl rand -base64 32

# Generate DCR_AUTH_TOKEN (hex-encoded, 32 bytes)  
openssl rand -hex 32
```

**Best Practice:** Generate new secrets for each environment (development, staging, production). Never reuse secrets across environments.

💡 **Cloud Deployments:** For Google Cloud Run, AWS Lambda, or Azure Functions, use the platform's secret manager instead of `.env` files:
- **GCP:** `gcloud secrets create jwt-secret --data-file=-` (paste secret when prompted)
- **AWS:** `aws secretsmanager create-secret --name jwt-secret --secret-string "your-secret"`
- **Azure:** `az keyvault secret set --vault-name myvault --name jwt-secret --value "your-secret"`

---

## Go Implementation Hints

### Recommended Web Framework

**Chi Router** or **Gin** for HTTP routing:
```go
import (
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
)

r := chi.NewRouter()
r.Use(middleware.Logger)
r.Use(middleware.Recoverer)
```

**Why Chi/Gin?**
- Lightweight and performant
- Excellent middleware support
- Idiomatic Go patterns
- Good community support

**Alternative:** Standard library `net/http` with custom routing (more verbose but no dependencies)

### OAuth 2.1 Libraries

**Primary Recommendation:** `golang.org/x/oauth2`
```go
import "golang.org/x/oauth2"
import "golang.org/x/oauth2/clientcredentials"

config := &oauth2.Config{
    ClientID:     "your-client-id",
    ClientSecret: "your-client-secret",
    Endpoint: oauth2.Endpoint{
        AuthURL:  "https://mcp-server.example.com/oauth/authorize",
        TokenURL: "https://mcp-server.example.com/oauth/token",
    },
    RedirectURL: "https://your-app.com/callback",
}
```

**For PKCE:**
```go
import "golang.org/x/oauth2"

// Generate code verifier and challenge
verifier := oauth2.GenerateVerifier()
challenge := oauth2.S256ChallengeFromVerifier(verifier)

// Use in authorization request
authURL := config.AuthCodeURL("state",
    oauth2.SetAuthURLParam("code_challenge", challenge),
    oauth2.SetAuthURLParam("code_challenge_method", "S256"),
)
```

### JWT Token Management

**Recommended Library:** `github.com/golang-jwt/jwt/v5`
```go
import "github.com/golang-jwt/jwt/v5"

// Create token
claims := jwt.MapClaims{
    "sub":       userID,
    "client_id": clientID,
    "scope":     scope,
    "type":      "access",
    "iat":       time.Now().Unix(),
    "exp":       time.Now().Add(time.Hour).Unix(),
    "iss":       issuer,
    "jti":       uuid.New().String(),
}

token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
tokenString, err := token.SignedString([]byte(jwtSecret))

// Verify token
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method")
    }
    return []byte(jwtSecret), nil
})

if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
    // Token is valid, use claims
}
```

### PKCE Implementation

**SHA-256 Hashing:**
```go
import (
    "crypto/sha256"
    "encoding/base64"
)

func validatePKCE(verifier, challenge, method string) bool {
    if method == "S256" {
        hash := sha256.Sum256([]byte(verifier))
        computed := base64.URLEncoding.WithPadding(base64.NoPadding).
            EncodeToString(hash[:])
        return computed == challenge
    } else if method == "plain" {
        return verifier == challenge
    }
    return false
}
```

### Storage Options

**Redis for Token Blacklist and Rate Limiting:**
```go
import "github.com/redis/go-redis/v9"

rdb := redis.NewClient(&redis.Options{
    Addr: "localhost:6379",
})

// Add to blacklist with TTL
ctx := context.Background()
err := rdb.SetEx(ctx, "revoked:"+jti, "1", time.Duration(ttl)*time.Second).Err()

// Check if revoked
exists, err := rdb.Exists(ctx, "revoked:"+jti).Result()
```

**PostgreSQL for Client Registry:**
```go
import (
    "database/sql"
    _ "github.com/lib/pq"
)

db, err := sql.Open("postgres", "postgres://user:pass@localhost/mcp?sslmode=disable")

// Store client
_, err = db.Exec(
    "INSERT INTO clients (client_id, client_secret, client_name, redirect_uris) VALUES ($1, $2, $3, $4)",
    clientID, clientSecret, clientName, redirectURIs,
)
```

**Alternative:** Use `pgx` for better PostgreSQL support or `gorm` for ORM

### Concurrency Considerations

**Goroutines for Concurrent MCP Requests:**
```go
// Handle multiple MCP connections concurrently
func handleMCPConnection(conn net.Conn) {
    go func() {
        defer conn.Close()
        // Handle MCP protocol here
    }()
}
```

**Rate Limiting with Sync Primitives:**
```go
import "sync"

var rateMutex sync.RWMutex
var rateStore = make(map[string]*RateLimit)

func checkRateLimit(clientKey string) error {
    rateMutex.Lock()
    defer rateMutex.Unlock()
    
    // Rate limit logic here
}
```

**Warning:** Be careful with goroutines and shared state. Use mutexes or channels to prevent race conditions.

### JSON-RPC 2.0 Handling

**Recommended:** Custom JSON-RPC handling with standard library
```go
import "encoding/json"

type JSONRPCRequest struct {
    JSONRPC string                 `json:"jsonrpc"`
    Method  string                 `json:"method"`
    Params  map[string]interface{} `json:"params,omitempty"`
    ID      *string                `json:"id,omitempty"`
}

type JSONRPCResponse struct {
    JSONRPC string      `json:"jsonrpc"`
    ID      *string     `json:"id,omitempty"`
    Result  interface{} `json:"result,omitempty"`
    Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
    Code    int         `json:"code"`
    Message string      `json:"message"`
    Data    interface{} `json:"data,omitempty"`
}
```

### Performance Tips

1. **Use `sync.Pool` for frequently allocated objects** (JWT claims, request structs)
2. **Connection pooling** for database connections
3. **Compile with race detector during development:** `go build -race`
4. **Profile with pprof** to identify bottlenecks
5. **Consider using `fasthttp` instead of `net/http`** for extreme performance needs

### Common Pitfalls

❌ **Don't:** Use global variables for request-scoped data  
✅ **Do:** Use `context.Context` to pass request data through call chain

❌ **Don't:** Ignore errors (Go's explicit error handling is a feature)  
✅ **Do:** Check and handle all errors appropriately

❌ **Don't:** Block goroutines indefinitely  
✅ **Do:** Use context cancellation and timeouts

---

## Java/Spring Boot Implementation Hints

### Recommended Framework

**Spring Boot** with **Spring Security OAuth2**:
```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-oauth2-resource-server</artifactId>
    </dependency>
</dependencies>
```

**Why Spring Boot?**
- Enterprise-standard framework
- Excellent OAuth 2.1 support out of the box
- Comprehensive security features
- Large ecosystem and community
- Built-in dependency injection

### OAuth 2.1 Configuration

**Authorization Server Configuration:**
```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig {
    
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // Store registered OAuth clients
        return new InMemoryRegisteredClientRepository();
        // In production: Use JdbcRegisteredClientRepository
    }
    
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // Configure JWT signing keys
        RSAKey rsaKey = generateRsaKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }
}
```

**PKCE Support:**
Spring Security OAuth2 includes built-in PKCE support:
```java
@Configuration
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) 
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .authorizationEndpoint(authorizationEndpoint ->
                authorizationEndpoint
                    .consentPage("/oauth2/consent")
            );
        
        return http.build();
    }
}
```

### JWT Token Management

**Using Spring Security OAuth2:**
```java
import org.springframework.security.oauth2.jwt.*;

@Service
public class TokenService {
    
    @Autowired
    private JwtEncoder jwtEncoder;
    
    public String createAccessToken(String userId, String clientId, String scope) {
        Instant now = Instant.now();
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
            .issuer("https://mcp-server.example.com")
            .subject(userId)
            .claim("client_id", clientId)
            .claim("scope", scope)
            .claim("type", "access")
            .issuedAt(now)
            .expiresAt(now.plusSeconds(3600))
            .claim("jti", UUID.randomUUID().toString())
            .build();
        
        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
    
    @Autowired
    private JwtDecoder jwtDecoder;
    
    public Jwt verifyToken(String token) {
        return jwtDecoder.decode(token);
    }
}
```

**Alternative JWT Library:** `io.jsonwebtoken:jjwt`
```java
import io.jsonwebtoken.*;

String token = Jwts.builder()
    .setSubject(userId)
    .claim("client_id", clientId)
    .claim("scope", scope)
    .setIssuedAt(new Date())
    .setExpiration(new Date(System.currentTimeMillis() + 3600000))
    .signWith(SignatureAlgorithm.HS256, jwtSecret)
    .compact();

Claims claims = Jwts.parser()
    .setSigningKey(jwtSecret)
    .parseClaimsJws(token)
    .getBody();
```

### Storage Options

**Redis for Token Blacklist:**
```java
import org.springframework.data.redis.core.RedisTemplate;

@Service
public class TokenBlacklistService {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    public void addToBlacklist(String jti, long ttlSeconds) {
        redisTemplate.opsForValue().set(
            "revoked:" + jti, 
            "1", 
            Duration.ofSeconds(ttlSeconds)
        );
    }
    
    public boolean isRevoked(String jti) {
        return Boolean.TRUE.equals(
            redisTemplate.hasKey("revoked:" + jti)
        );
    }
}
```

**JPA for Client Registry:**
```java
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
@Table(name = "oauth_clients")
public class OAuthClient {
    @Id
    private String clientId;
    private String clientSecret;
    private String clientName;
    
    @ElementCollection
    private List<String> redirectUris;
    
    // Getters and setters
}

public interface ClientRepository extends JpaRepository<OAuthClient, String> {
    Optional<OAuthClient> findByClientId(String clientId);
}
```

**Alternative:** Use Spring Data Redis or Lettuce for Redis, Hibernate for database

### REST Controllers

**OAuth Endpoints:**
```java
@RestController
@RequestMapping("/oauth")
public class OAuthController {
    
    @GetMapping("/authorize")
    public ResponseEntity<?> authorize(
            @RequestParam("response_type") String responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam("code_challenge_method") String codeChallengeMethod,
            @RequestParam(required = false) String state) {
        
        // Authorization logic here
        return ResponseEntity.ok().build();
    }
    
    @PostMapping("/token")
    public ResponseEntity<TokenResponse> token(@RequestBody TokenRequest request) {
        // Token exchange logic here
        return ResponseEntity.ok(tokenResponse);
    }
}
```

**MCP Endpoint:**
```java
@RestController
@RequestMapping("/mcp")
public class MCPController {
    
    @PostMapping
    public ResponseEntity<MCPResponse> handleMCP(
            @RequestHeader("Authorization") String authorization,
            @RequestBody MCPRequest request) {
        
        // Verify bearer token
        // Route to appropriate MCP handler
        return ResponseEntity.ok(response);
    }
}
```

### Rate Limiting

**Using Bucket4j:**
```java
import io.github.bucket4j.*;

@Component
public class RateLimiter {
    
    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();
    
    public Bucket resolveBucket(String key) {
        return cache.computeIfAbsent(key, k -> {
            Bandwidth limit = Bandwidth.classic(100, 
                Refill.intervally(100, Duration.ofMinutes(15)));
            return Bucket.builder()
                .addLimit(limit)
                .build();
        });
    }
    
    public boolean tryConsume(String key) {
        return resolveBucket(key).tryConsume(1);
    }
}
```

### Configuration Management

**application.properties:**
```properties
# Server Configuration
server.port=3000

# JWT Configuration
jwt.secret=${JWT_SECRET}
jwt.issuer=https://mcp-server.example.com

# OAuth Configuration
oauth.authorization-code-lifetime=300
oauth.access-token-lifetime=3600
oauth.refresh-token-lifetime=2592000

# Redis Configuration
spring.redis.host=localhost
spring.redis.port=6379

# Database Configuration
spring.datasource.url=jdbc:postgresql://localhost:5432/mcp
spring.datasource.username=${DB_USER}
spring.datasource.password=${DB_PASSWORD}
spring.jpa.hibernate.ddl-auto=update
```

### Performance Tips

1. **Use connection pooling** - HikariCP (default in Spring Boot) is excellent
2. **Enable caching** - Use Spring Cache abstraction with Redis
3. **Async processing** - Use `@Async` for non-blocking operations
4. **JVM tuning** - Adjust heap size and GC settings for production
5. **Actuator monitoring** - Enable Spring Boot Actuator for health checks and metrics

### Common Pitfalls

❌ **Don't:** Use field injection (`@Autowired` on fields)  
✅ **Do:** Use constructor injection for better testability

❌ **Don't:** Block reactive/async threads  
✅ **Do:** Use proper async patterns with CompletableFuture

❌ **Don't:** Store sensitive data in plain text properties  
✅ **Do:** Use Spring Cloud Config or external secret management

---

## C#/.NET Implementation Hints

### Recommended Framework

**ASP.NET Core** with **IdentityServer** or **Duende IdentityServer**:
```bash
dotnet new webapi -n MCPServer
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Duende.IdentityServer
```

**Why ASP.NET Core?**
- Modern, cross-platform framework
- Excellent OAuth/OpenID Connect support
- Built-in dependency injection
- Strong typing with C#
- Great performance

### OAuth 2.1 Configuration

**Using Duende IdentityServer:**
```csharp
using Duende.IdentityServer.Models;

public static class Config
{
    public static IEnumerable<Client> Clients =>
        new List<Client>
        {
            new Client
            {
                ClientId = "mcp-client",
                ClientSecrets = { new Secret("secret".Sha256()) },
                AllowedGrantTypes = GrantTypes.Code,
                RequirePkce = true,
                RedirectUris = { "https://client.example.com/callback" },
                AllowedScopes = { "openid", "profile", "email" }
            }
        };
}

// In Startup.cs or Program.cs
builder.Services.AddIdentityServer()
    .AddInMemoryClients(Config.Clients)
    .AddInMemoryIdentityResources(Config.IdentityResources)
    .AddInMemoryApiScopes(Config.ApiScopes)
    .AddDeveloperSigningCredential();
```

**Alternative:** Build custom OAuth server using ASP.NET Core Identity

### JWT Token Management

**Using Microsoft.IdentityModel.Tokens:**
```csharp
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

public class TokenService
{
    private readonly string _secret;
    private readonly string _issuer;
    
    public string CreateAccessToken(string userId, string clientId, string scope)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_secret);
        
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim("client_id", clientId),
                new Claim("scope", scope),
                new Claim("type", "access"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            Issuer = _issuer,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key), 
                SecurityAlgorithms.HmacSha256Signature
            )
        };
        
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
    
    public ClaimsPrincipal ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_secret);
        
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidIssuer = _issuer,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero
        };
        
        return tokenHandler.ValidateToken(token, validationParameters, out _);
    }
}
```

### PKCE Implementation

**SHA-256 Hashing:**
```csharp
using System.Security.Cryptography;
using System.Text;

public class PKCEValidator
{
    public bool ValidatePKCE(string verifier, string challenge, string method)
    {
        if (method == "S256")
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(verifier));
            var computed = Base64UrlEncode(hash);
            return computed == challenge;
        }
        else if (method == "plain")
        {
            return verifier == challenge;
        }
        return false;
    }
    
    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}
```

### Storage Options

**Redis for Token Blacklist:**
```csharp
using StackExchange.Redis;

public class TokenBlacklistService
{
    private readonly IDatabase _redis;
    
    public TokenBlacklistService(IConnectionMultiplexer redis)
    {
        _redis = redis.GetDatabase();
    }
    
    public async Task AddToBlacklistAsync(string jti, TimeSpan ttl)
    {
        await _redis.StringSetAsync($"revoked:{jti}", "1", ttl);
    }
    
    public async Task<bool> IsRevokedAsync(string jti)
    {
        return await _redis.KeyExistsAsync($"revoked:{jti}");
    }
}
```

**Entity Framework Core for Client Registry:**
```csharp
using Microsoft.EntityFrameworkCore;

public class OAuthClient
{
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public string ClientName { get; set; }
    public List<string> RedirectUris { get; set; }
    public List<string> GrantTypes { get; set; }
    public bool UsePkce { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class MCPDbContext : DbContext
{
    public DbSet<OAuthClient> Clients { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<OAuthClient>()
            .HasKey(c => c.ClientId);
        
        modelBuilder.Entity<OAuthClient>()
            .Property(c => c.RedirectUris)
            .HasConversion(
                v => string.Join(',', v),
                v => v.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList()
            );
    }
}
```

### API Controllers

**OAuth Endpoints:**
```csharp
[ApiController]
[Route("oauth")]
public class OAuthController : ControllerBase
{
    [HttpGet("authorize")]
    public IActionResult Authorize(
        [FromQuery] string response_type,
        [FromQuery] string client_id,
        [FromQuery] string redirect_uri,
        [FromQuery] string code_challenge,
        [FromQuery] string code_challenge_method,
        [FromQuery] string? state)
    {
        // Authorization logic
        return Redirect($"{redirect_uri}?code={authCode}&state={state}");
    }
    
    [HttpPost("token")]
    public async Task<ActionResult<TokenResponse>> Token(
        [FromForm] TokenRequest request)
    {
        // Token exchange logic
        return Ok(tokenResponse);
    }
}
```

**MCP Endpoint:**
```csharp
[ApiController]
[Route("mcp")]
[Authorize]
public class MCPController : ControllerBase
{
    [HttpPost]
    public async Task<ActionResult<MCPResponse>> HandleMCP(
        [FromBody] MCPRequest request)
    {
        // Route to appropriate handler
        return Ok(response);
    }
}
```

### Configuration Management

**appsettings.json:**
```json
{
  "Jwt": {
    "Secret": "your-secret-key-here",
    "Issuer": "https://mcp-server.example.com",
    "AccessTokenLifetime": 3600,
    "RefreshTokenLifetime": 2592000
  },
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=mcp;Username=user;Password=pass",
    "Redis": "localhost:6379"
  },
  "OAuth": {
    "AuthorizationCodeLifetime": 300
  }
}
```

**Dependency Injection Configuration:**
```csharp
// Program.cs or Startup.cs
builder.Services.Configure<JwtSettings>(
    builder.Configuration.GetSection("Jwt"));

builder.Services.AddSingleton<IConnectionMultiplexer>(
    ConnectionMultiplexer.Connect(
        builder.Configuration.GetConnectionString("Redis")));

builder.Services.AddDbContext<MCPDbContext>(options =>
    options.UseNpgsql(
        builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<TokenBlacklistService>();
```

### Rate Limiting

**Using ASP.NET Core Rate Limiting (built-in .NET 7+):**
```csharp
using Microsoft.AspNetCore.RateLimiting;

builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
        context =>
        {
            var clientKey = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            
            return RateLimitPartition.GetFixedWindowLimiter(
                clientKey,
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 100,
                    Window = TimeSpan.FromMinutes(15),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0
                });
        });
});

app.UseRateLimiter();
```

### Performance Tips

1. **Use async/await throughout** - Don't block async methods
2. **Configure Kestrel properly** - Adjust connection limits and timeouts
3. **Use memory pooling** - `ArrayPool<T>` for temporary buffers
4. **Enable response compression** - Use gzip/brotli middleware
5. **Profile with dotTrace/PerfView** - Identify performance bottlenecks

### Common Pitfalls

❌ **Don't:** Use `.Result` or `.Wait()` on async methods (causes deadlocks)  
✅ **Do:** Use `await` for all async operations

❌ **Don't:** Create new `HttpClient` instances per request  
✅ **Do:** Use `IHttpClientFactory` for managed HTTP clients

❌ **Don't:** Ignore `IDisposable` - memory leaks are common  
✅ **Do:** Use `using` statements or dependency injection for proper disposal

---

## Rust Implementation Hints

### Recommended Web Framework

**Axum** (modern, ergonomic) or **Actix-web** (mature, performant):

**Axum Example:**
```rust
use axum::{
    Router,
    routing::{get, post},
    Json, extract::State,
};

let app = Router::new()
    .route("/oauth/authorize", get(handle_authorize))
    .route("/oauth/token", post(handle_token))
    .route("/mcp", post(handle_mcp))
    .with_state(app_state);
```

**Actix-web Example:**
```rust
use actix_web::{web, App, HttpServer};

HttpServer::new(|| {
    App::new()
        .route("/oauth/authorize", web::get().to(handle_authorize))
        .route("/oauth/token", web::post().to(handle_token))
        .route("/mcp", web::post().to(handle_mcp))
})
.bind(("0.0.0.0", 3000))?
.run()
.await
```

**Why Axum/Actix?**
- Type-safe request/response handling
- Excellent async support with Tokio
- Middleware ecosystem
- Good performance characteristics

### OAuth 2.1 Libraries

**OAuth2 Crate:**
```rust
use oauth2::{
    AuthorizationCode, AuthUrl, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenUrl,
};

// Client configuration
let client = oauth2::basic::BasicClient::new(
    ClientId::new("client_id".to_string()),
    Some(ClientSecret::new("client_secret".to_string())),
    AuthUrl::new("https://mcp-server.example.com/oauth/authorize".to_string())?,
    Some(TokenUrl::new("https://mcp-server.example.com/oauth/token".to_string())?),
);

// Generate PKCE challenge
let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

// Authorization URL with PKCE
let (auth_url, csrf_token) = client
    .authorize_url(CsrfToken::new_random)
    .set_pkce_challenge(pkce_challenge)
    .url();
```

**Note:** The `oauth2` crate is designed for OAuth clients. For building an OAuth server, you'll need to implement server-side logic manually using the patterns from the pseudocode template.

### JWT Token Management

**jsonwebtoken Crate:**
```rust
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    client_id: String,
    scope: String,
    #[serde(rename = "type")]
    token_type: String,
    exp: usize,
    iat: usize,
    iss: String,
    jti: String,
}

// Create token
fn create_access_token(user_id: &str, client_id: &str, scope: &str, secret: &[u8]) 
    -> Result<String, jsonwebtoken::errors::Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    
    let claims = Claims {
        sub: user_id.to_string(),
        client_id: client_id.to_string(),
        scope: scope.to_string(),
        token_type: "access".to_string(),
        iat: now,
        exp: now + 3600,
        iss: "https://mcp-server.example.com".to_string(),
        jti: uuid::Uuid::new_v4().to_string(),
    };
    
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
}

// Verify token
fn verify_token(token: &str, secret: &[u8]) 
    -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["https://mcp-server.example.com"]);
    
    decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
        .map(|data| data.claims)
}
```

### PKCE Implementation

**SHA-256 Hashing:**
```rust
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};

fn validate_pkce(verifier: &str, challenge: &str, method: &str) -> bool {
    match method {
        "S256" => {
            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let hash = hasher.finalize();
            
            let computed = general_purpose::URL_SAFE_NO_PAD.encode(hash);
            computed == challenge
        }
        "plain" => verifier == challenge,
        _ => false,
    }
}
```

### Storage Options

**Redis for Token Blacklist:**
```rust
use redis::AsyncCommands;

async fn add_to_blacklist(
    redis: &mut redis::aio::Connection,
    jti: &str,
    ttl: usize,
) -> redis::RedisResult<()> {
    redis.set_ex(format!("revoked:{}", jti), "1", ttl).await
}

async fn is_revoked(
    redis: &mut redis::aio::Connection,
    jti: &str,
) -> redis::RedisResult<bool> {
    redis.exists(format!("revoked:{}", jti)).await
}
```

**SQLx for PostgreSQL:**
```rust
use sqlx::{PgPool, postgres::PgPoolOptions};

#[derive(sqlx::FromRow)]
struct OAuthClient {
    client_id: String,
    client_secret: String,
    client_name: String,
    redirect_uris: Vec<String>,
}

// Create pool
let pool = PgPoolOptions::new()
    .max_connections(5)
    .connect("postgresql://user:pass@localhost/mcp")
    .await?;

// Insert client
sqlx::query!(
    "INSERT INTO oauth_clients (client_id, client_secret, client_name, redirect_uris) 
     VALUES ($1, $2, $3, $4)",
    client_id, client_secret, client_name, &redirect_uris
)
.execute(&pool)
.await?;

// Query client
let client = sqlx::query_as!(
    OAuthClient,
    "SELECT * FROM oauth_clients WHERE client_id = $1",
    client_id
)
.fetch_one(&pool)
.await?;
```

### Request Handlers (Axum Example)

**OAuth Endpoints:**
```rust
use axum::{
    extract::{Query, State, Json},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct AuthorizeParams {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    state: Option<String>,
}

async fn handle_authorize(
    Query(params): Query<AuthorizeParams>,
    State(state): State<AppState>,
) -> Result<Redirect, StatusCode> {
    // Authorization logic
    let auth_code = generate_secure_token(32);
    
    // Store authorization code
    // ...
    
    Ok(Redirect::to(&format!(
        "{}?code={}&state={}",
        params.redirect_uri,
        auth_code,
        params.state.unwrap_or_default()
    )))
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: String,
    client_secret: String,
    code_verifier: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u32,
    refresh_token: String,
    scope: String,
}

async fn handle_token(
    State(state): State<AppState>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, StatusCode> {
    // Token exchange logic
    Ok(Json(token_response))
}
```

**MCP Endpoint:**
```rust
use axum::extract::TypedHeader;
use headers::Authorization;

async fn handle_mcp(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(request): Json<MCPRequest>,
) -> Result<Json<MCPResponse>, StatusCode> {
    // Verify bearer token
    let claims = verify_token(auth.token(), &state.jwt_secret)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Route to appropriate handler
    let result = match request.method.as_str() {
        "initialize" => handle_initialize(request.params).await,
        "tools/list" => handle_tools_list(request.params).await,
        "tools/call" => handle_tools_call(request.params).await,
        _ => return Err(StatusCode::NOT_FOUND),
    }?;
    
    Ok(Json(MCPResponse {
        jsonrpc: "2.0".to_string(),
        id: request.id,
        result: Some(result),
        error: None,
    }))
}
```

### Error Handling

**Using thiserror for Custom Errors:**
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OAuthError {
    #[error("invalid_client: {0}")]
    InvalidClient(String),
    
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),
    
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            OAuthError::InvalidClient(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            OAuthError::InvalidGrant(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            OAuthError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
        };
        
        (status, Json(serde_json::json!({
            "error": error_message
        }))).into_response()
    }
}
```

### State Management

**Application State:**
```rust
#[derive(Clone)]
struct AppState {
    jwt_secret: Vec<u8>,
    redis_pool: redis::aio::ConnectionManager,
    db_pool: sqlx::PgPool,
    registered_clients: Arc<RwLock<HashMap<String, OAuthClient>>>,
}

// In main
let state = AppState {
    jwt_secret: std::env::var("JWT_SECRET")?.into_bytes(),
    redis_pool: redis::Client::open("redis://localhost")?
        .get_tokio_connection_manager()
        .await?,
    db_pool: PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?,
    registered_clients: Arc::new(RwLock::new(HashMap::new())),
};
```

### Performance Tips

1. **Use `tokio` runtime** - Excellent async performance
2. **Connection pooling** - Always use connection pools for database/Redis
3. **Avoid unnecessary clones** - Leverage Rust's ownership system
4. **Profile with `cargo-flamegraph`** - Identify hot paths
5. **Consider `deadpool` for pooling** - Better than managing connections manually

### Common Pitfalls

❌ **Don't:** Fight the borrow checker - rethink your design  
✅ **Do:** Use `Arc<RwLock<T>>` or `Arc<Mutex<T>>` for shared state

❌ **Don't:** Block the async runtime with synchronous I/O  
✅ **Do:** Use `tokio::task::spawn_blocking` for CPU-intensive work

❌ **Don't:** Panic in production code  
✅ **Do:** Return `Result` types and handle errors gracefully

❌ **Don't:** Over-optimize prematurely  
✅ **Do:** Profile first, then optimize hot paths

---

## Docker Containerization Hints

### Overview

Docker containerization enables consistent deployment across environments and simplifies scaling MCP servers. This section provides Dockerfile examples optimized for each language template, along with Docker Compose configurations for local development with Redis and database backends.

**Key Container Principles:**
- Use official language base images (minimize attack surface)
- Run as non-root user (security best practice)
- Implement health checks (enables orchestration)
- Use multi-stage builds (reduce image size)
- Mount volumes for persistent data
- Configure environment variables externally

### Dockerfile Examples by Language

#### JavaScript/Node.js Dockerfile

**For:** `mcp-server-javascript-template.js`

```dockerfile
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY server.js ./

# Create data directory for file-based storage
RUN mkdir -p /app/data

# Create non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001

# Change ownership
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8080/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Start server
CMD ["node", "server.js"]
```

#### TypeScript Dockerfile

**For:** `mcp-server-typescript-template.ts`

```dockerfile
# Multi-stage build for TypeScript
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (including devDependencies for build)
RUN npm ci

# Copy source code
COPY src/ ./src/

# Compile TypeScript
RUN npm run build

# Production stage
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production

# Copy compiled JavaScript from builder
COPY --from=builder /app/dist ./dist

# Create data directory
RUN mkdir -p /app/data

# Create non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
RUN chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8080/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

CMD ["node", "dist/server.js"]
```

#### Python Dockerfile

**For:** `mcp-server-python-template.py`

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py ./

# Create data directory
RUN mkdir -p /app/data

# Create non-root user
RUN useradd -m -u 1001 appuser && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["python", "server.py"]
```

### Docker Compose Examples

#### Basic Docker Compose (MCP Server Only)

```yaml
version: '3.8'

services:
  mcp-server:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - NODE_ENV=production
      - JWT_SECRET=${JWT_SECRET}
      - SERVICENOW_INSTANCE=${SERVICENOW_INSTANCE}
    volumes:
      - ./data:/app/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 3s
      retries: 3
```

#### Docker Compose with Redis

```yaml
version: '3.8'

services:
  mcp-server:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - NODE_ENV=production
      - JWT_SECRET=${JWT_SECRET}
      - SERVICENOW_INSTANCE=${SERVICENOW_INSTANCE}
      - REDIS_HOST=redis
      - REDIS_PORT=6379
    volumes:
      - ./data:/app/data
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes
    restart: unless-stopped

volumes:
  redis-data:
```

#### Docker Compose with PostgreSQL

```yaml
version: '3.8'

services:
  mcp-server:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - NODE_ENV=production
      - JWT_SECRET=${JWT_SECRET}
      - SERVICENOW_INSTANCE=${SERVICENOW_INSTANCE}
      - DATABASE_URL=postgresql://mcp:mcp@postgres:5432/mcp_server
      - REDIS_HOST=redis
      - REDIS_PORT=6379
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=mcp
      - POSTGRES_PASSWORD=mcp
      - POSTGRES_DB=mcp_server
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes
    restart: unless-stopped

volumes:
  postgres-data:
  redis-data:
```

### Container Best Practices

#### Security Hardening

1. **Run as Non-Root User:**
```dockerfile
# Always create and use non-root user
RUN addgroup -g 1001 -S appgroup && adduser -S appuser -u 1001
USER appuser
```

2. **Minimal Base Images:**
```dockerfile
# Use Alpine variants for smaller attack surface
FROM node:18-alpine  # ~170MB vs ~900MB for full image
FROM python:3.11-slim  # ~150MB vs ~900MB
```

3. **Multi-Stage Builds:**
```dockerfile
# Build stage (larger, includes dev tools)
FROM node:18 AS builder
# ... compile TypeScript ...

# Runtime stage (minimal, production only)
FROM node:18-alpine
COPY --from=builder /app/dist ./dist
```

#### Performance Optimization

1. **Layer Caching:**
```dockerfile
# Copy package files first (changes less frequently)
COPY package*.json ./
RUN npm ci --only=production

# Copy source code last (changes more frequently)
COPY . .
```

2. **Health Checks:**
```dockerfile
# Enable container orchestration health monitoring
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8080/health || exit 1
```

3. **Resource Limits:**
```yaml
# In docker-compose.yml
services:
  mcp-server:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

### Environment Variable Injection

#### Using .env Files (Development)

```bash
# Create .env file
cat > .env << EOF
JWT_SECRET=$(openssl rand -base64 32)
DCR_AUTH_TOKEN=$(openssl rand -base64 32)
SERVICENOW_INSTANCE=https://your-instance.service-now.com
EOF

# Run with env file
docker-compose --env-file .env up
```

#### Using Secrets (Production)

```yaml
# docker-compose.yml with secrets
version: '3.8'

services:
  mcp-server:
    environment:
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
    secrets:
      - jwt_secret

secrets:
  jwt_secret:
    external: true
```

### Volume Mounts for Persistence

```yaml
# Persistent data storage
volumes:
  - ./data:/app/data           # Client registrations
  - ./logs:/app/logs           # Log files
  - ./certs:/app/certs:ro      # TLS certificates (read-only)
```

### Common Docker Issues

**Issue:** Container exits immediately  
**Solution:** Check logs with `docker-compose logs mcp-server`, verify environment variables are set

**Issue:** Cannot connect to Redis/PostgreSQL  
**Solution:** Use service names (`redis`, `postgres`) as hostnames in container network, not `localhost`

**Issue:** Permission denied writing to /app/data  
**Solution:** Ensure volume mount has correct permissions, or create directory in Dockerfile with correct ownership

**Issue:** Health check failing  
**Solution:** Verify health check endpoint returns 200, adjust timeout/interval if app has slow startup

---

## Storage Backend Recommendations

### Redis

**Best For:**
- Token blacklist (with automatic TTL expiration)
- Authorization codes (short-lived)
- Rate limiting counters
- Session storage

**Recommended Libraries:**
- **Go:** `github.com/redis/go-redis/v9`
- **Java:** Lettuce (async) or Jedis (sync)
- **C#:** StackExchange.Redis
- **Rust:** `redis-rs`

**Key Features to Use:**
- `SETEX` for automatic expiration
- `EXISTS` for fast lookups
- Redis Sentinel or Cluster for high availability

### PostgreSQL

**Best For:**
- Client registry (OAuth clients)
- Audit logs
- User accounts (if implementing user authentication)

**Recommended Libraries:**
- **Go:** `github.com/lib/pq` or `pgx`
- **Java:** JDBC with Spring Data JPA
- **C#:** Npgsql with Entity Framework Core
- **Rust:** `sqlx` or `diesel`

**Schema Considerations:**
- Index `client_id` for fast lookups
- Use JSONB for storing arrays (redirect_uris, grant_types)
- Add created_at/updated_at timestamps

### SQLite

**Best For:**
- Development environments
- Single-server deployments
- Embedded applications

**When NOT to Use:**
- High concurrency scenarios
- Distributed systems
- Production at scale

### MongoDB

**Best For:**
- Document-oriented data models
- Flexible schemas
- Fast writes

**Considerations:**
- Not ideal for transactional OAuth operations
- Better suited for audit logs and analytics
- Use only if already in your tech stack

---

## Security Considerations by Language

### Memory Safety

**Go:**
- No buffer overflows, but watch for nil pointer dereferences
- Use `context.Context` for request cancellation and timeouts

**Java:**
- Garbage collected, memory safe
- Watch for memory leaks in caches and connection pools

**C#:**
- Garbage collected, memory safe
- Be careful with `unsafe` code blocks (rarely needed)

**Rust:**
- Memory safe by design (ownership system)
- Unsafe blocks should be minimized and audited

### Input Validation

All languages should:
- Validate all user inputs before processing
- Use parameterized queries to prevent SQL injection
- Sanitize data for logging to prevent log injection
- Validate redirect URIs against registered values

**Language-Specific:**
- **Go:** Use `regexp` package for validation
- **Java:** Use Bean Validation (JSR 380) annotations
- **C#:** Use Data Annotations or FluentValidation
- **Rust:** Use `validator` crate or custom validation

### Secret Management

**Best Practices (All Languages):**
- Never hardcode secrets in source code
- Use environment variables or secret management services
- Rotate secrets regularly
- Use different secrets for dev/staging/production

**Tools:**
- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault
- Kubernetes Secrets

### HTTPS/TLS

**All implementations MUST use HTTPS in production.**

**Certificate Management:**
- Use Let's Encrypt for free SSL certificates
- Automate certificate renewal
- Use reverse proxy (nginx, traefik) for TLS termination

**Configuration:**
- Disable weak cipher suites
- Use TLS 1.2 or higher
- Enable HSTS (HTTP Strict Transport Security)

---

## Conclusion

This guide provides language-specific hints for implementing MCP servers with OAuth 2.1 + PKCE authentication in Go, Java/Spring Boot, C#/.NET, and Rust, along with Docker containerization patterns for all languages. While the core OAuth and MCP protocol logic remains consistent across languages (as shown in the pseudocode template), each language has its own ecosystem of libraries, frameworks, and best practices.

**Key Takeaways:**

1. **All languages can successfully implement the specification** - Choose based on your team's expertise and infrastructure
2. **Docker enables consistent deployment** - Containerize for portability and simplified operations
3. **Storage patterns are similar** - Redis for ephemeral data, PostgreSQL/similar for persistent data
4. **Security requirements are universal** - HTTPS, PKCE, token rotation, and rate limiting apply to all
5. **Performance characteristics differ** - Rust and Go offer lowest latency, Java/.NET excel at enterprise scale
6. **Developer experience varies** - Use the language that makes your team most productive

**Next Steps:**

1. Review the pseudocode template for complete logic flow
2. Examine reference implementations (JavaScript, TypeScript, Python)
3. Set up your development environment with recommended libraries
4. Choose deployment strategy (Docker, VM, cloud platform)
5. Implement core OAuth 2.1 flow first
6. Add MCP protocol handlers
7. Test thoroughly before production deployment

**Questions or Need Help?**

These hints should get you started, but every implementation will have unique requirements. Refer to official documentation for your chosen frameworks and libraries, and don't hesitate to adapt these patterns to your specific use case.

---

## Document Status

- **Version:** 2.0
- **Last Updated:** February 6, 2026
- **Status:** Complete

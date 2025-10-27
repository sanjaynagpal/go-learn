# Microsoft Entra ID OAuth2 Server with Go

This project consists of two Go servers:
1. **Main Server** (port 2020) - Handles authentication with Microsoft Entra ID using OAuth2 + PKCE
2. **API Server** (port 8899) - Validates JWT tokens and provides protected endpoints

## Features

### Main Server (Port 2020)
- ✅ OAuth2 with PKCE (no client secret required)
- ✅ Microsoft Entra ID authentication
- ✅ Automatic token refresh
- ✅ Microsoft Graph API integration
- ✅ Graceful shutdown (Ctrl+C or authenticated `/stop` endpoint)
- ✅ Session management with in-memory storage (avoids cookie size limits)
- ✅ Gorilla mux router and sessions

### API Server (Port 8899)
- ✅ JWT token validation using Microsoft's JWKS
- ✅ Token expiration checking
- ✅ Graceful shutdown
- ✅ Health check endpoint

## Prerequisites

1. **Go 1.21+** installed
2. **Microsoft Entra ID (Azure AD) App Registration**

## Azure AD Setup

### 1. Register an Application

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** → **App registrations** → **New registration**
3. Configure:
   - **Name**: Your app name (e.g., "Go OAuth2 PKCE App")
   - **Supported account types**: Choose based on your needs
   - **Redirect URI**: Select "Public client/native" and enter `http://localhost:2020/callback`

4. Click **Register**

### 2. Configure the Application

After registration:

1. Note the **Application (client) ID** and **Directory (tenant) ID** from the Overview page
2. Go to **Authentication**:
   - Under "Advanced settings", set **Allow public client flows** to **Yes**
   - This enables PKCE without requiring a client secret
3. Go to **API permissions**:
   - Ensure `User.Read` is added (should be by default)
   - Click **Grant admin consent** if required

### 3. No Client Secret Needed

Since we're using PKCE for a public client (desktop/mobile app), **DO NOT** create a client secret. The PKCE flow provides security without requiring a secret.

## Installation

### Main Server

```bash
# Create directory for main server
mkdir main-server
cd main-server

# Initialize module
go mod init entra-auth-server

# Create main.go with the main server code
# (Copy the Main Server code from artifact)

# Install dependencies
go get github.com/gorilla/mux
go get github.com/gorilla/sessions
go get golang.org/x/oauth2

# Tidy dependencies
go mod tidy
```

### API Server

```bash
# Create directory for API server
mkdir api-server
cd api-server

# Initialize module
go mod init api-validation-server

# Create main.go with the API server code
# (Copy the API Server code from artifact)

# Install dependencies
go get github.com/golang-jwt/jwt/v5
go get github.com/lestrrat-go/jwx/v2

# Tidy dependencies
go mod tidy
```

## Configuration

Set the following environment variables before running the main server:

```bash
# Required
export AZURE_CLIENT_ID="your-application-client-id"
export AZURE_TENANT_ID="your-tenant-id"

# Optional: Change the session secret (32 bytes recommended)
# Edit the code to use an environment variable for production
```

## Running the Servers

### Start API Server (Terminal 1)

```bash
cd api-server
go run main.go
```

Output: `API Server starting on http://localhost:8899`

### Start Main Server (Terminal 2)

```bash
cd main-server
export AZURE_CLIENT_ID="your-client-id"
export AZURE_TENANT_ID="your-tenant-id"
go run main.go
```

Output: `Server starting on http://localhost:2020`

## Usage

### 1. Open Browser

Navigate to: `http://localhost:2020`

### 2. Login

Click "Login with Microsoft" to authenticate with your Microsoft account.

### 3. Available Endpoints

After authentication:

- **Home** (`/`) - Main page with navigation links
- **View Profile** (`/profile`) - Displays user information from Microsoft Graph API
- **Call External API** (`/callapi`) - Calls the validation API server with your token
- **Stop Server** (`/stop`) - Gracefully stops the server (requires authentication)
- **Logout** (`/logout`) - Ends your session

### 4. API Server Endpoints

- **Validate Token** (`/validate`) - Validates bearer tokens (requires Authorization header)
- **Health Check** (`/health`) - Returns server health status

### Testing API Server Directly

```bash
# Get your access token from the main server session
# Then call the API:

curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:8899/validate
```

## Graceful Shutdown

Both servers support graceful shutdown in two ways:

### 1. Ctrl+C (SIGINT)
Press `Ctrl+C` in the terminal running the server.

### 2. Authenticated Stop Endpoint (Main Server Only)
After logging in, click "Stop Server" or make a POST request:

```bash
curl -X POST http://localhost:2020/stop \
     -H "Cookie: auth-session=YOUR_SESSION_COOKIE"
```

## Security Features

### Main Server
- ✅ PKCE (Proof Key for Code Exchange) - Protects against authorization code interception
- ✅ State parameter validation - Prevents CSRF attacks
- ✅ HttpOnly cookies - Protects against XSS
- ✅ Secure session management with in-memory storage (avoids cookie size limits)
- ✅ Automatic token refresh using refresh tokens
- ✅ Token expiration checking

### API Server
- ✅ JWT signature verification using Microsoft's JWKS (JSON Web Key Set)
- ✅ Token expiration validation
- ✅ Automatic JWKS refresh (every hour)
- ✅ RSA signature verification

## Token Refresh Flow

The main server automatically refreshes expired tokens:

1. Middleware checks if the access token is expired
2. If expired, uses the refresh token to obtain a new access token
3. Updates the session with new tokens
4. Continues processing the request

This happens transparently without user intervention.

## Session Management

To avoid cookie size limitations:

- Session IDs are stored in cookies (small)
- Actual session data (tokens, state) is stored server-side in memory
- Thread-safe access using `sync.RWMutex`

**Note**: In production, consider using a persistent session store like Redis.

## Architecture

```
┌─────────────┐         ┌──────────────────┐
│   Browser   │────────▶│  Main Server     │
│             │         │  (Port 2020)     │
└─────────────┘         │                  │
                        │  - OAuth2/PKCE   │
                        │  - Token Refresh │
                        │  - Sessions      │
                        └──────────────────┘
                                │
                                │ Bearer Token
                                ▼
                        ┌──────────────────┐
                        │  API Server      │
                        │  (Port 8899)     │
                        │                  │
                        │  - JWT Validate  │
                        │  - JWKS Fetch    │
                        └──────────────────┘
                                │
                                │ Verify
                                ▼
                        ┌──────────────────┐
                        │ Microsoft JWKS   │
                        │ (login.microsoft │
                        │  online.com)     │
                        └──────────────────┘
```

## Troubleshooting

### "Invalid state parameter" Error
- Clear your browser cookies and try again
- Ensure you're not reusing old authorization codes

### "Failed to exchange token" Error
- Check that your `AZURE_CLIENT_ID` is correct
- Verify "Allow public client flows" is enabled in Azure AD
- Ensure redirect URI matches exactly: `http://localhost:2020/callback`

### "Token validation failed" Error
- Token may be expired (tokens are typically valid for 1 hour)
- Ensure the API server can reach `login.microsoftonline.com`
- Check API server logs for specific validation errors

### "Failed to fetch JWKS" Warning
- Check internet connectivity
- Verify firewall allows outbound HTTPS connections
- The server will retry fetching JWKS on next validation attempt

### Session Data Lost
- Sessions are stored in memory and will be lost on server restart
- For production, implement persistent session storage

## Production Considerations

### 1. HTTPS
Enable HTTPS for production:

```go
store.Options.Secure = true // In main server
```

### 2. Session Secret
Use a cryptographically secure random key:

```go
sessionSecret := os.Getenv("SESSION_SECRET")
store = sessions.NewCookieStore([]byte(sessionSecret))
```

Generate a secure key:
```bash
openssl rand -base64 32
```

### 3. Persistent Session Storage
Replace in-memory storage with Redis, database, or other persistent store:

```go
import "github.com/gorilla/sessions"
import "github.com/rbcervilla/redisstore/v9"

// Use Redis for session storage
store, err := redisstore.NewRedisStore(context.Background(), redisClient)
```

### 4. CORS Configuration
If calling from different origins, add CORS middleware:

```go
import "github.com/gorilla/handlers"

router := mux.NewRouter()
corsRouter := handlers.CORS(
    handlers.AllowedOrigins([]string{"https://yourdomain.com"}),
    handlers.AllowedMethods([]string{"GET", "POST"}),
    handlers.AllowCredentials(),
)(router)
```

### 5. Rate Limiting
Implement rate limiting to prevent abuse:

```go
import "golang.org/x/time/rate"

limiter := rate.NewLimiter(rate.Limit(10), 100) // 10 req/sec, burst of 100
```

### 6. Logging
Use structured logging:

```go
import "log/slog"

logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
logger.Info("Server started", "port", 2020)
```

### 7. Token Validation Caching
Cache validated tokens temporarily to reduce JWKS lookups:

```go
// Add to API server
var tokenCache = make(map[string]time.Time)
var cacheMu sync.RWMutex
```

## Testing

### Unit Tests Example

```go
// main_test.go
package main

import (
    "testing"
)

func TestGenerateRandomString(t *testing.T) {
    s := generateRandomString(32)
    if len(s) != 32 {
        t.Errorf("Expected length 32, got %d", len(s))
    }
}

func TestGenerateCodeChallenge(t *testing.T) {
    verifier := "test_verifier"
    challenge := generateCodeChallenge(verifier)
    if challenge == "" {
        t.Error("Challenge should not be empty")
    }
}
```

### Integration Tests

```bash
# Test health endpoint
curl http://localhost:8899/health

# Expected response:
# {"status":"healthy","time":"2025-10-24T..."}
```

## Environment Variables Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `AZURE_CLIENT_ID` | Yes | Application (client) ID from Azure AD | `12345678-1234-1234-1234-123456789abc` |
| `AZURE_TENANT_ID` | Yes | Directory (tenant) ID from Azure AD | `87654321-4321-4321-4321-cba987654321` |
| `SESSION_SECRET` | Recommended | Secret key for session encryption (32 bytes) | `your-32-byte-secret-key-here!!!!` |

## API Reference

### Main Server Endpoints

#### `GET /`
Home page with authentication status

**Response**: HTML page

#### `GET /login`
Initiates OAuth2 login flow with Microsoft

**Response**: Redirect to Microsoft login

#### `GET /callback`
OAuth2 callback endpoint

**Query Parameters**:
- `code`: Authorization code
- `state`: State parameter for CSRF protection

**Response**: Redirect to home page

#### `GET /profile`
Get authenticated user profile from Microsoft Graph

**Authentication**: Required

**Response**:
```json
{
  "displayName": "John Doe",
  "mail": "john@example.com",
  "userPrincipalName": "john@example.com",
  "id": "user-id"
}
```

#### `GET /callapi`
Call the API validation server

**Authentication**: Required

**Response**: Proxied response from API server

#### `POST /stop`
Gracefully stop the server

**Authentication**: Required

**Response**: HTML confirmation page

#### `GET /logout`
End user session

**Response**: Redirect to home page

### API Server Endpoints

#### `GET /validate`
Validate JWT bearer token

**Headers**:
- `Authorization: Bearer <token>`

**Success Response** (200):
```json
{
  "message": "Token is valid. Access granted.",
  "timestamp": "2025-10-24T12:00:00Z",
  "user": "john@example.com"
}
```

**Error Response** (401):
```json
{
  "error": "Invalid token: token expired"
}
```

#### `GET /health`
Health check endpoint

**Response** (200):
```json
{
  "status": "healthy",
  "time": "2025-10-24T12:00:00Z"
}
```

## License

This is example code for educational purposes. Adapt and secure appropriately for production use.

## Additional Resources

- [Microsoft identity platform documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
- [OAuth 2.0 PKCE specification](https://oauth.net/2/pkce/)
- [Microsoft Graph API](https://docs.microsoft.com/en-us/graph/overview)
- [Go OAuth2 package](https://pkg.go.dev/golang.org/x/oauth2)
- [Gorilla web toolkit](https://www.gorillatoolkit.org/)


## Auth CLient

```go
package main

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "time"

    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/microsoft"
)

const (
    sessionName     = "auth-session"
    sessionIDKey    = "session_id"
    stateKey        = "oauth_state"
    verifierKey     = "code_verifier"
    tokenKey        = "access_token"
    refreshTokenKey = "refresh_token"
    expiryKey       = "token_expiry"
)

var (
    // Session store with a secure key
    store = sessions.NewCookieStore([]byte("change-this-to-a-32-byte-secret-key!!"))

    // In-memory session data store (avoids cookie size limits)
    sessionData = make(map[string]map[string]interface{})
    sessionMu   sync.RWMutex

    oauth2Config *oauth2.Config
)

type UserInfo struct {
    DisplayName       string `json:"displayName"`
    Mail              string `json:"mail"`
    UserPrincipalName string `json:"userPrincipalName"`
    ID                string `json:"id"`
}

func init() {
    // Configure session store
    store.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   3600 * 8, // 8 hours
        HttpOnly: true,
        Secure:   false, // Set to true in production with HTTPS
        SameSite: http.SameSiteLaxMode,
    }

    // Initialize OAuth2 config
    oauth2Config = &oauth2.Config{
        ClientID: os.Getenv("AZURE_CLIENT_ID"), // Set via environment variable
        Endpoint: microsoft.AzureADEndpoint(os.Getenv("AZURE_TENANT_ID")),
        RedirectURL: "http://localhost:2020/callback",
        Scopes: []string{
            "openid",
            "profile",
            "User.Read",
            "offline_access", // Required for refresh tokens
        },
    }
}

func main() {
    if oauth2Config.ClientID == "" {
        log.Fatal("AZURE_CLIENT_ID environment variable not set")
    }
    if os.Getenv("AZURE_TENANT_ID") == "" {
        log.Fatal("AZURE_TENANT_ID environment variable not set")
    }

    router := mux.NewRouter()

    // Routes
    router.HandleFunc("/", homeHandler).Methods("GET")
    router.HandleFunc("/login", loginHandler).Methods("GET")
    router.HandleFunc("/callback", callbackHandler).Methods("GET")
    router.HandleFunc("/profile", authenticatedMiddleware(profileHandler)).Methods("GET")
    router.HandleFunc("/callapi", authenticatedMiddleware(callAPIHandler)).Methods("GET")
    router.HandleFunc("/stop", authenticatedMiddleware(stopHandler)).Methods("POST")
    router.HandleFunc("/logout", logoutHandler).Methods("GET")

    server := &http.Server{
        Addr:         ":2020",
        Handler:      router,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    // Channel to signal shutdown
    done := make(chan bool, 1)

    // Start server in a goroutine
    go func() {
        log.Printf("Server starting on http://localhost:2020")
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Server failed to start: %v", err)
        }
    }()

    // Handle Ctrl+C (SIGINT) and SIGTERM
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

    // Wait for shutdown signal
    select {
    case sig := <-sigChan:
        log.Printf("Received signal: %v", sig)
    case <-done:
        log.Println("Shutdown initiated by authenticated user")
    }

    // Graceful shutdown
    log.Println("Shutting down server gracefully...")
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := server.Shutdown(ctx); err != nil {
        log.Fatalf("Server forced to shutdown: %v", err)
    }

    log.Println("Server stopped")
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, sessionName)
    sessionID := getSessionID(session)

    sessionMu.RLock()
    data, exists := sessionData[sessionID]
    sessionMu.RUnlock()

    authenticated := exists && data[tokenKey] != nil

    html := `<html><body><h1>Microsoft Entra ID OAuth2 Server</h1>`
    if authenticated {
        html += `<p>You are logged in!</p>
        <a href="/profile">View Profile</a> | 
        <a href="/callapi">Call External API</a> | 
        <form action="/stop" method="post" style="display:inline">
            <button type="submit">Stop Server</button>
        </form> | 
        <a href="/logout">Logout</a>`
    } else {
        html += `<p><a href="/login">Login with Microsoft</a></p>`
    }
    html += `</body></html>`

    w.Header().Set("Content-Type", "text/html")
    fmt.Fprint(w, html)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, sessionName)
    sessionID := getOrCreateSessionID(session)

    // Generate state and PKCE verifier
    state := generateRandomString(32)
    verifier := generateRandomString(64)

    // Store in session data
    sessionMu.Lock()
    if sessionData[sessionID] == nil {
        sessionData[sessionID] = make(map[string]interface{})
    }
    sessionData[sessionID][stateKey] = state
    sessionData[sessionID][verifierKey] = verifier
    sessionMu.Unlock()

    session.Save(r, w)

    // Generate PKCE challenge
    challenge := generateCodeChallenge(verifier)

    // Build authorization URL
    url := oauth2Config.AuthCodeURL(state,
        oauth2.SetAuthURLParam("code_challenge", challenge),
        oauth2.SetAuthURLParam("code_challenge_method", "S256"),
        oauth2.SetAuthURLParam("prompt", "select_account"),
    )

    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, sessionName)
    sessionID := getSessionID(session)

    sessionMu.RLock()
    data := sessionData[sessionID]
    sessionMu.RUnlock()

    if data == nil {
        http.Error(w, "Invalid session", http.StatusBadRequest)
        return
    }

    // Verify state
    state := r.URL.Query().Get("state")
    if state != data[stateKey].(string) {
        http.Error(w, "Invalid state parameter", http.StatusBadRequest)
        return
    }

    // Exchange code for token
    code := r.URL.Query().Get("code")
    verifier := data[verifierKey].(string)

    token, err := oauth2Config.Exchange(
        context.Background(),
        code,
        oauth2.SetAuthURLParam("code_verifier", verifier),
    )
    if err != nil {
        http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
        return
    }

    // Store token in session data
    sessionMu.Lock()
    sessionData[sessionID][tokenKey] = token.AccessToken
    sessionData[sessionID][refreshTokenKey] = token.RefreshToken
    sessionData[sessionID][expiryKey] = token.Expiry
    sessionMu.Unlock()

    session.Save(r, w)

    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
    token := r.Context().Value("access_token").(string)

    // Call Microsoft Graph API
    req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
    req.Header.Set("Authorization", "Bearer "+token)

    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        http.Error(w, "Failed to fetch user info", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        http.Error(w, "Failed to get user info from Microsoft Graph", resp.StatusCode)
        return
    }

    var userInfo UserInfo
    json.NewDecoder(resp.Body).Decode(&userInfo)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(userInfo)
}

func callAPIHandler(w http.ResponseWriter, r *http.Request) {
    token := r.Context().Value("access_token").(string)

    // Call the secondary API server
    req, _ := http.NewRequest("GET", "http://localhost:8899/validate", nil)
    req.Header.Set("Authorization", "Bearer "+token)

    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        http.Error(w, fmt.Sprintf("Failed to call API: %v", err), http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(resp.StatusCode)
    w.Write(body)
}

func stopHandler(w http.ResponseWriter, r *http.Request) {
    log.Println("Server stop requested by authenticated user")
    
    w.Header().Set("Content-Type", "text/html")
    fmt.Fprint(w, "<html><body><h1>Server is shutting down...</h1></body></html>")

    // Trigger shutdown in a goroutine
    go func() {
        time.Sleep(1 * time.Second)
        sigChan := make(chan os.Signal, 1)
        signal.Notify(sigChan, os.Interrupt)
        sigChan <- os.Interrupt
    }()
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, sessionName)
    sessionID := getSessionID(session)

    // Clear session data
    sessionMu.Lock()
    delete(sessionData, sessionID)
    sessionMu.Unlock()

    // Clear cookie
    session.Options.MaxAge = -1
    session.Save(r, w)

    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func authenticatedMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, sessionName)
        sessionID := getSessionID(session)

        sessionMu.Lock()
        data := sessionData[sessionID]
        
        if data == nil || data[tokenKey] == nil {
            sessionMu.Unlock()
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        accessToken := data[tokenKey].(string)
        expiry := data[expiryKey].(time.Time)

        // Check if token is expired
        if time.Now().After(expiry) {
            // Try to refresh token
            refreshToken := data[refreshTokenKey].(string)
            sessionMu.Unlock()

            newToken, err := refreshAccessToken(refreshToken)
            if err != nil {
                log.Printf("Failed to refresh token: %v", err)
                http.Redirect(w, r, "/login", http.StatusSeeOther)
                return
            }

            // Update tokens
            sessionMu.Lock()
            sessionData[sessionID][tokenKey] = newToken.AccessToken
            sessionData[sessionID][refreshTokenKey] = newToken.RefreshToken
            sessionData[sessionID][expiryKey] = newToken.Expiry
            accessToken = newToken.AccessToken
            sessionMu.Unlock()
        } else {
            sessionMu.Unlock()
        }

        // Add token to context
        ctx := context.WithValue(r.Context(), "access_token", accessToken)
        next.ServeHTTP(w, r.WithContext(ctx))
    }
}

func refreshAccessToken(refreshToken string) (*oauth2.Token, error) {
    token := &oauth2.Token{RefreshToken: refreshToken}
    tokenSource := oauth2Config.TokenSource(context.Background(), token)
    return tokenSource.Token()
}

func getSessionID(session *sessions.Session) string {
    if id, ok := session.Values[sessionIDKey].(string); ok {
        return id
    }
    return ""
}

func getOrCreateSessionID(session *sessions.Session) string {
    if id := getSessionID(session); id != "" {
        return id
    }
    id := generateRandomString(32)
    session.Values[sessionIDKey] = id
    return id
}

func generateRandomString(length int) string {
    b := make([]byte, length)
    rand.Read(b)
    return base64.RawURLEncoding.EncodeToString(b)[:length]
}

func generateCodeChallenge(verifier string) string {
    hash := sha256.Sum256([]byte(verifier))
    return base64.RawURLEncoding.EncodeToString(hash[:])
}
```

## API Server

```go
package apiserver

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    "github.com/gorilla/mux"
)

type JWKSResponse struct {
    Keys []JWK `json:"keys"`
}

type JWK struct {
    Kid string   `json:"kid"`
    Kty string   `json:"kty"`
    Use string   `json:"use"`
    N   string   `json:"n"`
    E   string   `json:"e"`
    X5c []string `json:"x5c"`
}

type TokenClaims struct {
    Aud string `json:"aud"`
    Iss string `json:"iss"`
    Iat int64  `json:"iat"`
    Exp int64  `json:"exp"`
    Sub string `json:"sub"`
}

func validateToken(token string) (bool, error) {
    if token == "" {
        return false, fmt.Errorf("empty token")
    }

    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        return false, fmt.Errorf("invalid token format")
    }

    tenantID := os.Getenv("AZURE_TENANT_ID")
    if tenantID == "" {
        tenantID = "common"
    }

    introspectionURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/me")
    req, err := http.NewRequest("GET", introspectionURL, nil)
    if err != nil {
        return false, err
    }
    req.Header.Set("Authorization", "Bearer "+token)

    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return false, err
    }
    defer resp.Body.Close()

    return resp.StatusCode == http.StatusOK, nil
}

func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
            return
        }

        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            http.Error(w, `{"error":"invalid authorization header format"}`, http.StatusUnauthorized)
            return
        }

        token := parts[1]
        valid, err := validateToken(token)
        if err != nil || !valid {
            log.Printf("Token validation failed: %v", err)
            http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    })
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
    response := map[string]interface{}{
        "message":   "Successfully accessed protected resource",
        "timestamp": time.Now().Format(time.RFC3339),
        "data": map[string]string{
            "server": "API Server 8899",
            "status": "authenticated",
        },
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    response := map[string]string{
        "status": "healthy",
        "time":   time.Now().Format(time.RFC3339),
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func StartAPIServer() {
    r := mux.NewRouter()

    r.HandleFunc("/health", healthHandler).Methods("GET")
    r.Handle("/protected", authMiddleware(http.HandlerFunc(protectedHandler))).Methods("GET")

    srv := &http.Server{
        Addr:         "localhost:8899",
        Handler:      r,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    shutdown := make(chan os.Signal, 1)
    signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

    go func() {
        log.Println("API Server starting on http://localhost:8899")
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("API Server failed: %v", err)
        }
    }()

    <-shutdown
    log.Println("API Server shutdown signal received, gracefully shutting down...")

    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        log.Printf("API Server forced to shutdown: %v", err)
    }

    log.Println("API Server exited")
}

func main() {
    StartAPIServer()
}
```
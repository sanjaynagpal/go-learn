# Microsoft Entra ID OAuth2 Server with Go

This project consists of two Go servers:
1. **API Client** (port 2020) - Handles authentication with Microsoft Entra ID using OAuth2 + PKCE
2. **API Server** (port 8899) - Validates JWT tokens and provides protected endpoints

## Features

### API Client (Port 2020)
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

1. **Go 1.24.5+** installed
2. **Microsoft Entra ID (Azure AD) App Registration**

## Azure AD Setup

### 1. Register an Application

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** → **App registrations** → **New registration**
3. Configure:
   - **Name**: Your app name (e.g., "Go OAuth2 PKCE App")
   - **Supported account types**: Choose based on your needs
   - **Redirect URI**: Select "Public client/native" and enter `http://localhost:2020/auth/callback` and `http://localhost:2021/auth/callback`

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
mkdir app-client
cd app-client

# Initialize module
go mod init app-auth-client

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
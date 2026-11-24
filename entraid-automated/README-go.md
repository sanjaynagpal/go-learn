# Entra ID–protected API tests in pure Go (client credentials)

A Go-only guide: the **test side** gets an app-only token with `azidentity`, and the **API side**
validates it with `golang-jwt/jwt/v5`. No `az`, `curl`, `jq`, Python or C# in the test path.

Companion to [README.md](README.md), which covers the same flow in more languages.
Portal setup (Parts 1–2 there) is language-neutral and is only summarized here.

## Contents

1. [How it works](#1-how-it-works)
2. [One-time Entra setup (summary)](#2-one-time-entra-setup-summary)
3. [Test side: the `testauth` package](#3-test-side-the-testauth-package)
4. [Writing the regression tests](#4-writing-the-regression-tests)
5. [CI pipelines](#5-ci-pipelines)
6. [API side: validate and authorize tokens](#6-api-side-validate-and-authorize-tokens)
7. [Testing the middleware offline](#7-testing-the-middleware-offline)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. How it works

```
 Test (Go) ──client_id + credential──▶ Entra token endpoint
           ◀────── access token (roles claim) ──────
 Test (Go) ──Authorization: Bearer <token>──▶ API (Go)
                                              validates signature, iss, aud, exp
                                              authorizes on `roles`
```

The test runner is an **application**, not a user, so it uses the OAuth 2.0 client credentials flow.
The scope is always `api://<api-client-id>/.default`, and there is no refresh token. The credential
object requests a new token when needed.

Suggested layout:

```
go.mod
internal/testauth/auth.go          # picks a credential, returns an authed *http.Client
api/auth/middleware.go             # JWT validation + authorization
api/auth/middleware_test.go        # offline tests with a local signing key
regression/main_test.go            # //go:build integration, builds the client once
regression/orders_test.go
```

Dependencies:

```bash
go get github.com/Azure/azure-sdk-for-go/sdk/azidentity
go get github.com/Azure/azure-sdk-for-go/sdk/azcore
go get github.com/golang-jwt/jwt/v5
go get github.com/MicahParks/keyfunc/v3
```

---

## 2. One-time Entra setup (summary)

Full portal steps are in [README.md](README.md) Parts 1–2. In short:

| Step | What |
|---|---|
| API registration | Set the Application ID URI (`api://<api-client-id>`). Add an app role with **Allowed member types = Applications**, value `Api.Test.ReadWrite`. |
| Token version | Check `requestedAccessTokenVersion`: `2` gives `aud=<client-id>` and a `login.microsoftonline.com/<tenant>/v2.0` issuer. `null` or `1` gives `aud=api://<client-id>` and a `sts.windows.net/<tenant>/` issuer. The API config in section 6 must match. |
| Test app | A **separate** registration (`myapi-regression-tests`) with no redirect URI. Grant it the app role under **API permissions → Application permissions**, then grant admin consent. |
| Credential | Prefer a **federated credential** (no secret). Use a certificate or client secret only if federation isn't possible. |
| Hardening | On the API's Enterprise application, set **Assignment required = Yes**. |

Federated credential values:

| CI | Issuer | Subject (exact match, no wildcards) | Audience |
|---|---|---|---|
| GitLab | `https://gitlab.com` (or your self-managed URL, no trailing slash) | `project_path:mygroup/myproject:ref_type:branch:ref:main` | `api://AzureADTokenExchange` |
| GitHub | `https://token.actions.githubusercontent.com` | `repo:myorg/myrepo:environment:regression` | `api://AzureADTokenExchange` |
| Azure DevOps | Created for you by a service connection with **Workload identity federation** | | |

---

## 3. Test side: the `testauth` package

One package decides which credential to use from the environment, so test code never knows how
the token was obtained.

### 3.1 Environment variables

| Variable | Purpose | Secret? |
|---|---|---|
| `TENANT_ID` | Directory (tenant) ID | no |
| `TEST_CLIENT_ID` | Test app's client ID | no |
| `API_CLIENT_ID` | API's client ID (used to build the scope) | no |
| `API_BASE_URL` | e.g. `https://myapi.example.com` | no |
| `AZURE_JWT` | GitLab `id_tokens` value (federated) | short-lived |
| `ACTIONS_ID_TOKEN_REQUEST_URL`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | Set by GitHub Actions when `id-token: write` | short-lived |
| `TEST_CLIENT_CERT_FILE` (+ optional `TEST_CLIENT_CERT_PASSWORD`) | PEM or PFX with private key | **yes** |
| `TEST_CLIENT_SECRET` | Client secret value | **yes** |

### 3.2 `internal/testauth/auth.go`

```go
// Package testauth builds an *http.Client that sends an Entra app-only
// access token as a Bearer token.
package testauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// ErrNotConfigured means no credential is configured. Callers should skip
// integration tests rather than fail.
var ErrNotConfigured = errors.New("testauth: no credential configured")

// Scope returns the .default scope for the API.
func Scope() string { return "api://" + os.Getenv("API_CLIENT_ID") + "/.default" }

// Credential picks a credential from the environment, most specific first.
// It is deliberately explicit rather than DefaultAzureCredential, so a test
// never silently falls back to a developer's own login.
func Credential() (azcore.TokenCredential, error) {
	tenant := os.Getenv("TENANT_ID")
	clientID := os.Getenv("TEST_CLIENT_ID")
	if tenant == "" || clientID == "" || os.Getenv("API_CLIENT_ID") == "" {
		return nil, fmt.Errorf("%w: TENANT_ID, TEST_CLIENT_ID and API_CLIENT_ID are required", ErrNotConfigured)
	}

	switch {
	case os.Getenv("AZURE_JWT") != "": // GitLab CI
		return azidentity.NewClientAssertionCredential(tenant, clientID,
			func(context.Context) (string, error) { return os.Getenv("AZURE_JWT"), nil }, nil)

	case os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "": // GitHub Actions
		return azidentity.NewClientAssertionCredential(tenant, clientID, githubOIDCToken, nil)

	case os.Getenv("TEST_CLIENT_CERT_FILE") != "": // certificate
		data, err := os.ReadFile(os.Getenv("TEST_CLIENT_CERT_FILE"))
		if err != nil {
			return nil, err
		}
		var pw []byte
		if p := os.Getenv("TEST_CLIENT_CERT_PASSWORD"); p != "" {
			pw = []byte(p)
		}
		certs, key, err := azidentity.ParseCertificates(data, pw)
		if err != nil {
			return nil, err
		}
		return azidentity.NewClientCertificateCredential(tenant, clientID, certs, key, nil)

	case os.Getenv("TEST_CLIENT_SECRET") != "": // client secret (local dev)
		return azidentity.NewClientSecretCredential(tenant, clientID, os.Getenv("TEST_CLIENT_SECRET"), nil)
	}
	return nil, ErrNotConfigured
}

// githubOIDCToken asks the GitHub Actions runner for an OIDC token whose
// audience is what the Entra federated credential expects.
func githubOIDCToken(ctx context.Context) (string, error) {
	u, err := url.Parse(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("audience", "api://AzureADTokenExchange")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github oidc: %s", resp.Status)
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	return body.Value, nil
}

// bearerTransport adds a fresh-enough token to every request. The credential
// caches tokens in memory and renews them before they expire, so this is cheap.
type bearerTransport struct {
	cred azcore.TokenCredential
	base http.RoundTripper
}

func (t *bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tok, err := t.cred.GetToken(r.Context(), policy.TokenRequestOptions{Scopes: []string{Scope()}})
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}
	r2 := r.Clone(r.Context()) // RoundTrippers must not modify the original request
	r2.Header.Set("Authorization", "Bearer "+tok.Token)
	return t.base.RoundTrip(r2)
}

// NewClient returns an authenticated client. Create it once and reuse it.
func NewClient(cred azcore.TokenCredential) *http.Client {
	return &http.Client{
		Timeout:   30 * 1e9, // 30s
		Transport: &bearerTransport{cred: cred, base: http.DefaultTransport},
	}
}
```

Notes:

- **Reuse the credential.** It owns the token cache. Creating one per test means one token request per test.
- **Don't use `DefaultAzureCredential` in tests.** Its fallback order depends on the machine, and it
  doesn't read GitLab's `AZURE_JWT`.
- The GitLab callback re-reads `AZURE_JWT` on each renewal, but that value is fixed for the job.
  GitLab ID tokens are short-lived (I believe about 5 minutes; check your GitLab version), so
  obtain the first token early in `TestMain` and rely on the cached access token, which lasts 60–90 minutes.
- **Never log** the token, the assertion, or `Authorization` headers.

---

## 4. Writing the regression tests

Gate them behind a build tag so a plain `go test ./...` never calls the network.

`regression/main_test.go`:

```go
//go:build integration

package regression

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"example.com/myapi/internal/testauth"
)

var client *http.Client // nil when not configured

func TestMain(m *testing.M) {
	cred, err := testauth.Credential()
	switch {
	case errors.Is(err, testauth.ErrNotConfigured):
		fmt.Fprintln(os.Stderr, "regression: no credentials configured, tests will be skipped")
	case err != nil:
		fmt.Fprintln(os.Stderr, "regression:", err)
		os.Exit(1)
	default:
		// Fail fast with a clear message instead of N confusing test failures.
		if _, err := cred.GetToken(context.Background(),
			policy.TokenRequestOptions{Scopes: []string{testauth.Scope()}}); err != nil {
			fmt.Fprintln(os.Stderr, "regression: token request failed:", err)
			os.Exit(1)
		}
		client = testauth.NewClient(cred)
	}
	os.Exit(m.Run())
}

func requireClient(t *testing.T) *http.Client {
	t.Helper()
	if client == nil {
		t.Skip("no Entra credentials configured")
	}
	return client
}
```

`regression/orders_test.go`:

```go
//go:build integration

package regression

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestListOrders(t *testing.T) {
	c := requireClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, os.Getenv("API_BASE_URL")+"/orders", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /orders: got %s, want 200", resp.Status)
	}
}

func TestNoTokenIsRejected(t *testing.T) {
	requireClient(t)
	resp, err := http.Get(os.Getenv("API_BASE_URL") + "/orders") // plain client, no token
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %s, want 401", resp.Status)
	}
}
```

Run:

```bash
go test -tags integration -count=1 ./regression/...
```

**`-count=1` matters.** Go caches passing test results whose inputs (files, env vars) haven't changed.
With a secret or certificate, nothing changes between runs, so a live-API test can show `(cached)`
and not call the API at all.

---

## 5. CI pipelines

The pipelines only provide the environment. Go does the token exchange.

### 5.1 GitLab CI (federated, no secret)

CI/CD variables (not secret): `TENANT_ID`, `TEST_CLIENT_ID`, `API_CLIENT_ID`, `API_BASE_URL`.

```yaml
regression-tests:
  stage: test
  image: golang:1.23            # match the go directive in go.mod
  id_tokens:
    AZURE_JWT:
      aud: api://AzureADTokenExchange   # must equal the federated credential's audience
  rules:
    - if: $CI_COMMIT_BRANCH == "main"   # must match the federated credential's subject
  script:
    - go test -tags integration -count=1 ./regression/...
```

Don't echo `AZURE_JWT`. GitLab can't mask values created at runtime. Add one federated credential per
branch that runs the tests (Entra matches the subject exactly, up to 20 per app).

### 5.2 GitHub Actions (federated, no secret)

```yaml
permissions:
  id-token: write      # makes ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN available
  contents: read

jobs:
  regression:
    runs-on: ubuntu-latest
    environment: regression       # must match the federated credential's subject
    env:
      TENANT_ID: ${{ vars.TENANT_ID }}
      TEST_CLIENT_ID: ${{ vars.TEST_CLIENT_ID }}
      API_CLIENT_ID: ${{ vars.API_CLIENT_ID }}
      API_BASE_URL: ${{ vars.API_BASE_URL }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version-file: go.mod }
      - run: go test -tags integration -count=1 ./regression/...
```

No `azure/login` step is needed; `testauth` fetches the OIDC token itself.

### 5.3 Azure DevOps

Use a service connection with **Workload identity federation**, then in `testauth` add a case using
`azidentity.NewAzurePipelinesCredential(tenant, clientID, serviceConnectionID, os.Getenv("SYSTEM_ACCESSTOKEN"), nil)`.
Pass `SYSTEM_ACCESSTOKEN: $(System.AccessToken)` in the step's `env:`.

### 5.4 Local development

Use a client secret or certificate for a **dev** test app (never the production one). Set
`TEST_CLIENT_SECRET` in your shell (not in a committed file) and run the same `go test` command.

---

## 6. API side: validate and authorize tokens

Two separate steps: **validate** the token (it's genuine, for this API, not expired), then **authorize**
(this caller may do this).

### 6.1 `api/auth/middleware.go`

```go
package auth

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	TenantID string
	// Must match the API's requestedAccessTokenVersion (see README.md 1.3):
	//   v2: Issuer "https://login.microsoftonline.com/<tenant>/v2.0", Audience "<api-client-id>"
	//   v1: Issuer "https://sts.windows.net/<tenant>/",               Audience "api://<api-client-id>"
	Issuer   string
	Audience string

	DelegatedScope string   // e.g. "access_as_user" (desktop app)
	AppRole        string   // e.g. "Api.Test.ReadWrite" (test runner)
	AllowedApps    []string // optional allow-list of azp/appid for app-only callers
}

type Claims struct {
	jwt.RegisteredClaims
	Tid   string   `json:"tid"`
	Oid   string   `json:"oid"`
	Scp   string   `json:"scp"`   // delegated tokens
	Roles []string `json:"roles"` // app-only tokens (and users with an app role)
	Azp   string   `json:"azp"`   // v2 tokens: calling app
	Appid string   `json:"appid"` // v1 tokens: calling app
}

func (c *Claims) callerApp() string {
	if c.Azp != "" {
		return c.Azp
	}
	return c.Appid
}

type Validator struct {
	cfg Config
	kf  keyfunc.Keyfunc
}

// NewValidator fetches and refreshes the tenant's signing keys in the background.
func NewValidator(ctx context.Context, cfg Config) (*Validator, error) {
	jwks := "https://login.microsoftonline.com/" + cfg.TenantID + "/discovery/v2.0/keys"
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{jwks})
	if err != nil {
		return nil, err
	}
	return &Validator{cfg: cfg, kf: kf}, nil
}

func (v *Validator) parse(raw string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(raw, claims, v.kf.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	if claims.Tid != v.cfg.TenantID { // defence in depth
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}

// authorize decides whether the validated caller may proceed.
func (v *Validator) authorize(c *Claims) bool {
	// Delegated token: a signed-in user via the desktop app.
	if v.cfg.DelegatedScope != "" && slices.Contains(strings.Fields(c.Scp), v.cfg.DelegatedScope) {
		return true
	}
	// App-only token: no scp, and the required app role. Don't rely on `idtyp`,
	// it is an optional claim.
	if c.Scp == "" && slices.Contains(c.Roles, v.cfg.AppRole) {
		if len(v.cfg.AllowedApps) == 0 {
			return true
		}
		return slices.Contains(v.cfg.AllowedApps, c.callerApp())
	}
	return false
}

type ctxKey struct{}

// ClaimsFrom returns the validated claims placed on the request context.
func ClaimsFrom(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}

// Require is the middleware: 401 for a bad/missing token, 403 for a valid
// token that isn't allowed.
func (v *Validator) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := v.parse(raw)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized) // don't leak the reason
			return
		}
		if !v.authorize(claims) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, claims)))
	})
}
```

Usage:

```go
v, err := auth.NewValidator(ctx, auth.Config{
	TenantID:       tenant,
	Issuer:         "https://login.microsoftonline.com/" + tenant + "/v2.0",
	Audience:       apiClientID,
	DelegatedScope: "access_as_user",
	AppRole:        "Api.Test.ReadWrite",
})
mux.Handle("GET /orders", v.Require(http.HandlerFunc(listOrders)))
```

### 6.2 Rules this enforces

- Signature checked with the tenant's JWKS, and **only RS256 allowed**.
- `iss`, `aud`, `exp` checked. `exp` is required.
- `tid` must be your tenant.
- App-only callers need the **`roles`** claim. Any app in the tenant can obtain a token for your API,
  and without a role it just has no `roles`, so a valid signature alone is not enough.
- Optional `azp`/`appid` allow-list for extra restriction.

### 6.3 Code that depends on a user

An app-only token has no `upn` or `name`, and `oid` is the service principal's. Either treat that `oid`
as the caller and seed test data for it, or accept a test-only header such as `X-Test-User` **only**
when the token has the test role **and** the environment is not production.

---

## 7. Testing the middleware offline

You can test the validator without Entra by signing tokens with a local RSA key and serving a fake JWKS
with `httptest`. Point a test `Validator` at that JWKS URL and assert:

| Token | Expected |
|---|---|
| Valid, role `Api.Test.ReadWrite`, no `scp` | 200 |
| Valid, `scp=access_as_user` | 200 |
| Valid signature, no `roles` | 403 |
| Wrong `aud` | 401 |
| Wrong `iss` or wrong `tid` | 401 |
| Expired | 401 |
| `alg: none` or HS256 | 401 |
| No `Authorization` header | 401 |

To do this, make the JWKS URL a field on `Config` (default to the Entra URL) so tests can override it.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `AADSTS700016` | Wrong `TEST_CLIENT_ID` or `TENANT_ID` |
| `AADSTS7000215` / `AADSTS7000222` | Wrong secret (use its *Value*, not its *ID*) / expired secret |
| `AADSTS500011` | Wrong App ID URI in the scope, or the API has no service principal in this tenant |
| `AADSTS70011` | The scope must end in `/.default` |
| `AADSTS501051` | "Assignment required" is on and the app role isn't granted |
| `AADSTS700213` | Federated credential's issuer, subject or audience doesn't match the CI token. Check the GitLab `rules` branch, the GitHub `environment`, and `aud` |
| API returns **401** | `iss`/`aud` mismatch (v1 vs v2 token version), wrong tenant, expired token |
| API returns **403** | No `roles` claim: admin consent missing, or the token predates consent. Managed identity tokens can be cached by Entra for hours, so a new role may take a long time to appear. |
| Tests pass instantly with `(cached)` | Use `-count=1` |
| Tests all skipped | A required env var is missing (`testauth.ErrNotConfigured`) |

To inspect a token while debugging, decode the payload locally (never paste production tokens into
third-party sites):

```go
parts := strings.Split(token, ".")
payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
fmt.Println(string(payload)) // check iss, aud, roles, scp, azp, tid
```

## Operational tips

- One test app **per environment** (dev, test, staging). Don't grant the test app roles on production unless you mean to.
- Prefer federation, so there are no secrets to rotate. If you must use a secret, keep it in the CI secret
  store (GitLab: Masked and Protected) with a short expiry.
- Review **Entra → Sign-in logs → Service principal sign-ins** for token requests and failures.
- Build the credential and HTTP client once per test run.

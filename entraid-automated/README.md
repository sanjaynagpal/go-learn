# Calling an Entra ID–protected API from automated tests (OAuth 2.0 client credentials)

## Problem

A desktop/mobile app calls a web service using **OAuth 2.0 Authorization Code + PKCE** with
**Microsoft Entra ID** as the IdP. A human signs in, the app receives an access token, and sends it
to the service as `Authorization: Bearer <token>`.

Automated regression tests have **no human in the loop**, so they cannot complete an interactive sign-in.

## Solution overview

Use the **OAuth 2.0 client credentials flow**. The test runner authenticates as an *application*
(a service principal), gets an **app-only** access token directly from Entra ID, and calls the API
with it as a Bearer token, just like the desktop app.

```
┌──────────────┐  1. client_id + credential      ┌──────────────┐
│ Test runner  │ ──────────────────────────────▶ │  Entra ID    │
│ (CI / local) │ ◀────────────────────────────── │ token endpoint│
└──────┬───────┘  2. access token (roles claim)  └──────────────┘
       │ 3. Authorization: Bearer <token>
       ▼
┌──────────────┐
│   Web API    │  4. validate signature/iss/aud, authorize on `roles`
└──────────────┘
```

> **Java?** See [README-java.md](README-java.md) for the same approach with Azure Identity for Java
> (JUnit 5, TestNG, REST Assured, Maven/Gradle in GitLab).

The setup has four parts:

1. Register the web API and define an **app role** on it.
2. Register a **separate test client app**, give it a credential, and grant it the role.
3. Have the test **get a token** and call the API with it.
4. Make sure the **API accepts and authorizes app-only tokens**.

---

## Part 1: Set up the web API's app registration

You probably already have this registration, since the desktop app requests delegated scopes from it.
Open **Entra admin center → Identity → Applications → App registrations → *your API***.

### 1.1 Application ID URI

**Expose an API → Application ID URI → Add**. The default `api://<api-client-id>` is fine.
Tests will request the scope `api://<api-client-id>/.default`.

### 1.2 Create an app role for applications

**App roles → Create app role**

| Field                | Value                                                                 |
|----------------------|-----------------------------------------------------------------------|
| Display name         | `Regression test access`                                              |
| Allowed member types | **Applications** (this makes it an *application permission*)          |
| Value                | `Api.Test.ReadWrite` (appears in the token's `roles` claim)           |
| Description          | `Allows automated test clients to call the API`                       |
| Enabled              | ✔                                                                     |

You can create several roles (for example `Api.Read.All` and `Api.Write.All`) if tests need different levels of access.

### 1.3 Check the access token version

In **Manifest**, look at `requestedAccessTokenVersion` (`api.requestedAccessTokenVersion` in the newer manifest):

| Value         | `aud` claim               | `iss` claim                                           |
|---------------|---------------------------|-------------------------------------------------------|
| `2`           | API client ID (GUID)      | `https://login.microsoftonline.com/<tenant>/v2.0`     |
| `null` or `1` | `api://<api-client-id>`   | `https://sts.windows.net/<tenant>/`                   |

The API's token validation must match this. A mismatch is the most common cause of `401` responses.

### 1.4 Require role assignment (recommended hardening)

By default, **any app in the tenant** can get a client credentials token for your API. The token
just won't have a `roles` claim. To make Entra refuse tokens to apps without an assigned role:

**Enterprise applications → *your API* → Properties → Assignment required? = Yes**

Apps without a role then get `AADSTS501051` instead of a token. The API must still check `roles`;
this is defense in depth.

---

## Part 2: Register the test client

### 2.1 Create the registration

**App registrations → New registration**

- Name: `myapi-regression-tests`
- Supported account types: **Accounts in this organizational directory only**
- Redirect URI: **leave empty** (client credentials doesn't use one)

Note the **Application (client) ID** and **Directory (tenant) ID**.

> Use a separate registration, not the desktop app's. The desktop app is a *public* client and must
> never hold a secret. A separate test app can also be disabled, audited, and limited on its own.

### 2.2 Give it a credential (pick one)

| Option | Best for | Secret to store? |
|---|---|---|
| A. Federated credential (workload identity federation) | GitHub Actions, Azure DevOps, GitLab CI/CD, Kubernetes | **No** |
| B. Managed identity | Tests running on Azure compute | **No** |
| C. Certificate | CI outside Azure | Private key |
| D. Client secret | Quick start, local dev | Yes (weakest) |

#### Option A: Federated credential

The CI platform proves its identity with its own OIDC token, and Entra trusts it. There is no secret.

**Certificates & secrets → Federated credentials → Add credential**

- Scenario: **GitHub Actions deploying Azure resources** (despite the name, it works for any token request)
- Organization / Repository: `myorg` / `myrepo`
- Entity type: **Environment** (e.g. `regression`), **Branch** (`main`), or **Pull request**
- Result:
  - Issuer: `https://token.actions.githubusercontent.com`
  - Subject: `repo:myorg/myrepo:environment:regression`
  - Audience: `api://AzureADTokenExchange`

The subject must match *exactly* what the workflow presents, or you get `AADSTS700213`.

For **Azure DevOps**, create an *Azure Resource Manager service connection* with
**Workload identity federation**. It can create or reuse the app registration and adds the federated credential for you.

For **GitLab**, add a federated credential with scenario **Other issuer**:

| Field    | Value |
|----------|-------|
| Issuer   | `https://gitlab.com` (or your self-managed GitLab URL, e.g. `https://gitlab.example.com`, with no trailing slash) |
| Subject  | `project_path:mygroup/myproject:ref_type:branch:ref:main` |
| Audience | `api://AzureADTokenExchange` |

Subject formats GitLab produces:

| Pipeline runs on | Subject |
|---|---|
| Branch `main` | `project_path:mygroup/myproject:ref_type:branch:ref:main` |
| Tag `v1.2.0`  | `project_path:mygroup/myproject:ref_type:tag:ref:v1.2.0` |

Entra matches the subject **exactly** (no wildcards), so add one federated credential per branch that
runs the tests. An app can have up to 20. For a self-managed GitLab, Entra must be able to reach
`<issuer>/.well-known/openid-configuration` and its JWKS endpoint over the internet.
See [3.7 GitLab CI/CD](#37-gitlab-cicd) for the pipeline.

#### Option B: Managed identity

If the test agent runs on Azure (VM, VM scale set, AKS, Container Apps, and so on), use its managed identity
in place of the app registration from 2.1. There is no portal UI for giving a managed identity an app role;
use the Graph call in 2.3.

#### Option C: Certificate

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout test.key -out test.crt -days 365 \
  -subj "/CN=myapi-regression-tests"
```

Upload `test.crt` (public part only) under **Certificates & secrets → Certificates**. Store the private
key (PFX/PEM) in Key Vault or the CI secret store.

#### Option D: Client secret

**Certificates & secrets → Client secrets → New client secret.** Copy the **Value** right away (it is
shown only once). Store it in Key Vault or the CI secret store, set a short expiry, and plan to rotate it.

### 2.3 Grant the app role

**Portal**

1. On the test app: **API permissions → Add a permission → APIs my organization uses** → select your API.
2. Choose **Application permissions** (not Delegated), tick `Api.Test.ReadWrite` → **Add permissions**.
3. Click **Grant admin consent for &lt;tenant&gt;**. This needs an admin role such as Cloud Application
   Administrator or Application Administrator. Status should show a green ✔ *Granted*.

This creates an **app role assignment** from the test app's service principal to the API's service principal.
That assignment is what puts `roles` into the token.

**Azure CLI equivalent**

```bash
API_APP_ID=<api-client-id>
TEST_APP_ID=<test-client-id>

# ID of the app role defined on the API
ROLE_ID=$(az ad app show --id $API_APP_ID \
  --query "appRoles[?value=='Api.Test.ReadWrite'].id" -o tsv)

# Make sure both service principals exist
az ad sp create --id $TEST_APP_ID 2>/dev/null
API_SP_ID=$(az ad sp show --id $API_APP_ID --query id -o tsv)
TEST_SP_ID=$(az ad sp show --id $TEST_APP_ID --query id -o tsv)
# For a managed identity, TEST_SP_ID = the identity's principal (object) ID

# Create the app role assignment (same as admin consent for application permissions)
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$TEST_SP_ID/appRoleAssignments" \
  --body "{\"principalId\":\"$TEST_SP_ID\",\"resourceId\":\"$API_SP_ID\",\"appRoleId\":\"$ROLE_ID\"}"
```

---

## Part 3: Get a token in the test

The **scope must be `<App ID URI>/.default`**. Individual scopes can't be requested with client
credentials; Entra includes every role that has been granted.

Tokens last about 60–90 minutes. There is **no refresh token**; just request a new one.

### 3.1 Raw HTTP

With a secret:

```http
POST https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

client_id=<test-client-id>
&scope=api%3A%2F%2F<api-client-id>%2F.default
&client_secret=<secret>
&grant_type=client_credentials
```

With a certificate or federated token, replace `client_secret` with:

```
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<signed JWT or CI OIDC token>
```

### 3.2 Go: `golang.org/x/oauth2/clientcredentials`

Gives you an `*http.Client` that adds the Bearer token and gets a new one automatically when it expires.

```go
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"golang.org/x/oauth2/clientcredentials"
)

func main() {
	tenant := os.Getenv("TENANT_ID")
	cfg := clientcredentials.Config{
		ClientID:     os.Getenv("TEST_CLIENT_ID"),
		ClientSecret: os.Getenv("TEST_CLIENT_SECRET"),
		TokenURL:     fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant),
		Scopes:       []string{"api://" + os.Getenv("API_CLIENT_ID") + "/.default"},
	}

	client := cfg.Client(context.Background()) // token is cached and renewed automatically
	resp, err := client.Get("https://myapi.example.com/orders")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(resp.Status, string(body))
}
```

### 3.3 Go: Azure SDK (`azidentity`)

Supports secrets, certificates, workload identity (federated), and managed identity.
`DefaultAzureCredential` picks the right one for the environment.

```go
import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

func apiToken(ctx context.Context, apiClientID string) (string, error) {
	// Or: azidentity.NewClientSecretCredential(tenant, clientID, secret, nil)
	//     azidentity.NewWorkloadIdentityCredential(nil)
	//     azidentity.NewManagedIdentityCredential(nil)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", err
	}
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"api://" + apiClientID + "/.default"},
	})
	if err != nil {
		return "", err
	}
	return tok.Token, nil
}
```

### 3.4 C# (MSAL.NET) test fixture

```csharp
public sealed class ApiTokenProvider
{
    private readonly IConfidentialClientApplication _app;
    private readonly string[] _scopes;

    public ApiTokenProvider(string tenantId, string clientId, string apiAppIdUri)
    {
        _app = ConfidentialClientApplicationBuilder.Create(clientId)
            .WithAuthority($"https://login.microsoftonline.com/{tenantId}")
            .WithClientSecret(Environment.GetEnvironmentVariable("TEST_CLIENT_SECRET"))
            // or .WithCertificate(new X509Certificate2("test.pfx", pwd))
            // or .WithClientAssertion(ct => GetFederatedTokenAsync(ct))
            .Build();
        _scopes = new[] { $"{apiAppIdUri}/.default" };
    }

    // MSAL caches app tokens in memory and renews them shortly before they expire
    public async Task<string> GetTokenAsync() =>
        (await _app.AcquireTokenForClient(_scopes).ExecuteAsync()).AccessToken;
}
```

### 3.5 Python (MSAL)

```python
import msal, os, requests

app = msal.ConfidentialClientApplication(
    client_id=os.environ["TEST_CLIENT_ID"],
    authority=f"https://login.microsoftonline.com/{os.environ['TENANT_ID']}",
    client_credential=os.environ["TEST_CLIENT_SECRET"],
)
result = app.acquire_token_for_client(scopes=[f"api://{os.environ['API_CLIENT_ID']}/.default"])
resp = requests.get("https://myapi.example.com/orders",
                    headers={"Authorization": f"Bearer {result['access_token']}"})
```

### 3.6 GitHub Actions with a federated credential (no secret)

```yaml
permissions:
  id-token: write      # required so the job can request an OIDC token
  contents: read

jobs:
  regression:
    runs-on: ubuntu-latest
    environment: regression          # must match the federated credential's subject
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2
        with:
          client-id: ${{ vars.TEST_CLIENT_ID }}
          tenant-id: ${{ vars.TENANT_ID }}
          allow-no-subscriptions: true
      - name: Get API token
        run: |
          TOKEN=$(az account get-access-token \
            --scope "api://${{ vars.API_CLIENT_ID }}/.default" --query accessToken -o tsv)
          echo "::add-mask::$TOKEN"
          echo "API_TOKEN=$TOKEN" >> $GITHUB_ENV
      - run: go test ./...   # tests read API_TOKEN, or use azidentity directly
```

In **Azure DevOps**, use an `AzureCLI@2` task with the workload identity service connection and run the
same `az account get-access-token --scope ...` command.

### 3.7 GitLab CI/CD

#### Option 1: Federated credential (recommended, no secret)

GitLab issues the job an OIDC ID token through the `id_tokens` keyword. The test exchanges it with Entra
for an API access token, using it as a `client_assertion`. This requires the federated credential from
[Option A](#option-a-federated-credential).

Set these as CI/CD variables (**Settings → CI/CD → Variables**). They aren't secrets: `TENANT_ID`,
`TEST_CLIENT_ID`, `API_CLIENT_ID`.

**a) Go tests get the token themselves** (simplest: no extra tools in the image)

`.gitlab-ci.yml`:

```yaml
stages: [test]

regression-tests:
  stage: test
  image: golang:1.23
  id_tokens:
    AZURE_JWT:                              # GitLab puts the signed OIDC token in $AZURE_JWT
      aud: api://AzureADTokenExchange       # must match the federated credential's audience
  rules:
    - if: $CI_COMMIT_BRANCH == "main"       # must match the federated credential's subject
  script:
    - go test ./... -v
```

Test helper using `azidentity.NewClientAssertionCredential`:

```go
package regression

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

func apiToken(t *testing.T) string {
	t.Helper()
	cred, err := azidentity.NewClientAssertionCredential(
		os.Getenv("TENANT_ID"),
		os.Getenv("TEST_CLIENT_ID"),
		func(ctx context.Context) (string, error) {
			return os.Getenv("AZURE_JWT"), nil // GitLab OIDC token = client assertion
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"api://" + os.Getenv("API_CLIENT_ID") + "/.default"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok.Token
}

func TestListOrders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, os.Getenv("API_BASE_URL")+"/orders", nil)
	req.Header.Set("Authorization", "Bearer "+apiToken(t))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %s", resp.Status)
	}
}
```

In a real suite, get the token once (for example in `TestMain`, or with `sync.Once`) and reuse it, rather
than getting one per test.

**b) Shell step gets the token and passes it to the tests**

Use this when the tests are in another language, or only read a ready-made token from `API_TOKEN`:

```yaml
regression-tests:
  stage: test
  image: golang:1.23
  id_tokens:
    AZURE_JWT:
      aud: api://AzureADTokenExchange
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  before_script:
    - apt-get update -qq && apt-get install -y -qq jq
    - |
      export API_TOKEN=$(curl -sf -X POST \
        "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
        -d "client_id=${TEST_CLIENT_ID}" \
        -d "grant_type=client_credentials" \
        --data-urlencode "scope=api://${API_CLIENT_ID}/.default" \
        -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
        --data-urlencode "client_assertion=${AZURE_JWT}" | jq -r .access_token)
    - test -n "$API_TOKEN" && test "$API_TOKEN" != "null"   # fail fast if the exchange failed
  script:
    - go test ./... -v                     # tests read os.Getenv("API_TOKEN")
```

With the Azure CLI image (`mcr.microsoft.com/azure-cli`), you can do the exchange with `az` instead
(full details in [3.8](#38-gitlab-cicd-with-the-azure-cli-detailed)):

```bash
az login --service-principal -u "$TEST_CLIENT_ID" -t "$TENANT_ID" \
  --federated-token "$AZURE_JWT" --allow-no-subscriptions
export API_TOKEN=$(az account get-access-token \
  --scope "api://${API_CLIENT_ID}/.default" --query accessToken -o tsv)
```

#### Option 2: Client secret or certificate

If you can't use federation (for example, your self-managed GitLab isn't reachable from the internet):

1. Add `TEST_CLIENT_SECRET` as a CI/CD variable with **Masked** and **Protected** enabled.
   Protected means only pipelines on protected branches and tags can read it.
2. Leave out `id_tokens` and use the secret version of the code in [3.2](#32-go-golangorgxoauth2clientcredentials)
   or [3.3](#33-go-azure-sdk-azidentity) (`azidentity.NewClientSecretCredential`).

For a certificate, store the PEM as a CI/CD variable of type **File**. GitLab writes it to a temp file and
puts the path in the variable, which `azidentity.NewClientCertificateCredential` can load.

#### GitLab tips

- **Don't echo** `$AZURE_JWT` or `$API_TOKEN`. GitLab can't mask values created at runtime, so they would
  appear in the job log.
- `rules` should match the federated credential's subject. Otherwise the exchange fails with
  `AADSTS700213` on branches that don't have a credential.
- To see what GitLab sends, decode the claims without the signature in a throwaway debug job (and remove it after):
  `echo "$AZURE_JWT" | cut -d. -f2 | base64 -d 2>/dev/null; echo`. Look at `iss`, `sub`, and `aud`.

### 3.8 GitLab CI/CD with the Azure CLI (detailed)

The Azure CLI does three things in a GitLab job:

1. **Sign in** as the test app (service principal) using a GitLab OIDC token (federated), a client secret, or a certificate.
2. **Get an access token** for the API with `az account get-access-token --scope api://<api>/.default`.
3. **Pass the token** to the tests running in the same job, for example through an environment variable.

#### 3.8.1 Prerequisites in Entra ID

See Parts 1–2:

- The API's app registration has an **app role** (e.g. `Api.Test.ReadWrite`).
- The test app registration has that role **granted with admin consent**.
- The test app has a credential:
  - **Federated (recommended):** issuer `https://gitlab.com` (or your self-managed URL), subject
    `project_path:mygroup/myproject:ref_type:branch:ref:main`, audience `api://AzureADTokenExchange`.
  - Or a **client secret** or **certificate**.

#### 3.8.2 GitLab CI/CD variables

**Settings → CI/CD → Variables**

| Variable | Value | Flags |
|---|---|---|
| `TENANT_ID` | Directory (tenant) ID | none (not secret) |
| `TEST_CLIENT_ID` | Test app's client ID | none |
| `API_CLIENT_ID` | API's client ID | none |
| `API_BASE_URL` | e.g. `https://myapi-test.example.com` | none |
| `TEST_CLIENT_SECRET` | *only if not federated* | **Masked + Protected** |
| `TEST_CLIENT_CERT` | *only for a certificate*: PEM with private key and certificate | Type **File**, **Protected** |

The federated option needs no secret variable. GitLab creates the OIDC token for each job.

#### 3.8.3 Choosing an image

The Azure CLI has to be in the job's image.

**A. Microsoft's Azure CLI image**

```yaml
image: mcr.microsoft.com/azure-cli:2.67.0   # pin a version, not :latest
```

It has `az`, `bash`, `curl`, and Python, but **not Go**. Use it for jobs that only get a token or call the API with `curl`.

**B. Install the CLI in the Go image at runtime**

```yaml
image: golang:1.23
before_script:
  - curl -sL https://aka.ms/InstallAzureCLIDeb | bash
```

Simple, but adds roughly 30–60 seconds to every job.

**C. Build your own image with Go and the Azure CLI (recommended for regular use)**

`ci/Dockerfile`:

```dockerfile
FROM golang:1.23
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash \
 && az version
```

Build it once, push it to the project's **Container Registry**, and use it in the job:

```yaml
image: $CI_REGISTRY_IMAGE/go-azcli:1.23
```

#### 3.8.4 Signing in

**Federated (no secret)**

The `id_tokens` keyword tells GitLab to put a signed OIDC token in a variable. `az login` sends that
token to Entra in place of a secret:

```yaml
regression-tests:
  image: mcr.microsoft.com/azure-cli:2.67.0
  id_tokens:
    AZURE_JWT:
      aud: api://AzureADTokenExchange      # must match the federated credential's audience
  script:
    - |
      az login --service-principal \
        --username "$TEST_CLIENT_ID" \
        --tenant   "$TENANT_ID" \
        --federated-token "$AZURE_JWT" \
        --allow-no-subscriptions \
        --output none
```

| Flag | Purpose |
|---|---|
| `--service-principal` | Sign in as an app, not a user |
| `--username` | The test app's **client ID** (not a user name) |
| `--federated-token` | The GitLab OIDC JWT. Entra checks its `iss`, `sub`, and `aud` against the federated credential |
| `--allow-no-subscriptions` | **Required in most cases.** The test app usually has no Azure subscription access (it only needs a role on the API). Without it, `az login` fails with "No subscriptions found" |
| `--output none` | Keeps the sign-in details out of the job log |

**Client secret**

```bash
az login --service-principal \
  --username "$TEST_CLIENT_ID" --tenant "$TENANT_ID" \
  --client-secret "$TEST_CLIENT_SECRET" \
  --allow-no-subscriptions --output none
```

Older CLI versions use `--password` / `-p`. Newer versions deprecate it for service principals in favor of
`--client-secret`. Check `az login --help` for your pinned version.

**Certificate**

```bash
az login --service-principal \
  --username "$TEST_CLIENT_ID" --tenant "$TENANT_ID" \
  --certificate "$TEST_CLIENT_CERT" \
  --allow-no-subscriptions --output none
```

`TEST_CLIENT_CERT` is a **File** variable, so GitLab passes the *path* to a temporary file holding the PEM,
which is what `--certificate` expects. Older versions use `-p <pem-path>`.

#### 3.8.5 Getting the API access token

```bash
API_TOKEN=$(az account get-access-token \
  --scope "api://${API_CLIENT_ID}/.default" \
  --query accessToken -o tsv)
export API_TOKEN
```

- `--scope ... /.default` is the v2 way to name the resource. `--resource api://<id>` (v1 style) works too.
- `--query accessToken -o tsv` prints only the raw token, with no JSON and no need for `jq`.
- To see the expiry without printing the token:

  ```bash
  az account get-access-token --scope "api://${API_CLIENT_ID}/.default" --query expiresOn -o tsv
  ```

The token is good for about 60–90 minutes. For longer jobs, see 3.8.9.

#### 3.8.6 Using the token in the tests

**Option 1: Pass it as an environment variable.** It's exported in the same job, so `go test` sees it:

```go
req.Header.Set("Authorization", "Bearer "+os.Getenv("API_TOKEN"))
```

**Option 2: Let Go ask the CLI (`AzureCLICredential`).** After `az login`, the Go code can get tokens
itself. It runs `az account get-access-token` for you and asks again when the token expires:

```go
cred, err := azidentity.NewAzureCLICredential(nil)
tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{
    Scopes: []string{"api://" + os.Getenv("API_CLIENT_ID") + "/.default"},
})
```

This needs both Go and `az` in the same image (option B or C in 3.8.3). The same code works locally after a
developer runs `az login`. Locally, though, it gets a **delegated** user token (`scp`), not an app token
(`roles`), so the API must accept both (Part 4).

#### 3.8.7 Full example `.gitlab-ci.yml`

```yaml
stages: [test]

variables:
  AZURE_CONFIG_DIR: "$CI_PROJECT_DIR/.azure"   # keep CLI state inside this job's folder

# Reusable sign-in steps
.azure-login:
  id_tokens:
    AZURE_JWT:
      aud: api://AzureADTokenExchange
  before_script:
    - az version --output none
    - |
      az login --service-principal \
        --username "$TEST_CLIENT_ID" \
        --tenant   "$TENANT_ID" \
        --federated-token "$AZURE_JWT" \
        --allow-no-subscriptions --output none
    - |
      export API_TOKEN=$(az account get-access-token \
        --scope "api://${API_CLIENT_ID}/.default" \
        --query accessToken -o tsv)
    - test -n "$API_TOKEN"                     # fail fast if no token
  after_script:
    - az logout || true
    - rm -rf "$AZURE_CONFIG_DIR"

# Smoke check with curl only
api-smoke:
  stage: test
  image: mcr.microsoft.com/azure-cli:2.67.0
  extends: .azure-login
  rules:
    - if: $CI_COMMIT_BRANCH == "main"          # must match the federated credential's subject
  script:
    - |
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $API_TOKEN" "$API_BASE_URL/health")
      echo "HTTP $STATUS"
      test "$STATUS" = "200"

# Go regression tests (image has Go + az)
regression-tests:
  stage: test
  image: $CI_REGISTRY_IMAGE/go-azcli:1.23
  extends: .azure-login
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  script:
    - go test ./... -v
```

- `.azure-login` is a **hidden job** (its name starts with `.`). Reuse it with `extends`, or pick pieces with
  `!reference [.azure-login, before_script]` if a job has its own `before_script`.
- `AZURE_CONFIG_DIR` keeps the CLI's sign-in state in the job's own folder. This matters on **shell** runners
  or shared runner hosts, where jobs could otherwise use each other's `~/.azure` sign-in. With **Docker**
  runners each job gets a fresh container anyway.
- `after_script` runs even if `script` fails, so the sign-in is always cleared.

#### 3.8.8 Passing the token to another job (avoid)

It's tempting to get the token in one job and pass it on as a `dotenv` artifact. **Don't.** Artifacts are
stored by GitLab, and anyone with access to the project can download them while the token is still valid.
Sign in **in every job that needs the token**. It takes about a second.

#### 3.8.9 Long jobs and expiry

- The **GitLab OIDC token** (`$AZURE_JWT`) is short-lived. Run `az login` at the **start** of the job.
- The **Entra access token** lasts about 60–90 minutes. For longer test runs:
  - use `AzureCLICredential` (3.8.6, option 2), which asks the CLI again when needed, or
  - run `az account get-access-token` again between test stages.
- With a *federated* sign-in, the CLI may not be able to get a new token once `$AZURE_JWT` has expired.
  For long suites, either use `azidentity.NewClientAssertionCredential` in Go (3.7, option 1a) or split the
  suite into shorter jobs.

#### 3.8.10 Security tips

- **Never echo** `$AZURE_JWT` or `$API_TOKEN`. GitLab can't mask values created during the job.
- **Don't turn on `CI_DEBUG_TRACE`** for these jobs. It prints every variable, including `AZURE_JWT`.
- Mark secret variables **Protected** so pipelines from untrusted branches or forks can't read them.
- Limit jobs with `rules` to the branches that have a federated credential.
- Pin the CLI image version so CLI changes don't break the pipeline without warning.
- Behind a corporate proxy, set `HTTPS_PROXY` / `NO_PROXY` as CI variables. `az` honors them.

#### 3.8.11 Debugging

```bash
# Which identity am I signed in as?
az account show --query "{tenant:tenantId, user:user.name, type:user.type}" -o table

# Look at the API token's claims (payload only, signature not printed)
python3 - <<'EOF'
import os, base64, json
p = os.environ["API_TOKEN"].split(".")[1]
p += "=" * (-len(p) % 4)
c = json.loads(base64.urlsafe_b64decode(p))
print({k: c.get(k) for k in ("aud", "iss", "azp", "appid", "roles", "scp", "exp")})
EOF

# Look at what GitLab sends to Entra (iss, sub, aud)
python3 - <<'EOF'
import os, base64, json
p = os.environ["AZURE_JWT"].split(".")[1]; p += "=" * (-len(p) % 4)
c = json.loads(base64.urlsafe_b64decode(p)); print({k: c[k] for k in ("iss", "sub", "aud")})
EOF
```

Use these only in a temporary debug job, then remove them.

| Error | Meaning / fix |
|---|---|
| `No subscriptions found for ...` | Add `--allow-no-subscriptions` |
| `AADSTS70021` / `AADSTS700213` no matching federated identity record | `iss`, `sub`, or `aud` doesn't match the federated credential. Compare with the debug output above. A different branch or a tag pipeline is the usual cause |
| `AADSTS700024` client assertion not within its valid time range | `$AZURE_JWT` expired. Sign in earlier in the job |
| `AADSTS7000215` invalid client secret | Wrong secret, or the secret's *ID* was used instead of its *Value* |
| `AADSTS500011` resource principal not found | Wrong `API_CLIENT_ID` / App ID URI in `--scope` |
| `az: command not found` | The image doesn't include the CLI. See 3.8.3 |
| API returns `403` | No `roles` claim. Admin consent is missing, or the API only checks `scp` |

### 3.9 azidentity in detail (Go)

`azidentity` (`github.com/Azure/azure-sdk-for-go/sdk/azidentity`) is Microsoft's official **Go library for
getting Entra ID tokens**. It's part of the Azure SDK for Go and is built on MSAL for Go. Despite the name,
it works for **any** Entra-protected API, including your own (scope `api://<api-client-id>/.default`).

Every credential type implements the same interface (`azcore.TokenCredential`):

```go
GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
```

So switching from a secret to federation, or from CI to a laptop, means changing one line or only
environment variables.

```bash
go get github.com/Azure/azure-sdk-for-go/sdk/azidentity
go get github.com/Azure/azure-sdk-for-go/sdk/azcore
```

For Java, see [README-java.md](README-java.md).

#### 3.9.1 Credential types

| Credential | How it proves identity | Use in this scenario |
|---|---|---|
| `ClientSecretCredential` | Client ID + secret | CI with a secret, local dev |
| `ClientCertificateCredential` | Client ID + certificate | CI without federation |
| `ClientAssertionCredential` | A callback that returns a signed JWT (e.g. the GitLab OIDC token) | **GitLab federated sign-in, the best fit** |
| `WorkloadIdentityCredential` | Reads a federated token from a **file** (`AZURE_FEDERATED_TOKEN_FILE`) | AKS, or GitLab if you write the JWT to a file |
| `ManagedIdentityCredential` | The Azure host's managed identity | Runners on Azure VMs or AKS |
| `AzureCLICredential` | Runs `az account get-access-token` | After `az login` (3.8), local dev |
| `AzurePipelinesCredential` | Azure DevOps service connection (federated) | Azure DevOps pipelines |
| `EnvironmentCredential` | Secret or certificate from `AZURE_*` environment variables | Configuration through environment variables only |
| `DefaultAzureCredential` | **Tries several of the above in order** | "Works everywhere" setups |
| `ChainedTokenCredential` | A chain you build yourself | Control over the order |
| `InteractiveBrowserCredential`, `DeviceCodeCredential` | A user signs in | ❌ Not for unattended tests |

`DefaultAzureCredential` tries, in order: **Environment** (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, plus
`AZURE_CLIENT_SECRET` or `AZURE_CLIENT_CERTIFICATE_PATH`) → **Workload identity**
(`AZURE_FEDERATED_TOKEN_FILE`) → **Managed identity** → **Azure CLI** → **Azure Developer CLI**. It uses the
first that works, which can hide which identity you got. In CI, prefer a specific credential so a
misconfigured pipeline fails clearly.

#### 3.9.2 Creating the credential

```go
// GitLab federated (recommended)
cred, err := azidentity.NewClientAssertionCredential(tenantID, clientID,
	func(ctx context.Context) (string, error) { return os.Getenv("AZURE_JWT"), nil }, nil)

// Client secret
cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, os.Getenv("TEST_CLIENT_SECRET"), nil)

// Certificate (PEM or PFX)
data, _ := os.ReadFile(os.Getenv("TEST_CLIENT_CERT"))      // GitLab File variable = path
certs, key, err := azidentity.ParseCertificates(data, nil) // second argument: PFX password, if any
cred, err := azidentity.NewClientCertificateCredential(tenantID, clientID, certs, key, nil)

// After `az login`
cred, err := azidentity.NewAzureCLICredential(nil)

// Works in CI (token file) and on a laptop (az login) without code changes
cred, err := azidentity.NewDefaultAzureCredential(nil)
```

For `DefaultAzureCredential` with GitLab federation, write the OIDC token to a file:

```yaml
regression-tests:
  image: golang:1.23
  id_tokens:
    AZURE_JWT:
      aud: api://AzureADTokenExchange
  variables:
    AZURE_TENANT_ID: $TENANT_ID
    AZURE_CLIENT_ID: $TEST_CLIENT_ID
    AZURE_FEDERATED_TOKEN_FILE: /tmp/azure-jwt
  script:
    - printf '%s' "$AZURE_JWT" > "$AZURE_FEDERATED_TOKEN_FILE"
    - go test ./... -v
```

#### 3.9.3 Adding the token to every HTTP call

Your API isn't an Azure SDK client, so wrap `http.RoundTripper`:

```go
package apiclient

import (
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type bearerTransport struct {
	cred   azcore.TokenCredential
	scopes []string
	next   http.RoundTripper
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := t.cred.GetToken(req.Context(), policy.TokenRequestOptions{Scopes: t.scopes})
	if err != nil {
		return nil, err
	}
	r := req.Clone(req.Context()) // RoundTrippers must not modify the original request
	r.Header.Set("Authorization", "Bearer "+tok.Token)
	return t.next.RoundTrip(r)
}

// New returns an *http.Client that adds an Entra token for the given API to every request.
func New(cred azcore.TokenCredential, apiClientID string) *http.Client {
	return &http.Client{Transport: &bearerTransport{
		cred:   cred,
		scopes: []string{"api://" + apiClientID + "/.default"},
		next:   http.DefaultTransport,
	}}
}
```

**Reuse one credential.** The secret, certificate, and assertion credentials keep tokens in memory and only
go back to Entra when the token is close to expiring.

#### 3.9.4 Set it up once in `TestMain`

```go
var api *http.Client

func TestMain(m *testing.M) {
	cred, err := azidentity.NewDefaultAzureCredential(nil) // or a specific credential from 3.9.2
	if err != nil {
		fmt.Fprintln(os.Stderr, "credential:", err)
		os.Exit(1)
	}
	// Fail fast: check that a token can be obtained before running any test
	if _, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"api://" + os.Getenv("API_CLIENT_ID") + "/.default"},
	}); err != nil {
		fmt.Fprintln(os.Stderr, "token:", err)
		os.Exit(1)
	}
	api = apiclient.New(cred, os.Getenv("API_CLIENT_ID"))
	os.Exit(m.Run())
}

func TestListOrders(t *testing.T) {
	resp, err := api.Get(os.Getenv("API_BASE_URL") + "/orders")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %s", resp.Status)
	}
}
```

#### 3.9.5 Errors, logging, options, fakes

```go
var authErr *azidentity.AuthenticationFailedError   // Entra rejected it; message has the AADSTS code
var unavailable *azidentity.CredentialUnavailableError // credential can't work here (az missing, env vars missing)
if errors.As(err, &authErr) { /* authErr.RawResponse has the HTTP response */ }
```

- **Logging:** set `AZURE_SDK_GO_LOGGING=all`, or in code:
  `azlog.SetListener(...)` and `azlog.SetEvents(azidentity.EventAuthentication)` (package
  `github.com/Azure/azure-sdk-for-go/sdk/azcore/log`). Tokens are not logged.
- **Sovereign clouds:** set `ClientOptions: azcore.ClientOptions{Cloud: cloud.AzureGovernment}` in the
  credential's options.
- **Proxies:** standard `HTTPS_PROXY` / `NO_PROXY` environment variables.
- **Unit tests without Entra:** `azcore.TokenCredential` is an interface, so use a fake:

  ```go
  type fakeCred struct{}

  func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
  	return azcore.AccessToken{Token: "fake", ExpiresOn: time.Now().Add(time.Hour)}, nil
  }
  ```

#### 3.9.6 azidentity vs. the other Go options

| | `x/oauth2/clientcredentials` | Azure CLI (`az`) | **azidentity** |
|---|---|---|---|
| Client secret | ✔ | ✔ | ✔ |
| Certificate | ✖ | ✔ | ✔ |
| Federated (GitLab OIDC) | ✖ (manual) | ✔ | ✔ |
| Managed identity | ✖ | ✔ | ✔ |
| Same code on laptop and in CI | ✖ | partly | ✔ (`DefaultAzureCredential`) |
| Gets new tokens automatically | ✔ | needs another command | ✔ |
| Needs an extra tool in the image | ✖ | ✔ (`az`) | ✖ |

For Go tests, **azidentity is the best choice**.

---

## Part 4: Make the API accept app-only tokens

### 4.1 Delegated vs app-only tokens

| | Desktop app (delegated, PKCE) | Test runner (app-only, client credentials) |
|---|---|---|
| Permission claim | `scp` (e.g. `access_as_user`) | `roles` (e.g. `Api.Test.ReadWrite`) |
| Identity | User's `oid`, `upn`, `name` | Service principal's `oid`, no user claims |
| `idtyp` (optional claim) | `user` | `app` |

Example app-only token payload (decode at <https://jwt.ms>, which decodes in the browser):

```json
{
  "aud": "<api-client-id>",
  "iss": "https://login.microsoftonline.com/<tenant>/v2.0",
  "azp": "<test-client-id>",
  "oid": "<test app service principal object id>",
  "roles": ["Api.Test.ReadWrite"],
  "idtyp": "app"
}
```

If the API checks only `scp`, test calls fail with `403`.

### 4.2 Validation rules for any stack

- Validate the **signature** with keys from `https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys`.
- Validate `iss` and `aud` against the token version (see 1.3).
- Validate `exp` and `nbf`.
- **Authorize on `roles`** for app-only tokens. Never accept a token on signature alone, because any
  app in the tenant can get one (see 1.4).
- Optionally allow only specific callers by checking `azp` (v2) / `appid` (v1).

### 4.3 Go: authorization middleware sketch

The sketch assumes the JWT has already been validated (signature, `iss`, `aud`, `exp`), for example with
`github.com/golang-jwt/jwt/v5` plus a JWKS key function, and that its claims are in the request context.

```go
func requireAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromContext(r.Context()) // map[string]any from the validated JWT

		// Delegated token from the desktop app
		if scp, ok := claims["scp"].(string); ok && slices.Contains(strings.Fields(scp), "access_as_user") {
			next.ServeHTTP(w, r)
			return
		}
		// App-only token from the test runner
		if roles, ok := claims["roles"].([]any); ok {
			for _, role := range roles {
				if role == "Api.Test.ReadWrite" {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}
```

### 4.4 ASP.NET Core (Microsoft.Identity.Web)

`appsettings.json`:

```json
"AzureAd": {
  "Instance": "https://login.microsoftonline.com/",
  "TenantId": "<tenant-id>",
  "ClientId": "<api-client-id>",
  "Audience": "<api-client-id>"
}
```

Use `"api://<api-client-id>"` as the audience for v1 tokens.

`Program.cs`:

```csharp
builder.Services.AddMicrosoftIdentityWebApiAuthentication(builder.Configuration);

builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("ApiAccess", p => p.RequireAssertion(ctx =>
        ctx.User.FindFirst("scp")?.Value.Split(' ').Contains("access_as_user") == true
        || ctx.User.IsInRole("Api.Test.ReadWrite")));
});

app.MapGet("/orders", ...).RequireAuthorization("ApiAccess");
```

### 4.5 Code that depends on the user

The test token has no user, so wherever the API reads `upn`, `name`, or the user's `oid`, decide what happens:

- Treat the service principal's `oid` as the caller and give it seeded test data, or
- Allow a test-only header (e.g. `X-Test-User`) that is honored **only** when the token has the test role
  and only in non-production environments.

---

## Part 5: Check it end to end

```bash
TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" \
  -d "client_id=$TEST_APP_ID" -d "client_secret=$SECRET" \
  -d "scope=api://$API_APP_ID/.default" -d "grant_type=client_credentials" | jq -r .access_token)

curl -i -H "Authorization: Bearer $TOKEN" https://myapi.example.com/orders
```

## Troubleshooting

| Error | Cause / fix |
|---|---|
| `AADSTS700016` application not found | Wrong client ID or tenant |
| `AADSTS7000215` / `AADSTS7000222` | Wrong secret (use the secret's *Value*, not its *ID*) / secret expired |
| `AADSTS500011` resource principal not found | Wrong App ID URI in the scope, or the API has no service principal in this tenant |
| `AADSTS70011` invalid scope | The scope must end in `/.default` |
| `AADSTS501051` not assigned to a role | "Assignment required" is on and the role isn't granted (step 2.3) |
| `AADSTS700213` no matching federated identity | The federated credential's subject, issuer, or audience doesn't match the CI token |
| API returns **401** | `aud` or `iss` mismatch (v1 vs v2 token), or wrong tenant |
| API returns **403** | No `roles` claim: admin consent missing, or the token was obtained before consent (get a new one). Or the API checks only `scp` |

## Operational tips

- Use **one test app per environment** (dev, test, staging). Don't grant the test app roles on the
  production API unless you mean to.
- Use federated credentials or managed identity so you have **no secrets to rotate**. If you must use a
  secret, keep it in Key Vault with a short expiry.
- Check **service principal sign-ins** (Entra → Sign-in logs → *Service principal sign-ins*) to see
  token requests and errors.
- Get the token once per test run (or let the library cache it), not once per test.

## Is there a Microsoft test runner for Entra ID?

No. Microsoft doesn't ship a test runner made for calling an Entra ID–protected API from regression tests.
You use your normal test framework (`go test`, xUnit, pytest, Playwright) and get tokens with Microsoft's
libraries and CLI, as described above. These are the Microsoft tools that do relate to testing with Entra ID:

| Tool | What it helps with | Does it fit this use case? |
|---|---|---|
| **MSAL** (Go, .NET, Java, Python, JS) / **Azure Identity** (`azidentity`, `Azure.Identity`) | Getting tokens with client credentials, certificates, federated credentials, or managed identity | **Yes.** This is what the tests use to get tokens. |
| **Azure CLI** (`az account get-access-token --scope …`) | Getting a token from a script or pipeline step | **Yes.** It's the usual approach in CI shell steps. |
| **Microsoft Dev Proxy** | Simulating APIs and failures locally. It may also have plugins that mock Entra token responses and check tokens on simulated APIs (confirm in its docs). | Partly. It's for local/offline testing, not for calling the real API with real Entra tokens. |
| **ASP.NET Core `WebApplicationFactory`** with a fake authentication handler | In-process integration tests that skip Entra and inject the claims you want | Only for .NET APIs, and it doesn't test the real Entra setup. |
| **Azure Load Testing** / **Playwright Testing** (Azure App Testing) | Hosted load and browser testing | They run tests. The scripts still have to get the Entra token themselves (for example through Key Vault secrets). |
| **Maester** (open source, started by Microsoft employees, not an official product) | Pester tests for the Entra **tenant configuration** (Conditional Access, security settings) | No. It tests the tenant, not your API. |
| **Conditional Access "What If"** tool | Predicting which Conditional Access policies apply to a sign-in | Useful for figuring out why a test identity is blocked. |

**Recommended pattern:** your test framework, plus `azidentity` or MSAL for tokens, plus a federated
credential in the CI system (GitLab, GitHub, Azure DevOps). Nothing else is needed.

## Alternatives (when a real user context is required)

| Approach | Notes |
|---|---|
| ROPC (username/password) with a dedicated test user | Discouraged by Microsoft. Fails with MFA, federated or guest accounts, and Conditional Access. Needs "Allow public client flows". |
| Browser automation (Playwright/Selenium) of the PKCE login | Tests the real flow but is brittle (MFA, Conditional Access, UI changes). Keep it to a few end-to-end smoke tests. |
| Cached refresh token from an interactive login | Fragile (inactivity expiry, revocation) and a sensitive secret. Not recommended. |
| Test-only token issuer (API also trusts a local signing key in non-prod) | Fast, works offline, any claims you like, but doesn't test the Entra integration. **Never enable in production.** |

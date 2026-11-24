# Java test automation against an Entra ID–protected API (Azure Identity for Java)

This is the Java version of the Go `azidentity` approach in [README.md](README.md). It covers how Java
regression tests (JUnit 5, TestNG, REST Assured, and so on) get an **app-only access token** from
Microsoft Entra ID with the **client credentials flow**, without a human signing in.

> **Prerequisites:** the Entra ID setup is the same for every language. Follow
> [README.md Parts 1–2](README.md#part-1-set-up-the-web-apis-app-registration): an app role on the API,
> a test app registration with that role granted, and a credential (federated, certificate, or secret).
> The API must accept app-only tokens ([Part 4](README.md#part-4-make-the-api-accept-app-only-tokens)).

---

## 1. What Azure Identity for Java is

`com.azure:azure-identity` is Microsoft's official **Java library for getting Entra ID tokens**. It is the
Java counterpart of Go's `azidentity` and is built on **MSAL4J**.

It gives you **credential types**, each one a different way of proving identity. All of them implement
`com.azure.core.credential.TokenCredential`:

```java
Mono<AccessToken> getToken(TokenRequestContext request);   // async (Reactor)
AccessToken getTokenSync(TokenRequestContext request);     // blocking, easiest in tests
```

Test code asks for a token the same way whatever the credential is. Switching from a secret to federation,
or from CI to a laptop, means changing **one builder** or only environment variables.

It works for **any** Entra-protected API, including your own. Ask for the scope `api://<api-client-id>/.default`.

---

## 2. Dependencies

### Maven

```xml
<properties>
  <!-- check Maven Central for the latest azure-sdk-bom version -->
  <azure-sdk-bom.version>1.2.30</azure-sdk-bom.version>
</properties>

<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.azure</groupId>
      <artifactId>azure-sdk-bom</artifactId>
      <version>${azure-sdk-bom.version}</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>

<dependencies>
  <!-- Entra ID tokens (version comes from the BOM) -->
  <dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-identity</artifactId>
    <scope>test</scope>
  </dependency>

  <!-- test stack (pick what you use) -->
  <dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.11.3</version>
    <scope>test</scope>
  </dependency>
  <dependency>
    <groupId>io.rest-assured</groupId>
    <artifactId>rest-assured</artifactId>
    <version>5.5.0</version>
    <scope>test</scope>
  </dependency>

  <!-- optional: lets you see azure-identity logs -->
  <dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-simple</artifactId>
    <version>2.0.16</version>
    <scope>test</scope>
  </dependency>
</dependencies>
```

The BOM keeps `azure-identity`, `azure-core`, and their transitive dependencies on compatible versions.
Use it rather than pinning `azure-identity` alone.

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    testImplementation(platform("com.azure:azure-sdk-bom:1.2.30")) // check for the latest
    testImplementation("com.azure:azure-identity")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testImplementation("io.rest-assured:rest-assured:5.5.0")
    testRuntimeOnly("org.slf4j:slf4j-simple:2.0.16")
}

tasks.test { useJUnitPlatform() }
```

---

## 3. Credential types and when to use each

| Credential (builder) | How it proves identity | Use in this scenario |
|---|---|---|
| `ClientSecretCredentialBuilder` | Client ID + secret | CI with a secret, local dev |
| `ClientCertificateCredentialBuilder` | Client ID + certificate (PEM or PFX) | CI without federation |
| `ClientAssertionCredentialBuilder` | A supplier that returns a signed JWT (for example the GitLab OIDC token) | **GitLab federated sign-in, the best fit** |
| `WorkloadIdentityCredentialBuilder` | Reads a federated token from a **file** | AKS workload identity, or GitLab if you write the JWT to a file |
| `ManagedIdentityCredentialBuilder` | The Azure host's managed identity | Runners on Azure VMs or AKS |
| `AzureCliCredentialBuilder` | Runs `az account get-access-token` | After `az login` ([README 3.8](README.md#38-gitlab-cicd-with-the-azure-cli-detailed)), local dev |
| `AzurePipelinesCredentialBuilder` | Azure DevOps service connection (federated) | Azure DevOps pipelines |
| `EnvironmentCredentialBuilder` | Secret or certificate from `AZURE_*` environment variables | Configuration through environment variables only |
| `DefaultAzureCredentialBuilder` | **Tries several of the above in order** | "Works everywhere" setups |
| `ChainedTokenCredentialBuilder` | A chain you build yourself | Control over the order |
| `InteractiveBrowserCredentialBuilder`, `DeviceCodeCredentialBuilder` | A user signs in | ❌ Not for unattended tests |

### What `DefaultAzureCredential` tries

In order: **Environment** (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, plus `AZURE_CLIENT_SECRET` or
`AZURE_CLIENT_CERTIFICATE_PATH`) → **Workload identity** (`AZURE_FEDERATED_TOKEN_FILE`) → **Managed
identity** → developer tools (IntelliJ, **Azure CLI**, Azure PowerShell, Azure Developer CLI).

The exact list depends on the library version. It uses the first one that works. That's convenient, but
it can hide which identity you actually got. In CI, prefer a **specific** credential (or the explicit chain
in section 4.2) so a misconfigured pipeline fails clearly.

---

## 4. Creating the credential

All examples read the same CI/CD variables as the Go guide: `TENANT_ID`, `TEST_CLIENT_ID`,
`API_CLIENT_ID`, `API_BASE_URL`, and optionally `AZURE_JWT`, `TEST_CLIENT_SECRET`, `TEST_CLIENT_CERT`.

### 4.1 Individual credentials

**GitLab federated (recommended): `ClientAssertionCredential`**

```java
TokenCredential cred = new ClientAssertionCredentialBuilder()
        .tenantId(System.getenv("TENANT_ID"))
        .clientId(System.getenv("TEST_CLIENT_ID"))
        .clientAssertion(() -> System.getenv("AZURE_JWT"))   // GitLab id_tokens value
        .build();
```

**GitLab federated through a token file: `WorkloadIdentityCredential`**

```java
TokenCredential cred = new WorkloadIdentityCredentialBuilder()
        .tenantId(System.getenv("TENANT_ID"))
        .clientId(System.getenv("TEST_CLIENT_ID"))
        .tokenFilePath("/tmp/azure-jwt")       // the job writes $AZURE_JWT here
        .build();
```

If you set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_FEDERATED_TOKEN_FILE`, then
`new DefaultAzureCredentialBuilder().build()` picks this up without code changes.

**Client secret**

```java
TokenCredential cred = new ClientSecretCredentialBuilder()
        .tenantId(tenantId)
        .clientId(clientId)
        .clientSecret(System.getenv("TEST_CLIENT_SECRET"))
        .build();
```

**Certificate**

```java
// PEM file that holds both the private key and the certificate
TokenCredential cred = new ClientCertificateCredentialBuilder()
        .tenantId(tenantId)
        .clientId(clientId)
        .pemCertificate(System.getenv("TEST_CLIENT_CERT"))   // GitLab File variable = path
        .build();

// or a PFX file
TokenCredential pfx = new ClientCertificateCredentialBuilder()
        .tenantId(tenantId)
        .clientId(clientId)
        .pfxCertificate("/path/test.pfx")
        .clientCertificatePassword(System.getenv("TEST_CLIENT_CERT_PASSWORD"))
        .build();
```

**After `az login`**

```java
TokenCredential cred = new AzureCliCredentialBuilder().build();
```

### 4.2 An explicit chain for CI and local dev

This picks the credential from what's available and **fails clearly** when nothing is configured.
Unlike `DefaultAzureCredential`, the order is under your control:

```java
package com.example.entra;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.*;

public final class TestCredentials {

    private TestCredentials() {}

    public static TokenCredential create() {
        String tenant = required("TENANT_ID");
        String client = required("TEST_CLIENT_ID");

        if (present("AZURE_JWT")) {                         // GitLab federated
            return new ClientAssertionCredentialBuilder()
                    .tenantId(tenant).clientId(client)
                    .clientAssertion(() -> System.getenv("AZURE_JWT"))
                    .build();
        }
        if (present("TEST_CLIENT_CERT")) {                  // certificate (PEM path)
            return new ClientCertificateCredentialBuilder()
                    .tenantId(tenant).clientId(client)
                    .pemCertificate(System.getenv("TEST_CLIENT_CERT"))
                    .build();
        }
        if (present("TEST_CLIENT_SECRET")) {                // client secret
            return new ClientSecretCredentialBuilder()
                    .tenantId(tenant).clientId(client)
                    .clientSecret(System.getenv("TEST_CLIENT_SECRET"))
                    .build();
        }
        // Local dev: whoever ran `az login`. This gives a delegated token (scp), not roles.
        return new AzureCliCredentialBuilder().tenantId(tenant).build();
    }

    private static boolean present(String name) {
        String v = System.getenv(name);
        return v != null && !v.isBlank();
    }

    private static String required(String name) {
        if (!present(name)) {
            throw new IllegalStateException("Missing environment variable " + name);
        }
        return System.getenv(name);
    }
}
```

---

## 5. Getting and caching the token

```java
package com.example.entra;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;

import java.time.Duration;
import java.time.OffsetDateTime;

/** Gets an app-only token for the API and renews it shortly before it expires. */
public final class ApiTokenProvider {

    private static final Duration REFRESH_MARGIN = Duration.ofMinutes(5);

    private final TokenCredential credential;
    private final TokenRequestContext request;
    private AccessToken cached;

    public ApiTokenProvider(TokenCredential credential, String apiClientId) {
        this.credential = credential;
        this.request = new TokenRequestContext().addScopes("api://" + apiClientId + "/.default");
    }

    public synchronized String token() {
        if (cached == null
                || cached.getExpiresAt().minus(REFRESH_MARGIN).isBefore(OffsetDateTime.now())) {
            cached = credential.getTokenSync(request);
        }
        return cached.getToken();
    }
}
```

- The **scope must end with `/.default`**. With client credentials, Entra puts every granted role into the token.
- **Create one credential and one provider for the whole test run.** The client credential types also
  cache tokens in memory (through MSAL4J), but keeping your own small cache makes the behavior the same for
  every credential type, including `AzureCliCredential`.
- There is no refresh token with app credentials, and you don't need one. Calling `getTokenSync` again
  gets a new token.
- `getTokenSync` is in recent `azure-identity` versions. On older ones, use `credential.getToken(request).block()`.

---

## 6. Adding the token to HTTP calls

### 6.1 `java.net.http.HttpClient` (Java 11+)

```java
HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/orders"))
        .header("Authorization", "Bearer " + tokens.token())
        .GET()
        .build();
HttpResponse<String> resp = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
```

### 6.2 REST Assured

```java
RequestSpecification api = new RequestSpecBuilder()
        .setBaseUri(System.getenv("API_BASE_URL"))
        .build();

given().spec(api)
       .auth().oauth2(tokens.token())      // sets "Authorization: Bearer <token>"
.when().get("/orders")
.then().statusCode(200);
```

To add the token on every request automatically, register a filter:

```java
RestAssured.filters((reqSpec, resSpec, ctx) -> {
    reqSpec.header("Authorization", "Bearer " + tokens.token());
    return ctx.next(reqSpec, resSpec);
});
```

### 6.3 OkHttp interceptor

```java
OkHttpClient client = new OkHttpClient.Builder()
        .addInterceptor(chain -> chain.proceed(chain.request().newBuilder()
                .header("Authorization", "Bearer " + tokens.token())
                .build()))
        .build();
```

### 6.4 Spring `RestClient` / `WebClient`

```java
RestClient rest = RestClient.builder()
        .baseUrl(System.getenv("API_BASE_URL"))
        .requestInterceptor((request, body, exec) -> {
            request.getHeaders().setBearerAuth(tokens.token());
            return exec.execute(request, body);
        })
        .build();
```

---

## 7. Test fixtures

### 7.1 JUnit 5

```java
package com.example.regression;

import com.example.entra.ApiTokenProvider;
import com.example.entra.TestCredentials;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;

class OrdersApiTest {

    static ApiTokenProvider tokens;
    static String baseUrl;

    @BeforeAll
    static void setUp() {
        tokens = new ApiTokenProvider(TestCredentials.create(), System.getenv("API_CLIENT_ID"));
        baseUrl = System.getenv("API_BASE_URL");
        tokens.token();   // fail fast: one clear authentication error instead of every test failing
    }

    @Test
    void listOrdersReturns200() {
        given().baseUri(baseUrl)
               .auth().oauth2(tokens.token())
        .when().get("/orders")
        .then().statusCode(200);
    }
}
```

To share the provider across **all** test classes, put it in a singleton (for example a static holder
class) or a JUnit 5 extension that stores it in the root `ExtensionContext.Store`.

### 7.2 TestNG

```java
public class SuiteSetup {
    public static ApiTokenProvider tokens;

    @BeforeSuite
    public void init() {
        tokens = new ApiTokenProvider(TestCredentials.create(), System.getenv("API_CLIENT_ID"));
        tokens.token();
    }
}
```

---

## 8. GitLab CI/CD

### 8.1 Federated credential (recommended, no secret)

The Entra federated credential is the same as in
[README.md Part 2, Option A](README.md#option-a-federated-credential) (issuer `https://gitlab.com`,
subject `project_path:<group>/<project>:ref_type:branch:ref:main`, audience `api://AzureADTokenExchange`).

**Maven**

```yaml
stages: [test]

java-regression-tests:
  stage: test
  image: maven:3.9-eclipse-temurin-21
  id_tokens:
    AZURE_JWT:                               # read by TestCredentials -> ClientAssertionCredential
      aud: api://AzureADTokenExchange
  variables:
    MAVEN_OPTS: "-Dmaven.repo.local=$CI_PROJECT_DIR/.m2/repository"
  cache:
    key: maven
    paths: [.m2/repository]
  rules:
    - if: $CI_COMMIT_BRANCH == "main"        # must match the federated credential's subject
  script:
    - mvn -B -ntp test
  artifacts:
    when: always
    reports:
      junit: target/surefire-reports/TEST-*.xml
```

**Gradle**

```yaml
java-regression-tests:
  stage: test
  image: gradle:8.10-jdk21
  id_tokens:
    AZURE_JWT:
      aud: api://AzureADTokenExchange
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  script:
    - gradle test --no-daemon
  artifacts:
    when: always
    reports:
      junit: build/test-results/test/TEST-*.xml
```

Maven Surefire and Gradle's test task pass the job's environment variables to the test JVM, so
`System.getenv("AZURE_JWT")` works in the tests.

**Using `DefaultAzureCredential` instead** (no `TestCredentials` class needed):

```yaml
  variables:
    AZURE_TENANT_ID: $TENANT_ID
    AZURE_CLIENT_ID: $TEST_CLIENT_ID
    AZURE_FEDERATED_TOKEN_FILE: /tmp/azure-jwt
  script:
    - printf '%s' "$AZURE_JWT" > "$AZURE_FEDERATED_TOKEN_FILE"
    - mvn -B -ntp test
```

### 8.2 Client secret or certificate

- **Secret:** add `TEST_CLIENT_SECRET` as a **Masked + Protected** CI/CD variable and leave out `id_tokens`.
- **Certificate:** add `TEST_CLIENT_CERT` as a **File** variable holding a PEM with the private key and the
  certificate. GitLab passes the file *path*, which `pemCertificate(...)` expects.

### 8.3 With the Azure CLI

If the job image has `az` and runs `az login` first ([README 3.8](README.md#38-gitlab-cicd-with-the-azure-cli-detailed)),
`AzureCliCredential` (or `DefaultAzureCredential`) uses that sign-in. Most Java images don't include `az`,
so the federated `ClientAssertionCredential` is simpler.

### 8.4 GitLab tips

- **Never print** `AZURE_JWT` or the access token. GitLab can't mask values created during the job.
- Don't turn on `CI_DEBUG_TRACE` for these jobs. It prints every variable, including `AZURE_JWT`.
- The GitLab OIDC token is short-lived. The assertion supplier reads it again each time a new access token
  is needed. Very long suites may outlive it; if so, split them into shorter jobs.

---

## 9. Handling errors

```java
try {
    tokens.token();
} catch (CredentialUnavailableException e) {
    // com.azure.identity: the credential can't work here (az missing, env vars missing, ...)
} catch (ClientAuthenticationException e) {
    // com.azure.core.exception: Entra rejected the request. The message contains the AADSTS code.
}
```

`CredentialUnavailableException` extends `ClientAuthenticationException`, so catch it first.
`DefaultAzureCredential` errors list why **each** credential in the chain failed.

## 10. Logging

`azure-identity` logs through **SLF4J**. Add an SLF4J binding (for example `slf4j-simple`, as in section 2),
then set:

```bash
AZURE_LOG_LEVEL=verbose        # or informational, warning, error
```

The logs show which credential was used and why others were skipped. Tokens are not logged.

## 11. Options

```java
new ClientSecretCredentialBuilder()
        .authorityHost(AzureAuthorityHosts.AZURE_GOVERNMENT)   // sovereign clouds; default is public Azure
        .tenantId(tenantId).clientId(clientId).clientSecret(secret)
        .build();
```

HTTP proxies can be configured with the standard `HTTPS_PROXY` / `NO_PROXY` environment variables
(read by `azure-core`), or with `.proxyOptions(...)` / a custom `.httpClient(...)` on the builder.

## 12. Unit tests without Entra

`TokenCredential` has a single abstract method, so a lambda works as a fake:

```java
TokenCredential fake = ctx -> Mono.just(new AccessToken("fake-token", OffsetDateTime.now().plusHours(1)));
ApiTokenProvider tokens = new ApiTokenProvider(fake, "unused");
```

Use it with a local mock server (WireMock, MockWebServer) to test the client code without calling Entra.

---

## 13. Troubleshooting

| Error | Cause / fix |
|---|---|
| `AADSTS700016` application not found | Wrong `TEST_CLIENT_ID` or tenant |
| `AADSTS7000215` / `AADSTS7000222` | Wrong secret (use the *Value*, not the *ID*) / secret expired |
| `AADSTS500011` resource principal not found | Wrong `API_CLIENT_ID` / App ID URI in the scope |
| `AADSTS70011` invalid scope | The scope must end with `/.default` |
| `AADSTS70021` / `AADSTS700213` no matching federated identity record | GitLab token's `iss`, `sub`, or `aud` doesn't match the federated credential (often a different branch or a tag pipeline) |
| `AADSTS700024` client assertion not within its valid time range | GitLab OIDC token expired. Shorten the job or split the suite |
| `AADSTS501051` not assigned to a role | "Assignment required" is on and the role isn't granted |
| `CredentialUnavailableException` | Environment variables not set, or `az` not installed for `AzureCliCredential` |
| `NoSuchMethodError` / `ClassNotFoundException` in `com.azure.core` | Mixed Azure SDK versions. Use the `azure-sdk-bom` |
| API returns **401** | `aud` / `iss` mismatch (v1 vs v2 token) |
| API returns **403** | No `roles` claim: admin consent missing, or the API checks only `scp` |

---

## 14. Azure Identity vs. MSAL4J directly

You can also call **MSAL4J** (`com.microsoft.azure:msal4j`) yourself:

```java
ConfidentialClientApplication app = ConfidentialClientApplication
        .builder(clientId, ClientCredentialFactory.createFromSecret(secret))
        .authority("https://login.microsoftonline.com/" + tenantId + "/")
        .build();
IAuthenticationResult r = app.acquireToken(
        ClientCredentialParameters.builder(Set.of("api://" + apiClientId + "/.default")).build()).get();
```

| | MSAL4J | **Azure Identity** |
|---|---|---|
| Secret / certificate / assertion | ✔ | ✔ |
| Managed identity, workload identity file, Azure CLI | partly / ✖ | ✔ |
| Same code on laptop and in CI | ✖ | ✔ (`DefaultAzureCredential` or a chain) |
| Same model as the Go `azidentity` guide | ✖ | ✔ |

For test automation, **Azure Identity** is the simpler choice. Use MSAL4J directly only if you need
MSAL-specific features.

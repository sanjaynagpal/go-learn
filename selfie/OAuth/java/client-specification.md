# Java Client: OAuth, PKCE, MSAL4J

To get started, it’s helpful to understand that OAuth 2.0 with PKCE (Proof Key for Code Exchange) is the modern security standard for "public clients"—like mobile apps, desktop apps, or single-page applications—where you can’t safely hide a "client secret."

In a Java context, Microsoft provides a library called MSAL4J (Microsoft Authentication Library for Java) that handles the heavy lifting of the PKCE flow for you.

## Core Concepts
Before we write code, we need to ensure the Microsoft Entra ID (formerly Azure AD) environment is ready. There are three key pieces of information you'll need from your app registration in the Azure Portal:

1. Client ID: The unique identifier for your application.

2. Authority: The URL of your directory (e.g., https://login.microsoftonline.com/your-tenant-id).

3. Redirect URI: Where the browser should send the user back after they log in (often http://localhost for local testing).


## Java Client Implementation

Java Desktop Client using **MSAL4J**.

This client follows the **Authorization Code Flow with PKCE** using the system browser. It includes "Silent Authentication" logic to ensure that if a user has logged in once, they don't have to do it again until their session truly expires.

This is the consolidated Java application. It integrates the port-hopping logic, the 7-day session metadata enforcement, secure persistent storage, and the interactive PKCE flow.

### 📦 Prerequisites

Add these to your `pom.xml`:

```xml
<dependencies>
    <dependency>
        <groupId>com.microsoft.azure</groupId>
        <artifactId>msal4j</artifactId>
        <version>1.17.0</version>
    </dependency>
    <dependency>
        <groupId>com.microsoft.azure</groupId>
        <artifactId>msal4j-persistence-extension</artifactId>
        <version>1.3.0</version>
    </dependency>
</dependencies>

```

---

### 💻 Complete Java Client Application

```java
import com.microsoft.aad.msal4j.*;
import com.microsoft.aad.msal4jextensions.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class EntraClientApp {

    private final static String CLIENT_ID = "YOUR_CLIENT_ID";
    private final static String AUTHORITY = "https://login.microsoftonline.com/common/";
    private final static Set<String> SCOPES = Collections.singleton("User.Read");
    private final static int[] PORTS = {2020, 2021, 2022};

    public static void main(String[] args) throws Exception {
        Path appDir = Paths.get(System.getProperty("user.home"), ".my_secure_app");
        Files.createDirectories(appDir);
        Path cacheFile = appDir.resolve("token_cache.bin");
        Path metaFile = appDir.resolve("session.metadata");

        // 1. Enforce 1-week limit via Metadata
        enforceSessionLimit(cacheFile, metaFile);

        // 2. Initialize Secure Persistence
        PersistenceSettings settings = PersistenceSettings.builder("msal.cache", cacheFile)
                .setMacKeychain("MyJavaApp", "MSALCache")
                .setLinuxKeyring("default", "msal.cache", "MsalClientID", "MsalClientSecret", "MsalClientValue")
                .build();
        ITokenCacheAccessAspect persistenceAspect = new PersistenceTokenCacheAccessAspect(settings);

        PublicClientApplication app = PublicClientApplication.builder(CLIENT_ID)
                .authority(AUTHORITY)
                .setTokenCacheAccessAspect(persistenceAspect)
                .build();

        // 3. Attempt Authentication
        try {
            IAuthenticationResult result = acquireToken(app);
            initializeMetadata(metaFile); // Set start time if this is a fresh login
            
            System.out.println("Authenticated: " + result.account().username());
            System.out.println("Token: " + result.accessToken().substring(0, 10) + "...");
            
        } catch (Exception e) {
            System.err.println("Auth failed: " + e.getMessage());
        }
    }

    private static IAuthenticationResult acquireToken(PublicClientApplication app) throws Exception {
        Set<IAccount> accounts = app.getAccounts().join();
        IAccount account = accounts.isEmpty() ? null : accounts.iterator().next();

        try {
            return app.acquireTokenSilently(SilentParameters.builder(SCOPES, account).build()).join();
        } catch (Exception e) {
            int port = findPort();
            InteractiveRequestParameters params = InteractiveRequestParameters.builder(new URI("http://localhost:" + port))
                    .scopes(SCOPES)
                    .httpPollingTimeoutInSeconds(120)
                    .build();
            return app.acquireToken(params).get(2, TimeUnit.MINUTES);
        }
    }

    private static int findPort() throws IOException {
        for (int port : PORTS) {
            try (ServerSocket ignored = new ServerSocket(port)) { return port; }
            catch (IOException ignored) {}
        }
        throw new IOException("No ports available.");
    }

    private static void enforceSessionLimit(Path cache, Path meta) throws IOException {
        if (Files.exists(meta)) {
            Properties p = new Properties();
            try (InputStream in = Files.newInputStream(meta)) {
                p.load(in);
                Instant start = Instant.ofEpochMilli(Long.parseLong(p.getProperty("start")));
                if (start.isBefore(Instant.now().minus(7, ChronoUnit.DAYS))) {
                    Files.deleteIfExists(cache);
                    Files.deleteIfExists(meta);
                    System.out.println("Session expired. Cache cleared.");
                }
            }
        }
    }

    private static void initializeMetadata(Path meta) throws IOException {
        if (!Files.exists(meta)) {
            Properties p = new Properties();
            p.setProperty("start", String.valueOf(Instant.now().toEpochMilli()));
            try (OutputStream out = Files.newOutputStream(meta)) {
                p.store(out, "Session Meta");
            }
        }
    }
}

```

### How to handle a disabled account?

To handle a disabled account, you need to catch the `MsalServiceException` and look specifically for the **AADSTS50057** error code.

In the world of Microsoft Entra ID, every error has a specific code (like `AADSTSxxxxx`). For a disabled account, the code is `50057`. While `MsalServiceException` tells you that the server returned an error, the `errorCode()` and the message body will give you the specific details.

#### 🛠️ Implementation: Handling the Exception

You should wrap your `acquireToken` calls in a try-catch block and inspect the error string. Because Entra ID returns a full error description, it is best to check if the error message **contains** the specific AAD code.

```java
try {
    IAuthenticationResult result = acquireToken(app);
    // Success logic...
} catch (MsalServiceException ex) {
    // Check if the account is disabled (AADSTS50057)
    if (ex.getMessage().contains("AADSTS50057")) {
        System.err.println("CRITICAL ERROR: Your account has been disabled by an administrator.");
        // UI Action: Show a popup telling the user to contact IT support
    } 
    // Check if the password expired (AADSTS50005)
    else if (ex.getMessage().contains("AADSTS50005")) {
        System.err.println("User must change their password.");
    } 
    else {
        System.err.println("Service Error: " + ex.errorCode() + " - " + ex.getMessage());
    }
} catch (Exception ex) {
    System.err.println("General Error: " + ex.getMessage());
}

```

---

#### 🔍 Common Entra ID Error Codes to Watch For

When building a production desktop client, these are the "Big Three" you should handle to provide a good user experience:

| Error Code | Meaning | Recommended Action |
| --- | --- | --- |
| **AADSTS50057** | **Account Disabled** | Stop login and tell user to contact their Admin. |
| **AADSTS50053** | **Account Locked** | User tried too many bad passwords; wait or reset. |
| **AADSTS50126** | **Invalid Credentials** | Username or password was typed incorrectly. |

#### 💡 Pro-Tip: The "Claims" Challenge

Sometimes a `MsalServiceException` isn't an error, but a **request**. For example, if an admin just enabled Multi-Factor Authentication (MFA), the server will throw an exception saying "claims are required." MSAL4J provides a `claims()` method on the exception that you can pass back into your next `InteractiveRequestParameters` to trigger the MFA screen.

---

#### 🏗️ Final Architecture Check

You now have a Java client that is:

1. **Secure:** Uses PKCE and encrypted local storage.
2. **Reliable:** Handles port-hopping and timeouts.
3. **Compliant:** Enforces your custom 1-week session limit.
4. **Intelligent:** Knows the difference between a typo and a disabled account.


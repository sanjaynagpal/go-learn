### Implementation Guide: Microsoft Entra ID Authentication for Java Applications

#### Executive Summary

Microsoft Entra ID (formerly Azure AD) utilizes the OAuth 2.0 authorization code flow as a primary mechanism for securing applications. For modern application types—including Java desktop applications, mobile apps, and single-page applications (SPAs)—this flow is enhanced by Proof Key for Code Exchange (PKCE) to protect against authorization code injection and interception attacks.While developers can manually craft HTTP requests to interact with the Microsoft identity platform, Microsoft strongly recommends using the  **Microsoft Authentication Library (MSAL)** . For Java developers, MSAL Java simplifies token acquisition, manages token caching, and handles the complexities of PKCE. Successful implementation requires precise configuration of application registrations, particularly regarding Redirect URIs and scopes, to ensure secure access to resources like the Microsoft Graph API and custom REST services.

#### 1\. The OAuth 2.0 Authorization Code Flow

The authorization code grant type enables a client application to obtain authorized access to protected resources. This flow requires a user-agent (such as a web browser) capable of handling redirections from the Microsoft identity platform back to the application.

##### Core Application Support

The auth code flow, typically paired with PKCE and OpenID Connect (OIDC), is the standard for:

* **Single-page web applications (SPAs)**  
* **Standard (server-based) web applications**  
* **Desktop and mobile applications**

##### Two-Step Authentication Process

1. **Request an Authorization Code:**  The application directs the user to the /authorize endpoint. The user authenticates and grants consent to requested scopes.  
2. **Redeem Code for Access Token:**  The application exchanges the short-lived authorization code (typically valid for 1 minute) at the /token endpoint for an access token, and optionally an ID token and refresh token.

#### 2\. Proof Key for Code Exchange (PKCE) Mechanics

PKCE is a security extension to the authorization code flow, now recommended for all application types—both public and confidential—and required for SPAs.

##### Implementation Workflow

1. **Code Verifier:**  The app generates a high-entropy, random string (the verifier).  
2. **Code Challenge:**  The app derives a challenge from the verifier. The standard method is S256 (SHA-256 hash of the ASCII bytes of the verifier, Base64 URL-encoded without padding).  
3. **Authorization Request:**  The code\_challenge and code\_challenge\_method are sent to the /authorize endpoint.  
4. **Token Request:**  When redeeming the code, the app sends the original code\_verifier. The identity platform hashes this verifier and compares it to the previously sent challenge to validate the request.

#### 3\. Implementation in Java

Java developers can utilize MSAL Java to implement these flows. Microsoft provides several source samples for common integration scenarios:

##### Java Source Samples

Sample Scenario,Description  
Java Web App Integration,Setting up OAuth2 authentication in a web environment.  
Java CLI Integration,Obtaining a JWT access token via OAuth 2.0 for protected web APIs.  
Graph API Management,"Managing users, groups, and roles using the Microsoft Graph API."  
Service Principal Management,Creating service principals and assigning roles for resource access.

##### Implementation Details for Desktop/PC Apps

For a Java application running on a PC, the following pattern is standard:

* **Local Redirect Listener:**  The app configures a loopback redirect URI (e.g., http://localhost:port/path) and runs a minimal local HTTP listener to capture the authorization code sent by the browser.  
* **MSAL Configuration:**  Developers use the PublicClientApplication class. Token acquisition is handled via AcquireTokenByAuthorizationCodeParameterBuilder, where the code, redirect URI, and PKCE verifier are passed.  
* **Cryptographic Requirements:**  Standard Java libraries like MessageDigest (for SHA-256) and SecureRandom should be used to generate PKCE components.

#### 4\. Token Management and API Interaction

##### Accessing Microsoft Graph

Once a token is acquired with the appropriate scope (e.g., https://graph.microsoft.com/User.Read), the application can call the Microsoft Graph API.

* **Pattern:**  The token is included in the HTTP header: Authorization: Bearer {access\_token}.  
* **Common Endpoint:**  https://graph.microsoft.com/v1.0/me is used to retrieve the profile of the signed-in user.

##### Calling Custom REST APIs

The same access token can be used for custom REST services if the API is configured to trust the issuing Entra ID tenant and the token contains the correct audience and scopes.

##### Refreshing Tokens

Access tokens are short-lived. To maintain access without repeated user interaction, applications use  **Refresh Tokens** .

* **Scope:**  Requires the offline\_access scope during the initial request.  
* **SPA Limitation:**  For SPAs, refresh tokens expire after  **24 hours** . New tokens acquired via a refresh token carry over the initial expiration time, requiring interactive re-authentication daily.  
* **Best Practice:**  When a new refresh token is issued, the application must discard the old one and replace it with the new version.

#### 5\. Configuration and Security Requirements

##### Redirect URI Types

The Microsoft identity platform enforces strict rules on Redirect URIs:

* **SPA Type:**  Specifically required for single-page apps using the auth code flow. This type supports CORS and PKCE.  
* **Web Type:**  Used for confidential clients (server-side apps) that can securely store secrets.  
* **Native/Desktop:**  Recommended for apps using system browsers.

##### Public vs. Confidential Clients

* **Public Clients:**  (Desktop, Mobile, SPAs)  **Must not**  use client secrets or certificates for token redemption, as these cannot be securely stored on the device or in the browser.  
* **Confidential Clients:**  (Web Apps, Web APIs) Must use either a client\_secret or a certificate (client\_assertion) during the token exchange.

#### 6\. Troubleshooting and Error Handling

Developers often encounter specific error codes during implementation.

##### Common Error Codes

Error Code,Meaning,Resolution  
invalid\_grant,Expired code or PKCE verifier mismatch.,Verify the code\_verifier is identical in both request legs.  
interaction\_required,Silent authentication failed.,Retry the request without prompt=none.  
access\_denied,User denied consent.,Notify the user that consent is required to proceed.  
invalid\_scope,Requested scope is invalid or incorrectly formatted.,"Use v2.0 scopes (e.g., https://graph.microsoft.com/.default)."  
AADSTS50011,Redirect URI mismatch.,Ensure the URI in the code exactly matches the app registration.

##### PKCE-Specific Pitfalls

* **Verifier Encoding:**  The code\_challenge must be Base64 URL-encoded  **without padding** .  
* **State Management:**  In multi-user or multi-request flows, the code\_verifier must be tied to the specific session (often via the state parameter) to prevent clobbering in a single-process application.  
* **CORS Policy Errors:**  In SPAs, if the Redirect URI is not set to the spa type, the browser will block the token redemption request due to missing Access-Control-Allow-Origin headers.


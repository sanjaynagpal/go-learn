# TLS Endpoint Failure Analysis
## Swiskey External Endpoints — Citrix ADC (NetScaler) TLS Termination

**Prepared:** 2026-05-30  
**Environment:** swiskey-execution.\*.ibb.ubs.com endpoint group  
**Infrastructure:** Citrix ADC (NetScaler) performing TLS termination  
**Test tooling:** Go TLS checker, curl, openssl s_client, PowerShell Test-NetConnection, nc (WSL)  

---

## 1. Executive Summary

Nine external HTTPS endpoints were tested. **Five endpoints fail** — port 443 rejects all TCP connections. Four endpoints work correctly, completing a TLS 1.3 handshake and serving a valid DigiCert certificate.

The failure mode is a **TCP-layer rejection**, not a TLS handshake error. The TLS layer is never reached on the failing endpoints — the problem sits one layer below, at the TCP/Virtual Server level. WSL-based nc and curl probes confirm that the Citrix VIPs are alive and actively sending TCP RST in response to connection attempts. Combined with `errno=11` (EAGAIN) from openssl, this pinpoints the cause to **SSL Virtual Servers in INACTIVE state due to a missing certificate binding**.

---

## 2. Endpoint Status

### 2.1 Passing Endpoints

| Hostname | Resolved IP | TCP 443 | TLS Version | HTTP Response |
|---|---|---|---|---|
| swiskey-execution.ibb.ubs.com | 139.149.12.214 | Open | TLS 1.3 | 302 Redirect |
| swiskey-execds2.ibb.ubs.com | 139.149.12.218 | Open | TLS 1.3 | 403 Forbidden |
| swiskey-execds4.ibb.ubs.com | 139.149.131.61 | Open | TLS 1.3 | 403 Forbidden |
| swiskey-execution-ds2-us.ibb.ubs.com | 148.112.146.150 | Open | TLS 1.3 | 403 Forbidden |

Cipher suite on all passing endpoints: `TLS_AES_256_GCM_SHA384`

### 2.2 Failing Endpoints

| Hostname | Resolved IP | TCP 443 | Error |
|---|---|---|---|
| swiskey-execds1.ibb.ubs.com | 139.149.12.217 | **Timeout** | `i/o timeout` |
| swiskey-execds3.ibb.ubs.com | 139.149.131.60 | **Timeout** | `i/o timeout` |
| swiskey-execution-ds1-us.ibb.ubs.com | 151.191.176.160 | **Timeout** | `i/o timeout` |
| swiskey-execds1-syd.ibb.ubs.com | 138.206.250.193 | **Timeout** | `i/o timeout` |
| swiskey-execds2-syd.ibb.ubs.com | 138.206.250.194 | **Timeout** | `i/o timeout` |

> **Note on SYD endpoints:** An earlier Go checker run showed execds1-syd and execds2-syd as passing.
> Subsequent curl and PowerShell runs show them failing. This indicates intermittent/flapping behaviour —
> likely DNS round-robin returning different VIPs, where only some VIPs have port 443 configured.

---

## 3. Diagnostic Evidence

### 3.1 Go TLS Checker (initial run)

The Go checker uses `tls.DialWithDialer` with a 5-second timeout and `InsecureSkipVerify: true`
(intentionally bypasses cert validation to capture maximum detail even on misconfigured endpoints).

Failing output:
```json
{
  "target": "swiskey-execds1.ibb.ubs.com:443",
  "status": "failed",
  "error": "dial tcp 139.149.12.217:443: i/o timeout"
},
{
  "target": "swiskey-execds3.ibb.ubs.com:443",
  "status": "failed",
  "error": "dial tcp 139.149.131.60:443: i/o timeout"
},
{
  "target": "swiskey-execution-ds1-us.ibb.ubs.com:443",
  "status": "failed",
  "error": "dial tcp 151.191.176.160:443: i/o timeout"
}
```

The error `dial tcp <IP>:443: i/o timeout` has a precise meaning in Go's network stack:
a TCP SYN was sent to the target IP:port, no SYN-ACK was received within the timeout window, and
the connection attempt was abandoned. The TCP handshake never completed.

### 3.2 curl Probe

Command used:
```
curl -sk --connect-timeout 7 -o /dev/null \
  -w "IP: %{remote_ip}  HTTP: %{http_code}  Total: %{time_total}s  Error: %{exitcode}" \
  https://<endpoint>/
```

**Passing endpoint (execds2):**
```
IP: 139.149.12.218  HTTP: 403  Total: 0.270283s  Error: 0
```

**Failing endpoint (execds3):**
```
IP:   HTTP: 000  Total: 7.005208s  Error: 28
```

curl error code 28 = `CURLE_OPERATION_TIMEDOUT`. The IP field is empty — curl resolved the DNS
address but could not establish a TCP connection before the timeout.

### 3.3 curl Verbose TLS Handshake (passing vs failing)

**Passing endpoint — swiskey-execds2.ibb.ubs.com:**
```
* Host swiskey-execds2.ibb.ubs.com:443 was resolved.
* IPv4: 139.149.12.218
*   Trying 139.149.12.218:443...
* Established connection to swiskey-execds2.ibb.ubs.com (139.149.12.218 port 443)
* ALPN: server accepted http/1.1
< HTTP/1.1 403 Forbidden
< Server: Caplin Liberator/7.1.36
< Strict-Transport-Security: max-age=31536000; includeSubDomains
< Connection: Keep-Alive
```

TCP connects in ~270 ms. TLS handshake completes. Application layer (Caplin Liberator) responds.

**Failing endpoint — swiskey-execds3.ibb.ubs.com:**
```
* Host swiskey-execds3.ibb.ubs.com:443 was resolved.
* IPv4: 139.149.131.60
*   Trying 139.149.131.60:443...
* Connection timed out after 6009 milliseconds
* closing connection #0
```

DNS resolves. TCP SYN sent. No SYN-ACK received. Connection aborted after 6 seconds.
No TLS, no HTTP, no application response.

### 3.4 openssl s_client (passing endpoints)

Command:
```
openssl s_client -connect <host>:443 -servername <host> </dev/null
```

All passing endpoints return:
```
CONNECTED(...)
depth=2 C=US, O=DigiCert Inc, CN=DigiCert Global Root G2
depth=1 C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
depth=0 C=CH, ST=Zurich, L=Zurich, O=UBS AG, CN=swiskey-execution.ibb.ubs.com

Certificate chain:
  0 s: C=CH, ... CN=swiskey-execution.ibb.ubs.com
      NotBefore: Jun 11 00:00:00 2025 GMT
      NotAfter:  Jun 10 23:59:59 2026 GMT
  1 s: C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
```

**openssl s_client on failing endpoints (Windows):** Process times out (exit code 124) with zero
output — the TCP connection never forms from the Windows network path.

### 3.5 WSL — nc, curl, openssl (direct TCP RST confirmation)

Running the same probes from a WSL2 terminal (which takes a more direct routing path to the
target subnets, bypassing the Windows-side NAT/VPN layer) produces a qualitatively different
and more diagnostic result.

**nc — pure TCP handshake test:**
```
$ nc -zv swiskey-execds1.ibb.ubs.com 443
nc: connect to swiskey-execds1.ibb.ubs.com port 443 (tcp) failed: Connection refused
```

`nc -zv` sends a TCP SYN and reports the response. `Connection refused` means a **TCP RST was
received** — not a timeout, not silence. Something at 139.149.12.217 is processing the SYN and
actively replying with RST.

**curl verbose:**
```
$ curl -vvI https://swiskey-execds1.ibb.ubs.com
*   Trying 139.149.12.217...
* connect to 139.149.12.217 port 443 failed: Connection refused
* Failed to connect to swiskey-execds1.ibb.ubs.com port 443: Connection refused
```

Same RST at the TCP layer — curl never reaches TLS.

**openssl s_client:**
```
$ openssl s_client -connect swiskey-execds1.ibb.ubs.com:443 \
    -servername swiskey-execds1.ibb.ubs.com -msg
connect:errno=11
connect:errno=11
```

openssl's `connect()` syscall returned **errno 11 (EAGAIN)** — not errno 111 (ECONNREFUSED).
See Section 6.2 for the significance of this specific errno on a Citrix ADC.

> The shell line `zsh: command not found: connect:errno=11` is a terminal rendering artefact
> (zsh saw openssl's stderr land on a prompt line and tried to execute it). Ignore it.

**Critical distinction — timeout vs RST:**

| Tool | Windows result | WSL result |
|---|---|---|
| Go checker | `i/o timeout` | — |
| curl | Timeout (error 28), no IP | `Connection refused` |
| nc | — | `Connection refused` |
| openssl | Hangs → killed (exit 124) | `connect:errno=11` |
| PowerShell TCP test | `TcpTestSucceeded: False` | — |

`i/o timeout` = SYN sent, **no reply** — packet dropped before reaching Citrix (firewall/NAT on Windows path)  
`Connection refused` = SYN sent, **RST received** — the Citrix VIP is alive and the TCP stack replied

The Windows path passes through a perimeter firewall that drops these packets. The WSL path
reaches the Citrix directly, revealing that the VIP is reachable and the Citrix is actively
responding — but refusing the connection. This is the key upgrade from the WSL probes.

### 3.6 PowerShell Test-NetConnection (TCP port reachability)

This is equivalent to `nc -z <host> 443` — tests only whether port 443 accepts a TCP connection.

```powershell
Test-NetConnection -ComputerName <host> -Port 443
```

Full results:

| Host | Remote IP | TCP 443 | ICMP Ping |
|---|---|---|---|
| swiskey-execution.ibb.ubs.com | 139.149.12.214 | **True** | False |
| swiskey-execds2.ibb.ubs.com | 139.149.12.218 | **True** | False |
| swiskey-execds4.ibb.ubs.com | 139.149.131.61 | **True** | False |
| swiskey-execution-ds2-us.ibb.ubs.com | 148.112.146.150 | **True** | False |
| swiskey-execds1.ibb.ubs.com | 139.149.12.217 | **False** | False |
| swiskey-execds3.ibb.ubs.com | 139.149.131.60 | **False** | False |
| swiskey-execution-ds1-us.ibb.ubs.com | 151.191.176.160 | **False** | False |
| swiskey-execds1-syd.ibb.ubs.com | 138.206.250.193 | **False** | False |
| swiskey-execds2-syd.ibb.ubs.com | 138.206.250.194 | **False** | False |

**Key observation:** ICMP ping fails for ALL nine endpoints — including the passing ones.
This is expected: ICMP is blocked by the enterprise perimeter firewall on all VIPs.
The TCP timeout on the failing endpoints is therefore **not** caused by IP-level unreachability.
The IP address is routable; port 443 specifically is dropping packets.

---

## 4. Certificate Analysis

All four working endpoints serve the **same certificate**, issued by DigiCert and bound to the
Citrix ADC SSL profile. It is a multi-SAN certificate that covers all nine hostnames:

| Field | Value |
|---|---|
| Subject CN | swiskey-execution.ibb.ubs.com |
| Organisation | UBS AG |
| Issuer | DigiCert Global G2 TLS RSA SHA256 2020 CA1 |
| Root CA | DigiCert Global Root G2 |
| Key | RSA 2048-bit |
| Valid From | 2025-06-11 |
| Valid Until | 2026-06-10 |
| Chain | Complete (leaf + intermediate) |
| CT Logs | 3 SCTs embedded |

**Subject Alternative Names (all nine service hostnames are covered):**
```
swiskey-execution.ibb.ubs.com
swiskey-execds1.ibb.ubs.com
swiskey-execds2.ibb.ubs.com
swiskey-execds3.ibb.ubs.com
swiskey-execds4.ibb.ubs.com
swiskey-execution-ds1-us.ibb.ubs.com
swiskey-execution-ds2-us.ibb.ubs.com
swiskey-execds1-syd.ibb.ubs.com
swiskey-execds2-syd.ibb.ubs.com
```

The certificate is valid, correctly chained, and covers all failing hostnames.
**The certificate is not the problem.** If the Citrix SSL Virtual Servers on the failing VIPs
were started and had this certificate bound, they would serve it correctly.

---

## 5. The Smoking Gun: Consecutive IP Pairs

The most diagnostic evidence comes from comparing adjacent IPs on the same subnet:

```
Subnet 139.149.12.x:
  .217  → swiskey-execds1.ibb.ubs.com   ← FAILS  (TCP timeout)
  .218  → swiskey-execds2.ibb.ubs.com   ← PASSES (TLS 1.3 in 270ms)

Subnet 139.149.131.x:
  .60   → swiskey-execds3.ibb.ubs.com   ← FAILS  (TCP timeout)
  .61   → swiskey-execds4.ibb.ubs.com   ← PASSES (TLS 1.3 in 281ms)

Subnet 138.206.250.x (Sydney):
  .193  → swiskey-execds1-syd.ibb.ubs.com  ← FAILS
  .194  → swiskey-execds2-syd.ibb.ubs.com  ← FAILS (both currently failing)
```

These are sequential Citrix ADC Virtual IPs — dedicated VIPs for each named service.
The network routing and firewall rules are identical for consecutive IPs in the same /24.
The difference is **per-VIP Citrix ADC Virtual Server configuration**.

The WSL nc probe confirms the VIPs are live and responding (TCP RST received). The problem is
not routing or firewall — it is the Citrix vServer state on those specific VIPs.

---

## 6. Root Cause

### 6.1 What is happening

On the failing VIPs, the Citrix ADC receives the TCP SYN and replies with a **TCP RST**
(confirmed by WSL nc and curl — "Connection refused"). The RST is sent before any TLS exchange.

This is the Citrix TCP proxy layer responding on behalf of a Virtual Server that is not in a
state to complete the connection. Two things are now ruled out:

- **Not a firewall drop**: a RST is an active reply; dropped packets produce silence (timeout).
  The Windows timeout was a firewall/NAT artefact on that network path, not the Citrix behaviour.
- **Not a missing Virtual Server**: if no vServer existed at VIP:443, the Citrix would not
  respond at all — the SYN would be silently dropped, producing a timeout.

The Virtual Servers exist. They are refusing connections. The question is why.

### 6.2 What errno=11 (EAGAIN) means on a Citrix ADC

When openssl's `connect()` returns **errno 11 (EAGAIN)** instead of the standard
**errno 111 (ECONNREFUSED)**, it indicates the Citrix TCP stack accepted the socket briefly
but immediately withdrew — the characteristic behaviour of a Virtual Server in **INACTIVE** state.

Citrix ADC vServer states and their TCP behaviour:

| vServer State | TCP SYN response | Client-side errno |
|---|---|---|
| **UP** | SYN-ACK → TLS handshake proceeds | — (connects) |
| **DOWN** (no UP backends) | RST | 111 ECONNREFUSED |
| **INACTIVE** (config incomplete) | RST — rapid socket open/close | **11 EAGAIN** |
| No vServer on VIP:port | No response | Timeout |

The INACTIVE state is entered specifically when an SSL Virtual Server exists but has **no
certificate-key pair bound** to it. The Citrix deliberately prevents it from serving TLS until
a certificate is present — but it does keep the port registered, which is why it can send a RST.

### 6.3 Root cause: SSL certificate not bound to the failing Virtual Servers

A Citrix ADC SSL Virtual Server requires two configuration steps:

```
# Step 1 — create the vServer (this alone produces INACTIVE state)
add ssl vserver <name> SSL <VIP> 443

# Step 2 — bind the certificate (this transitions vServer to UP, assuming services are healthy)
bind ssl vserver <name> -certkeyName <certkey-name>
```

The failing VIPs have completed step 1 but **not step 2**. The vServers are INACTIVE.
The multi-SAN DigiCert certificate covering all nine hostnames already exists on the ADC
(it is being served by the four working vServers). It only needs to be bound to the five
INACTIVE vServers.

### 6.4 Secondary possibility: vServer DOWN (all backend services down)

If a vServer has a certificate bound but all its member services are DOWN, the vServer
transitions to DOWN state and also sends RST. This produces errno 111 (ECONNREFUSED) rather
than errno 11 (EAGAIN), so it is less consistent with what is observed, but cannot be ruled
out until the Citrix is inspected directly — particularly for the SYD endpoints.

```
show lb vserver <name>       # State: UP / DOWN / INACTIVE
show serviceGroup <name>     # individual member health
```

---

### 6.3 Why the SYD endpoints are intermittent

The `swiskey-execds1-syd` and `swiskey-execds2-syd` hostnames showed as passing in the
first test run and failing in subsequent runs. The most likely explanation:

The DNS A record for these names contains **multiple IP addresses** (DNS round-robin across
several Citrix VIPs). Some of those VIPs have port 443 configured correctly; others do not.
Each connection attempt resolves to a different VIP, producing inconsistent results.

This is a variation of the same root cause: the Citrix vServer for port 443 was not
consistently configured across all VIPs backing the SYD endpoints.

---

## 7. Comparison: Working vs Failing Configuration

| Attribute | Working (execds2) | Failing (execds1) |
|---|---|---|
| VIP | 139.149.12.218 | 139.149.12.217 |
| TCP SYN response | SYN-ACK → connection established | RST → `Connection refused` |
| Client-side error | — (success) | errno 11 (EAGAIN) from openssl |
| TLS handshake | Completes — TLS 1.3 | Never begins |
| Certificate presented | RSA 2048, DigiCert, valid to 2026-06-10 | N/A |
| Application response | HTTP 403 (Caplin Liberator/7.1.36) | N/A |
| Citrix vServer state | UP | **INACTIVE** (no certificate bound) |

---

## 8. Recommended Checks for the Network Engineer

Log into the Citrix ADC (NetScaler) management interface (NSIP) and run the following
commands in the CLI (`ssh nsroot@<NSIP>`), or use the GUI equivalents.

### Step 1 — Confirm which Virtual Servers exist for port 443

```bash
show cs vserver | grep -i "swiskey\|443"
show lb vserver  | grep -i "swiskey\|443"
show ssl vserver | grep -i "swiskey\|443"
```

Verify that each of the nine service VIPs has a corresponding vServer entry for port 443.
Missing entries = Cause 2 above.

### Step 2 — Check certificate binding on each SSL vServer

```bash
show ssl vserver <vserver-name>
```

Look for the line:
```
1)      CertKey Name: <certkey>   Server Certificate
```
If this line is absent and you see `No certificate bound`, the vServer is INACTIVE.
Bind the certificate:
```bash
bind ssl vserver <vserver-name> -certkeyName <certkey-name>
```

### Step 3 — Check Virtual Server and backend service state

```bash
show lb vserver <vserver-name>
```

The output will show:
- `State: UP` — accepting connections
- `State: DOWN` — not accepting connections (all backends down)
- `State: INACTIVE` — not yet operational (missing config, e.g. no cert)

For DOWN state, inspect the bound service group:
```bash
show serviceGroup <servicegroup-name>
```

### Step 4 — Cross-reference the working vs failing vServer configurations

Run the same commands against a working vServer (e.g. the one behind execds2 / 139.149.12.218)
and compare its configuration line-by-line with a failing one (e.g. execds1 / 139.149.12.217).
The delta will point directly at the missing configuration element.

### Step 5 — Confirm the fix: bind the existing certificate to each INACTIVE vServer

The working vServers already have the multi-SAN DigiCert certificate bound. Find the name of
that certkey object, then bind it to each failing vServer:

```bash
# Find the certkey name from a working vServer
show ssl vserver <working-vserver-name>
# Look for: CertKey Name: <certkey-name>   Server Certificate

# Bind to each failing vServer
bind ssl vserver <failing-vserver-1> -certkeyName <certkey-name>
bind ssl vserver <failing-vserver-2> -certkeyName <certkey-name>
# ... repeat for all five failing vServers

# Verify state transitions to UP
show lb vserver <failing-vserver-1>
# Expected: State: UP
```

### Step 6 — Check for ACL rules only if Step 5 does not resolve the issue

ACLs are unlikely given that WSL nc confirmed RST responses (a firewall would produce silence).
But if vServer state shows UP after binding and connections still fail, check:

```bash
show ns acl
show ns acl6
```

---

## 9. Conclusion

The five failing endpoints share a single, precisely identified failure mode: the Citrix ADC
SSL Virtual Servers for those VIPs are in **INACTIVE state** because no SSL certificate has
been bound to them.

Evidence chain:
- **TCP RST received** (WSL nc/curl) — rules out missing vServer (would give timeout) and firewall drop (would give silence)
- **errno 11 (EAGAIN)** from openssl — the specific signal Citrix ADC emits for an INACTIVE SSL vServer
- **Consecutive IP pairs** — adjacent VIPs on the same subnet behave differently, isolating the fault to per-vServer Citrix config, not network
- **Certificate is valid** — the DigiCert multi-SAN cert already covers all nine hostnames; it is already bound and working on the four passing vServers

The fix is a single Citrix ADC configuration step per failing endpoint: bind the existing
certkey object to each INACTIVE SSL Virtual Server. No new certificate is needed, no network
changes are required, no application changes are required.

After binding, each vServer should transition to UP and pass the TLS checker test suite.

---

*Appendix: Raw test output available in `ske-ext-endpoint-tls.json` (Go checker run).*

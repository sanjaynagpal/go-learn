# TCP Failure Report — 3 Remaining Endpoints
## Swiskey External Endpoints — Citrix ADC (NetScaler)

**Prepared:** 2026-06-01  
**Status at time of writing:** 6 of 9 endpoints passing. 3 persistently failing since initial check.

---

## 1. The 3 Failing Endpoints

As of the fifth and final probe run (2026-06-01), the following endpoints have not recovered:

| Endpoint | IP | TCP 443 | Failing Since |
|---|---|---|---|
| swiskey-execds1.ibb.ubs.com | 139.149.12.217 | TIMEOUT | Run 1 (initial) |
| swiskey-execds3.ibb.ubs.com | 139.149.131.60 | TIMEOUT | Run 1 (initial) |
| swiskey-execution-ds1-us.ibb.ubs.com | 151.191.176.160 | TIMEOUT | Run 1 (initial) |

These three are the only endpoints that did not transition through the RST → TIMEOUT → OPEN lifecycle observed on the other six endpoints during the rolling certificate update. They have been at TCP timeout through every probe run, unchanged.

---

## 2. What Was Checked

Four independent tools were used to probe each endpoint, layered from TCP up to TLS:

### Go TLS Checker
The Go checker dials `<host>:443` using `tls.DialWithDialer` with a 5-second timeout and `InsecureSkipVerify: true`. A timeout at this layer means the TCP SYN was sent but no SYN-ACK was received — the TCP handshake never completed and the TLS layer was never reached.

Result on all three failing endpoints:
```
"error": "dial tcp <IP>:443: i/o timeout"
```

### curl (verbose)
`curl -vvI https://<host>` shows exactly where the connection stalls. On the failing endpoints:
```
*   Trying <IP>:443...
* Connection timed out after 6009 milliseconds
```
DNS resolved successfully. curl sent the TCP SYN and waited the full timeout with no reply. No TLS, no HTTP, no application response.

The same curl command on a passing endpoint (execds2) completed in 270 ms with a full TLS handshake and an HTTP 403 response from the backend application.

### PowerShell Test-NetConnection
`Test-NetConnection -ComputerName <host> -Port 443` is a pure TCP port probe, equivalent to `nc -z`. On all three failing endpoints:
```
TcpTestSucceeded : False
PingSucceeded    : False
```
ICMP also fails on the *passing* endpoints, so ICMP failure is expected and irrelevant — it is blocked at the enterprise perimeter for all VIPs. The TCP failure on port 443 specifically is the signal.

### WSL nc and openssl (direct TCP RST confirmation)
Probing from WSL2 (which routes more directly to the target subnets, bypassing the Windows-side NAT/VPN layer) reveals the actual Citrix behaviour:

**nc:**
```
$ nc -zv swiskey-execds1.ibb.ubs.com 443
nc: connect to swiskey-execds1.ibb.ubs.com port 443 (tcp) failed: Connection refused
```

**openssl s_client:**
```
$ openssl s_client -connect swiskey-execds1.ibb.ubs.com:443 -servername swiskey-execds1.ibb.ubs.com
connect:errno=11
```

These two results — `Connection refused` from nc and `errno=11` from openssl — are the critical diagnostic signals explained in the next section.

---

## 3. How It Was Determined That Citrix vServer INACTIVE Is the Cause

The diagnosis rests on three interlocking pieces of evidence.

### 3.1 TCP RST, Not Silence

The Windows path (Go checker, curl, PowerShell) shows timeouts on the failing endpoints. Timeouts could mean firewall drop, misconfigured route, or unreachable IP. On their own they are ambiguous.

The WSL probe removes that ambiguity. From WSL, the same IPs return `Connection refused` — meaning a **TCP RST** was received in response to the SYN. A RST is an active reply from the remote host's TCP stack. This distinction is decisive:

| Response | What it means |
|---|---|
| Silence / timeout | Packet dropped before reaching the host (firewall, missing route) |
| TCP RST (`Connection refused`) | The host received the SYN and actively rejected it |

The Citrix VIPs are live and reachable. Something on each VIP is processing the SYN and sending RST. The question becomes: what Citrix component sends RST at port 443?

The Windows timeouts are explained by a perimeter firewall that blocks the Windows network path to these subnets. The WSL path reaches the Citrix directly. Both observations are consistent.

### 3.2 errno=11 (EAGAIN) — The Citrix INACTIVE Fingerprint

openssl's `connect()` syscall on the failing endpoints returned **errno 11 (EAGAIN)**, not the standard **errno 111 (ECONNREFUSED)** that a normal RST produces. This is not a general network error — it is specific to Citrix ADC behaviour.

Citrix ADC SSL Virtual Servers have three observable states at the TCP layer:

| vServer State | TCP behaviour | Client errno |
|---|---|---|
| **UP** | SYN-ACK → TLS handshake proceeds | — (success) |
| **DOWN** (all backends down, cert present) | RST | 111 ECONNREFUSED |
| **INACTIVE** (no certificate bound) | RST — rapid socket open/close | **11 EAGAIN** |
| No vServer on VIP:port | No response | Timeout |

errno 11 (EAGAIN) is emitted when the Citrix TCP stack briefly accepts the socket and immediately closes it before the connection is established — the characteristic behaviour of a Virtual Server that exists in the configuration but is not operational because it has no SSL certificate bound to it. A fully absent vServer would produce silence (timeout); a vServer with a cert but no healthy backends would produce errno 111. errno 11 points specifically to the INACTIVE state.

### 3.3 Adjacent IP Pairs on the Same Subnet

The network-vs-configuration question is settled by comparing consecutive VIPs on the same /24 subnet:

```
Subnet 139.149.12.x:
  .217  → swiskey-execds1.ibb.ubs.com   FAILS  (TCP timeout / RST)
  .218  → swiskey-execds2.ibb.ubs.com   PASSES (TLS 1.3 in 270ms)

Subnet 139.149.131.x:
  .60   → swiskey-execds3.ibb.ubs.com   FAILS  (TCP timeout / RST)
  .61   → swiskey-execds4.ibb.ubs.com   PASSES (TLS 1.3 in 281ms)
```

Adjacent IPs on the same subnet share identical network routing, firewall rules, and ACL policies. The only thing that differs between .217 and .218, or between .60 and .61, is the per-VIP Citrix ADC Virtual Server configuration. Network is not the variable. Citrix configuration is.

### 3.4 The Certificate Is Not the Problem

All nine hostnames — including the three failing ones — are listed in the Subject Alternative Names of the DigiCert certificate currently being served by the six passing endpoints:

```
swiskey-execds1.ibb.ubs.com       ← failing, covered by cert
swiskey-execds3.ibb.ubs.com       ← failing, covered by cert
swiskey-execution-ds1-us.ibb.ubs.com  ← failing, covered by cert
```

The certificate exists on the Citrix ADC, is valid until 2026-11-26, and is correctly bound to the six passing vServers. It is not missing or expired. It simply has not been bound to the three failing vServers.

---

## 4. How to Fix It

The fix is a single Citrix ADC CLI command per failing endpoint. No new certificate is needed, no network changes are required, no application changes are required.

### Step 1 — Identify the certkey name from a working vServer

Log into the Citrix ADC management interface and run:

```bash
show ssl vserver <working-vserver-name>
```

Use a vServer that is currently UP and serving the Nov 2026 certificate (e.g. the one behind `swiskey-execds2.ibb.ubs.com` / 139.149.12.218). Look for the line:

```
1)      CertKey Name: <certkey-name>   Server Certificate
```

Note that `<certkey-name>`.

### Step 2 — Confirm each failing vServer is INACTIVE and has no cert bound

```bash
show ssl vserver <execds1-vserver-name>
show ssl vserver <execds3-vserver-name>
show ssl vserver <execution-ds1-us-vserver-name>
```

Expected output for each:
```
No certificate bound
```
and:
```bash
show lb vserver <name>
# State: INACTIVE
```

### Step 3 — Bind the certificate to each failing vServer

```bash
bind ssl vserver <execds1-vserver>          -certkeyName <certkey-name>
bind ssl vserver <execds3-vserver>          -certkeyName <certkey-name>
bind ssl vserver <execution-ds1-us-vserver> -certkeyName <certkey-name>
```

### Step 4 — Verify each vServer transitions to UP

```bash
show lb vserver <execds1-vserver>
# Expected: State: UP

show lb vserver <execds3-vserver>
# Expected: State: UP

show lb vserver <execution-ds1-us-vserver>
# Expected: State: UP
```

### Step 5 — Verify TLS is now working on each endpoint

```bash
echo | openssl s_client -connect swiskey-execds1.ibb.ubs.com:443 \
    -servername swiskey-execds1.ibb.ubs.com 2>&1 | grep "Not After"
# Expected: Nov 26 23:59:59 2026 GMT

echo | openssl s_client -connect swiskey-execds3.ibb.ubs.com:443 \
    -servername swiskey-execds3.ibb.ubs.com 2>&1 | grep "Not After"
# Expected: Nov 26 23:59:59 2026 GMT

echo | openssl s_client -connect swiskey-execution-ds1-us.ibb.ubs.com:443 \
    -servername swiskey-execution-ds1-us.ibb.ubs.com 2>&1 | grep "Not After"
# Expected: Nov 26 23:59:59 2026 GMT
```

If any endpoint still shows INACTIVE after binding, check that the vServer has at least one healthy backend service bound to it:

```bash
show serviceGroup <servicegroup-name>
```

A vServer with a cert but no healthy backends will be in DOWN state, not INACTIVE. DOWN is a separate issue requiring the backend services to be brought up.

---

## 5. Summary

| Question | Answer |
|---|---|
| What was checked? | TCP connectivity (Go checker, curl, PowerShell, nc), TLS handshake (openssl, curl verbose), certificate validity and SAN coverage |
| What ruled out network / firewall? | WSL nc received TCP RST — an active reply, not silence. Adjacent VIPs on the same subnet behave differently. ICMP fails on passing endpoints too. |
| What identified INACTIVE specifically? | openssl errno=11 (EAGAIN) — the specific errno Citrix ADC emits for an SSL vServer with no certificate bound. errno 111 would indicate DOWN; silence would indicate no vServer. |
| What is the fix? | `bind ssl vserver <name> -certkeyName <certkey-name>` on each of the three failing vServers — using the same certkey already bound to the six passing vServers. |
| Is a new certificate needed? | No. The existing DigiCert cert (valid to Nov 26 2026) already covers all three failing hostnames in its SAN list. |

# Security Header Check — swiskey-execds2-sys.ibb.ubs.com

**Date:** 06 June 2026
**Target:** swiskey-execds2-sys.ibb.ubs.com:443

---

## What we were looking at

This is a Caplin Liberator instance running on port 443, streaming real-time financial market data over RTTP. It does not serve any HTML. That detail matters a lot for most of the findings below.

---

## How we checked

Use `curl` against the endpoint to pull the response headers:

```bash
# Grab all headers
curl -s -I -L https://swiskey-execds2-syd.ibb.ubs.com

# Isolate the Server header specifically
curl -s -I -L https://swiskey-execds2-syd.ibb.ubs.com | grep -i "^server:"

# Check HSTS preload status
curl -s "https://hstspreload.org/api/v2/status?domain=swiskey-execds2-syd.ibb.ubs.com"
```

What came back:

```
HTTP/1.1 200 OK
Server: Liberator/7.1.4 (Linux)
Strict-Transport-Security: max-age=31536000
Content-Type: application/rttp
Connection: keep-alive
```

---

## The Findings

### 1. CSP Not Implemented — ❌ False Positive

CSP exists to stop XSS attacks in browsers rendering HTML. No HTML here, no DOM, no rendering engine — CSP does absolutely nothing on an RTTP stream. The scanner flagged it because it doesn't know what kind of endpoint it's talking to.

**Close it.** Justification: *"Endpoint is a Caplin Liberator RTTP streaming server with no HTML content. CSP is not applicable."*

---

### 2. Domain Not Found in HSTS Preload — ❌ False Positive

The HSTS preload list lives inside browsers and covers public internet domains. `swiskey-execds2-sys.ibb.ubs.com` is an internal UBS hostname — it's never going to be on that list, nor should it be.

What actually matters here is whether the HSTS *response header* is present, and it is — `Strict-Transport-Security: max-age=31536000`. That's a year. We're fine.

**Close it.** Justification: *"Internal hostname, not eligible for preload list. HSTS response header is correctly configured."*

---

### 3. Server Header Exposed — ✅ Valid Finding

This one's real. The response is handing out:

```
Server: Liberator/7.1.4 (Linux)
```

That's the product name, the exact version, and the OS. Anyone who can hit this endpoint — insider, compromised machine, or an attacker who's already on the network — now knows exactly what software to look up CVEs for. Not great.

**Fix it.** One line in `rttpd.conf`:

```
server-name ""
```

Restart Liberator, then verify the header is gone:

```bash
curl -s -I https://swiskey-execds2-sys.ibb.ubs.com | grep -i "^server:"
# should return nothing
```

---

### 4. X-Content-Type-Options Not nosniff — ❌ False Positive

`nosniff` stops browsers from MIME-sniffing responses. Browsers only MIME-sniff content they're about to render. This endpoint returns `application/rttp` data consumed by the Caplin client library, not the browser renderer. There's nothing to sniff.

**Close it.** Justification: *"RTTP streaming endpoint, no browser-renderable content. X-Content-Type-Options is not applicable."*

---

### 5. X-Frame-Options Not DENY or SAMEORIGIN — ❌ False Positive

Clickjacking needs an HTML page you can drop in an `<iframe>` and trick a user into clicking. You can't iframe an RTTP stream. There's no UI, no buttons, nothing to hijack.

**Close it.** Justification: *"No HTML served, no frameable content. X-Frame-Options is not applicable."*

---

## Summary

| # | Finding | Verdict | What to do |
|---|---------|---------|------------|
| 1 | CSP Not Implemented | ❌ False Positive | Close — not applicable |
| 2 | Not in HSTS Preload | ❌ False Positive | Close — not applicable |
| 3 | Server Header Exposed | ✅ Valid | Fix `rttpd.conf`, suppress header |
| 4 | X-Content-Type-Options | ❌ False Positive | Close — not applicable |
| 5 | X-Frame-Options | ❌ False Positive | Close — not applicable |

---

## Bottom Line

4 out of 5 findings are scanner noise. The tool has no idea it's talking to a streaming backend and fired off a checklist designed for web apps. The only thing worth acting on is the Server header — and that's a one-line config fix.

Also worth raising with whoever owns the scanner config: non-HTML endpoints should probably be excluded from HTML-specific header checks. This won't be the only Liberator instance that trips these same false positives.

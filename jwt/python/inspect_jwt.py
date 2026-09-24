#!/usr/bin/env python3
"""Decode and display the contents of a JWT (JSON Web Token).

Splits the token into header, payload and signature, Base64Url-decodes the
header and payload, pretty-prints them as JSON, and interprets the common time
claims (exp, iat, nbf, auth_time) as readable UTC/local dates with an expiry
status.

It does NOT verify the signature. Do not trust the output for security decisions.

Requires Python 3.8+ and only the standard library.
"""

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

CLAIM_LABELS = [
    ("iss", "Issuer"), ("sub", "Subject"), ("aud", "Audience"), ("azp", "Authorized party"),
    ("jti", "Token ID"), ("scope", "Scope"), ("scp", "Scopes"), ("roles", "Roles"),
    ("name", "Name"), ("email", "Email"), ("upn", "UPN"), ("preferred_username", "Username"),
    ("tid", "Tenant ID"), ("oid", "Object ID"), ("client_id", "Client ID"), ("appid", "App ID"),
]
TIME_LABELS = [("iat", "Issued at"), ("nbf", "Not before"), ("exp", "Expires"), ("auth_time", "Auth time")]

BEARER_PREFIX = re.compile(r"^(authorization:\s*)?bearer\s+", re.IGNORECASE)


class Colors:
    def __init__(self, enabled):
        self.enabled = enabled

    def _wrap(self, code, s):
        return f"\x1b[{code}m{s}\x1b[0m" if self.enabled else s

    def cyan(self, s): return self._wrap("36", s)
    def green(self, s): return self._wrap("32", s)
    def yellow(self, s): return self._wrap("33", s)
    def red(self, s): return self._wrap("31", s)
    def dim(self, s): return self._wrap("90", s)


# --- Getting the token -------------------------------------------------------

def read_clipboard():
    if sys.platform == "win32":
        candidates = [["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"]]
    elif sys.platform == "darwin":
        candidates = [["pbpaste"]]
    else:
        candidates = [
            ["wl-paste", "--no-newline"],
            ["xclip", "-o", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--output"],
            ["powershell.exe", "-NoProfile", "-Command", "Get-Clipboard -Raw"],  # WSL
        ]
    for cmd in candidates:
        if shutil.which(cmd[0]):
            try:
                return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
            except (OSError, subprocess.CalledProcessError):
                continue
    return ""


def read_token(args, colors):
    if args:
        return " ".join(args)
    if not sys.stdin.isatty():
        text = sys.stdin.read()
        if text.strip():
            return text
    text = read_clipboard()
    if not text.strip():
        raise ValueError("No token supplied. Pass it as an argument, pipe it in, or copy it to the clipboard.")
    print(colors.dim("(Token read from clipboard)"), file=sys.stderr)
    return text


def clean_token(token):
    """Strip "Bearer " / "Authorization: Bearer ", surrounding quotes and all whitespace."""
    token = BEARER_PREFIX.sub("", token.strip())
    token = token.strip().strip("\"'")
    return re.sub(r"\s+", "", token)


# --- Decoding ---------------------------------------------------------------

def b64url_decode(segment):
    """Decode one Base64Url segment, with or without '=' padding."""
    s = segment.rstrip("=")
    if len(s) % 4 == 1:
        raise ValueError("invalid Base64Url segment length")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decode_json_segment(segment, name):
    try:
        value = json.loads(b64url_decode(segment).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"Could not decode {name}: {e}") from None
    if not isinstance(value, dict):
        raise ValueError(f"{name.capitalize()} is not a JSON object.")
    return value


def pretty(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False)


def display(value):
    """Strings unquoted, arrays joined with ", ", anything else as compact JSON."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ", ".join(display(v) for v in value)
    return json.dumps(value, separators=(",", ":"))


def format_time(ts):
    utc = datetime.fromtimestamp(ts, tz=timezone.utc)
    return f"{utc:%Y-%m-%d %H:%M:%S} UTC  ({utc.astimezone():%Y-%m-%d %H:%M:%S} local)"


def format_duration(seconds):
    """Seconds -> "[Nd ]HH:MM:SS" (sign dropped)."""
    s = abs(int(seconds))
    days, s = divmod(s, 86400)
    hms = f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"
    return f"{days}d {hms}" if days else hms


def row(label, value):
    print(f"{label + ':':<18} {value}")


# --- Output -----------------------------------------------------------------

def print_summary(payload, now, c):
    for key, label in CLAIM_LABELS:
        if key in payload:
            row(label, display(payload[key]))

    times = {}
    for key, label in TIME_LABELS:
        if key not in payload:
            continue
        v = payload[key]
        try:
            if isinstance(v, bool):
                raise TypeError
            ts = int(float(v))
            text = format_time(ts)
        except (TypeError, ValueError, OverflowError, OSError):
            row(label, f"{display(v)} (unparseable)")
            continue
        times[key] = ts
        row(label, text)

    if "iat" in times and "exp" in times:
        row("Lifetime", format_duration(times["exp"] - times["iat"]))

    print()
    nbf, exp = times.get("nbf"), times.get("exp")
    if nbf is not None and nbf > now:
        print(c.yellow(f"STATUS: NOT YET VALID (valid in {format_duration(nbf - now)})"))
    elif exp is not None and exp <= now:
        print(c.red(f"STATUS: EXPIRED ({format_duration(now - exp)} ago)"))
    elif exp is not None:
        print(c.green(f"STATUS: VALID (expires in {format_duration(exp - now)})"))
    else:
        print(c.yellow("STATUS: No 'exp' claim - token does not expire."))


def inspect(raw_token, raw, c):
    parts = clean_token(raw_token).split(".")
    if len(parts) == 5:
        print(c.yellow("WARNING: Token has 5 parts - this looks like an encrypted JWE. Only the header can be decoded."))
    elif len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 dot-separated parts, found {len(parts)}.")

    header = decode_json_segment(parts[0], "header")
    payload = decode_json_segment(parts[1], "payload") if len(parts) == 3 else None

    if raw:
        print(pretty(header))
        if payload is not None:
            print(pretty(payload))
        return

    print()
    print(c.cyan("=== HEADER ==="))
    print(pretty(header))

    if payload is not None:
        print()
        print(c.cyan("=== PAYLOAD ==="))
        print(pretty(payload))
        print()
        print(c.cyan("=== SUMMARY ==="))
        print_summary(payload, int(datetime.now(timezone.utc).timestamp()), c)

    print()
    print(c.cyan("=== SIGNATURE ==="))
    alg = display(header.get("alg", ""))
    row("Algorithm", alg)
    if "kid" in header:
        row("Key ID (kid)", display(header["kid"]))
    if alg.lower() == "none":
        print(c.red("WARNING: alg is 'none' - token is unsigned!"))
    row("Signature length", f"{len(parts[-1])} chars (Base64Url)")
    print(c.dim("Signature NOT verified by this script."))
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Decode a JWT and print its header, payload, a claim summary and expiry status. "
                    "The signature is NOT verified. The token is read from the arguments, "
                    "then piped stdin, then the clipboard.")
    parser.add_argument("token", nargs="*", help='the JWT; a "Bearer " prefix is stripped')
    parser.add_argument("-r", "--raw", action="store_true", help="print only the decoded header and payload JSON")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output (also: NO_COLOR env var)")
    args = parser.parse_args()

    color = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
    if color and sys.platform == "win32":
        os.system("")  # enables ANSI escape processing in the Windows console
    c = Colors(color)

    # Make sure non-ASCII claim values print on consoles with a legacy code page.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    try:
        inspect(read_token(args.token, c), args.raw, c)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

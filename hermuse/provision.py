"""One-time loopback OAuth provisioning. Tokens never enter stdout or URLs we log.

Run as the VM application user; forward the printed loopback callback port over
SSH to the browser's machine. The browser owner approves each new connection.
"""
import argparse
import base64
import hashlib
import http.cookiejar
import http.server
import json
import os
from pathlib import Path
import secrets
import time
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("provider", choices=["openrouter", "codex"])
    parser.add_argument("--credentials", required=True)
    parser.add_argument("--dashboard-password")
    args = parser.parse_args()
    credential_file = Path(args.credentials).expanduser()
    if credential_file.stat().st_mode & 0o077:
        raise SystemExit("Unsafe credential file permissions")
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def api(url, body=None, method=None):
        request = urllib.request.Request(
            url, data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json"}, method=method)
        with client.open(request, timeout=30) as response:
            return json.load(response)

    def store(field, value):
        if not value or not isinstance(value, str):
            raise ValueError("No credential returned")
        data = json.loads(credential_file.read_text())
        data[field] = value
        temp = credential_file.with_name(credential_file.name + "." + secrets.token_hex(8))
        try:
            with open(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, credential_file)
        finally:
            temp.unlink(missing_ok=True)

    base = "http://127.0.0.1:20128"
    verifier = secrets.token_urlsafe(48)
    callback_path = "/callback/" + secrets.token_urlsafe(24)
    port = 23672
    state = None
    if args.provider == "codex":
        password = Path(args.dashboard_password).expanduser().read_text().strip()
        if not api(base + "/api/auth/login", {"password": password}).get("success"):
            raise SystemExit("Dashboard authentication failed")
        port, callback_path = 1455, "/auth/callback"
    callback_url = f"http://localhost:{port}{callback_path}"
    if args.provider == "openrouter":
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        auth_url = "https://openrouter.ai/auth?" + urllib.parse.urlencode({
            "callback_url": callback_url, "code_challenge": challenge,
            "code_challenge_method": "S256", "key_label": "hermuse-v2-zdr"})
    else:
        flow = api(base + "/api/oauth/codex/authorize?" + urllib.parse.urlencode({"redirect_uri": callback_url}))
        verifier, state = flow["codeVerifier"], flow["state"]
        auth_url = flow.get("authorizeUrl") or flow["authUrl"]

    result = {"done": False, "success": False}

    class Callback(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # The default access logger would expose the authorization code.

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            if parsed.path != callback_path:
                self.send_error(404)
                return
            if state and not secrets.compare_digest(query.get("state", [""])[0], state):
                self.send_error(403)
                return
            code = query.get("code", [""])[0]
            if not code or "error" in query:
                self.send_error(400)
                return
            try:
                if args.provider == "openrouter":
                    exchanged = api("https://openrouter.ai/api/v1/auth/keys", {
                        "code": code, "code_verifier": verifier, "code_challenge_method": "S256"})
                    store("openrouter_key", exchanged["key"])
                else:
                    exchanged = api(base + "/api/oauth/codex/exchange", {
                        "code": code, "redirectUri": callback_url, "codeVerifier": verifier, "state": state})
                    if not exchanged.get("success"):
                        raise ValueError("Exchange failed")
                    api(base + "/api/settings", {"enableObservability": False, "headroomEnabled": False,
                        "headroomCompressUserMessages": False, "cavemanEnabled": False,
                        "ponytailEnabled": False, "pxpipeEnabled": False, "requireApiKey": True}, "PATCH")
                    key = api(base + "/api/keys", {"name": "hermuse-policy-only"})
                    store("backend_key", key["key"])
                result["success"] = True
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(b"Hermuse VM authorization complete. Credentials saved privately. You can close this tab.")
            except Exception:
                self.send_error(502, "Authorization exchange failed; no credential values logged")
            finally:
                result["done"] = True

    with http.server.HTTPServer(("127.0.0.1", port), Callback) as server:
        server.timeout = 1
        print("Callback port:", port, flush=True)
        print("Authorize URL:", auth_url, flush=True)
        deadline = time.monotonic() + 1200
        while not result["done"] and time.monotonic() < deadline:
            server.handle_request()
    print("Authorization succeeded." if result["success"] else "Authorization not completed.", flush=True)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

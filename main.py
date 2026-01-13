"""
X OAuth Tester (Flask)

- OAuth2 Authorization Code + PKCE
- Token persistence: Redis (optional) or token.json
- Auto refresh + manual refresh button
- Post tweet (text)
- Post tweet with media (X API v2 chunked upload: INIT/APPEND/FINALIZE)
- Verbose HTTP logging (toggle PRINT_SECRETS=1)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, redirect, request, session

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None

# Load env vars from .env (if present)
load_dotenv()


# =========================
# Config
# =========================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
REDIRECT_URI = os.environ["REDIRECT_URI"]

REDIS_URL = os.environ.get("REDIS_URL_DOGS")  # optional
TOKEN_FILE = os.environ.get("TOKEN_FILE", "token.json")

AUTH_URL = "https://twitter.com/i/oauth2/authorize"
TOKEN_URL = "https://api.twitter.com/2/oauth2/token"
TWEET_URL = "https://api.twitter.com/2/tweets"

# X API v2 media upload (chunked) - dedicated endpoints
MEDIA_INIT_URL = "https://api.x.com/2/media/upload/initialize"
MEDIA_APPEND_URL_TMPL = "https://api.x.com/2/media/upload/{id}/append"
MEDIA_FINALIZE_URL_TMPL = "https://api.x.com/2/media/upload/{id}/finalize"

SCOPES = [
    "tweet.read",
    "users.read",
    "tweet.write",
    "offline.access",
    "media.write",
]

PRINT_SECRETS = os.environ.get("PRINT_SECRETS", "0") == "1"
REDIS_KEY = "x_oauth_token_v1"

r: Optional[Any] = None
if REDIS_URL and redis_lib is not None:
    r = redis_lib.from_url(REDIS_URL)


# =========================
# Small UI (single page)
# =========================
INDEX_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>X OAuth Tester</title>
  <style>
    body { font-family: -apple-system, system-ui, Arial; margin: 24px; }
    .row { margin: 12px 0; }
    input, textarea { width: 100%; padding: 10px; font-size: 14px; }
    button { padding: 10px 14px; font-size: 14px; cursor: pointer; }
    .card { border: 1px solid #ddd; border-radius: 10px; padding: 14px; margin: 16px 0; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; }
    .hint { color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <h2>X OAuth Tester</h2>

  <div class="card">
    <div class="row">
      <button onclick="location.href='/authorize'">Authorize / Re-authorize</button>
      <button onclick="refreshToken()">Refresh access token</button>
      <button onclick="showToken()">Show stored token</button>
      <button onclick="clearToken()">Clear token</button>
    </div>
    <div class="row hint">
      Tip: Once authorized, the app will auto-refresh access tokens using refresh_token.
    </div>
  </div>

  <div class="card">
    <h3>Post text</h3>
    <div class="row">
      <textarea id="text" rows="3">aloha testing from python</textarea>
    </div>
    <div class="row">
      <button onclick="postText()">Post Tweet</button>
    </div>
  </div>

  <div class="card">
    <h3>Post with media (image URL)</h3>
    <div class="row">
      <input id="image_url" placeholder="https://..." />
      <div class="hint">You can paste multiple URLs separated by commas/newlines (max 4).</div>
    </div>
    <div class="row">
      <textarea id="media_text" rows="3">aloha with image</textarea>
    </div>
    <div class="row">
      <button onclick="postMedia()">Upload + Tweet</button>
    </div>
    <small class="hint">
      If your X access level doesn’t allow media upload, you’ll see a 4xx with details.
    </small>
  </div>

  <div class="card">
    <h3>Output</h3>
    <div id="out" class="mono"></div>
  </div>

<script>
function out(t){
  document.getElementById('out').textContent = t;
}

async function readBodyPretty(res){
  const contentType = (res.headers.get('content-type') || '').toLowerCase();

  // Prefer JSON pretty print if server returns JSON
  if (contentType.includes('application/json')) {
    try {
      const j = await res.json();
      return JSON.stringify(j, null, 2);
    } catch (e) {
      // fall through to text
    }
  }

  // Fallback: try parse text as JSON anyway
  const text = await res.text();
  try {
    const j = JSON.parse(text);
    return JSON.stringify(j, null, 2);
  } catch (e) {
    return text;
  }
}

async function showToken(){
  const res = await fetch('/token', { method: 'GET' });
  out(await readBodyPretty(res));
}

async function clearToken(){
  const res = await fetch('/logout', { method: 'POST' });
  out(await readBodyPretty(res));
}

async function postText(){
  const text = document.getElementById('text').value;
  const res = await fetch('/tweet', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text})
  });
  out(await readBodyPretty(res));
}

async function postMedia(){
  const text = document.getElementById('media_text').value;
  const image_url = document.getElementById('image_url').value;
  const res = await fetch('/tweet-media', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text, image_url})
  });
  out(await readBodyPretty(res));
}

async function refreshToken(){
  const res = await fetch('/refresh', { method: 'POST' });
  out(await readBodyPretty(res));
}
</script>
</body>
</html>
"""


# =========================
# Logging helpers
# =========================
def _redact(text: str) -> str:
    """Redact secrets from logs unless PRINT_SECRETS=1."""
    if PRINT_SECRETS:
        return text

    text = re.sub(
        r"(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+",
        r"\1***REDACTED***",
        text,
    )
    text = re.sub(
        r"(Authorization:\s*Bearer\s+)[A-Za-z0-9\-_\.]+",
        r"\1***REDACTED***",
        text,
    )
    text = re.sub(r'("access_token"\s*:\s*")[^"]+(")', r"\1***REDACTED***\2", text)
    text = re.sub(r'("refresh_token"\s*:\s*")[^"]+(")', r"\1***REDACTED***\2", text)
    return text


def log_http(
    title: str,
    method: str,
    url: str,
    headers: Optional[dict] = None,
    body: Optional[str] = None,
) -> None:
    """Print structured HTTP logs."""
    print(f"\n=== {title} ===")
    print("METHOD:", method)
    print("URL   :", url)
    if headers:
        print("HEADERS:")
        print(_redact(json.dumps(headers, indent=2)))
    if body is not None:
        print("BODY:")
        print(_redact(body))
    print("================\n")


def safe_json(resp: requests.Response) -> dict:
    """Parse JSON response safely."""
    try:
        return resp.json()
    except ValueError:
        return {"raw": resp.text}


# =========================
# Token storage (Redis or file)
# =========================
def load_token() -> Optional[dict]:
    """Load token from Redis or file."""
    if r is not None:
        raw = r.get(REDIS_KEY)
        if raw:
            return json.loads(raw)
        return None

    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    return None


def save_token(token: dict) -> None:
    """Save token to Redis or file."""
    if r is not None:
        r.set(REDIS_KEY, json.dumps(token))
        return

    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump(token, f, indent=2)


def clear_token() -> None:
    """Clear stored token."""
    if r is not None:
        r.delete(REDIS_KEY)
        return

    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)


def token_is_valid(token: dict) -> bool:
    """Return True if token has expires_at and is still valid."""
    expires_at = token.get("expires_at")
    if not expires_at:
        return False
    return time.time() < float(expires_at)


# =========================
# OAuth / PKCE
# =========================
def create_pkce_pair() -> tuple[str, str]:
    """Create PKCE verifier + challenge."""
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
    code_verifier = re.sub(r"[^a-zA-Z0-9]+", "", code_verifier)

    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
    code_challenge = code_challenge.replace("=", "")
    return code_verifier, code_challenge


def build_authorize_url(code_challenge: str) -> tuple[str, str]:
    """Build X authorize URL and state."""
    state = base64.urlsafe_b64encode(os.urandom(18)).decode("utf-8").replace("=", "")
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(SCOPES),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{AUTH_URL}?{urlencode(params)}", state


def basic_auth_header() -> str:
    """Build Basic auth header for token endpoint."""
    raw = f"{CLIENT_ID}:{CLIENT_SECRET}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("utf-8")


def exchange_code_for_token(code: str, code_verifier: str) -> dict:
    """Exchange auth code for access/refresh token."""
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": basic_auth_header(),
    }
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
        "client_id": CLIENT_ID,
    }

    log_http(
        "TOKEN EXCHANGE REQUEST",
        "POST",
        TOKEN_URL,
        headers=headers,
        body=urlencode(form),
    )

    resp = requests.post(TOKEN_URL, headers=headers, data=form, timeout=20)
    data = safe_json(resp)

    log_http(
        "TOKEN EXCHANGE RESPONSE",
        "RESPONSE",
        str(resp.status_code),
        headers=dict(resp.headers),
        body=json.dumps(data, indent=2),
    )

    resp.raise_for_status()

    expires_in = int(data.get("expires_in", 0))
    data["expires_at"] = int(time.time()) + max(expires_in - 60, 0)
    return data


def refresh_access_token(refresh_token: str) -> dict:
    """Refresh access token using refresh_token."""
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": basic_auth_header(),
    }
    form = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
    }

    log_http(
        "TOKEN REFRESH REQUEST",
        "POST",
        TOKEN_URL,
        headers=headers,
        body=urlencode(form),
    )

    resp = requests.post(TOKEN_URL, headers=headers, data=form, timeout=20)
    data = safe_json(resp)

    log_http(
        "TOKEN REFRESH RESPONSE",
        "RESPONSE",
        str(resp.status_code),
        headers=dict(resp.headers),
        body=json.dumps(data, indent=2),
    )

    resp.raise_for_status()

    expires_in = int(data.get("expires_in", 0))
    data["expires_at"] = int(time.time()) + max(expires_in - 60, 0)
    return data


def get_access_token_or_refresh() -> str:
    """Return valid access token; refresh if needed; otherwise error."""
    token = load_token()
    if token and token_is_valid(token):
        return token["access_token"]

    if token and token.get("refresh_token"):
        new_token = refresh_access_token(token["refresh_token"])
        if "refresh_token" not in new_token:
            new_token["refresh_token"] = token["refresh_token"]
        save_token(new_token)
        return new_token["access_token"]

    raise RuntimeError("No valid token stored. Click Authorize first.")


# =========================
# Tweet + Media
# =========================
def post_tweet(
    text: str,
    access_token: str,
    media_ids: Optional[list[str]] = None,
) -> requests.Response:
    """Post a Tweet, optionally with media."""
    payload: dict[str, Any] = {"text": text}
    if media_ids:
        payload["media"] = {"media_ids": media_ids}

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    log_http(
        "TWEET REQUEST",
        "POST",
        TWEET_URL,
        headers=headers,
        body=json.dumps(payload),
    )

    resp = requests.post(TWEET_URL, headers=headers, json=payload, timeout=20)

    log_http(
        "TWEET RESPONSE",
        "RESPONSE",
        str(resp.status_code),
        headers=dict(resp.headers),
        body=json.dumps(safe_json(resp), indent=2),
    )
    return resp


def _guess_media_type(content_type: str, url: str) -> str:
    """Guess media MIME type using HTTP header then URL extension."""
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct.startswith("image/"):
        return ct

    u = url.lower()
    if u.endswith((".jpg", ".jpeg")):
        return "image/jpeg"
    if u.endswith(".png"):
        return "image/png"
    if u.endswith(".gif"):
        return "image/gif"
    if u.endswith(".webp"):
        return "image/webp"

    return "image/jpeg"


def upload_image_from_url_v2(image_url: str, access_token: str) -> str:
    """Upload an image (by URL) using X API v2 chunked media upload."""
    dl = requests.get(image_url, timeout=30)
    dl.raise_for_status()

    media_type = _guess_media_type(dl.headers.get("Content-Type", ""), image_url)
    media_bytes = dl.content
    total_bytes = len(media_bytes)

    bearer_headers = {"Authorization": f"Bearer {access_token}"}

    # 1) INITIALIZE
    init_headers = {**bearer_headers, "Content-Type": "application/json"}
    init_body = {
        "media_category": "tweet_image",
        "media_type": media_type,
        "total_bytes": total_bytes,
    }

    log_http(
        "MEDIA INIT REQUEST (v2)",
        "POST",
        MEDIA_INIT_URL,
        headers=init_headers,
        body=json.dumps(init_body),
    )
    init_resp = requests.post(
        MEDIA_INIT_URL,
        headers=init_headers,
        json=init_body,
        timeout=30,
    )
    init_data = safe_json(init_resp)
    log_http(
        "MEDIA INIT RESPONSE (v2)",
        "RESPONSE",
        str(init_resp.status_code),
        headers=dict(init_resp.headers),
        body=json.dumps(init_data, indent=2),
    )
    init_resp.raise_for_status()

    media_id = (init_data.get("data") or {}).get("id")
    if not media_id:
        raise RuntimeError(f"INIT succeeded but missing data.id: {init_data}")

    # 2) APPEND
    chunk_size = 1024 * 1024
    append_url = MEDIA_APPEND_URL_TMPL.format(id=media_id)
    append_headers = {**bearer_headers, "Content-Type": "application/json"}

    segment_index = 0
    offset = 0
    while offset < total_bytes:
        chunk = media_bytes[offset : offset + chunk_size]
        offset += len(chunk)

        b64 = base64.b64encode(chunk).decode("ascii")
        append_body = {"media": b64, "segment_index": segment_index}

        log_http(
            f"MEDIA APPEND REQUEST (v2) [segment={segment_index} bytes={len(chunk)}]",
            "POST",
            append_url,
            headers=append_headers,
            body=f"<json: media(base64) {len(b64)} chars, segment_index={segment_index}>",
        )

        append_resp = requests.post(
            append_url,
            headers=append_headers,
            json=append_body,
            timeout=60,
        )
        append_data = safe_json(append_resp)
        log_http(
            f"MEDIA APPEND RESPONSE (v2) [segment={segment_index}]",
            "RESPONSE",
            str(append_resp.status_code),
            headers=dict(append_resp.headers),
            body=json.dumps(append_data, indent=2),
        )
        append_resp.raise_for_status()
        segment_index += 1

    # 3) FINALIZE
    finalize_url = MEDIA_FINALIZE_URL_TMPL.format(id=media_id)
    log_http(
        "MEDIA FINALIZE REQUEST (v2)",
        "POST",
        finalize_url,
        headers=bearer_headers,
    )
    fin_resp = requests.post(finalize_url, headers=bearer_headers, timeout=30)
    fin_data = safe_json(fin_resp)
    log_http(
        "MEDIA FINALIZE RESPONSE (v2)",
        "RESPONSE",
        str(fin_resp.status_code),
        headers=dict(fin_resp.headers),
        body=json.dumps(fin_data, indent=2),
    )
    fin_resp.raise_for_status()

    return str(media_id)


def _parse_image_urls(image_url_field: str) -> list[str]:
    """Parse multiple image URLs from UI field (commas/newlines). Max 4."""
    raw = (image_url_field or "").strip()
    if not raw:
        return []
    parts = [p.strip() for p in re.split(r"[\n,]+", raw) if p.strip()]
    return parts[:4]


def _timestamped(text: str) -> str:
    """Append timestamp to avoid duplicate content rejection."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"{text} | {ts}"


# =========================
# Routes
# =========================
@app.get("/")
def index() -> Response:
    """UI page."""
    return Response(INDEX_HTML, mimetype="text/html")


@app.get("/authorize")
def authorize() -> Response:
    """Start OAuth flow."""
    code_verifier, code_challenge = create_pkce_pair()
    auth_url, state = build_authorize_url(code_challenge)

    session["code_verifier"] = code_verifier
    session["oauth_state"] = state

    log_http("AUTHORIZATION REQUEST (Browser Redirect)", "GET", auth_url)
    return redirect(auth_url)


@app.get("/oauth/callback")
def oauth_callback() -> Response:
    """OAuth callback handler."""
    code = request.args.get("code")
    state = request.args.get("state")

    if not code:
        return jsonify({"error": "Missing code"}), 400
    if not state or state != session.get("oauth_state"):
        return jsonify({"error": "State mismatch"}), 400

    code_verifier = session.get("code_verifier")
    if not code_verifier:
        return jsonify({"error": "Missing code_verifier"}), 400

    token = exchange_code_for_token(code, code_verifier)
    save_token(token)
    return redirect("/")


@app.get("/token")
def show_token() -> Response:
    """Show stored token (redacted unless PRINT_SECRETS=1)."""
    tok = load_token()
    if not tok:
        return jsonify({"stored": False})

    safe = dict(tok)
    if not PRINT_SECRETS:
        safe["access_token"] = "***REDACTED***" if "access_token" in safe else None
        safe["refresh_token"] = "***REDACTED***" if "refresh_token" in safe else None

    return jsonify({"stored": True, "token": safe})


@app.post("/refresh")
def force_refresh() -> Response:
    """Force refresh using stored refresh_token."""
    tok = load_token()
    if not tok or not tok.get("refresh_token"):
        return (
            jsonify({"error": "No refresh_token stored. Click Authorize first."}),
            400,
        )

    try:
        new_token = refresh_access_token(tok["refresh_token"])
        if "refresh_token" not in new_token:
            new_token["refresh_token"] = tok["refresh_token"]
        save_token(new_token)
    except requests.HTTPError as e:
        resp = e.response
        return (
            jsonify(
                {
                    "error": "token_refresh_failed",
                    "status": resp.status_code if resp is not None else None,
                    "headers": dict(resp.headers) if resp is not None else None,
                    "body": safe_json(resp) if resp is not None else None,
                }
            ),
            400,
        )

    safe = dict(new_token)
    if not PRINT_SECRETS:
        safe["access_token"] = "***REDACTED***" if "access_token" in safe else None
        safe["refresh_token"] = "***REDACTED***" if "refresh_token" in safe else None

    return jsonify({"ok": True, "token": safe})


@app.post("/logout")
def logout() -> Response:
    """Clear stored token."""
    clear_token()
    return jsonify({"ok": True})


@app.post("/tweet")
def tweet_text() -> Response:
    """Post a text tweet."""
    data = request.get_json(force=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text is required"}), 400

    try:
        access = get_access_token_or_refresh()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400

    resp = post_tweet(_timestamped(text), access)
    return jsonify(safe_json(resp)), resp.status_code


@app.post("/tweet-media")
def tweet_media() -> Response:
    """Upload images then tweet with media."""
    data = request.get_json(force=True) or {}
    text = (data.get("text") or "").strip()
    image_url_field = (data.get("image_url") or "").strip()

    if not text:
        return jsonify({"error": "text is required"}), 400

    urls = _parse_image_urls(image_url_field)
    if not urls:
        return jsonify({"error": "image_url is required"}), 400

    try:
        access = get_access_token_or_refresh()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400

    media_ids: list[str] = []
    try:
        for u in urls:
            media_ids.append(upload_image_from_url_v2(u, access))
    except requests.HTTPError as e:
        resp = e.response
        return (
            jsonify(
                {
                    "error": "media_upload_failed",
                    "status": resp.status_code if resp is not None else None,
                    "headers": dict(resp.headers) if resp is not None else None,
                    "body": safe_json(resp) if resp is not None else None,
                }
            ),
            400,
        )

    resp = post_tweet(_timestamped(text), access, media_ids=media_ids)
    return jsonify(safe_json(resp)), resp.status_code


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)

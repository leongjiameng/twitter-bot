"""
X OAuth Tester (Flask)

- OAuth2 Authorization Code + PKCE
- Token persistence: Redis (optional) or token.json
- Supports automatic refresh for browser-authorized tokens
- Imported tokens can be access-token-only
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
# Public clients do not have a client secret and authenticate with PKCE only.
# Confidential clients should set CLIENT_SECRET and use HTTP Basic auth below.
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "").strip()
OAUTH_CLIENT_TYPE = os.environ.get(
    "OAUTH_CLIENT_TYPE", "confidential" if CLIENT_SECRET else "public"
).strip().lower()
if OAUTH_CLIENT_TYPE not in {"public", "confidential"}:
    raise RuntimeError("OAUTH_CLIENT_TYPE must be 'public' or 'confidential'")
if OAUTH_CLIENT_TYPE == "confidential" and not CLIENT_SECRET:
    raise RuntimeError("CLIENT_SECRET is required for a confidential client")
REDIRECT_URI = os.environ["REDIRECT_URI"]

REDIS_URL = os.environ.get("REDIS_URL_DOGS")  # optional
TOKEN_FILE = os.environ.get("TOKEN_FILE", "token.json")

AUTH_URL = "https://twitter.com/i/oauth2/authorize"
TOKEN_URL = "https://api.x.com/2/oauth2/token"
TWEET_URL = "https://api.twitter.com/2/tweets"
USER_ME_URL = "https://api.x.com/2/users/me"

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
    input, textarea { width: 100%; padding: 10px; font-size: 14px; box-sizing: border-box; }
    button { padding: 10px 14px; font-size: 14px; cursor: pointer; }
    button:disabled { opacity: 0.6; cursor: not-allowed; }
    .card { border: 1px solid #ddd; border-radius: 10px; padding: 14px; margin: 16px 0; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; }
    .hint { color: #666; font-size: 12px; }

    .statusbar { display:flex; align-items:center; gap:10px; margin: 10px 0 12px; }
    .spinner {
      width: 16px; height: 16px; border-radius: 50%;
      border: 2px solid #ddd; border-top-color: #333;
      animation: spin 0.8s linear infinite;
      display: none;
      flex: 0 0 auto;
    }
    .spinner.on { display: inline-block; }
    @keyframes spin { to { transform: rotate(360deg); } }

    .status { min-height: 16px; }
  </style>
</head>
<body>
  <h2>X OAuth Tester</h2>

  <div class="card">
    <div class="row">
      <button onclick="location.href='/authorize'">Authorize / Re-authorize</button>
      <button onclick="refreshToken()">Refresh access token</button>
      <button onclick="showToken()">Show stored token</button>
      <button onclick="getMe()">Call /2/users/me</button>
      <button onclick="clearToken()">Clear token</button>
    </div>
    <div class="row hint">
      Tip: Imported tokens use the access token as-is; browser-authorized tokens can auto-refresh.
    </div>
  </div>

  <div class="card">
    <h3>Delete all posts</h3>
    <div class="row hint">This includes replies. Reposts are not handled.</div>
    <div class="row">
      <button onclick="previewAllPosts()">Preview my posts</button>
      <button id="deleteAllButton" onclick="deleteAllPosts()" disabled>Delete previewed posts</button>
    </div>
    <div id="deletePreview" class="mono"></div>
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

    <!-- FIX: these were missing, causing JS errors -->
    <div class="statusbar">
      <div id="spinner" class="spinner"></div>
      <div id="status" class="hint status"></div>
    </div>

    <div id="out" class="mono"></div>
  </div>

<script>
function out(t){
  document.getElementById('out').textContent = t;
}

function setLoading(isLoading, message){
  const spinner = document.getElementById('spinner');
  const status = document.getElementById('status');

  if (spinner) spinner.classList.toggle('on', !!isLoading);
  if (status) status.textContent = isLoading ? (message || 'Working...') : '';

  // Disable all buttons while loading
  document.querySelectorAll('button').forEach(b => b.disabled = !!isLoading);
}

async function readBodyPretty(res){
  const contentType = (res.headers.get('content-type') || '').toLowerCase();

  if (contentType.includes('application/json')) {
    try {
      const j = await res.json();
      return JSON.stringify(j, null, 2);
    } catch (e) { /* fall through */ }
  }

  const text = await res.text();
  try {
    const j = JSON.parse(text);
    return JSON.stringify(j, null, 2);
  } catch (e) {
    return text;
  }
}

async function run(actionName, fn){
  try{
    setLoading(true, actionName);
    const res = await fn();
    const body = await readBodyPretty(res);

    // Always output body; if non-2xx, show status too
    if (!res.ok) {
      out(body || ('Request failed with HTTP ' + res.status));
      return;
    }

    out(body || 'OK');
  } catch (e) {
    out(String(e && e.stack ? e.stack : e));
  } finally {
    setLoading(false);
  }
}

async function showToken(){
  return run('Fetching token...', () => fetch('/token', { method: 'GET' }));
}

async function getMe(){
  return run('Calling /2/users/me...', () => fetch('/me', { method: 'GET' }));
}

async function refreshToken(){
  return run('Refreshing access token...', () => fetch('/refresh', { method: 'POST' }));
}

async function clearToken(){
  return run('Clearing token...', () => fetch('/logout', { method: 'POST' }));
}

async function deleteAllPosts(){
  if (!window.previewedPostCount) {
    out('Preview the posts first.');
    return;
  }
  if (!confirm('Delete every post and reply from the logged-in account? This cannot be undone.')) {
    return;
  }
  return run('Deleting all posts...', () => fetch('/delete-all-posts', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({confirm: 'DELETE'})
  }));
}

async function previewAllPosts(){
  return run('Loading posts for preview...', async () => {
    const res = await fetch('/delete-all-posts/preview', {method: 'GET'});
    if (res.ok) {
      const body = await res.clone().json();
      window.previewedPostCount = body.posts.length;
      document.getElementById('deleteAllButton').disabled = !body.posts.length;
      document.getElementById('deletePreview').textContent = body.posts.length
        ? body.posts.map(p => `${p.id}  ${p.created_at || ''}  ${p.text}`).join('\\n')
        : 'No posts found.';
    }
    return res;
  });
}

async function postText(){
  const text = document.getElementById('text').value;
  return run('Posting tweet...', () => fetch('/tweet', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text})
  }));
}

async function postMedia(){
  const text = document.getElementById('media_text').value;
  const image_url = document.getElementById('image_url').value;
  return run('Uploading media + posting tweet...', () => fetch('/tweet-media', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text, image_url})
  }));
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

    # Headers are logged as JSON, so support both JSON keys and plain text.
    text = re.sub(
        r'("?Authorization"?\s*:\s*"?Basic\s+)[A-Za-z0-9+/=]+("?)',
        r"\1***REDACTED***\2",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r'("?Authorization"?\s*:\s*"?Bearer\s+)[A-Za-z0-9\-_\.]+("?)',
        r"\1***REDACTED***\2",
        text,
        flags=re.IGNORECASE,
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


def configure_user_token(token_data: dict[str, Any]) -> dict[str, Any]:
    """Import an existing OAuth token payload and make it the active token.

    The payload may contain string values, as commonly returned by secret
    stores or templating systems. Imported tokens are marked access-token-only;
    any refresh_token is preserved but never used by API calls. client_id and
    redirect_uri are also accepted and preserved.
    """
    if not isinstance(token_data, dict):
        raise TypeError("token_data must be a dictionary")

    access_token = str(token_data.get("access_token", "")).strip()
    if not access_token or access_token.startswith("{{"):
        raise ValueError("token_data must contain a real access_token")

    normalized = dict(token_data)
    normalized["refresh_enabled"] = False
    normalized["access_token"] = access_token
    if token_data.get("refresh_token"):
        normalized["refresh_token"] = str(token_data["refresh_token"]).strip()

    if token_data.get("expires_at") is not None:
        try:
            normalized["expires_at"] = int(float(token_data["expires_at"]))
        except (TypeError, ValueError) as exc:
            raise ValueError("expires_at must be a Unix timestamp") from exc

    scopes = token_data.get("scopes")
    if isinstance(scopes, str):
        normalized["scopes"] = scopes.split()

    save_token(normalized)
    return normalized


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


def token_request_auth() -> tuple[dict[str, str], dict[str, str]]:
    """Return token headers and form fields for public/confidential clients."""
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    form = {"client_id": CLIENT_ID}

    if OAUTH_CLIENT_TYPE == "confidential":
        # requests handles RFC 7617 encoding and ensures the Authorization
        # header is attached to the actual request sent to X.
        headers["Authorization"] = requests.auth._basic_auth_str(
            CLIENT_ID, CLIENT_SECRET
        )
        # X's confidential-client example authenticates the client in Basic
        # auth; do not send client_id a second time in the form body.
        form.pop("client_id")

    return headers, form


def exchange_code_for_token(code: str, code_verifier: str) -> dict:
    """Exchange auth code for access/refresh token."""
    headers, form = token_request_auth()
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
        **form,
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

    if not resp.ok:
        detail = data.get("error_description") or data.get("error") or resp.text
        raise requests.HTTPError(
            f"X token exchange failed ({resp.status_code}): {detail}",
            response=resp,
        )

    expires_in = int(data.get("expires_in", 0))
    data["expires_at"] = int(time.time()) + max(expires_in - 60, 0)
    data["refresh_enabled"] = True
    return data


def refresh_access_token(refresh_token: str) -> dict[str, Any]:
    """Refresh a browser-authorized token."""
    headers, form = token_request_auth()
    form = {"grant_type": "refresh_token", "refresh_token": refresh_token, **form}
    log_http("TOKEN REFRESH REQUEST", "POST", TOKEN_URL, headers=headers, body=urlencode(form))

    resp = requests.post(TOKEN_URL, headers=headers, data=form, timeout=20)
    data = safe_json(resp)
    log_http(
        "TOKEN REFRESH RESPONSE", "RESPONSE", str(resp.status_code),
        headers=dict(resp.headers), body=json.dumps(data, indent=2),
    )
    if not resp.ok:
        detail = data.get("error_description") or data.get("error") or resp.text
        raise requests.HTTPError(
            f"X token refresh failed ({resp.status_code}): {detail}", response=resp
        )

    expires_in = int(data.get("expires_in", 0))
    data["expires_at"] = int(time.time()) + max(expires_in - 60, 0)
    data["refresh_enabled"] = True
    return data


def get_access_token_or_refresh() -> str:
    """Use an imported token as-is; refresh browser-authorized tokens."""
    token = load_token()
    if not token or not token.get("access_token"):
        raise RuntimeError("No access_token stored. Import or authorize a token first.")

    if token.get("refresh_enabled", True) and not token_is_valid(token):
        if not token.get("refresh_token"):
            raise RuntimeError("Access token expired and no refresh_token is available.")
        new_token = refresh_access_token(token["refresh_token"])
        if "refresh_token" not in new_token:
            new_token["refresh_token"] = token["refresh_token"]
        save_token(new_token)
        return new_token["access_token"]

    return token["access_token"]


def get_authenticated_user(access_token: str) -> requests.Response:
    """Fetch the authenticated user's profile using the OAuth user token."""
    headers = {"Authorization": f"Bearer {access_token}"}

    log_http("ME REQUEST", "GET", USER_ME_URL, headers=headers)
    resp = requests.get(USER_ME_URL, headers=headers, timeout=20)
    log_http(
        "ME RESPONSE",
        "RESPONSE",
        str(resp.status_code),
        headers=dict(resp.headers),
        body=json.dumps(safe_json(resp), indent=2),
    )
    return resp


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

    try:
        token = exchange_code_for_token(code, code_verifier)
    except requests.HTTPError as exc:
        # Do not turn a provider error into an opaque Flask 500 page.
        return jsonify({"error": "oauth_token_exchange_failed", "detail": str(exc)}), 502
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
    """Manually refresh a browser-authorized token."""
    tok = load_token()
    if not tok or not tok.get("refresh_token"):
        return jsonify({"error": "No refresh_token stored. Authorize first."}), 400
    if tok.get("refresh_enabled") is False:
        return jsonify({
            "error": "refresh_disabled",
            "detail": "Imported tokens are access-token-only; import a new access token instead.",
        }), 400

    try:
        new_token = refresh_access_token(tok["refresh_token"])
        if "refresh_token" not in new_token:
            new_token["refresh_token"] = tok["refresh_token"]
        save_token(new_token)
    except requests.HTTPError as exc:
        resp = exc.response
        return jsonify({
            "error": "token_refresh_failed",
            "status": resp.status_code if resp is not None else None,
            "body": safe_json(resp) if resp is not None else None,
        }), 400

    safe = dict(new_token)
    if not PRINT_SECRETS:
        safe["access_token"] = "***REDACTED***"
        safe["refresh_token"] = "***REDACTED***"
    return jsonify({"ok": True, "token": safe})


@app.post("/logout")
def logout() -> Response:
    """Clear stored token."""
    clear_token()
    return jsonify({"ok": True})


@app.post("/delete-all-posts")
def delete_all_posts_route() -> Response:
    """Delete every post and reply belonging to the authenticated account."""
    data = request.get_json(silent=True) or {}
    if data.get("confirm") != "DELETE":
        return jsonify({
            "error": "confirmation_required",
            "detail": 'Send {"confirm": "DELETE"} to confirm deletion.',
        }), 400

    try:
        access = get_access_token_or_refresh()
        me_response = get_authenticated_user(access)
        if not me_response.ok:
            return jsonify({"error": "could_not_identify_user", "body": safe_json(me_response)}), 400

        user = safe_json(me_response).get("data") or {}
        user_id = user.get("id")
        if not user_id:
            return jsonify({"error": "users_me_missing_id", "body": user}), 400

        # Imported here to keep the command-line utility reusable without
        # creating an import cycle while main.py is being loaded.
        from delete_all_posts import delete_posts_for_user

        rate_limit_events: list[str] = []
        result = delete_posts_for_user(user_id, access, rate_limit_events=rate_limit_events)
        return jsonify({
            "ok": not result["failed"],
            "username": user.get("username"),
            "rate_limit_events": rate_limit_events,
            **result,
        }), 200 if not result["failed"] else 207
    except (RuntimeError, requests.RequestException) as exc:
        return jsonify({"error": "delete_all_posts_failed", "detail": str(exc)}), 502


@app.get("/delete-all-posts/preview")
def preview_all_posts_route() -> Response:
    """List the authenticated user's posts without changing anything."""
    try:
        access = get_access_token_or_refresh()
        me_response = get_authenticated_user(access)
        if not me_response.ok:
            return jsonify({"error": "could_not_identify_user", "body": safe_json(me_response)}), 400
        user = safe_json(me_response).get("data") or {}
        user_id = user.get("id")
        if not user_id:
            return jsonify({"error": "users_me_missing_id", "body": user}), 400

        from delete_all_posts import iter_user_posts

        rate_limit_events: list[str] = []
        posts = list(iter_user_posts(user_id, access, rate_limit_events=rate_limit_events))
        return jsonify({
            "username": user.get("username"),
            "posts": posts,
            "rate_limit_events": rate_limit_events,
        })
    except (RuntimeError, requests.RequestException) as exc:
        return jsonify({"error": "preview_failed", "detail": str(exc)}), 502


@app.get("/me")
def authenticated_user() -> Response:
    """Return the X account associated with the stored OAuth token."""
    try:
        access = get_access_token_or_refresh()
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400

    resp = get_authenticated_user(access)
    return jsonify(safe_json(resp)), resp.status_code


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

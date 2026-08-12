# X (Twitter) OAuth Bot

A Flask-based web application that allows you to authenticate with X (formerly Twitter) API v2 using OAuth2 and post tweets programmatically, including support for media uploads (images).

## Features

- **X OAuth2 Authentication**: Secure login flow with automatic token refresh
- **Post Text Tweets**: Send simple text tweets via an intuitive web interface
- **Post Media Tweets**: Upload images and post tweets with media attachments
- **Token Management**: Store tokens locally or in Redis for persistent authentication
- **Web UI**: Single-page HTML interface for easy interaction
- **Secure Token Handling**: Redacts sensitive credentials in logs by default

## Prerequisites

- Python 3.8+
- X Developer Account with API v2 access
- X App credentials (Client ID, Client Secret)
- Redis (optional, only if you want Redis-backed token storage)

## Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd twitter-bot
   ```
2. **Create a virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

## Configuration

1. **Set up environment variables** by copying `.env.sample` to `.env`:

   ```bash
   cp .env.sample .env
   ```

   Then edit `.env` with your values.

   ```env
   CLIENT_ID=your_x_api_client_id
   # Set to public for Native/Single Page apps, confidential for Web/Automated apps
   OAUTH_CLIENT_TYPE=confidential
   # Required only when OAUTH_CLIENT_TYPE=confidential; use the OAuth 2.0 Client Secret
   CLIENT_SECRET=your_x_api_client_secret
   REDIRECT_URI=http://127.0.0.1:5000/oauth/callback
   FLASK_SECRET_KEY=your-secret-key-for-sessions

   # Optional: If set, tokens are stored in Redis (instead of token.json)
   REDIS_URL_DOGS=redis://localhost:6379/0

   # Optional: Local token file (used when REDIS_URL_DOGS is not set)
   TOKEN_FILE=token.json

   # Optional: Set to "1" to print secrets in logs (strongly discouraged)
   PRINT_SECRETS=0
   ```
2. **Get X API Credentials**:

   - Go to [X Developer Portal](https://developer.twitter.com/)
   - Create an app and generate OAuth2 credentials
   - Set the Redirect URI to match your `REDIRECT_URI` environment variable
   - Ensure your app has these OAuth2 scopes enabled:
     - `tweet.read`
     - `tweet.write`
     - `users.read`
     - `media.write`

## Usage

### Starting Redis (optional)

Redis is only required if you set `REDIS_URL_DOGS`. Otherwise the app stores tokens in `token.json`.

**Automated (recommended): Docker Compose**

1. Start Redis:

   ```bash
   docker compose up -d redis
   ```

2. Point your `.env` at it:

   ```env
   REDIS_URL_DOGS=redis://localhost:6379/0
   ```

To stop Redis:

```bash
docker compose down
```

**Manual (no Docker)**

- **macOS (Homebrew)**:

  ```bash
  brew install redis
  brew services start redis
  ```

- **Ubuntu/Debian**:

  ```bash
  sudo apt-get update
  sudo apt-get install -y redis-server
  sudo systemctl enable --now redis-server
  ```

### Start the app

1. **Start the Flask server**

   ```bash
   python main.py
   ```
2. **Open in browser**

   ```
   http://127.0.0.1:5000
   ```
3. **Authorize the app**

   - Click "Authorize / Re-authorize" button
   - Login with your X account
   - Grant permissions when prompted
   - The app will store your token for future use
4. **Post Tweets**

   - **Text Only**: Enter your tweet text and click "Post Tweet"
   - **With Media**: Paste image URL(s) (comma-separated for multiple), add caption, and click "Upload + Tweet"
5. **Manage Tokens**

   - Click "Show stored token" to view current access token
   - Click "Refresh access token" to refresh a browser-authorized token
   - Click "Clear token" to logout and remove stored credentials

### Delete all posts

`delete_all_posts.py` uses the stored OAuth token, verifies the account through
`/2/users/me`, lists that account's posts, and deletes them through the X API.
Replies are included; reposts are a separate action and are not handled.

Preview first:

```bash
python delete_all_posts.py
```

To actually delete the previewed posts:

```bash
python delete_all_posts.py --yes
```

For a small test run, use `--limit 5 --yes`.

The preview/deletion requests wait 4 seconds before each API call by default.
To change that delay, set `DELETE_API_DELAY_SECONDS` in `.env`, for example
`DELETE_API_DELAY_SECONDS=6`. Set it to `0` to disable the delay.

## API Endpoints

- `GET /` - Main page with web UI
- `GET /authorize` - Start OAuth2 authorization flow
- `GET /oauth/callback` - OAuth2 callback endpoint (handled automatically)
- `GET /token` - Retrieve stored token (JSON)
- `POST /refresh` - Force refresh a browser-authorized token
- `POST /logout` - Clear stored token
- `POST /delete-all-posts` - Delete all posts and replies for the authenticated user
- `GET /delete-all-posts/preview` - Preview posts before deletion
- `POST /tweet` - Post a text tweet
  - Body: `{"text": "your tweet text"}`
- `POST /tweet-media` - Post tweet with media
  - Body: `{"text": "caption", "image_url": "https://..."}`

## Token Storage

The app supports two token storage methods:

1. **Local File** (default): Stores tokens in `token.json`
2. **Redis**: If `REDIS_URL_DOGS` is set, tokens are stored in Redis

Browser-authorized tokens are automatically refreshed using the refresh token.
Tokens imported with `configure_user_token` are marked access-token-only and are
never refreshed; import a new access token when one expires.

### Import an existing token

If you already have an OAuth token payload, import it from Python instead of
running the browser authorization flow:

```python
from main import configure_user_token

configure_user_token({
    "client_id": "your_oauth2_client_id",
    "redirect_uri": "https://example.com/access-token",
    "access_token": "your_access_token",
    "refresh_token": "your_refresh_token",
    "expires_at": "1786099703",
    "scopes": "tweet.write media.write users.read tweet.read",
    "token_type": "bearer",
})
```

The function converts `expires_at` to an integer and splits the space-separated
scope string. The access token must be a real value, not a template placeholder
such as `{{token}}`. Any supplied refresh token is preserved but not used by
the imported-token flow.

## Troubleshooting

- **"Missing valid authorization header"**: Set `OAUTH_CLIENT_TYPE=public` and remove `CLIENT_SECRET` for a Native/Single Page app. For a Web/Automated app, set `OAUTH_CLIENT_TYPE=confidential` and use its OAuth 2.0 Client Secret (not the API key secret), then authorize again.
- **Redis connection errors**: Either start Redis (see above) or unset `REDIS_URL_DOGS` to fall back to `token.json`
- **Media upload fails with 4xx error**: Check that your X app has `media.write` permission in OAuth2 scopes
- **CORS or Redirect URI mismatch**: Verify your `REDIRECT_URI` matches exactly in `.env` and X Developer Portal settings

## Development

For development with printed secrets (useful for debugging):

```env
PRINT_SECRETS=1
```

This will show redacted credentials in logs. **Never use this in production.**

## Project Structure

```
twitter-bot/
├── main.py           # Main Flask application
├── .env.sample       # Environment template
├── .env              # Environment configuration (not committed)
├── token.json        # Stored OAuth token (if using file storage)
├── compose.yml       # Optional: Redis container for local dev
├── .gitignore        # Git ignore rules
└── README.md         # This file
```

**Note**: Keep your `CLIENT_ID`, `CLIENT_SECRET`, and tokens secure. Never commit `.env` files or `token.json` to version control.

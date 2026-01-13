# X (Twitter) OAuth Bot

A Flask-based web application that allows you to authenticate with X (formerly Twitter) API v2 using OAuth2 and post tweets programmatically, including support for media uploads (images).

## Features

- **X OAuth2 Authentication**: Secure login flow with automatic token refresh using refresh tokens
- **Post Text Tweets**: Send simple text tweets via an intuitive web interface
- **Post Media Tweets**: Upload images and post tweets with media attachments
- **Token Management**: Store tokens locally or in Redis for persistent authentication
- **Web UI**: Single-page HTML interface for easy interaction
- **Secure Token Handling**: Redacts sensitive credentials in logs by default

## Prerequisites

- Python 3.8+
- X Developer Account with API v2 access
- X App credentials (Client ID, Client Secret)

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
   pip install flask python-dotenv requests
   ```

   Optional: For Redis token storage support

   ```bash
   pip install redis
   ```

## Configuration

1. **Set up environment variables** by creating a `.env` file in the project root:

   ```env
   CLIENT_ID=your_x_api_client_id
   CLIENT_SECRET=your_x_api_client_secret
   REDIRECT_URI=http://localhost:5000/callback
   FLASK_SECRET_KEY=your-secret-key-for-sessions

   # Optional: For production token storage
   REDIS_URL_DOGS=redis://your-redis-url
   TOKEN_FILE=token.json  # Default local file for storing tokens

   # Optional: Set to "1" to print secrets in logs (dev only)
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
     - `offline.access`
     - `media.write`

## Usage

1. **Start the Flask server**

   ```bash
   python main.py
   ```
2. **Open in browser**

   ```
   http://localhost:5000
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
   - Click "Refresh access token" to refresh the access token
   - Click "Clear token" to logout and remove stored credentials

## API Endpoints

- `GET /` - Main page with web UI
- `GET /authorize` - Start OAuth2 authorization flow
- `GET /callback` - OAuth2 callback endpoint (handled automatically)
- `GET /token` - Retrieve stored token (JSON)
- `POST /refresh` - Force refresh access token
- `POST /logout` - Clear stored token
- `POST /tweet` - Post a text tweet
  - Body: `{"text": "your tweet text"}`
- `POST /tweet-media` - Post tweet with media
  - Body: `{"text": "caption", "image_url": "https://..."}`

## Token Storage

The app supports two token storage methods:

1. **Local File** (default): Stores tokens in `token.json`
2. **Redis**: If `REDIS_URL_DOGS` is set and `redis` package is installed, tokens are stored in Redis

Tokens are automatically refreshed using the refresh token, keeping you logged in.

## Troubleshooting

- **"Missing required environment variables"**: Ensure all required `.env` variables are set (CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)
- **Media upload fails with 4xx error**: Check that your X app has `media.write` permission in OAuth2 scopes
- **Token refresh issues**: Ensure `offline.access` scope is enabled in your X app settings
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
├── .env              # Environment configuration (not committed)
├── token.json        # Stored OAuth token (if using file storage)
├── .gitignore        # Git ignore rules
└── README.md         # This file
```

**Note**: Keep your `CLIENT_ID`, `CLIENT_SECRET`, and tokens secure. Never commit `.env` files or `token.json` to version control.

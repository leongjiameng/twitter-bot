"""Preview or delete posts authored by the account with the stored OAuth token."""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any, Iterator

import requests

from main import get_access_token_or_refresh, get_authenticated_user, safe_json


USER_TWEETS_URL = "https://api.x.com/2/users/{user_id}/tweets"
DELETE_TWEET_URL = "https://api.x.com/2/tweets/{tweet_id}"
DEFAULT_API_DELAY_SECONDS = float(os.environ.get("DELETE_API_DELAY_SECONDS", "4"))


def request_with_rate_limit_retry(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, Any] | None = None,
    retries: int = 3,
    rate_limit_events: list[str] | None = None,
    delay_seconds: float = DEFAULT_API_DELAY_SECONDS,
) -> requests.Response:
    """Make a request and retry after HTTP 429 responses."""
    for attempt in range(retries + 1):
        if delay_seconds > 0:
            if rate_limit_events is not None:
                rate_limit_events.append(f"Waiting {delay_seconds:g}s before API request")
            time.sleep(delay_seconds)
        response = requests.request(method, url, headers=headers, params=params, timeout=30)
        if response.status_code != 429 or attempt == retries:
            return response

        wait_seconds = 5
        reset = response.headers.get("x-rate-limit-reset")
        if reset:
            try:
                wait_seconds = max(1, int(float(reset)) - int(time.time()))
            except ValueError:
                pass
        print(f"Rate limited; waiting {wait_seconds}s before retrying...", file=sys.stderr)
        if rate_limit_events is not None:
            rate_limit_events.append(f"Rate limited; waited {wait_seconds}s before retrying")
        time.sleep(wait_seconds)

    raise AssertionError("unreachable")


def iter_user_posts(
    user_id: str,
    access_token: str,
    limit: int | None = None,
    rate_limit_events: list[str] | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield posts authored by user_id, newest first, including replies."""
    headers = {"Authorization": f"Bearer {access_token}"}
    pagination_token: str | None = None
    yielded = 0

    while True:
        params: dict[str, Any] = {"max_results": 100, "tweet.fields": "created_at"}
        if pagination_token:
            params["pagination_token"] = pagination_token

        response = request_with_rate_limit_retry(
            "GET", USER_TWEETS_URL.format(user_id=user_id), headers=headers, params=params,
            rate_limit_events=rate_limit_events,
        )
        if not response.ok:
            raise RuntimeError(
                f"Could not list posts ({response.status_code}): {safe_json(response)}"
            )

        payload = safe_json(response)
        for post in payload.get("data", []):
            yield post
            yielded += 1
            if limit is not None and yielded >= limit:
                return

        pagination_token = (payload.get("meta") or {}).get("next_token")
        if not pagination_token:
            return


def delete_post(
    tweet_id: str,
    access_token: str,
    rate_limit_events: list[str] | None = None,
) -> requests.Response:
    return request_with_rate_limit_retry(
        "DELETE",
        DELETE_TWEET_URL.format(tweet_id=tweet_id),
        headers={"Authorization": f"Bearer {access_token}"},
        rate_limit_events=rate_limit_events,
    )


def delete_posts_for_user(
    user_id: str,
    access_token: str,
    limit: int | None = None,
    rate_limit_events: list[str] | None = None,
) -> dict[str, Any]:
    """Delete posts for a previously verified user and return a summary."""
    posts = list(iter_user_posts(user_id, access_token, limit, rate_limit_events))
    deleted: list[str] = []
    failed: list[dict[str, Any]] = []
    for post in posts:
        response = delete_post(post["id"], access_token, rate_limit_events)
        if response.ok and (safe_json(response).get("data") or {}).get("deleted") is True:
            deleted.append(post["id"])
        else:
            failed.append({"id": post["id"], "response": safe_json(response)})
    return {"found": len(posts), "deleted": deleted, "failed": failed}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Preview or delete posts authored by the logged-in X user."
    )
    parser.add_argument(
        "--yes", action="store_true", help="actually delete posts (preview is the default)"
    )
    parser.add_argument(
        "--limit", type=int, default=None, help="maximum number of posts to process"
    )
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")

    try:
        access_token = get_access_token_or_refresh()
        me_response = get_authenticated_user(access_token)
        if not me_response.ok:
            print(f"Could not identify logged-in user: {safe_json(me_response)}", file=sys.stderr)
            return 1
        me = safe_json(me_response).get("data") or {}
        user_id = me.get("id")
        username = me.get("username", "unknown")
        if not user_id:
            print(f"/users/me returned no user ID: {me}", file=sys.stderr)
            return 1
        posts = list(iter_user_posts(user_id, access_token, args.limit))
    except (RuntimeError, requests.RequestException) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Authenticated as @{username} ({user_id})")
    print(f"Found {len(posts)} post(s), including replies.")
    for post in posts:
        text = " ".join(str(post.get("text", "")).split())
        print(f"- {post['id']}  {post.get('created_at', 'unknown date')}  {text[:120]}")

    if not args.yes:
        print("\nDry run: nothing was deleted. Re-run with --yes to delete these posts.")
        return 0

    deleted = failed = 0
    for post in posts:
        response = delete_post(post["id"], access_token)
        if response.ok and (safe_json(response).get("data") or {}).get("deleted") is True:
            deleted += 1
            print(f"Deleted {post['id']}")
        else:
            failed += 1
            print(f"Failed to delete {post['id']}: {safe_json(response)}", file=sys.stderr)

    print(f"Finished: {deleted} deleted, {failed} failed.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Read-only console snapshot client using an authenticated local session."""

import argparse
import ipaddress
import json
import os
from http.cookiejar import CookieJar
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, Request, build_opener


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8001")
    args = parser.parse_args()
    url = urlsplit(args.url)
    if (
        url.scheme != "http"
        or not ipaddress.ip_address(url.hostname).is_loopback
        or url.username
        or url.password
        or url.path not in {"", "/"}
    ):
        parser.error("Use an HTTP loopback console origin")
    token = os.environ.get("CRYPTOWARDEN_DASHBOARD_TOKEN")
    if not token:
        parser.error("Set CRYPTOWARDEN_DASHBOARD_TOKEN to the current console access key")
    origin = args.url.rstrip("/")
    client = build_opener(HTTPCookieProcessor(CookieJar()))
    request = Request(
        origin + "/api/session",
        data=json.dumps({"token": token}).encode(),
        headers={"Content-Type": "application/json", "Origin": origin},
    )
    with client.open(request, timeout=5) as response:
        json.load(response)
    with client.open(origin + "/api/snapshot", timeout=5) as response:
        print(json.dumps(json.load(response), indent=2))


if __name__ == "__main__":
    main()

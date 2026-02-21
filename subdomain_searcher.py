#!/usr/bin/env python3
"""Subdomain searcher using passive and active discovery techniques.

Methods:
1) Certificate Transparency lookup (crt.sh)
2) GitHub code search for referenced hostnames
3) Crawl homepage HTML for matching hostnames
4) DNS brute-force with common prefixes (or custom wordlist)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from typing import Iterable

COMMON_PREFIXES = [
    "www",
    "mail",
    "webmail",
    "smtp",
    "imap",
    "pop",
    "api",
    "app",
    "dev",
    "staging",
    "test",
    "beta",
    "admin",
    "portal",
    "dashboard",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "m",
    "mobile",
    "blog",
    "shop",
    "support",
    "help",
    "status",
    "auth",
    "login",
    "sso",
    "vpn",
    "git",
    "docs",
    "download",
    "forum",
]

HOSTNAME_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if not domain:
        raise ValueError("Domain is empty")
    if "://" in domain:
        domain = urllib.parse.urlparse(domain).hostname or ""
    return domain.strip(".")


def fetch_url(url: str, timeout: float = 8.0) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "subdomain-searcher/1.0",
            "Accept": "application/json,text/html,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
        return response.read().decode("utf-8", errors="ignore")


def discover_from_crtsh(domain: str) -> set[str]:
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    found: set[str] = set()
    try:
        body = fetch_url(url)
        data = json.loads(body)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ssl.SSLError):
        return found

    for entry in data:
        names = entry.get("name_value", "")
        for raw in names.splitlines():
            candidate = raw.strip().lower().lstrip("*.")
            if candidate.endswith(domain):
                found.add(candidate)
    return found


def discover_from_github(domain: str, github_token: str | None = None) -> set[str]:
    """Discover potential subdomains through GitHub code search.

    GitHub code search can surface hardcoded API endpoints in public repos.
    Authentication is optional, but improves rate limits and compatibility.
    """
    query = urllib.parse.quote(f'".{domain}" in:file', safe="")
    url = f"https://api.github.com/search/code?q={query}&per_page=100"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "subdomain-searcher/1.0",
            "Accept": "application/vnd.github+json",
            **({"Authorization": f"Bearer {github_token}"} if github_token else {}),
        },
    )

    found: set[str] = set()
    try:
        with urllib.request.urlopen(req, timeout=8.0, context=ssl.create_default_context()) as response:
            payload = json.loads(response.read().decode("utf-8", errors="ignore"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, ssl.SSLError):
        return found

    for item in payload.get("items", []):
        text = " ".join(
            [
                str(item.get("name", "")),
                str(item.get("path", "")),
                str(item.get("html_url", "")),
                str(item.get("repository", {}).get("full_name", "")),
            ]
        )
        for host in HOSTNAME_RE.findall(text):
            candidate = host.lower().strip(".")
            if candidate.endswith(domain):
                found.add(candidate)
    return found


def discover_from_homepage(domain: str) -> set[str]:
    found: set[str] = set()
    for url in (f"https://{domain}", f"http://{domain}"):
        try:
            body = fetch_url(url)
        except (urllib.error.URLError, TimeoutError, ssl.SSLError):
            continue
        for host in HOSTNAME_RE.findall(body):
            host = host.lower().strip(".")
            if host.endswith(domain):
                found.add(host)
        if found:
            break
    return found


def resolve_hostname(host: str, timeout: float = 2.0) -> bool:
    default_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False
    finally:
        socket.setdefaulttimeout(default_timeout)


def discover_bruteforce(domain: str, prefixes: Iterable[str], workers: int = 25) -> set[str]:
    candidates = [f"{prefix.strip().lower()}.{domain}" for prefix in prefixes if prefix.strip()]
    found: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(resolve_hostname, host): host for host in candidates}
        for future in concurrent.futures.as_completed(future_map):
            host = future_map[future]
            try:
                if future.result():
                    found.add(host)
            except Exception:
                pass
    return found


def load_wordlist(path: str | None) -> list[str]:
    if not path:
        return COMMON_PREFIXES
    with open(path, "r", encoding="utf-8") as fh:
        values = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    return values or COMMON_PREFIXES


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find subdomains using certificate transparency, page scraping, and DNS brute-force."
    )
    parser.add_argument("domain", help="Root domain to inspect (e.g. example.com)")
    parser.add_argument("--wordlist", help="Optional file with one subdomain prefix per line")
    parser.add_argument("--workers", type=int, default=25, help="Worker threads for DNS brute-force")
    parser.add_argument(
        "--github-token",
        default=None,
        help="Optional GitHub token for higher API limits when using GitHub search",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    domain = normalize_domain(args.domain)
    prefixes = load_wordlist(args.wordlist)

    sources: dict[str, set[str]] = defaultdict(set)

    crt = discover_from_crtsh(domain)
    for host in crt:
        sources[host].add("crt.sh")

    gh = discover_from_github(domain, github_token=args.github_token)
    for host in gh:
        sources[host].add("github")

    page = discover_from_homepage(domain)
    for host in page:
        sources[host].add("homepage")

    brute = discover_bruteforce(domain, prefixes, workers=max(1, args.workers))
    for host in brute:
        sources[host].add("dns")

    all_hosts = sorted(sources.keys())

    if args.json:
        print(
            json.dumps(
                {
                    "domain": domain,
                    "count": len(all_hosts),
                    "subdomains": [
                        {"host": host, "sources": sorted(sources[host])} for host in all_hosts
                    ],
                },
                indent=2,
            )
        )
    else:
        print(f"Domain: {domain}")
        print(f"Discovered subdomains: {len(all_hosts)}")
        for host in all_hosts:
            print(f"- {host} [{', '.join(sorted(sources[host]))}]")

    return 0


if __name__ == "__main__":
    sys.exit(main())

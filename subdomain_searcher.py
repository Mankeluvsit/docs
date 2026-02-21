#!/usr/bin/env python3
"""Subdomain searcher using passive and active discovery techniques.

Methods:
1) Certificate Transparency lookup (crt.sh)
2) GitHub code search for hostnames mentioning the target domain
3) Crawl homepage HTML for matching hostnames
4) DNS brute-force with common prefixes (or custom wordlist)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
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
    domain = domain.strip(".")
    if not domain or "." not in domain:
        raise ValueError("Domain must look like example.com")
    return domain


def fetch_url(url: str, timeout: float = 8.0, headers: dict[str, str] | None = None) -> str:
    request_headers = {
        "User-Agent": "subdomain-searcher/1.1",
        "Accept": "application/json,text/html,*/*",
    }
    if headers:
        request_headers.update(headers)

    req = urllib.request.Request(url, headers=request_headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
        return response.read().decode("utf-8", errors="ignore")


def extract_domain_hosts(text: str, domain: str) -> set[str]:
    found: set[str] = set()
    suffix = f".{domain}"
    for host in HOSTNAME_RE.findall(text):
        host = host.lower().strip(".")
        if host == domain or host.endswith(suffix):
            found.add(host)
    return found


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
            if candidate == domain or candidate.endswith(f".{domain}"):
                found.add(candidate)
    return found


def discover_from_github(domain: str, github_token: str | None = None) -> set[str]:
    """Use GitHub's public code search API to find hostnames that mention this domain."""
    query = urllib.parse.quote(f'".{domain}" in:file')
    url = f"https://api.github.com/search/code?q={query}&per_page=100"
    headers = {"Accept": "application/vnd.github+json"}
    token = github_token or os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        body = fetch_url(url, headers=headers)
        data = json.loads(body)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ssl.SSLError):
        return set()

    found: set[str] = set()
    for item in data.get("items", []):
        # We can parse URL/path metadata and any text fragments returned.
        for field in ("name", "path", "html_url", "url", "git_url"):
            value = item.get(field)
            if isinstance(value, str):
                found.update(extract_domain_hosts(value, domain))

        for match in item.get("text_matches", []):
            fragment = match.get("fragment")
            if isinstance(fragment, str):
                found.update(extract_domain_hosts(fragment, domain))

    return found


def discover_from_homepage(domain: str) -> set[str]:
    for url in (f"https://{domain}", f"http://{domain}"):
        try:
            body = fetch_url(url)
        except (urllib.error.URLError, TimeoutError, ssl.SSLError):
            continue
        return extract_domain_hosts(body, domain)
    return set()


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
        description="Find subdomains via crt.sh, GitHub, homepage scraping, and DNS brute-force."
    )
    parser.add_argument("domain", help="Root domain to inspect (e.g. example.com)")
    parser.add_argument("--wordlist", help="Optional file with one subdomain prefix per line")
    parser.add_argument("--workers", type=int, default=25, help="Worker threads for DNS brute-force")
    parser.add_argument("--github-token", help="Optional GitHub token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    prefixes = load_wordlist(args.wordlist)

    sources: dict[str, set[str]] = defaultdict(set)

    for host in discover_from_crtsh(domain):
        sources[host].add("crt.sh")

    for host in discover_from_github(domain, github_token=args.github_token):
        sources[host].add("github")

    for host in discover_from_homepage(domain):
        sources[host].add("homepage")

    for host in discover_bruteforce(domain, prefixes, workers=max(1, args.workers)):
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

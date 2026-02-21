import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import json

import subdomain_searcher as s


def test_normalize_domain_accepts_url_and_strips_dots():
    assert s.normalize_domain("https://API.Example.com./path") == "api.example.com"


def test_discover_from_crtsh_parses_entries(monkeypatch):
    payload = json.dumps(
        [
            {"name_value": "*.api.example.com\nmail.example.com"},
            {"name_value": "unrelated.org"},
        ]
    )

    monkeypatch.setattr(s, "fetch_url", lambda _url: payload)

    result = s.discover_from_crtsh("example.com")
    assert result == {"api.example.com", "mail.example.com"}


def test_discover_from_homepage_extracts_hosts(monkeypatch):
    html = "Visit https://portal.example.com and cdn.example.com for static assets."
    monkeypatch.setattr(s, "fetch_url", lambda _url: html)

    result = s.discover_from_homepage("example.com")
    assert result == {"portal.example.com", "cdn.example.com"}


def test_discover_bruteforce_uses_resolver(monkeypatch):
    def fake_resolve(host, timeout=2.0):
        return host in {"api.example.com", "www.example.com"}

    monkeypatch.setattr(s, "resolve_hostname", fake_resolve)

    result = s.discover_bruteforce("example.com", ["api", "www", "bad"], workers=2)
    assert result == {"api.example.com", "www.example.com"}


def test_discover_from_github_parses_items(monkeypatch):
    class DummyResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def read(self):
            return json.dumps(
                {
                    "items": [
                        {
                            "name": "subdomains.md",
                            "path": "infra/prod/endpoints.md",
                            "html_url": "https://api.example.com/docs uses portal.example.com",
                            "repository": {"full_name": "org/repo"},
                        }
                    ]
                }
            ).encode("utf-8")

    monkeypatch.setattr(s.urllib.request, "urlopen", lambda *args, **kwargs: DummyResponse())

    result = s.discover_from_github("example.com")
    assert {"api.example.com", "portal.example.com"}.issubset(result)


def test_load_wordlist_filters_comments(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("# comment\napi\n\nwww\n", encoding="utf-8")

    result = s.load_wordlist(str(wl))
    assert result == ["api", "www"]

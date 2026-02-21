import json
import unittest
from unittest.mock import patch

import subdomain_searcher as s


class TestSubdomainSearcher(unittest.TestCase):
    def test_normalize_domain_handles_url(self):
        self.assertEqual(s.normalize_domain("https://Blog.Example.com/abc"), "blog.example.com")

    def test_normalize_domain_rejects_invalid(self):
        with self.assertRaises(ValueError):
            s.normalize_domain("localhost")

    def test_extract_domain_hosts(self):
        text = "api.example.com and test.other.com and EXAMPLE.com"
        self.assertEqual(s.extract_domain_hosts(text, "example.com"), {"api.example.com", "example.com"})

    @patch("subdomain_searcher.fetch_url")
    def test_discover_from_crtsh(self, mock_fetch):
        mock_fetch.return_value = json.dumps(
            [
                {"name_value": "*.api.example.com\nexample.com"},
                {"name_value": "dev.example.com"},
                {"name_value": "other.com"},
            ]
        )
        found = s.discover_from_crtsh("example.com")
        self.assertEqual(found, {"api.example.com", "example.com", "dev.example.com"})

    @patch("subdomain_searcher.fetch_url")
    def test_discover_from_github(self, mock_fetch):
        mock_fetch.return_value = json.dumps(
            {
                "items": [
                    {
                        "path": "configs/subdomains.txt",
                        "text_matches": [{"fragment": "api.example.com and https://cdn.example.com/assets"}],
                    }
                ]
            }
        )
        found = s.discover_from_github("example.com")
        self.assertEqual(found, {"api.example.com", "cdn.example.com"})

    @patch("subdomain_searcher.fetch_url")
    def test_discover_from_homepage(self, mock_fetch):
        mock_fetch.return_value = "<a href='https://portal.example.com'>Portal</a>"
        found = s.discover_from_homepage("example.com")
        self.assertEqual(found, {"portal.example.com"})

    @patch("subdomain_searcher.resolve_hostname")
    def test_discover_bruteforce(self, mock_resolve):
        mock_resolve.side_effect = lambda host: host.startswith("www")
        found = s.discover_bruteforce("example.com", ["www", "api"], workers=2)
        self.assertEqual(found, {"www.example.com"})


if __name__ == "__main__":
    unittest.main()

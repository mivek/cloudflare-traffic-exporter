import io
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from exporter import Config, Exporter, build_query, fetch

ZONE = "0123456789abcdef0123456789abcdef"


class ExporterTest(unittest.TestCase):
    def setUp(self):
        self.config = Config(
            zone_id=ZONE, host="example.com", token_file="/unused",
            excluded_ips=("192.0.2.10",), excluded_paths=("/robots.txt",),
            excluded_path_prefixes=("/assets/",), excluded_path_suffixes=(".css",),
        )

    def test_query_uses_configured_filters(self):
        query = build_query(self.config, "2026-10-03T13:00:00Z", "2026-10-03T13:15:00Z")
        for expected in (
            'clientRequestHTTPHost: "example.com"', 'edgeResponseStatus: 200',
            'verifiedBotCategory: ""', 'requestSource: "eyeball"',
            'clientIP_neq: "192.0.2.10"',
            'clientRequestPath_notlike: "/assets/%"',
            'clientRequestPath_notlike: "%.css"',
            'clientRequestPath_neq: "/robots.txt"', 'limit: 1000',
        ):
            self.assertIn(expected, query)

    def test_count_is_aggregate_and_not_ip_label(self):
        response = {"data": {"viewer": {"zones": [{"httpRequestsAdaptiveGroups": [
            {"dimensions": {"clientIP": "192.0.2.1"}},
            {"dimensions": {"clientIP": "192.0.2.2"}},
        ]}]}}}
        with patch("exporter.urlopen", return_value=io.BytesIO(json.dumps(response).encode())):
            count, capped = fetch(self.config, "token", datetime(2026, 10, 3, 13, 20, tzinfo=timezone.utc))
        self.assertEqual((count, capped), (2, 0))
        instance = Exporter(self.config)
        instance.unique_ips = count
        metrics = instance.metrics().decode()
        self.assertIn('cloudflare_traffic_distinct_client_ips{host="example.com",zone="' + ZONE + '"} 2', metrics)
        self.assertNotIn("192.0.2.", metrics)

    def test_api_error_does_not_become_zero(self):
        with patch("exporter.urlopen", return_value=io.BytesIO(b'{"errors":[{"message":"forbidden"}]}')):
            with self.assertRaises(ValueError):
                fetch(self.config, "token", datetime.now(timezone.utc))
        self.assertNotIn("cloudflare_traffic_distinct_client_ips{", Exporter(self.config).metrics().decode())

    def test_invalid_ip_is_rejected(self):
        with self.assertRaises(ValueError):
            Config(zone_id=ZONE, host="example.com", token_file="/unused", excluded_ips=("bad",)).validate()


if __name__ == "__main__":
    unittest.main()

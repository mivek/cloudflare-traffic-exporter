"""Low-cardinality Prometheus exporter for filtered Cloudflare HTTP analytics."""

import ipaddress
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

API_URL = "https://api.cloudflare.com/client/v4/graphql"
LOG = logging.getLogger(__name__)


def csv(value):
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class Config:
    zone_id: str
    host: str
    token_file: str
    port: int = 8080
    poll_seconds: int = 300
    window_seconds: int = 900
    ingestion_delay_seconds: int = 120
    group_limit: int = 1000
    edge_response_status: int = 200
    exclude_verified_bots: bool = True
    request_source: str = "eyeball"
    excluded_ips: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()
    excluded_path_prefixes: tuple[str, ...] = ()
    excluded_path_suffixes: tuple[str, ...] = ()

    @classmethod
    def from_env(cls):
        env = os.environ
        config = cls(
            zone_id=env["CLOUDFLARE_ZONE_ID"],
            host=env["CLOUDFLARE_HOST"],
            token_file=env.get("CLOUDFLARE_API_TOKEN_FILE", "/var/run/secrets/cloudflare/token"),
            port=int(env.get("PORT", "8080")),
            poll_seconds=int(env.get("POLL_SECONDS", "300")),
            window_seconds=int(env.get("WINDOW_SECONDS", "900")),
            ingestion_delay_seconds=int(env.get("INGESTION_DELAY_SECONDS", "120")),
            group_limit=int(env.get("GROUP_LIMIT", "1000")),
            edge_response_status=int(env.get("EDGE_RESPONSE_STATUS", "200")),
            exclude_verified_bots=env.get("EXCLUDE_VERIFIED_BOTS", "true").lower() == "true",
            request_source=env.get("REQUEST_SOURCE", "eyeball"),
            excluded_ips=csv(env.get("EXCLUDED_IPS", "")),
            excluded_paths=csv(env.get("EXCLUDED_PATHS", "")),
            excluded_path_prefixes=csv(env.get("EXCLUDED_PATH_PREFIXES", "")),
            excluded_path_suffixes=csv(env.get("EXCLUDED_PATH_SUFFIXES", "")),
        )
        config.validate()
        return config

    def validate(self):
        if not re.fullmatch(r"[0-9a-fA-F]{32}", self.zone_id):
            raise ValueError("CLOUDFLARE_ZONE_ID must be a 32-character hex ID")
        if not re.fullmatch(r"[A-Za-z0-9.-]+", self.host):
            raise ValueError("CLOUDFLARE_HOST must be a hostname")
        if not (0 < self.port < 65536 and self.poll_seconds > 0 and
                self.window_seconds > 0 and self.ingestion_delay_seconds >= 0 and
                0 < self.group_limit <= 10000 and 100 <= self.edge_response_status <= 599):
            raise ValueError("Invalid numeric configuration")
        for ip in self.excluded_ips:
            ipaddress.ip_address(ip)
        if any(not path.startswith("/") for path in
               self.excluded_paths + self.excluded_path_prefixes):
            raise ValueError("Excluded paths and prefixes must begin with /")
        if any(not item for item in self.excluded_path_suffixes):
            raise ValueError("Empty path suffix")


def build_query(config, start, end):
    exclusions = [f"{{clientIP_neq: {json.dumps(ip)}}}" for ip in config.excluded_ips]
    exclusions += [f"{{clientRequestPath_neq: {json.dumps(path)}}}"
                   for path in config.excluded_paths]
    exclusions += [f"{{clientRequestPath_notlike: {json.dumps(prefix + '%')}}}"
                   for prefix in config.excluded_path_prefixes]
    exclusions += [f"{{clientRequestPath_notlike: {json.dumps('%' + suffix)}}}"
                   for suffix in config.excluded_path_suffixes]
    filters = [
        f"datetime_geq: {json.dumps(start)}",
        f"datetime_lt: {json.dumps(end)}",
        f"clientRequestHTTPHost: {json.dumps(config.host)}",
        f"edgeResponseStatus: {config.edge_response_status}",
        f"requestSource: {json.dumps(config.request_source)}",
    ]
    if config.exclude_verified_bots:
        filters.append('verifiedBotCategory: ""')
    if exclusions:
        filters.append("AND: [" + ", ".join(exclusions) + "]")
    return ("{ viewer { zones(filter: { zoneTag: " + json.dumps(config.zone_id) +
            " }) { httpRequestsAdaptiveGroups(limit: " + str(config.group_limit) +
            ", filter: { " + ", ".join(filters) +
            " }) { dimensions { clientIP } } } } }")


def fetch(config, token, now):
    end = now - timedelta(seconds=config.ingestion_delay_seconds)
    start = end - timedelta(seconds=config.window_seconds)
    query = build_query(config, start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        end.strftime("%Y-%m-%dT%H:%M:%SZ"))
    request = Request(API_URL, data=json.dumps({"query": query}).encode(),
                      headers={"Authorization": "Bearer " + token,
                               "Content-Type": "application/json",
                               "User-Agent": "cloudflare-traffic-exporter/0.1"},
                      method="POST")
    with urlopen(request, timeout=25) as response:
        result = json.load(response)
    if result.get("errors"):
        raise ValueError("Cloudflare GraphQL returned errors")
    zones = result["data"]["viewer"]["zones"]
    if len(zones) != 1:
        raise ValueError("Unexpected Cloudflare zone count")
    groups = zones[0]["httpRequestsAdaptiveGroups"]
    if not isinstance(groups, list) or any(
            not group.get("dimensions", {}).get("clientIP") for group in groups):
        raise ValueError("Invalid Cloudflare client IP groups")
    # Client IPs exist only in the API response; they never become metric labels.
    return len(groups), int(len(groups) == config.group_limit)


class Exporter:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.unique_ips = None
        self.capped = 0
        self.last_success = 0
        self.errors = 0

    def refresh(self):
        with open(self.config.token_file, encoding="utf-8") as secret:
            token = secret.read().strip()
        if not token:
            raise ValueError("Cloudflare API token is empty")
        count, capped = fetch(self.config, token, datetime.now(timezone.utc))
        with self.lock:
            self.unique_ips = count
            self.capped = capped
            self.last_success = time.time()
        LOG.info("Analytics refreshed: distinct client IPs=%d; capped=%d", count, capped)

    def run(self):
        while True:
            try:
                self.refresh()
            except Exception as error:
                with self.lock:
                    self.errors += 1
                # Avoid leaking token, response body, or visitor IPs to logs.
                LOG.warning("Analytics refresh failed: %s", type(error).__name__)
            time.sleep(self.config.poll_seconds)

    def metrics(self):
        with self.lock:
            count, capped = self.unique_ips, self.capped
            last_success, errors = self.last_success, self.errors
        labels = '{host=' + json.dumps(self.config.host) + ',zone=' + json.dumps(self.config.zone_id) + '}'
        lines = [
            "# HELP cloudflare_traffic_last_success_timestamp_seconds Unix time of the latest successful query.",
            "# TYPE cloudflare_traffic_last_success_timestamp_seconds gauge",
            f"cloudflare_traffic_last_success_timestamp_seconds{labels} {last_success}",
            "# HELP cloudflare_traffic_refresh_errors_total Failed analytics refresh attempts.",
            "# TYPE cloudflare_traffic_refresh_errors_total counter",
            f"cloudflare_traffic_refresh_errors_total{labels} {errors}",
        ]
        if count is not None:
            lines += [
                "# HELP cloudflare_traffic_distinct_client_ips Distinct client IP groups in the configured rolling window; adaptive analytics may sample.",
                "# TYPE cloudflare_traffic_distinct_client_ips gauge",
                f"cloudflare_traffic_distinct_client_ips{labels} {count}",
                "# HELP cloudflare_traffic_group_limit_reached Whether the GraphQL group limit was reached; count is then a lower bound.",
                "# TYPE cloudflare_traffic_group_limit_reached gauge",
                f"cloudflare_traffic_group_limit_reached{labels} {capped}",
            ]
        return ("\n".join(lines) + "\n").encode()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = Config.from_env()
    exporter = Exporter(config)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/metrics":
                body = exporter.metrics()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/healthz":
                self.send_response(200)
                self.end_headers()
            else:
                self.send_error(404)

        def log_message(self, *args):
            pass

    threading.Thread(target=exporter.run, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", config.port), Handler).serve_forever()


if __name__ == "__main__":
    main()

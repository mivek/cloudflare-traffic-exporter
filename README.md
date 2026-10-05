# Cloudflare traffic exporter

A small Prometheus exporter for a **filtered, rolling count of distinct Cloudflare client IPs**. It is intended for alerts about distributed traffic on one hostname. It does not export individual IP addresses as labels or logs.

Cloudflare also publishes an [official Prometheus exporter](https://github.com/cloudflare/cloudflare-prometheus-exporter). Use that for its broad zone, hostname, firewall, and Worker metrics. Its published metric set does not include the filtered per-hostname client-IP-group count provided here.

## How it works

Every poll, the exporter queries Cloudflare GraphQL `httpRequestsAdaptiveGroups`, grouped by `clientIP`. It counts returned groups for a configurable rolling window and exposes a single gauge per configured zone and hostname. Filters can select an edge response status, request source, unverified bots, and exclude specific IPs or paths. Cloudflare adaptive analytics may sample, so this is an estimate. If the result reaches `GROUP_LIMIT`, the count is a lower bound and `cloudflare_traffic_group_limit_reached` is 1. This is an analytics signal, not a count of requests reaching your origin.

The exporter runs **one instance per zone and hostname**. It needs an API token with Cloudflare Analytics read permission for that zone. Store the token in a readable file and set `CLOUDFLARE_API_TOKEN_FILE`; never put it in the image or Git.

## Run

```sh
export CLOUDFLARE_ZONE_ID=0123456789abcdef0123456789abcdef
export CLOUDFLARE_HOST=example.com
export CLOUDFLARE_API_TOKEN_FILE=/path/to/token
python3 exporter.py
```

`GET /metrics` exposes Prometheus text; `GET /healthz` checks the HTTP process. Readiness of the analytics query is visible in `cloudflare_traffic_last_success_timestamp_seconds`. A failed query leaves the last count intact, so alert rules should require a recent last-success timestamp.

Build a container with `docker build -t cloudflare-traffic-exporter:0.1.0 .`. Mount the token file at the configured path. No third-party Python packages are required.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CLOUDFLARE_ZONE_ID` | required | 32-character zone ID |
| `CLOUDFLARE_HOST` | required | Exact requested hostname |
| `CLOUDFLARE_API_TOKEN_FILE` | `/var/run/secrets/cloudflare/token` | Token file |
| `PORT` | `8080` | Metrics HTTP port |
| `POLL_SECONDS` | `300` | Query interval |
| `WINDOW_SECONDS` | `900` | Rolling window |
| `INGESTION_DELAY_SECONDS` | `120` | Delay before the window ends |
| `GROUP_LIMIT` | `1000` | Maximum returned IP groups; max 10,000 |
| `EDGE_RESPONSE_STATUS` | `200` | Edge HTTP status |
| `EXCLUDE_VERIFIED_BOTS` | `true` | Require empty `verifiedBotCategory` |
| `REQUEST_SOURCE` | `eyeball` | Cloudflare request source |
| `EXCLUDED_IPS` | empty | Comma-separated probe/client IPs |
| `EXCLUDED_PATHS` | empty | Comma-separated exact paths |
| `EXCLUDED_PATH_PREFIXES` | empty | Comma-separated prefixes |
| `EXCLUDED_PATH_SUFFIXES` | empty | Comma-separated suffixes |

Path exclusions use Cloudflare's `notlike` filter. Prefix and suffix values are converted to `prefix%` and `%suffix`. Paths do not include query strings. Excluded IPs are configured per installation; there is no hard-coded blocklist.

## Metrics

All metrics carry only `host` and `zone` labels:

- `cloudflare_traffic_distinct_client_ips`: filtered IP group count for the configured window; absent until first successful query.
- `cloudflare_traffic_group_limit_reached`: 1 when the group limit was hit.
- `cloudflare_traffic_last_success_timestamp_seconds`: Unix timestamp of last successful query; 0 before first success.
- `cloudflare_traffic_refresh_errors_total`: failed refresh attempts.

For a 15-minute window, an example PromQL alert is:

```promql
(cloudflare_traffic_distinct_client_ips{host="example.com"} > 80)
and on (host, zone)
(time() - cloudflare_traffic_last_success_timestamp_seconds{host="example.com"} < 600)
```

Set the threshold from your own traffic baseline. The count includes only requests matching your filters; an empty `verifiedBotCategory` does not prove the visitor is malicious. A query using the same filters in Cloudflare GraphQL is the safest way to check whether the result matches expected traffic.

## Test

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile exporter.py
```

The tests use mocked API responses and do not need a token.

## Contributing and releases

Use [Conventional Commits](https://www.conventionalcommits.org/) for commits and
pull request titles, for example `feat(filters): support a new path exclusion`
or `fix(graphql): retain the last valid sample`. CI checks every PR commit and
the PR title. Configure GitHub branch protection to require the `test`,
`commits`, and `title` checks before merging into `main`; workflow checks alone
do not prevent an administrator from bypassing them.

After tests pass on `main`, [semantic-release](https://semantic-release.gitbook.io/semantic-release/)
analyzes commits, creates a `vX.Y.Z` tag and GitHub release, and publishes
`ghcr.io/<owner>/<repository>:X.Y.Z` and `:latest` images. `feat` increments
the minor version; `fix`, `refactor`, `chore(deps)`, and `docs(README)` increment
the patch version. A `BREAKING CHANGE:` footer increments the major version.
No npm package is published; npm is used only for release tooling. The workflow
uses GitHub's repository token with package-write permission, so no extra
registry credential is needed. Enable public visibility for the GHCR package
if people outside your account should pull it anonymously.

The first release version is selected by semantic-release from the repository
history. After that release, update any deployment that references a provisional
image tag to the actual published version.

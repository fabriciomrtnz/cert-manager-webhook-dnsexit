# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-07-25

### Fixed

- **DNS-01 challenges always failed with `code=3` — no certificate could ever be
  issued.** `createTXT` sent `"ttl": 0`. The DNSExit API expects `ttl` in
  **minutes** (multiplied by 60 server-side) and requires `>= 1`, so every
  `Present` call was rejected:

  ```text
  [DNSEXIT] Sending create payload: {"add":{"content":"...","name":"_acme-challenge","overwrite":false,"ttl":0,"type":"TXT"},"domain":"example.com"}
  [DNSEXIT] Response status: 200, body:
  {"code":3,"message":"Missing Required Parameters - ttl must be >= 1 (ttl is in minutes; the value is multiplied by 60 internally)"}
  ```

  The pod itself was healthy — the APIService was available, RBAC was correct and
  cert-manager reached the solver. Only the payload was invalid, so cert-manager
  retried indefinitely and the `Challenge` resources never left `pending`.

  Fixed by introducing `dnsexitTTLMinutes = 1` (60 seconds, the shortest DNSExit
  accepts) and sending it as the `ttl`.

- **`CleanUp` deleted sibling challenge records.** `deleteTXT` sent only `type`
  and `name`, which removes *every* TXT record at that name. Because `createTXT`
  intentionally uses `overwrite: false` so that apex and wildcard values coexist
  on the same `_acme-challenge` name, cleaning up one finished challenge wiped
  the value belonging to the other, still-pending challenge. `deleteTXT` now also
  sends the record `content` to scope the deletion. Signature changed to
  `deleteTXT(apiKey, zone, name, value string)`.

### Added

- `.dockerignore` — keeps `apiserver.local.config/` (which holds a generated
  **private key** from local `go run` sessions) and other local artifacts out of
  the Docker build context.
- README: "DNSExit API quirks" section documenting the minutes-based TTL, the
  HTTP-200-on-error behaviour, and the `overwrite` / `content` requirements.
- README: troubleshooting entry for `code=3 Missing Required Parameters`.

## [0.1.0] - 2026-07-24

### Added

- Initial release: ACME DNS-01 solver webhook for cert-manager backed by the
  DNSExit DNS API.
- Apex + wildcard support via `overwrite: false` on TXT `add`.
- Authoritative success checking on the JSON `code` field rather than the HTTP
  status.
- Deployment manifests under `deploy/` and examples under `deploy/example/`.

[0.1.1]: https://github.com/fabriciomrtnz/cert-manager-webhook-dnsexit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/fabriciomrtnz/cert-manager-webhook-dnsexit/releases/tag/v0.1.0

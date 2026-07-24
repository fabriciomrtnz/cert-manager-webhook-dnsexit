# cert-manager webhook for DNSExit

An [ACME DNS-01](https://cert-manager.io/docs/configuration/acme/dns01/) solver
webhook for [cert-manager](https://cert-manager.io/) that provisions the
`_acme-challenge` TXT records through the
[DNSExit DNS API](https://dnsexit.com/dns/dns-api/).

Use it to issue Let's Encrypt (or any ACME CA) certificates — including
**wildcard** certificates — for domains whose DNS is hosted at DNSExit.

## Features

- DNS-01 challenge solving via the DNSExit JSON API (`https://api.dnsexit.com/dns/`).
- Correct handling of **apex + wildcard** certificates (e.g. `example.com` and
  `*.example.com`), which place two different TXT values on the same
  `_acme-challenge` record. The webhook adds both without overwriting.
- Authoritative success checking: DNSExit returns HTTP 200 even on logical
  errors, so the response `code` field is parsed (`0` = success).
- Minimal, static, non-root container image.

## How it works

cert-manager calls this webhook's `Present` / `CleanUp` methods during a DNS-01
challenge. The webhook reads your DNSExit API key from a Kubernetes Secret and
creates or deletes the challenge TXT record via the DNSExit API. The zone and
record name are derived from the resolved challenge FQDN and zone.

## DNSExit API quirks

The [DNSExit DNS API](https://dnsexit.com/dns/dns-api/) has a few behaviours that
are easy to get wrong. They are handled by this webhook, and documented here
because they cost real debugging time.

| Behaviour | Detail |
| --- | --- |
| `ttl` is in **minutes**, not seconds | The value is multiplied by 60 server-side and must be `>= 1`. Sending `0` returns `code=3 Missing Required Parameters`. This webhook sends `1` (60s), the shortest allowed — good for ACME, since stale challenge records expire quickly. |
| HTTP 200 does **not** mean success | Logical failures still return `200 OK`. The JSON `code` field is authoritative: `0` = success, anything else = error. |
| `add` needs `overwrite: false` | An apex + wildcard certificate places two different TXT values on the same `_acme-challenge` name. `overwrite: true` clobbers the first one and the apex challenge fails. |
| `delete` needs `content` | Deleting by `name` alone removes **every** TXT at that name — including the sibling challenge value that is still pending validation. Always scope the delete with the record's `content`. |

## Prerequisites

- A Kubernetes cluster with [cert-manager](https://cert-manager.io/docs/installation/)
  already installed.
- A domain hosted on DNSExit and a **DNS API key**
  (DNSExit dashboard → Settings → DNS API Key).
- To build the image: Go 1.25+ and Docker (or any OCI builder).

> **Namespace note:** The manifests in `deploy/` assume cert-manager runs in the
> `infra` namespace. If yours runs elsewhere (the Helm default is
> `cert-manager`), update every `namespace:` field and the `cert-manager`
> ServiceAccount binding in `deploy/rbac.yaml` accordingly.

## Build

Set your own module path and image reference first (see
[Configuration](#configuration)), then:

```sh
# Build the binary locally
go build -o dnsexit-webhook .

# Or build and push a container image
docker build -t ghcr.io/<your-username>/dnsexit-webhook:v0.1.0 .
docker push ghcr.io/<your-username>/dnsexit-webhook:v0.1.0
```

## Configuration

The Go module is published under a placeholder path. Rename it to your own
before pushing to GitHub:

- `go.mod` — line 1: `module github.com/<your-username>/dnsexit-webhook`
- `main.go` — import: `github.com/<your-username>/dnsexit-webhook/solver`

Other knobs:

- **Image** — set `spec.template.spec.containers[0].image` in
  `deploy/deployment.yaml` to the image you pushed.
- **API group** — the `GROUP_NAME` env var in `deploy/deployment.yaml` must match
  `spec.group` in `deploy/apiservice.yaml` and `groupName` in your ClusterIssuer
  (default: `dnsexit.acme.internal`).

## Deploy

1. Store your DNSExit API key (edit the placeholder first):

   ```sh
   kubectl apply -f deploy/example/dnsexit-credentials-secret.yaml
   ```

2. Deploy the webhook and its supporting resources:

   ```sh
   kubectl apply -f deploy/serviceaccount.yaml
   kubectl apply -f deploy/rbac.yaml
   kubectl apply -f deploy/auth-delegator.yaml
   kubectl apply -f deploy/webhook-serving-cert.yaml
   kubectl apply -f deploy/service.yaml
   kubectl apply -f deploy/deployment.yaml
   kubectl apply -f deploy/apiservice.yaml
   ```

   Confirm the API is available:

   ```sh
   kubectl get apiservice v1alpha1.dnsexit.acme.internal
   # AVAILABLE should be True
   ```

3. Create an issuer that uses the solver, then request a certificate:

   ```sh
   kubectl apply -f deploy/example/clusterissuer.yaml
   kubectl apply -f deploy/example/certificate.yaml
   ```

## Usage

Reference the DNSExit solver from any ACME `Issuer` / `ClusterIssuer`:

```yaml
solvers:
  - dns01:
      webhook:
        groupName: dnsexit.acme.internal
        solverName: dnsexit
        config:
          apiKeySecretRef:
            name: dnsexit-credentials
            key: apiKey
```

Then request certificates as usual, including wildcards:

```yaml
spec:
  dnsNames:
    - example.com
    - "*.example.com"
```

## Verifying and troubleshooting

Watch progress:

```sh
kubectl describe certificate <name>
kubectl get challenges -A
kubectl logs -l app=dnsexit-webhook -n infra
```

- **`code=3 Missing Required Parameters - ttl must be >= 1`** — fixed in v0.1.1.
  The DNSExit `ttl` field is in **minutes** and rejects `0`. Older builds sent
  `"ttl": 0`, so every `Present` failed, cert-manager retried forever and no
  certificate was ever issued. Symptom in the logs:

  ```text
  [DNSEXIT] Sending create payload: {"add":{...,"ttl":0,"type":"TXT"},"domain":"example.com"}
  [DNSEXIT] Response status: 200, body:
  {"code":3,"message":"Missing Required Parameters - ttl must be >= 1 (ttl is in minutes; the value is multiplied by 60 internally)"}
  ```

  Upgrade the image and restart: `kubectl -n infra rollout restart deploy/dnsexit-webhook`.
- **`code=2 API Key Authentication Error`** — wrong or missing API key in the
  `dnsexit-credentials` Secret.
- **Secret read errors** — the webhook ServiceAccount can't read the Secret;
  check that `deploy/rbac.yaml` was applied and the Secret is in cert-manager's
  namespace.
- **Wildcard only gets one value** — make sure you're running this build; the
  TXT `add` uses `overwrite: false` so apex + wildcard values coexist.
- **Pod fails to bind `:443` (permission denied)** — the container runs as a
  non-root user. On most clusters binding 443 works; if not, add the
  `NET_BIND_SERVICE` capability to the container, or pass a high `--secure-port`
  and update `targetPort` in `deploy/service.yaml`.

## Security

Never commit real credentials. `deploy/example/` files contain placeholders
only; keep your real Secret out of version control (see `.gitignore`). If a key
is ever exposed, rotate it in the DNSExit dashboard.

## License

[Apache License 2.0](./LICENSE)

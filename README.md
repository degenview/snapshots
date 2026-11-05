# DegenView Snapshots

A small, secure image host for [DegenView](https://degenview.app) chart snapshots. Point DegenView's
**Settings ▸ Snapshots** at it and the camera menu's *Copy link*, *Open in new tab* and *Tweet image*
actions get short, unguessable links to the chart you shared.

[![Deploy to DigitalOcean](https://www.deploytodo.com/do-btn-blue.svg)](https://cloud.digitalocean.com/apps/new?repo=https://github.com/degenview/snapshots/tree/main)
[![CI](https://github.com/degenview/snapshots/actions/workflows/ci.yml/badge.svg)](https://github.com/degenview/snapshots/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-lightgrey.svg)](LICENSE)

- **One static binary or one container.** Go, no CGO, no Node toolchain; the web UI is embedded.
- **Local disk or S3.** AWS S3, DigitalOcean Spaces, Cloudflare R2, MinIO, anything S3-compatible.
- **SQLite or Postgres** for metadata.
- **First-run setup in the browser.** Storage, retention, limits and tokens are configured in a
  wizard and an admin console, not in a pile of environment variables.
- **Short links:** `https://snaps.example.com/i/Xk3p9QwZtA`: 10 random characters (≈ 2⁵⁹ possibilities).
- **Auto-delete** after a configurable time (1 day … 1 year, or never), enforced on read and swept by a janitor.
- **Per-IP rate limits**, upload tokens, owner delete links, metadata stripped from every image.
- **Security first.** See [Security](#security) and [SECURITY.md](SECURITY.md).

## Quick start

### Docker (local or a small server)

```bash
git clone https://github.com/degenview/snapshots && cd snapshots
docker compose up --build
docker compose logs snapshots | grep "setup token"   # copy the token
open http://localhost:8080/setup
```

Everything (SQLite database, images) lives on the `snapshots-data` volume.
To try the production shape (Postgres + a throwaway S3 API): `docker compose -f compose.full.yaml up --build`
(the file lists the values to type into the wizard).

### Pre-built image and binaries

Tagged releases publish `ghcr.io/degenview/snapshots:<version>` (linux/amd64, arm64) and archives for
Linux, macOS and Windows on the [releases page](https://github.com/degenview/snapshots/releases).

```bash
docker run -d --name snapshots -p 127.0.0.1:8080:8080 -v snapshots-data:/data ghcr.io/degenview/snapshots:latest
```

### DigitalOcean App Platform

Press the **Deploy to DigitalOcean** button at the top. It creates the app and a development Postgres
database, and asks for two secrets:

| Secret | Value |
| --- | --- |
| `SETUP_TOKEN` | any long random string (`openssl rand -hex 24`): unlocks the setup wizard |
| `SECRET_KEY` | any long random string (`openssl rand -hex 32`): encrypts your bucket secret in the database |

App Platform's disk is **ephemeral**, so in the wizard choose *S3-compatible bucket* and create a
[Spaces](https://docs.digitalocean.com/products/spaces/) bucket for the images
(endpoint `https://<region>.digitaloceanspaces.com`). For anything you depend on, replace the
development database with a managed one by changing `DATABASE_URL`.
`PUBLIC_URL` defaults to the app's `ondigitalocean.app` address: set it to your own domain after adding one.

## Connecting DegenView

After setup the wizard (and **Admin ▸ Overview**) shows what to enter in DegenView under
**Settings ▸ Snapshots**:

- **Host address:** `https://snaps.example.com/api/v1/images`
- **Token:** an upload token from **Admin ▸ Tokens** (`dvs_…`), unless you turned the requirement off.

DegenView uploads the PNG once per share, after you agree to send charts to that host. See
DegenView's [snapshot documentation](https://github.com/degenview/degenview/blob/main/docs/snapshots.md)
for the protocol this server implements.

## Configuration

Infrastructure settings are environment variables. Everything else is in the browser.

| Variable | Default | Purpose |
| --- | --- | --- |
| `LISTEN_ADDR` / `PORT` | `:8080` | listen address |
| `DATA_DIR` | `./data` (`/data` in the image) | SQLite file, local images, generated key |
| `DATABASE_URL` | SQLite in `DATA_DIR` | `postgres://…` for Postgres, `sqlite:///path` to place the file |
| `PUBLIC_URL` | set in the wizard | public base URL used in returned links; https unless localhost. When set, it cannot be changed in the UI |
| `SETUP_TOKEN` | random, printed in the log | unlocks the first-run wizard (≥ 16 characters) |
| `SECRET_KEY` | generated in `DATA_DIR` (SQLite only) | encrypts the S3 secret at rest (≥ 32 characters). **Required with Postgres** if you use S3 |
| `TRUSTED_PROXIES` + `CLIENT_IP_HEADER` | unset | see [Behind a proxy](#behind-a-proxy) |
| `LOG_LEVEL` / `LOG_FORMAT` | `info` / `json` | `debug…error` / `json` or `text` |
| `ALLOW_INSECURE_BACKENDS` | `false` | acknowledge plaintext links to backends on other hosts: an `http://` S3 endpoint (otherwise refused) or `sslmode=disable` in `DATABASE_URL` (otherwise a startup warning). Loopback is always allowed |

Backend connections: use an `https://` S3 endpoint and, for a Postgres on another host, `sslmode=verify-full`
(or at least `require`). The driver default, `prefer`, uses TLS when the server offers it but does not verify
it. Set `ALLOW_INSECURE_BACKENDS=true` only for a private network you trust, such as the Compose test stack.

In the admin console: public address, retention (1 day – 1 year – never), upload token requirement,
largest image (default 24 MiB, DegenView's limit), total storage quota, per-IP upload and view
limits, storage backend, tokens and the admin password.

### Behind a proxy

Rate limits are per client IP. By default only the TCP peer address counts, because forwarding
headers can be forged. If a reverse proxy is in front, tell the server which peers may be believed
and which header carries the client address:

```bash
# nginx / Caddy / Traefik on the same host or a private network, X-Forwarded-For
TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8
CLIENT_IP_HEADER=X-Forwarded-For
```

The header is read from the right and the first address that is not a trusted proxy wins, so a client
cannot choose its own identity by sending its own `X-Forwarded-For`. `TRUSTED_PROXIES=*` trusts the
header from any peer (the last entry is the client): use it **only** when the service is reachable
solely through a proxy that sets the header, as on App Platform (`CLIENT_IP_HEADER=do-connecting-ip`).
Without this, everyone behind a proxy shares one rate-limit bucket.

Terminate TLS at the proxy; the service speaks plain HTTP. It sets HSTS itself when the public URL is https.

### Backups and upgrades

State is the database plus the image store. Back up the SQLite file (or Postgres) and the images
directory/bucket. Losing `secret.key` / `SECRET_KEY` only loses the stored S3 secret (re-enter it in
Settings). Migrations run automatically at start; upgrade by replacing the binary or image.

## API

`POST /api/v1/images` with `Content-Type: image/png` and `Authorization: Bearer <token>`:

```bash
curl -X POST https://snaps.example.com/api/v1/images \
  -H "Authorization: Bearer dvs_…" -H "Content-Type: image/png" --data-binary @chart.png
# 201 {"url":"https://snaps.example.com/i/Xk3p9QwZtA","delete_url":"https://snaps.example.com/d/…","expires_at":"2027-02-02T22:36:14Z"}
```

Errors are `{"error":{"code":"…","message":"…"}}`: `401` token missing/invalid, `413` too large,
`415` wrong content type, `422` not a valid PNG, `429` rate limited (with `Retry-After`), `503` busy
or not set up, `507` quota full. The full contract is in [docs/openapi.yaml](docs/openapi.yaml).

`GET /i/{id}` serves the image; `GET /d/{secret}` shows a confirmation page whose button deletes it.
`GET /healthz` (liveness) and `GET /readyz` (database and storage reachable) are for your platform.

## Security

Written so that the obvious bug classes have nowhere to live. Each point is covered by a test.

- **No IDOR.** No endpoint accepts an image id for a state change. Deleting needs the image's own
  24-character secret (stored only as a hash, shown once); admin actions need a session; an upload
  token cannot reach the admin API. Unknown and expired images give the identical `404`.
- **No SQL injection.** Every value is a bound parameter; the only text in SQL is constant. Tests
  push injection strings through every lookup on SQLite and Postgres.
- **No path traversal.** Ids must match `^[0-9A-Za-z]{10}$` before touching storage, and local files are
  accessed through Go's `os.Root`, which cannot be escaped by names, `..` or symlinks.
- **Unguessable links.** 10 characters from `crypto/rand` (rejection-sampled, no modulo bias); there is no
  listing, and views are rate-limited per IP.
- **Uploads are checked, not trusted.** The PNG is parsed chunk by chunk (checksums, structure, limits of
  8192 px a side and 32 megapixels) without decoding pixels, and **rewritten without metadata** (text,
  EXIF, time, private chunks). Size is enforced even for chunked bodies.
- **Safe delivery.** `Content-Type: image/png`, `nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`,
  `Content-Disposition: inline`, `noindex`. S3 images are proxied, so the bucket stays private and expiry is
  always enforced.
- **Admin hardening.** argon2id passwords, 256-bit random session ids stored hashed, `HttpOnly`,
  `SameSite=Strict`, `__Host-` cookie on https, CSRF token plus same-origin checks on every change, login
  throttling, all sessions revoked on password change. Strict CSP: no inline scripts or styles.
- **Setup can't be hijacked.** The wizard needs the setup token and permanently disappears once setup completes.
- **Secrets.** Upload tokens are hashed; the S3 secret is AES-256-GCM encrypted at rest; nothing secret is logged
  (delete links and image ids are redacted from request logs, and logs contain no request bodies).
- **No Host-header trust.** Links use the configured public URL, never the request's `Host`.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Development

```bash
make test          # go test -race ./...  (SQLite; set TEST_POSTGRES_URL to include Postgres)
make lint          # golangci-lint
make run           # http://localhost:8080/setup, setup token "local-dev-setup-token"
make docker        # build the image
```

```
cmd/snapshots/        entry point: serve | healthcheck | version
internal/server/      HTTP: upload, delivery, delete, setup wizard, admin API, middleware
internal/repo, db/    SQL (SQLite + Postgres), embedded migrations
internal/storage/     local (os.Root) and S3 backends
internal/pngcheck/    PNG validation and metadata stripping
internal/ratelimit/   token buckets and client-IP resolution
internal/auth/        tokens, argon2id, sessions, CSRF
internal/settings/    runtime settings, encryption of the S3 secret
internal/janitor/     expiry sweeper
web/                  embedded templates and static files
```

CI runs formatting, `go vet`, golangci-lint, `govulncheck`, the full test suite with `-race` against
SQLite and Postgres, and a container smoke test on every pull request. Releases are cut manually:
**Actions ▸ Release ▸ Run workflow**, enter a version (`1.2.3` or `1.2.3-rc.1`).

### Limits worth knowing

- Rate limiting is in memory and per process: run one instance, or accept that each instance enforces its own limits.
- Metadata and images are not transactional: a crash between the two leaves, at worst, a record without an
  image (a 404 that the janitor removes at expiry).
- Changing where images are stored is blocked while images exist there, so links never silently break.

## License

[AGPL-3.0](LICENSE). If you run a modified version as a public service, you must offer its source to its users.

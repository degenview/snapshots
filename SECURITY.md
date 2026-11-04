# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through
[GitHub security advisories](https://github.com/degenview/snapshots/security/advisories/new).
Do not open a public issue. Include what you found, how to reproduce it and the version. You will get an
acknowledgement within a few days, and credit in the advisory if you want it.

## Scope

In scope: this server (upload, delivery, delete links, setup wizard, admin console), its container image and
release artifacts. Out of scope: your own deployment's TLS, firewalls and DNS, and denial of service by raw
traffic volume.

## Supported versions

Fixes go into the latest release.

## Deployment checklist

- Serve it over HTTPS (terminate TLS at a proxy) and set the public address to the `https://` URL.
- Keep **Require an upload token** on. With it off, anyone who finds the address can store images on your disk or bucket.
- Complete setup immediately after the first start: until then, whoever has the setup token can claim the server.
  Choose it yourself with `SETUP_TOKEN` instead of reading it from the log if the log is shared.
- Configure `TRUSTED_PROXIES` and `CLIENT_IP_HEADER` correctly behind a proxy, or rate limits act on the proxy's address.
- Give the bucket credentials only the access they need (read/write/delete on one bucket) and keep the bucket private.
- Back up the database and the image store; restrict who can read them. Images are private data.
- The setup wizard and storage test make the server contact an endpoint an administrator typed. That is the
  administrator's authority by design; the setup token and admin password protect it.

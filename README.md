# securitytxt-exporter

Prometheus exporter for [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)
`security.txt` files. It follows the multi-target pattern of the
blackbox_exporter: targets live in the Prometheus scrape config, not in a local
config file.

## Usage

The exporter listens on `127.0.0.1:2610` by default, see `-h` for flags.

```sh
go install github.com/digineo/securitytxt-exporter@latest
securitytxt-exporter
```

or with Docker:

```sh
docker run -p 127.0.0.1:2610:2610 ghcr.io/digineo/securitytxt-exporter
```

Inside the container, the image listens on all interfaces, so `-p` decides the
exposure. Flags passed to the container replace that default, so repeat
`-web.listen-address :2610` along with them.

or with the `.deb`/`.rpm` packages from the releases. They install, enable and
start `securitytxt-exporter.service`, which runs as a dynamic user. Flags go
into `/etc/default/securitytxt-exporter`, e.g. for a Prometheus server on
another host (firewall the port to that host):

```sh
ARGS="-web.listen-address 192.0.2.10:2610"
```

- `/probe?target=<host[:port]>` fetches `https://<host>/.well-known/security.txt`
- `/probe?target=...&fingerprint=<hex>` additionally requires the signature to
  be made by the key with this primary key fingerprint
- `/probe?target=...&format=json` returns the result as JSON, including the
  reasons of failed checks
- `/metrics` serves the exporter's own Go/process metrics
- `/` shows the version and a form to probe a domain

The exporter fetches any `https://` host it is asked to, plus the key URIs
listed in the probed files. It only connects to public IP addresses, which also
applies to redirects and the keyserver. Do not expose it publicly: failure
reasons in its JSON output reveal details such as the addresses internal names
resolve to.

The exporter does not check the `Host` header. Web pages in a browser that can
reach it can therefore query it via DNS rebinding. Keep it off workstations, or
stop it after use.

## Metrics

| Metric | Description |
|--------|-------------|
| `securitytxt_probe_success`             | 1 if the file was fetched and has exactly one valid `Expires` field |
| `securitytxt_expires_timestamp_seconds` | `Expires` field as Unix timestamp |
| `securitytxt_signature_valid`           | 1 if the file carries a valid OpenPGP cleartext signature |
| `securitytxt_content_type_valid`        | 1 if the file is served as `text/plain; charset=utf-8` |
| `securitytxt_canonical_valid`           | 1 if the requested URL, not the one after redirects, is listed in a `Canonical` field |

The check metrics are only exported if the probe succeeded. Reasons for
failures are logged.

Following RFC 9116, section 5.4, a file larger than 32 KiB, with more than 1000
lines or with a line longer than 2048 characters fails the probe.

A missing `Canonical` field counts as invalid, although RFC 9116 makes it
optional: without it, a signed file can be replayed on another host.

## Signature verification

The signature is verified against the keys behind the file's `Encryption`
fields, at most 5 of them. Supported URI schemes:

- `https:` fetches an ASCII-armored key
- `openpgp4fpr:` fetches the key from the HKP keyserver given by `-keyserver`.
  Only a key with the given fingerprint is used. keys.openpgp.org strips the
  user IDs of keys whose owner has not verified their email address, which
  makes them unusable here, hence the default keyserver.ubuntu.com.
- `dns:` ([RFC 4501](https://www.rfc-editor.org/rfc/rfc4501)) looks up
  `OPENPGPKEY` records ([RFC 7929](https://www.rfc-editor.org/rfc/rfc7929)) via
  the first nameserver in `/etc/resolv.conf`. The URI's DNS server is ignored,
  and DNSSEC is not validated.

Content outside the signed part, apart from whitespace, fails the check.

Without a `fingerprint` pin, this catches a forgotten re-sign, an expired key or
edited content, but not a compromised web server, DNS zone or redirect that
serves both file and key.

## Prometheus config

```yaml
scrape_configs:
  - job_name: securitytxt
    metrics_path: /probe
    scrape_interval: 1h
    static_configs:
      - targets: [www.digineo.de]
        labels:
          __param_fingerprint: 8118C009C16FABE5FEFD5EABB86B57ADD7BC4A0E
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:2610
```

A probe gets the scrape timeout minus 0.5s, at most 30s. Checks that run out of
time count as failed.

## Alerts

```yaml
- alert: SecurityTxtProbeFailed
  expr: securitytxt_probe_success == 0
- alert: SecurityTxtExpiresSoon
  expr: securitytxt_expires_timestamp_seconds - time() < 30 * 86400
- alert: SecurityTxtInvalid
  expr: |
    securitytxt_signature_valid == 0
    or securitytxt_content_type_valid == 0
    or securitytxt_canonical_valid == 0
```

## Development

```sh
make lint test
```

Pushing a `v*` tag builds archives, `.deb`/`.rpm` packages and multi-arch
images to `ghcr.io/digineo/securitytxt-exporter` via goreleaser. The
`Dockerfile` expects the binary prepared by goreleaser, for a local image run
`goreleaser release --snapshot --clean`.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] - 2026-10-06

### Added

- `/probe?target=<host>` endpoint in the multi-target exporter pattern. It
  fetches `/.well-known/security.txt` and checks the `Expires`, `Canonical`
  and `Content-Type` fields as per RFC 9116, plus the OpenPGP cleartext
  signature.
- Signature verification against the keys behind `Encryption` fields, with
  `https:`, `openpgp4fpr:` (via `-keyserver`) and `dns:` (`OPENPGPKEY`) URIs.
- `fingerprint` parameter to pin the expected signing key.
- `format=json` parameter to return the probe result with the reasons of
  failed checks.
- Index page showing the version and a form to probe a domain.
- Release archives, `.deb`/`.rpm` packages with a hardened systemd unit, and
  multi-arch images on `ghcr.io/digineo/securitytxt-exporter`.

[Unreleased]: https://github.com/digineo/securitytxt-exporter/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/digineo/securitytxt-exporter/releases/tag/v0.1.0

# CPANSec Feed Agent Guide

This repository builds the CPANSec CPAN advisory feed. The production feed is served from:

- https://butterfly.cpansec.org/feed/

## What This Project Does

`cpansec-feed` generates a CPAN security feed JSON document from two upstream data sources:

- CPANSA JSON from `https://github.com/briandfoy/cpan-security-advisory/releases/latest/download/cpan-security-advisory.json`
- A local checkout of `https://github.com/CVEProject/cvelistV5.git`

The generator treats CPANSec-owned CVE records from `cvelistV5` as authoritative. CPANSA advisories are used as fallback data for historical or external-CNA records and for records that are not emitted from the CPANSec CVE path. During generation, affected version ranges are resolved against MetaCPAN release data and cached locally.

Primary outputs are:

- `_site/cpansa.json`: generated feed
- `_site/report.html`: validation/source-decision report
- `_site/schema.json`: schema copy
- `_site/index.html`: minimal landing page
- `var/cpan-security-advisory.json`: downloaded CPANSA input
- `var/metacpan-cache/`: cached MetaCPAN release lists

Do not commit generated output, downloaded upstream data, local package artifacts, or cache directories unless the user explicitly asks for that.

## Important Paths

- `bin/cpansec-feed-run`: production-oriented entry point; refreshes inputs and publishes the site.
- `bin/cpansec-feed-update-data`: downloads CPANSA JSON and clones/pulls `cvelistV5`.
- `bin/cpansec-feed-generate`: generates `cpansa.json` from already available local inputs.
- `lib/CPANSec/Feed/Generator.pm`: core merge, filtering, MetaCPAN lookup, validation, and HTML report logic.
- `lib/CPANSec/Feed/CPANSA.pm`: CPANSA download/load helpers.
- `lib/CPANSec/Feed/DataUpdate.pm`: CPANSA and `cvelistV5` update helpers.
- `lib/CPANSec/Feed/VersionRange.pm`: version range parsing and release matching.
- `lib/CPANSA/Feed/VersionRange.pm`: compatibility wrapper around `CPANSec::Feed::VersionRange`.
- `lib/CPANSec/Feed/FileUtil.pm`: atomic write-if-changed helper.
- `schema.json`: JSON Schema for the generated feed.
- `t/`: focused unit and compatibility tests.
- `debian/`: Debian package, systemd timer/service, autopkgtest metadata, and install rules.
- `Dockerfile`, `Makefile`, `podman_run.sh`, `build-deb.sh`: Debian 13/podman build and test workflow.

## Data Flow

1. `setup.sh` or `bin/cpansec-feed-update-data` refreshes local source data:
   - writes `var/cpan-security-advisory.json`
   - clones or pulls `cvelistV5`
2. `generate.sh` or `bin/cpansec-feed-generate` loads CPANSA JSON and walks `cvelistV5/cves`.
3. CPANSec CVEs are emitted first when they contain usable affected package/version data.
4. CPANSA entries are then included only when they are not already covered, are not DarkPAN, pass sanitization, and can resolve affected releases.
5. MetaCPAN release lists are fetched from `https://fastapi.metacpan.org/release?size=5000` when no fresh cache exists.
6. The feed is validated against `schema.json`.
7. `bin/cpansec-feed-run` writes a site tree. If the configured output dir is named `current`, it stages under `.releases/` and atomically swaps the `current` symlink only when content changed.

## Local Commands

Build the Debian 13 podman image:

```sh
make image
```

Refresh upstream inputs inside podman:

```sh
make setup
```

Generate the feed and report inside podman:

```sh
make generate
```

Run the test suite inside podman:

```sh
make test
```

Build the Debian package:

```sh
make deb
```

Run tests directly when Perl dependencies are already available locally:

```sh
prove -l t/metacpan-cache.t t/version-range.t t/cpansa-json.t t/generator.t t/schema.t t/cpansa-audit.t t/test-cve-compat.t
```

`t/test-cve-compat.t` skips when `Test::CVE` is not installed. Debian package builds use the same test list through `debian/rules`.

## Runtime Configuration

The packaged systemd service reads `/etc/default/cpansec-feed`. Relevant environment variables include:

- `CPANSEC_FEED_STATE_DIR`: state/input directory, default `/var/lib/cpansec-feed` in the package.
- `CPANSEC_FEED_OUTPUT_DIR`: output directory, default `/var/www/cpansec-feed/current` in the package.
- `CPANSEC_FEED_CVELIST_DIR`: local `cvelistV5` checkout path.
- `CPANSEC_FEED_SCHEMA_PATH`: schema path.
- `CPANSEC_FEED_CPANSA_URL`: optional CPANSA source override.
- `CPANSEC_FEED_CVELIST_REPO`: optional `cvelistV5` repo override.
- `CPANSEC_FEED_METACPAN_CACHE_TTL`: MetaCPAN cache TTL in seconds; `0` disables staleness checks.

The systemd timer runs hourly (`OnBootSec=5m`, `OnUnitActiveSec=1h`, `Persistent=true`) but is not auto-enabled by the package.

## Coding Conventions

- This is a Perl 5.36 codebase and uses signatures. Keep new Perl code compatible with that baseline.
- Prefer existing helpers and patterns: `Path::Tiny`, `JSON::MaybeXS`, `write_if_changed`, and existing command-line option style.
- Preserve canonical JSON output and schema validation behavior for generated feeds.
- Keep changes scoped. The generator has production data-quality policy embedded in report decisions; avoid broad refactors unless asked.
- Treat CPANSec CVE data as authoritative over CPANSA source data unless a requested change explicitly revises that policy.
- Be careful with `cvelistV5`, `_site`, `var`, `debian/.debhelper`, and `*.deb` artifacts. They are generated or external data, not normal source edits.
- Network-dependent commands are `make setup`, `make generate` when the MetaCPAN cache is missing/stale, and `make deb` because it builds a container image.

## Testing Guidance

For changes in:

- Version parsing or affected-release matching: run `prove -l t/version-range.t`.
- CPANSA loading/downloading assumptions: run `prove -l t/cpansa-json.t`.
- MetaCPAN cache behavior: run `prove -l t/metacpan-cache.t`.
- Feed compatibility with `Test::CVE`: run `prove -l t/test-cve-compat.t` when `Test::CVE` is installed.
- Generator behavior or schema shape: run `prove -l t/generator.t t/schema.t`, the full `prove -l ...` test list, and, when input data is available, generate `_site/cpansa.json` against `schema.json`.

When changing Debian packaging, also check:

```sh
make deb
```

## Current Repository Notes

At the time this guide was written, the active branch was `deb-packaging`. The working tree already contained untracked package/debug artifacts such as `cpansec-feed_*.deb`, `0.2.0-to-0.2.1.diffoscope`, `debian/cpansec-feed.debhelper.log`, and a test fixture. Do not remove or overwrite unrelated untracked files without explicit user approval.

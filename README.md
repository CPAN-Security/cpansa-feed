# CPANSec::Feed

`CPANSec::Feed` generates a CPAN security feed JSON document from two inputs:

- the latest published CPANSA JSON release from `https://github.com/briandfoy/cpan-security-advisory/releases`
- a local `cvelistV5` checkout for authoritative `CPANSec` CVE records

`CPANSec` CVEs are taken from `cvelistV5` first, and CPANSA is used for enrichment or fallback when needed.

## Repo Workflow

Build the Debian 13 podman image:

```bash
podman build -t cpansec-feed-deb .
```

Refresh local inputs:

```bash
./podman_run.sh './setup.sh'
```

Generate the feed and validation report:

```bash
./podman_run.sh './generate.sh'
```

Outputs in the repo:

- `var/cpan-security-advisory.json`: downloaded CPANSA JSON
- `var/metacpan-cache/`: cached MetaCPAN release lists
- `_site/cpansa.json`: generated feed
- `_site/report.html`: validation report
- `_site/schema.json`: schema copy
- `_site/index.html`: simple landing page
- `_site/cpansa_dev.json`: dev fixture copy

Generated files are only replaced when their contents change. MetaCPAN cache entries are refreshed automatically after 6 hours.

## Debian Package

Build the package inside podman:

```bash
./build-deb.sh
```

Artifacts are written to the parent directory of the repo:

- `../cpansec-feed_0.1.0_all.deb`
- `../cpansec-feed_0.1.0.dsc`
- `../cpansec-feed_0.1.0.tar.xz`
- `../cpansec-feed_0.1.0_amd64.buildinfo`
- `../cpansec-feed_0.1.0_amd64.changes`

Install the package on Debian 13:

```bash
sudo apt install ../cpansec-feed_0.1.0_all.deb
```

The package installs:

- `/usr/bin/cpansec-feed-update-data`
- `/usr/bin/cpansec-feed-generate`
- `/usr/bin/cpansec-feed-run`
- `/usr/share/cpansec-feed/schema.json`
- Perl modules under `/usr/share/perl5/CPANSec/Feed/`

## Systemd Timer

The package installs these units:

- `cpansec-feed.service`
- `cpansec-feed.timer`

The timer uses:

- `OnBootSec=5m`
- `OnUnitActiveSec=1h`
- `Persistent=true`

It is not auto-enabled. Enable it explicitly:

```bash
sudo systemctl enable --now cpansec-feed.timer
```

Service defaults can be overridden in `/etc/default/cpansec-feed`. The packaged service reads that file via `EnvironmentFile=`, so values such as `CPANSEC_FEED_METACPAN_CACHE_TTL=21600` can be changed without editing the unit.

On an installed system, the service writes to:

- `/var/lib/cpansec-feed/cpan-security-advisory.json`
- `/var/lib/cpansec-feed/metacpan-cache/`
- `/var/lib/cpansec-feed/cvelistV5/`
- `/var/www/cpansec-feed/cpansa.json`
- `/var/www/cpansec-feed/report.html`
- `/var/www/cpansec-feed/schema.json`
- `/var/www/cpansec-feed/index.html`

Those generated output files are only replaced when contents change.
MetaCPAN cache entries older than 6 hours are treated as stale and refetched on demand. Set `--metacpan-cache-ttl 0` to disable expiry.

## Tests

Package builds run:

```bash
prove -l t/metacpan-cache.t t/version-range.t t/cpansa-json.t t/test-cve-compat.t
```

`Test::CVE` is not packaged in Debian 13, so `t/test-cve-compat.t` currently skips in the Debian package build.

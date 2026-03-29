# Oxi-Hole

A fast, memory-safe DNS sinkhole written in Rust. Blocks ads, trackers, and malicious domains at the DNS level for every device on your network.

Supports plain DNS (UDP), DNS-over-TLS, DNS-over-HTTPS, and DNS-over-QUIC. Ships as a single static binary with a built-in web dashboard.

> **Early alpha** — under active development. Expect rough edges.

## Features

### DNS Protocol Support

- **Plain DNS** (UDP, port 53)
- **DNS-over-TLS** (DoT, port 853)
- **DNS-over-HTTPS** (DoH, port 443)
- **DNS-over-QUIC** (DoQ, port 853/UDP)
- Dual-stack IPv4/IPv6 listening on all protocols
- Multiple listen addresses per protocol

### Ad & Tracker Blocking

- Network-wide blocking via DNS sinkhole
- Supports hosts-file, Adblock, and AdGuard filter syntax
- Multiple blocklist sources (URLs or local files)
- Custom blocked domains and allowlist
- Automatic blocklist refresh on a configurable interval
- One-click feature toggles:
  - Ads, malware & trackers
  - NSFW content
  - Safe search enforcement (Google, Bing, DuckDuckGo)
  - YouTube restricted mode
  - Root server resolution (queries root DNS directly, bypassing third-party upstreams)

### Blocking Modes

Choose how blocked queries are answered:

| Mode | Behavior |
|------|----------|
| Default | 0.0.0.0 / :: (adblock-style) |
| Refused | DNS REFUSED response |
| NxDomain | NXDOMAIN (domain does not exist) |
| NullIp | Always 0.0.0.0 / :: |
| CustomIp | User-specified IPv4/IPv6 address |

All modes are changeable at runtime without restart.

### IPv6 Control

- AAAA response filtering toggle — disable to strip IPv6 records from DNS answers
- Dual-stack listen addresses by default (`0.0.0.0` + `[::]`)
- IPv6 root server fallback resolution

### Reliable Auto-Update

Updates are designed to never leave you with a broken DNS server:

1. **Download** the new binary for your platform
2. **Health-check** — the new binary is started with `--health-check`, which verifies config loading, upstream resolution, and end-to-end DNS queries. A 30-second timeout kills stalled checks.
3. **Replace** — on Linux, the old binary inode is unlinked (safe while running) and the new binary is written. A `.bak` backup is created.
4. **Zero-downtime takeover** — the new process starts with `SO_REUSEPORT`, binding the same port alongside the old process. Once it writes a readiness file, the old process exits. DNS never goes down.

If any step fails, the old binary keeps running and the failure is reported in the dashboard. Checks run every 8 hours when auto-update is enabled. Manual updates from the dashboard use the same pipeline.

### Web Dashboard

Available at `http://<host>:8080`:

- Real-time query stats (total, blocked, block rate)
- Searchable query log with status/domain/client filters
- Blocklist and allowlist management
- Upstream DNS server configuration
- Feature toggles and system settings
- Update status and manual trigger
- All changes take effect immediately — no restart needed

### Query Logging

- SQLite-backed persistent log (WAL mode)
- Search by domain, client IP, status, block source, feature, upstream
- Configurable retention (1–90 days, hourly purge)
- Optional client IP anonymization

## Installation

### Install Script

```bash
curl -sSL "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh" | sh
```

Installs the binary to `/opt/oxi-hole/`, config to `/etc/oxi-hole/config.toml`, and creates a systemd service.

**Options** (pass via `sh -s -- <flags>`):

| Flag | Description |
|------|-------------|
| `-c <channel>` | Release channel: `stable` (default), `beta`, `edge` |
| `-r` | Reinstall (fresh) |
| `-U` | Update binary only (preserves config) |
| `-u` | Uninstall |
| `-v` | Verbose output |

Example — install from the beta channel:
```bash
curl -sSL "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh" | sh -s -- -c beta
```

### Docker / Podman

Images are published to GHCR for `linux/amd64` and `linux/arm64`.

```bash
docker run -d \
  --name oxi-hole \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 8080:8080 \
  -v oxi-hole-config:/etc/oxi-hole \
  ghcr.io/ron-png/oxi-hole:latest
```

Docker Compose:

```yaml
services:
  oxi-hole:
    image: ghcr.io/ron-png/oxi-hole:latest
    container_name: oxi-hole
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "8080:8080"
      # Uncomment for encrypted DNS:
      # - "853:853/tcp"   # DoT
      # - "443:443/tcp"   # DoH
      # - "853:853/udp"   # DoQ
    volumes:
      - oxi-hole-config:/etc/oxi-hole

volumes:
  oxi-hole-config:
```

## Configuration

Default config (`config.toml`):

```toml
[dns]
listen = ["0.0.0.0:53", "[::]:53"]
upstreams = [
    "tls://9.9.9.10:853",
    "tls://149.112.112.10:853",
]

[web]
listen = ["0.0.0.0:8080", "[::]:8080"]
```

Most settings are configurable at runtime through the web dashboard. The full set of config sections:

| Section | Key settings |
|---------|-------------|
| `[dns]` | `listen`, `dot_listen`, `doh_listen`, `doq_listen`, `upstreams`, `timeout_ms` |
| `[web]` | `listen` |
| `[blocking]` | `enabled`, `blocklists`, `custom_blocked`, `allowlist`, `blocking_mode`, `update_interval_minutes`, `enabled_features` |
| `[tls]` | `cert_path`, `key_path` (auto-generates self-signed if omitted) |
| `[system]` | `auto_update`, `ipv6_enabled` |
| `[log]` | `retention_days`, `anonymize_client_ip` |

Upstream formats: `udp://`, `tls://`, `https://`, `quic://` — defaults to UDP if no prefix.

## Uninstall

```bash
curl -sSL "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh" | sh -s -- -u
```

## Contributing

Bug reports, feature requests, and pull requests are welcome. Open an issue on GitHub.

## License

MIT

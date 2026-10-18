# Changelog

Each version's section is published as its release notes on testopscenter.com/releases
and on GitHub. Add a `## X.Y.Z — YYYY-MM-DD` section before tagging a release.

## 0.1.0 — 2026-10-19

First public release.

- OpenVPN server setup with a guided wizard on Debian 12/13 and Ubuntu 22.04/24.04
- VPN users with fixed addresses and `.ovpn` profiles; disable, renew and delete
- Internal DNS hosts (`stage.internal → 10.0.5.20`), wildcards and CNAMEs
- Split or full tunnel, globally or per user; VPN clients are kept on the VPN's DNS
- Per-user session, DNS and connection logs, kept for 14 days
- Security monitoring: port scans, blocked networks, forbidden ports, malicious domains,
  Suricata IDS, unusual upload volume, failed logins
- Slack and email alerts with severity thresholds and muting
- Terminal dashboard in English and Turkish; update and uninstall commands

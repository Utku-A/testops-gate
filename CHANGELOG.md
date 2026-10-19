# Changelog

Each version's section is published as its release notes on testopscenter.com/releases
and on GitHub. Add a `## X.Y.Z — YYYY-MM-DD` section before tagging a release.

## 0.3.0 — 2026-10-19

- `testops-gate doctor` finds out why services are not running: the error lines from the
  service's log, a VPN port held by another program (and which one), missing packages,
  configuration files, certificates or the TUN device
- `testops-gate repair` puts the installation back together: installs missing packages, removes a
  leftover TUN interface, restores certificates and keys, regenerates the configuration, clears
  failed service states and restarts the services; users, certificates and settings are kept
- Dashboard: when a service is down the Services panel says so; `r` opens diagnose and repair
- The installer stops before writing anything when the VPN port is already in use, and names
  the program using it

## 0.2.1 — 2026-10-19

- Dashboard: mouse escape codes (`^[[<35;152;14M…`) could appear as text while it refreshed;
  commands it runs in the background no longer have access to its terminal

## 0.2.0 — 2026-10-19

- Passwords on top of the certificate, chosen in Settings → Authentication (or
  `testops-gate settings auth`):
  - **username + password** (default for new installations): checked by the server, so a
    copied profile alone is not enough; passwords are stored as scrypt hashes
  - **profile password**: the private key in the `.ovpn` file is encrypted
  - **certificate only**: as before; servers installed with 0.1.x keep this until it is changed
- New users get a generated password (or one you choose); the dashboard, the setup wizard and
  `testops-gate user add` show it once together with where the profile is and how to download it
- `testops-gate user passwd NAME` and `p` on the Users page set a new password
- Wrong passwords count as failed sign-ins in security monitoring
- Installer: after `curl … | sudo sh` it prints what to run next instead of starting the wizard
  inside the pipe, which suspended the shell job (`Stopped`)

## 0.1.1 — 2026-10-19

- Supported systems: Debian 12 or later and Ubuntu 22.04 or later (LTS and interim releases), their
  derivatives (Raspberry Pi OS, Linux Mint, Pop!_OS, …), on any architecture (amd64, arm64, …);
  tested on Debian 12/13 and Ubuntu 22.04/24.04/25.10/26.04
- Installer: `curl … | sudo sh` failed on every system (it used the operating system's `VERSION`
  from `/etc/os-release` as the package version); clearer output with step-by-step status
- Dashboard: a setting changed right after saving a form (user, host, notification channel)
  could be lost
- Dashboard: quitting right after changing the language no longer shows an error

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

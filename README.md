<p align="center">
  <a href="https://testopscenter.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-white.png">
      <img src="docs/assets/logo-dark.png" width="216" height="60" alt="TestOps Center">
    </picture>
  </a>
</p>

<h1 align="center">TestOps Gate</h1>

<p align="center">
  A private OpenVPN network for your team, managed from a terminal dashboard.<br>
  <a href="https://testopscenter.com">TestOps Center</a> · <a href="LICENSE">AGPL-3.0</a> · Debian 12+ · Ubuntu 22.04+ · amd64 / arm64
</p>

<p align="center">
  <img src="docs/assets/dashboard.png" alt="TestOps Gate dashboard" width="900">
</p>

## Features

- **VPN users** — one command or one form per user; fixed VPN address, `.ovpn` profile, disable / renew / delete.
- **Servers** — join a server to the VPN with one command (`testops-gate node add web-01`); servers reach each other by name.
- **Passwords** — username + password checked by the server (default), a password on the profile, or certificate only.
- **Internal DNS** — map names to private addresses (`stage.internal → 10.0.5.20`, wildcards, CNAMEs).
- **Split or full tunnel** — only your internal hosts over the VPN, or all traffic; globally or per user.
- **Per-user logs** — sessions, DNS queries and connections in `/var/log/testops-gate/users/<user>/`, kept 14 days.
- **Security monitoring** — port scans, blocked networks, forbidden ports, malicious domains, Suricata IDS, unusual upload volume, failed logins.
- **Alerts** — Slack and email, with severity thresholds and muting.
- **Dashboard** — keyboard-driven terminal UI in English and Turkish; everything is also available from the CLI.

<table>
  <tr>
    <td width="50%"><img src="docs/assets/screenshots/users.png" alt="Users: status, VPN address, tunnel mode, traffic and last alert per user"><br><sub>Users</sub></td>
    <td width="50%"><img src="docs/assets/screenshots/hosts.png" alt="Hosts: internal DNS records"><br><sub>Hosts — internal DNS</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/assets/screenshots/security.png" alt="Security: detection categories and recent alerts"><br><sub>Security monitoring</sub></td>
    <td width="50%"><img src="docs/assets/screenshots/logs.png" alt="Logs: one user's sessions, DNS queries and connections"><br><sub>Per-user logs</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/assets/screenshots/servers.png" alt="Servers: servers joined to the VPN with their address, name and state"><br><sub>Servers in the VPN</sub></td>
    <td width="50%"><img src="docs/assets/screenshots/join.png" alt="The one-time join command for a new server"><br><sub>Join command</sub></td>
  </tr>
</table>

## Install

On a fresh Debian 12 or later, or Ubuntu 22.04 or later server (amd64, arm64 or any other architecture;
derivatives such as Raspberry Pi OS work too):

```bash
curl -fsSL https://testopscenter.com/install.sh | sudo sh
```

The script downloads the package, verifies its checksum, installs it and opens the setup wizard.
For an unattended setup, pass the options to `testops-gate install`:

```bash
curl -fsSL https://testopscenter.com/install.sh | sudo sh -s -- \
    --endpoint vpn.example.com --user alice --yes
```

Open UDP port **1194** (or the port you choose) in your cloud firewall.

## Usage

```bash
sudo testops-gate                                   # dashboard
```

Or from the command line:

```bash
sudo testops-gate user add alice --email alice@example.com   # prints the password and the profile path
sudo testops-gate user export alice -o ~/            # copy the .ovpn to your home, then scp it
sudo testops-gate user passwd alice                  # new password
sudo testops-gate user send alice                    # email the profile (+ setup steps, never the password)
sudo testops-gate host add stage.internal 10.0.5.20
sudo testops-gate node add web-01                    # prints a one-time join command for that server
sudo testops-gate tunnel set full                    # or: split
sudo testops-gate settings port 443 --protocol tcp   # move the VPN; every profile is renewed
sudo testops-gate notify add slack --name '#vpn-alerts' --webhook https://hooks.slack.com/services/…
sudo testops-gate logs alice --since 2h
sudo testops-gate status
```

Profiles are kept in `/var/lib/testops-gate/profiles/<user>.ovpn`. Import the profile into any OpenVPN
client (OpenVPN Connect, `openvpn`, Tunnelblick); with passwords on, it asks for the username and password.
Change how users sign in with `testops-gate settings auth user-password|profile-password|certificate`
or in the dashboard under Settings → Authentication.

Run `testops-gate --help` or `testops-gate <command> --help` for all options.

## Update and uninstall

```bash
sudo testops-gate doctor            # a service is not running? shows why
sudo testops-gate repair            # reinstall, regenerate and restart; users and certificates are kept
sudo testops-gate update            # also from the dashboard: Settings → Updates
sudo testops-gate uninstall         # removes everything; --keep-data keeps certificates, users and logs
```

The dashboard shows a badge when a new version is available. Updates verify the package checksum
and back up the configuration first; users, certificates and settings are kept.

## Documentation

- [Detailed guide (Turkish)](docs/GUIDE.tr.md) — architecture, tunnel modes, DNS, logs, security categories, notifications, files
- [Releasing](docs/RELEASING.md) — build, test and publish a version

## License

TestOps Gate is free software, licensed under the [GNU Affero General Public License v3.0 or later](LICENSE).
Copyright © 2026 Halis Utku Aladağ ([NOTICE](NOTICE)).

"TestOps Center" and its logo and icon are trademarks and are not covered by the license; see [TRADEMARKS.md](TRADEMARKS.md).

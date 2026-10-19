# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Command line interface. Without arguments it opens the terminal dashboard."""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from collections.abc import Callable, Sequence
from datetime import date, datetime, timedelta

from testops_gate import BRAND, BRAND_URL, __version__, logs
from testops_gate import config as config_mod
from testops_gate.config import AUTH_MODES, SECURITY_CATEGORIES, TUNNEL_MODES, UPSTREAMS, Channel
from testops_gate.core.context import USER_MODES, Context, ValidationError
from testops_gate.i18n import LANGUAGES, T, set_language
from testops_gate.paths import P
from testops_gate.system import netinfo, services

SINCE_RE = re.compile(r"^(\d+)([smhd])$")
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class CliError(Exception):
    pass


def parse_since(value: str) -> float:
    match = SINCE_RE.match(value)
    if not match:
        raise CliError(T("Invalid duration: {value} (use e.g. 30m, 2h, 7d)", value=value))
    return time.time() - int(match.group(1)) * UNITS[match.group(2)]


def table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    cells = [[str(c) for c in row] for row in rows]
    widths = [max(len(h), *(len(r[i]) for r in cells)) if cells else len(h) for i, h in enumerate(headers)]
    lines = ["  ".join(h.upper().ljust(w) for h, w in zip(headers, widths, strict=True)).rstrip()]
    lines += ["  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)).rstrip() for row in cells]
    return "\n".join(lines)


def confirm(question: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise CliError(T("Refusing to continue without confirmation; pass --yes"))
    answer = input(f"{question} [y/N] ").strip().lower()
    return answer in ("y", "yes", "e", "evet")


def require_root() -> None:
    if os.environ.get("TESTOPS_GATE_ROOT"):
        return  # test/development root
    if not netinfo.is_root():
        raise CliError(T("testops-gate must be run as root (sudo testops-gate)"))


def open_context() -> Context:
    require_root()
    if not config_mod.exists():
        raise CliError(T("testops-gate is not installed yet. Run `sudo testops-gate` or `sudo testops-gate install`."))
    return Context.open(reload=not os.environ.get("TESTOPS_GATE_ROOT"))


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "—"


def fmt_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit in ("B", "KB") else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


# --- install / uninstall / status ---------------------------------------------


def cmd_install(args: argparse.Namespace) -> int:
    from testops_gate.core.install import InstallOptions, install, preflight

    set_language(args.language)
    problems = preflight()
    if problems and not os.environ.get("TESTOPS_GATE_ROOT"):
        raise CliError("\n".join(problems))
    endpoint = args.endpoint or netinfo.suggest_endpoint()
    if not endpoint:
        raise CliError(T("Could not detect the public address; pass --endpoint"))
    opts = InstallOptions(
        endpoint=endpoint, port=args.port, protocol=args.protocol, tunnel_mode=args.mode, upstream=args.dns,
        language=args.language, security=not args.no_security, ids=not args.no_ids,
        first_user=args.user or "", first_user_email=args.email or "", auth_mode=args.auth,
    )
    print(T("Endpoint: {endpoint}:{port}/{proto}", endpoint=endpoint, port=args.port, proto=args.protocol))
    if not confirm(T("Install TestOps Gate on this server?"), args.yes):
        return 1
    ctx = install(opts, log=lambda line: print(f"• {line}", flush=True))
    if ctx.new_user:
        print_access(ctx, ctx.new_user.name, ctx.new_user.password)
    print()
    print(T("Open the dashboard: sudo testops-gate"))
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    from testops_gate.core.install import run_final, uninstall

    require_root()
    if config_mod.exists():
        set_language(config_mod.load().language)
    purge = not args.keep_data
    remove_packages = not args.keep_packages
    if purge and remove_packages:
        question = T("Remove TestOps Gate completely: services, configuration, ALL certificates, users and logs, "
                     "the packages it installed and TestOps Gate itself?")
    elif purge:
        question = T("Remove TestOps Gate and delete ALL certificates, users and logs? Packages are kept.")
    elif remove_packages:
        question = T("Remove TestOps Gate and its packages? Certificates, users and logs are kept.")
    else:
        question = T("Remove TestOps Gate? Certificates, users, logs and packages are kept.")
    if not confirm(question, args.yes):
        return 1
    final = uninstall(purge=purge, remove_packages=remove_packages, log=lambda line: print(f"• {line}", flush=True))
    if not purge:
        print(T("Kept: /etc/testops-gate, /var/lib/testops-gate, /var/log/testops-gate"))
    if final:
        print(f"• {T('Removing the testops-gate package')}: {' '.join(final)}", flush=True)
        if not os.environ.get("TESTOPS_GATE_ROOT"):
            run_final(final)
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    from testops_gate.core import update
    from testops_gate.core.install import run_final

    ctx = open_context()
    if args.base_url:
        ctx.cfg.updates.base_url = args.base_url
    state = update.check(ctx.cfg, force=True)
    if state.error:
        raise CliError(T("Could not check for updates: {error}", error=state.error))
    print(T("Installed: {current} · latest: {latest}", current=state.current, latest=state.latest))
    if not state.available:
        print(T("TestOps Gate is up to date"))
        return 0
    if args.check:
        print(T("Update available: sudo testops-gate update"))
        return 0
    if not confirm(T("Update TestOps Gate to {version}?", version=state.latest), args.yes):
        return 1
    command = update.prepare(ctx.cfg, log=lambda line: print(f"• {line}", flush=True))
    print(f"• {T('Installing')}: {' '.join(command)}", flush=True)
    if not os.environ.get("TESTOPS_GATE_ROOT"):
        run_final(command)
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    """Regenerate every configuration file and reload what changed (run by the package on upgrade)."""
    ctx = open_context()
    changed = ctx.apply()
    print(", ".join(sorted(changed)) or T("No changes"))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    ctx = open_context()
    cfg = ctx.cfg
    units = [services.OPENVPN_UNIT, services.UNBOUND_UNIT, services.FIREWALL_UNIT, services.DAEMON_UNIT]
    if cfg.security.category_enabled("ids"):
        units.append(services.SURICATA_UNIT)
    states = services.is_active(units)
    print(f"TestOps Gate {__version__} · {cfg.server.endpoint}:{cfg.server.port}/{cfg.server.protocol} · "
          f"{T('tunnel')}: {cfg.tunnel.mode} · {T('security')}: {T('on') if cfg.security.enabled else T('off')}")
    print()
    print(table([T("Service"), T("State")], [[u, T("active") if ok else T("inactive")] for u, ok in states.items()]))
    live = {name: c for name, c in ctx.store.live_clients().items() if not name.endswith(".node")}
    users = ctx.store.users()
    print()
    print(T("{online} of {total} users connected", online=len(live), total=len(users)))
    joined = ctx.store.nodes()
    if joined:
        online = sum(1 for n in joined if n.cn in ctx.store.live_clients())
        print(T("{online} of {total} servers connected", online=online, total=len(joined)))
    if live:
        print(table([T("User"), "VPN IP", T("Real IP"), T("Since"), "↓", "↑"],
                    [[c.name, c.vpn_ip, c.real_ip, fmt_ts(c.connected_since), fmt_bytes(c.rx), fmt_bytes(c.tx)]
                     for c in live.values()]))
    if not all(states.values()):
        print()
        print(T("Some services are not running. Find out why: sudo testops-gate doctor · fix: sudo testops-gate repair"))
    return 0 if all(states.values()) else 3


def print_findings(findings) -> None:
    for f in findings:
        mark = "✓" if f.ok else "✗"
        print(f"  {mark} {f.title:<22} {T('ok') if f.ok else ''}".rstrip())
        for line in f.detail.splitlines():
            print(f"      {line}")


def cmd_doctor(args: argparse.Namespace) -> int:
    from testops_gate.core import doctor

    findings = doctor.diagnose(open_context().cfg)
    print_findings(findings)
    if doctor.problems(findings):
        print()
        print(T("Repair (keeps users, certificates and settings): sudo testops-gate repair"))
        return 1
    return 0


def cmd_repair(args: argparse.Namespace) -> int:
    from testops_gate.core import doctor

    ctx = open_context()
    if not confirm(T("Reinstall missing packages, regenerate the configuration and restart the services?"), args.yes):
        return 1
    findings = doctor.repair(ctx, log=lambda line: print(f"• {line}", flush=True))
    print()
    print_findings(findings)
    return 1 if doctor.problems(findings) else 0


# --- users ----------------------------------------------------------------------


def user_state(ctx: Context, name: str) -> str:
    user = ctx.store.user(name)
    if not user:
        return ""
    if not user.enabled:
        return T("disabled")
    if user.blocked:
        return T("blocked")
    return T("online") if name in ctx.store.live_clients() else T("offline")


def print_access(ctx, name: str, password: str = "") -> None:
    """Sign-in details and where the profile is, after a user or a password was created."""
    from testops_gate.core import access

    print()
    for label, value in access.details(ctx.cfg, name, password):
        print(f"  {label:<18} {value}")
    print()
    if password:
        print(f"  {access.password_note(ctx.cfg)}")
    print(f"  {access.connect_hint(ctx.cfg)}")


def read_password(args: argparse.Namespace) -> str | None:
    """--password-stdin: first line of stdin; otherwise None (generate one)."""
    if not getattr(args, "password_stdin", False):
        return None
    return sys.stdin.readline().rstrip("\r\n")


CERT_ONLY_WARNING = ("Sign-in is certificate only: the profile alone is enough to connect, so anyone who reads "
                     "the email can connect.")


def send_profile_after_add(ctx, user) -> None:
    """New users get their profile by email unless --no-send; says why when it cannot."""
    if not user.email:
        print(T("Profile not emailed: {name} has no email address", name=user.name))
        return
    if ctx.mail_channel() is None:
        print(T("Profile not emailed: no email notification channel is set up"))
        return
    if ctx.cfg.auth.mode == "certificate":
        print(T(CERT_ONLY_WARNING))
    try:
        print(T("Profile emailed to {email}", email=ctx.send_profile(user.name)))
    except RuntimeError as exc:
        print(T("Profile not emailed: {error}", error=exc))


def cmd_user(args: argparse.Namespace) -> int:
    ctx = open_context()
    action = args.user_action
    if action == "list":
        live = ctx.store.live_clients()
        rows = []
        with_password = ctx.cfg.auth.mode == "user-password"
        for u in ctx.store.users():
            row = [u.name, user_state(ctx, u.name), u.vpn_ip, u.mode, u.email or "—",
                   fmt_ts(u.cert_expires)[:10], live[u.name].real_ip if u.name in live else "—"]
            rows.append(row + (["✓" if u.has_password else T("not set")] if with_password else []))
        headers = [T("User"), T("Status"), "VPN IP", T("Tunnel"), T("Email"), T("Expires"), T("Real IP")]
        print(table(headers + ([T("Password")] if with_password else []), rows))
    elif action == "add":
        user = ctx.add_user(args.name, args.email or "", args.mode, args.days, args.ip or "", read_password(args))
        print(T("User {name} created: {path}", name=user.name, path=P.profiles_dir / f"{user.name}.ovpn"))
        print(T("VPN address: {ip}", ip=user.vpn_ip))
        print_access(ctx, user.name, user.password)
        if not args.no_send:
            print()
            send_profile_after_add(ctx, user)
    elif action == "send":
        if not args.names and not args.all:
            raise CliError(T("Name users, or use --all"))
        if ctx.cfg.auth.mode == "certificate" and not confirm(T(CERT_ONLY_WARNING) + " " + T("Send anyway?"), args.yes):
            return 1
        sent, skipped = ctx.send_profiles(None if args.all else args.names)
        for name in sent:
            print(f"✓ {name}")
        for name, reason in skipped:
            print(f"✗ {name}: {reason}")
        return 0 if not skipped else 1
    elif action == "passwd":
        password = ctx.set_password(args.name, read_password(args))
        if ctx.cfg.auth.mode == "profile-password":
            print(T("New profile password for {name}; send the user the new profile.", name=args.name))
        else:
            print(T("New password for {name}; the current session was closed.", name=args.name))
        print_access(ctx, args.name, password)
    elif action == "edit":
        ctx.update_user(args.name, email=args.email, mode=args.mode, vpn_ip=args.ip, note=args.note)
        print(T("{name} updated", name=args.name))
        print(T("If connected, the user reconnects now to apply tunnel mode or address changes."))
    elif action == "disable":
        kicked = ctx.set_user_enabled(args.name, False)
        print(T("{name} disabled", name=args.name) + (T(" · disconnected") if kicked else ""))
    elif action == "enable":
        ctx.set_user_enabled(args.name, True)
        print(T("{name} enabled", name=args.name))
    elif action == "delete":
        if not confirm(T("Delete {name}? The certificate is revoked; logs are kept for {days} days.",
                         name=args.name, days=ctx.cfg.logging.retention_days), args.yes):
            return 1
        ctx.delete_user(args.name)
        print(T("{name} deleted · certificate revoked", name=args.name))
    elif action == "renew":
        password = ctx.renew_user(args.name, args.days)
        print(T("New certificate issued for {name}; send the user the new profile.", name=args.name))
        print_access(ctx, args.name, password)
    elif action == "export":
        if args.output:
            print(ctx.export_profile(args.name, args.output))
        else:
            sys.stdout.write(ctx.profile(args.name))
    return 0


# --- servers (nodes) ----------------------------------------------------------------


def print_join(ctx, token, token_string) -> None:
    from testops_gate.core import nodes

    until = datetime.fromtimestamp(token.expires).strftime("%Y-%m-%d %H:%M")
    print(T("Run this on {name} to join it to the VPN (once, until {until}):", name=token.node, until=until))
    print()
    print(f"  {nodes.join_command(ctx, token, token_string)}")
    print()
    print(T("Open {port}/tcp to this server in the cloud provider's firewall while joining: the joining server "
            "connects there once. The join service stops by itself afterwards.", port=ctx.cfg.nodes.enroll_port))


def cmd_node(args: argparse.Namespace) -> int:
    from testops_gate.core import nodes

    ctx = open_context()
    if args.node_action == "add":
        token, token_string = nodes.create_join_token(ctx, args.name, args.minutes)
        print_join(ctx, token, token_string)
    elif args.node_action == "list":
        states = {"online": T("online"), "offline": T("offline"), "waiting": T("waiting to join")}
        print(table([T("Server"), "VPN IP", T("DNS name"), T("Status"), T("Real IP")],
                    [[r["name"], r["vpn_ip"] or "—", r["fqdn"], states[r["state"]], r["real_ip"] or "—"]
                     for r in nodes.node_rows(ctx)]))
    elif args.node_action == "remove":
        if not confirm(T("Remove {name}? Its certificate is revoked and it disconnects.", name=args.name), args.yes):
            return 1
        nodes.remove_node(ctx, args.name)
        print(T("{name} removed · certificate revoked", name=args.name))
    return 0


def cmd_enroll_serve(args: argparse.Namespace) -> int:
    from testops_gate import enroll

    require_root()
    return enroll.serve()


# --- hosts ----------------------------------------------------------------------


def cmd_host(args: argparse.Namespace) -> int:
    ctx = open_context()
    action = args.host_action
    if action == "list":
        print(table([T("Domain"), T("Type"), T("Target"), T("Note")],
                    [[h.name, h.rtype, h.value, h.note or "—"] for h in ctx.store.hosts()]))
    elif action == "add":
        host = ctx.save_host(args.name, args.type, args.target, args.note or "")
        print(T("{name} -> {value} added", name=host.name, value=host.value))
    elif action == "edit":
        current = ctx.store.host(args.name.lower())
        if not current:
            raise ValidationError(T("No such host: {name}", name=args.name))
        host = ctx.save_host(args.rename or current.name, args.type or current.rtype, args.target or current.value,
                             current.note if args.note is None else args.note, old_name=current.name)
        print(T("{name} updated", name=host.name))
    elif action == "delete":
        ctx.delete_host(args.name.lower())
        print(T("{name} deleted", name=args.name))
    if action in ("add", "edit", "delete") and ctx.cfg.tunnel.mode == "split":
        print(T("Split-mode routes are updated for users when they reconnect."))
    return 0


# --- tunnel / settings ------------------------------------------------------------


def cmd_tunnel(args: argparse.Namespace) -> int:
    ctx = open_context()
    if args.tunnel_action == "set":
        reconnected = ctx.set_tunnel_mode(args.mode, reconnect=not args.no_reconnect)
        print(T("Tunnel mode: {mode}", mode=args.mode))
        if args.no_reconnect:
            print(T("Applied to connected users when they reconnect."))
        elif reconnected:
            print(T("Reconnected now: {names}", names=", ".join(reconnected)))
        else:
            print(T("No connected user was affected; others get it when they connect."))
    elif args.tunnel_action == "routes":
        if args.routes is not None:
            ctx.set_extra_routes(args.routes)
        print(", ".join(ctx.cfg.tunnel.extra_routes) or "—")
    else:
        overrides = [f"{u.name}={u.mode}" for u in ctx.store.users() if u.mode != "default"]
        print(f"{T('Tunnel mode')}: {ctx.cfg.tunnel.mode}")
        print(f"{T('Extra routes')}: {', '.join(ctx.cfg.tunnel.extra_routes) or '—'}")
        print(f"{T('Per-user overrides')}: {', '.join(overrides) or '—'}")
    return 0


def cmd_settings(args: argparse.Namespace) -> int:
    ctx = open_context()
    if args.settings_action == "language":
        ctx.set_language(args.value)
    elif args.settings_action == "retention":
        ctx.set_retention(args.value)
    elif args.settings_action == "dns":
        ctx.set_upstream(args.value)
    elif args.settings_action == "dns-enforce":
        ctx.set_dns_enforce(args.value == "on")
    elif args.settings_action == "update-check":
        ctx.set_update_check(args.value == "on")
    elif args.settings_action == "update-url":
        ctx.set_update_url("" if args.value == "default" else args.value)
    elif args.settings_action in ("port", "endpoint"):
        if args.settings_action == "port":
            created = ctx.set_server(port=args.value, protocol=args.protocol)
        else:
            created = ctx.set_server(endpoint=args.value)
        server = ctx.cfg.server
        print(T("Clients connect to {endpoint}:{port}/{proto}. Every profile was renewed: send users their profile "
                "again.", endpoint=server.endpoint, port=server.port, proto=server.protocol))
        print(T("Allow {port}/{proto} in the cloud provider's firewall.", port=server.port, proto=server.protocol))
        print(T("Email everyone their new profile: testops-gate user send --all"))
        if created:
            from testops_gate.core import access

            print(table([T("User"), access.password_label(ctx.cfg)], [[n, p] for n, p in created.items()]))
            print(access.password_note(ctx.cfg))
    elif args.settings_action == "auth":
        created = ctx.set_auth_mode(args.value)
        print(T("Sign-in mode: {mode}. Every profile was renewed: send users their profile again.", mode=args.value))
        print(T("Email everyone their new profile: testops-gate user send --all"))
        if created:
            from testops_gate.core import access

            print(table([T("User"), access.password_label(ctx.cfg)], [[n, p] for n, p in created.items()]))
            print(access.password_note(ctx.cfg))
    cfg = ctx.cfg
    print(table([T("Setting"), T("Value")], [
        ["language", cfg.language],
        ["retention", f"{cfg.logging.retention_days} {T('days')}"],
        ["dns", f"{cfg.dns.upstream} ({UPSTREAMS[cfg.dns.upstream][0]})"],
        ["dns-enforce", T("on") if cfg.dns.enforce else T("off")],
        ["auth", cfg.auth.mode],
        ["update-check", T("on") if cfg.updates.check else T("off")],
        ["update-url", cfg.updates.base_url or "default (testopscenter.com)"],
        ["endpoint", f"{cfg.server.endpoint}:{cfg.server.port}/{cfg.server.protocol}"],
        ["network", cfg.server.network],
    ]))
    return 0


# --- security / alerts ------------------------------------------------------------


def cmd_security(args: argparse.Namespace) -> int:
    ctx = open_context()
    action = args.security_action
    valid = [*SECURITY_CATEGORIES, "autoblock"]
    if action in ("enable", "disable"):
        value = action == "enable"
        unknown = [c for c in args.categories if c not in valid]
        if unknown:
            raise CliError(T("Unknown security category: {value}", value=", ".join(unknown)) + f" ({', '.join(valid)})")
        if args.categories:
            ctx.set_security(**{c: value for c in args.categories})
        else:
            ctx.set_security(enabled=value)
    elif action == "block-networks":
        ctx.set_security_lists(blocked_networks=args.values)
    elif action == "forbidden-ports":
        ctx.set_security_lists(forbidden_ports=args.values)
    elif action == "rpz-url":
        ctx.set_rpz_url(args.url)
    sec = ctx.cfg.security
    print(f"{T('Security monitoring')}: {T('on') if sec.enabled else T('off')}")
    print(table([T("Category"), T("Alert"), T("State")],
                [[key, SECURITY_CATEGORIES.get(key, "—"), T("on") if sec.categories.get(key) else T("off")] for key in valid]))
    print(f"{T('Blocked networks')}: {', '.join(sec.blocked_networks) or '—'}")
    print(f"{T('Forbidden ports')}: {', '.join(sec.forbidden_ports) or '—'}")
    print(f"RPZ: {sec.rpz_url}")
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    ctx = open_context()
    alerts = ctx.store.alerts(since=parse_since(args.since), user=args.user, limit=args.limit)
    print(table([T("Time"), T("Severity"), T("User"), T("Category"), T("Detail")],
                [[fmt_ts(a.ts), a.severity, a.user, a.category, a.detail] for a in reversed(alerts)]))
    return 0


# --- notifications ----------------------------------------------------------------


def cmd_notify(args: argparse.Namespace) -> int:
    ctx = open_context()
    action = args.notify_action
    if action == "list":
        print(table(["ID", T("Channel"), T("Name"), T("Target"), T("Min. severity"), T("Mute"), T("State")],
                    [[c.id, c.kind, c.name, c.target, c.min_severity, f"{c.mute_minutes}m",
                      T("on") if c.enabled else T("off")] for c in ctx.cfg.channels]))
    elif action == "add":
        channel = Channel(id="", kind=args.kind, name=args.name, min_severity=args.min_severity,
                          mute_minutes=args.mute)
        if args.kind == "slack":
            channel.webhook = args.webhook or ""
        else:
            channel.recipients = (args.to or "").split(",")
            channel.smtp_host = args.smtp_host or ""
            channel.smtp_port = args.smtp_port
            channel.smtp_security = args.smtp_security
            channel.smtp_user = args.smtp_user or ""
            channel.smtp_password = os.environ.get("TESTOPS_GATE_SMTP_PASSWORD", args.smtp_password or "")
            channel.sender = args.sender or ""
        channel = ctx.save_channel(channel)
        print(T("Channel {name} added ({id})", name=channel.name, id=channel.id))
    elif action in ("enable", "disable"):
        ctx.set_channel_enabled(args.id, action == "enable")
        print(f"{args.id}: {T('on') if action == 'enable' else T('off')}")
    elif action == "delete":
        ctx.delete_channel(args.id)
        print(T("{name} deleted", name=args.id))
    elif action == "test":
        from testops_gate.notify.send import DeliveryError, send
        from testops_gate.notify.testing import test_alert

        channels = [ctx.cfg.channel(args.id)] if args.id else [c for c in ctx.cfg.channels if c.enabled]
        if not channels or channels[0] is None:
            raise CliError(T("No enabled notification channels"))
        failed = 0
        for channel in channels:
            try:
                send(channel, test_alert(ctx.cfg))
                print(f"✓ {channel.name}")
            except DeliveryError as exc:
                failed += 1
                print(f"✗ {channel.name}: {exc}")
        return 1 if failed else 0
    return 0


# --- logs -------------------------------------------------------------------------


def log_source(name: str, security_only: bool, day: str) -> list:
    if name == "security":
        return [logs.security_log(day)]
    if name == "audit":
        return [logs.audit_log(day)]
    return [logs.user_security_log(name, day) if security_only else logs.user_log(name, day)]


def line_time(line: str) -> float:
    try:
        return datetime.fromisoformat(line.split(" ", 1)[0]).timestamp()
    except ValueError:
        return 0.0


def cmd_logs(args: argparse.Namespace) -> int:
    ctx = open_context()
    if args.source not in ("security", "audit") and not ctx.store.user(args.source) \
            and not (P.users_log_dir / args.source).exists():
        raise CliError(T("No such user: {name}", name=args.source))
    since = parse_since(args.since) if args.since else 0.0
    if args.day:
        days = [args.day]
    else:
        start = date.fromtimestamp(since) if since else date.today()
        days = [(start + timedelta(days=i)).isoformat() for i in range((date.today() - start).days + 1)]
    kind = f"[{args.kind.upper()}]" if args.kind else None
    printer: Callable[[str], None] = print
    for day in days:
        for path in log_source(args.source, args.security, day):
            for line in logs.tail(path, 1_000_000):
                if since and line_time(line) < since:
                    continue
                if kind and kind not in line:
                    continue
                printer(line)
    if args.follow:
        path = log_source(args.source, args.security, date.today().isoformat())[0]
        position = path.stat().st_size if path.exists() else 0
        try:
            while True:
                time.sleep(1)
                current = log_source(args.source, args.security, date.today().isoformat())[0]
                if current != path:
                    path, position = current, 0
                if not path.exists():
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    fh.seek(position)
                    for line in fh:
                        if not kind or kind in line:
                            printer(line.rstrip("\n"))
                    position = fh.tell()
        except KeyboardInterrupt:
            return 0
    return 0


# --- parser -----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="testops-gate", description="OpenVPN private network manager. "
                                     "Run without arguments for the terminal dashboard.")
    parser.add_argument("--version", action="version", version=f"TestOps Gate {__version__} · {BRAND}™ ({BRAND_URL})")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("tui", help="open the terminal dashboard (default)")

    p = sub.add_parser("install", help="install and configure the VPN server")
    p.add_argument("--endpoint", help="public IP or hostname clients connect to (default: detected)")
    p.add_argument("--port", type=int, default=1194)
    p.add_argument("--protocol", choices=["udp", "tcp"], default="udp")
    p.add_argument("--mode", choices=TUNNEL_MODES, default="split", help="tunnel mode (default: split)")
    p.add_argument("--dns", choices=list(UPSTREAMS), default="cloudflare", help="upstream DNS resolver")
    p.add_argument("--language", choices=[c for _, c in LANGUAGES], default="en")
    p.add_argument("--no-security", action="store_true", help="disable security monitoring")
    p.add_argument("--no-ids", action="store_true", help="do not install Suricata")
    p.add_argument("--user", help="create a first VPN user")
    p.add_argument("--email", help="email of the first user")
    p.add_argument("--auth", choices=AUTH_MODES, default="user-password",
                   help="how users sign in on top of their certificate (default: user-password)")
    p.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")

    p = sub.add_parser("uninstall", help="remove testops-gate completely (data, packages and itself)")
    p.add_argument("--keep-data", action="store_true", help="keep certificates, users, state and logs")
    p.add_argument("--keep-packages", action="store_true",
                   help="keep the installed packages and the testops-gate package")
    # accepted for compatibility with earlier versions (now the default)
    p.add_argument("--purge", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--remove-packages", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("-y", "--yes", action="store_true")

    sub.add_parser("status", help="service state and connected users")
    sub.add_parser("doctor", help="find out why services are not running")
    sub.add_parser("repair", help="reinstall missing packages, regenerate the configuration, restart services").add_argument(
        "-y", "--yes", action="store_true")
    sub.add_parser("apply", help=argparse.SUPPRESS)  # regenerate configuration (package upgrades)

    p = sub.add_parser("update", help="update testops-gate to the latest release")
    p.add_argument("--check", action="store_true", help="only check whether an update is available")
    p.add_argument("--base-url", help="release mirror to use for this run")
    p.add_argument("-y", "--yes", action="store_true")

    p = sub.add_parser("user", help="manage VPN users")
    us = p.add_subparsers(dest="user_action", required=True)
    us.add_parser("list")
    a = us.add_parser("add")
    a.add_argument("name")
    a.add_argument("--email")
    a.add_argument("--mode", choices=USER_MODES, default="default", help="tunnel mode override")
    a.add_argument("--days", type=int, default=365, help="certificate validity")
    a.add_argument("--ip", help="fixed VPN address (default: next free)")
    a.add_argument("--password-stdin", action="store_true", help="read the password from stdin (default: generate)")
    a.add_argument("--no-send", action="store_true", help="do not email the profile to the user")
    a = us.add_parser("send", help="email users their profile (attachment + setup steps, never the password)")
    a.add_argument("names", nargs="*")
    a.add_argument("--all", action="store_true", help="every user with an email address")
    a.add_argument("-y", "--yes", action="store_true")
    a = us.add_parser("passwd", help="set a new password (generated unless --password-stdin)")
    a.add_argument("name")
    a.add_argument("--password-stdin", action="store_true")
    a = us.add_parser("edit")
    a.add_argument("name")
    a.add_argument("--email")
    a.add_argument("--mode", choices=USER_MODES)
    a.add_argument("--ip")
    a.add_argument("--note")
    for action in ("disable", "enable"):
        us.add_parser(action).add_argument("name")
    a = us.add_parser("delete")
    a.add_argument("name")
    a.add_argument("-y", "--yes", action="store_true")
    a = us.add_parser("renew")
    a.add_argument("name")
    a.add_argument("--days", type=int, default=365)
    a = us.add_parser("export", help="print the .ovpn profile, or write it with -o")
    a.add_argument("name")
    a.add_argument("-o", "--output", help="file or directory")

    p = sub.add_parser("node", help="servers in the VPN: join with a one-time command")
    ns = p.add_subparsers(dest="node_action", required=True)
    a = ns.add_parser("add", help="create a one-time join command for a server")
    a.add_argument("name", help="e.g. web-01 (reachable as web-01.internal)")
    a.add_argument("--minutes", type=int, help="how long the join command works (default 60)")
    ns.add_parser("list")
    a = ns.add_parser("remove", help="remove a server (or cancel its join command)")
    a.add_argument("name")
    a.add_argument("-y", "--yes", action="store_true")
    sub.add_parser("enroll-serve")  # run by testops-gate-enroll.service

    p = sub.add_parser("host", help="manage internal DNS host records")
    hs = p.add_subparsers(dest="host_action", required=True)
    hs.add_parser("list")
    a = hs.add_parser("add")
    a.add_argument("name", help="e.g. stage.internal or *.preview.internal")
    a.add_argument("target", help="IPv4 address (A) or domain (CNAME)")
    a.add_argument("--type", choices=["A", "CNAME"], default="A")
    a.add_argument("--note")
    a = hs.add_parser("edit")
    a.add_argument("name")
    a.add_argument("--rename")
    a.add_argument("--target")
    a.add_argument("--type", choices=["A", "CNAME"])
    a.add_argument("--note")
    hs.add_parser("delete").add_argument("name")

    p = sub.add_parser("tunnel", help="tunnel mode (split / full)")
    ts = p.add_subparsers(dest="tunnel_action")
    ts.add_parser("show")
    a = ts.add_parser("set", help="split or full; connected users it affects reconnect at once")
    a.add_argument("mode", choices=TUNNEL_MODES)
    a.add_argument("--no-reconnect", action="store_true", help="apply only when users reconnect themselves")
    ts.add_parser("routes", help="extra networks routed via the VPN in split mode").add_argument(
        "routes", nargs="*", default=None)

    p = sub.add_parser("settings", help="language, log retention, DNS upstream")
    ss = p.add_subparsers(dest="settings_action")
    ss.add_parser("show")
    ss.add_parser("language").add_argument("value", choices=[c for _, c in LANGUAGES])
    ss.add_parser("retention").add_argument("value", type=int, help="days")
    ss.add_parser("dns").add_argument("value", choices=list(UPSTREAMS))
    ss.add_parser("dns-enforce", help="force VPN clients onto the VPN resolver").add_argument(
        "value", choices=["on", "off"])
    ss.add_parser("update-check", help="check for new releases daily").add_argument("value", choices=["on", "off"])
    ss.add_parser("update-url", help="release mirror URL, or `default`").add_argument("value")
    a = ss.add_parser("port", help="port (and protocol) clients connect to; renews every profile")
    a.add_argument("value", type=int)
    a.add_argument("--protocol", choices=["udp", "tcp"])
    ss.add_parser("endpoint", help="public address clients connect to; renews every profile").add_argument("value")
    ss.add_parser("auth", help="how users sign in: user-password, profile-password or certificate").add_argument(
        "value", choices=AUTH_MODES)

    p = sub.add_parser("security", help="security monitoring")
    se = p.add_subparsers(dest="security_action")
    se.add_parser("status")
    se.add_parser("enable", help="turn monitoring (or the given categories) on").add_argument("categories", nargs="*")
    se.add_parser("disable", help="turn monitoring (or the given categories) off").add_argument("categories", nargs="*")
    se.add_parser("block-networks", help="destinations VPN users may not reach").add_argument("values", nargs="*")
    se.add_parser("forbidden-ports", help="ports VPN users may not use").add_argument("values", nargs="*")
    se.add_parser("rpz-url", help="malicious-domain feed (RPZ zone URL)").add_argument("url")

    p = sub.add_parser("alerts", help="recent security alerts")
    p.add_argument("--since", default="24h")
    p.add_argument("--user")
    p.add_argument("--limit", type=int, default=200)

    p = sub.add_parser("notify", help="notification channels (Slack, email)")
    ns = p.add_subparsers(dest="notify_action", required=True)
    ns.add_parser("list")
    a = ns.add_parser("add")
    a.add_argument("kind", choices=["slack", "email"])
    a.add_argument("--name", required=True)
    a.add_argument("--webhook", help="Slack incoming webhook URL")
    a.add_argument("--to", help="comma-separated recipients")
    a.add_argument("--smtp-host")
    a.add_argument("--smtp-port", type=int, default=587)
    a.add_argument("--smtp-security", choices=["starttls", "ssl", "none"], default="starttls")
    a.add_argument("--smtp-user")
    a.add_argument("--smtp-password", help="or set TESTOPS_GATE_SMTP_PASSWORD")
    a.add_argument("--sender")
    a.add_argument("--min-severity", choices=["low", "medium", "high"], default="medium")
    a.add_argument("--mute", type=int, default=15, help="minutes between alerts of one kind per user")
    for action in ("enable", "disable", "delete"):
        ns.add_parser(action).add_argument("id")
    ns.add_parser("test").add_argument("id", nargs="?")

    p = sub.add_parser("logs", help="show logs of a user, `security` or `audit`")
    p.add_argument("source")
    p.add_argument("--since", help="e.g. 30m, 2h, 7d (default: today)")
    p.add_argument("--day", help="YYYY-MM-DD")
    p.add_argument("--security", action="store_true", help="only this user's security alerts")
    p.add_argument("--kind", choices=["session", "dns", "conn", "security"])
    p.add_argument("-f", "--follow", action="store_true")
    return parser


COMMANDS: dict[str, Callable[[argparse.Namespace], int]] = {
    "install": cmd_install, "uninstall": cmd_uninstall, "status": cmd_status, "doctor": cmd_doctor, "repair": cmd_repair, "apply": cmd_apply, "update": cmd_update, "user": cmd_user, "node": cmd_node, "enroll-serve": cmd_enroll_serve,
    "host": cmd_host, "tunnel": cmd_tunnel, "settings": cmd_settings, "security": cmd_security,
    "alerts": cmd_alerts, "notify": cmd_notify, "logs": cmd_logs,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in (None, "tui"):
        from testops_gate.tui.app import run_tui

        return run_tui()
    try:
        return COMMANDS[args.command](args)
    except (CliError, ValidationError) as exc:
        print(f"testops-gate: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:  # CommandError and other system failures
        print(f"testops-gate: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

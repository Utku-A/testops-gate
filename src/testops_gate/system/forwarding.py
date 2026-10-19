# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Let VPN traffic through firewalls other than ours.

A packet is forwarded only if every forward chain accepts it. Docker sets the iptables FORWARD
policy to DROP, so does ufw by default, and hand-written nftables rulesets often do: then the
VPN connects but nothing is routed (full tunnel: no internet; split: no internal hosts), and
our own table cannot override that. We add two narrow rules to such chains: traffic from the
VPN, and replies to it. They carry the comment "testops-gate" so they can be found and removed.
Docker and ufw rebuild their rules on restart, so testops-gated re-checks every minute.
"""

from __future__ import annotations

import json
import shutil

from testops_gate.render import TUN_DEVICE
from testops_gate.system.nft import TABLE
from testops_gate.system.runner import run

COMMENT = "testops-gate"
IPTABLES_RULES = [
    ["-i", TUN_DEVICE, "-j", "ACCEPT"],
    ["-o", TUN_DEVICE, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
]
NFT_RULES = [
    f'iifname "{TUN_DEVICE}" accept',
    f'oifname "{TUN_DEVICE}" ct state established,related accept',
]


def _iptables_drops() -> bool:
    """iptables FORWARD policy is DROP (Docker, ufw), with either the nft or the legacy backend."""
    if not shutil.which("iptables"):
        return False
    out = run(["iptables", "-S", "FORWARD"], check=False).stdout
    return "-P FORWARD DROP" in out


def _iptables_has(rule: list[str]) -> bool:
    return run(["iptables", "-C", "FORWARD", *rule, "-m", "comment", "--comment", COMMENT], check=False).ok


def _nft_chains() -> list[dict]:
    result = run(["nft", "-j", "list", "chains"], check=False)
    if not result.ok:
        return []
    try:
        items = json.loads(result.stdout).get("nftables", [])
    except json.JSONDecodeError:
        return []
    return [i["chain"] for i in items if "chain" in i]


def _foreign_drop_chains() -> list[tuple[str, str, str]]:
    """nft forward chains with policy drop outside our table and outside iptables' ip filter FORWARD
    (that one is handled with iptables, which also covers the legacy backend)."""
    chains = []
    for c in _nft_chains():
        if c.get("hook") != "forward" or c.get("policy") != "drop" or c.get("table") == TABLE:
            continue
        if (c.get("family"), c.get("table"), c.get("name")) == ("ip", "filter", "FORWARD"):
            continue
        chains.append((c["family"], c["table"], c["name"]))
    return chains


def _nft_rule_handles(family: str, table: str, chain: str) -> list[str]:
    out = run(["nft", "-a", "list", "chain", family, table, chain], check=False).stdout
    return [line.rsplit("# handle ", 1)[1].strip() for line in out.splitlines()
            if f'comment "{COMMENT}"' in line and "# handle " in line]


def blocking() -> list[str]:
    """Firewalls that would drop VPN traffic without our rules, e.g. "iptables FORWARD"."""
    found = ["iptables FORWARD"] if _iptables_drops() else []
    return found + [f"nft {family} {table} {chain}" for family, table, chain in _foreign_drop_chains()]


def missing() -> list[str]:
    """Blocking firewalls that do not let VPN traffic through yet."""
    result = []
    if _iptables_drops() and not all(_iptables_has(rule) for rule in IPTABLES_RULES):
        result.append("iptables FORWARD")
    for family, table, chain in _foreign_drop_chains():
        if len(_nft_rule_handles(family, table, chain)) < len(NFT_RULES):
            result.append(f"nft {family} {table} {chain}")
    return result


def ensure() -> list[str]:
    """Add the missing rules; returns where rules were added."""
    added = []
    if _iptables_drops():
        for rule in reversed(IPTABLES_RULES):  # inserted at the top, so reversed keeps their order
            if not _iptables_has(rule):
                run(["iptables", "-I", "FORWARD", "1", *rule, "-m", "comment", "--comment", COMMENT], check=False)
                if "iptables FORWARD" not in added:
                    added.append("iptables FORWARD")
    for family, table, chain in _foreign_drop_chains():
        if len(_nft_rule_handles(family, table, chain)) >= len(NFT_RULES):
            continue
        for handle in _nft_rule_handles(family, table, chain):  # a partial set: start over
            run(["nft", "delete", "rule", family, table, chain, "handle", handle], check=False)
        for rule in reversed(NFT_RULES):
            run(["nft", "insert", "rule", family, table, chain, *rule.split(), "comment", f'"{COMMENT}"'],
                check=False)
        added.append(f"nft {family} {table} {chain}")
    return added


def remove() -> None:
    """Take our rules out of other firewalls (uninstall)."""
    if shutil.which("iptables"):
        for rule in IPTABLES_RULES:
            for _ in range(10):  # a rule added more than once; bounded in case iptables misbehaves
                if not _iptables_has(rule) or not run(
                        ["iptables", "-D", "FORWARD", *rule, "-m", "comment", "--comment", COMMENT], check=False).ok:
                    break
    for c in _nft_chains():
        if c.get("hook") == "forward" and c.get("table") != TABLE:
            for handle in _nft_rule_handles(c["family"], c["table"], c["name"]):
                run(["nft", "delete", "rule", c["family"], c["table"], c["name"], "handle", handle], check=False)

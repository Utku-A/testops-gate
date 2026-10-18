# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""nftables helpers."""

from __future__ import annotations

import json

from testops_gate.paths import P
from testops_gate.system.runner import run

TABLE = "testops_gate"


def load() -> None:
    run(["nft", "-f", str(P.nft_file)])


def check(path: str) -> None:
    run(["nft", "-c", "-f", path])


def delete_table() -> None:
    run(["nft", "delete", "table", "inet", TABLE], check=False)


def set_elements(name: str) -> list[tuple[str, ...]]:
    """Elements of a concatenated set, e.g. [("10.8.0.10", "10.0.6.1", "443")]."""
    return [element for element, _ in set_elements_with_age(name)]


def set_elements_with_age(name: str) -> list[tuple[tuple[str, ...], float]]:
    """Elements of a timeout set with their age in seconds (timeout - expires)."""
    result = run(["nft", "-j", "list", "set", "inet", TABLE, name], check=False)
    if not result.ok:
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    elements: list[tuple[tuple[str, ...], float]] = []
    for item in data.get("nftables", []):
        set_data = item.get("set", {})
        for elem in set_data.get("elem", []) or []:
            meta = elem.get("elem", {}) if isinstance(elem, dict) else {}
            value = meta.get("val", elem) if meta else elem
            timeout = float(meta.get("timeout", set_data.get("timeout", 0)) or 0)
            age = timeout - float(meta.get("expires", timeout) or 0) if timeout else 0.0
            if isinstance(value, dict) and "concat" in value:
                key = tuple(str(v) for v in value["concat"])
            elif isinstance(value, list):
                key = tuple(str(v) for v in value)
            else:
                key = (str(value),)
            elements.append((key, age))
    return elements

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Interface translations.

Strings are written in English in the code and wrapped with T(); the English
text is the message id (gettext style). Turkish translations live in tr.py.
"""

from __future__ import annotations

from testops_gate.i18n.tr import TR

LANGUAGES = [("English", "en"), ("Türkçe", "tr")]
CATALOGS = {"tr": TR}

_current = "en"


def set_language(language: str) -> None:
    global _current
    _current = language if language in {code for _, code in LANGUAGES} else "en"


def current_language() -> str:
    return _current


def T(msg: str, **kwargs: object) -> str:
    """Translate msg to the current language and format it with kwargs."""
    catalog = CATALOGS.get(_current)
    text = catalog.get(msg, msg) if catalog else msg
    return text.format(**kwargs) if kwargs else text

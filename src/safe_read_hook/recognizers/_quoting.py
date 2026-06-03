"""Shared quote-stripping primitive for recognizers (WR-02).

The redirect policy was deliberately extracted to ONE helper (D-05) so the
security-sensitive logic is defined exactly once and cannot drift. The same
discipline applies to ``_strip_one_quote_layer``: ``reader.py`` and ``sed.py``
both need to remove a single shell-quoting layer from a captured argument
before handing it to an analyzer / mini-parser, and two byte-for-byte copies on
the security path can drift independently. This module is the single source.
"""

from __future__ import annotations


def strip_one_quote_layer(token: str) -> str:
    """Strip a single surrounding matched single/double quote pair, if present.

    The tokenizer emits a quoted argument with its quotes intact (``"import
    os"``, ``'s/a/b/'``); the consumer wants the inner content WITHOUT the shell
    quoting. Only a single outer layer is stripped (sufficient for the
    recognized shapes); an unbalanced or unquoted token is returned unchanged.
    """
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "'\"":
        return token[1:-1]
    return token

"""Evasao SQL: injeta comentarios inline /**/ dentro de palavras-chave.

Ex.: SELECT -> S/**/ELECT, UNION -> U/**/NION. Muitos parsers SQL ignoram
os comentarios; o WAF, nao.
"""

from __future__ import annotations

import re

from wafkit.evasions.registry import register

_KEYWORDS = [
    "information_schema", "benchmark", "load_file", "select", "union",
    "sleep", "concat", "from", "where", "insert", "update", "delete",
    "drop", "into", "outfile", "order", "and", "or", "group", "having",
]


@register("sql_comments", 30)
def ev_sql_comments(ctx):
    out = ctx.payload
    for kw in sorted(_KEYWORDS, key=len, reverse=True):
        repl = kw[0] + "/**/" + kw[1:]
        out = re.sub(r"(?<![a-z0-9_])" + re.escape(kw) + r"(?![a-z0-9_])",
                     repl, out, flags=re.I)
    ctx.payload = out
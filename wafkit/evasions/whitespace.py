"""Evasao de espacos: substitui espacos por comentarios/encodings."""

from __future__ import annotations

import random

from wafkit.evasions.registry import register

_WS_REPL = ["/**/", "%09", "%0a", "%0b", "%0c", "%0d", "/*!00000*/"]


@register("whitespace", 30)
def ev_whitespace(ctx):
    """Troca cada espaco do payload por um equivalente.

    MySQL aceita /**/ e /*!00000*/ (comment de versao); %09/%0a/%0b/%0c/%0d
    sao TAB/LF/VT/FF/CR encodados — burlam assinaturas que exigem espaco
    literal entre palavras-chave SQL.
    """
    out = ctx.payload
    for _ in range(ctx.payload.count(" ")):
        out = out.replace(" ", random.choice(_WS_REPL), 1)
    ctx.payload = out
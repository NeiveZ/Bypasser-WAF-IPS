"""Evasao de case aleatorio — burla assinaturas case-sensitive do WAF."""

from __future__ import annotations

import random

from wafkit.evasions.registry import register


@register("case", 20)
def ev_case(ctx):
    """Alterna maiusculas/minusculas aleatoriamente em letras do payload."""
    ctx.payload = "".join(
        c.upper() if random.random() < 0.5 else c.lower()
        if c.isalpha() else c
        for c in ctx.payload)
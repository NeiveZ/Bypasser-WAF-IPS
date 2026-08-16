"""Evasao HPP (HTTP Parameter Pollution)."""

from __future__ import annotations

from wafkit.evasions.registry import register


@register("hpp", 70)
def ev_hpp(ctx):
    """Envia o parametro-alvo duas vezes: valor benigno primeiro, payload
    por ultimo.

    WAFs que validam apenas a 1a ocorrencia liberam o request; a aplicacao
    normalmente usa a ultima (ou concatena ambas) — o payload passa.
    Requer que ctx.params seja dict; converte para lista de tuplas.
    """
    if isinstance(ctx.params, dict):
        pairs = [(k, v) for k, v in ctx.params.items()
                 if k != ctx.target.param]
        pairs.append((ctx.target.param, "safe"))
        pairs.append((ctx.target.param, ctx.payload))
        ctx.params = pairs
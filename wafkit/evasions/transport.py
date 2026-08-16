"""Evasoes de transporte HTTP: chunked, JSON e XML wrappers (POST)."""

from __future__ import annotations

import json

from wafkit.evasions.registry import register


@register("chunked", 80)
def ev_chunked(ctx):
    """Transfer-Encoding: chunked.

    Muitos WAFs so inspecionam o corpo quando ha Content-Length; com
    chunked o session.py envia o body em blocos de tamanho variavel.
    """
    if ctx.target.method == "POST":
        ctx.headers["Transfer-Encoding"] = "chunked"


@register("json", 80)
def ev_json(ctx):
    """Envolve todos os parametros num corpo JSON (Content-Type json).

    Burla WAFs que so analisam application/x-www-form-urlencoded.
    """
    if ctx.target.method == "POST":
        params = ctx.params
        if isinstance(params, list):  # apos hpp, converte de volta
            params = {k: v for k, v in params}
        ctx.headers["Content-Type"] = "application/json"
        ctx.body = json.dumps(params, ensure_ascii=False)
        ctx.params = {}


@register("xml", 80)
def ev_xml(ctx):
    """Envolve o parametro-alvo num wrapper XML (Content-Type text/xml).

    Para apps que desserializam XML (SOAP/REST legado) e WAFs que nao
    inspecionam corpo XML.
    """
    if ctx.target.method == "POST":
        ctx.headers["Content-Type"] = "text/xml"
        ctx.body = (f"<root><{ctx.target.param}>{ctx.payload}"
                    f"</{ctx.target.param}></root>")
        ctx.params = {}
"""Evasoes de encoding do payload: url, double_url, hex, unicode, html, b64."""

from __future__ import annotations

import base64
import urllib.parse

from wafkit.evasions.registry import register


@register("url", 10)
def ev_url(ctx):
    """URL-encode total do payload (burla assinaturas por bytes puros)."""
    ctx.payload = urllib.parse.quote(ctx.payload, safe="")


@register("double_url", 10)
def ev_double_url(ctx):
    """URL-encode duplo — burla WAFs que decodificam apenas 1 camada."""
    ctx.payload = urllib.parse.quote(
        urllib.parse.quote(ctx.payload, safe=""), safe="")


@register("hex", 10)
def ev_hex(ctx):
    """Codificacao hexadecimal %xx byte a byte."""
    ctx.payload = "".join("%%%02x" % ord(c) for c in ctx.payload)


@register("unicode", 10)
def ev_unicode(ctx):
    """Codificacao %uXXXX (interpretada por IIS/ASP)."""
    ctx.payload = "".join("%u%04x" % ord(c) for c in ctx.payload)


@register("html_entities", 10)
def ev_html(ctx):
    """Entidades HTML decimais &#NN; (para contextos HTML)."""
    ctx.payload = "".join("&#%d;" % ord(c) for c in ctx.payload)


@register("base64", 10)
def ev_b64(ctx):
    """Base64 puro — util quando a app decodifica o parametro."""
    ctx.payload = base64.b64encode(ctx.payload.encode()).decode()
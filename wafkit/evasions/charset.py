"""Evasoes de charset: null byte e overlong UTF-8."""

from __future__ import annotations

from wafkit.evasions.registry import register


@register("null_byte", 25)
def ev_null_byte(ctx):
    """Terminador nulo %00.

    Corta o restante do request em apps antigas (ASP, PHP < 5.3.4) e burla
    regras que so procuram a assinatura ate o fim do payload.
    """
    ctx.payload += "%00"


@register("overlong", 25)
def ev_overlong(ctx):
    """Overlong UTF-8: '.' -> %c0%ae e '/' -> %c0%af.

    Apos o urlencode final, o servidor recebe %25c0%25ae... — se a app
    decodificar duas vezes, vira '.'/'/' e o WAF nao reconheceu nada.
    """
    ctx.payload = (ctx.payload.replace(".", "%c0%ae")
                   .replace("/", "%c0%af"))
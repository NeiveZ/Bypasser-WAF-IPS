"""Normalizacao de texto para comparacoes do Validator.

O objetivo e comparar a resposta da sonda com o baseline ignorando o que
muda por motivos banais (tags, entidades, case, espacos duplicados).
"""

from __future__ import annotations

import html as _html
import re

_TAG_RE = re.compile(r"<[^>]*>")


def normalize(text: str) -> str:
    """Normaliza o corpo de uma resposta HTTP para comparacao robusta.

    1. remove tags HTML (substitui por espaco p/ nao juntar palavras);
    2. decodifica entidades HTML (&#x28; -> '(' etc.);
    3. lowercase;
    4. colapsa qualquer sequencia de whitespace em um espaco unico.
    """
    if not text:
        return ""
    t = _TAG_RE.sub(" ", text)
    t = _html.unescape(t)
    t = t.lower()
    t = re.sub(r"\s+", " ", t)
    return t.strip()
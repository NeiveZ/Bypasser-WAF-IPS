"""Contexto da sonda: estado mutavel que os plugins de evasao transformam."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union


@dataclass
class ProbeContext:
    """Carrega o alvo, o payload atual e os artefatos HTTP em construcao.

    Cada plugin recebe este objeto e altera apenas o que lhe interessa
    (payload, params, headers, body). O transporte (SessionFactory) le o
    resultado final montado pela chain.
    """

    target: Any
    payload: str = ""
    params: Union[Dict[str, str], List[tuple]] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
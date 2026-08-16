"""Modelos de dados centrais do Bypasser."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class ScanType(Enum):
    """Tipos de ataque suportados (nomes == arquivos em configs/payloads/)."""

    SQLI = "sqli"
    XSS = "xss"
    TRAVERSAL = "traversal"
    RCE = "rce"
    SSTI = "ssti"
    SSRF = "ssrf"


@dataclass
class Target:
    """Descricao completa do alvo e do parametro a injetar."""

    url: str
    param: str
    method: str = "POST"
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    verify: str = ""


@dataclass
class Baseline:
    """Mediana das sondas limpas (estado 'normal' da aplicacao)."""

    status: int = 200
    size: int = 0
    elapsed_avg: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
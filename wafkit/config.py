"""Carregamento do settings.yaml via ymin (mini-parser YAML stdlib)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from wafkit.exceptions import ConfigError
from wafkit.utils.ymin import load as load_yaml

_DEFAULT_EVASIONS = [
    "url", "double_url", "hex", "unicode", "html_entities", "base64", "case",
    "sql_comments", "whitespace", "null_byte", "overlong",
    "hpp", "chunked", "json", "xml",
]


@dataclass
class Limits:
    delay: float = 0.8
    jitter: float = 0.3
    timeout: int = 10
    workers: int = 1
    max_chains_per_payload: int = 12
    block_codes: list = field(default_factory=lambda: [403, 406, 429, 503, 509])
    confidence_threshold: int = 70
    stop_on_bypass: bool = True


@dataclass
class TlsSettings:
    impersonate: Optional[str] = None
    http2: bool = False


@dataclass
class OutputSettings:
    log_file: str = "logs/bypasser.log"
    jsonl_events: bool = True


@dataclass
class Settings:
    waf_signatures: str = "configs/waf_signatures.yaml"
    payloads_dir: str = "configs/payloads"
    evasions: list = field(default_factory=lambda: list(_DEFAULT_EVASIONS))
    proxies: list = field(default_factory=list)
    proxy_rotation: str = "round_robin"
    tls: TlsSettings = field(default_factory=TlsSettings)
    limits: Limits = field(default_factory=Limits)
    output: OutputSettings = field(default_factory=OutputSettings)


def load_settings(path: str) -> Settings:
    """Le o settings.yaml e devolve um objeto Settings tipado.

    Campos ausentes assumem os defaults acima (tolerante a config minima).
    """
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"config nao encontrada: {path}")
    data = load_yaml(p.read_text(encoding="utf-8")) or {}

    ev = (data.get("evasions", {}) or {}).get("enabled") or _DEFAULT_EVASIONS

    limits_data = data.get("limits") or {}
    limits = Limits(**{k: v for k, v in limits_data.items()
                       if k in Limits.__dataclass_fields__})

    tls_data = data.get("tls") or {}
    tls = TlsSettings(**{k: v for k, v in tls_data.items()
                         if k in TlsSettings.__dataclass_fields__})

    out_data = data.get("output") or {}
    output = OutputSettings(**{k: v for k, v in out_data.items()
                               if k in OutputSettings.__dataclass_fields__})

    return Settings(
        waf_signatures=data.get("waf_signatures", "configs/waf_signatures.yaml"),
        payloads_dir=data.get("payloads_dir", "configs/payloads"),
        evasions=[e for e in ev if isinstance(e, str)],
        proxies=[p for p in (data.get("proxies") or []) if isinstance(p, str)],
        proxy_rotation=data.get("proxy_rotation", "round_robin"),
        tls=tls,
        limits=limits,
        output=output,
    )
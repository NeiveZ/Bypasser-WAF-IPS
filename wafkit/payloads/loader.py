"""Loader dos payloads por categoria (sqli, xss, traversal, rce, ssti, ssrf)."""

from __future__ import annotations

from pathlib import Path

from wafkit.exceptions import ConfigError
from wafkit.models import ScanType
from wafkit.utils.ymin import load as load_yaml


class PayloadLoader:
    """Le configs/payloads/<tipo>.yaml e devolve a lista de payloads."""

    def __init__(self, directory: str):
        self.dir = Path(directory)

    def load(self, scan_type: ScanType) -> list:
        p = self.dir / f"{scan_type.value}.yaml"
        if not p.exists():
            raise ConfigError(f"arquivo de payloads nao encontrado: {p}")
        data = load_yaml(p.read_text(encoding="utf-8")) or {}
        payloads = data.get("payloads", [])
        if not isinstance(payloads, list):
            raise ConfigError(f"campo 'payloads' invalido em {p}")
        return [str(x) for x in payloads if x is not None]
"""Fingerprint de WAF por pontuacao de headers/cookies/status/corpo."""

from __future__ import annotations

import re
from typing import List

from wafkit.models import Baseline
from wafkit.utils.ymin import load as load_yaml


class WafFingerprinter:
    """Detecta o WAF/proxy do alvo a partir do baseline."""

    def __init__(self, signatures_path: str):
        with open(signatures_path, encoding="utf-8") as fh:
            data = load_yaml(fh.read()) or {}
        self._signatures: List[dict] = data.get("wafs", [])

    def detect(self, baseline: Baseline) -> List[str]:
        hdrs = {k.lower(): v for k, v in baseline.headers.items()}
        cookies = baseline.headers.get("Set-Cookie", "")
        hits: List[tuple] = []
        for sig in self._signatures:
            score = 0
            for h, pat in (sig.get("headers") or {}).items():
                if h.lower() in hdrs:
                    if not pat or re.search(pat, hdrs[h.lower()], re.I):
                        score += 2
            for c in sig.get("cookies") or []:
                if re.search(c, cookies, re.I):
                    score += 2
            if baseline.status in (sig.get("status") or []):
                score += 1
            for b in sig.get("body") or []:
                if b in baseline.body[:4000].lower():
                    score += 2
            if score >= 3:
                hits.append((sig.get("name", "?"), score))
        return [name for name, _ in sorted(hits, key=lambda x: -x[1])]
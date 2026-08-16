"""Validator: veredito + confianca 0-100 por sinais (nao binario)."""

from __future__ import annotations

import difflib
import re

from wafkit.models import Baseline
from wafkit.utils.text import normalize

_SQL_ERROR_RE = re.compile(
    r"SQL syntax|mysql_fetch|Warning: mysql_|Unclosed quotation|"
    r"you have an error|ORA-[0-9]{5}|PostgreSQL|SQLSTATE|sqlite3\.|"
    r"syntax error|near \"", re.I)
_BLOCK_RE = re.compile(
    r"blocked|access denied|request rejected|forbidden|security violation|"
    r"attention required|cf-error|incapsula", re.I)
_SLEEP_RE = re.compile(r"sleep|pg_sleep|waitfor|benchmark|timeout", re.I)


class Validator:
    """Pontua cada sonda contra o baseline e classifica o resultado."""

    def __init__(self, settings):
        self.settings = settings

    def evaluate(self, baseline: Baseline, payload: str, chain: list,
                 status: int, size: int, elapsed: float, text: str,
                 marker: str = "", error: str | None = None) -> dict:
        if error:
            return {"payload": payload, "chain": list(chain), "status": status,
                    "size": size, "elapsed": elapsed, "verdict": "error",
                    "confidence": 0, "signals": {"error": error}}

        block_codes = set(self.settings.limits.block_codes)
        threshold = self.settings.limits.confidence_threshold
        norm_body = normalize(text)
        norm_base = normalize(baseline.body[:4096])

        blocked = status in block_codes or bool(_BLOCK_RE.search(text[:600]))
        reflected = any(
            probe and normalize(probe) in norm_body
            for probe in (marker, payload[:12]) if probe)
        sql_error = bool(_SQL_ERROR_RE.search(text))
        status_delta = (status != baseline.status) and not blocked
        sim = difflib.SequenceMatcher(None, norm_body[:4096],
                                      norm_base).ratio()
        body_delta = sim < 0.85 and not blocked
        time_based = (bool(_SLEEP_RE.search(payload))
                      and elapsed > max(baseline.elapsed_avg * 3,
                                        baseline.elapsed_avg + 2.0))

        score = 0.0
        if reflected:
            score += 40
        if sql_error:
            score += 45
        if time_based:
            score += 45
        if status_delta:
            score += 20
        if body_delta:
            score += 15
        confidence = int(min(100, score))

        if blocked:
            verdict = "blocked"
        elif confidence >= threshold:
            verdict = "bypass"
        elif any((reflected, sql_error, time_based, status_delta, body_delta)):
            verdict = "anomaly"
        else:
            verdict = "clean"

        signals = {
            "reflected": reflected, "sql_error": sql_error,
            "status_delta": status_delta, "similarity": round(sim, 3),
            "body_delta": body_delta, "time_based": time_based,
            "blocked": blocked,
        }
        return {"payload": payload, "chain": list(chain), "status": status,
                "size": size, "elapsed": elapsed, "verdict": verdict,
                "confidence": confidence, "signals": signals}
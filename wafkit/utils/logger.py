"""EventLogger: log rotativo em texto puro + eventos JSONL (1 por linha).

- logs/bypasser.log  -> legivel, com timestamp e veredito por sonda;
- logs/events.jsonl  -> bruto, pronto para jq/pandas:
      jq 'select(.verdict=="bypass")' logs/events.jsonl
"""

from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


class EventLogger:
    """Registra cada sonda no log rotativo e no JSONL de eventos."""

    def __init__(self, settings):
        self.settings = settings
        log_path = Path(settings.output.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        handler = RotatingFileHandler(
            log_path, maxBytes=5 * 1024 * 1024, backupCount=3,
            encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(message)s"))

        self._log = logging.getLogger("bypasser")
        self._log.setLevel(logging.INFO)
        self._log.addHandler(handler)
        self._log.propagate = False

        self.jsonl_path = None
        if settings.output.jsonl_events:
            self.jsonl_path = Path("logs/events.jsonl")
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)

        self._count = 0

    def event(self, res: dict) -> None:
        """Registra o resultado de uma sonda (dict do Validator)."""
        self._count += 1
        verdict = res.get("verdict", "?")
        chain = "+".join(res.get("chain", []))
        msg = (f"[{self._count:>5}] {verdict:<8s} "
               f"conf={res.get('confidence', 0):>3}% "
               f"status={res.get('status', 0):>4} "
               f"tempo={res.get('elapsed', 0.0):5.1f}s "
               f"chain={chain:<28s} payload={res.get('payload')!r}")
        level = logging.WARNING if verdict == "error" else logging.INFO
        self._log.log(level, msg)

        if self.jsonl_path:
            with open(self.jsonl_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(res, ensure_ascii=False) + "\n")
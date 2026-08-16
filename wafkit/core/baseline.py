"""Baseline: mede o estado 'normal' do alvo com sondas limpas."""

from __future__ import annotations

import time

from wafkit.models import Baseline, Target


class BaselineProbe:
    """3 sondas limpas para estabilizar status, tamanho e tempo medio."""

    def __init__(self, session, settings):
        self.session = session
        self.settings = settings

    def measure(self, target: Target) -> Baseline:
        times, sizes, last = [], [], None
        for _ in range(3):
            start = time.time()
            if target.method == "GET":
                r = self.session.request(
                    "GET", target.url, params=target.params,
                    headers=target.headers,
                    timeout=self.settings.limits.timeout)
            else:
                r = self.session.request(
                    "POST", target.url, data=target.params,
                    headers=target.headers,
                    timeout=self.settings.limits.timeout)
            times.append(time.time() - start)
            sizes.append(len(r.content))
            last = r
            time.sleep(self.settings.limits.delay)
        return Baseline(
            status=last.status_code,
            size=int(sum(sizes) / max(len(sizes), 1)),
            elapsed_avg=sum(times) / max(len(times), 1),
            headers=dict(last.headers),
            body=last.text or "",
        )
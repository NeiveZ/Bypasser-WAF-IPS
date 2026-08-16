"""Orquestrador: pipeline baseline -> fingerprint -> scan -> relatorios."""

from __future__ import annotations

import json
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from wafkit.evasions import registry as ev_registry
from wafkit.evasions.base import ProbeContext
from wafkit.models import ScanType, Target
from wafkit.ui import cprint, phase, probe_line
from wafkit.utils.logger import EventLogger
from wafkit.core.validator import Validator

_PAYLOAD_EVASIONS = ["url", "double_url", "hex", "unicode", "html_entities",
                     "base64", "case", "sql_comments", "whitespace",
                     "overlong", "null_byte"]

_TRANSPORT_EVASIONS = ["chunked", "json", "xml"]


class ScanOrchestrator:
    """Controla as fases do scan e a forca de trabalho (1 ou N workers)."""

    def __init__(self, settings, session, baseline, finger, loader):
        self.settings = settings
        self.session = session
        self.baseline = baseline
        self.finger = finger
        self.loader = loader
        self.validator = Validator(settings)
        self.logger = EventLogger(settings)

    # ---- construcao das chains ----
    @staticmethod
    def build_chains(enabled: list, max_chains: int) -> list:
        payload_ev = [e for e in _PAYLOAD_EVASIONS if e in enabled]
        transport_ev = [e for e in _TRANSPORT_EVASIONS if e in enabled]
        combos = []
        for p in payload_ev:
            combos.append([p])
            combos.append([p, "sql_comments"])
            combos.append([p, "whitespace"])
        if "hpp" in enabled:
            for p in payload_ev[:6]:
                combos.append([p, "hpp"])
        for t in transport_ev:
            for p in payload_ev[:6]:
                combos.append([p, t])
        random.shuffle(combos)
        return combos[:max_chains]

    # ---- uma sonda ----
    def probe_once(self, target: Target, payload: str, chain: list,
                   baseline, args) -> dict:
        ctx = ProbeContext(target=target)
        ctx.payload = payload
        ctx.params = dict(target.params)
        ctx.params[target.param] = payload
        ctx.headers = dict(target.headers)
        for name in sorted(chain, key=lambda n: ev_registry.priority(n)):
            ev_registry.apply(name, ctx)
        start = time.time()
        try:
            resp = self.session.send_ctx(ctx)
            elapsed = time.time() - start
            return self.validator.evaluate(
                baseline, payload, chain, resp.status_code, len(resp.content),
                elapsed, resp.text, args.verify)
        except Exception as exc:
            return self.validator.evaluate(
                baseline, payload, chain, 0, 0, 0.0, "", args.verify,
                error=str(exc))

    # ---- pipeline principal ----
    def bypasser(self, args) -> int:
        settings = self.settings
        settings.limits.timeout = args.timeout
        settings.limits.delay = args.delay
        settings.limits.jitter = args.jitter
        settings.limits.workers = args.workers

        params = {}
        for pair in (args.data or "").split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v
        params[args.param] = "A" * 16  # valor benigno p/ baseline
        headers = {}
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        cookies = {}
        for pair in (args.cookie or "").split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

        target = Target(url=args.url, param=args.param, method=args.method,
                        params=params, headers=headers, cookies=cookies,
                        verify=args.verify)

        # FASE 1 - baseline
        phase("FASE 1/3 - baseline (3 sondas limpas)")
        baseline = self.baseline.measure(target)
        cprint(f"  status={baseline.status} tam={baseline.size}B "
               f"tempo_medio={baseline.elapsed_avg:.2f}s", "dim")

        # FASE 2 - fingerprint
        phase("FASE 2/3 - fingerprint de WAF")
        wafs = self.finger.detect(baseline)
        cprint(f"  WAF: {', '.join(wafs) if wafs else 'nenhum identificado'}")

        # FASE 3 - scan
        payloads = self.loader.load(ScanType(args.type))
        if args.max_payloads:
            payloads = payloads[:args.max_payloads]
        if not payloads:
            cprint("[!] lista de payloads vazia para o tipo "
                   f"'{args.type}'", "red")
            return 1
        chains = self.build_chains(settings.evasions, args.max_chains)
        jobs = [(p, c) for p in payloads for c in chains]
        phase(f"FASE 3/3 - varredura: {len(jobs)} sondas "
              f"({len(payloads)} payloads x {len(chains)} chains, "
              f"{args.workers} worker(s))")

        started = time.time()
        results = []
        stop = settings.limits.stop_on_bypass

        if args.workers > 1:
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                futs = {ex.submit(self.probe_once, target, p, c, baseline,
                                  args): (p, c) for p, c in jobs}
                for done in as_completed(futs):
                    res = done.result()
                    res["ts"] = time.time()
                    results.append(res)
                    probe_line(len(results), res)
                    self.logger.event(res)
            results.sort(key=lambda r: r.get("ts", 0))
        else:
            for idx, (payload, chain) in enumerate(jobs, 1):
                res = self.probe_once(target, payload, chain, baseline, args)
                res["ts"] = time.time()
                results.append(res)
                probe_line(idx, res)
                self.logger.event(res)
                if (stop and res["verdict"] == "bypass"
                        and res["confidence"] >= 85):
                    cprint("[!] bypass de alta confianca - interrompendo",
                           "yellow")
                    break
                time.sleep(args.delay + random.uniform(0, args.jitter))

        # resumo
        counts = {v: 0 for v in ("clean", "blocked", "anomaly",
                                 "bypass", "error")}
        for r in results:
            counts[r["verdict"]] += 1
        phase("Resumo")
        cprint(f"  WAF detectado : {', '.join(wafs) or 'nenhum'}")
        cprint(f"  Baseline      : {baseline.status} | {baseline.size}B | "
               f"media {baseline.elapsed_avg:.2f}s")
        for k, v in counts.items():
            color = {"bypass": "green", "anomaly": "yellow",
                     "blocked": "red"}.get(k)
            cprint(f"  {k:<10s}: {v}", color)

        # relatorio JSON
        out_dir = Path(args.outdir)
        out_dir.mkdir(parents=True, exist_ok=True)
        report_path = out_dir / f"scan_{started:.0f}.json"
        report_path.write_text(json.dumps({
            "tool": "bypasser v2.0",
            "target": args.url, "param": args.param, "method": args.method,
            "scan_type": args.type, "wafs": wafs,
            "baseline": {"status": baseline.status, "size": baseline.size,
                         "elapsed_avg": baseline.elapsed_avg},
            "summary": counts,
            "results": results,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        cprint(f"[+] relatorio: {report_path}", "cyan")
        return 0
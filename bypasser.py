from __future__ import annotations
import argparse
import sys
from wafkit.config import load_settings
from wafkit.core.orchestrator import ScanOrchestrator
from wafkit.evasions import registry as ev_registry
from wafkit.payloads.loader import PayloadLoader
from wafkit.ui import banner, cprint, phase


def cmd_check(args) -> int:
    """Sanidade do ambiente: python, modulos, evasoes e payloads."""
    banner()
    cprint(f" python  : {sys.version.split()[0]}", "green")
    cprint(f" evasoes : {len(ev_registry.all())} registradas "
           f"({', '.join(sorted(ev_registry.all()))})", "green")
    loader = PayloadLoader(args.settings.payloads_dir)
    from wafkit.models import ScanType
    for st in ScanType:
        n = len(loader.load(st))
        cprint(f" payloads[{st.value}] : {n}", "green" if n else "red")
    cprint(" OK - pronto para rodar sem dependencias externas.", "green")
    return 0


def cmd_list(args) -> int:
    """Lista as tecnicas de evasao disponiveis (plugins registrados)."""
    banner()
    cprint("Evasoes disponiveis:", "bold")
    for name in sorted(ev_registry.all()):
        prio = ev_registry.priority(name)
        cprint(f"  - {name:<16s} (prioridade {prio})", "cyan")
    cprint("\nUse --no-stop + --workers 1 para percorrer todas as chains.", "dim")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="bypasser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Bypasser — framework modular de evasao de WAF/Firewall.\n"
            "100%% biblioteca padrao do Python (sem venv, sem pip, sem "
            "variaveis de ambiente).\n\n"
            "Fluxo de trabalho:\n"
            "  1) baseline: 3 sondas limpas (status, tamanho, tempo medio)\n"
            "  2) fingerprint: deteccao do WAF por assinaturas\n"
            "  3) scan: chains de evasao x payloads, com veredito e "
            "confianca 0-100\n"
            "  4) relatorio JSON + auditoria JSONL\n\n"
            "Exemplos:\n"
            "  python3 bypasser.py scan --url http://alvo/login.php --param user "
            "--type sqli --method POST --data 'pass=123' --verify 'Bem-vindo'\n"
            "  python3 bypasser.py scan --url http://alvo/busca.php --param q "
            "--type xss --method GET --workers 4\n"
            "  python3 bypasser.py --check\n"
            "  python3 bypasser.py list-evasions\n"),
        epilog="Uso autorizado apenas. Veja o README.",
    )
    ap.add_argument("--check", action="store_true",
                    help="verifica sanidade do ambiente (python, plugins, "
                         "payloads) e sai")
    ap.add_argument("--config", default="configs/settings.yaml",
                    help="caminho do settings.yaml (padrao: "
                         "configs/settings.yaml)")
    ap.set_defaults(func=None)

    s = ap.add_subparsers(dest="cmd", metavar="COMANDO")

    p_scan = s.add_parser(
        "scan", help="executa a varredura de evasao contra o alvo",
        description=(
            "Executa o pipeline completo: baseline -> fingerprint -> scan "
            "de chains de evasao x payloads -> relatorio.\n"
            "Cada sonda recebe um veredito (bypass/blocked/anomaly/clean) "
            "e uma confianca 0-100 baseada em sinais (reflexao, erro SQL, "
            "delay, delta de status/corpo).\n"
            "Com --workers 1 (padrao) o scan para no primeiro bypass de "
            "alta confianca (>=85); use --no-stop para varrer tudo."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_scan.add_argument("--url", required=True,
                        help="URL alvo (ex.: http://alvo/login.php)")
    p_scan.add_argument("--param", required=True,
                        help="nome do parametro a injetar (ex.: user)")
    p_scan.add_argument("--type", choices=["sqli", "xss", "traversal", "rce",
                                           "ssti", "ssrf"],
                        default="sqli",
                        help="categoria de payload (padrao: sqli)")
    p_scan.add_argument("--method", choices=["GET", "POST"], default="POST",
                        help="metodo HTTP (padrao: POST)")
    p_scan.add_argument("--data", default="",
                        help="parametros adicionais do request "
                             "(ex.: 'pass=123&token=abc')")
    p_scan.add_argument("--header", action="append", default=[],
                        help="header extra no formato 'Nome: valor'; "
                             "repita a flag para varios")
    p_scan.add_argument("--cookie", default="",
                        help="cookie de sessao (ex.: 'SID=abc; lang=pt')")
    p_scan.add_argument("--verify", default="",
                        help="marcador de texto esperado na resposta limpa; "
                             "usado para detectar reflexao do payload")
    p_scan.add_argument("--max-payloads", type=int, default=None,
                        help="limita a quantidade de payloads testados")
    p_scan.add_argument("--max-chains", type=int, default=12,
                        help="maximo de chains de evasao por payload "
                             "(padrao: 12)")
    p_scan.add_argument("--workers", type=int, default=1,
                        help="threads paralelas (padrao: 1; aumente apenas "
                             "se o alvo nao tiver rate-limit)")
    p_scan.add_argument("--proxy", default="",
                        help="proxy HTTP (ex.: http://127.0.0.1:8080)")
    p_scan.add_argument("--delay", type=float, default=0.8,
                        help="atraso entre sondas em segundos (padrao: 0.8)")
    p_scan.add_argument("--jitter", type=float, default=0.3,
                        help="variacao aleatoria do atraso (anti-detecao)")
    p_scan.add_argument("--timeout", type=int, default=10,
                        help="timeout por request em segundos (padrao: 10)")
    p_scan.add_argument("--block-codes", default="403,406,429,503,509",
                        help="codigos HTTP tratados como bloqueio "
                             "(padrao: 403,406,429,503,509)")
    p_scan.add_argument("--threshold", type=int, default=70,
                        help="confianca minima (0-100) para considerar "
                             "bypass (padrao: 70)")
    p_scan.add_argument("--no-stop", dest="stop_on_bypass", action="store_false",
                        help="nao interrompe o scan ao achar o primeiro "
                             "bypass de alta confianca")
    p_scan.add_argument("--outdir", default="reports",
                        help="pasta dos relatorios (padrao: reports)")
    p_scan.set_defaults(func=cmd_scan)

    s.add_parser("list-evasions", help="lista as tecnicas de evasao "
                                       "registradas (plugins)",
                 description="Exibe todos os plugins de evasao carregados "
                             "pelo registry com suas prioridades de execucao.",
                 formatter_class=argparse.RawDescriptionHelpFormatter
                 ).set_defaults(func=cmd_list)

    return ap


def cmd_scan(args) -> int:
    from wafkit.core.session import SessionFactory
    from wafkit.core.baseline import BaselineProbe
    from wafkit.core.fingerprint import WafFingerprinter

    banner()
    settings = args.settings
    block_codes = {int(x) for x in args.block_codes.split(",")
                   if x.strip().isdigit()}
    settings.limits.block_codes = sorted(block_codes)
    settings.limits.confidence_threshold = args.threshold
    settings.limits.stop_on_bypass = args.stop_on_bypass

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    params = {}
    for pair in (args.data or "").split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[k] = v
    cookies = {}
    for pair in (args.cookie or "").split(";"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    if args.proxy:
        settings.proxies = [args.proxy]

    session = SessionFactory(settings)
    baseline = BaselineProbe(session, settings)
    finger = WafFingerprinter(settings.waf_signatures)
    loader = PayloadLoader(settings.payloads_dir)
    orch = ScanOrchestrator(settings, session, baseline, finger, loader)
    return orch.bypasser(args)


def main() -> int:
    ap = build_parser()
    args = ap.parse_args()
    args.settings = load_settings(args.config)

    if args.check:
        return cmd_check(args)
    if not getattr(args, "func", None):
        ap.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        cprint("\n[!] interrompido pelo usuario", "yellow")
        return 130
    except Exception as exc:
        cprint(f"[!] erro: {exc}", "red")
        return 1


if __name__ == "__main__":
    sys.exit(main())
"""Interface de console: ANSI puro, sem dependencias (sem rich)."""

from __future__ import annotations

_C = {
    "green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m",
    "magenta": "\033[95m", "cyan": "\033[96m", "dim": "\033[2m",
    "bold": "\033[1m", "reset": "\033[0m",
}

_ICONS = {"bypass": "[+]", "blocked": "[x]", "anomaly": "[~]",
          "clean": "[ ]", "error": "[!]"}
_COLORS = {"bypass": "green", "blocked": "red", "anomaly": "yellow",
           "clean": "dim", "error": "magenta"}


def cprint(text: str = "", color: str | None = None) -> None:
    """Print colorido (no-op se a saida nao for TTY)."""
    if color and color in _C:
        print(f"{_C[color]}{text}{_C['reset']}")
    else:
        print(text)


def banner() -> None:
    cprint("=" * 72, "cyan")
    cprint(" Bypasser v2.0 - evasao de WAF/IPS (uso autorizado)", "cyan")
    cprint("=" * 72, "cyan")


def phase(text: str) -> None:
    cprint(f"\n--- {text} ---", "bold")


def describe(res: dict) -> str:
    """Resumo legivel dos sinais detectados numa sonda."""
    s = res.get("signals", {}) or {}
    parts = []
    if s.get("reflected"):
        parts.append("reflexao")
    if s.get("sql_error"):
        parts.append("erro SQL")
    if s.get("time_based"):
        parts.append(f"delay {res.get('elapsed', 0.0):.1f}s")
    if s.get("status_delta"):
        parts.append(f"status {res.get('status')}")
    if s.get("body_delta"):
        parts.append(f"corpo sim={s.get('similarity')}")
    if res.get("verdict") == "blocked":
        parts.append("bloqueio")
    return ", ".join(parts) or "-"


def probe_line(idx: int, res: dict) -> None:
    """Linha de resultado de uma sonda, com cor por veredito."""
    verdict = res.get("verdict", "error")
    icon = _ICONS.get(verdict, "[ ]")
    color = _COLORS.get(verdict)
    chain = "+".join(res.get("chain", []))
    cprint(
        f"{idx:>4} {icon} {chain:<36s} {str(res.get('payload'))[:44]!r:<48s} "
        f"{res.get('status', 0):>4} {res.get('elapsed', 0.0):5.1f}s "
        f"{res.get('confidence', 0):>3}% {verdict}", color)
    if verdict in ("anomaly", "bypass"):
        cprint(f"       ^ {describe(res)}", "dim")
"""Registry de evasoes: auto-registro por decorator + aplicacao por nome."""

from __future__ import annotations

from wafkit.evasions.base import ProbeContext

_EVASIONS = {}  # nome -> (prioridade, funcao(ctx))


def register(name: str, priority: int):
    """Decorator: registra um plugin de evasao com sua prioridade."""
    def deco(fn):
        _EVASIONS[name] = (priority, fn)
        return fn
    return deco


def all() -> list:
    """Nomes de todas as evasoes registradas."""
    return list(_EVASIONS)


def priority(name: str) -> int:
    """Prioridade de execucao de uma evasao (menor = aplicada antes)."""
    return _EVASIONS.get(name, (0, None))[0]


def apply(name: str, ctx: ProbeContext) -> None:
    """Aplica uma evasao pelo nome; KeyError se nao existir."""
    _EVASIONS[name][1](ctx)


def names_sorted() -> list:
    """Nomes ordenados por prioridade (ordem de aplicacao numa chain)."""
    return sorted(_EVASIONS, key=lambda n: _EVASIONS[n][0])
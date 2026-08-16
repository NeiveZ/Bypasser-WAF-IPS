"""Excecoes padronizadas do Bypasser."""

from __future__ import annotations


class BypasserError(Exception):
    """Erro base de todos os erros do framework."""


class ConfigError(BypasserError):
    """Erro de configuracao (arquivo ausente, YAML malformado, campo invalido)."""


class TargetError(BypasserError):
    """Erro relacionado ao alvo (URL invalida, parametro ausente, etc.)."""


class NetworkError(BypasserError):
    """Falha de rede/conexao ao falar com o alvo."""


class EvasionError(BypasserError):
    """Erro na execucao de um plugin de evasao."""
"""ymin - mini-parser YAML (subset suficiente para configs e payloads).

Suporta: comentarios (# fora de aspas), strings simples/duplas, listas de
bloco (- item), dicts aninhados por indentacao (2 espacos), listas/dicts
inline ([...] e {...}), numeros, booleanos e null.

Escapes: apenas \\ \\" \\' sao processados. \\n permanece como backslash+n
literal (necessario para payloads de shell e caminhos Windows).

REGRAS DE CITACAO (ver README):
  1. Payload que COMECA com { ou [  ->  obrigatorio usar aspas.
  2. Payload com # fora de aspas   ->  o # vira comentario; citar.
  3. Payload que comeca E termina com a MESMA aspa -> _unquote removeria as
     duas; envolver com a aspa OPOSTA, ex.:  '-alert(1)-'  no YAML fica
     "-alert(1)-'  ->  na verdade:  "'-alert(1)-'"  (dupla por fora).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------- lexico ---

def _strip_comment(line: str) -> str:
    """Remove tudo a partir de # fora de aspas simples/duplas."""
    in_s = in_d = esc = False
    for i, c in enumerate(line):
        if esc:
            esc = False
            continue
        if c == "\\":
            esc = True
            continue
        if c == "'" and not in_d:
            in_s = not in_s
        elif c == '"' and not in_s:
            in_d = not in_d
        elif c == "#" and not in_s and not in_d:
            return line[:i]
    return line


def _split_inline(s: str) -> list:
    """Divide por virgulas de nivel 0 (respeitando aspas e []/{})."""
    parts, cur = [], []
    in_s = in_d = depth = 0
    for c in s:
        if c == "'" and not in_d:
            in_s = not in_s; cur.append(c); continue
        if c == '"' and not in_s:
            in_d = not in_d; cur.append(c); continue
        if not in_s and not in_d:
            if c in "[{":
                depth += 1
            elif c in "]}":
                depth -= 1
            elif c == "," and depth == 0:
                parts.append("".join(cur).strip()); cur = []; continue
        cur.append(c)
    if cur:
        parts.append("".join(cur).strip())
    return parts


def _split_kv(s: str):
    """Primeiro ':' fora de aspas -> (chave, valor). Sem ':' -> (s, '')."""
    in_s = in_d = False
    for i, c in enumerate(s):
        if c == "'" and not in_d:
            in_s = not in_s
        elif c == '"' and not in_s:
            in_d = not in_d
        elif c == ":" and not in_s and not in_d:
            return s[:i].strip(), s[i + 1:].strip()
    return s, ""


def _is_kv(s: str) -> bool:
    k, _ = _split_kv(s)
    return bool(k) and k != s


def _unquote(v: str) -> str:
    """Remove aspas externas (simples ou duplas) e processa \\ \\" \\'."""
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        q, body, out, i = v[0], v[1:-1], [], 0
        while i < len(body):
            c = body[i]
            if c == "\\" and i + 1 < len(body) and body[i + 1] in ("\\", q):
                out.append(body[i + 1]); i += 2; continue
            out.append(c); i += 1
        return "".join(out)
    return v


def _parse_value(v: str):
    v = v.strip()
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return [] if not inner else [_parse_value(x) for x in _split_inline(inner)]
    if v.startswith("{") and v.endswith("}"):
        inner = v[1:-1].strip()
        if not inner:
            return {}
        d = {}
        for part in _split_inline(inner):
            k, val = _split_kv(part)
            d[k] = _parse_value(val)
        return d
    uq = _unquote(v)
    low = uq.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if uq in ("null", "~", ""):
        return None
    if re.fullmatch(r"[-+]?\d+", uq):
        return int(uq)
    if re.fullmatch(r"[-+]?\d*\.\d+", uq):
        return float(uq)
    return uq


# ---------------------------------------------------------------- bloco ----

def _parse(lines: list, i: int):
    """Parseia o bloco a partir de lines[i]; devolve (valor, proximo indice)."""
    line = lines[i]
    indent = len(line) - len(line.lstrip())
    is_list = line.strip().startswith("- ")
    result = [] if is_list else {}

    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        cur = len(line) - len(line.lstrip())
        if cur < indent:
            break
        if cur > indent:
            raise ValueError(f"ymin: indentacao inesperada em {line!r}")
        stripped = line.strip()

        if is_list:
            if not stripped.startswith("- "):
                break
            rest = stripped[2:].strip()
            if _is_kv(rest):
                entry, k, v = {}, *_split_kv(rest)
                i += 1
                if v == "":
                    if i < len(lines) and len(lines[i]) - len(lines[i].lstrip()) > indent:
                        entry[k], i = _parse(lines, i)
                    else:
                        entry[k] = {}
                else:
                    entry[k] = _parse_value(v)
                    while i < len(lines):
                        nxt = lines[i]
                        if not nxt.strip():
                            i += 1; continue
                        ncur = len(nxt) - len(nxt.lstrip())
                        if ncur <= indent:
                            break
                        if ncur != indent + 2:
                            raise ValueError(f"ymin: indentacao em {nxt!r}")
                        k2, v2 = _split_kv(nxt.strip())
                        i += 1
                        if v2 == "":
                            if i < len(lines) and len(lines[i]) - len(lines[i].lstrip()) > ncur:
                                entry[k2], i = _parse(lines, i)
                            else:
                                entry[k2] = {}
                        else:
                            entry[k2] = _parse_value(v2)
                result.append(entry)
            else:
                result.append(_parse_value(rest))
                i += 1
        else:
            if stripped.startswith("- "):
                break
            if not _is_kv(stripped):
                raise ValueError(f"ymin: linha invalida {stripped!r}")
            k, v = _split_kv(stripped)
            i += 1
            if v == "":
                if i < len(lines) and len(lines[i]) - len(lines[i].lstrip()) > indent:
                    result[k], i = _parse(lines, i)
                else:
                    result[k] = {}
            else:
                result[k] = _parse_value(v)
    return result, i


def load(text: str):
    """Converte texto YAML em objetos Python (dict raiz)."""
    lines = [_strip_comment(raw).rstrip()
             for raw in text.splitlines()
             if _strip_comment(raw).strip()]
    if not lines:
        return {}
    value, _ = _parse(lines, 0)
    return value
"""Проверка переводов интерфейса (ADR-0158).

    python scripts/i18n_check.py                 – полнота каталога: у каждой строки из _(), N_(), plural(), Labels(),
                                                   ltT(), ltPlural() есть английский перевод без кириллицы и с теми же
                                                   подстановками {name}; код выхода 1 при пропусках
    python scripts/i18n_check.py --raw ФАЙЛЫ…    – кириллица вне перевода в указанных файлах (шаблоны, Python, JS):
                                                   что ещё не обёрнуто; докстринги, комментарии и вызовы журнала
                                                   (log.*) не считаются
    python scripts/i18n_check.py --missing ФАЙЛЫ… – строки этих файлов без перевода в каталоге, JSON «msgid: ""»
                                                   (заготовка для части каталога)

Ключ перевода – русский текст (msgid), каталог – app/locales/en/*.json.
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import i18n  # noqa: E402

CYR = re.compile(r"[А-Яа-яЁё]")
# строки шаблонов: _("…"), _('…'); plural(n, "…", "…", "…") и фильтр |plural("…", "…", "…")
_STR = r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\''
TPL_CALL = re.compile(r"(?<![A-Za-z0-9_.])(?:_|N_|ltT)\(\s*(?:" + _STR + r")")
TPL_PLURAL = re.compile(r"(?:plural|ltPlural)\(\s*(?:[^,()]+(?:\([^()]*\))?\s*,\s*)?(?:" + _STR + r")\s*,\s*(?:"
                        + _STR + r")\s*,\s*(?:" + _STR + r")\s*\)")
SKIP_PY = {"prompts.py", "hub_import.py", "i18n.py"}  # промпт и формат выгрузки Hub не переводятся (ADR-0158)


def _unescape(text: str) -> str:
    try:
        return json.loads('"' + text.replace('"', '\\"').replace("\\'", "'") + '"')
    except ValueError:
        return text


def _first(groups: Iterable[str | None]) -> str:
    for g in groups:
        if g is not None:
            return _unescape(g)
    return ""


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def python_msgids(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        args = node.args
        if name in ("_", "N_", "translate") and args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
            out.append(args[0].value)
        elif name in ("plural", "_plural") and len(args) >= 4 and all(
                isinstance(a, ast.Constant) and isinstance(a.value, str) for a in args[1:4]):
            out.append("|".join(a.value for a in args[1:4]))
        elif name in ("Labels", "register_messages") and args and isinstance(args[0], ast.Dict):
            out += [v.value for v in args[0].values if isinstance(v, ast.Constant) and isinstance(v.value, str)]
    return [m for m in out if CYR.search(m)]


def text_msgids(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".js":  # комментарии сценариев – не строки интерфейса
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    else:
        text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    out = [_first(m.groups()) for m in TPL_CALL.finditer(text)]
    for m in TPL_PLURAL.finditer(text):
        g = m.groups()
        out.append("|".join(_first(g[i:i + 2]) for i in (0, 2, 4)))
    return [m for m in out if CYR.search(m)]


def source_files() -> list[Path]:
    files = [p for p in (ROOT / "app").rglob("*.py") if "__pycache__" not in p.parts and p.name not in SKIP_PY]
    files += list((ROOT / "app" / "templates").rglob("*.html"))
    files += list((ROOT / "app" / "static").glob("*.js"))
    return sorted(files)


def msgids_of(path: Path) -> list[str]:
    return python_msgids(path) if path.suffix == ".py" else text_msgids(path)


def all_msgids() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for path in source_files():
        for m in msgids_of(path):
            found.setdefault(m, []).append(str(path.relative_to(ROOT)))
    return found


def problems() -> list[str]:
    i18n.reload_catalog()
    cat = i18n.catalog()
    out = [f"разные переводы: {c}" for c in i18n.conflicts()]
    for msgid, where in sorted(all_msgids().items()):
        value = cat.get(msgid)
        if value is None:
            out.append(f"нет перевода: {msgid!r} ({where[0]})")
            continue
        if CYR.search(value):
            out.append(f"кириллица в переводе: {msgid!r} -> {value!r}")
        if "|" in msgid and msgid.count("|") == 2 and "|" not in value:
            out.append(f"у формы числа нет «единственное|множественное»: {msgid!r} -> {value!r}")
        try:
            if i18n.placeholders(msgid) != i18n.placeholders(value):
                out.append(f"подстановки не совпадают: {msgid!r} -> {value!r}")
        except ValueError as e:
            out.append(f"испорченная подстановка: {msgid!r} -> {value!r} ({e})")
    return out


# ------------------------------------------------------------------ кириллица вне перевода

def _docstring_ids(tree: ast.AST) -> set[int]:
    ids = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body:
            first = n.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def raw_python(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skip = _docstring_ids(tree)
    for n in ast.walk(tree):  # внутри перевода и вызовов журнала – не считаются
        if isinstance(n, ast.Call):
            name = _call_name(n)
            is_log = isinstance(n.func, ast.Attribute) and name in ("debug", "info", "warning", "error", "exception", "log",
                                                                    "critical") or name == "log_failure"
            if name in ("_", "N_", "plural", "_plural", "Labels", "translate", "register_messages") or is_log:
                for sub in ast.walk(n):
                    skip.add(id(sub))
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and CYR.search(n.value) and id(n) not in skip:
            out.append((n.lineno, n.value[:100]))
    return sorted(out)


_TPL_STRIP = [re.compile(r"\{#.*?#\}", re.S), re.compile(r"\{\{.*?\}\}", re.S), re.compile(r"\{%.*?%\}", re.S)]


def raw_text(path: Path) -> list[tuple[int, str]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".js":
        text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
        text = re.sub(r"//[^\n]*", "", text)
        text = TPL_CALL.sub("", text)
        text = TPL_PLURAL.sub("", text)
    else:
        for rx in _TPL_STRIP:
            text = rx.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    out = []
    for no, line in enumerate(text.splitlines(), 1):
        if CYR.search(line):
            out.append((no, line.strip()[:120]))
    return out


def raw(path: Path) -> list[tuple[int, str]]:
    return raw_python(path) if path.suffix == ".py" else raw_text(path)


def main(argv: list[str]) -> int:
    if argv[:1] == ["--raw"]:
        total = 0
        for name in argv[1:]:
            path = Path(name).resolve()
            items = raw(path)
            total += len(items)
            for no, text in items:
                print(f"{path.relative_to(ROOT)}:{no}: {text}")
        print(f"всего: {total}", file=sys.stderr)
        return 0
    if argv[:1] == ["--missing"]:
        cat = i18n.catalog()
        missing = {}
        for name in argv[1:]:
            for m in msgids_of(Path(name).resolve()):
                if m not in cat:
                    missing[m] = ""
        print(json.dumps(missing, ensure_ascii=False, indent=1))
        return 0
    found = problems()
    for line in found:
        print(line)
    print(f"строк: {len(all_msgids())}, замечаний: {len(found)}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

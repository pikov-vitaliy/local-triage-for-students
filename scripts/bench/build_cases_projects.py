"""Эталон по тестовым проектам с GitHub для стенда замера моделей: Juice Shop по
авторским меткам, плюс PyGoat и WebGoat вручную.

Источники известных ответов:
- OWASP Juice Shop: авторская разметка в коде – комментарии `vuln-code-snippet vuln-line <задание>` (строка намеренно
  уязвима) и `vuln-code-snippet neutral-line <задание>` (строка внутри уязвимого фрагмента, которая уязвимой не
  является); описание задания – `data/static/challenges.yml` (name, category, difficulty). Классы CWE по категориям
  задания – наше соответствие (CWE_BY_CATEGORY), а не авторское: у авторов CWE нет.
- PyGoat и WebGoat: список уязвимых строк, составленный вручную по коду лабораторий и уроков (`--known ФАЙЛ.json`,
  записи {project, lesson, file, line, cwe, cwe_name, why, confidence}); каждая запись сверяется с файлом клона:
  строка должна существовать, иначе запись отклоняется с замечанием.

Набор пишется в results/bench/cases-projects.json (схема случая – как у build_cases.py: id, source, category, cwe,
rule, language, repo_root, file, line, snippet, expected, also_ok, expected_note, hint_comment, codebase, hub_file)
и cases_meta-projects.json. Папка results/ в .gitignore: в наборе абсолютные пути к клонам и строки чужого кода.
Важно: у Juice Shop метка стоит в самой уязвимой строке комментарием – модель видит подсказку; поле hint_comment =
true, стенд считает такие случаи отдельно (как подсказки OWASP Benchmark).

Запуск из корня репозитория:
    .venv\\Scripts\\python -I -B scripts/bench/build_cases_projects.py --juice-shop ПАПКА_КЛОНА \\
        --known test-projects/known-pygoat-webgoat.json --pygoat ПАПКА --webgoat ПАПКА [--hub-out ПАПКА]
`--hub-out` – дополнительно выгрузки формата Hub (`<проект>-known-hub.xlsx`) из тех же случаев: для показа цикла в
приложении на известных ответах (сборщик листов – scripts/make_hub_from_sast.py).
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True
for _stream in (sys.stdout, sys.stderr):  # -I не берёт PYTHONIOENCODING: вывод кириллицы в консоль Windows
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

import argparse  # noqa: E402
import datetime as dt  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
from pathlib import Path  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
OUT_DIR = REPO / "results" / "bench"

MARK = re.compile(r"vuln-code-snippet\s+(vuln-line|neutral-line)\s+([A-Za-z0-9_ ]+?)\s*(?:-->|\*/|$)")
SKIP_DIRS = {"node_modules", "build", "dist", ".git", "coverage", "vagrant"}
CODE_SUFFIXES = {".ts": "TypeScript", ".js": "JavaScript", ".html": "HTML", ".yml": "YAML", ".yaml": "YAML",
                 ".py": "Python", ".java": "Java", ".ejs": "HTML"}

# Наше соответствие категорий заданий Juice Shop классам CWE (у авторов классов нет; где класс неочевиден – «-»).
CWE_BY_CATEGORY = {
    "Injection": ("CWE-89", "Внедрение (SQL/NoSQL)"),
    "XSS": ("CWE-79", "Межсайтовый скриптинг"),
    "Sensitive Data Exposure": ("CWE-200", "Раскрытие чувствительных данных"),
    "Broken Access Control": ("CWE-284", "Нарушение контроля доступа"),
    "Improper Input Validation": ("CWE-20", "Недостаточная проверка входных данных"),
    "Broken Authentication": ("CWE-287", "Ошибки аутентификации"),
    "Security Misconfiguration": ("CWE-16", "Небезопасная конфигурация"),
    "Cryptographic Issues": ("CWE-327", "Слабая криптография"),
    "Vulnerable Components": ("CWE-1104", "Уязвимые компоненты"),
    "Insecure Deserialization": ("CWE-502", "Небезопасная десериализация"),
    "XXE": ("CWE-611", "Внешние сущности XML"),
    "Unvalidated Redirects": ("CWE-601", "Открытое перенаправление"),
    "Observability Failures": ("CWE-532", "Чувствительные данные в журналах"),
    "Broken Anti Automation": ("CWE-799", "Нет защиты от автоматизации"),
    "Security through Obscurity": ("CWE-656", "Безопасность через неясность"),
    "Miscellaneous": ("-", "Прочее"),
}
SEVERITY_BY_DIFFICULTY = {1: "Low", 2: "Low", 3: "Medium", 4: "Medium", 5: "High", 6: "High"}


def load_challenges(clone: Path) -> dict[str, dict]:
    """challenges.yml без YAML-библиотеки: записи начинаются с «-», поля name/category/difficulty/key однострочные."""
    text = (clone / "data" / "static" / "challenges.yml").read_text(encoding="utf-8")
    out: dict[str, dict] = {}
    current: dict = {}
    for raw in text.splitlines():
        if raw.rstrip() == "-":
            if current.get("key"):
                out[current["key"]] = current
            current = {}
            continue
        m = re.match(r"^  (name|category|difficulty|key):\s*(.+?)\s*$", raw)
        if m:
            value = m.group(2).strip().strip("'\"")
            current[m.group(1)] = int(value) if m.group(1) == "difficulty" else value
    if current.get("key"):
        out[current["key"]] = current
    return out


def strip_marker(line: str) -> str:
    """Строка кода без комментария-метки (срез в карточке приложение берёт из клона – там метка остаётся)."""
    return re.sub(r"\s*(?://|<!--|/\*|#)\s*vuln-code-snippet.*$", "", line).rstrip()


def juice_shop_cases(clone: Path) -> tuple[list[dict], dict]:
    challenges = load_challenges(clone)
    cases: list[dict] = []
    unknown_keys: set[str] = set()
    for path in sorted(clone.rglob("*")):
        if not path.is_file() or path.suffix not in CODE_SUFFIXES or SKIP_DIRS & set(path.relative_to(clone).parts):
            continue
        try:
            lines = path.read_text(encoding="utf-8").split("\n")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(clone).as_posix()
        for n, raw in enumerate(lines, 1):
            m = MARK.search(raw)
            if not m:
                continue
            kind = m.group(1)
            keys = m.group(2).split()
            main_key = keys[0]
            info = challenges.get(main_key)
            if info is None:
                unknown_keys.add(main_key)
                info = {"name": main_key, "category": "Miscellaneous", "difficulty": 3}
            cwe, rule = CWE_BY_CATEGORY.get(info["category"], ("-", info["category"]))
            vulnerable = kind == "vuln-line"
            cases.append({
                "id": f"JS-{main_key}-{n}",
                "source": "juice-shop-markers",
                "category": info["category"],
                "cwe": cwe,
                "rule": f"{rule}: {info['name']}",
                "language": CODE_SUFFIXES[path.suffix],
                "repo_root": clone.as_posix(),
                "file": rel,
                "line": n,
                "snippet": strip_marker(raw).strip(),
                "expected": "true_positive" if vulnerable else "false_positive",
                "how_line": "авторская метка vuln-line" if vulnerable else "авторская метка neutral-line",
                "also_ok": [] if vulnerable else ["uncertain"],
                "expected_note": (f"Задание «{info['name']}» (сложность {info['difficulty']}): строка помечена авторами как "
                                  + ("уязвимая" if vulnerable else "не уязвимая внутри уязвимого фрагмента")
                                  + ("; задания: " + ", ".join(keys) if len(keys) > 1 else "")),
                "depends_on": None,
                "hint_comment": True,
                "hint_comments": [m.group(0)],
                "sink_pattern": None,
                "codebase": clone.name,
                "hub_file": None,
                "severity": SEVERITY_BY_DIFFICULTY.get(int(info["difficulty"]), "Medium"),
            })
    meta = {"challenges": len(challenges), "vuln_lines": sum(1 for c in cases if c["expected"] == "true_positive"),
            "neutral_lines": sum(1 for c in cases if c["expected"] == "false_positive"),
            "unknown_keys": sorted(unknown_keys),
            "note": "neutral-line → ложное срабатывание (строка внутри уязвимого фрагмента, но не уязвимая) – наше толкование, "
                    "допускается «неясно»; метки стоят в коде комментарием – подсказка видна модели (hint_comment)"}
    return cases, meta


def known_cases(path: Path, roots: dict[str, Path]) -> tuple[list[dict], dict]:
    """Ручной список для PyGoat и WebGoat: каждая запись сверяется с файлом клона."""
    rows = json.loads(path.read_text(encoding="utf-8-sig"))
    cases, problems = [], []
    for i, r in enumerate(rows, 1):
        project = str(r.get("project") or "")
        root = roots.get(project)
        if root is None:
            problems.append(f"{i}: проект «{project}» без папки клона (--pygoat/--webgoat)")
            continue
        rel = str(r.get("file") or "").replace("\\", "/").strip("/")
        file = root / rel
        if not file.is_file():
            problems.append(f"{i}: файла нет – {project}/{rel}")
            continue
        lines = file.read_text(encoding="utf-8", errors="replace").split("\n")
        line = int(r.get("line") or 0)
        if not 1 <= line <= len(lines):
            problems.append(f"{i}: строки {line} нет в {project}/{rel} ({len(lines)} строк)")
            continue
        actual = lines[line - 1].strip()
        claimed = str(r.get("code") or "").strip()
        if claimed and claimed not in actual and actual not in claimed:
            problems.append(f"{i}: текст строки {project}/{rel}:{line} не совпадает: в файле «{actual[:80]}», в списке «{claimed[:80]}»")
            continue
        cwe = str(r.get("cwe") or "-")
        confidence = str(r.get("confidence") or "high")
        cases.append({
            "id": f"{project.upper()}-{i:03d}",
            "source": f"{project}-manual",
            "category": str(r.get("cwe_name") or cwe),
            "cwe": cwe if cwe.startswith("CWE-") else "-",
            "rule": f"{r.get('cwe_name') or cwe}: {r.get('lesson') or ''}".strip(": "),
            "language": CODE_SUFFIXES.get(file.suffix, "Python" if project == "pygoat" else "Java"),
            "repo_root": root.as_posix(),
            "file": rel,
            "line": line,
            "snippet": actual,
            "expected": "true_positive",
            "how_line": f"ручная разметка ({confidence})",
            "also_ok": ["uncertain"] if confidence != "high" else [],
            "expected_note": str(r.get("why") or ""),
            "depends_on": None,
            "hint_comment": False,
            "hint_comments": [],
            "sink_pattern": None,
            "codebase": root.name,
            "hub_file": None,
            "severity": "High" if confidence == "high" else "Medium",
        })
    return cases, {"rows": len(rows), "accepted": len(cases), "problems": problems}


def write_hub(cases: list[dict], out_dir: Path) -> list[str]:
    """Выгрузки формата Hub по случаям – для показа цикла в приложении (лист SAST, номера от 950001)."""
    spec = importlib.util.spec_from_file_location("make_hub", REPO / "scripts" / "make_hub_from_sast.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    written = []
    for codebase in sorted({c["codebase"] for c in cases}):
        rows = []
        number = 950001
        for c in [x for x in cases if x["codebase"] == codebase]:
            cwe_num = c["cwe"].replace("CWE-", "") if c["cwe"].startswith("CWE-") else ""
            rows.append({"Issue id": str(number), "Application": codebase, "Severity": c["severity"],
                         "Category": c["rule"][:300], "File": c["file"], "Line number": str(c["line"]),
                         "Source code": c["snippet"][:300], "Status": "To verify", "Type": "source",
                         "Found By": "known-answers", "CWE ID": cwe_num or "-",
                         "CWE link": module.MITRE.format(cwe_num) if cwe_num else "-", "Codebase": codebase,
                         "Artifact": "-", "Language": c["language"]})
            number += 1
        out = out_dir / f"{codebase}-known-hub.xlsx"
        module.write_xlsx(out, codebase, rows, [])
        written.append(f"{out}: {len(rows)}")
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description="Эталон по тестовым проектам: Juice Shop по меткам, PyGoat/WebGoat по списку")
    ap.add_argument("--juice-shop", type=Path, help="клон OWASP Juice Shop")
    ap.add_argument("--known", type=Path, help="JSON-список уязвимых строк PyGoat/WebGoat (ручная разметка)")
    ap.add_argument("--pygoat", type=Path, help="клон PyGoat (для --known)")
    ap.add_argument("--webgoat", type=Path, help="клон WebGoat (для --known)")
    ap.add_argument("--out", type=Path, default=OUT_DIR / "cases-projects.json")
    ap.add_argument("--hub-out", type=Path, help="папка для выгрузок формата Hub по тем же случаям")
    args = ap.parse_args()
    cases: list[dict] = []
    meta: dict = {"built_at": dt.datetime.now().isoformat(timespec="seconds"), "sources": {}}
    if args.juice_shop:
        js, js_meta = juice_shop_cases(args.juice_shop)
        cases += js
        meta["sources"]["juice-shop"] = js_meta
    if args.known:
        roots = {k: v for k, v in (("pygoat", args.pygoat), ("webgoat", args.webgoat)) if v}
        kn, kn_meta = known_cases(args.known, roots)
        cases += kn
        meta["sources"]["known"] = kn_meta
    if not cases:
        print("нет источников: укажите --juice-shop и/или --known с --pygoat/--webgoat", file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(cases, ensure_ascii=False, indent=1), encoding="utf-8")
    meta_path = args.out.with_name(args.out.stem.replace("cases", "cases_meta") + ".json")
    meta["cases"] = len(cases)
    meta["expected"] = {k: sum(1 for c in cases if c["expected"] == k) for k in ("true_positive", "false_positive")}
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    if args.hub_out:
        args.hub_out.mkdir(parents=True, exist_ok=True)
        for line in write_hub(cases, args.hub_out):
            print(line)
    print(f"{args.out}: случаев {len(cases)} ({meta['expected']}); meta – {meta_path}")
    problems = meta["sources"].get("known", {}).get("problems") or []
    for p in problems:
        print("замечание:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

"""Выгрузка в формате AppSec.Hub из отчётов открытых анализаторов – для демонстрации приложения на тестовых проектах
без доступа к Hub: клон проекта с известными уязвимостями + настоящие находки SAST →
файл `.xlsx` с листами Hub (сводка, SAST, при желании SCA Security из списка компонентов).

Поддерживаются отчёты:
- Bandit (Python): `bandit -r ПАПКА -f json -o bandit.json`;
- Semgrep (любой язык): `semgrep scan --config p/owasp-top-ten --json -o semgrep.json .` (в том числе из образа
  Docker `semgrep/semgrep`).

Колонки и листы – как у отчёта Hub (tests/hub_fixtures.py описывает те же заголовки); номера находок и категории –
от анализатора, не от Hub. Пути файлов – относительно корня клона: кодовая база в выгрузке называется по имени папки
клона, тогда папка клонов приложения подбирается по имени. Все значения – строки, пустое – «-».

Запуск из корня репозитория:
    .venv\\Scripts\\python scripts/make_hub_from_sast.py --app "PyGoat" --codebase pygoat --language Python \\
        --bandit test-projects/pygoat-bandit.json --semgrep test-projects/pygoat-semgrep.json \\
        --sca test-projects/pygoat-sca.csv --out test-projects/pygoat-hub.xlsx
`--sca` – CSV с колонками ecosystem,component,version,cve,cvss,fixed[,note] (необязательно; note попадает в категорию).
Пути из отчётов приводятся к путям внутри клона: всё до папки `--codebase` включительно снимается.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import sys
from pathlib import Path

HEADERS = {
    "SAST": ["Issue id", "Application", "Severity", "Category", "File", "Line number", "Source code", "Status", "Type",
             "Found By", "CWE ID", "CWE link", "Codebase", "Artifact", "Language"],
    "SCA Security": ["Issue id", "Application", "Severity", "CVSS score", "Category", "Component name",
                     "Component version", "CVE id", "Status", "Type", "Found By", "Non-vulnerable versions", "Path",
                     "CWE ID", "CWE link", "Codebase", "Artifact", "Proxy"],
    "SCA Compliance": ["Issue id", "Application", "Severity", "Category", "Component name", "Component version",
                       "Licenses", "Status", "Type", "Found By", "Non-vulnerable versions", "Path", "Codebase",
                       "Artifact", "Proxy"],
    "DAST": ["Issue id", "Application", "Severity", "Location", "Source", "Status", "Found By", "CWE ID", "CWE link",
             "Artifact", "Instance"],
}
MITRE = "https://cwe.mitre.org/data/definitions/{}.html"
SEVERITY_BANDIT = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
SEVERITY_SEMGREP = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low", "CRITICAL": "High", "HIGH": "High",
                    "MEDIUM": "Medium", "LOW": "Low"}
ECOSYSTEM_TYPE = {"pypi": "pip", "npm": "npm", "maven": "maven", "nuget": "nuget", "go": "go", "cargo": "cargo",
                  "packagist": "composer", "rubygems": "gem"}
# Язык находки – по файлу (иначе у Dockerfile и шаблонов HTML стоял бы язык всей выгрузки «Python»);
# неизвестное расширение – значение --language
LANGUAGE_BY_SUFFIX = {".py": "Python", ".html": "HTML", ".htm": "HTML", ".js": "JavaScript", ".jsx": "JavaScript",
                      ".mjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".kt": "Kotlin",
                      ".xml": "XML", ".yml": "YAML", ".yaml": "YAML", ".json": "JSON", ".sh": "Shell", ".sql": "SQL",
                      ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".cs": "C#"}
# Semgrep без входа в учётную запись вместо строки кода пишет в extra.lines эту заглушку (все 131 срабатывание
# тестовых проектов 25.10) – строка берётся из файла клона
SEMGREP_NO_LINES = "requires login"


def language_of(file: str, default: str) -> str:
    name = str(file or "").replace("\\", "/").rsplit("/", 1)[-1]
    if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile"):
        return "Dockerfile"
    suffix = name[name.rfind("."):].lower() if "." in name else ""
    return LANGUAGE_BY_SUFFIX.get(suffix, default)


def source_line(root: Path | None, file: str, line: int | None) -> str:
    """Строка line файла клона (до 300 знаков, без концевых пробелов); файла или строки нет – ""."""
    if root is None or not line:
        return ""
    try:
        lines = (root / file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return lines[int(line) - 1].strip()[:300] if 0 < int(line) <= len(lines) else ""


def _norm_path(path: str, root_name: str, root: Path | None = None) -> str:
    """Путь внутри клона: разделители – «/»; всё до папки клона включительно (относительный `test-projects/pygoat/…`,
    абсолютный, `./`) снимается – тогда отчёты Bandit и Semgrep, запущенных из разных папок, сравниваются одинаково.
    root – папка клона: берётся тот вариант пути, файл которого в ней есть. Имя клона бывает и папкой внутри проекта
    (WebGoat: `src/main/java/org/owasp/webgoat/…`) – без проверки по клону путь обрезался до несуществующего
    (25.10: из 45 путей выгрузки WebGoat в клоне были 2)."""
    p = str(path or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    parts = p.split("/")
    name = str(root_name or "").casefold()  # имя папки клона – без учёта регистра (WebGoat и webgoat; ревью круг 18)
    cut = ["/".join(parts[i + 1:]) for i, part in enumerate(parts) if part.casefold() == name and i + 1 < len(parts)]
    if root is not None:
        absolute = p.startswith("/") or bool(re.match(r"^[A-Za-z]:/", p))
        candidates = [] if absolute else [p]
        if absolute:  # абсолютный путь внутри папки клона – относительно неё, как бы ни называлась папка
            try:
                candidates.append(Path(p).resolve().relative_to(root.resolve()).as_posix())
            except (ValueError, OSError):
                pass
        for candidate in candidates + cut:
            if candidate and (root / candidate).is_file():
                return candidate
    return cut[0] if cut else p


def _cwe_of(value) -> list[str]:
    """Номера CWE из числа, строки «CWE-89: …» или списка таких значений."""
    items = value if isinstance(value, list) else [value]
    found = []
    for item in items:
        m = re.search(r"(\d{1,5})", str(item or ""))
        if m and m.group(1) not in found:
            found.append(m.group(1))
    return found


def bandit_rows(report: dict, codebase: str, language: str, root: Path | None = None) -> list[dict]:
    rows = []
    for item in report.get("results") or []:
        cwe = _cwe_of((item.get("issue_cwe") or {}).get("id"))
        file = _norm_path(item.get("filename", ""), codebase, root)
        rows.append({"Severity": SEVERITY_BANDIT.get(str(item.get("issue_severity")).upper(), "Low"),
                     "Category": f"{item.get('test_id')} {item.get('test_name')}: {item.get('issue_text')}"[:300],
                     "File": file,
                     "Line number": str(item.get("line_number") or ""),
                     "Source code": _code_line(item.get("code") or "", item.get("line_number")),
                     "Found By": "bandit", "CWE ID": ", ".join(cwe) or "-",
                     "CWE link": ", ".join(MITRE.format(c) for c in cwe) or "-",
                     "Language": language_of(file, language)})
    return rows


def semgrep_rows(report: dict, codebase: str, language: str, root: Path | None = None) -> list[dict]:
    """root – папка клона: строка кода берётся из файла, когда Semgrep вместо неё отдал заглушку."""
    rows = []
    for item in report.get("results") or []:
        extra = item.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwe = _cwe_of(meta.get("cwe") or [])
        rule = str(item.get("check_id") or "").split(".")[-1]
        file = _norm_path(item.get("path", ""), codebase, root)
        line = (item.get("start") or {}).get("line")
        code = str(extra.get("lines") or "").strip().split("\n")[0][:300]
        if not code or code == SEMGREP_NO_LINES:
            code = source_line(root, file, line)
        rows.append({"Severity": SEVERITY_SEMGREP.get(str(extra.get("severity")).upper(), "Low"),
                     "Category": f"{rule}: {extra.get('message', '')}"[:300].replace("\n", " "),
                     "File": file,
                     "Line number": str(line or ""),
                     "Source code": code or "-",
                     "Found By": "semgrep", "CWE ID": ", ".join(cwe) or "-",
                     "CWE link": ", ".join(MITRE.format(c) for c in cwe) or "-",
                     "Language": language_of(file, language)})
    return rows


def _code_line(block: str, line: int | None) -> str:
    """Строка срабатывания из блока кода Bandit («NN текст»)."""
    for raw in str(block).split("\n"):
        m = re.match(r"\s*(\d+)\s(.*)$", raw)
        if m and line is not None and int(m.group(1)) == int(line):
            return m.group(2).strip()[:300]
    return str(block).strip().split("\n")[0][:300]


def sca_rows(path: Path, codebase: str) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8-sig", newline="") as f:
        for item in csv.DictReader(f):
            cvss = str(item.get("cvss") or "").strip()
            severity = "Critical" if cvss and float(cvss) >= 9 else "High" if cvss and float(cvss) >= 7 else "Medium"
            category = "Политика: CVSS выше 6" if cvss and float(cvss) > 6 else "Уязвимость компонента"
            if str(item.get("note") or "").strip():  # предположение о версии или неполнота – видны в выгрузке
                category += f" ({str(item['note']).strip()})"
            rows.append({"Severity": severity, "CVSS score": cvss or "-", "Category": category,
                         "Component name": item["component"], "Component version": item["version"],
                         "CVE id": item.get("cve") or "-", "Non-vulnerable versions": item.get("fixed") or "-",
                         "Type": ECOSYSTEM_TYPE.get(str(item.get("ecosystem") or "").lower(), item.get("ecosystem") or "-"),
                         "Found By": "osv", "Codebase": codebase, "Path": "-", "CWE ID": "-", "CWE link": "-",
                         "Artifact": "-", "Proxy": "-"})
    return rows


def write_xlsx(out: Path, application: str, sast: list[dict], sca: list[dict]) -> None:
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Summary Report"
    sheets = {"SAST": sast, "SCA Security": sca, "SCA Compliance": [], "DAST": []}
    severities: dict[str, int] = {}
    for rows in sheets.values():
        for row in rows:
            severities[row["Severity"]] = severities.get(row["Severity"], 0) + 1
    ws["A3"], ws["B3"] = "Application", application
    ws["A5"] = "Severity Summary"
    ws.cell(row=6, column=1, value="Severity type")
    ws.cell(row=7, column=1, value="Count")
    for k, name in enumerate(("Critical", "High", "Medium", "Low"), start=2):
        ws.cell(row=6, column=k, value=name)
        ws.cell(row=7, column=k, value=str(severities.get(name, 0)))
    ws["A8"], ws["B8"] = "Total", str(sum(severities.values()))
    ws["A10"] = "Practices Summary"
    ws.cell(row=11, column=1, value="Practice")
    ws.cell(row=12, column=1, value="Count")
    for k, (name, rows) in enumerate(sheets.items(), start=2):
        ws.cell(row=11, column=k, value=name)
        ws.cell(row=12, column=k, value=str(len(rows)))
    ws["A13"], ws["B13"] = "Total", str(sum(len(r) for r in sheets.values()))
    ws["A15"], ws["B15"] = "Report created", dt.datetime.now()
    for name, rows in sheets.items():
        sheet = wb.create_sheet(name)
        sheet.append(HEADERS[name])
        for row in rows:
            sheet.append([str(row.get(h, "-") or "-") for h in HEADERS[name]])
        if not rows:
            sheet.sheet_state = "hidden"
    out.parent.mkdir(parents=True, exist_ok=True)
    wb.save(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="Выгрузка в формате Hub из отчётов Bandit и Semgrep")
    ap.add_argument("--app", required=True, help="название системы в выгрузке")
    ap.add_argument("--codebase", required=True, help="имя кодовой базы = имя папки клона")
    ap.add_argument("--language", default="Python")
    ap.add_argument("--bandit", type=Path)
    ap.add_argument("--semgrep", type=Path)
    ap.add_argument("--source-root", type=Path,
                    help="папка клона: пути находок сверяются с файлами клона; строка кода находки Semgrep – из файла, "
                         "если в отчёте её нет («requires login»)")
    ap.add_argument("--sca", type=Path, help="CSV: ecosystem,component,version,cve,cvss,fixed")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--start-id", type=int, default=900001, help="первый номер находки")
    ap.add_argument("--exclude", default=".github,terraform,infrastructure",
                    help="папки клона (через запятую), находки в которых не берутся: сборка, инфраструктура")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):  # консоль Windows с cp1252: русский текст не роняет сценарий
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sast: list[dict] = []
    if args.bandit:
        sast += bandit_rows(json.loads(args.bandit.read_text(encoding="utf-8")), args.codebase, args.language,
                            args.source_root)
    if args.semgrep:
        sast += semgrep_rows(json.loads(args.semgrep.read_text(encoding="utf-8")), args.codebase, args.language,
                             args.source_root)
    excluded = tuple(x.strip().strip("/") + "/" for x in str(args.exclude or "").split(",") if x.strip())
    sast = [row for row in sast if not row["File"].startswith(excluded)]
    missing = [f"{row['File']}:{row['Line number']}" for row in sast
               if row["Found By"] == "semgrep" and row["Source code"] == "-"]
    if missing:
        print(f"Внимание: у {len(missing)} находок Semgrep строки кода нет ни в отчёте, ни в клоне "
              f"(--source-root): {', '.join(missing[:5])}")
    # одна находка на (файл, строка): Bandit и Semgrep часто срабатывают на одной строке разными правилами – в
    # демонстрационной выгрузке это одна находка (остаётся первая по порядку: Bandit, затем Semgrep)
    seen: set[tuple[str, str]] = set()
    unique = []
    for row in sast:
        key = (row["File"], row["Line number"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    order = {"High": 0, "Medium": 1, "Low": 2}
    unique.sort(key=lambda r: (order.get(r["Severity"], 9), r["File"], int(r["Line number"] or 0)))
    number = args.start_id
    for row in unique:
        row.update({"Issue id": str(number), "Application": args.app, "Status": "To verify",
                    "Type": "source", "Codebase": args.codebase, "Artifact": "-"})
        number += 1
    sca = sca_rows(args.sca, args.codebase) if args.sca else []
    for row in sca:
        row.update({"Issue id": str(number), "Application": args.app, "Status": "To verify"})
        number += 1
    write_xlsx(args.out, args.app, unique, sca)
    print(f"{args.out}: SAST {len(unique)}, SCA {len(sca)}")


if __name__ == "__main__":
    main()

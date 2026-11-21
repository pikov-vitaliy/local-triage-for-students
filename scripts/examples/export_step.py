"""Входы SAST без кода и выгрузка формата Hub для каталога примеров (план, разделы 4.2–4.3).

Публичный режим: колонка Source code пустая («-»); Category – идентификатор правила и постоянное описание (своё
учебное правило – его сообщение; Bandit – test_id и test_name без issue_text; gosec – rule_id и постоянный текст
правила из таблицы ниже, а не details); кодовая база – у каждой строки и в ключе устранения дублей. Книга пишется
детерминированно: дата сборки – в «Report created» и в docProps/core.xml, отметки времени записей ZIP постоянные."""

from __future__ import annotations

import io
import re
import zipfile
from collections import defaultdict
from pathlib import Path

SAST_LIMIT = 80
SCA_LIMIT = 60
LICENSE_LIMIT = 30
# вендорские и собранные файлы – не код примера: срабатывания в них студенту ничего не дают
VENDORED = re.compile(r"(^|/)(node_modules|vendor|vendors|libs?|third[-_]?party|bower_components|dist|build|"
                      r"plugins|static/js/libs|assets/js|wwwroot/lib)/|\.min\.(js|css)$|jquery|bootstrap|angular\.js",
                      re.IGNORECASE)
TEST_PATH = re.compile(r"(^|/)(tests?|spec|__tests__|e2e|cypress)/|_test\.go$|\.spec\.(js|ts)$|test_[^/]*\.py$",
                       re.IGNORECASE)
GOSEC_TEXT = {
    "G101": "Возможные учётные данные в коде", "G104": "Ошибка не проверяется", "G107": "HTTP-запрос по адресу из переменной",
    "G108": "Профилировщик открыт на /debug/pprof", "G110": "Распаковка без ограничения объёма",
    "G112": "Сервер без ReadHeaderTimeout", "G114": "http.ListenAndServe без таймаутов", "G201": "SQL-запрос из fmt.Sprintf",
    "G202": "SQL-запрос склейкой строк", "G203": "Шаблон HTML без экранирования", "G204": "Запуск процесса с переменными аргументами",
    "G301": "Права папки шире нужного", "G302": "Права файла шире нужного", "G304": "Путь к файлу из переменной",
    "G306": "Права записываемого файла шире нужного", "G401": "Устаревшая хеш-функция", "G402": "Небезопасные настройки TLS",
    "G404": "Слабый генератор случайных чисел", "G501": "Импорт crypto/md5", "G505": "Импорт crypto/sha1",
    "G601": "Адрес переменной цикла", "G115": "Переполнение при преобразовании целых"}
GOSEC_CWE = {"G101": "798", "G104": "703", "G107": "88", "G108": "200", "G110": "409", "G112": "400", "G114": "676",
             "G201": "89", "G202": "89", "G203": "79", "G204": "78", "G301": "276", "G302": "276", "G304": "22",
             "G306": "276", "G401": "328", "G402": "295", "G404": "338", "G501": "327", "G505": "327", "G601": "118",
             "G115": "190"}
SEVERITY = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}


def _rel(path) -> str:
    """Путь от корня дерева: отчёты анализаторов в контейнере начинаются с /src/."""
    p = str(path or "").replace("\\", "/")
    for prefix in ("/src/", "./"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p


def _codebase_of(file: str, codebases: list[dict]) -> tuple[str, str]:
    """(кодовая база, путь внутри неё) по самой длинной подходящей подпапке; база без подпапки – запасная."""
    best: tuple[int, str, str] | None = None
    for cb in codebases:
        prefix = cb["path"].strip("/")
        if not prefix:
            cand = (0, cb["name"], file)
        elif file.startswith(prefix + "/"):
            cand = (len(prefix), cb["name"], file[len(prefix) + 1:])
        else:
            continue
        if best is None or cand[0] > best[0]:
            best = cand
    return (best[1], best[2]) if best else ("", "")


def sast_entries(reports: Path, codebases: list[dict], rules_meta: dict) -> tuple[list[dict], dict]:
    """Записи SAST из сырых отчётов: (записи, сведения об отборе)."""
    import json

    raw: list[dict] = []
    semgrep = reports / "semgrep.json"
    if semgrep.is_file():
        for r in json.loads(semgrep.read_text(encoding="utf-8")).get("results") or []:
            rule = str(r.get("check_id") or "")
            rule = rule[rule.index("lt."):] if "lt." in rule else rule
            meta = rules_meta.get(rule) or {}
            raw.append({"tool": "semgrep", "rule": rule, "file": _rel(r.get("path")),
                        "line": int((r.get("start") or {}).get("line") or 0),
                        "cwe": [re.sub(r"\D", "", c) for c in meta.get("cwe") or []],
                        "severity": SEVERITY.get(str((r.get("extra") or {}).get("severity")).upper(), "Low"),
                        "category": f"{rule}: {meta.get('message', '')}"})
    bandit = reports / "bandit.json"
    if bandit.is_file():
        for r in json.loads(bandit.read_text(encoding="utf-8") or "{}").get("results") or []:
            raw.append({"tool": "bandit", "rule": str(r.get("test_id")), "file": _rel(r.get("filename")),
                        "line": int(r.get("line_number") or 0),
                        "cwe": [str((r.get("issue_cwe") or {}).get("id") or "")] if r.get("issue_cwe") else [],
                        "severity": SEVERITY.get(str(r.get("issue_severity")).upper(), "Low"),
                        "category": f"{r.get('test_id')} {r.get('test_name')}"})
    for g in sorted(reports.glob("gosec-*.json")):
        cb_name = g.stem[len("gosec-"):]
        cb = next((c for c in codebases if c["name"] == cb_name), None)
        prefix = (cb or {}).get("path", "").strip("/")
        for r in json.loads(g.read_text(encoding="utf-8") or "{}").get("Issues") or []:
            rule = str(r.get("rule_id"))
            file = _rel(r.get("file"))
            raw.append({"tool": "gosec", "rule": rule, "file": f"{prefix}/{file}" if prefix else file,
                        "line": int(str(r.get("line") or "0").split("-")[0] or 0),
                        "cwe": [GOSEC_CWE.get(rule, str((r.get("cwe") or {}).get("id") or ""))],
                        "severity": SEVERITY.get(str(r.get("severity")).upper(), "Low"),
                        "category": f"{rule} {GOSEC_TEXT.get(rule, 'Правило gosec')}"})
    dropped = {"вендорские и собранные файлы": 0, "тесты": 0, "повтор той же строки": 0, "сверх предела": 0}
    by_rule: dict[tuple[str, str], list[dict]] = defaultdict(list)
    seen: set[tuple[str, str, int]] = set()
    for e in sorted(raw, key=lambda e: (e["file"], e["line"], e["tool"] != "semgrep", e["rule"])):
        if VENDORED.search(e["file"]):
            dropped["вендорские и собранные файлы"] += 1
            continue
        if TEST_PATH.search(e["file"]):
            dropped["тесты"] += 1
            continue
        cb, inner = _codebase_of(e["file"], codebases)
        if not cb:
            continue
        key = (cb, inner, e["line"])
        if key in seen:
            dropped["повтор той же строки"] += 1
            continue
        seen.add(key)
        e = {**e, "codebase": cb, "file": inner, "cwe": [c for c in e["cwe"] if c]}
        by_rule[(e["tool"], e["rule"])].append(e)
    # отбор по кругу между правилами: разнообразие классов важнее числа срабатываний одного правила
    picked: list[dict] = []
    queues = [by_rule[k] for k in sorted(by_rule)]
    i = 0
    while len(picked) < SAST_LIMIT and any(queues):
        q = queues[i % len(queues)]
        if q:
            picked.append(q.pop(0))
        i += 1
    dropped["сверх предела"] = sum(len(q) for q in queues)
    picked.sort(key=lambda e: ({"High": 0, "Medium": 1, "Low": 2}[e["severity"]], e["codebase"], e["file"], e["line"]))
    return picked, dropped


def sca_selected(entries: list[dict]) -> tuple[list[dict], dict]:
    dropped = {"псевдопакет Go (stdlib, toolchain)": 0, "сверх предела": 0}
    rows = []
    for e in entries:
        if e["ecosystem"].lower() == "go" and e["name"] in ("stdlib", "toolchain"):
            dropped["псевдопакет Go (stdlib, toolchain)"] += 1
            continue
        rows.append(e)
    def score(e):
        try:
            return -float(e.get("cvss") or 0)
        except ValueError:
            return 0.0
    rows.sort(key=lambda e: ("dev" in (e.get("dependency_groups") or []), score(e), e["codebase"], e["name"],
                             e["version"], e["osv_id"]))
    dropped["сверх предела"] = max(0, len(rows) - SCA_LIMIT)
    return rows[:SCA_LIMIT], dropped


def write_book(out: Path, application: str, sast: list[dict], sca: list[dict], compliance: list[dict],
               headers: dict, build_date: str) -> None:
    """Книга формата Hub, байт в байт одинаковая при одинаковых входах."""
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    assert ws is not None
    ws.title = "Summary Report"
    sheets = {"SAST": sast, "SCA Security": sca, "SCA Compliance": compliance, "DAST": []}
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
    ws["A15"], ws["B15"] = "Report created", f"{build_date} 00:00:00"
    for name, rows in sheets.items():
        sheet = wb.create_sheet(name)
        sheet.append(headers[name])
        for row in rows:
            sheet.append([str(row.get(h, "-") or "-") for h in headers[name]])
        if not rows:
            sheet.sheet_state = "hidden"
    buf = io.BytesIO()
    wb.save(buf)
    stamp = f"{build_date}T00:00:00Z"
    src = zipfile.ZipFile(io.BytesIO(buf.getvalue()))
    res = io.BytesIO()
    with zipfile.ZipFile(res, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename == "docProps/core.xml":
                text = data.decode("utf-8")
                text = re.sub(r"(<dcterms:created[^>]*>)[^<]*(</dcterms:created>)", rf"\g<1>{stamp}\g<2>", text)
                text = re.sub(r"(<dcterms:modified[^>]*>)[^<]*(</dcterms:modified>)", rf"\g<1>{stamp}\g<2>", text)
                data = text.encode("utf-8")
            fixed = zipfile.ZipInfo(info.filename, date_time=(1980, 1, 1, 0, 0, 0))
            fixed.compress_type = zipfile.ZIP_DEFLATED
            fixed.external_attr = 0o600 << 16
            dst.writestr(fixed, data)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(res.getvalue())

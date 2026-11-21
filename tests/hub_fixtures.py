"""Синтетический отчёт AppSec.Hub для тестов.

Листы и заголовки колонок – как у отчёта Hub, значения выдуманы: система «Demo Library», кодовые базы
billing-core и catalog-api, пакет org.example, номера находок и идентификаторы уязвимостей к настоящим выгрузкам
отношения не имеют. Все значения – строки, пустое значение – «-».
"""

from __future__ import annotations

import datetime as dt
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

APP = "Demo Library"
MITRE = "https://cwe.mitre.org/data/definitions/{}.html"
INVOICE = "src/main/java/org/example/billing/InvoiceDao.java"
RENDERER = "src/main/java/org/example/web/Renderer.java"
SETTINGS = "src/main/java/org/example/config/Settings.java"
SEARCH = "catalog_api/search.py"
SQL_LINE = 'String sql = "SELECT * FROM invoice WHERE owner = \'" + owner + "\'";'
XSS_LINE = 'out.print(request.getParameter("name"));'
SECRET_LINE = 'private static final String DB_PASSWORD = "Demo-Secret-Value-1";'
PY_LINE = 'cursor.execute(f"SELECT * FROM item WHERE title = \'{title}\'")'

SAST_BASE = {"Application": APP, "Status": "To verify", "Type": "maven", "Found By": "demo-sast",
             "Codebase": "billing-core", "Artifact": "-", "Language": "Java"}
SAST_ROWS = [
    dict(SAST_BASE, **{"Issue id": "510001", "Severity": "High", "Category": "Внедрение SQL-кода", "File": INVOICE,
                       "Line number": "58", "Source code": f"{SQL_LINE} : 58", "CWE ID": "89",
                       "CWE link": MITRE.format(89)}),
    dict(SAST_BASE, **{"Issue id": "510002", "Severity": "Medium", "Category": "Межсайтовый скриптинг",
                       "File": RENDERER, "Line number": "21", "Source code": f"{XSS_LINE} : 22",  # хвост не совпал
                       "CWE ID": "79", "CWE link": MITRE.format(79), "Artifact": "billing-core-1.0.jar"}),
    dict(SAST_BASE, **{"Issue id": "510003", "Severity": "Low", "Category": "Пароль в исходном коде",
                       "File": SETTINGS, "Line number": "14", "Source code": f"{SECRET_LINE} : 14", "CWE ID": "798",
                       "CWE link": MITRE.format(798)}),
    dict(SAST_BASE, **{"Issue id": "510004", "Severity": "Critical", "Category": "Внедрение SQL-кода",
                       "File": SEARCH, "Line number": "9", "Source code": f"{PY_LINE} : 9", "CWE ID": "89",
                       "CWE link": MITRE.format(89), "Codebase": "catalog-api", "Type": "pip", "Language": "Python"}),
]

SCA_BASE = {"Application": APP, "Severity": "Critical", "Category": "Политика: CVSS выше 6", "Status": "To verify",
            "Type": "maven", "Found By": "demo-sca", "Path": "-", "Codebase": "billing-core", "Artifact": "-",
            "Proxy": "-"}
SCA_ROWS = [
    dict(SCA_BASE, **{"Issue id": "73001", "CVSS score": "9.8", "Component name": "example-parser",
                      "Component version": "1.4.2", "CVE id": "AST-2026-000101", "Non-vulnerable versions": "1.4.9",
                      "CWE ID": "1333, 400", "CWE link": f"{MITRE.format(1333)}, \n{MITRE.format(400)}"}),
    dict(SCA_BASE, **{"Issue id": "73002", "CVSS score": "8.2", "Component name": "example-parser",
                      "Component version": "1.4.2", "CVE id": "CVE-2099-10001", "Non-vulnerable versions": "1.4.9",
                      "CWE ID": "611", "CWE link": MITRE.format(611)}),
    dict(SCA_BASE, **{"Issue id": "73003", "CVSS score": "8.9", "Component name": "demo-xml",
                      "Component version": "2.0.0", "CVE id": "AST-2026-000103", "Non-vulnerable versions": "2.0.4",
                      "CWE ID": "776", "CWE link": MITRE.format(776), "Codebase": "catalog-api",
                      "Path": "catalog-api > demo-xml"}),
]
LICENSE_ROW = {"Issue id": "74001", "Application": APP, "Severity": "High", "Category": "Запрещённая лицензия",
               "Component name": "example-parser", "Component version": "1.4.2", "Licenses": "GPL-3.0",
               "Status": "To verify", "Type": "maven", "Found By": "demo-sca", "Codebase": "billing-core"}
DAST_ROW = {"Issue id": "75001", "Application": APP, "Severity": "Medium",
            "Location": "https://demo.example.invalid/login", "Source": "crawler", "Status": "To verify",
            "Found By": "demo-dast", "CWE ID": "352", "CWE link": MITRE.format(352), "Instance": "demo-1"}

# Сводка по умолчанию нарочно не сходится с листами: так проверяется сверка.
SUMMARY_PRACTICES = {"SAST": "120", "SCA Security": "80", "SCA Compliance": "0", "DAST": "0"}
SUMMARY_SEVERITIES = {"Critical": "80", "High": "10", "Medium": "20", "Low": "90"}
REPORT_CREATED = dt.datetime(2026, 10, 1, 9, 5, 0, 54000)


def make_hub_xlsx(path: Path, sast=SAST_ROWS, sca=SCA_ROWS, compliance=(), dast=(), *, summary=True,
                  practices=None, severities=None, trailing=True, extra_sheets=(), application=APP) -> Path:
    """Отчёт Hub: сводка (числа строками, «Report created» – датой), листы практик; пустые листы скрыты, на листах
    с находками – пустая строка 1 048 576, как после правки файла в редакторе таблиц.

    practices и severities – счётчики сводки ({практика: "число"}); "auto" – посчитать по строкам листов."""
    import openpyxl

    sheets = {"SAST": list(sast), "SCA Security": list(sca), "SCA Compliance": list(compliance), "DAST": list(dast)}
    wb = openpyxl.Workbook()
    ws = wb.active
    if summary:
        ws.title = "Summary Report"
        if practices == "auto":
            practices = {name: str(len(rows)) for name, rows in sheets.items()}
        if severities == "auto":
            severities = {}
            for rows in sheets.values():
                for row in rows:
                    severities[row["Severity"]] = str(int(severities.get(row["Severity"], "0")) + 1)
        practices = practices or SUMMARY_PRACTICES
        severities = severities or SUMMARY_SEVERITIES
        ws["A3"], ws["B3"] = "Application", application
        ws["A5"] = "Severity Summary"
        ws.cell(row=6, column=1, value="Severity type")
        ws.cell(row=7, column=1, value="Count")
        for k, (name, count) in enumerate(severities.items(), start=2):
            ws.cell(row=6, column=k, value=name)
            ws.cell(row=7, column=k, value=count)
        total_sev = sum(int(v) for v in severities.values() if v.isdigit())
        ws["A8"], ws["B8"] = "Total", str(total_sev)
        ws["A10"] = "Practices Summary"
        ws.cell(row=11, column=1, value="Practice")
        ws.cell(row=12, column=1, value="Count")
        for k, (name, count) in enumerate(practices.items(), start=2):
            ws.cell(row=11, column=k, value=name)
            ws.cell(row=12, column=k, value=count)
        ws["A13"], ws["B13"] = "Total", str(sum(int(v) for v in practices.values() if v.isdigit()))
        ws["A15"], ws["B15"] = "Report created", REPORT_CREATED
        first = None
    else:
        first = ws  # первый лист книги займёт лист практики
    for name, rows in sheets.items():
        if not summary and not rows and name != "SAST":
            continue
        sheet = first if first is not None else wb.create_sheet(name)
        sheet.title = name
        first = None
        sheet.append(HEADERS[name])
        for row in rows:
            sheet.append([row.get(h, "-") for h in HEADERS[name]])
        if not rows:
            sheet.sheet_state = "hidden"
        elif trailing:
            sheet.row_dimensions[1048576].height = 12.8
    for title, rows in extra_sheets:
        sheet = wb.create_sheet(title)
        for row in rows:
            sheet.append(row)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)
    return path

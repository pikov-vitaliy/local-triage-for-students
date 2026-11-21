"""Синтетическая выгрузка AppSec.Hub для выдуманной системы «Demo Library».

Строит книгу в формате отчёта Hub: лист «Summary Report» и листы SAST, SCA Security, SCA Compliance, DAST.
Номера строк находок SAST не записаны в сценарии, а ищутся в файлах examples/demo/repos по фрагментам кода,
поэтому правка демо-кода не ломает выгрузку. Все значения выдуманы.

Вторая выгрузка (--variant v2, examples/demo/demo-hub-report-v2.xlsx) – для проверки повторного импорта: в ней
нет находки 100115, есть новая находка 100116, а у находки 100105 другая строка кода в выгрузке. Даты в книге
постоянные, поэтому повторная сборка даёт тот же файл.

Запуск из корня репозитория:
    .venv/Scripts/python scripts/make_demo_xlsx.py [--variant v2] [--out путь.xlsx]
"""

from __future__ import annotations

import argparse
import datetime as dt
import io
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT / "examples" / "demo"
REPOS_DIR = DEMO_DIR / "repos"
DEFAULT_OUT = DEMO_DIR / "demo-hub-report.xlsx"
VARIANT_OUT = {"v1": DEFAULT_OUT, "v2": DEMO_DIR / "demo-hub-report-v2.xlsx"}

APPLICATION = "Demo Library"
MITRE = "https://cwe.mitre.org/data/definitions/{}.html"
CREATED = dt.datetime(2026, 10, 1, 9, 30, 0)

# Листы и заголовки колонок – как в отчёте AppSec.Hub.
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

# Папки репозиториев для кодовых баз выгрузки. У notify-gateway папки нет: по её находке контекст – только строка
# кода из выгрузки. «Catalog_API» в выгрузке и папка catalog-api называются по-разному нарочно.
FOLDERS = {"billing-core": "billing-core", "Catalog_API": "catalog-api", "notify-gateway": None}

_BILLING = "src/main/java/org/example/billing"
SQL, PATH, XSS = "Внедрение SQL-кода", "Обход пути", "Межсайтовый скриптинг"
RANDOM, HASH, PASSWORD = "Слабый генератор случайных чисел", "Слабый алгоритм хеширования", "Пароль в исходном коде"
COMMAND, DESERIALIZE, SSRF = "Внедрение команд ОС", "Небезопасная десериализация", "Подделка серверных запросов"

# Находки SAST. file – путь в репозитории; hub_file – путь в выгрузке, если он другой; anchor и code – где искать
# строку срабатывания: первая строка с code после строки с anchor; export – строка кода в выгрузке, если она не
# совпадает со строкой в репозитории; line – номер строки, если файла в демо нет.
SAST_FINDINGS = [
    dict(id="100101", codebase="billing-core", file=f"{_BILLING}/InvoiceRepository.java", anchor="findByCustomer(",
         code="statement.executeQuery(sql)", severity="Critical", category=SQL, cwe="89"),
    dict(id="100102", codebase="billing-core", file=f"{_BILLING}/InvoiceRepository.java", anchor="findByStatus(",
         code="statement.executeQuery(sql)", severity="High", category=SQL, cwe="89"),
    dict(id="100103", codebase="billing-core", file=f"{_BILLING}/web/InvoiceExportController.java",
         anchor="void downloadInvoice(", code="Files.copy(invoice.toPath()", severity="High", category=PATH, cwe="22"),
    dict(id="100104", codebase="billing-core", file=f"{_BILLING}/web/InvoiceExportController.java",
         anchor="void downloadReport(", code="Files.copy(report,", severity="High", category=PATH, cwe="22"),
    dict(id="100105", codebase="billing-core", file=f"{_BILLING}/web/InvoiceExportController.java",
         anchor="void showGreeting(", code="out.write(", severity="Medium", category=XSS, cwe="79",
         export='out.write("<p>Hello, " + name + "</p>");'),
    dict(id="100106", codebase="billing-core", file=f"{_BILLING}/payment/PaymentTokenService.java",
         anchor="newPaymentToken()", code="random.nextInt(16)", severity="Medium", category=RANDOM, cwe="330"),
    dict(id="100107", codebase="billing-core", file=f"{_BILLING}/payment/PaymentTokenService.java",
         anchor="shuffleBannerOrder(", code="Collections.shuffle(", severity="Low", category=RANDOM, cwe="330"),
    dict(id="100108", codebase="billing-core", file=f"{_BILLING}/payment/PaymentTokenService.java",
         anchor="cardFingerprint(", code='getInstance("MD5")', severity="Medium", category=HASH, cwe="328"),
    dict(id="100109", codebase="billing-core", file=f"{_BILLING}/config/DatabaseSettings.java",
         hub_file=f"billing-core/{_BILLING}/config/DatabaseSettings.java", anchor="class DatabaseSettings",
         code="DB_PASSWORD =", severity="High", category=PASSWORD, cwe="798", status="Confirmed"),
    dict(id="100110", codebase="Catalog_API", file="catalog_api/products.py", anchor="def search_products(",
         code="conn.execute(query)", severity="Critical", category=SQL, cwe="89"),
    dict(id="100111", codebase="Catalog_API", file="catalog_api/products.py", anchor="def get_product(",
         code="conn.execute(", severity="High", category=SQL, cwe="89"),
    dict(id="100112", codebase="Catalog_API", file="catalog_api/tasks.py", anchor="def unpack_supplier_archive(",
         code="subprocess.run(", severity="Critical", category=COMMAND, cwe="78"),
    dict(id="100113", codebase="Catalog_API", file="catalog_api/tasks.py", anchor="def load_import_settings(",
         code="yaml.safe_load(", severity="Medium", category=DESERIALIZE, cwe="502"),
    dict(id="100114", codebase="Catalog_API", file="catalog_api/tasks.py", anchor="def restore_cart(",
         code="pickle.loads(", severity="High", category=DESERIALIZE, cwe="502"),
    dict(id="100115", codebase="notify-gateway", file="src/main/java/org/example/notify/WebhookSender.java",
         line=42, export='URL target = new URL(request.getParameter("callback"));', severity="High", category=SSRF,
         cwe="918"),
]

# Вторая выгрузка: 100115 пропала, 100116 – новая, у 100105 другая строка кода в выгрузке
V2_REMOVED = {"100115"}
V2_CHANGED = {"100105": {"export": 'out.write("<p>Welcome back, " + name + "</p>");'}}
V2_ADDED = [
    dict(id="100116", codebase="Catalog_API", file="catalog_api/views.py", anchor="def search(",
         code='request.args.get("q"', severity="Medium", category=SQL, cwe="89"),
]


def sast_specs(variant: str = "v1") -> list[dict]:
    """Находки SAST выгрузки: v1 – основная, v2 – для проверки повторного импорта."""
    if variant == "v1":
        return list(SAST_FINDINGS)
    specs = [dict(spec, **V2_CHANGED.get(spec["id"], {})) for spec in SAST_FINDINGS if spec["id"] not in V2_REMOVED]
    return specs + V2_ADDED

_SCA_BASE = {"Application": APPLICATION, "Severity": "Critical", "Category": "Политика: CVSS выше 5",
             "Status": "To verify", "Found By": "demo-sca", "Artifact": "-", "Proxy": "-"}
_XML_PARSER = "org.example.thirdparty:example-xml-parser"
SCA_ROWS = [
    dict(_SCA_BASE, **{"Issue id": "200201", "CVSS score": "9.8", "Component name": _XML_PARSER,
                       "Component version": "2.3.1", "CVE id": "AST-2026-000101", "Type": "maven",
                       "Non-vulnerable versions": "2.3.9", "Path": "org.example:billing-core > example-xml-parser",
                       "CWE ID": "611", "CWE link": MITRE.format(611), "Codebase": "billing-core"}),
    dict(_SCA_BASE, **{"Issue id": "200202", "CVSS score": "7.5", "Component name": _XML_PARSER,
                       "Component version": "2.3.1", "CVE id": "CVE-2099-10001", "Type": "maven",
                       "Non-vulnerable versions": "2.3.9", "Path": "org.example:billing-core > example-xml-parser",
                       "CWE ID": "776", "CWE link": MITRE.format(776), "Codebase": "billing-core"}),
    dict(_SCA_BASE, **{"Issue id": "200203", "CVSS score": "8.1", "Component name": "demo-yaml-lib",
                       "Component version": "5.1.0", "CVE id": "GHSA-abcd-1234-efgh", "Type": "pypi",
                       "Non-vulnerable versions": "5.4.1", "Path": "-", "CWE ID": "502",
                       "CWE link": MITRE.format(502), "Codebase": "Catalog_API"}),
    dict(_SCA_BASE, **{"Issue id": "200204", "CVSS score": "5.3", "Component name": "demo-http-client",
                       "Component version": "1.0.2", "CVE id": "AST-2026-000102", "Type": "pypi",
                       "Non-vulnerable versions": "1.0.7", "Path": "-", "CWE ID": "1333, 400",
                       "CWE link": f"{MITRE.format(1333)}, \n{MITRE.format(400)}", "Codebase": "Catalog_API"}),
]
COMPLIANCE_ROWS = [
    {"Issue id": "200301", "Application": APPLICATION, "Severity": "High", "Category": "Запрещённая лицензия",
     "Component name": "example-graph-lib", "Component version": "3.0.0", "Licenses": "GPL-3.0-only",
     "Status": "To verify", "Type": "pypi", "Found By": "demo-sca", "Non-vulnerable versions": "-", "Path": "-",
     "Codebase": "Catalog_API"},
]
DAST_ROWS = [
    {"Issue id": "200401", "Application": APPLICATION, "Severity": "Medium",
     "Location": "https://demo-library.example.invalid/account/login", "Source": "-", "Status": "To verify",
     "Found By": "demo-dast", "CWE ID": "352", "CWE link": MITRE.format(352)},
]


def locate(path: Path, anchor: str, code: str) -> tuple[int, str]:
    """Строка срабатывания: первая строка с фрагментом code после строки с anchor -> (номер с 1, текст строки)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    starts = [i for i, text in enumerate(lines) if anchor in text]
    if len(starts) != 1:
        raise ValueError(f"{path.name}: «{anchor}» встречается {len(starts)} раз, нужен ровно один")
    for i in range(starts[0], len(lines)):
        if code in lines[i]:
            return i + 1, lines[i]
    raise ValueError(f"{path.name}: после «{anchor}» нет строки с «{code}»")


def sast_rows(repos_dir: Path = REPOS_DIR, variant: str = "v1") -> list[dict]:
    """Строки листа SAST: номера строк и строки кода – из файлов демо."""
    rows = []
    for spec in sast_specs(variant):
        folder = FOLDERS[spec["codebase"]]
        if folder is None:
            line, code = spec["line"], spec["export"]
        else:
            line, code = locate(repos_dir / folder / spec["file"], spec["anchor"], spec["code"])
            code = spec.get("export", code)
        java = spec["file"].endswith(".java")
        rows.append({
            "Issue id": spec["id"], "Application": APPLICATION, "Severity": spec["severity"],
            "Category": spec["category"], "File": spec.get("hub_file", spec["file"]), "Line number": str(line),
            "Source code": f"{code.strip()} : {line}", "Status": spec.get("status", "To verify"),
            "Type": "maven" if java else "pip", "Found By": "demo-sast", "CWE ID": spec["cwe"],
            "CWE link": MITRE.format(spec["cwe"]), "Codebase": spec["codebase"], "Artifact": "-",
            "Language": "Java" if java else "Python",
        })
    return rows


def _summary(ws, sheets: dict[str, list[dict]]) -> None:
    """Лист «Summary Report»: приложение, счётчики по критичности и практикам (числа строками), время отчёта."""
    severities = Counter(row["Severity"] for rows in sheets.values() for row in rows)
    order = [s for s in ("Critical", "High", "Medium", "Low", "Info") if severities[s]]
    total = sum(len(rows) for rows in sheets.values())
    ws["A1"] = "AppSec.Hub issue report"
    ws["A3"], ws["B3"] = "Application", APPLICATION
    ws["A5"] = "Severity Summary"
    ws["A6"] = "Severity type"
    ws["A7"] = "Count"
    for k, name in enumerate(order, start=2):
        ws.cell(row=6, column=k, value=name)
        ws.cell(row=7, column=k, value=str(severities[name]))
    ws["A8"], ws["B8"] = "Total", str(total)
    ws["A10"] = "Practices Summary"
    ws["A11"] = "Practice"
    ws["A12"] = "Count"
    for k, name in enumerate(sheets, start=2):
        ws.cell(row=11, column=k, value=name)
        ws.cell(row=12, column=k, value=str(len(sheets[name])))
    ws["A13"], ws["B13"] = "Total", str(total)
    ws["A15"], ws["B15"] = "Report created", CREATED


def _fix_dates(path: Path) -> None:
    """Постоянные даты внутри книги (свойства документа и время файлов архива): повторная сборка даёт тот же
    файл, и в истории репозитория не появляются лишние версии."""
    stamp = CREATED.strftime("%Y-%m-%dT%H:%M:%SZ")
    with zipfile.ZipFile(path) as src:
        items = [(info.filename, src.read(info.filename)) for info in src.infolist()]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        for name, data in items:
            if name == "docProps/core.xml":
                text = data.decode("utf-8")
                for tag in ("dcterms:created", "dcterms:modified"):
                    text = re.sub(rf"(<{tag}[^>]*>)[^<]*(</{tag}>)", rf"\g<1>{stamp}\g<2>", text)
                data = text.encode("utf-8")
            info = zipfile.ZipInfo(name, date_time=CREATED.timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            dst.writestr(info, data)
    path.write_bytes(buf.getvalue())


def build(out_path: Path = DEFAULT_OUT, repos_dir: Path = REPOS_DIR, variant: str = "v1") -> Path:
    """Пишет выгрузку в out_path и возвращает путь. variant: v1 – основная, v2 – для повторного импорта."""
    import openpyxl

    sheets = {"SAST": sast_rows(repos_dir, variant), "SCA Security": SCA_ROWS, "SCA Compliance": COMPLIANCE_ROWS,
              "DAST": DAST_ROWS}
    wb = openpyxl.Workbook()
    summary = wb.active
    summary.title = "Summary Report"
    _summary(summary, sheets)
    for name, rows in sheets.items():
        ws = wb.create_sheet(name)
        ws.append(HEADERS[name])
        for row in rows:
            ws.append([str(row.get(h, "-")) for h in HEADERS[name]])
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    wb.properties.created = CREATED
    wb.save(out_path)
    _fix_dates(out_path)
    return out_path


class _RuHelp(argparse.HelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        super().add_usage(usage, actions, groups, "Использование: " if prefix is None else prefix)


# Сообщения argparse об ошибках параметров -> по-русски (подстановкой по порядку).
_ARGPARSE_RU = (
    ("the following arguments are required:", "не заданы обязательные параметры:"),
    ("unrecognized arguments:", "неизвестные параметры:"),
    ("expected one argument", "нужно значение"),
    ("invalid choice:", "недопустимое значение:"),
    ("ambiguous option:", "неоднозначный параметр:"),
    ("could match", "подходит к"),
    ("argument ", "параметр "),
)


class _RuParser(argparse.ArgumentParser):
    """ArgumentParser с сообщениями об ошибках по-русски."""

    def error(self, message):
        for en, ru in _ARGPARSE_RU:
            message = message.replace(en, ru)
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: ошибка: {message}\n")


def _safe_console() -> None:
    """Вывод в канал с кодировкой без кириллицы (например, cp1252) не должен ронять сценарий: книга к этому
    моменту уже записана. Непредставимые символы заменяются на «?»."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):  # поток подменён или уже закрыт
            pass


def main(argv: list[str] | None = None) -> int:
    _safe_console()
    parser = _RuParser(description="Строит синтетическую выгрузку AppSec.Hub для выдуманной системы Demo Library.",
                       formatter_class=_RuHelp, add_help=False, allow_abbrev=False)
    parser.add_argument("-h", "--help", action="help", help="показать эту справку и выйти")
    parser.add_argument("--variant", choices=("v1", "v2"), default="v1", metavar="ВАРИАНТ",
                        help="v1 – основная выгрузка, v2 – вторая, для проверки повторного импорта")
    parser.add_argument("--out", type=Path, default=None, metavar="ПУТЬ",
                        help="куда записать книгу (по умолчанию examples/demo/demo-hub-report.xlsx, для v2 – "
                             "examples/demo/demo-hub-report-v2.xlsx)")
    parser._optionals.title = "параметры"
    args = parser.parse_args(argv)
    try:
        path = build(args.out or VARIANT_OUT[args.variant], variant=args.variant)
    except (OSError, ValueError) as e:  # папка вместо файла, нет прав, демо-код изменён и строка не находится
        detail = e.strerror if isinstance(e, OSError) and e.strerror else str(e)
        print(f"{parser.prog}: ошибка: не удалось построить выгрузку ({type(e).__name__}: {detail}).", file=sys.stderr)
        return 1
    print(f"Готово: {path} (SAST: {len(sast_specs(args.variant))}, SCA Security: {len(SCA_ROWS)}, "
          f"SCA Compliance: {len(COMPLIANCE_ROWS)}, DAST: {len(DAST_ROWS)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

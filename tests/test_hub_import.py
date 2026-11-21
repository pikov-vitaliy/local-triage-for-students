"""Разбор выгрузки AppSec.Hub: отчёт Hub, таблица, защиты от подложенного файла, группы и срочность."""

from __future__ import annotations

import time
import zipfile

import openpyxl
import pytest

from app import hub_import as hi
from app.hub_import import ImportFailure, group_key, is_urgent, parse_workbook
from app.models import Finding, ImportResult
from hub_fixtures import (APP, DAST_ROW, INVOICE, LICENSE_ROW, MITRE, PY_LINE, SAST_BASE, SAST_ROWS, SQL_LINE,
                          XSS_LINE, make_hub_xlsx)


def by_id(result: ImportResult) -> dict[str, Finding]:
    return {f.hub_id: f for f in result.findings}


# ============================================================================ отчёт Hub

def test_hub_report_findings(hub_xlsx):
    result = parse_workbook(hub_xlsx)
    assert result.format == "hub"
    f = by_id(result)
    assert sorted(f) == ["510001", "510002", "510003", "510004", "73001", "73002", "73003"], \
        "сводка и пустые листы находками не считаются"
    sast = f["510001"]
    assert (sast.kind, sast.tool, sast.build_type, sast.application) == ("SAST", "demo-sast", "maven", APP)
    assert (sast.file, sast.line, sast.rule, sast.severity, sast.cwe) == (INVOICE, 58, "Внедрение SQL-кода", "high",
                                                                          ["CWE-89"])
    assert sast.cwe_links == [MITRE.format(89)]
    assert sast.snippet == SQL_LINE, "хвост « : 58» отделён от кода"
    assert (sast.codebase, sast.language, sast.status) == ("billing-core", "Java", "To verify")
    assert (sast.sheet, sast.row) == ("SAST", 2)
    assert sast.extra == {}, "«-» – пустое значение, в extra не попадает"
    assert sast.policy_severity == "" and sast.cvss is None
    assert f["510002"].extra == {"Artifact": "billing-core-1.0.jar"}, "колонка без поля – в extra"
    assert f["510004"].codebase == "catalog-api" and f["510004"].snippet == PY_LINE


def test_dash_is_empty(tmp_path):
    row = dict(SAST_BASE, **{"Issue id": "600001", "Severity": "-", "Category": "-", "File": "-",
                             "Line number": "-", "Source code": "-", "CWE ID": "-", "CWE link": "-", "Status": "-",
                             "Codebase": chr(0x2014), "Language": chr(0x2013)})
    result = parse_workbook(make_hub_xlsx(tmp_path / "r.xlsx", sast=[row], sca=[]))
    (f,) = result.findings
    assert (f.severity, f.rule, f.file, f.line, f.snippet, f.cwe, f.cwe_links, f.status, f.codebase, f.language) == \
        ("", "", "", None, "", [], [], "", "", "")
    assert f.extra == {}


def test_code_tail_and_line_number(tmp_path):
    rows = [dict(SAST_ROWS[0]),
            dict(SAST_ROWS[1]),  # хвост « : 22», а Line number 21
            dict(SAST_ROWS[0], **{"Issue id": "510010", "Line number": "-", "Source code": "a ? b : 5 : 12"})]
    result = parse_workbook(make_hub_xlsx(tmp_path / "r.xlsx", sast=rows, sca=[]))
    f = by_id(result)
    assert f["510002"].line == 21, "верным считается Line number"
    assert f["510002"].snippet == XSS_LINE
    assert (f["510010"].snippet, f["510010"].line) == ("a ? b : 5", 12), "номер строки – из хвоста, если колонка пуста"
    assert any("хвосте Source code не совпал с Line number у 1" in w and "SAST:3" in w for w in result.warnings)


def test_sca_ids_cwe_lists_and_policy_severity(hub_xlsx):
    f = by_id(parse_workbook(hub_xlsx))
    sca = f["73001"]
    assert (sca.kind, sca.tool, sca.build_type) == ("SCA", "demo-sca", "maven")
    assert (sca.severity, sca.policy_severity, sca.cvss) == ("", "critical", 9.8), \
        "Severity у SCA – уровень политики Hub"
    assert (sca.cve, sca.vuln_ids) == ([], ["AST-2026-000101"]), "AST-… – идентификатор, а не CVE"
    assert sca.cwe == ["CWE-1333", "CWE-400"]
    assert sca.cwe_links == [MITRE.format(1333), MITRE.format(400)], "ссылки через запятую и перевод строки"
    assert (sca.component, sca.version, sca.fixed_version) == ("example-parser", "1.4.2", "1.4.9")
    assert (sca.dep_path, sca.file, sca.line) == ("", "", None), "Path у SCA – путь зависимости, а не файл"
    assert (f["73002"].cve, f["73002"].vuln_ids) == (["CVE-2099-10001"], [])
    assert f["73003"].dep_path == "catalog-api > demo-xml"


def test_empty_sheets_skipped(hub_xlsx):
    result = parse_workbook(hub_xlsx)
    sheets = {s["name"]: s for s in result.sheets}
    assert list(sheets) == ["Summary Report", "SAST", "SCA Security", "SCA Compliance", "DAST"]
    for s in result.sheets:
        assert {"name", "rows", "skipped", "reason"} <= set(s)
    assert sheets["Summary Report"]["skipped"] and "сводка" in sheets["Summary Report"]["reason"]
    assert (sheets["SAST"]["rows"], sheets["SAST"]["skipped"], sheets["SAST"]["findings"]) == (4, False, 4)
    for name in ("SCA Compliance", "DAST"):
        assert sheets[name]["skipped"] and sheets[name]["rows"] == 0
        assert sheets[name]["reason"] == "лист без находок"


def test_all_practices_and_extra_sheet(tmp_path):
    path = make_hub_xlsx(tmp_path / "r.xlsx", compliance=[LICENSE_ROW], dast=[DAST_ROW], practices="auto",
                         severities="auto", extra_sheets=[("Заметки", [["что-то своё"]])])
    result = parse_workbook(path)
    f = by_id(result)
    lic, dast = f["74001"], f["75001"]
    assert (lic.kind, lic.licenses, lic.severity, lic.policy_severity) == ("SCA-license", "GPL-3.0", "", "high")
    assert (dast.kind, dast.location, dast.severity, dast.cwe) == ("DAST", "https://demo.example.invalid/login",
                                                                   "medium", ["CWE-352"])
    assert dast.extra == {"Source": "crawler", "Instance": "demo-1"}, "Source у DAST – не инструмент"
    assert dast.tool == "demo-dast"
    assert not any("не сходится" in w for w in result.warnings)
    assert any("«Заметки»" in w for w in result.warnings)
    assert {s["name"]: s["skipped"] for s in result.sheets}["Заметки"] is True


def test_summary_check(hub_xlsx):
    result = parse_workbook(hub_xlsx)
    summary = result.summary
    assert summary["application"] == APP
    assert summary["report_created"] == "2026-10-01 09:05:00"
    assert summary["by_practice"] == {"SAST": 120, "SCA Security": 80, "SCA Compliance": 0, "DAST": 0}
    assert summary["by_severity"] == {"critical": 80, "high": 10, "medium": 20, "low": 90}
    assert summary["total"] == 200
    assert any(w.startswith("Сводка «Summary Report» не сходится с листами: SAST – в сводке 120, на листе 4; "
                            "SCA Security – в сводке 80, на листе 3") for w in result.warnings)
    check = {c["practice"]: c for c in summary["check"]}
    assert (check["SAST"]["expected"], check["SAST"]["actual"], check["SAST"]["ok"]) == (120, 4, False)
    assert check["DAST"]["ok"] is True
    sheets = {s["name"]: s for s in result.sheets}
    assert (sheets["SAST"]["expected"], sheets["SAST"]["match"]) == (120, False)


def test_summary_totals_and_severities(tmp_path):
    rows = [SAST_ROWS[0]]
    path = make_hub_xlsx(tmp_path / "r.xlsx", sast=rows, sca=[], practices={"SAST": "1"},
                         severities={"Critical": "888"})
    wb = openpyxl.load_workbook(path)
    wb["Summary Report"]["B13"] = "999"
    wb.save(path)
    result = parse_workbook(path)
    assert result.summary["check"][0]["ok"] is True, "счётчик практики сходится"
    assert any("Итог сводки «Summary Report» не сходится с числом находок на листах (1): по практикам – 999; "
               "по критичности – 888" in w for w in result.warnings)
    assert any("по критичности не сходится" in w and "critical – в сводке 888, на листах 0" in w
               for w in result.warnings)


def test_unrecognized_summary_counter(tmp_path):
    path = make_hub_xlsx(tmp_path / "r.xlsx", practices={"SAST": "н/д", "SCA Security": "3"}, severities="auto")
    result = parse_workbook(path)
    check = {c["practice"]: c for c in result.summary["check"]}
    assert check["SAST"]["ok"] is None and check["SCA Security"]["ok"] is True
    assert any("не распознаны счётчики: SAST" in w for w in result.warnings)


def test_summary_matches(tmp_path):
    rows = [SAST_ROWS[0], SAST_ROWS[2], SAST_ROWS[3]]
    result = parse_workbook(make_hub_xlsx(tmp_path / "r.xlsx", sast=rows, practices="auto", severities="auto"))
    assert all(c["ok"] for c in result.summary["check"])
    assert result.warnings == []
    assert result.summary["total"] == len(result.findings) == 6


def test_trailing_row_1048576_is_not_walked(hub_xlsx):
    with zipfile.ZipFile(hub_xlsx) as z:
        sheets = [z.read(n).decode("utf-8") for n in z.namelist() if n.startswith("xl/worksheets/sheet")]
    assert any('r="1048576"' in xml for xml in sheets), "в фикстуре есть пустая строка 1 048 576"
    wb = openpyxl.load_workbook(hub_xlsx, read_only=True, data_only=True)
    try:
        rows = [num for num, _ in hi._physical_rows(wb["SAST"])]
    finally:
        wb.close()
    assert rows == [1, 2, 3, 4, 5, 1048576], "пропуск до строки 1 048 576 не перебирается"
    started = time.monotonic()
    result = parse_workbook(hub_xlsx)
    assert time.monotonic() - started < 5
    assert [f.row for f in result.findings if f.kind == "SAST"] == [2, 3, 4, 5]
    assert len(result.findings) == 7


def test_far_column_is_not_expanded(tmp_path):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    wb = openpyxl.load_workbook(path)
    wb["SAST"].cell(row=2, column=16384, value="далёкая ячейка")
    wb.save(path)
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        widths = [max((col for col, _ in cells), default=0) for _, cells in hi._physical_rows(wb["SAST"])]
    finally:
        wb.close()
    assert max(widths) <= hi.MAX_COLUMNS, "ячейки правее предела не собираются"
    f = by_id(parse_workbook(path))["510001"]
    assert "далёкая ячейка" not in f.extra.values()


def test_corrupted_sheet_is_import_failure(tmp_path, hub_xlsx):
    broken = tmp_path / "broken.xlsx"
    with zipfile.ZipFile(hub_xlsx) as src, zipfile.ZipFile(broken, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "xl/worksheets/sheet2.xml":
                data = data[: len(data) // 2]  # оборванная разметка листа SAST
            dst.writestr(item, data)
    with pytest.raises(ImportFailure, match="повреждён"):
        parse_workbook(broken)


def test_physical_row_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_SHEET_ROWS", 4)
    with pytest.raises(ImportFailure, match="строк разметки"):
        parse_workbook(make_hub_xlsx(tmp_path / "r.xlsx", sca=[]))


def test_rows_without_id_and_duplicates(tmp_path):
    rows = [SAST_ROWS[0], dict(SAST_ROWS[1], **{"Issue id": "-"}), dict(SAST_ROWS[2], **{"Issue id": "510001"})]
    result = parse_workbook(make_hub_xlsx(tmp_path / "r.xlsx", sast=rows, sca=[]))
    assert [f.hub_id for f in result.findings] == ["510001"]
    assert result.findings[0].row == 2, "при повторе ID остаётся первая строка"
    assert any(w.startswith("Строки без ID находки пропущены (1): SAST:3") for w in result.warnings)
    assert any("ID находки повторяется (1)" in w and "510001 (SAST:2 и SAST:4)" in w for w in result.warnings)
    assert {s["name"]: s["findings"] for s in result.sheets}["SAST"] == 1


def test_hub_sheet_without_id_column(tmp_path):
    path = tmp_path / "r.xlsx"
    make_hub_xlsx(path)
    wb = openpyxl.load_workbook(path)
    wb["SAST"]["A1"] = "Номер"
    wb.save(path)
    with pytest.raises(ImportFailure, match="Issue id"):
        parse_workbook(path)


def test_single_practice_sheet_without_summary(tmp_path):
    result = parse_workbook(make_hub_xlsx(tmp_path / "r.xlsx", sca=[], summary=False))
    assert result.format == "hub"
    assert [f.kind for f in result.findings] == ["SAST"] * 4
    assert any("нет листа «Summary Report»" in w for w in result.warnings)
    assert result.summary["by_practice"] == {} and result.summary["total"] is None


def test_hub_detection_needs_summary_or_two_practices(tmp_path):
    """Лист с именем «DAST», но без колонок Hub, – обычная таблица, а не отчёт Hub."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "DAST"
    ws.append(["ID", "File", "Line", "Severity", "Rule"])
    ws.append(["A-1", "src/app.py", "3", "High", "Внедрение SQL-кода"])
    path = tmp_path / "t.xlsx"
    wb.save(path)
    result = parse_workbook(path)
    assert result.format == "table"
    (f,) = result.findings
    assert (f.hub_id, f.kind, f.file, f.line, f.severity, f.rule) == ("A-1", "SAST", "src/app.py", 3, "high",
                                                                      "Внедрение SQL-кода")


# ============================================================================ таблица

def test_csv_table_cp1251_with_footer(tmp_path):
    text = ("Выгрузка находок;;;;;;\n"
            "ID;Вид;Файл;Строка;Критичность;Правило;Компонент;Версия;CVE\n"
            "S-1;SAST;src\\app\\Main.java;12;Высокий;Внедрение SQL-кода;;;\n"
            "C-1;;;;Средний;;demo-lib;1.0;CVE-2099-0001\n"
            "D-1;DAST;;;Низкий;Открытый редирект;;;\n"
            "Итого:;3;;;;;;;\n")
    path = tmp_path / "findings.csv"
    path.write_bytes(text.encode("cp1251"))
    result = parse_workbook(path)
    assert result.format == "table"
    f = by_id(result)
    assert sorted(f) == ["C-1", "D-1", "S-1"]
    assert (f["S-1"].kind, f["S-1"].file, f["S-1"].line, f["S-1"].severity) == ("SAST", "src/app/Main.java", 12, "high")
    assert (f["C-1"].kind, f["C-1"].component, f["C-1"].cve, f["C-1"].severity) == ("SCA", "demo-lib",
                                                                                    ["CVE-2099-0001"], "medium")
    assert f["D-1"].kind == "DAST"
    assert any("подвалы" in w for w in result.warnings)
    assert result.sheets[0]["findings"] == 3


def test_xlsx_table_with_hub_headers(tmp_path):
    """Таблица с колонками Hub: у SCA колонка Severity – уровень политики, как в отчёте."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Находки"
    ws.append(["Issue id", "Practice", "Severity", "CVSS score", "Component name", "Component version", "CVE id",
               "File", "Line number"])
    ws.append(["9001", "SCA Security", "Critical", "9.1", "demo-lib", "2.0", "AST-2026-000999", "-", "-"])
    ws.append(["9002", "SAST", "Medium", "-", "-", "-", "-", "src/a.py", "5"])
    ws.append(["9003", "SCA Compliance", "High", "-", "demo-lib", "2.0", "-", "-", "-"])
    wb.create_sheet("Пустой")
    path = tmp_path / "t.xlsx"
    wb.save(path)
    f = by_id(parse_workbook(path))
    assert (f["9001"].kind, f["9001"].severity, f["9001"].policy_severity, f["9001"].vuln_ids) == \
        ("SCA", "", "critical", ["AST-2026-000999"])
    assert (f["9002"].kind, f["9002"].severity, f["9002"].line) == ("SAST", "medium", 5)
    assert (f["9003"].kind, f["9003"].policy_severity) == ("SCA-license", "high")


def test_id_only_row_is_kept_with_warning(tmp_path):
    path = tmp_path / "t.csv"
    path.write_text("ID;File;Line;Severity\ndemo-1;;;\nS-2;src/a.py;3;High\nИтого:;2;;\n", encoding="utf-8")
    result = parse_workbook(path)
    assert [f.hub_id for f in result.findings] == ["demo-1", "S-2"], "строка с номером – находка, подпись – нет"
    assert any("заполнен только номер находки (1)" in w for w in result.warnings)
    assert any("подвалы" in w for w in result.warnings)


def test_caption_needs_whole_word_and_id_only_table(tmp_path):
    path = tmp_path / "t.csv"
    path.write_text("ID;File\ntotal-1;\nTotal: 2;\n", encoding="utf-8")
    result = parse_workbook(path)
    assert [f.hub_id for f in result.findings] == ["total-1"], "номер находки, похожий на подпись, – не подвал"
    only_id = tmp_path / "ids.csv"
    only_id.write_text("ID\nA-1\nA-2\n", encoding="utf-8")
    result = parse_workbook(only_id)
    assert [f.hub_id for f in result.findings] == ["A-1", "A-2"]
    assert any("заполнен только номер находки (2)" in w for w in result.warnings)


def test_broken_csv_quote_is_import_failure(tmp_path):
    path = tmp_path / "t.csv"
    path.write_text('ID;Rule\n1;"demo\n2;demo\n', encoding="utf-8")
    with pytest.raises(ImportFailure, match="кавычка"):
        parse_workbook(path)


def test_long_csv_cell_does_not_depend_on_process_state(tmp_path):
    import csv

    path = tmp_path / "t.csv"
    path.write_text("ID;Source code\nX-1;" + "z" * 200_000 + "\n", encoding="utf-8")
    previous = csv.field_size_limit(131072)
    try:
        (f,) = parse_workbook(path).findings
    finally:
        csv.field_size_limit(max(previous, csv.field_size_limit()))
    assert f.hub_id == "X-1" and len(f.snippet) == hi.MAX_SNIPPET_CHARS


def test_wide_rows_warning(tmp_path):
    path = tmp_path / "t.csv"
    path.write_text("ID;File\nS-1;a.py;лишнее\n", encoding="utf-8")
    result = parse_workbook(path)
    assert result.findings[0].extra == {"Колонка 3": "лишнее"}
    assert any("больше ячеек, чем в строке заголовков" in w for w in result.warnings)


def test_unparsed_severity_and_total(tmp_path):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sast=[SAST_ROWS[0]], sca=[], practices={"SAST": "1"},
                         severities={"High": "1", "Critical": "н/д"})
    wb = openpyxl.load_workbook(path)
    wb["Summary Report"]["B8"] = "н/д"
    wb.save(path)
    result = parse_workbook(path)
    assert result.summary["by_severity"] == {"high": 1, "critical": None}
    assert any("не распознаны счётчики: critical, итог по критичности" in w for w in result.warnings)


def test_huge_line_number_is_not_a_crash(tmp_path):
    path = tmp_path / "t.csv"
    path.write_text("ID;File;Line;Source code\nS-1;src/a.py;" + "1" * 5000 + ";x : " + "2" * 5000 + "\n",
                    encoding="utf-8")
    (f,) = parse_workbook(path).findings
    assert f.line is None
    assert hi.parse_line("1" * 5000) is None and hi.split_code_tail("x : " + "2" * 5000)[1] is None
    assert hi.parse_line("0" * 4999 + "1") is None, "ведущие нули тоже считаются цифрами номера"
    assert hi.parse_line("0057") == 57 and hi.parse_line("57,0") == 57


def test_hub_like_table_path_is_dependency_path(tmp_path):
    path = tmp_path / "sca.csv"
    path.write_text("Issue id,Component name,Component version,CVSS score,Path\n"
                    "8001,demo-lib,1.0,7.5,app > demo-lib\n", encoding="utf-8")
    (f,) = parse_workbook(path).findings
    assert (f.kind, f.dep_path, f.file, f.extra) == ("SCA", "app > demo-lib", "", {})


def test_table_without_id_column(tmp_path):
    path = tmp_path / "t.csv"
    path.write_text("Файл;Строка\nsrc/a.py;1\n", encoding="utf-8")
    with pytest.raises(ImportFailure, match="номером находки"):
        parse_workbook(path)


def test_long_values_are_clipped(tmp_path):
    path = tmp_path / "t.csv"
    path.write_text("ID;Source code;Правило;Комментарий\nX-1;" + "a" * 40_000 + ";" + "r" * 5000 + ";"
                    + "c" * 9000 + "\n", encoding="utf-8")
    result = parse_workbook(path)
    (f,) = result.findings
    # строка кода – без пометки: сверка со строкой файла идёт по началу строки
    assert f.snippet == "a" * hi.MAX_SNIPPET_CHARS
    assert len(f.rule) == hi.MAX_FIELD_CHARS and f.rule.endswith(hi.CELL_CUT_MARK)
    assert len(f.extra["Комментарий"]) == hi.MAX_EXTRA_VALUE and f.extra["Комментарий"].endswith(hi.CELL_CUT_MARK)
    assert any("слишком длинные значения обрезаны" in w for w in result.warnings)


def _shared_string_book(path, rows: int, cols: int = 500, value: str = "A" * 32000):
    """Книга-таблица, где все ячейки данных ссылаются на одну общую строку (sharedStrings)."""
    import zipfile

    def col(n: int) -> str:
        name = ""
        while n:
            n, r = divmod(n - 1, 26)
            name = chr(65 + r) + name
        return name

    main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    pkg = "http://schemas.openxmlformats.org/package/2006/relationships"
    office = "application/vnd.openxmlformats-officedocument.spreadsheetml"
    header = ['<c r="A1" t="inlineStr"><is><t>Issue id</t></is></c>'] + [
        f'<c r="{col(c)}1" t="inlineStr"><is><t>H{c}</t></is></c>' for c in range(2, cols + 1)]
    body = ['<row r="1">' + "".join(header) + "</row>"]
    for r in range(2, rows + 2):
        cells = [f'<c r="A{r}" t="inlineStr"><is><t>ID-{r}</t></is></c>'] + [
            f'<c r="{col(c)}{r}" t="s"><v>0</v></c>' for c in range(2, cols + 1)]
        body.append(f'<row r="{r}">' + "".join(cells) + "</row>")
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/'
            'content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.'
            'relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
            f'<Override PartName="/xl/workbook.xml" ContentType="{office}.sheet.main+xml"/>'
            f'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="{office}.worksheet+xml"/>'
            f'<Override PartName="/xl/sharedStrings.xml" ContentType="{office}.sharedStrings+xml"/></Types>'),
        "_rels/.rels": (f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{pkg}"><Relationship Id="rId1" '
                        f'Type="{rel}/officeDocument" Target="xl/workbook.xml"/></Relationships>'),
        "xl/workbook.xml": (f'<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="{main}" xmlns:r="{rel}"><sheets>'
                            '<sheet name="Data" sheetId="1" r:id="rId1"/></sheets></workbook>'),
        "xl/_rels/workbook.xml.rels": (
            f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{pkg}">'
            f'<Relationship Id="rId1" Type="{rel}/worksheet" Target="worksheets/sheet1.xml"/>'
            f'<Relationship Id="rId2" Type="{rel}/sharedStrings" Target="sharedStrings.xml"/></Relationships>'),
        "xl/sharedStrings.xml": (f'<?xml version="1.0" encoding="UTF-8"?><sst xmlns="{main}" count="1" '
                                 f'uniqueCount="1"><si><t>{value}</t></si></sst>'),
        "xl/worksheets/sheet1.xml": (f'<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="{main}"><sheetData>'
                                     + "".join(body) + "</sheetData></worksheet>"),
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in parts.items():
            z.writestr(name, text)
    return path


def test_shared_string_amplification_is_refused(tmp_path):
    """Одна общая строка на 32 000 знаков в 500 ячейках строки: маленький файл не раздувается в сотни мегабайт."""
    path = _shared_string_book(tmp_path / "amplified.xlsx", rows=3)
    assert path.stat().st_size < 100_000
    with pytest.raises(ImportFailure, match="млн знаков текста"):
        parse_workbook(path)


def test_extra_columns_are_limited_in_bytes(tmp_path):
    """Прочие колонки находки ограничены по числу, длине и сумме в байтах UTF-8 (эмодзи – 4 байта на знак);
    нераспознанная критичность проходит тот же предел."""
    emoji = "\U0001F600" * 1000  # 1000 знаков, 4000 байт
    headers = ["ID", "Критичность"] + [f"Поле {k}" for k in range(60)]
    values = ["X-1", "неведомая"] + [emoji] * 60
    path = tmp_path / "wide.csv"
    path.write_text(";".join(headers) + "\n" + ";".join(values) + "\n", encoding="utf-8")
    result = parse_workbook(path)
    (f,) = result.findings
    size = sum(len(k.encode()) + len(v.encode()) for k, v in f.extra.items())
    assert size <= hi.MAX_EXTRA_BYTES and len(f.extra) <= hi.MAX_EXTRA_COLUMNS
    assert f.extra["Критичность"] == "неведомая"  # не потерялась и учтена в пределе
    assert any("прочие колонки сохранены не все" in w for w in result.warnings)
    many = tmp_path / "many.csv"
    many.write_text(";".join(["ID", "Критичность"] + [f"П{k}" for k in range(60)]) + "\n"
                    + ";".join(["X-2", "неведомая"] + ["x"] * 60) + "\n", encoding="utf-8")
    (g,) = parse_workbook(many).findings
    assert len(g.extra) == hi.MAX_EXTRA_COLUMNS


def test_sparse_rows_do_not_expand_to_all_columns(tmp_path):
    """Строка с одним ID при 500 колонках заголовка – словарь из одного значения, а не из 500 пустых."""
    path = tmp_path / "ids.csv"
    path.write_text(";".join(["ID"] + [f"H{k}" for k in range(499)]) + "\n" + "\n".join(f"X-{k}" for k in range(50))
                    + "\n", encoding="utf-8")
    headers, rows, _ = hi._grid_to_rows(hi._csv_grid(path.read_bytes(), hi._Limits(path.stat().st_size)), "Таблица")
    assert len(headers) == 500 and all(len(row) == 2 for row in rows)  # ID и номер строки


def test_too_many_grid_cells_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_GRID_CELLS", 1000)
    path = tmp_path / "far.csv"
    path.write_text("ID;A\n" + "\n".join(f"X-{k};" + ";" * 300 + "z" for k in range(10)) + "\n", encoding="utf-8")
    with pytest.raises(ImportFailure, match="млн ячеек"):
        parse_workbook(path)


# ============================================================================ разметка листа: пределы до разбора

SHEET_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def _raw_book(path, sheet_data: str, prolog: str = ""):
    """Книга-таблица из одного листа «Data» с заданным содержимым sheetData (разметка пишется как есть)."""
    rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    pkg = "http://schemas.openxmlformats.org/package/2006/relationships"
    office = "application/vnd.openxmlformats-officedocument.spreadsheetml"
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/'
            'content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.'
            'relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
            f'<Override PartName="/xl/workbook.xml" ContentType="{office}.sheet.main+xml"/>'
            f'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="{office}.worksheet+xml"/></Types>'),
        "_rels/.rels": (f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{pkg}"><Relationship Id="rId1" '
                        f'Type="{rel}/officeDocument" Target="xl/workbook.xml"/></Relationships>'),
        "xl/workbook.xml": (f'<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="{SHEET_MAIN}" xmlns:r="{rel}">'
                            '<sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets></workbook>'),
        "xl/_rels/workbook.xml.rels": (
            f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{pkg}">'
            f'<Relationship Id="rId1" Type="{rel}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'),
        "xl/worksheets/sheet1.xml": (f'<?xml version="1.0" encoding="UTF-8"?>{prolog}<worksheet xmlns="{SHEET_MAIN}">'
                                     f"<sheetData>{sheet_data}</sheetData></worksheet>"),
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in parts.items():
            z.writestr(name, text)
    return path


def _inline(ref: str, text: str) -> str:
    return f'<c r="{ref}" t="inlineStr"><is><t>{text}</t></is></c>'


HEADER_ROW = '<row r="1">' + _inline("A1", "ID") + _inline("B1", "File") + "</row>"


@pytest.fixture
def parsed_rows(monkeypatch):
    """Сколько ячеек было в строках, которые разобрал openpyxl (WorkSheetParser.parse_row)."""
    from openpyxl.worksheet._reader import WorkSheetParser

    sizes = []
    real = WorkSheetParser.parse_row

    def spy(self, row):
        sizes.append(len(row))
        return real(self, row)

    monkeypatch.setattr(WorkSheetParser, "parse_row", spy)
    return sizes


def test_huge_row_is_refused_before_openpyxl_builds_it(tmp_path, parsed_rows):
    """Строка из 200 000 пустых ячеек (сжимается в килобайты): отказ при просмотре разметки, до того как openpyxl
    соберёт строку целиком, и быстро."""
    huge = '<row r="2">' + _inline("A2", "X-1") + "<c/>" * 200_000 + "</row>"
    path = _raw_book(tmp_path / "wide.xlsx", HEADER_ROW + huge)
    assert path.stat().st_size < 100_000
    started = time.monotonic()
    with pytest.raises(ImportFailure, match=f"В строке 2 листа «Data» больше {hi.MAX_ROW_CELLS} ячеек"):
        parse_workbook(path)
    assert time.monotonic() - started < 3
    assert parsed_rows == [], "openpyxl ни одной строки не разбирал"


def test_row_with_huge_rich_text_is_refused(tmp_path, parsed_rows):
    runs = "<r><t>x</t></r>" * (hi.MAX_ROW_ELEMENTS // 2 + 10)
    rich = f'<row r="2"><c r="A2" t="inlineStr"><is>{runs}</is></c></row>'
    with pytest.raises(ImportFailure, match="слишком сложная"):
        parse_workbook(_raw_book(tmp_path / "rich.xlsx", HEADER_ROW + rich))
    assert parsed_rows == []


def test_elements_outside_rows_are_limited(tmp_path, monkeypatch, parsed_rows):
    monkeypatch.setattr(hi, "MAX_OUTSIDE_ELEMENTS", 100)
    junk = "<x/>" * 200
    with pytest.raises(ImportFailure, match="вне строк таблицы"):
        parse_workbook(_raw_book(tmp_path / "junk.xlsx", junk + HEADER_ROW))
    assert parsed_rows == []


def test_book_cell_limit_counts_every_cell(tmp_path, monkeypatch):
    """Ячейки считаются по всей книге, вместе с пустыми и дальними колонками, которые в находки не попадают."""
    monkeypatch.setattr(hi, "MAX_BOOK_CELLS", 40)
    rows = "".join(f'<row r="{r}">' + _inline(f"A{r}", f"X-{r}") + "<c/>" * 10 + "</row>" for r in range(2, 6))
    with pytest.raises(ImportFailure, match="ячеек"):
        parse_workbook(_raw_book(tmp_path / "cells.xlsx", HEADER_ROW + rows))
    monkeypatch.setattr(hi, "MAX_BOOK_CELLS", 100)
    assert [f.hub_id for f in parse_workbook(_raw_book(tmp_path / "ok.xlsx", HEADER_ROW + rows)).findings] == \
        ["X-2", "X-3", "X-4", "X-5"]


@pytest.mark.parametrize("sheet_data, prolog", [
    (HEADER_ROW + '<row r="2"><row r="3">' + _inline("A3", "X-1") + "</row></row>", ""),  # строка внутри строки
    (HEADER_ROW, '<!DOCTYPE worksheet [<!ENTITY big "x">]>'),  # объявления DTD и сущностей
    (HEADER_ROW + '<row r="2"><c r="ZZZZ2"/></row>', ""),  # неверная ссылка на ячейку
])
def test_odd_sheet_markup_is_damaged(tmp_path, sheet_data, prolog):
    with pytest.raises(ImportFailure, match="повреждён"):
        parse_workbook(_raw_book(tmp_path / "odd.xlsx", sheet_data, prolog))


def test_csv_record_with_too_many_delimiters_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_CSV_RECORD_DELIMITERS", 100)
    path = tmp_path / "wide.csv"
    path.write_text("ID;File\nX-1;" + ";" * 500 + "\n", encoding="utf-8")
    with pytest.raises(ImportFailure, match="больше 100 разделителей"):
        parse_workbook(path)
    path.write_text("ID;File\n" + "\n".join(f"X-{k};" + ";" * 60 for k in range(50)) + "\n", encoding="utf-8")
    assert len(parse_workbook(path).findings) == 50, "предел – на запись, а не на файл"


# ============================================================================ формулы

def _patch_sheet(path, part: str, replacements: dict[str, str]):
    """Заменить в разметке листа куски текста (ячейки) – так получаются формулы с сохранённым значением, которые
    openpyxl сам не пишет."""
    with zipfile.ZipFile(path) as src:
        items = [(item, src.read(item.filename)) for item in src.infolist()]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as dst:
        for item, data in items:
            if item.filename == part:
                text = data.decode("utf-8")
                for old, new in replacements.items():
                    assert old in text, old
                    text = text.replace(old, new)
                data = text.encode("utf-8")
            dst.writestr(item, data)
    return path


SAST_PART = "xl/worksheets/sheet2.xml"  # лист SAST в make_hub_xlsx (первый – сводка)


def test_formula_with_stale_value_in_id_column_is_refused(tmp_path):
    """Формула в колонке номера находки со старым сохранённым значением: раньше в базу попал бы чужой номер."""
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    _patch_sheet(path, SAST_PART, {_inline("A2", "510001"):
                                   '<c r="A2" t="str"><f>"5100"&amp;"09"</f><v>510009</v></c>'})
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2") as info:
        parse_workbook(path)
    assert "Выгрузите отчёт из AppSec.Hub заново" in str(info.value)


def test_formula_without_value_in_line_column_is_refused(tmp_path):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    _patch_sheet(path, SAST_PART, {_inline("F2", "58"): '<c r="F2"><f>57+1</f></c>'})
    with pytest.raises(ImportFailure, match="«Line number» – строка 2"):
        parse_workbook(path)


def test_array_formula_covers_its_whole_range(tmp_path):
    """Формула массива записана только в первой ячейке диапазона, а значения – во всех: отмечается весь диапазон."""
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    _patch_sheet(path, SAST_PART, {_inline("B2", "Demo Library"):
                                   '<c r="B2" t="str"><f t="array" ref="B2:B5">"Demo Library"</f>'
                                   "<v>Demo Library</v></c>"})
    with pytest.raises(ImportFailure, match="«Application» – строки 2–5"):
        parse_workbook(path)


def test_formula_in_unused_column_is_a_warning(tmp_path):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    _patch_sheet(path, SAST_PART, {_inline("N2", "-"): '<c r="N2" t="str"><f>"artifact"</f><v>artifact.jar</v></c>'})
    result = parse_workbook(path)
    assert len(result.findings) == 4
    assert any("есть формулы (лист «SAST», «Artifact»)" in w for w in result.warnings)


def test_table_formulas_below_and_above_header(tmp_path):
    """Таблица (не отчёт Hub): формула над строкой заголовков не мешает, формула в колонке ID – отказ."""
    path = tmp_path / "t.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = "=1+1"  # подпись над таблицей, без сохранённого значения
    ws.append(["ID", "File", "Line"])
    ws.append(["X-1", "src/a.py", 3])
    wb.save(path)
    result = parse_workbook(path)
    assert [f.hub_id for f in result.findings] == ["X-1"] and result.warnings == []
    ws["A3"] = "=\"X-\"&2"
    wb.save(path)
    with pytest.raises(ImportFailure, match="«ID» – строка 3"):
        parse_workbook(path)


def test_formula_areas_merge_down_a_column():
    formulas = hi._Formulas()
    for row in range(2, 1000):
        formulas.add(3, row)
    formulas.add(3, 2000)
    formulas.add(hi.MAX_COLUMNS + 1, 5)  # дальние колонки не читаются
    assert formulas.areas == [[3, 3, 2, 999], [3, 3, 2000, 2000]]
    assert formulas.rows_in(3, 500) == [(500, 999), (2000, 2000)]
    assert hi._spans_text(formulas.rows_in(3, 1)) == "строки 2–999, 2000"


# ============================================================================ защиты и формат по содержимому

def test_format_by_content_not_extension(tmp_path, hub_xlsx):
    renamed = tmp_path / "upload.tmp"
    renamed.write_bytes(hub_xlsx.read_bytes())
    assert parse_workbook(renamed).format == "hub", "книга с другим расширением всё равно книга"
    fake = tmp_path / "fake.xlsx"
    fake.write_text("ID;File\n1;a\n", encoding="utf-8")
    with pytest.raises(ImportFailure, match="не является"):
        parse_workbook(fake)
    old = tmp_path / "old.xls"
    old.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600)
    with pytest.raises(ImportFailure, match=r"\.xls"):
        parse_workbook(old)
    binary = tmp_path / "picture.csv"
    binary.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    with pytest.raises(ImportFailure, match="не похож на таблицу"):
        parse_workbook(binary)
    broken = tmp_path / "broken.xlsx"
    broken.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    with pytest.raises(ImportFailure):
        parse_workbook(broken)


def test_missing_empty_and_too_big(tmp_path, hub_xlsx):
    with pytest.raises(ImportFailure, match="не найден"):
        parse_workbook(tmp_path / "nope.xlsx")
    empty = tmp_path / "empty.csv"
    empty.write_bytes(b"")
    with pytest.raises(ImportFailure, match="пуст"):
        parse_workbook(empty)
    with pytest.raises(ImportFailure, match="больше 1 МБ"):
        parse_workbook(hub_xlsx, max_bytes=1024)


def test_zip_bomb_guard(tmp_path, hub_xlsx, monkeypatch):
    monkeypatch.setattr(hi, "MAX_UNZIPPED_BYTES", 2000)
    with pytest.raises(ImportFailure, match="Распакованная книга"):
        parse_workbook(hub_xlsx)
    monkeypatch.undo()
    monkeypatch.setattr(hi, "MAX_ZIP_ENTRIES", 3)
    with pytest.raises(ImportFailure, match="много частей"):
        parse_workbook(hub_xlsx)


def test_zip_ratio_guard(tmp_path):
    """Сжатие в сотни раз при большом распакованном размере – архив-бомба, до openpyxl дело не доходит."""
    path = tmp_path / "bomb.xlsx"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("xl/worksheets/sheet1.xml", b"\x00" * (60 * 1024 * 1024))
    assert path.stat().st_size < 1024 * 1024
    with pytest.raises(ImportFailure, match="Распакованная книга"):
        parse_workbook(path)


def test_row_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_ROWS", 3)
    with pytest.raises(ImportFailure, match="больше 3 строк"):
        parse_workbook(make_hub_xlsx(tmp_path / "r.xlsx", sca=[]))


# ============================================================================ разбор значений

def test_parsing_helpers():
    assert hi.parse_cwes("1333, 400") == ["CWE-1333", "CWE-400"]
    assert hi.parse_cwes("89.0") == ["CWE-89"]
    assert hi.parse_cwes("CWE-79; CWE-80; CWE-79") == ["CWE-79", "CWE-80"]
    assert hi.parse_cwes("CWE-89: SQL (OWASP A03:2021)") == ["CWE-89"], "2021 – не CWE"
    assert hi.parse_cwes("нет данных") == []
    assert hi.parse_vuln_ids("AST-2026-000101, CVE-2099-10001; GHSA-abcd-1234-efgh BDU:2026-01234") == \
        ["AST-2026-000101", "GHSA-abcd-1234-efgh", "BDU:2026-01234"]
    assert hi.parse_vuln_ids("Log4Shell") == [], "слово без номера – не идентификатор"
    assert hi.parse_vuln_ids("GHSA-cfgh-jmpq-rvwx") == ["GHSA-cfgh-jmpq-rvwx"], "GHSA бывает без цифр"
    hyphen = chr(0x2011)  # неразрывный дефис
    assert hi.parse_cves(f"cve-2099-0001 и CVE{hyphen}2099{hyphen}12345") == ["CVE-2099-0001", "CVE-2099-12345"]
    assert hi.split_code_tail("a ? b : 5 : 12") == ("a ? b : 5", 12)
    assert hi.split_code_tail("x = 1;") == ("x = 1;", None)
    assert hi.parse_urls(f"{MITRE.format(1)}, \n{MITRE.format(2)}") == [MITRE.format(1), MITRE.format(2)]
    assert [hi.norm_severity(s) for s in ("Critical", "Высокий", "Medium", "Низкая", "Info", "Unknown")] == \
        ["critical", "high", "medium", "low", "info", ""]
    assert [hi.parse_float(s) for s in ("7,5", "9.8 (Critical)", "1 234", "AV:N/AC:L", "")] == [7.5, 9.8, 1234.0,
                                                                                               None, None]
    assert [hi.parse_line(s) for s in ("57", "57.0", "57:12", "57-60", "0", "abc")] == [57, 57, 57, 57, None, None]
    assert hi.norm_path("\\builds\\.\\app//src/A.java") == "builds/app/src/A.java"


# ============================================================================ группы и срочность

def test_group_key():
    sast = Finding(hub_id="1", kind="SAST", rule="Внедрение SQL-кода", cwe=["CWE-89"], file="src/A.java", line=58)
    assert group_key(sast) == "Внедрение SQL-кода|CWE-89|src/A.java|58"
    assert group_key(Finding(hub_id="2", kind="SAST")) == "|||"
    sca = Finding(hub_id="3", kind="SCA", component="example-parser", version="1.4.2")
    assert group_key(sca) == "example-parser|1.4.2"
    lic = Finding(hub_id="4", kind="SCA-license", component="example-parser", version="1.4.2")
    assert group_key(lic) == "license|example-parser|1.4.2", "лицензия не склеивается с уязвимостями"
    assert group_key(sca.to_dict()) == group_key(sca), "словарь из базы – тоже находка"


def test_is_urgent_sca_by_cvss_not_policy(hub_xlsx):
    f = by_id(parse_workbook(hub_xlsx))
    assert is_urgent(f["73001"]) is True, "CVSS 9,8"
    assert is_urgent(f["73003"]) is False, "CVSS 8,9 – не срочная, хотя в Hub «Critical»"
    assert is_urgent(f["73003"], sca_cvss=8.5) is True
    assert is_urgent(f["510001"]) is True, "SAST High"
    assert is_urgent(f["510002"]) is False, "SAST Medium"
    assert is_urgent(f["510002"], sast_levels=("critical", "high", "medium")) is True
    assert is_urgent(Finding(hub_id="x", kind="SCA")) is False, "без CVSS SCA не срочная"
    assert is_urgent(Finding(hub_id="y", kind="SCA-license", severity="critical")) is False
    assert is_urgent({"kind": "SCA", "cvss": "9.0"}) is True


def test_finding_from_dict_roundtrip(hub_xlsx):
    for f in parse_workbook(hub_xlsx).findings:
        assert Finding.from_dict(f.to_dict()) == f
    loose = Finding.from_dict({"hub_id": 5, "kind": "SAST", "line": "58", "cvss": "9,8", "cwe": "CWE-89, CWE-79",
                               "unknown": 1})
    assert (loose.hub_id, loose.line, loose.cvss, loose.cwe) == ("5", 58, 9.8, ["CWE-89", "CWE-79"])
    result = parse_workbook(hub_xlsx)
    assert ImportResult.from_dict(result.to_dict()) == result


def test_stored_size_counts_json_escaping(tmp_path):
    """Управляющие знаки в JSON занимают по 6 байт: предел прочих колонок считается по тому, что ляжет в базу."""
    import json

    path = tmp_path / "ctl.csv"
    control = "\x01" * 4000
    path.write_text(";".join(["ID"] + [f"П{k}" for k in range(20)]) + "\n"
                    + ";".join(["X-1"] + [control] * 20) + "\n", encoding="utf-8")
    (f,) = parse_workbook(path).findings
    stored = len(json.dumps(f.extra, ensure_ascii=False, sort_keys=True).encode("utf-8"))
    assert stored <= hi.MAX_EXTRA_BYTES + 64 and len(f.extra) < 20

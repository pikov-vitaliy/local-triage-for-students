"""Формулы HYPERLINK в выгрузке AppSec.Hub.

Hub пишет в колонки «Issue id», «Application» и «CVE id» не значения, а формулы вида
HYPERLINK("адрес","текст") с сохранённым значением. Принимается только формула целиком из одного вызова HYPERLINK
с двумя литералами и сохранённым значением, равным второму литералу; остальное – отказ, как и раньше.
Адреса в тестах выдуманы (example.org), номера и названия тоже.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

import openpyxl
import pytest

from app import hub_import as hi
from app.hub_import import ImportFailure, hyperlink_text, parse_workbook
from hub_fixtures import SAST_ROWS, SCA_ROWS, make_hub_xlsx

SUMMARY_PART = "xl/worksheets/sheet1.xml"
SAST_PART = "xl/worksheets/sheet2.xml"
SCA_PART = "xl/worksheets/sheet3.xml"
URL = "https://hub.example.org/issues/{}"
GOOD_URL = "https://hub.example.org/issues/1"  # корректный адрес: в тестах видимого текста меняется только текст

# Колонки листов: A – Issue id, B – Application, H (SCA Security) – CVE id, N (SAST) – Artifact.


def _patch(path, part: str, change):
    """Применить change к тексту разметки листа внутри книги."""
    with zipfile.ZipFile(path) as src:
        items = [(item, src.read(item.filename)) for item in src.infolist()]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as dst:
        for item, data in items:
            if item.filename == part:
                data = change(data.decode("utf-8")).encode("utf-8")
            dst.writestr(item, data)
    return path


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def link_cell(ref: str, text: str, *, url: str | None = None, formula: str | None = None, value: str | None = ...,
              cell_type: str = "str", attrs: str = ' aca="false"') -> str:
    """Ячейка с формулой HYPERLINK и сохранённым значением, как её пишет Hub (value=None – без значения)."""
    body = formula if formula is not None else f'HYPERLINK("{url or URL.format(text)}","{text}")'
    shown = text if value is ... else value
    cached = "" if shown is None else f"<v>{_escape(shown)}</v>"
    return f'<c r="{ref}" t="{cell_type}"><f{attrs}>{_escape(body)}</f>{cached}</c>'


def _replace_cell(xml: str, ref: str, new_cell: str) -> str:
    """Заменить ячейку листа целиком (она написана как значение, строка или пустая)."""
    pattern = re.compile(rf'<c r="{ref}"[^>]*?(?:/>|>.*?</c>)', re.S)
    assert pattern.search(xml), ref
    return pattern.sub(lambda m: new_cell, xml, count=1)


def put(path, part: str, cells: dict[str, str]):
    def change(xml: str) -> str:
        for ref, cell in cells.items():
            xml = _replace_cell(xml, ref, cell)
        return xml
    return _patch(path, part, change)


def _cell_text(path, part: str, ref: str) -> str:
    with zipfile.ZipFile(path) as z:
        xml = z.read(part).decode("utf-8")
    return re.search(rf'<c r="{ref}"[^>]*?(?:/>|>.*?</c>)', xml, re.S).group(0)


def _sast_rows(n: int):
    rows = [dict(r) for r in SAST_ROWS]
    while len(rows) < n:
        extra = dict(rows[0])
        extra["Issue id"] = str(510000 + len(rows) + 1)
        extra["Line number"] = str(60 + len(rows))
        extra["Source code"] = f"{extra['Source code'].split(' : ')[0]} : {extra['Line number']}"
        rows.append(extra)
    return rows[:n]


def _real_like(tmp_path, *, sast=5, summary_link=True):
    """Книга по структуре настоящей выгрузки: HYPERLINK в Issue id и Application обоих листов, в CVE id и в сводке."""
    path = make_hub_xlsx(tmp_path / "hub.xlsx", sast=_sast_rows(sast), sca=SCA_ROWS, practices="auto",
                         severities="auto")
    sast_cells, sca_cells = {}, {}
    for k, row in enumerate(_sast_rows(sast), start=2):
        sast_cells[f"A{k}"] = link_cell(f"A{k}", row["Issue id"])
        sast_cells[f"B{k}"] = link_cell(f"B{k}", row["Application"], url="https://hub.example.org/apps/7")
    for k, row in enumerate(SCA_ROWS, start=2):
        sca_cells[f"A{k}"] = link_cell(f"A{k}", row["Issue id"])
        sca_cells[f"B{k}"] = link_cell(f"B{k}", row["Application"], url="https://hub.example.org/apps/7")
        if row["CVE id"].startswith("AST-"):
            sca_cells[f"H{k}"] = link_cell(f"H{k}", row["CVE id"], url="https://track.example.org/v/" + row["CVE id"])
    put(path, SAST_PART, sast_cells)
    put(path, SCA_PART, sca_cells)
    if summary_link:
        put(path, SUMMARY_PART, {"B3": link_cell("B3", "Demo Library", url="https://hub.example.org/apps/7")})
    return path


# ============================================================================ принимается

def test_real_like_workbook_imports_all_findings(tmp_path):
    path = _real_like(tmp_path)
    result = parse_workbook(path)
    assert result.format == "hub"
    kinds = [f.kind for f in result.findings]
    assert kinds.count("SAST") == 5 and kinds.count("SCA") == 3
    sast = [f for f in result.findings if f.kind == "SAST"]
    assert [f.hub_id for f in sast] == [str(r["Issue id"]) for r in _sast_rows(5)], "номер – видимый текст ссылки"
    assert {f.application for f in result.findings} == {"Demo Library"}
    assert result.summary["application"] == "Demo Library", "ссылка в B3 сводки читается тем же правилом"
    assert [c["ok"] for c in result.summary["check"] if c["practice"] in ("SAST", "SCA Security")] == [True, True]
    assert not any("формул" in w for w in result.warnings), result.warnings


def test_ast_identifier_in_cve_column_is_kept_as_is(tmp_path):
    result = parse_workbook(_real_like(tmp_path))
    by_id = {f.hub_id: f for f in result.findings}
    assert by_id["73001"].vuln_ids == ["AST-2026-000101"] and by_id["73001"].cve == []
    assert by_id["73003"].vuln_ids == ["AST-2026-000103"]
    assert by_id["73002"].cve == ["CVE-2099-10001"], "обычный CVE рядом не затронут"


def test_formulas_are_not_stored_and_address_is_dropped(tmp_path):
    """В находке нет ни адреса, ни текста формулы: только видимый текст."""
    result = parse_workbook(_real_like(tmp_path))
    dump = repr([vars(f) for f in result.findings])
    assert "example.org" not in dump and "HYPERLINK" not in dump


def test_formula_attributes_and_case_are_tolerated(tmp_path):
    path = make_hub_xlsx(tmp_path / "h.xlsx", sca=[])
    put(path, SAST_PART, {"A2": link_cell("A2", "510001", formula='hyperlink( "https://hub.example.org/i/1" , "510001" )',
                                          attrs="")})
    assert parse_workbook(path).findings[0].hub_id == "510001"


def test_summary_without_link_still_works(tmp_path):
    result = parse_workbook(_real_like(tmp_path, summary_link=False))
    assert len(result.findings) == 8 and result.summary["application"] == "Demo Library"


def test_hyperlink_text_units():
    assert hyperlink_text('HYPERLINK("https://hub.example.org/1","17")') == "17"
    assert hyperlink_text('=HYPERLINK("http://hub.example.org/1","Название системы")') == "Название системы"
    assert hyperlink_text('HYPERLINK("https://hub.example.org/1", "AST-2026-000101")') == "AST-2026-000101"


# ============================================================================ отказ

REFUSED = {
    "arithmetic": "A1+1",
    "cell_reference": 'HYPERLINK(A1,"510001")',
    "cell_reference_text": 'HYPERLINK("https://hub.example.org/1",A1)',
    "three_arguments": 'HYPERLINK("https://hub.example.org/1","510001","x")',
    "one_argument": 'HYPERLINK("https://hub.example.org/1")',
    "nested_function": 'HYPERLINK("https://hub.example.org/1",TEXT(510001,"0"))',
    "nested_url_function": 'HYPERLINK(CONCATENATE("https://hub.example.org/","1"),"510001")',
    "concatenation": 'HYPERLINK("https://hub.example.org/1","5100"&"01")',
    "text_around": '"x"&HYPERLINK("https://hub.example.org/1","510001")',
    "two_calls": 'HYPERLINK("https://hub.example.org/1","510001")&HYPERLINK("https://hub.example.org/2","2")',
    "doubled_quotes": 'HYPERLINK("https://hub.example.org/1","51""0001")',
    "empty_text": 'HYPERLINK("https://hub.example.org/1","")',
    "blank_text": 'HYPERLINK("https://hub.example.org/1","   ")',
    "script_url": 'HYPERLINK("javascript:alert(1)","510001")',
    "file_url": 'HYPERLINK("file:///C:/x","510001")',
    "relative_url": 'HYPERLINK("#Sheet1!A1","510001")',
    "url_with_space": 'HYPERLINK("https://hub.example.org/a b","510001")',
    "semicolon": 'HYPERLINK("https://hub.example.org/1";"510001")',
    "other_function": 'IMPORTXML("https://hub.example.org/1","510001")',
    "dde": "cmd|' /C calc'!A0",
    "dde_in_text": 'HYPERLINK("https://hub.example.org/1","=cmd|\' /C calc\'!A0")&"x"',
    "long_url": 'HYPERLINK("https://hub.example.org/' + "a" * 2100 + '","510001")',
    "long_text": 'HYPERLINK("https://hub.example.org/1","' + "9" * 4200 + '")',
}


@pytest.mark.parametrize("name", sorted(REFUSED))
def test_other_formulas_are_still_refused(tmp_path, name):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": link_cell("A2", "510001", formula=REFUSED[name])})
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2") as info:
        parse_workbook(path)
    message = str(info.value)
    assert "HYPERLINK" in message and "заменить значениями" in message, "в сообщении подсказка про HYPERLINK"


@pytest.mark.parametrize("variant", ["missing_value", "different_value", "number_type", "shared_string_type",
                                     "inline_type", "padded_value"])
def test_hyperlink_with_untrusted_stored_value_is_refused(tmp_path, variant):
    """Сохранённое значение должно совпасть с видимым текстом и быть строкой результата формулы."""
    cell = {
        "missing_value": link_cell("A2", "510001", value=None),
        "different_value": link_cell("A2", "510001", value="510009"),
        "number_type": link_cell("A2", "510001", cell_type="n"),
        "shared_string_type": link_cell("A2", "510001", cell_type="s"),
        "inline_type": link_cell("A2", "510001", cell_type="inlineStr"),
        "padded_value": link_cell("A2", "510001", value="510001 "),
    }[variant]
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": cell})
    # тип «общая строка» с текстом вместо номера – повреждённый лист (тоже отказ)
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2|повреждён"):
        parse_workbook(path)


@pytest.mark.parametrize("attrs", [' t="shared" ref="A2:A5" si="0"', ' t="array" ref="A2:A5"', ' t="dataTable"', ' si="0"'])
def test_shared_and_array_hyperlink_formulas_are_refused(tmp_path, attrs):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": link_cell("A2", "510001", attrs=attrs)})
    with pytest.raises(ImportFailure, match="«Issue id» – строк"):
        parse_workbook(path)


def test_two_formula_elements_in_one_cell_are_refused(tmp_path):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    double = ('<c r="A2" t="str"><f>HYPERLINK("https://hub.example.org/1","510001")</f>'
              '<f>HYPERLINK("https://hub.example.org/1","510001")</f><v>510001</v></c>')
    put(path, SAST_PART, {"A2": double})
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2"):
        parse_workbook(path)


def test_one_bad_formula_among_good_ones_is_found(tmp_path):
    path = _real_like(tmp_path)
    put(path, SAST_PART, {"B4": link_cell("B4", "Demo Library", formula='HYPERLINK("https://hub.example.org/a",B3)')})
    with pytest.raises(ImportFailure, match="«Application» – строка 4") as info:
        parse_workbook(path)
    assert "«Issue id»" not in str(info.value), "принятые ссылки в сообщение не попадают"


def test_formula_in_other_mapped_column_is_refused(tmp_path):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"F2": '<c r="F2" t="str"><f>57+1</f><v>58</v></c>'})
    with pytest.raises(ImportFailure, match="«Line number» – строка 2"):
        parse_workbook(path)


@pytest.mark.parametrize("ref, header, text", [("F2", "Line number", "58"), ("E2", "File", "src/Main.java"),
                                               ("G2", "Source code", "int x = 0;"), ("D2", "Category", "SQL"),
                                               ("C2", "Severity", "High")])
def test_hyperlink_in_other_mapped_column_is_refused(tmp_path, ref, header, text):
    """Ссылка HYPERLINK допустима только в «Issue id», «Application», «CVE id»: в остальных полях находки – отказ."""
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {ref: link_cell(ref, text)})
    with pytest.raises(ImportFailure, match=f"«{header}» – строка 2"):
        parse_workbook(path)


def test_hyperlink_in_sca_component_and_path_is_refused(tmp_path):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sast=[])
    put(path, SCA_PART, {"F2": link_cell("F2", "example-parser"), "M2": link_cell("M2", "a > b")})
    with pytest.raises(ImportFailure, match="«Component name» – строка 2.*«Path» – строка 2|«Path» – строка 2"):
        parse_workbook(path)


def test_hyperlink_in_unused_column_is_a_warning_like_other_formulas(tmp_path):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"N2": link_cell("N2", "billing-core-1.0.jar")})
    result = parse_workbook(path)
    assert len(result.findings) == 4 and any("есть формулы (лист «SAST», «Artifact»)" in w for w in result.warnings)


def test_bad_formula_in_unused_column_is_a_warning(tmp_path):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"N2": '<c r="N2" t="str"><f>"a"&amp;"b"</f><v>ab</v></c>'})
    assert any("есть формулы (лист «SAST», «Artifact»)" in w for w in parse_workbook(path).warnings)


def test_summary_with_other_formula_gives_warning_not_refusal(tmp_path):
    path = _real_like(tmp_path, summary_link=False)
    put(path, SUMMARY_PART, {"B3": '<c r="B3" t="str"><f>"Demo "&amp;"Library"</f><v>Demo Library</v></c>'})
    result = parse_workbook(path)
    assert len(result.findings) == 8
    assert any("На листе сводки" in w and "сверка со сводкой" in w for w in result.warnings)


# ============================================================================ пределы

def test_accepted_formulas_do_not_enter_the_formula_budget(tmp_path):
    """Много принятых ссылок – не «слишком много формул»: участки считаются только у отказных формул."""
    rows = _sast_rows(4)
    path = make_hub_xlsx(tmp_path / "r.xlsx", sast=rows, sca=[])
    put(path, SAST_PART, {f"A{k}": link_cell(f"A{k}", r["Issue id"]) for k, r in enumerate(rows, start=2)})
    scan = hi._BookScan()
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        hi._scan_sheet(wb["SAST"], "SAST", hi._Limits(1000, scan))
    finally:
        wb.close()
    assert scan.sheets["SAST"].link_cells.areas == [[1, 1, 2, 5]] and not scan.sheets["SAST"]


def test_long_visible_text_is_limited_like_any_cell(tmp_path):
    text = "x" * 3000
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"B2": link_cell("B2", text, url="https://hub.example.org/apps/7")})
    result = parse_workbook(path)
    application = result.findings[0].application
    assert application.startswith("x" * 900) and application.endswith(hi.CELL_CUT_MARK), "поле обрезано как обычно"
    assert any("слишком длинные значения" in w for w in result.warnings)


def test_formula_text_is_not_accumulated_without_limit():
    """Формула в мегабайт не копится целиком: она короче предела не станет и всё равно отказ."""
    assert hyperlink_text('HYPERLINK("https://hub.example.org/1","' + "a" * (hi.MAX_FORMULA_CHARS + 10) + '")') is None


# ============================================================================ конфликт интерпретаций: f и v

F = 'HYPERLINK("https://hub.example.org/1","510001")'
CONFLICTS = {
    "two_values_concatenated": f'<c r="A2" t="str"><f>{_escape(F)}</f><v>5100</v><v>01</v></c>',
    "two_equal_values": f'<c r="A2" t="str"><f>{_escape(F)}</f><v>510001</v><v>510001</v></c>',
    "nested_in_value": f'<c r="A2" t="str"><f>{_escape(F)}</f><v>5100<x>01</x></v></c>',
    "nested_in_value_tail": f'<c r="A2" t="str"><f>{_escape(F)}</f><v>510001<x/></v></c>',
    "nested_in_formula": f'<c r="A2" t="str"><f>{_escape(F)}<x/></f><v>510001</v></c>',
    "two_formulas": f'<c r="A2" t="str"><f>{_escape(F)}</f><f>{_escape(F)}</f><v>510001</v></c>',
    "value_before_formula_and_second": f'<c r="A2" t="str"><v>510009</v><f>{_escape(F)}</f><v>510001</v></c>',
}


@pytest.mark.parametrize("name", sorted(CONFLICTS))
def test_ambiguous_formula_cells_are_refused_through_parse_workbook(tmp_path, name):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": CONFLICTS[name]})
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2"):
        parse_workbook(path)


def test_value_is_compared_without_normalization(tmp_path):
    """Сохранённое значение с пробелом по краю не равно литералу без него: отказ."""
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": link_cell("A2", "510001", value="510001 ")})
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2"):
        parse_workbook(path)


# ============================================================================ двойники имени и пробелы

LOOKALIKES = {
    "dotless_i": 'HYPERLıNK("https://hub.example.org/1","510001")',
    "dotted_capital_i": 'HYPERLİNK("https://hub.example.org/1","510001")',
    "kelvin_sign": 'HYPERLINK("https://hub.example.org/1","510001")',
    "cyrillic_letters": 'НYPERLINK("https://hub.example.org/1","510001")',
    "cyrillic_e": 'HYPЕRLINK("https://hub.example.org/1","510001")',
    "no_break_space": 'HYPERLINK( "https://hub.example.org/1","510001")',
    "em_space": 'HYPERLINK("https://hub.example.org/1", "510001")',
    "ideographic_space": 'HYPERLINK("https://hub.example.org/1","510001"　)',
    "newline_between": 'HYPERLINK("https://hub.example.org/1",\n"510001")',
    "space_before_paren": 'HYPERLINK ("https://hub.example.org/1","510001")',
}


@pytest.mark.parametrize("name", sorted(LOOKALIKES))
def test_lookalike_function_names_and_unicode_spaces_are_refused(tmp_path, name):
    assert hyperlink_text(LOOKALIKES[name]) is None
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": link_cell("A2", "510001", formula=LOOKALIKES[name])})
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2"):
        parse_workbook(path)


def test_ascii_tabs_and_spaces_between_tokens_are_allowed():
    assert hyperlink_text('hYpErLiNk(\t"https://hub.example.org/1" ,\t"17" )') == "17"


@pytest.mark.parametrize("shown", ["a\tb", "a\nb", "a\rb", "a\x00b", "a\x1fb", "a\x7fb"])
def test_control_characters_in_visible_text_are_refused(shown):
    assert hyperlink_text(f'HYPERLINK("https://hub.example.org/1","{shown}")') is None


# ============================================================================ пределы разметки до чтения листа

def _forbid_sheet_reading(monkeypatch):
    original = hi._physical_rows

    def spy(ws):
        if ws.title == "SAST":
            raise AssertionError("лист попал к openpyxl, хотя просмотр должен был отказать раньше")
        return original(ws)
    monkeypatch.setattr(hi, "_physical_rows", spy)


def test_megabyte_formula_is_refused_before_openpyxl_reads_the_sheet(tmp_path, monkeypatch):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    huge = 'HYPERLINK("https://hub.example.org/1","' + "9" * (1024 * 1024) + '")'
    put(path, SAST_PART, {"A2": link_cell("A2", "510001", formula=huge, value="510001")})
    _forbid_sheet_reading(monkeypatch)
    with pytest.raises(ImportFailure, match="слишком длинный текст"):
        parse_workbook(path)


def test_megabyte_value_is_refused_before_openpyxl_reads_the_sheet(tmp_path, monkeypatch):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": link_cell("A2", "510001", value="9" * (1024 * 1024))})
    _forbid_sheet_reading(monkeypatch)
    with pytest.raises(ImportFailure, match="слишком длинный текст"):
        parse_workbook(path)


def test_row_text_limit_is_refused_before_openpyxl(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_XML_ROW_TEXT", 5000)
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    cells = {f"{c}2": f'<c r="{c}2" t="inlineStr"><is><t>{"x" * 2000}</t></is></c>' for c in "HIJ"}
    put(path, SAST_PART, cells)
    _forbid_sheet_reading(monkeypatch)
    with pytest.raises(ImportFailure, match="слишком много текста"):
        parse_workbook(path)


def test_recognition_limit_is_separate_from_xml_limit(tmp_path):
    """Формула в 5000 знаков короче предела разметки, но длиннее предела распознавания HYPERLINK: обычный отказ."""
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    long_formula = 'HYPERLINK("https://hub.example.org/1","' + "9" * 5000 + '")'
    put(path, SAST_PART, {"A2": link_cell("A2", "510001", formula=long_formula, value="9" * 5000)})
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2"):
        parse_workbook(path)


# ============================================================================ много формул: поведение

# ============================================================================ формульный текст как данные

DDE = "=cmd|' /C calc'!A0"


def test_formula_like_text_is_data_and_outputs_neutralize_it(tmp_path):
    """Чистый HYPERLINK с литералом, похожим на DDE-формулу, и совпадающим значением - обычный текст номера: при
    импорте он не исполняется, в CSV пакета получает апостроф. Текст дефекта предназначен для вставки в форму Hub,
    а не в таблицу: номер там выводится как есть (ADR-0043)."""
    import csv
    import io

    from app import sca

    path = make_hub_xlsx(tmp_path / "r.xlsx", sast=[], sca=SCA_ROWS[:1], practices="auto", severities="auto")
    put(path, SCA_PART, {"A2": link_cell("A2", DDE, url="https://hub.example.org/1")})
    finding = parse_workbook(path).findings[0]
    assert finding.hub_id == DDE
    crafted = [{"ecosystem": "maven", "component": finding.hub_id, "version": "1", "vulnerabilities": [],
                "hub_safe_version": ""}]
    cells = [c for row in csv.reader(io.StringIO(sca.package_csv(crafted))) for c in row]
    assert not any(c[:1] in ("=", "+", "-", "@") for c in cells), cells
    assert "'" + DDE in cells


def test_summary_link_outside_application_value_gives_warning(tmp_path):
    path = _real_like(tmp_path)
    put(path, SUMMARY_PART, {"B13": link_cell("B13", "1759")})
    result = parse_workbook(path)
    assert any("На листе сводки" in w for w in result.warnings)
    assert result.summary["application"] == "Demo Library"


# ============================================================================ пустой текст по Unicode

UNICODE_BLANKS = {"nbsp": " ", "em_space": " ", "ideographic_space": "　",
                  "nbsp_and_space": "   ", "figure_space": " "}


@pytest.mark.parametrize("name", sorted(UNICODE_BLANKS))
def test_unicode_blank_visible_text_is_refused_in_issue_id(tmp_path, name):
    """Текст из одних пробелов (в том числе неразрывных) – пустое значение ячейки: находка потерялась бы, нужен отказ."""
    blank = UNICODE_BLANKS[name]
    assert hyperlink_text(f'HYPERLINK("{GOOD_URL}","{blank}")') is None
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": link_cell("A2", blank, url=GOOD_URL)})  # адрес корректен: проверяется текст
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2"):
        parse_workbook(path)


@pytest.mark.parametrize("name", sorted(UNICODE_BLANKS))
def test_unicode_blank_visible_text_is_refused_in_summary_application(tmp_path, name):
    """В значении «Application» сводки такая ссылка дала бы пустое название системы без предупреждения."""
    path = _real_like(tmp_path, summary_link=False)
    put(path, SUMMARY_PART, {"B3": link_cell("B3", UNICODE_BLANKS[name], url=GOOD_URL)})
    result = parse_workbook(path)
    assert result.summary["application"] == ""
    assert any("На листе сводки" in w for w in result.warnings), result.warnings


@pytest.mark.parametrize("shown", ["a\tb", "a\nb", "a\x7fb", "a\x80b", "a\x85b", "a\x9fb", "a\u2028b",
                                   "a\u2029b"])
def test_c1_and_line_separators_in_visible_text_are_refused(tmp_path, shown):
    """Управляющие знаки сверх ASCII (C1, Zl, Zp) в видимом тексте тоже отказ – ADR-0043."""
    assert hyperlink_text(f'HYPERLINK("{GOOD_URL}","{shown}")') is None
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": link_cell("A2", shown, url=GOOD_URL)})  # адрес корректен: проверяется текст
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2"):
        parse_workbook(path)


@pytest.mark.parametrize("url", ["https://hub.example.org/\x80", "https://hub.example.org/\x85",
                                 "https://hub.example.org/\x9f", "https://hub.example.org/\u2028",
                                 "https://hub.example.org/\u2029",
                                 "https://hub.example.org/ a", "https://hub.example.org/\u00a0",
                                 "HTTPS://hub.example.org/1", "ftp://hub.example.org/1", "//hub.example.org/1",
                                 "https://", "javascript:alert(1)"])
def test_bad_url_with_correct_text_is_refused(tmp_path, url):
    """Текст и сохранённое значение корректны, меняется только адрес: отказ – именно из-за адреса."""
    assert hyperlink_text(f'HYPERLINK("{url}","510001")') is None
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": link_cell("A2", "510001", url=url)})
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2"):
        parse_workbook(path)


@pytest.mark.parametrize("bad", ["\x00", "\x0b", "\x1f"])
def test_c0_characters_make_the_sheet_damaged(tmp_path, bad):
    """Знаки C0, которых разметка XML не несёт вовсе: лист считается повреждённым – отказ, но по другой причине."""
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": link_cell("A2", f"5100{bad}01", url=GOOD_URL)})
    with pytest.raises(ImportFailure, match="повреждён"):
        parse_workbook(path)


def test_good_url_with_the_same_text_is_accepted(tmp_path):
    """Обратная сторона предыдущего теста: с корректным адресом та же ячейка принимается."""
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": link_cell("A2", "510001", url=GOOD_URL)})
    assert parse_workbook(path).findings[0].hub_id == "510001"


# ============================================================================ длина формулы суммарно

def test_long_formula_split_by_nested_element_is_refused_before_openpyxl(tmp_path, monkeypatch):
    """«[8000]<x/>[8000]» внутри f: каждый кусок короче предела, вся формула – длиннее; отказ до чтения листа."""
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    half = "9" * 8000
    cell = f'<c r="A2" t="str"><f>{half}<x/>{half}</f><v>510001</v></c>'
    put(path, SAST_PART, {"A2": cell})
    _forbid_sheet_reading(monkeypatch)
    with pytest.raises(ImportFailure, match="слишком длинный текст формулы"):
        parse_workbook(path)


def test_value_split_by_nested_element_is_refused_before_openpyxl(tmp_path, monkeypatch):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    half = "9" * 200_000
    cell = f'<c r="A2" t="str"><f>510001</f><v>{half}<x/>{half}</v></c>'
    put(path, SAST_PART, {"A2": cell})
    _forbid_sheet_reading(monkeypatch)
    with pytest.raises(ImportFailure, match="слишком длинный текст ячейки"):
        parse_workbook(path)


def _formula_of_length(length: int) -> str:
    """Формула ровно указанной длины: HYPERLINK с добитым нулями числом (распознавание её всё равно отвергнет)."""
    body = f'HYPERLINK("{GOOD_URL}","")'
    assert length > len(body)
    return body[:-2] + "9" * (length - len(body)) + '")'


def test_formula_length_exactly_at_the_limit_and_one_over(tmp_path, monkeypatch):
    """Ровно предел разметки – просмотр пройден, отказ обычный (по формуле); предел + 1 – отказ до чтения листа."""
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    exact = _formula_of_length(hi.MAX_XML_FORMULA_CHARS)
    assert len(exact) == hi.MAX_XML_FORMULA_CHARS
    put(path, SAST_PART, {"A2": link_cell("A2", "510001", formula=exact, value="510001")})
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2"):
        parse_workbook(path)
    over = _formula_of_length(hi.MAX_XML_FORMULA_CHARS + 1)
    put(path, SAST_PART, {"A2": link_cell("A2", "510001", formula=over, value="510001")})
    _forbid_sheet_reading(monkeypatch)
    with pytest.raises(ImportFailure, match="слишком длинный текст формулы"):
        parse_workbook(path)


def test_cell_text_exactly_at_the_limit_and_one_over(tmp_path, monkeypatch):
    """То же для текста ячейки: ровно предел читается, предел + 1 – отказ при просмотре."""
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    exact = f'<c r="B2" t="inlineStr"><is><t>{"x" * hi.MAX_XML_TEXT_NODE}</t></is></c>'
    put(path, SAST_PART, {"B2": exact})
    assert len(parse_workbook(path).findings) == 4
    over = f'<c r="B2" t="inlineStr"><is><t>{"x" * (hi.MAX_XML_TEXT_NODE + 1)}</t></is></c>'
    put(path, SAST_PART, {"B2": over})
    _forbid_sheet_reading(monkeypatch)
    with pytest.raises(ImportFailure, match="слишком длинный текст ячейки"):
        parse_workbook(path)


def test_inline_cell_text_is_summed_across_runs(tmp_path, monkeypatch):
    """Текст ячейки в нескольких кусках (inlineStr с оформлением): считается суммарно, отказ до чтения листа."""
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    run = "<r><t>" + "x" * 200_000 + "</t></r>"
    put(path, SAST_PART, {"B2": f'<c r="B2" t="inlineStr"><is>{run}{run}</is></c>'})
    _forbid_sheet_reading(monkeypatch)
    with pytest.raises(ImportFailure, match="слишком длинный текст ячейки"):
        parse_workbook(path)


# ============================================================================ значение, которое читает потребитель

def _consumer_values(path, sheet: str) -> dict:
    """Значения ячеек так, как их получает приложение (тот же путь, что при разборе): {(строка, колонка): значение}."""
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        return {(row, column): value for row, cells in hi._physical_rows(wb[sheet]) for column, value in cells}
    finally:
        wb.close()


def test_accepted_link_value_equals_what_the_consumer_reads(tmp_path):
    """Для принятой ссылки проверенный кеш и значение, которое читает приложение, – одно и то же."""
    path = _real_like(tmp_path)
    values = _consumer_values(path, "SAST")
    assert values[(2, 1)] == "510001" and values[(2, 2)] == "Demo Library"
    by_id = {f.hub_id: f for f in parse_workbook(path).findings}
    assert by_id["510001"].application == values[(2, 2)]


def test_second_value_element_changes_what_the_consumer_reads(tmp_path):
    """Основание правила «один v»: приложение прочитает «5100», а не склейку «510001», поэтому ячейка отвергается."""
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": CONFLICTS["two_values_concatenated"]})
    assert _consumer_values(path, "SAST")[(2, 1)] == "5100"
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2"):
        parse_workbook(path)


def test_nested_element_in_value_changes_what_the_consumer_reads(tmp_path):
    path = make_hub_xlsx(tmp_path / "r.xlsx", sca=[])
    put(path, SAST_PART, {"A2": CONFLICTS["nested_in_value"]})
    assert _consumer_values(path, "SAST")[(2, 1)] == "5100"
    with pytest.raises(ImportFailure, match="«Issue id» – строка 2"):
        parse_workbook(path)


# ============================================================================ ссылка выше строки заголовков

def test_link_above_the_header_row_does_not_matter(tmp_path):
    """Таблица (не отчёт Hub): ссылка в подписи над строкой заголовков разбору не мешает."""
    path = tmp_path / "t.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["Отчёт за октябрь"])  # строка 1 – подпись, строка 2 – заголовки
    ws.append(["ID", "File", "Line"])
    ws.append(["X-1", "src/a.py", 3])
    wb.save(path)
    put(path, "xl/worksheets/sheet1.xml", {"A1": link_cell("A1", "Отчёт за октябрь", url=GOOD_URL)})
    assert hyperlink_text(f'HYPERLINK("{GOOD_URL}","Отчёт за октябрь")') == "Отчёт за октябрь", "ссылка разрешённая"
    result = parse_workbook(path)
    assert [f.hub_id for f in result.findings] == ["X-1"] and not any("формул" in w for w in result.warnings)


def test_bad_formula_above_the_header_row_does_not_matter(tmp_path):
    path = tmp_path / "t.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["Отчёт"])
    ws.append(["ID", "File", "Line"])
    ws.append(["X-1", "src/a.py", 3])
    wb.save(path)
    put(path, "xl/worksheets/sheet1.xml", {"A1": '<c r="A1" t="str"><f>"Отч"&amp;"ёт"</f><v>Отчёт</v></c>'})
    assert [f.hub_id for f in parse_workbook(path).findings] == ["X-1"]


# ============================================================================ бюджет участков: порознь

def _scattered(rows, column: str, cell_for) -> dict:
    """Ячейки в каждой второй строке: участки не сливаются, их столько же, сколько ячеек."""
    return {f"{column}{k}": cell_for(f"{column}{k}", k) for k in range(2, 2 + 2 * rows, 2)}


def _book_with_rows(tmp_path, name: str, count: int):
    rows = _sast_rows(count)
    return make_hub_xlsx(tmp_path / name, sast=rows, sca=[], practices="auto", severities="auto"), rows


BAD_CELL = '<c r="%s" t="str"><f>"a"&amp;"b"</f><v>ab</v></c>'


def test_refused_formula_areas_limit_exact_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_FORMULA_AREAS", 3)
    path, _ = _book_with_rows(tmp_path, "bad.xlsx", 8)
    put(path, SAST_PART, _scattered(3, "N", lambda ref, k: BAD_CELL % ref))
    assert any("есть формулы" in w for w in parse_workbook(path).warnings), "ровно предел – ещё можно сказать, где они"
    put(path, SAST_PART, _scattered(4, "N", lambda ref, k: BAD_CELL % ref))
    with pytest.raises(ImportFailure, match="слишком много формул"):
        parse_workbook(path)


def test_accepted_link_areas_limit_exact_boundary(tmp_path, monkeypatch):
    """У принятых ссылок свой счёт участков: до предела – импорт, сверх – отказ (где они, уже не сказать)."""
    monkeypatch.setattr(hi, "MAX_FORMULA_AREAS", 3)
    path, rows = _book_with_rows(tmp_path, "links.xlsx", 8)
    put(path, SAST_PART, _scattered(3, "A", lambda ref, k: link_cell(ref, rows[k - 2]["Issue id"])))
    assert len([f for f in parse_workbook(path).findings if f.kind == "SAST"]) == 8
    put(path, SAST_PART, _scattered(4, "A", lambda ref, k: link_cell(ref, rows[k - 2]["Issue id"])))
    with pytest.raises(ImportFailure, match="слишком много формул"):
        parse_workbook(path)


def test_contiguous_links_are_one_area(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_FORMULA_AREAS", 1)
    path, rows = _book_with_rows(tmp_path, "col.xlsx", 8)
    put(path, SAST_PART, {f"A{k}": link_cell(f"A{k}", r["Issue id"]) for k, r in enumerate(rows, start=2)})
    assert len([f for f in parse_workbook(path).findings if f.kind == "SAST"]) == 8


# ============================================================================ пакет SCA: номера находок не уходят

def test_package_report_never_carries_hub_ids(tmp_path):
    """Производственный путь пакета: номер находки (даже похожий на формулу) в строки пакета не попадает."""
    from app import sca

    path = make_hub_xlsx(tmp_path / "r.xlsx", sast=[], sca=SCA_ROWS[:1], practices="auto", severities="auto")
    put(path, SCA_PART, {"A2": link_cell("A2", DDE, url="https://hub.example.org/1")})
    finding = parse_workbook(path).findings[0]
    component = {"component": finding.component, "version": finding.version, "findings": 1,
                 "hub_ids": [finding.hub_id], "finding_ids": [1], "cvss": 9.8, "urgent": True, "cve": [],
                 "vuln_ids": list(finding.vuln_ids), "fixed_versions": [finding.fixed_version], "cwe": ["CWE-611"],
                 "codebases": ["billing-core"], "build_types": ["maven"], "dep_paths": ["a > b"], "reviewed": 0,
                 "entered": 0}
    rows, excluded = sca.package_report([component])
    assert rows and DDE not in repr(rows) and "hub_ids" not in repr(rows), rows
    assert DDE not in sca.package_csv(rows) and DDE not in repr(sca.answer_template(rows))


# ============================================================================ бюджет служебных частей книги

MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
PKG_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
OFFICE = "application/vnd.openxmlformats-officedocument.spreadsheetml"


def hand_made_xlsx(path, strings_part: str = "xl/sharedStrings.xml", filler: int = 0):
    """Книга, собранная вручную: одна строка данных и общие строки, которые можно положить под любым путём.

    `strings_part` – где лежат общие строки (назначение задаёт оглавление пакета, а не путь), `filler` – сколько
    лишних знаков добавить в них, чтобы проверить бюджет служебных частей."""
    sheet = (f'<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="{MAIN_NS}"><sheetData>'
             '<row r="1"><c r="A1" t="inlineStr"><is><t>Issue id</t></is></c>'
             '<c r="B1" t="inlineStr"><is><t>File</t></is></c></row>'
             '<row r="2"><c r="A2" t="s"><v>0</v></c><c r="B2" t="inlineStr"><is><t>src/a.py</t></is></c></row>'
             "</sheetData></worksheet>")
    strings = (f'<?xml version="1.0" encoding="UTF-8"?><sst xmlns="{MAIN_NS}" count="1" uniqueCount="1">'
               f'<si><t>X-1</t></si><si><t>{"y" * filler}</t></si></sst>')
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/'
            'content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.'
            'relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
            f'<Override PartName="/xl/workbook.xml" ContentType="{OFFICE}.sheet.main+xml"/>'
            f'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="{OFFICE}.worksheet+xml"/>'
            f'<Override PartName="/{strings_part}" ContentType="{OFFICE}.sharedStrings+xml"/></Types>'),
        "_rels/.rels": (f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{PKG_NS}"><Relationship '
                        f'Id="rId1" Type="{REL_NS}/officeDocument" Target="xl/workbook.xml"/></Relationships>'),
        "xl/workbook.xml": (f'<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="{MAIN_NS}" xmlns:r="{REL_NS}">'
                            '<sheets><sheet name="SAST" sheetId="1" r:id="rId1"/></sheets></workbook>'),
        "xl/_rels/workbook.xml.rels": (
            f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{PKG_NS}">'
            f'<Relationship Id="rId1" Type="{REL_NS}/worksheet" Target="worksheets/sheet1.xml"/>'
            f'<Relationship Id="rId2" Type="{REL_NS}/sharedStrings" Target="/{strings_part}"/></Relationships>'),
        strings_part: strings,
        "xl/worksheets/sheet1.xml": sheet,
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in parts.items():
            z.writestr(name, text)
    return path


def _forbid_opening_workbook(monkeypatch):
    def spy(fh):
        raise AssertionError("книга открыта, хотя проверка архива должна была отказать раньше")
    monkeypatch.setattr(hi, "_open_workbook", spy)


def test_hand_made_workbook_is_read(tmp_path):
    """Сначала – что собранная вручную книга вообще читается: иначе следующие проверки ничего не доказывают."""
    result = parse_workbook(hand_made_xlsx(tmp_path / "plain.xlsx"))
    assert [f.hub_id for f in result.findings] == ["X-1"]


def test_shared_strings_under_the_sheets_folder_still_count_as_a_service_part(tmp_path, monkeypatch):
    """Общие строки, объявленные под путём листов, – служебная часть: назначение задаёт оглавление пакета, а не путь.
    Их объём расходует бюджет, и отказ происходит до открытия книги."""
    monkeypatch.setattr(hi, "MAX_META_BYTES", 4000)
    disguised = "xl/worksheets/strings.xml"
    assert parse_workbook(hand_made_xlsx(tmp_path / "ok.xlsx", disguised)).findings, "маленькая книга читается"
    path = hand_made_xlsx(tmp_path / "big.xlsx", disguised, filler=20_000)
    _forbid_opening_workbook(monkeypatch)
    with pytest.raises(ImportFailure, match="Служебные части книги"):
        parse_workbook(path)


def test_sheet_part_outside_the_sheets_folder_is_not_a_service_part(tmp_path, monkeypatch):
    """И наоборот: часть листа вне папки листов остаётся листом, её объём бюджет служебных частей не расходует."""
    monkeypatch.setattr(hi, "MAX_META_BYTES", 4000)
    path = hand_made_xlsx(tmp_path / "moved.xlsx")
    with zipfile.ZipFile(path) as src:
        items = [(i.filename, src.read(i.filename)) for i in src.infolist()]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as dst:
        for name, data in items:
            text = data.decode("utf-8")
            if name in ("[Content_Types].xml", "xl/_rels/workbook.xml.rels"):
                text = text.replace("worksheets/sheet1.xml", "sheets/one.xml")
            if name == "xl/worksheets/sheet1.xml":
                name = "xl/sheets/one.xml"
                text += "<!--" + "z" * 20_000 + "-->"  # лист крупный, но это лист
            dst.writestr(name, text)
    assert [f.hub_id for f in parse_workbook(path).findings] == ["X-1"]


def test_service_parts_budget_exact_boundary(tmp_path, monkeypatch):
    """Ровно предел – книга читается, предел + 1 – отказ до открытия книги."""
    path = hand_made_xlsx(tmp_path / "exact.xlsx")
    with zipfile.ZipFile(path) as z:
        sizes = {i.filename: i.file_size for i in z.infolist()}
    meta = sum(size for name, size in sizes.items() if name != "xl/worksheets/sheet1.xml")
    monkeypatch.setattr(hi, "MAX_META_BYTES", meta)
    assert parse_workbook(path).findings, "служебные части ровно в предел"
    monkeypatch.setattr(hi, "MAX_META_BYTES", meta - 1)
    _forbid_opening_workbook(monkeypatch)
    with pytest.raises(ImportFailure, match="Служебные части книги"):
        parse_workbook(path)


def test_package_table_of_contents_is_limited(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_PACKAGE_XML_BYTES", 500)
    path = hand_made_xlsx(tmp_path / "toc.xlsx")
    _forbid_opening_workbook(monkeypatch)
    with pytest.raises(ImportFailure, match="Служебная часть книги"):
        parse_workbook(path)


def test_workbook_without_declared_parts_counts_everything_as_service(tmp_path, monkeypatch):
    """Оглавление пакета испорчено: назначение частей неизвестно, в бюджет идёт вся книга (запас в сторону отказа)."""
    monkeypatch.setattr(hi, "MAX_META_BYTES", 4000)
    path = hand_made_xlsx(tmp_path / "broken.xlsx", filler=20_000)
    with zipfile.ZipFile(path) as src:
        items = [(i.filename, src.read(i.filename)) for i in src.infolist()]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as dst:
        for name, data in items:
            dst.writestr(name, b"<broken" if name == "[Content_Types].xml" else data)
    _forbid_opening_workbook(monkeypatch)
    with pytest.raises(ImportFailure, match="Служебные части книги"):
        parse_workbook(path)


def test_real_hub_report_keeps_its_sheets_out_of_the_service_budget(tmp_path):
    """Выгрузка, собранная openpyxl (как настоящая): листы распознаны, бюджет служебных частей ею не исчерпан."""
    path = _real_like(tmp_path)
    with zipfile.ZipFile(path) as z:
        sheets = hi._sheet_parts(z, {i.filename for i in z.infolist()})
    assert sheets == {f"xl/worksheets/sheet{k}.xml" for k in range(1, 6)}, sheets
    assert parse_workbook(path).findings

"""Формулы HYPERLINK с сохранённым значением t="s" (индекс общей строки).

В настоящих полных выгрузках Hub значение формулы HYPERLINK хранится не строкой (t="str"), а ссылкой на общую строку: в <v>
индекс элемента sharedStrings. Ячейка принимается, если индекс в границах, <v> один и без вложенных элементов, общая строка
простая (<si><t>…</t></si>, без rich text и фонетики), а её текст – тот, который получит потребитель (таблица openpyxl), –
равен второму литералу формулы, ровно как у t="str". Адреса и тексты в тестах выдуманы.
"""

from __future__ import annotations

import time
import zipfile
from pathlib import Path

import pytest

from app import hub_import as hi
from app.hub_import import ImportFailure, parse_workbook
from hub_fixtures import SAST_ROWS, SCA_ROWS, make_hub_xlsx
from test_hub_hyperlinks import SAST_PART, SCA_PART, SUMMARY_PART, _escape, _sast_rows, link_cell, put
from test_web import create_project, web  # noqa: F401

SHARED_PART = "xl/sharedStrings.xml"
APP_URL = "https://hub.example.org/apps/7"


def simple(text: str) -> str:
    return f"<si><t>{_escape(text)}</t></si>"


def append_shared(path: Path, items: list[str]) -> int:
    """Дописать элементы <si> в общие строки книги -> индекс первого дописанного. Тестовые книги пишут строки внутри ячеек
    (inlineStr), поэтому части с общими строками может не быть: тогда она создаётся, как её пишет Excel (часть, объявление
    типа в оглавлении, отношение книги)."""
    with zipfile.ZipFile(path) as src:
        entries = [(item, src.read(item.filename)) for item in src.infolist()]
    names = {item.filename for item, _ in entries}
    first = 0
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as dst:
        for item, data in entries:
            if item.filename == SHARED_PART:
                xml = data.decode("utf-8")
                first = xml.count("<si>") + xml.count("<si ")
                data = xml.replace("</sst>", "".join(items) + "</sst>").encode("utf-8")
            elif item.filename == "[Content_Types].xml" and SHARED_PART not in names:
                data = data.decode("utf-8").replace(
                    "</Types>", f'<Override PartName="/{SHARED_PART}" ContentType="{hi._SHARED_STRINGS_TYPE}"/></Types>'
                ).encode("utf-8")
            elif item.filename == "xl/_rels/workbook.xml.rels" and SHARED_PART not in names:
                data = data.decode("utf-8").replace(
                    "</Relationships>", '<Relationship Id="rIdShared1" Type="http://schemas.openxmlformats.org/'
                    'officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/></Relationships>'
                ).encode("utf-8")
            dst.writestr(item, data)
        if SHARED_PART not in names:
            body = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' + "".join(items) + "</sst>")
            dst.writestr(SHARED_PART, body.encode("utf-8"))
    return first


def shared_book(tmp_path: Path, *, sast: int = 5, sca_rows=None, summary_link: bool = True, item=simple,
                cell=None, value=None, padding: int = 0) -> Path:
    """Книга по структуре настоящей выгрузки, у которой все ссылки HYPERLINK хранят значение как индекс общей строки.

    item(text) – разметка общей строки; cell(ref, text, url, index) – разметка ячейки (по умолчанию t="s" и <v>индекс</v>);
    value(index) – что записать в <v>; padding – сколько посторонних простых строк стоит в таблице перед нужными."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    sca_rows = SCA_ROWS if sca_rows is None else sca_rows
    sast_rows = _sast_rows(sast) if sast <= len(SAST_ROWS) else _sast_rows(sast)
    path = make_hub_xlsx(tmp_path / "hub.xlsx", sast=sast_rows, sca=sca_rows, practices="auto", severities="auto")
    wanted: list[tuple[str, str, str, str]] = []  # (часть листа, ячейка, текст, адрес)
    for k, row in enumerate(sast_rows, start=2):
        wanted.append((SAST_PART, f"A{k}", row["Issue id"], f"https://hub.example.org/issues/{row['Issue id']}"))
        wanted.append((SAST_PART, f"B{k}", row["Application"], APP_URL))
    for k, row in enumerate(sca_rows, start=2):
        wanted.append((SCA_PART, f"A{k}", row["Issue id"], f"https://hub.example.org/issues/{row['Issue id']}"))
        wanted.append((SCA_PART, f"B{k}", row["Application"], APP_URL))
        if row["CVE id"].startswith("AST-"):
            wanted.append((SCA_PART, f"H{k}", row["CVE id"], "https://track.example.org/v/" + row["CVE id"]))
    if summary_link:
        wanted.append((SUMMARY_PART, "B3", "Demo Library", APP_URL))
    first = append_shared(path, [simple(f"посторонняя строка {n}") for n in range(padding)]
                          + [item(text) for _, _, text, _ in wanted]) + padding
    by_part: dict[str, dict[str, str]] = {}
    for n, (part, ref, text, url) in enumerate(wanted):
        index = first + n
        stored = str(index) if value is None else value(index)
        if cell is None:
            xml = link_cell(ref, text, url=url, value=stored, cell_type="s")
        else:
            xml = cell(ref, text, url, stored)
        by_part.setdefault(part, {})[ref] = xml
    for part, cells in by_part.items():
        put(path, part, cells)
    return path


def refused(path: Path) -> str:
    with pytest.raises(ImportFailure) as info:
        parse_workbook(path)
    return str(info.value)


# ============================================================================ принимается

def test_formulas_with_shared_string_values_import_like_str_values(tmp_path):
    result = parse_workbook(shared_book(tmp_path))
    reference = parse_workbook(_str_book(tmp_path / "ref"))
    assert [f.hub_id for f in result.findings] == [f.hub_id for f in reference.findings]
    assert [f.kind for f in result.findings].count("SAST") == 5 and len(result.findings) == 8
    assert {f.application for f in result.findings} == {"Demo Library"}
    assert result.summary["application"] == "Demo Library"
    assert [c["ok"] for c in result.summary["check"] if c["practice"] in ("SAST", "SCA Security")] == [True, True]
    assert not any("формул" in w for w in result.warnings), result.warnings
    dump = repr([vars(f) for f in result.findings])
    assert "example.org" not in dump and "HYPERLINK" not in dump, "адрес и формула не сохраняются"
    by_id = {f.hub_id: f for f in result.findings}
    assert by_id["73001"].vuln_ids == ["AST-2026-000101"], "AST-идентификатор из ссылки в колонке CVE id"


def _str_book(tmp_path: Path) -> Path:
    from test_hub_hyperlinks import _real_like

    tmp_path.mkdir(parents=True, exist_ok=True)
    return _real_like(tmp_path)


def test_mixed_str_and_shared_values_in_one_book(tmp_path):
    path = shared_book(tmp_path)
    # половина ячеек листа SAST – прежнего вида t="str"
    put(path, SAST_PART, {f"A{k}": link_cell(f"A{k}", row["Issue id"]) for k, row in enumerate(_sast_rows(5), start=2)})
    assert len(parse_workbook(path).findings) == 8


def test_large_shared_strings_table_is_fine(tmp_path):
    started = time.monotonic()
    result = parse_workbook(shared_book(tmp_path, padding=60_000))
    assert len(result.findings) == 8 and time.monotonic() - started < 20


def test_full_size_workbook_does_not_hit_the_limits(tmp_path):
    """800 находок SAST и 1000 SCA: по две-три ссылки в строке, все t="s" – бюджеты участков, ячеек и обращений не срабатывают."""
    sca = []
    for n in range(1000):
        row = dict(SCA_ROWS[0])
        row["Issue id"] = str(90000 + n)
        sca.append(row)
    started = time.monotonic()
    path = shared_book(tmp_path, sast=800, sca_rows=sca, summary_link=True)
    result = parse_workbook(path)
    elapsed = time.monotonic() - started
    kinds = [f.kind for f in result.findings]
    assert kinds.count("SAST") == 800 and kinds.count("SCA") == 1000, (kinds.count("SAST"), kinds.count("SCA"))
    assert not any("формул" in w for w in result.warnings)
    assert elapsed < 60, elapsed


# ============================================================================ отказ: каждый случай – обычная формула

BAD_FORMULA = "формулы в колонках"


def refused_either(path: Path) -> str:
    """Отказ либо нашей сверкой (обычная формула), либо самим openpyxl, который не читает такую ячейку («лист повреждён»)."""
    message = refused(path)
    assert BAD_FORMULA in message or "повреждён" in message, message
    return message


def test_index_out_of_bounds_is_refused(tmp_path):
    refused_either(shared_book(tmp_path, value=lambda index: str(index + 1_000_000)))


@pytest.mark.parametrize("stored", ["-1", "+3", "07", " 3", "3 ", "3.0", "1e1", "0x3", "", "три", "9" * 12])
def test_malformed_index_is_refused(tmp_path, stored):
    refused_either(shared_book(tmp_path, value=lambda index: stored))


def test_rich_text_shared_string_is_refused(tmp_path):
    assert BAD_FORMULA in refused(shared_book(tmp_path, item=lambda text: f"<si><r><t>{_escape(text)}</t></r></si>"))


def test_phonetic_runs_in_shared_string_are_refused(tmp_path):
    phonetic = lambda text: f'<si><t>{_escape(text)}</t><rPh sb="0" eb="1"><t>x</t></rPh></si>'  # noqa: E731
    assert BAD_FORMULA in refused(shared_book(tmp_path, item=phonetic))
    props = lambda text: f'<si><t>{_escape(text)}</t><phoneticPr fontId="1"/></si>'  # noqa: E731
    assert BAD_FORMULA in refused(shared_book(tmp_path / "p", item=props))


def test_shared_text_different_from_the_literal_is_refused(tmp_path):
    assert BAD_FORMULA in refused(shared_book(tmp_path, item=lambda text: simple(text + "X")))


def test_two_values_in_a_cell_are_refused(tmp_path):
    def two(ref, text, url, stored):
        return link_cell(ref, text, url=url, value=stored, cell_type="s").replace(
            f"<v>{stored}</v>", f"<v>{stored}</v><v>{stored}</v>")

    assert BAD_FORMULA in refused(shared_book(tmp_path, cell=two))


def test_nested_element_in_the_value_is_refused(tmp_path):
    def nested(ref, text, url, stored):
        return link_cell(ref, text, url=url, value=stored, cell_type="s").replace(
            f"<v>{stored}</v>", f"<v>{stored}<x/></v>")

    assert BAD_FORMULA in refused(shared_book(tmp_path, cell=nested))


def test_xml_escapes_and_whitespace_in_the_shared_text_must_match_exactly(tmp_path):
    assert BAD_FORMULA in refused(shared_book(tmp_path, item=lambda text: simple(text + " ")))


def test_formula_shape_rules_are_unchanged_for_shared_values(tmp_path):
    """Правила формулы те же: вложенная функция и ссылка на ячейку по-прежнему отказ, хотя значение – общая строка."""
    def odd(ref, text, url, stored):
        return link_cell(ref, text, formula=f'HYPERLINK("{url}",A1)', value=stored, cell_type="s")

    assert BAD_FORMULA in refused(shared_book(tmp_path, cell=odd))


# ============================================================================ пределы

def test_too_many_shared_strings_means_no_trust(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_SHARED_STRINGS", 5)
    assert BAD_FORMULA in refused(shared_book(tmp_path))


def test_lookup_budget_is_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_SHARED_LOOKUPS", 3)
    assert "общие строки" in refused(shared_book(tmp_path)).replace("общих строк", "общие строки")


def test_oversized_shared_text_is_not_trusted(tmp_path):
    long = "9" * (hi.MAX_SAFE_VALUE_CHARS + 10)
    rows = _sast_rows(5)
    rows[0]["Issue id"] = long
    path = make_hub_xlsx(tmp_path / "hub.xlsx", sast=rows, sca=SCA_ROWS, practices="auto", severities="auto")
    first = append_shared(path, [simple(long)])
    put(path, SAST_PART, {"A2": link_cell("A2", long, url="https://hub.example.org/1", value=str(first), cell_type="s")})
    assert BAD_FORMULA in refused(path)


# ============================================================================ загрузка в приложение

def test_http_upload_of_a_workbook_with_shared_values(web, tmp_path):  # noqa: F811
    from test_web import upload

    pid = create_project(web.client)
    r = upload(web.client, pid, shared_book(tmp_path))
    assert r.status_code == 303, r.text
    assert len(web.app.state.db.findings_data(pid)) == 8
    bad = upload(web.client, pid, shared_book(tmp_path / "bad", item=lambda text: simple(text + "X")))
    assert bad.status_code == 400 and "формулы в колонках" in bad.text

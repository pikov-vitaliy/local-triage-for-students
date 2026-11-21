"""Классификация частей XLSX по структуре пакета (ADR-0044, ADR-0048): какие части – листы, а какие служебные.

Бюджет служебных частей (MAX_META_BYTES) считается до открытия книги, поэтому от классификации зависит, можно ли
спрятать большую часть, «объявив» её листом. Любое противоречие в оглавлении, отношениях или списке листов делает
назначение неопределённым, и весь пакет идёт в бюджет служебных.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from app import hub_import as hi
from app.hub_import import ImportFailure, parse_workbook

MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
PKG = "http://schemas.openxmlformats.org/package/2006/relationships"
TYPES = "http://schemas.openxmlformats.org/package/2006/content-types"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
OFFICE = "application/vnd.openxmlformats-officedocument.spreadsheetml"
WORKSHEET_REL = f"{REL}/worksheet"
SHARED_REL = f"{REL}/sharedStrings"
BIG = 30_000  # размер большой части: больше MAX_META_BYTES в тестах бюджета


def make_parts(filler: int = 0) -> dict[str, str]:
    """Корректный пакет: книга, один лист, общие строки (в filler знаков можно спрятать большую часть)."""
    return {
        "[Content_Types].xml": (
            f'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="{TYPES}">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            f'<Override PartName="/xl/workbook.xml" ContentType="{OFFICE}.sheet.main+xml"/>'
            f'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="{OFFICE}.worksheet+xml"/>'
            f'<Override PartName="/xl/sharedStrings.xml" ContentType="{OFFICE}.sharedStrings+xml"/></Types>'),
        "_rels/.rels": (f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{PKG}"><Relationship Id="rId1" '
                        f'Type="{REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>'),
        "xl/workbook.xml": (f'<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="{MAIN}" xmlns:r="{REL}">'
                            '<sheets><sheet name="SAST" sheetId="1" r:id="rId1"/></sheets></workbook>'),
        "xl/_rels/workbook.xml.rels": (
            f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{PKG}">'
            f'<Relationship Id="rId1" Type="{WORKSHEET_REL}" Target="worksheets/sheet1.xml"/>'
            f'<Relationship Id="rId2" Type="{SHARED_REL}" Target="sharedStrings.xml"/></Relationships>'),
        "xl/sharedStrings.xml": (f'<?xml version="1.0" encoding="UTF-8"?><sst xmlns="{MAIN}" count="1" uniqueCount="1">'
                                 f'<si><t>X-1</t></si><si><t>{"y" * filler}</t></si></sst>'),
        "xl/worksheets/sheet1.xml": (
            f'<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="{MAIN}"><sheetData>'
            '<row r="1"><c r="A1" t="inlineStr"><is><t>Issue id</t></is></c></row>'
            '<row r="2"><c r="A2" t="s"><v>0</v></c></row></sheetData></worksheet>'),
    }


def write(path: Path, parts: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in parts.items():
            z.writestr(name, text)
    return path


def classify(tmp_path: Path, parts: dict[str, str]) -> set[str]:
    path = write(tmp_path / "p.xlsx", parts)
    with zipfile.ZipFile(path) as z:
        return hi._sheet_parts(z, {i.filename for i in z.infolist()})


def edit(parts: dict[str, str], name: str, old: str, new: str) -> dict[str, str]:
    assert old in parts[name], old
    return {**parts, name: parts[name].replace(old, new)}


SHEET = {"xl/worksheets/sheet1.xml"}


def test_valid_package_has_one_sheet(tmp_path):
    assert classify(tmp_path, make_parts()) == SHEET


def test_real_openpyxl_report_has_all_its_sheets(tmp_path):
    from hub_fixtures import make_hub_xlsx

    path = make_hub_xlsx(tmp_path / "hub.xlsx")
    with zipfile.ZipFile(path) as z:
        sheets = hi._sheet_parts(z, {i.filename for i in z.infolist()})
    assert sheets == {f"xl/worksheets/sheet{k}.xml" for k in range(1, 6)}


# ============================================================================ противоречия: пакет не классифицируется

CONFLICTS = {
    "second_override_changes_role": lambda p: edit(
        p, "[Content_Types].xml", "</Types>",
        f'<Override PartName="/xl/sharedStrings.xml" ContentType="{OFFICE}.worksheet+xml"/></Types>'),
    "repeated_default": lambda p: edit(
        p, "[Content_Types].xml", "</Types>", '<Default Extension="XML" ContentType="application/xml"/></Types>'),
    "empty_override_type": lambda p: edit(
        p, "[Content_Types].xml", f'<Override PartName="/xl/sharedStrings.xml" ContentType="{OFFICE}.sharedStrings+xml"/>',
        '<Override PartName="/xl/sharedStrings.xml" ContentType=""/>'),
    "non_canonical_part_name": lambda p: edit(
        p, "[Content_Types].xml", 'PartName="/xl/worksheets/sheet1.xml"', 'PartName="/xl//worksheets/sheet1.xml"'),
    "dot_segments_in_part_name": lambda p: edit(
        p, "[Content_Types].xml", 'PartName="/xl/worksheets/sheet1.xml"',
        'PartName="/xl/worksheets/../worksheets/sheet1.xml"'),
    "case_collision_of_part_names": lambda p: edit(
        p, "[Content_Types].xml", "</Types>",
        f'<Override PartName="/XL/WORKBOOK.XML" ContentType="{OFFICE}.sheet.main+xml"/></Types>'),
    "content_types_root_is_wrong": lambda p: edit(p, "[Content_Types].xml", "<Types ", "<Other "),
    "content_types_wrong_namespace": lambda p: edit(p, "[Content_Types].xml", f'xmlns="{TYPES}"', 'xmlns="urn:x"'),
    "broken_content_types": lambda p: {**p, "[Content_Types].xml": "<Types"},
    "no_office_document_relation": lambda p: edit(p, "_rels/.rels", f"{REL}/officeDocument", f"{REL}/other"),
    "two_office_document_relations": lambda p: edit(
        p, "_rels/.rels", "</Relationships>",
        f'<Relationship Id="rId2" Type="{REL}/officeDocument" Target="xl/sharedStrings.xml"/></Relationships>'),
    "office_document_is_external": lambda p: edit(p, "_rels/.rels", 'Target="xl/workbook.xml"',
                                                  'Target="xl/workbook.xml" TargetMode="External"'),
    "office_document_is_not_a_workbook_type": lambda p: edit(
        p, "[Content_Types].xml", f'<Override PartName="/xl/workbook.xml" ContentType="{OFFICE}.sheet.main+xml"/>',
        f'<Override PartName="/xl/workbook.xml" ContentType="{OFFICE}.styles+xml"/>'),
    "repeated_relation_id": lambda p: edit(
        p, "xl/_rels/workbook.xml.rels", 'Id="rId2"', 'Id="rId1"'),
    "same_part_two_roles": lambda p: edit(
        p, "xl/_rels/workbook.xml.rels", "</Relationships>",
        f'<Relationship Id="rId9" Type="{SHARED_REL}" Target="worksheets/sheet1.xml"/></Relationships>'),
    "sheet_listed_twice": lambda p: edit(
        p, "xl/workbook.xml", "</sheets>", '<sheet name="B" sheetId="2" r:id="rId1"/></sheets>'),
    "sheet_content_type_differs": lambda p: edit(
        p, "[Content_Types].xml", f'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="{OFFICE}.worksheet+xml"/>',
        f'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="{OFFICE}.styles+xml"/>'),
    "sheet_declared_with_other_case": lambda p: edit(
        p, "[Content_Types].xml", 'PartName="/xl/worksheets/sheet1.xml"', 'PartName="/xl/Worksheets/sheet1.xml"'),
    "sheet_target_outside_the_package": lambda p: edit(
        p, "xl/_rels/workbook.xml.rels", 'Target="worksheets/sheet1.xml"', 'Target="../../worksheets/sheet1.xml"'),
    "sheet_target_with_backslash": lambda p: edit(
        p, "xl/_rels/workbook.xml.rels", 'Target="worksheets/sheet1.xml"', 'Target="worksheets\\\\sheet1.xml"'),
    "sheet_part_is_missing": lambda p: edit(
        p, "xl/_rels/workbook.xml.rels", 'Target="worksheets/sheet1.xml"', 'Target="worksheets/none.xml"'),
    "workbook_relations_root_is_wrong": lambda p: edit(p, "xl/_rels/workbook.xml.rels", "<Relationships ",
                                                       "<Other "),
    "workbook_root_is_wrong": lambda p: edit(p, "xl/workbook.xml", "<workbook ", "<book "),
}


@pytest.mark.parametrize("name", sorted(CONFLICTS))
def test_contradictory_package_is_not_classified(tmp_path, name):
    parts = CONFLICTS[name](make_parts())
    assert classify(tmp_path, parts) == set(), name


# ============================================================================ не лист: остаётся служебной частью

NOT_A_SHEET = {
    "sheet_without_workbook_entry": lambda p: edit(p, "xl/workbook.xml", '<sheet name="SAST" sheetId="1" r:id="rId1"/>',
                                                   ""),
    "relation_id_not_listed": lambda p: edit(p, "xl/workbook.xml", 'r:id="rId1"', 'r:id="rId77"'),
    "external_sheet_relation": lambda p: edit(p, "xl/_rels/workbook.xml.rels", 'Target="worksheets/sheet1.xml"',
                                              'Target="worksheets/sheet1.xml" TargetMode="External"'),
    "chartsheet_relation": lambda p: edit(p, "xl/_rels/workbook.xml.rels", WORKSHEET_REL,
                                          f"{REL}/chartsheet"),
    "sheet_entry_in_foreign_namespace": lambda p: edit(
        p, "xl/workbook.xml", "<sheets><sheet ", '<sheets xmlns="urn:foreign"><sheet '),
}


@pytest.mark.parametrize("name", sorted(NOT_A_SHEET))
def test_part_that_is_not_listed_as_a_sheet_stays_service(tmp_path, name):
    assert classify(tmp_path, NOT_A_SHEET[name](make_parts())) == set(), name


def test_override_nested_in_an_extension_element_is_ignored(tmp_path):
    """Объявление не на своём месте оглавления (вложенное, в расширении) не считается: назначение берётся из настоящих."""
    parts = edit(make_parts(), "[Content_Types].xml", "</Types>",
                 f'<ext><Override PartName="/xl/sharedStrings.xml" ContentType="{OFFICE}.worksheet+xml"/></ext></Types>')
    assert classify(tmp_path, parts) == SHEET


def test_relation_in_a_foreign_namespace_is_a_conflict(tmp_path):
    """Прежняя редакция теста закрепляла «игнорируется»; openpyxl читает такие элементы без учёта пространства имён
    (см. ниже), поэтому назначение частей неоднозначно и пакет не классифицируется."""
    parts = edit(make_parts(), "xl/_rels/workbook.xml.rels", "</Relationships>",
                 f'<x:Relationship xmlns:x="urn:foreign" Id="rId1" Type="{SHARED_REL}" Target="worksheets/sheet1.xml"/>'
                 "</Relationships>")
    assert classify(tmp_path, parts) == set()


def test_macro_enabled_workbook_type_is_accepted(tmp_path):
    parts = edit(make_parts(), "[Content_Types].xml", f"{OFFICE}.sheet.main+xml",
                 "application/vnd.ms-excel.sheet.macroEnabled.main+xml")
    assert classify(tmp_path, parts) == SHEET


def test_workbook_in_another_folder_is_followed_through_the_root_relation(tmp_path):
    parts = make_parts()
    moved = {}
    for name, text in parts.items():
        new = name.replace("xl/", "book/") if name.startswith("xl/") else name
        moved[new] = text.replace("xl/", "book/")
    assert classify(tmp_path, moved) == {"book/worksheets/sheet1.xml"}


def test_absolute_targets_are_resolved_from_the_package_root(tmp_path):
    parts = edit(make_parts(), "xl/_rels/workbook.xml.rels", 'Target="worksheets/sheet1.xml"',
                 'Target="/xl/worksheets/sheet1.xml"')
    assert classify(tmp_path, parts) == SHEET


# ============================================================================ обход бюджета служебных частей

def spy_open(monkeypatch):
    def spy(fh):
        raise AssertionError("книга открыта, хотя проверка архива должна была отказать раньше")
    monkeypatch.setattr(hi, "_open_workbook", spy)


def disguise_as_sheet(parts: dict[str, str]) -> dict[str, str]:
    """Сценарий проверки: части общих строк повторно объявлена листом и указана отношением листа."""
    parts = edit(parts, "[Content_Types].xml", "</Types>",
                 f'<Override PartName="/xl/sharedStrings.xml" ContentType="{OFFICE}.worksheet+xml"/></Types>')
    return edit(parts, "xl/_rels/workbook.xml.rels", "</Relationships>",
                f'<Relationship Id="rId3" Type="{WORKSHEET_REL}" Target="sharedStrings.xml"/></Relationships>')


def test_shared_strings_redeclared_as_a_sheet_still_count(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_META_BYTES", 4000)
    path = write(tmp_path / "p.xlsx", disguise_as_sheet(make_parts(filler=BIG)))
    spy_open(monkeypatch)
    with pytest.raises(ImportFailure, match="Служебные части книги"):
        parse_workbook(path)


def test_styles_declared_as_a_sheet_without_being_listed_still_count(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_META_BYTES", 4000)
    parts = make_parts()
    parts["xl/styles.xml"] = f'<?xml version="1.0"?><styleSheet xmlns="{MAIN}"><!--{"z" * BIG}--></styleSheet>'
    parts = edit(parts, "[Content_Types].xml", "</Types>",
                 f'<Override PartName="/xl/styles.xml" ContentType="{OFFICE}.worksheet+xml"/></Types>')
    parts = edit(parts, "xl/_rels/workbook.xml.rels", "</Relationships>",
                 f'<Relationship Id="rId3" Type="{WORKSHEET_REL}" Target="styles.xml"/></Relationships>')
    path = write(tmp_path / "p.xlsx", parts)
    spy_open(monkeypatch)
    with pytest.raises(ImportFailure, match="Служебные части книги"):
        parse_workbook(path)


def test_theme_listed_as_a_sheet_with_a_second_role_still_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_META_BYTES", 4000)
    parts = make_parts()
    parts["xl/theme/theme1.xml"] = f'<?xml version="1.0"?><theme xmlns="urn:t"><!--{"z" * BIG}--></theme>'
    parts = edit(parts, "[Content_Types].xml", "</Types>",
                 f'<Override PartName="/xl/theme/theme1.xml" ContentType="{OFFICE}.worksheet+xml"/></Types>')
    parts = edit(parts, "xl/_rels/workbook.xml.rels", "</Relationships>",
                 f'<Relationship Id="rId3" Type="{WORKSHEET_REL}" Target="theme/theme1.xml"/>'
                 f'<Relationship Id="rId4" Type="{REL}/theme" Target="theme/theme1.xml"/></Relationships>')
    parts = edit(parts, "xl/workbook.xml", "</sheets>", '<sheet name="T" sheetId="2" r:id="rId3"/></sheets>')
    path = write(tmp_path / "p.xlsx", parts)
    spy_open(monkeypatch)
    with pytest.raises(ImportFailure, match="Служебные части книги"):
        parse_workbook(path)


def test_ordinary_big_sheet_is_not_a_service_part(tmp_path, monkeypatch):
    """Положительный контроль: настоящий большой лист бюджет служебных частей не расходует."""
    monkeypatch.setattr(hi, "MAX_META_BYTES", 4000)
    parts = make_parts()
    parts["xl/worksheets/sheet1.xml"] = parts["xl/worksheets/sheet1.xml"].replace(
        "</worksheet>", f"<!--{'z' * BIG}--></worksheet>")
    assert [f.hub_id for f in parse_workbook(write(tmp_path / "p.xlsx", parts)).findings] == ["X-1"]


def test_conflict_in_the_table_of_contents_puts_the_whole_package_into_the_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(hi, "MAX_META_BYTES", 4000)
    parts = make_parts()
    parts["xl/worksheets/sheet1.xml"] = parts["xl/worksheets/sheet1.xml"].replace(
        "</worksheet>", f"<!--{'z' * BIG}--></worksheet>")
    parts = CONFLICTS["repeated_default"](parts)
    path = write(tmp_path / "p.xlsx", parts)
    spy_open(monkeypatch)
    with pytest.raises(ImportFailure, match="Служебные части книги"):
        parse_workbook(path)


def test_dtd_in_the_package_part_is_refused(tmp_path, monkeypatch):
    parts = make_parts()
    parts["[Content_Types].xml"] = '<!DOCTYPE Types [<!ENTITY a "b">]>' + parts["[Content_Types].xml"]
    path = write(tmp_path / "p.xlsx", parts)
    spy_open(monkeypatch)
    with pytest.raises(ImportFailure, match="повреждена"):
        parse_workbook(path)


# ============================================================================ части, которые загрузчик читает по постоянным именам

import openpyxl  # noqa: E402

FIXED = {"xl/styles.xml": f'<?xml version="1.0"?><styleSheet xmlns="{MAIN}">%s</styleSheet>',
         "xl/theme/theme1.xml": '<?xml version="1.0"?><theme xmlns="urn:t">%s</theme>',
         "docProps/core.xml": '<?xml version="1.0"?><coreProperties xmlns="urn:c">%s</coreProperties>'}
FIXED_ROLES = {"xl/styles.xml": "styles", "xl/theme/theme1.xml": "theme", "docProps/core.xml": None}


def declare_as_sheet(parts: dict[str, str], name: str, filler: int = BIG, keep_second_role: bool = False,
                     list_in_workbook: bool = True) -> dict[str, str]:
    """Служебная часть с постоянным именем объявлена листом: оглавление, отношение листа и элемент sheet книги; вторая
    служебная роль (отношение styles или theme) по умолчанию убрана – самый коварный вариант."""
    parts = {**parts, name: FIXED[name] % ("<!--" + "z" * filler + "-->")}
    parts = edit(parts, "[Content_Types].xml", "</Types>",
                 f'<Override PartName="/{name}" ContentType="{OFFICE}.worksheet+xml"/></Types>')
    rid = "rId9"
    rel = f'<Relationship Id="{rid}" Type="{WORKSHEET_REL}" Target="/{name}"/>'
    if keep_second_role and FIXED_ROLES[name]:
        rel += f'<Relationship Id="rId10" Type="{REL}/{FIXED_ROLES[name]}" Target="/{name}"/>'
    parts = edit(parts, "xl/_rels/workbook.xml.rels", "</Relationships>", rel + "</Relationships>")
    if list_in_workbook:
        parts = edit(parts, "xl/workbook.xml", "</sheets>", f'<sheet name="X" sheetId="9" r:id="{rid}"/></sheets>')
    return parts


@pytest.mark.parametrize("name", sorted(FIXED))
@pytest.mark.parametrize("second_role", [False, True])
def test_part_with_a_fixed_service_name_declared_as_a_sheet_still_counts(tmp_path, monkeypatch, name, second_role):
    """Через настоящую загрузку и малый предел: бюджет не освобождается, отказ – до открытия книги."""
    monkeypatch.setattr(hi, "MAX_META_BYTES", 4000)
    parts = declare_as_sheet(make_parts(), name, keep_second_role=second_role)
    with zipfile.ZipFile(write(tmp_path / "p.xlsx", parts)) as z:
        assert hi._sheet_parts(z, {i.filename for i in z.infolist()}) == set(), "пакет не классифицирован"
    spy_open(monkeypatch)
    with pytest.raises(ImportFailure, match="Служебные части книги"):
        parse_workbook(tmp_path / "p.xlsx")


def test_openpyxl_really_reads_the_fixed_parts_whatever_the_package_says(tmp_path):
    """Основание правила: загрузчик читает xl/styles.xml и docProps/core.xml по постоянному имени даже у такой части,
    которую пакет объявил листом, – испорченная часть валит загрузку."""
    for name in ("xl/styles.xml", "docProps/core.xml"):
        parts = declare_as_sheet(make_parts(), name, filler=10)
        parts[name] = "<broken"
        path = write(tmp_path / (name.replace("/", "_") + ".xlsx"), parts)
        with pytest.raises(Exception):
            openpyxl.load_workbook(path, read_only=True, data_only=True)


def test_part_referenced_by_the_root_relations_cannot_be_a_sheet(tmp_path):
    parts = declare_as_sheet(make_parts(), "xl/styles.xml", filler=10)
    parts = edit(parts, "_rels/.rels", "</Relationships>",
                 f'<Relationship Id="rId5" Type="{REL}/extended-properties" Target="xl/worksheets/sheet1.xml"/>'
                 "</Relationships>")
    assert classify(tmp_path, parts) == set()


# ============================================================================ чужое пространство имён – по интерпретации openpyxl

def openpyxl_reads(path):
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        return [list(r) for r in wb["SAST"].iter_rows(values_only=True)]
    finally:
        wb.close()


FOREIGN = {
    "override_of_shared_strings": lambda p: edit(
        p, "[Content_Types].xml", f'<Override PartName="/xl/sharedStrings.xml" ContentType="{OFFICE}.sharedStrings+xml"/>',
        f'<x:Override xmlns:x="urn:foreign" PartName="/xl/sharedStrings.xml" ContentType="{OFFICE}.sharedStrings+xml"/>'),
    "extra_foreign_override": lambda p: edit(
        p, "[Content_Types].xml", "</Types>",
        f'<x:Override xmlns:x="urn:foreign" PartName="/xl/sharedStrings.xml" ContentType="{OFFICE}.worksheet+xml"/></Types>'),
    "foreign_worksheet_relation": lambda p: edit(
        p, "xl/_rels/workbook.xml.rels", "</Relationships>",
        f'<x:Relationship xmlns:x="urn:foreign" Id="rId7" Type="{WORKSHEET_REL}" Target="sharedStrings.xml"/>'
        "</Relationships>"),
    "foreign_sheet_entry": lambda p: edit(
        p, "xl/workbook.xml", "</sheets>", '<x:sheet xmlns:x="urn:foreign" name="Z" sheetId="7" r:id="rId2"/></sheets>'),
}


@pytest.mark.parametrize("name", sorted(FOREIGN))
def test_foreign_namespace_elements_are_a_conflict_because_openpyxl_ignores_namespaces(tmp_path, name):
    """openpyxl принимает такие элементы за настоящие (читает без учёта пространства имён), поэтому классификатор
    не вправе их игнорировать: назначение частей неоднозначно, весь пакет идёт в бюджет служебных частей."""
    parts = FOREIGN[name](make_parts())
    path = write(tmp_path / "p.xlsx", parts)
    with zipfile.ZipFile(path) as z:
        assert hi._sheet_parts(z, {i.filename for i in z.infolist()}) == set(), name


def test_openpyxl_ignores_the_namespace_of_the_table_of_contents(tmp_path):
    """Контроль основания: загрузчик читает пакет, у которого всё оглавление в чужом пространстве имён."""
    parts = edit(make_parts(), "[Content_Types].xml", f'xmlns="{TYPES}"', 'xmlns="urn:foreign"')
    assert openpyxl_reads(write(tmp_path / "p.xlsx", parts)) == [["Issue id"], ["X-1"]]
    assert classify(tmp_path, parts) == set()


def test_openpyxl_takes_a_foreign_namespace_override_for_a_real_one(tmp_path):
    """Контроль основания для элемента на месте настоящего: чужое пространство имён загрузчик не останавливает."""
    parts = FOREIGN["override_of_shared_strings"](make_parts())
    assert openpyxl_reads(write(tmp_path / "p.xlsx", parts)) == [["Issue id"], ["X-1"]]

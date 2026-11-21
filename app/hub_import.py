"""Разбор выгрузки AppSec.Hub.

Читается:
  отчёт Hub – книга .xlsx с листом «Summary Report» и листами практик SAST, SCA Security, SCA Compliance, DAST.
             У каждого листа своя карта колонок; вид находки – по листу, инструмент – из Found By, «-» – пустое
             значение. Сводка находками не считается: с её счётчиками сверяется число находок на листах;
  таблица  – одна таблица с заголовками (.xlsx или .csv): колонки сопоставляются по названиям (английским, как
             в Hub, или русским), вид находки – по колонке Practice/«Вид» или по заполненным полям.

Ловушки отчёта Hub, учтённые в карте колонок: Type – тип сборки или экосистема пакета (build_type), а не вид
находки; Path у SCA – путь зависимости (dep_path), а не файл; у SCA колонка Severity – уровень политики Hub
(policy_severity), а не тяжесть уязвимости, поэтому срочность SCA считается по CVSS; в колонке «CVE id» у SCA
часто стоит не CVE, а номер уязвимости AppSec.Track (AST-…): такие номера идут в vuln_ids; Source code
кончается хвостом « : <номер строки>», он отрезается.

Защита от подложенного файла: предел размера файла, проверка распакованного размера книги до openpyxl
(архив-бомба), пределы строк, колонок и длины ячейки; пустые строки не считаются и не разворачиваются в ячейки
(на листе бывает пустая строка 1 048 576 после правки в редакторе таблиц). openpyxl собирает строку разметки
листа целиком, со всеми её ячейками, и лишь потом отдаёт её, поэтому разметка каждого листа сначала просматривается
потоком (_scan_sheet): ячейки строки, элементы разметки и ячейки всей книги считаются до того, как openpyxl что-то
накопит. Ячейка книги может ссылаться на общую строку (sharedStrings): одна строка на 32 000 знаков размножается во
все ячейки, а маленький файл – в сотни мегабайт базы. Поэтому считается и общий объём текста – в ячейках книги и в
сохраняемых полях находок (каждая ячейка – до того, как её значение сохранено), – а у полей находки и прочих
колонок есть свои пределы длины.

Формулы не вычисляются: книга читается со значениями, сохранёнными при последнем пересчёте в Excel, а без
пересчёта они пустые или устаревшие. Формула в колонке, из которой берутся сведения о находке (номер, файл, строка,
код, компонент…), – отказ с понятным сообщением; в прочих колонках – предупреждение.
"""

from __future__ import annotations

import codecs
import csv
import datetime as dt
import io
import itertools
import json
import math
import posixpath
from xml.parsers import expat
import re
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from app.models import Finding, ImportResult

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_ROWS = 200_000                      # непустых строк на листе
MAX_SHEET_ROWS = 1_000_000              # строк разметки листа, вместе с пустыми оформленными
MAX_COLUMNS = 500                       # дальше ячейки строки не читаются
MAX_CELL_CHARS = 32_767                 # предел длины ячейки Excel; длиннее – обрезается с пометкой
MAX_UNZIPPED_BYTES = 500 * 1024 * 1024  # распакованная книга
MAX_ZIP_RATIO = 100                     # распакованная больше сжатой во столько раз – архив-бомба
MAX_ZIP_ENTRIES = 10_000
# Служебные части книги (общие строки, стили, свойства, списки отношений) openpyxl читает в память целиком ещё при
# открытии, до просмотра листов: их распакованный объём ограничен отдельно от всей книги. Служебная часть – всё, кроме
# проверенных частей листов (см. _sheet_parts): путь к части ничего не значит, назначение задаёт оглавление пакета.
MAX_META_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_XML_BYTES = 4 * 1024 * 1024  # оглавление пакета и список отношений книги: больше – так книга не выглядит

# Назначение частей книги по оглавлению пакета [Content_Types].xml и отношениям части книги.
_CONTENT_TYPES_PART = "[Content_Types].xml"
_WORKSHEET_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
_WORKBOOK_TYPES = ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
                   "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml",
                   "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
                   "application/vnd.ms-excel.template.macroEnabled.main+xml")
_WORKSHEET_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
# Объём текста ячеек (работа разбора): знаков – не больше TEXT_PER_BYTE распакованных размеров книги (или размеров
# CSV), маленькому файлу – не меньше MIN_TEXT_CHARS, всего – не больше MAX_TEXT_CHARS.
TEXT_PER_BYTE = 4
MIN_TEXT_CHARS = 2_000_000
MAX_TEXT_CHARS = 200_000_000
# Объём сохраняемых находок (то, что ляжет в базу), байты UTF-8: STORED_PER_BYTE размеров файла и STORED_PER_FINDING
# на каждую находку (у находки есть постоянная часть – названия полей), маленькому файлу – не меньше
# MIN_STORED_BYTES, всего – не больше MAX_STORED_BYTES.
STORED_PER_BYTE = 8
STORED_PER_FINDING = 4096
MIN_STORED_BYTES = 8 * 1024 * 1024
MAX_STORED_BYTES = 256 * 1024 * 1024
MAX_GRID_CELLS = 10_000_000             # ячеек в развёрнутых строках листа (вместе с пустыми до последней)
# Разметка листа до разбора (_scan_sheet): ячеек в одной строке (столько колонок в Excel), элементов разметки
# в строке вместе с вложенными (текст с оформлением – это элементы внутри ячейки), ячеек во всей книге вместе
# с пустыми и дальними, элементов вне строк таблицы на листе.
MAX_ROW_CELLS = 16_384
MAX_ROW_ELEMENTS = 200_000
MAX_BOOK_CELLS = 20_000_000
MAX_OUTSIDE_ELEMENTS = 1_000_000
MAX_SHARED_STRINGS = 2_000_000          # элементов si в общих строках, которые разбирает сверка ссылок HYPERLINK (t="s")
MAX_SHARED_LOOKUPS = 1_000_000          # обращений к общим строкам из ячеек с формулами HYPERLINK за книгу
MAX_FORMULA_AREAS = 10_000              # участков с формулами на листе: больше – отказ, где они, уже не сказать
MAX_CSV_RECORD_DELIMITERS = 1_000_000   # разделителей в одной записи CSV: строка не разворачивается в миллионы полей
MAX_HEADER_CHARS = 200                  # название колонки длиннее обрезается
MAX_FIELD_CHARS = 1000                  # правило, путь файла, компонент и другие поля находки
MAX_SNIPPET_CHARS = 4000                # строка кода; обрезается без пометки: сверка с файлом идёт по началу строки
MAX_EXTRA_COLUMNS = 50                  # прочих колонок у находки – не больше
MAX_EXTRA_VALUE = 4000                  # знаков в значении прочей колонки
MAX_EXTRA_BYTES = 64 * 1024             # байт UTF-8 во всех прочих колонках находки вместе с названиями
CELL_CUT_MARK = " …[обрезано]"
SHOW = 10  # сколько мест перечислять в предупреждении

HUB_SUMMARY = "Summary Report"
HUB_PRACTICES = ("SAST", "SCA Security", "SCA Compliance", "DAST")
HUB_KIND = {"SAST": "SAST", "SCA Security": "SCA", "SCA Compliance": "SCA-license", "DAST": "DAST"}
DASHES = ("-", chr(0x2013), chr(0x2014))  # пустое значение в отчёте Hub: дефис, короткое или длинное тире
SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")

# Карта колонок листов отчёта Hub: поле находки -> варианты названия колонки (без учёта регистра и пробелов).
_HUB_COMMON = {"hub_id": ["Issue id"], "application": ["Application"], "status": ["Status"], "tool": ["Found By"]}
HUB_COLUMNS = {
    "SAST": {**_HUB_COMMON, "severity": ["Severity"], "rule": ["Category"], "file": ["File"],
             "line": ["Line number"], "snippet": ["Source code"], "build_type": ["Type"], "cwe": ["CWE ID"],
             "cwe_links": ["CWE link"], "codebase": ["Codebase"], "language": ["Language"]},
    "SCA Security": {**_HUB_COMMON, "policy_severity": ["Severity"], "cvss": ["CVSS score"], "rule": ["Category"],
                     "component": ["Component name"], "version": ["Component version"], "cve": ["CVE id"],
                     "build_type": ["Type"], "fixed_version": ["Non-vulnerable versions"], "dep_path": ["Path"],
                     "cwe": ["CWE ID"], "cwe_links": ["CWE link"], "codebase": ["Codebase"]},
    "SCA Compliance": {**_HUB_COMMON, "policy_severity": ["Severity"], "rule": ["Category"],
                       "component": ["Component name"], "version": ["Component version"], "licenses": ["Licenses"],
                       "build_type": ["Type"], "fixed_version": ["Non-vulnerable versions"], "dep_path": ["Path"],
                       "codebase": ["Codebase"]},
    "DAST": {**_HUB_COMMON, "severity": ["Severity"], "rule": ["Category"], "location": ["Location"],
             "cwe": ["CWE ID"], "cwe_links": ["CWE link"]},
}

# Карта колонок таблицы: английские названия, как в Hub, и русские.
TABLE_COLUMNS = {
    "hub_id": ["Issue id", "ID", "ID находки", "Идентификатор", "Идентификатор находки"],
    "kind": ["Practice", "Практика", "Вид находки", "Тип находки", "Вид"],
    "tool": ["Found By", "Tool", "Scanner", "Инструмент", "Сканер"],
    "application": ["Application", "Приложение", "Система"],
    "severity": ["Severity", "Критичность", "Уровень критичности", "Важность"],
    "cvss": ["CVSS score", "CVSS", "Оценка CVSS"],
    "rule": ["Category", "Rule", "Правило", "Категория", "Тип уязвимости", "Уязвимость"],
    "cwe": ["CWE ID", "CWE"],
    "cwe_links": ["CWE link", "Ссылка CWE"],
    "codebase": ["Codebase", "Кодовая база", "Repository", "Репозиторий"],
    "file": ["File", "Файл", "File path", "Путь к файлу"],
    "line": ["Line number", "Line", "Строка", "Номер строки"],
    "snippet": ["Source code", "Code", "Код", "Фрагмент кода"],
    "status": ["Status", "Статус"],
    "language": ["Language", "Язык"],
    "build_type": ["Type", "Тип сборки"],
    "component": ["Component name", "Component", "Компонент", "Библиотека", "Package", "Пакет"],
    "version": ["Component version", "Version", "Версия", "Версия компонента"],
    "fixed_version": ["Non-vulnerable versions", "Fixed version", "Безопасная версия", "Исправлено в версии"],
    "dep_path": ["Dependency path", "Путь зависимости"],
    "cve": ["CVE id", "CVE"],
    "licenses": ["Licenses", "License", "Лицензии", "Лицензия"],
    "location": ["Location", "URL", "Адрес"],
}


MAX_FORMULA_CHARS = 4096                # текст принимаемой формулы HYPERLINK; длиннее – обычная формула, отказ
MAX_LINK_CHARS = 2048                   # адрес в первом аргументе HYPERLINK (хранится только для проверки, не сохраняется)
MAX_SAFE_VALUE_CHARS = 4096             # видимый текст ссылки (он же значение ячейки): в Hub это номер или название
# Пределы разметки листа, проверяются при просмотре до чтения листа openpyxl (отдельно от предела распознавания
# HYPERLINK): формула в Excel не длиннее 8192 знаков; текстовый узел – в 8 раз больше предела ячейки; весь текст строки.
MAX_XML_FORMULA_CHARS = 8192
MAX_XML_TEXT_NODE = 8 * 32_767
MAX_XML_ROW_TEXT = 4_000_000
# Знаки, которых не бывает в адресе и в видимом тексте ссылки: Cc (C0 \x00–\x1f, \x7f и C1 \x80–\x9f),
# Zl (U+2028) и Zp (U+2029) – остальные пробелы в тексте допустимы, а в адресе их отсекает \s.
_BAD_CHARS = "\x00-\x1f\x7f-\x9f\u2028\u2029"
_LINK_URL = re.compile(r"https?://[^\s" + _BAD_CHARS + r'"]+')
_LINK_TEXT_BAD = re.compile(f"[{_BAD_CHARS}]")  # видимый текст – одна строка без управляющих знаков


def hyperlink_text(formula: str) -> str | None:
    """Формула целиком из одного вызова HYPERLINK("адрес";"текст") с двумя строковыми литералами -> видимый текст,
    иначе None. Ничего не вычисляется: текст разбирается по месту. Принимается только запятая между аргументами
    (в OOXML она единственная) и литералы без кавычек внутри: ни вложенных функций, ни ссылок на ячейки, ни
    склейки, ни третьего аргумента; адрес – http или https без пробелов и управляющих символов; текст – одна строка,
    не пустая и после снятия любых пробелов (пустое значение ячейки сбило бы находку)."""
    text = formula.strip(" \t")
    if text.startswith("="):
        text = text[1:]
    if not text or len(text) > MAX_FORMULA_CHARS:
        return None
    match = _HYPERLINK.fullmatch(text)
    if match is None:
        return None
    url, shown = match.group(1), match.group(2)
    if len(url) > MAX_LINK_CHARS or not _LINK_URL.fullmatch(url):
        return None
    # непустота текста – по Unicode (strip() убирает и неразрывный пробел): пустое значение ячейки сбило бы находку
    if not shown.strip() or len(shown) > MAX_SAFE_VALUE_CHARS or _LINK_TEXT_BAD.search(shown):
        return None
    return shown


# Имя функции – только ASCII-буквы (без Unicode-двойников вроде ı и K), между токенами – пробел или табуляция ASCII.
_HYPERLINK = re.compile(r'(?ai:HYPERLINK)\([ \t]*"([^"]*)"[ \t]*,[ \t]*"([^"]*)"[ \t]*\)')


class ImportFailure(Exception):
    """Выгрузку не прочитать. Сообщение – по-русски и говорит, что поправить."""


_AMPLIFIED = ("так выгрузка AppSec.Hub не выглядит: похоже, одни и те же длинные значения размножены по ячейкам. "
              "Выгрузите отчёт из Hub заново.")


class _TextBudget:
    """Сколько знаков текста ячеек ещё можно прочитать из выгрузки."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def spend(self, chars: int) -> None:
        self.used += chars
        if self.used > self.limit:
            raise ImportFailure(f"В ячейках выгрузки больше {self.limit / 1_000_000:g} млн знаков текста – "
                                + _AMPLIFIED)


class _StoredBudget:
    """Сколько байт находок можно сохранить: base + per_finding на каждую находку, не больше cap."""

    def __init__(self, base: int, per_finding: int, cap: int) -> None:
        self.base, self.per_finding, self.cap = base, per_finding, cap
        self.used = 0
        self.count = 0

    def spend(self, size: int) -> None:
        self.used += size
        self.count += 1
        limit = min(self.cap, self.base + self.per_finding * self.count)
        if self.used > limit:
            raise ImportFailure(f"Находки выгрузки занимают больше {limit // (1024 * 1024)} МБ – " + _AMPLIFIED)


class _Formulas:
    """Где на листе формулы: участки [первая колонка, последняя, первая строка, последняя]. Ячейки с формулами
    одной колонки подряд сливаются в один участок (колонка, заполненная формулой вниз, – один участок). Участков
    не больше MAX_FORMULA_AREAS; сверх этого – overflow: где формулы, уже не сказать."""

    def __init__(self) -> None:
        self.areas: list[list[int]] = []
        self.overflow = False
        # принятые формулы HYPERLINK (участки тем же способом): допустимы только в колонках номера находки, системы
        # и идентификатора уязвимости – это решает _check_formulas, когда известна карта колонок
        self.link_cells: _Formulas | None = None
        self._run: dict[int, int] = {}  # колонка -> её последний участок, который можно продлить вниз

    def __bool__(self) -> bool:
        return bool(self.areas) or self.overflow

    def add_link(self, column: int, row: int) -> None:
        if self.link_cells is None:
            self.link_cells = _Formulas()
        self.link_cells.add(column, row)
        if self.link_cells.overflow:
            self.overflow = True

    def add(self, column: int, row: int) -> None:
        if column > MAX_COLUMNS:  # дальние колонки не читаются
            return
        i = self._run.get(column)
        if i is not None:
            area = self.areas[i]
            if area[2] <= row <= area[3]:
                return
            if row == area[3] + 1:
                area[3] = row
                return
        if self._append([column, column, row, row]):
            self._run[column] = len(self.areas) - 1

    def add_area(self, first_col: int, last_col: int, first_row: int, last_row: int) -> None:
        """Диапазон формулы массива или общей формулы (атрибут ref): её значения стоят и в ячейках без <f>."""
        last_col = min(last_col, MAX_COLUMNS)
        if first_col <= last_col and first_row <= last_row:
            self._append([first_col, last_col, first_row, last_row])

    def _append(self, area: list[int]) -> bool:
        if len(self.areas) >= MAX_FORMULA_AREAS:
            self.overflow = True
            return False
        self.areas.append(area)
        return True

    def rows_in(self, column: int, from_row: int) -> list[tuple[int, int]]:
        """Участки строк с формулами в колонке, не выше строки from_row: [(первая, последняя)], пересекающиеся
        и соседние – слиты."""
        merged: list[tuple[int, int]] = []
        for first, last in sorted((max(a[2], from_row), a[3]) for a in self.areas
                                  if a[0] <= column <= a[1] and a[3] >= from_row):
            if merged and first <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], last))
            else:
                merged.append((first, last))
        return merged


class _BookScan:
    """Просмотр разметки листов одной книги: формулы по листам и ячейки всей книги. Общий для пробы листа
    и настоящего разбора: каждый лист просматривается один раз."""

    def __init__(self) -> None:
        self.sheets: dict[str, _Formulas] = {}
        self.cells = 0
        self.shared: list[str | None] | None = None  # простые общие строки (_read_shared_strings); None – не прочитаны
        self.shared_read = False
        self.shared_lookups = 0

    def spend_lookup(self) -> None:
        self.shared_lookups += 1
        if self.shared_lookups > MAX_SHARED_LOOKUPS:
            raise ImportFailure(f"Ссылок на общие строки в формулах больше {MAX_SHARED_LOOKUPS // 1000} тыс. – так выгрузка "
                                "AppSec.Hub не выглядит. Проверьте файл.")

    def spend_cell(self) -> None:
        self.cells += 1
        if self.cells > MAX_BOOK_CELLS:
            raise ImportFailure(f"В книге больше {MAX_BOOK_CELLS // 1_000_000} млн ячеек – так выгрузка AppSec.Hub "
                                "не выглядит. Проверьте файл.")


class _Limits:
    """Бюджеты одной выгрузки по её размеру (распакованная книга или CSV): текст ячеек, развёрнутые ячейки строк
    и сохраняемые находки; book – просмотр разметки листов (общий для пробы листа и разбора)."""

    def __init__(self, size: int, book: _BookScan | None = None) -> None:
        size = max(0, size)
        self.size = size
        self.cells = _TextBudget(min(MAX_TEXT_CHARS, max(MIN_TEXT_CHARS, TEXT_PER_BYTE * size)))
        self.stored = _StoredBudget(max(MIN_STORED_BYTES, STORED_PER_BYTE * size), STORED_PER_FINDING,
                                    MAX_STORED_BYTES)
        self.grid_cells = 0
        self.book = book if book is not None else _BookScan()

    def spend_grid(self, width: int) -> None:
        """Строка листа разворачивается в список до последней заполненной ячейки: ячейка в колонке 500 у каждой
        из 200 000 строк – это 100 млн элементов списков."""
        self.grid_cells += width
        if self.grid_cells > MAX_GRID_CELLS:
            raise ImportFailure(f"В выгрузке больше {MAX_GRID_CELLS // 1_000_000} млн ячеек – так выгрузка AppSec.Hub "
                                "не выглядит. Проверьте файл.")


# ============================================================================ разбор значений

_SEVERITY_PREFIXES = (
    ("critical", ("crit", "крит", "blocker", "блокир")),
    ("high", ("high", "выс")),
    ("medium", ("med", "moder", "сред", "умерен")),
    ("low", ("low", "низ")),
    ("info", ("info", "инфо", "note", "none", "potential", "потенц", "незнач")),
)


def norm_severity(value: str) -> str:
    """Критичность RU/EN -> critical|high|medium|low|info или "" (не распознана)."""
    s = str(value or "").strip().casefold().replace("ё", "е").strip(" .:")
    for level, prefixes in _SEVERITY_PREFIXES:
        if s.startswith(prefixes):
            return level
    return ""


_CWE_ANY = re.compile(r"cwe\D{0,3}?(\d{1,5})", re.I)
_CWE_NUMBERS = re.compile(r"\s*\d{1,5}(?:\.0+)?(?:\s*[,;/\s]\s*\d{1,5}(?:\.0+)?)*\s*")
_CWE_LINK = re.compile(r"/definitions/(\d{1,5})\.html?\b", re.I)


def parse_cwes(value: str) -> list[str]:
    """Все CWE из ячейки -> ["CWE-1333", "CWE-400"] по порядку, без повторов.

    Понимает «1333, 400» (список номеров, как в выгрузке Hub), «CWE-79; CWE-80», «89», «89.0». Голые числа берутся,
    только если в ячейке нет ничего, кроме номеров и разделителей: в «CWE-89 (OWASP A03:2021)» 2021 – не CWE.
    """
    s = str(value or "").strip()
    if not s:
        return []
    if "cwe" in s.casefold():
        numbers = [m.group(1) for m in _CWE_ANY.finditer(s)]
    elif _CWE_NUMBERS.fullmatch(s):
        numbers = re.findall(r"\d+", re.sub(r"\.0+(?!\d)", "", s))
    else:
        numbers = []
    result = []
    for n in numbers:
        cwe = f"CWE-{int(n)}"
        if cwe not in result:
            result.append(cwe)
    return result


_DASH_CHARS = "-" + "".join(chr(c) for c in (0x2010, 0x2011, 0x2013, 0x2014))  # дефис и его типографские двойники
_CVE_RE = re.compile("CVE[" + _DASH_CHARS + r"](\d{4})[" + _DASH_CHARS + r"](\d{4,})", re.I)
# Идентификатор уязвимости, кроме CVE: AST-2026-000123 (AppSec.Track), GHSA-xxxx-xxxx-xxxx, BDU:2026-01234.
_VULN_ID = re.compile(r"(?<![\w-])([A-Za-z]{2,10}(?:[-:][A-Za-z0-9]+){1,4})(?![\w-])")


def parse_cves(value: str) -> list[str]:
    """Все CVE-ГГГГ-NNNN из текста – по порядку, без повторов, в верхнем регистре."""
    result = []
    for m in _CVE_RE.finditer(str(value or "")):
        cve = f"CVE-{m.group(1)}-{m.group(2)}"
        if cve not in result:
            result.append(cve)
    return result


_GHSA = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}", re.I)  # бывает и без цифр: GHSA-cfgh-jmpq-rvwx


def parse_vuln_ids(value: str) -> list[str]:
    """Идентификаторы уязвимостей из ячейки, кроме CVE и CWE: AST-…, GHSA-…, BDU:… (в идентификаторе есть цифра;
    GHSA – по своему формату)."""
    result = []
    for m in _VULN_ID.finditer(str(value or "")):
        token = m.group(1)
        if _CVE_RE.fullmatch(token) or token.casefold().startswith("cwe"):
            continue
        if not re.search(r"\d", token) and not _GHSA.fullmatch(token):
            continue
        if token not in result:
            result.append(token)
    return result


_URL_TOKEN = re.compile(r"https?://[^\s,;<>\"']+", re.I)


def parse_urls(text: str) -> list[str]:
    """Адреса из ячейки (несколько – через запятую или перевод строки) -> список без повторов."""
    result = []
    for url in _URL_TOKEN.findall(str(text or "")):
        url = url.rstrip(".,;)")
        if url not in result:
            result.append(url)
    return result


# Разделитель тысяч в «1 234»: пробел, неразрывный или узкий неразрывный пробел.
_THOUSANDS = re.compile(r"(?<=\d)[ " + chr(0xA0) + chr(0x202F) + r"](?=\d{3}(?!\d))")


def parse_float(value) -> float | None:
    """Число из ячейки: «7,5», «7.5», «9.8 (Critical)», «1 234» -> float; пусто или не число -> None."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return None if isinstance(value, float) and (math.isnan(value) or math.isinf(value)) else float(value)
    s = _THOUSANDS.sub("", str(value))
    m = re.fullmatch(r"\s*(-?\d+(?:[.,]\d+)?)(?:\s+(?!\d).*)?\s*", s, flags=re.S)
    return float(m.group(1).replace(",", ".")) if m else None


MAX_LINE_NUMBER = 100_000_000  # номер строки больше – не номер строки


_LINE_NUMBER = re.compile(r"\s*(\d{1,9})(?:[.,]0+)?\s*(?:[:\-" + chr(0x2013) + r"]\s*\d{1,9}\s*)?")


def parse_line(text: str) -> int | None:
    """Номер строки: «57», «57.0», «57:12» (строка:столбец), «57-60» (диапазон – первая) -> 57; иначе None.
    Номер длиннее 9 цифр (в том числе с ведущими нулями) – не номер строки."""
    m = _LINE_NUMBER.fullmatch(str(text or ""))
    n = int(m.group(1)) if m else None
    return n if n is not None and 1 <= n <= MAX_LINE_NUMBER else None


_CODE_TAIL = re.compile(r"(?:^|\s+):\s+(\d{1,9})\s*$")  # «код : 163» – Hub дописывает номер строки к коду


def split_code_tail(text: str) -> tuple[str, int | None]:
    """Строка кода из выгрузки Hub: «код : 163» -> ("код", 163); без хвоста – (код, None)."""
    s = str(text or "").strip()
    m = _CODE_TAIL.search(s)
    if not m:
        return s, None
    return s[:m.start()].strip(), int(m.group(1))


def norm_path(value: str) -> str:
    """Путь файла: прямые слэши, без «./», ведущего «/», двойных слэшей. «..» не раскрывается."""
    s = str(value or "").strip().replace("\\", "/")
    return "/".join(part for part in s.split("/") if part not in ("", "."))


_FILE_LINE_RE = re.compile(r"(.+?):(\d{1,9})(?::\d{1,9})?")  # «src/A.java:57» или «src/A.java:57:12» в колонке файла
_DATE_CELL = re.compile(r"\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}:\d{2})?")  # ячейка, которую Excel превратил в дату


def _norm_name(s: str) -> str:
    """Название колонки или листа для сравнения: без регистра, без пробелов, ё = е."""
    return "".join(str(s).split()).casefold().replace("ё", "е")


# ============================================================================ чтение файла

def _clip(text: str, limit: int = MAX_CELL_CHARS) -> str:
    return text if len(text) <= limit else text[:limit - len(CELL_CUT_MARK)] + CELL_CUT_MARK


def _cell_text(value) -> str:
    """Значение ячейки XLSX -> строка так же, как его дал бы CSV."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return ""
        return str(int(value)) if value.is_integer() else repr(value)
    if isinstance(value, dt.datetime):
        return value.strftime("%Y-%m-%d") if value.time() == dt.time(0) else value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, (dt.date, dt.time)):
        return value.isoformat()
    return _clip(str(value).strip())


class _PackageConflict(Exception):
    """Назначение частей пакета неоднозначно или противоречиво: такой пакет не классифицируется, все его части идут
    в бюджет служебных (запас в сторону отказа)."""


# Части, которые openpyxl читает по постоянным именам, а не по оглавлению и отношениям (reader/excel.py,
# styles/stylesheet.py, xml/constants.py): такая часть никогда не лист, что бы про неё ни говорили оглавление и отношения.
_FIXED_SERVICE_PARTS = frozenset((
    "[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/styles.xml",
    "xl/theme/theme1.xml", "xl/sharedStrings.xml", "xl/calcChain.xml", "docProps/core.xml", "docProps/app.xml",
    "docProps/custom.xml", "customUI/customUI.xml", "xl/vbaProject.bin",
))
_NS_TYPES = "http://schemas.openxmlformats.org/package/2006/content-types"
_NS_RELS = "http://schemas.openxmlformats.org/package/2006/relationships"
_NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS_DOC_RELS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_OFFICE_DOCUMENT_REL = _NS_DOC_RELS + "/officeDocument"


def _qname(ns: str, local: str) -> str:
    return f"{ns} {local}"


def _package_items(z, name: str, paths: dict[str, tuple[str, ...]]) -> dict[str, list[dict]]:
    """Элементы небольшой служебной части пакета (оглавление, список отношений, список листов книги) с проверкой
    структуры: корень и пространство имён должны быть ожидаемыми, а собираются только элементы, чей путь от корня
    совпадает с одним из paths ({ключ: (корень, ..., элемент)}, имена – «пространство имён + пробел + имя»).
    Элементы с тем же именем в другом месте (вложенные, в чужом пространстве имён, в расширениях) пропускаются.
    Возвращает {ключ: [атрибуты каждого элемента]}.

    Читается не больше MAX_PACKAGE_XML_BYTES байт (больше – отказ импорта); объявления DTD и сущностей – отказ.
    Части нет, она испорчена или корень не тот – _PackageConflict."""
    import xml.parsers.expat

    try:
        with z.open(name) as src:
            data = src.read(MAX_PACKAGE_XML_BYTES + 1)
    except (KeyError, OSError, zipfile.BadZipFile):
        raise _PackageConflict(name) from None
    if len(data) > MAX_PACKAGE_XML_BYTES:
        raise ImportFailure(f"Служебная часть книги «{name}» больше {MAX_PACKAGE_XML_BYTES // (1024 * 1024)} МБ – "
                            "так выгрузка AppSec.Hub не выглядит. Проверьте файл.")
    roots = {path[0] for path in paths.values()}
    found: dict[str, list[dict]] = {key: [] for key in paths}
    stack: list[str] = []
    count = [0]

    def local(tag: str) -> str:
        return tag.rsplit(" ", 1)[-1]

    def start(tag: str, attrs: dict) -> None:
        count[0] += 1
        if count[0] > 4 * MAX_ZIP_ENTRIES:
            raise ImportFailure(f"В служебной части книги «{name}» слишком много записей – так выгрузка AppSec.Hub "
                                "не выглядит. Проверьте файл.")
        stack.append(tag)
        if len(stack) == 1 and tag not in roots:
            raise _PackageConflict(name)
        for key, path in paths.items():
            if tuple(stack) == path:
                found[key].append(dict(attrs))
            elif len(stack) == len(path) and [local(x) for x in stack] == [local(x) for x in path]:
                # openpyxl читает такие части без учёта пространства имён: элемент с тем же именем на том же месте,
                # но в чужом пространстве, он принял бы за настоящий. Назначение частей неоднозначно.
                raise _PackageConflict(name)

    def end(tag: str) -> None:
        stack.pop()

    def refuse_dtd(*args) -> None:
        raise ImportFailure(f"Служебная часть книги «{name}» повреждена. Откройте книгу в Excel и сохраните заново "
                            "как .xlsx.")

    parser = xml.parsers.expat.ParserCreate(namespace_separator=" ")
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = refuse_dtd
    parser.EntityDeclHandler = refuse_dtd
    try:
        parser.Parse(data, True)
    except (ImportFailure, _PackageConflict):
        raise
    except Exception:
        raise _PackageConflict(name) from None
    return found


def _part_name(value: str, base: str = "") -> str:
    """Имя части пакета как в архиве по адресу из отношения или оглавления: «/xl/a.xml» – от корня пакета, «a.xml» –
    от папки base. Обратная косая черта, выход выше корня, пустое и неканонические имена – _PackageConflict."""
    if not value or "\\" in value or "\x00" in value:
        raise _PackageConflict(value)
    name = posixpath.normpath(value[1:] if value.startswith("/") else posixpath.join(base, value))
    if name in ("", ".") or name.startswith("../") or name == ".." or name.startswith("/"):
        raise _PackageConflict(value)
    return name


def _canonical_part(value: str) -> str:
    """PartName из оглавления: уже каноническое имя вида «/xl/a.xml», совпадающее с его нормализацией."""
    name = _part_name(value)
    if not value.startswith("/") or value != "/" + name:
        raise _PackageConflict(value)
    return name


def _sheet_parts(z, names: set[str]) -> set[str]:
    """Части листов книги, проверенные по структуре пакета; всё остальное – служебные части, где бы оно ни лежало.

    Лист признаётся, только если одновременно: книга найдена корневым отношением officeDocument (одним), её
    оглавление объявляет её книгой; на часть указывает отношение worksheet от книги, и это отношение выбрано
    элементом `sheet` самой книги (r:id); часть объявлена листом в оглавлении; ни у этой части, ни у её отношения нет
    другой роли. Любое противоречие – повтор Override или Default, пустой или неканоническое имя, повтор Id отношения,
    корень не тот, лист указан дважды, у одной части две роли – делает назначение неопределённым: _PackageConflict и
    пустой результат (в бюджет служебных идёт весь пакет)."""
    try:
        return _classify_sheets(z, names)
    except _PackageConflict:
        return set()


def _classify_sheets(z, names: set[str]) -> set[str]:
    types = _package_items(z, _CONTENT_TYPES_PART, {
        "Default": (_qname(_NS_TYPES, "Types"), _qname(_NS_TYPES, "Default")),
        "Override": (_qname(_NS_TYPES, "Types"), _qname(_NS_TYPES, "Override"))})
    overrides: dict[str, str] = {}
    for attrs in types["Override"]:
        part = _canonical_part(attrs.get("PartName", ""))
        content = attrs.get("ContentType", "")
        if not content or part in overrides:
            raise _PackageConflict(part)
        overrides[part] = content
    if len({p.casefold() for p in overrides}) != len(overrides):
        raise _PackageConflict("PartName")
    defaults: dict[str, str] = {}
    for attrs in types["Default"]:
        ext, content = attrs.get("Extension", "").casefold(), attrs.get("ContentType", "")
        if not ext or not content or ext in defaults:
            raise _PackageConflict(ext)
        defaults[ext] = content

    def content_type(part: str) -> str:
        if part in overrides:
            return overrides[part]
        return defaults.get(part.rsplit(".", 1)[-1].casefold(), "") if "." in part.rsplit("/", 1)[-1] else ""

    def single(part: str) -> str:
        if part not in names:
            raise _PackageConflict(part)
        return part

    # книга – одно корневое отношение officeDocument
    root = _package_items(z, "_rels/.rels", {"Relationship": (_qname(_NS_RELS, "Relationships"),
                                                              _qname(_NS_RELS, "Relationship"))})["Relationship"]
    root_roles: dict[str, set[str]] = {}
    for rel in root:
        if rel.get("TargetMode", "Internal") == "Internal" and rel.get("Target"):
            root_roles.setdefault(_part_name(rel["Target"]), set()).add(rel.get("Type", ""))
    documents = [r for r in root if r.get("Type") == _OFFICE_DOCUMENT_REL]
    if len(documents) != 1 or documents[0].get("TargetMode", "Internal") != "Internal":
        raise _PackageConflict("officeDocument")
    workbook = single(_part_name(documents[0].get("Target", "")))
    if content_type(workbook) not in _WORKBOOK_TYPES:
        raise _PackageConflict(workbook)
    folder = posixpath.dirname(workbook)

    # отношения книги: уникальные Id, роль каждой части
    rel_path = posixpath.join(folder, "_rels", posixpath.basename(workbook) + ".rels")
    rels = _package_items(z, rel_path, {"Relationship": (_qname(_NS_RELS, "Relationships"),
                                                         _qname(_NS_RELS, "Relationship"))})["Relationship"]
    by_id: dict[str, dict] = {}
    roles: dict[str, set[str]] = {}
    for rel in rels:
        ident = rel.get("Id", "")
        if not ident or ident in by_id:
            raise _PackageConflict(ident)
        by_id[ident] = rel
        if rel.get("TargetMode", "Internal") == "Internal" and rel.get("Target"):
            roles.setdefault(_part_name(rel["Target"], folder), set()).add(rel.get("Type", ""))
    # листы самой книги: <sheet r:id="…">
    listed = _package_items(z, workbook, {"sheet": (_qname(_NS_MAIN, "workbook"), _qname(_NS_MAIN, "sheets"),
                                                   _qname(_NS_MAIN, "sheet"))})["sheet"]
    sheets: set[str] = set()
    for item in listed:
        rel = by_id.get(item.get(_qname(_NS_DOC_RELS, "id"), ""))
        if rel is None or rel.get("Type") != _WORKSHEET_REL or rel.get("TargetMode", "Internal") != "Internal":
            continue  # лист-диаграмма, макрос и т. п.: не лист данных, остаётся служебной частью
        part = single(_part_name(rel.get("Target", ""), folder))
        if part in sheets or part == workbook or content_type(part) != _WORKSHEET_TYPE or roles.get(part) != {
                _WORKSHEET_REL} or part in root_roles:
            raise _PackageConflict(part)
        if part in _FIXED_SERVICE_PARTS or part.endswith(".rels") or part.startswith(("docProps/", "customUI/")):
            raise _PackageConflict(part)  # служебное имя: загрузчик прочтёт часть сам, льгот листа у неё нет
        sheets.add(part)
    return sheets


def _check_archive(p: Path) -> int:
    """XLSX – это zip: до openpyxl проверяем распакованный размер, чтобы подложенный файл не съел память.
    Отдельно – объём служебных частей (всё, кроме проверенных частей листов): их openpyxl читает целиком при открытии
    книги. Размеры берутся из оглавления архива. Возвращает распакованный размер книги, байты."""
    try:
        with zipfile.ZipFile(p) as z:
            infos = z.infolist()
    except (zipfile.BadZipFile, OSError):
        raise ImportFailure("Файл повреждён или это не книга Excel (.xlsx). Выгрузите отчёт из AppSec.Hub заново.") \
            from None
    if len(infos) > MAX_ZIP_ENTRIES:
        raise ImportFailure("В книге слишком много частей – так выгрузка AppSec.Hub не выглядит. Проверьте файл.")
    unpacked = sum(info.file_size for info in infos)
    packed = max(1, p.stat().st_size)
    if unpacked > MAX_UNZIPPED_BYTES or (unpacked > 50 * 1024 * 1024 and unpacked / packed > MAX_ZIP_RATIO):
        raise ImportFailure(f'Распакованная книга – {unpacked // (1024 * 1024)} МБ: превышен предел объёма или сжатия.')
    # До чтения связей книги и до openpyxl: запрещены DTD во всех XML-частях,
    # включая стили, свойства и общие строки. Expat читает BOM/encoding и вызывает
    # обработчик объявления до раскрытия даже одной внутренней сущности.
    malformed_xml = False
    with zipfile.ZipFile(p) as archive:
        for info in infos:
            if not info.filename.lower().endswith(('.xml', '.rels')):
                continue
            parser = expat.ParserCreate()
            def reject_dtd(*args):
                raise ImportFailure('Книга повреждена: повреждён XML, DTD и сущности в Excel не допускаются.')
            parser.StartDoctypeDeclHandler = reject_dtd
            parser.EntityDeclHandler = reject_dtd
            parser.ExternalEntityRefHandler = reject_dtd
            read = 0
            try:
                with archive.open(info) as stream:
                    while chunk := stream.read(64 * 1024):
                        read += len(chunk)
                        if read > MAX_UNZIPPED_BYTES:
                            raise ImportFailure('XML-часть книги превышает допустимый размер.')
                        parser.Parse(chunk, False)
                    parser.Parse(b'', True)
            except (expat.ExpatError, zipfile.BadZipFile, OSError):
                malformed_xml = True
    counted = Counter(info.filename for info in infos)
    with zipfile.ZipFile(p) as z:
        # повторяющиеся имена частей – книга испорчена: такая часть считается служебной
        sheets = {n for n in _sheet_parts(z, set(counted)) if counted[n] == 1}
    meta = sum(info.file_size for info in infos if info.filename not in sheets)
    if meta > MAX_META_BYTES:
        raise ImportFailure(f"Служебные части книги (общие строки, стили) – {meta // (1024 * 1024)} МБ. Так выгрузка "
                            "AppSec.Hub не выглядит: файл не читается.")
    if malformed_xml:
        raise ImportFailure('Книга повреждена: повреждён XML-формат части Excel.')
    packed = max(1, p.stat().st_size)
    if unpacked > MAX_UNZIPPED_BYTES or (unpacked > 50 * 1024 * 1024 and unpacked / packed > MAX_ZIP_RATIO):
        raise ImportFailure(f"Распакованная книга – {unpacked // (1024 * 1024)} МБ (в {unpacked // packed} раз больше "
                            "файла). Так выгрузка AppSec.Hub не выглядит: файл не читается.")
    return unpacked


def _sheet_source(ws):
    """Разборщик разметки листа openpyxl, открытие разметки и параметры разборщика (режим read_only) ->
    (класс разборщика, функция открытия разметки, общие строки, параметры). Разметка листа просматривается
    (_scan_sheet) и читается (_physical_rows) одним и тем же способом, которым её читает openpyxl, поэтому другая
    версия openpyxl без этих внутренних частей – отказ, а не разбор без проверок."""
    try:
        from openpyxl.worksheet._reader import WorkSheetParser
        wb = ws.parent
        options = {"data_only": wb.data_only, "epoch": wb.epoch, "date_formats": wb._date_formats,
                   "timedelta_formats": wb._timedelta_formats}
        return WorkSheetParser, ws._get_source, ws._shared_strings, options
    except (ImportError, AttributeError):
        raise ImportFailure("Эта версия openpyxl не поддерживается: книги Excel читаются с версией из "
                            "requirements.txt.") from None


_SHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_ROW_TAG = _SHEET_NS + " row"  # имена элементов так, как их отдаёт expat с namespace_separator=" "
_FORMULA_TAG = _SHEET_NS + " f"
_VALUE_TAG = _SHEET_NS + " v"
_PLAIN_FORMULA_ATTRS = {"aca", "ca"}  # атрибуты обычной формулы; общая формула и формула массива (t, ref, si) – нет


def _row_number(text: str) -> int:
    """Номер строки из атрибута r элемента row так же, как его понимает openpyxl: «5» или «5.0»."""
    try:
        return int(text)
    except ValueError:
        value = float(text)
        if not value.is_integer():
            raise
        return int(value)


_SHARED_STRINGS_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"
_SHARED_INDEX = re.compile(r"0|[1-9][0-9]{0,8}")  # индекс общей строки в <v>: десятичное число без знака и пробелов


def _read_shared_strings(ws) -> list[str | None] | None:
    """Общие строки книги, пригодные для сверки значения формулы HYPERLINK с t="s": список по индексам, где элемент – текст
    общей строки, если она простая (<si> с единственным дочерним <t>, без вложенных элементов: ни rich text <r>, ни
    фонетики <rPh> и <phoneticPr>) и не длиннее MAX_SAFE_VALUE_CHARS, иначе None. Часть берётся так, как её находит
    openpyxl (единственное объявление типа sharedStrings в оглавлении), читается потоком; число элементов и объём ограничены.
    Количество элементов должно совпасть с таблицей, которую получит потребитель (ws._shared_strings): иначе None –
    сверка не принимается, формула остаётся обычной. Ошибка чтения тоже None (отказ, а не разбор без проверки)."""
    import xml.parsers.expat

    try:
        consumer = ws._shared_strings
        z = ws.parent._archive
        types = _package_items(z, _CONTENT_TYPES_PART, {
            "Override": (_qname(_NS_TYPES, "Types"), _qname(_NS_TYPES, "Override"))})
        parts = [a for a in types["Override"] if a.get("ContentType") == _SHARED_STRINGS_TYPE]
        if len(parts) != 1:
            return None
        name = _canonical_part(parts[0].get("PartName", ""))
        info = z.getinfo(name)
        if info.file_size > MAX_META_BYTES:
            return None
    except (_PackageConflict, KeyError, AttributeError, OSError, zipfile.BadZipFile):
        return None

    items: list[str | None] = []
    stack: list[str] = []
    cur = {"simple": True, "t": 0, "chars": []}
    size = [0]
    ns_si, ns_t, ns_sst = _qname(_NS_MAIN, "si"), _qname(_NS_MAIN, "t"), _qname(_NS_MAIN, "sst")

    def start(tag: str, attrs: dict) -> None:
        stack.append(tag)
        depth = len(stack)
        if depth == 1:
            if tag != ns_sst:
                raise ValueError("корень")
        elif depth == 2:
            if tag != ns_si:
                raise ValueError("элемент вне si")
            if len(items) >= MAX_SHARED_STRINGS:
                raise ValueError("слишком много общих строк")
            cur.update(simple=True, t=0, chars=[])
            size[0] = 0
        elif depth == 3:
            if tag == ns_t and cur["t"] == 0:
                cur["t"] = 1
            else:
                cur["simple"] = False
        else:
            cur["simple"] = False

    def end(tag: str) -> None:
        depth = len(stack)
        if depth == 3 and tag == ns_t:
            cur["t"] = 2  # текст закончен
        if depth == 2:
            ok = cur["simple"] and cur["t"] == 2 and size[0] <= MAX_SAFE_VALUE_CHARS
            items.append("".join(cur["chars"]) if ok else None)
        stack.pop()

    def chars(data: str) -> None:
        if len(stack) == 3 and stack[-1] == ns_t and cur["t"] == 1:
            size[0] += len(data)
            if size[0] <= MAX_SAFE_VALUE_CHARS:
                cur["chars"].append(data)

    def refuse(*args) -> None:
        raise ValueError("DTD")

    parser = xml.parsers.expat.ParserCreate(namespace_separator=" ")
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    try:
        with z.open(name) as src:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                parser.Parse(chunk, False)
            parser.Parse(b"", True)
    except Exception:  # испорченная разметка, превышение пределов
        return None
    return items if len(items) == len(consumer) else None


def _shared_text(ws, limits: _Limits, index_text: str) -> str | None:
    """Текст простой общей строки по индексу из <v> ячейки t="s" -> ровно то значение, которое получит потребитель
    (таблица openpyxl) и которое записано в разметке; None – индекс не число, вне границ, строка не простая, длиннее предела
    или таблицы нет. Обращения считаются бюджетом (MAX_SHARED_LOOKUPS)."""
    book = limits.book
    if not book.shared_read:
        book.shared = _read_shared_strings(ws)
        book.shared_read = True
    table = book.shared
    if table is None or not _SHARED_INDEX.fullmatch(index_text):
        return None
    book.spend_lookup()
    index = int(index_text)
    if index >= len(table):
        return None
    raw = table[index]
    # потребитель читает таблицу openpyxl, где «x005F_» вырезается: сверяется и она (расхождение – не принимать)
    if raw is None or ws._shared_strings[index] != raw:
        return None
    return raw


def _scan_sheet(ws, sheet_name: str, limits: _Limits) -> _Formulas:
    """Просмотр разметки листа до разбора openpyxl -> где на листе формулы.

    openpyxl собирает строку разметки целиком, со всеми её ячейками и вложенными элементами, и лишь потом отдаёт её;
    элементы вне строк он держит в памяти до конца листа. Поэтому разметка сначала читается потоком (expat, без
    построения дерева), и до разбора считаются: строки листа (MAX_SHEET_ROWS), ячейки в строке (MAX_ROW_CELLS;
    ячейка – любой дочерний элемент строки, как у openpyxl, в том числе пустая и дальняя), элементы разметки
    в строке вместе с вложенными (MAX_ROW_ELEMENTS), ячейки всей книги (MAX_BOOK_CELLS), элементы вне строк
    (MAX_OUTSIDE_ELEMENTS). Строка внутри строки и объявления DTD и сущностей – повреждённый лист: в разметке
    листа их не бывает. Заодно отмечаются ячейки с формулами (элемент f) и диапазоны формул массивов (атрибут ref).
    Номера строк и колонок – как у openpyxl. Итог запоминается в limits.book: лист просматривается один раз."""
    cached = limits.book.sheets.get(sheet_name)
    if cached is not None:
        return cached
    import xml.parsers.expat

    from openpyxl.utils.cell import coordinate_to_tuple, range_boundaries

    source = _sheet_source(ws)[1]
    formulas = _Formulas()
    damaged = (f"Лист «{sheet_name}» повреждён. Откройте книгу в Excel и сохраните заново как .xlsx или выгрузите "
               "отчёт из AppSec.Hub ещё раз.")
    state = {"depth": 0, "row_depth": -1, "cell_depth": -1, "row": 0, "col": 0, "cell_col": 0, "row_cells": 0,
             "row_elements": 0, "rows": 0, "outside": 0}
    # ячейка с формулой: решение принимается в конце ячейки, когда известно и сохранённое значение
    cell = {"type": "", "formula": [], "formula_len": 0, "value": [], "value_len": 0, "formulas": 0, "values": 0,
            "plain": True, "capture": "", "capture_depth": -1, "nested": False, "text_len": 0}
    text = {"node": 0, "row": 0}  # знаков в текущем текстовом узле и во всей строке

    def reset_cell(attrs: dict) -> None:
        cell.update(type=attrs.get("t", ""), formula=[], formula_len=0, value=[], value_len=0, formulas=0, values=0,
                    plain=True, capture="", capture_depth=-1, nested=False, text_len=0)

    def finish_cell() -> None:
        """Формула, целиком состоящая из HYPERLINK с двумя литералами и сохранённым значением, равным видимому
        тексту, – не формула для отказа (см. hyperlink_text); любая другая отмечается."""
        if not cell["formulas"]:
            return
        # ровно один непосредственный f и один v без вложенных элементов: openpyxl берёт текст первого v, проверяется
        # тот же текст, до какой-либо нормализации
        single = cell["plain"] and cell["formulas"] == 1 and cell["values"] == 1 and not cell["nested"]
        shown = hyperlink_text("".join(cell["formula"])) if single else None
        stored_ok = False
        if (shown is not None and cell["formula_len"] <= MAX_FORMULA_CHARS and cell["value_len"] <= MAX_SAFE_VALUE_CHARS):
            stored = "".join(cell["value"])
            if cell["type"] == "str":
                stored_ok = stored == shown
            elif cell["type"] == "s":
                # сохранённое значение – индекс общей строки (так Excel хранит текст формулы в настоящих выгрузках Hub):
                # сверяется её текст, ровно такой, какой получит потребитель, так же строго, как значение t="str"
                stored_ok = _shared_text(ws, limits, stored) == shown
        if stored_ok:
            formulas.add_link(state["cell_col"], state["row"])
        else:
            formulas.add(state["cell_col"], state["row"])

    def chars(data: str) -> None:
        """Жёсткие пределы текста разметки: отказ до того, как лист попадёт к openpyxl. Длина формулы и всего текста
        ячейки считается суммарно, независимо от границ вложенных элементов: «[8000]<x/>[8000]» внутри f – тоже
        слишком длинная формула, а два куска по 200 000 знаков в строке ячейки (inlineStr) – слишком длинный текст."""
        text["node"] += len(data)
        text["row"] += len(data)
        if state["cell_depth"] >= 0:
            cell["text_len"] += len(data)
        if text["node"] > MAX_XML_TEXT_NODE or cell["text_len"] > MAX_XML_TEXT_NODE:
            raise too_many(f"На листе «{sheet_name}» слишком длинный текст ячейки")
        if text["row"] > MAX_XML_ROW_TEXT:
            raise too_many(f"В строке {state['row']} листа «{sheet_name}» слишком много текста")
        kind = cell["capture"]
        if not kind:
            return
        cell[kind + "_len"] += len(data)
        if cell["formula_len"] > MAX_XML_FORMULA_CHARS:
            raise too_many(f"На листе «{sheet_name}» слишком длинный текст формулы (больше "
                           f"{MAX_XML_FORMULA_CHARS} знаков)")
        if cell["value_len"] > MAX_XML_TEXT_NODE:
            raise too_many(f"На листе «{sheet_name}» слишком длинный текст ячейки")
        if cell[kind + "_len"] <= MAX_FORMULA_CHARS + 1:  # дальше не копится: такая формула всё равно отказ
            cell[kind].append(data)

    def too_many(text: str) -> ImportFailure:
        return ImportFailure(f"{text} – так выгрузка AppSec.Hub не выглядит. Проверьте файл.")

    def start(name: str, attrs: dict) -> None:
        s = state
        s["depth"] += 1
        depth = s["depth"]
        text["node"] = 0
        if cell["capture"]:  # элемент внутри f или v
            cell["nested"] = True
        if name == _ROW_TAG:
            text["row"] = 0
            if s["row_depth"] >= 0:
                raise ImportFailure(damaged)
            s["rows"] += 1
            if s["rows"] > MAX_SHEET_ROWS:
                raise too_many(f"На листе «{sheet_name}» больше {MAX_SHEET_ROWS} строк разметки")
            ref = attrs.get("r")
            s["row"] = _row_number(ref) if ref else s["row"] + 1
            s.update(row_depth=depth, col=0, row_cells=0, row_elements=0)
            return
        if s["row_depth"] < 0:
            s["outside"] += 1
            if s["outside"] > MAX_OUTSIDE_ELEMENTS:
                raise too_many(f"На листе «{sheet_name}» больше {MAX_OUTSIDE_ELEMENTS} элементов разметки вне строк "
                               "таблицы")
            return
        s["row_elements"] += 1
        if s["row_elements"] > MAX_ROW_ELEMENTS:
            raise too_many(f"Строка {s['row']} листа «{sheet_name}» слишком сложная: больше {MAX_ROW_ELEMENTS} "
                           "элементов разметки")
        if depth == s["row_depth"] + 1:  # ячейка: любой дочерний элемент строки, как у openpyxl
            s["row_cells"] += 1
            if s["row_cells"] > MAX_ROW_CELLS:
                raise too_many(f"В строке {s['row']} листа «{sheet_name}» больше {MAX_ROW_CELLS} ячеек")
            limits.book.spend_cell()
            ref = attrs.get("r")
            s["col"] = coordinate_to_tuple(ref)[1] if ref else s["col"] + 1
            s.update(cell_depth=depth, cell_col=s["col"])
            reset_cell(attrs)
        elif name == _VALUE_TAG and depth == s["cell_depth"] + 1:
            cell["values"] += 1
            cell.update(capture="value", capture_depth=depth)
        elif name == _FORMULA_TAG and depth == s["cell_depth"] + 1:
            cell["formulas"] += 1
            cell.update(capture="formula", capture_depth=depth)
            if not set(attrs) <= _PLAIN_FORMULA_ATTRS:
                cell["plain"] = False
            area = attrs.get("ref")
            if not cell["plain"]:
                formulas.add(s["cell_col"], s["row"])
            if area:
                try:
                    first_col, first_row, last_col, last_row = range_boundaries(area)
                except (ValueError, TypeError):
                    return  # диапазон не разобран: отмечена сама ячейка с формулой
                formulas.add_area(first_col or 1, last_col or MAX_COLUMNS, first_row or 1, last_row or 1_048_576)

    def end(name: str) -> None:
        s = state
        text["node"] = 0
        if cell["capture"] and s["depth"] == cell["capture_depth"]:
            cell["capture"] = ""
        if s["depth"] == s["cell_depth"]:
            finish_cell()
            s["cell_depth"] = -1
        if s["depth"] == s["row_depth"]:
            s["row_depth"] = -1
        s["depth"] -= 1

    def refuse_dtd(*args) -> None:
        raise ImportFailure(damaged)

    parser = xml.parsers.expat.ParserCreate(namespace_separator=" ")
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.StartDoctypeDeclHandler = refuse_dtd
    parser.EntityDeclHandler = refuse_dtd
    try:
        with source() as src:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                parser.Parse(chunk, False)
            parser.Parse(b"", True)
    except ImportFailure:
        raise
    except Exception as e:  # испорченная разметка, неверная ссылка на ячейку и т. п.
        raise ImportFailure(damaged) from e
    limits.book.sheets[sheet_name] = formulas
    return formulas


def _physical_rows(ws):
    """Строки, которые есть в разметке листа: (номер строки как в Excel, [(номер колонки, значение)]).

    Пропуски между строками не перебираются, а ячейки правее MAX_COLUMNS не собираются: пустая оформленная строка
    1 048 576 стоит одну итерацию, ячейка в колонке XFD не разворачивает строку в 16 384 значения. Читается разметка
    листа разборщиком openpyxl; размеры строк до этого проверяет _scan_sheet."""
    parser_class, source, shared, options = _sheet_source(ws)
    with source() as src:
        parser = parser_class(src, shared, **options)
        for num, cells in parser.parse():
            yield num, [(c["column"], c["value"]) for c in cells
                        if c["column"] <= MAX_COLUMNS and c["value"] is not None]


def _sheet_grid(ws, sheet_name: str, limits: _Limits,
                max_filled: int | None = None) -> list[tuple[int, list[str]]]:
    """Непустые строки листа: [(номер строки как в Excel, [ячейки-строки])]. Сначала разметка листа просматривается
    (_scan_sheet: размеры строк и книги, формулы), затем читается. Пределы: MAX_SHEET_ROWS строк разметки
    (вместе с пустыми), MAX_ROWS непустых строк, общий объём текста (каждая ячейка – до того, как её значение
    сохранено) и развёрнутых ячеек (limits). max_filled – прочитать только столько первых непустых строк.
    Повреждённый лист – ImportFailure."""
    _scan_sheet(ws, sheet_name, limits)
    grid, filled, physical = [], 0, 0
    rows = _physical_rows(ws)
    try:
        for num, cells in rows:
            physical += 1
            if physical > MAX_SHEET_ROWS:
                raise ImportFailure(f"На листе «{sheet_name}» больше {MAX_SHEET_ROWS} строк разметки – так выгрузка "
                                    "AppSec.Hub не выглядит. Проверьте файл.")
            values = {}
            for column, value in cells:
                text = _cell_text(value)
                if text:
                    limits.cells.spend(len(text))
                    values[column] = text
            if not values:
                continue
            filled += 1
            if filled > MAX_ROWS:
                raise ImportFailure(f"На листе «{sheet_name}» больше {MAX_ROWS} строк – так выгрузка AppSec.Hub не "
                                    "выглядит. Проверьте файл.")
            limits.spend_grid(max(values))
            grid.append((num, [values.get(k, "") for k in range(1, max(values) + 1)]))
            if max_filled is not None and filled >= max_filled:
                break
    except ImportFailure:
        raise
    except Exception as e:  # повреждённая разметка листа, неверная ссылка на общую строку и т. п.
        raise ImportFailure(f"Лист «{sheet_name}» повреждён ({type(e).__name__}). Откройте книгу в Excel и сохраните "
                            "заново как .xlsx или выгрузите отчёт из AppSec.Hub ещё раз.") from e
    finally:
        rows.close()  # чтение прервано раньше конца листа: разметка листа закрывается сразу
    return grid


def decode_text(raw: bytes) -> str:
    """Байты файла -> текст: UTF-16 с меткой порядка байтов, затем строго UTF-8 (с меткой или без), иначе cp1251.
    Один декодер для выгрузок Hub и ответов агента (app/sca.py берёт его отсюда)."""
    if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return raw.decode("utf-16", errors="replace")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp1251", errors="replace")


_decode_text = decode_text


def _guess_delimiter(text: str) -> str:
    """Разделитель CSV по первым 20 записям: тот, при котором больше записей делится на одинаковое число полей
    (не меньше двух). При равенстве – «;», TAB, «,»."""
    sample = text[:256 * 1024]
    best, best_score = ",", (0, 0)
    for d in (";", "\t", ","):
        try:
            rows = [r for r in itertools.islice(csv.reader(io.StringIO(sample, newline=""), delimiter=d), 20)
                    if any(cell.strip() for cell in r)]
        except csv.Error:
            continue
        widths = Counter(len(r) for r in rows if len(r) >= 2)
        width, same = widths.most_common(1)[0] if widths else (0, 0)
        if (same, width) > best_score:
            best, best_score = d, (same, width)
    return best


def _csv_grid(raw: bytes, limits: _Limits) -> list[tuple[int, list[str]]]:
    if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        text = _decode_text(raw)
    elif b"\x00" in raw[:8192] or raw.startswith(b"%PDF"):
        raise ImportFailure("Файл не похож на таблицу. Загрузите выгрузку AppSec.Hub в формате .xlsx или таблицу .csv.")
    else:
        text = _decode_text(raw)
    text = text.replace("\x00", "")
    # Предел длины поля поднимается до определения разделителя: иначе длинная ячейка сорвёт разбор образца,
    # и разделитель определится неверно.
    csv.field_size_limit(max(csv.field_size_limit(), 64 * 1024 * 1024))
    delimiter = _guess_delimiter(text)
    grid = []
    # csv.reader собирает запись целиком и лишь потом отдаёт её: разделители записи считаются до разбора, по
    # строкам, которые он берёт (вместе с разделителями внутри кавычек – оценка сверху)
    pending = [0]

    def lines():
        for line in io.StringIO(text, newline=""):
            pending[0] += line.count(delimiter)
            if pending[0] > MAX_CSV_RECORD_DELIMITERS:
                raise ImportFailure(f"В записи таблицы больше {MAX_CSV_RECORD_DELIMITERS} разделителей – так выгрузка "
                                    "AppSec.Hub не выглядит. Проверьте файл.")
            yield line

    # strict: незакрытая кавычка – ошибка, а не склейка следующих строк в одну ячейку
    reader = csv.reader(lines(), delimiter=delimiter, strict=True)
    try:
        for num, row in enumerate(reader, start=1):
            pending[0] = 0
            cells = [_clip(cell.strip()) for cell in row[:MAX_COLUMNS]]
            while cells and not cells[-1]:
                cells.pop()
            if not cells:
                continue
            limits.cells.spend(sum(len(cell) for cell in cells))
            limits.spend_grid(len(cells))
            if len(grid) >= MAX_ROWS:
                raise ImportFailure(f"В таблице больше {MAX_ROWS} строк – так выгрузка AppSec.Hub не выглядит. "
                                    "Проверьте файл.")
            grid.append((num, cells))
    except csv.Error as e:
        raise ImportFailure(f"Не удалось разобрать CSV около записи {reader.line_num}: незакрытая кавычка или лишний "
                            "знак после кавычки. Сохраните таблицу заново (CSV в UTF-8) или загрузите .xlsx.") from e
    return grid


@dataclass
class _Table:
    """Таблица листа: заголовки, строки-словари {заголовок: значение, "_row": номер строки как в Excel}, номер
    строки заголовков (None – таблицы нет) и номер колонки листа (с 1) для каждого заголовка."""

    headers: list[str]
    rows: list[dict]
    header_row: int | None
    columns: dict[str, int]


def _grid_to_rows(grid, label: str) -> tuple[list[str], list[dict], int | None]:
    """Сетка -> (заголовки, строки-словари, номер строки заголовка); подробности – _grid_to_table."""
    table = _grid_to_table(grid, label)
    return table.headers, table.rows, table.header_row


def _grid_to_table(grid, label: str) -> _Table:
    """Сетка -> таблица (_Table).

    Заголовок – первая строка, где заполнено не меньше половины ячеек самой полной из первых 50 строк (и не меньше
    двух): строки над таблицей вроде «Проект: | Система» пропускаются. Повтор названия получает « (2)», колонка
    без названия с данными – «Колонка N». Пустая сетка – таблица без заголовков и строк."""
    if not grid:
        return _Table([], [], None, {})
    filled = [sum(1 for c in cells if c) for _, cells in grid]
    widest = max(filled[:50], default=0)
    need = max(min(2, widest), (widest + 1) // 2)
    hk = next((k for k, n in enumerate(filled) if n >= need), None)
    if hk is None:
        raise ImportFailure(f"{label}: не найдена строка заголовков таблицы.")
    header_row, header_cells = grid[hk]
    data = grid[hk + 1:]
    width = max([len(header_cells)] + [len(cells) for _, cells in data])
    with_data = {i for _, cells in data for i, cell in enumerate(cells) if cell}  # колонки, где есть значения
    used = {"_row"}
    columns = []
    for i in range(width):
        # название колонки повторяется в каждой находке (прочие колонки) – длинное обрезается
        name = " ".join((header_cells[i] if i < len(header_cells) else "").split())[:MAX_HEADER_CHARS]
        if not name:
            if i not in with_data:
                continue
            name = f"Колонка {i + 1}"
        if name in used:
            k = 2
            while f"{name} ({k})" in used:
                k += 1
            name = f"{name} ({k})"
        used.add(name)
        columns.append((i, name))
    rows = []
    for num, cells in data:
        # только заполненные ячейки: строка с одним ID при 500 колонках – словарь из двух ключей, а не из 501
        row = {name: cells[i] for i, name in columns if i < len(cells) and cells[i]}
        row["_row"] = num
        rows.append(row)
    return _Table([name for _, name in columns], rows, header_row, {name: i + 1 for i, name in columns})


def _spans_text(spans: list[tuple[int, int]]) -> str:
    """[(2, 40), (57, 57)] -> «строки 2–40, 57»."""
    parts = [str(a) if a == b else f"{a}–{b}" for a, b in spans[:3]]
    single = len(spans) == 1 and spans[0][0] == spans[0][1]
    return ("строка " if single else "строки ") + ", ".join(parts) + (" и далее" if len(spans) > 3 else "")


def _check_formulas(sheet: str, table: _Table, mapping: dict[str, str], formulas: _Formulas | None,
                    notes: _Notes) -> None:
    """Формулы в таблице листа (со строки заголовков и ниже).

    Книга читается со значениями, сохранёнными при последнем пересчёте в Excel: без пересчёта значение формулы
    пустое, после правки соседних ячеек – устаревшее. В колонках карты (номер находки, файл, строка, код, компонент
    и другие поля) такое значение испортило бы находку, а при повторной загрузке – и привязку решений к номерам
    находок: отчёт отклоняется (ImportFailure). Формулы в прочих колонках – предупреждение. Если участков
    с формулами больше MAX_FORMULA_AREAS, где они, не известно – отчёт отклоняется."""
    if formulas is None or not (formulas or formulas.link_cells) or table.header_row is None:
        return
    advice = ("Приложение формулы не вычисляет, а значения, сохранённые в файле, бывают пустыми или устаревшими: "
              "номер находки, файл или строка оказались бы неверными. Выгрузите отчёт из AppSec.Hub заново или "
              "замените формулы значениями (в Excel: «Копировать», затем «Специальная вставка» – «Значения»). "
              "Формулы HYPERLINK(\"адрес\"; \"текст\") с двумя текстами в кавычках принимаются, остальные нужно "
              "заменить значениями.")
    if formulas.overflow:
        raise ImportFailure(f"На листе «{sheet}» слишком много формул. {advice}")
    used = set(mapping.values())
    # ссылки HYPERLINK допустимы только в номере находки, названии системы и идентификаторе уязвимости
    link_headers = {mapping[k] for k in ("hub_id", "application", "cve") if k in mapping}
    bad = []
    for header, column in table.columns.items():
        spans = formulas.rows_in(column, table.header_row)
        if formulas.link_cells is not None and header not in link_headers:
            spans = sorted(set(spans) | set(formulas.link_cells.rows_in(column, table.header_row)))
        if not spans:
            continue
        if header in used:
            bad.append(f"«{header}» – {_spans_text(spans)}")
        else:
            notes.add("formula_other", f"лист «{sheet}», «{header}»" if sheet else f"«{header}»")
    if bad:
        raise ImportFailure(f"На листе «{sheet}» формулы в колонках, из которых берутся сведения о находках: "
                            f"{'; '.join(bad[:SHOW])}. {advice}")


_GENERATED_COLUMN = re.compile(r"Колонка \d+")


def _note_wide_rows(headers: list[str], label: str, notes) -> None:
    """В строках данных есть ячейки правее строки заголовков: _grid_to_rows назвал их «Колонка N»."""
    generated = [h for h in headers if _GENERATED_COLUMN.fullmatch(h)]
    if generated:
        notes.add("wide_rows", f"{label}: {', '.join(generated)}")


def map_columns(headers: list[str], candidates: dict[str, list[str]]) -> dict[str, str]:
    """{поле: колонка файла} по вариантам названий (без учёта регистра и пробелов). Колонка, занятая полем выше
    по карте, другим полям не достаётся."""
    by_norm = {}
    for h in headers:
        by_norm.setdefault(_norm_name(h), h)
    taken, result = set(), {}
    for field_name, names in candidates.items():
        for name in names:
            header = by_norm.get(_norm_name(name))
            if header is not None and header not in taken:
                result[field_name] = header
                taken.add(header)
                break
    return result


# ============================================================================ строка -> находка

_SAST_RE = re.compile(r"\bsast\b|static|статическ", re.I)
_SCA_RE = re.compile(r"\b(sca|osa|oss)\b|composition|dependenc|librar|open\s*-?\s*source|зависимост|библиотек"
                     r"|компонент", re.I)
_DAST_RE = re.compile(r"\bdast\b|dynamic|динамическ", re.I)
_LICENSE_RE = re.compile(r"compliance|licen|лиценз", re.I)


def _kind_from_text(value: str) -> str:
    """Значение колонки вида -> SAST, SCA, SCA-license, DAST или "" (не распознан)."""
    s = str(value or "")
    if _LICENSE_RE.search(s):
        return "SCA-license"
    if _DAST_RE.search(s):
        return "DAST"
    sast, sca = bool(_SAST_RE.search(s)), bool(_SCA_RE.search(s))
    if sast != sca:
        return "SAST" if sast else "SCA"
    return ""


def _guess_kind(f: Finding) -> str:
    """Вид по полям, если колонки вида нет: компонент без места в коде – SCA (лицензия, если нет уязвимости),
    адрес без файла – DAST, иначе SAST."""
    if f.component and not (f.file and f.line is not None):
        if f.licenses and not f.cve and not f.vuln_ids and f.cvss is None:
            return "SCA-license"
        return "SCA"
    if f.location and not f.file:
        return "DAST"
    return "SAST"


class _Notes:
    """Счётчики того, что пришлось поправить при разборе строк (для предупреждений)."""

    def __init__(self):
        self.count = Counter()
        self.places: dict[str, list[str]] = {}

    def add(self, key: str, place: str = "") -> None:
        self.count[key] += 1
        if place:
            self.places.setdefault(key, []).append(place)

    def listing(self, key: str) -> str:
        places = self.places.get(key, [])
        shown = ", ".join(places[:SHOW])
        return shown + (f" и ещё {len(places) - SHOW}" if len(places) > SHOW else "")


_LEADING_ZEROS = re.compile(r"^0+(?=\d)")


def norm_hub_id(value: str) -> str:
    """Номер находки Hub – как целое, без ведущих нулей: выгрузка через редактор таблиц может отдать «0012» (ячейка-
    текст), в Hub номер – 12, и Pull, статусы и дефекты ищут находку по нему (бэклог 64).
    Буквенные номера таблиц не из Hub не меняются."""
    v = str(value or "").strip()
    return _LEADING_ZEROS.sub("", v) if v.isascii() and v.isdigit() else v


def _to_finding(row: dict, mapping: dict[str, str], kind: str, sheet: str, hub_rules: bool,
                notes: _Notes) -> Finding:
    """Строка таблицы -> находка. kind – вид по листу ("" – определить по колонке вида или по полям).
    hub_rules – колонка Severity у SCA – уровень политики Hub.

    Поля находки и прочие колонки ограничены по длине (MAX_FIELD_CHARS, MAX_SNIPPET_CHARS, MAX_EXTRA_*): находка
    хранится в базе целиком и показывается в списке, длинные значения из подложенного файла не должны её раздувать."""
    place = f"{sheet}:{row['_row']}" if sheet else str(row["_row"])
    cut: set[str] = set()  # поля, обрезанные по длине

    def cell(name: str) -> str:
        header = mapping.get(name)
        value = str(row.get(header, "") or "").strip() if header else ""
        if value in DASHES:
            return ""
        limit = MAX_SNIPPET_CHARS if name == "snippet" else MAX_FIELD_CHARS
        if len(value) <= limit:
            return value
        cut.add(name)
        # строка кода – без пометки: строка из выгрузки сверяется с файлом по началу строки
        return value[:limit] if name == "snippet" else _clip(value, limit)

    file_text, line_text = norm_path(cell("file")), cell("line")
    line = parse_line(line_text)
    if line_text and line is None:
        notes.add("line_bad", place)
    m = _FILE_LINE_RE.fullmatch(file_text)
    if m:  # «src/A.java:57» – номер отделяется от пути
        file_text = m.group(1)
        if line is None and not line_text:
            line = int(m.group(2))
    snippet, tail = split_code_tail(cell("snippet"))
    if tail is not None:  # номер в хвосте Source code сверяется с Line number; верным считается Line number
        if line is None and not line_text:
            line = tail
        elif line is not None and tail != line:
            notes.add("tail_mismatch", place)
    cvss_text = cell("cvss")
    cvss = parse_float(cvss_text)
    if cvss is not None and not 0 <= cvss <= 10:
        cvss = None
    if cvss_text and cvss is None:
        notes.add("cvss_bad", place)
    rule = cell("rule")
    cwe_text, cwe_links = cell("cwe"), parse_urls(cell("cwe_links"))
    cwe = parse_cwes(cwe_text)
    if not cwe and "cwe" in rule.casefold():  # «SQL Injection (CWE-89)» без отдельной колонки CWE
        cwe = parse_cwes(rule)
    if not cwe and cwe_links:  # номер CWE есть только в ссылке на cwe.mitre.org
        for link in cwe_links:
            for n in _CWE_LINK.findall(link):
                if f"CWE-{int(n)}" not in cwe:
                    cwe.append(f"CWE-{int(n)}")
    extra: dict[str, str] = {}
    extra_size = [0, False]  # байт UTF-8 в прочих колонках, что-то не поместилось

    def add_extra(header: str, text: str) -> None:
        """Прочая колонка – в пределах MAX_EXTRA_COLUMNS колонок и MAX_EXTRA_BYTES байт на находку (в том виде,
        в каком она ляжет в базу: JSON в UTF-8)."""
        text = _clip(text, MAX_EXTRA_VALUE)
        size = _json_size(header) + _json_size(text)
        if len(extra) >= MAX_EXTRA_COLUMNS or extra_size[0] + size > MAX_EXTRA_BYTES:
            extra_size[1] = True
            return
        extra[header] = text
        extra_size[0] += size

    severity_text, policy_text = cell("severity"), cell("policy_severity")
    if severity_text and not norm_severity(severity_text):  # не распознанная критичность не теряется
        add_extra(mapping["severity"], severity_text)
    used = set(mapping.values())
    for header, value in row.items():
        if header == "_row" or header in used:
            continue
        text = str(value or "").strip()
        if text and text not in DASHES:
            add_extra(header, text)
    if extra_size[1]:
        notes.add("extra_cut", place)
    f = Finding(
        hub_id=norm_hub_id(cell("hub_id")) if hub_rules else cell("hub_id"), kind=kind, tool=cell("tool"),
        application=cell("application"),
        severity=norm_severity(severity_text), policy_severity=norm_severity(policy_text) or policy_text,
        cvss=cvss, rule=rule, cwe=cwe, cwe_links=cwe_links, codebase=cell("codebase"), file=file_text, line=line,
        snippet=snippet, status=cell("status"), language=cell("language"), build_type=cell("build_type"),
        component=cell("component"), version=cell("version"), fixed_version=cell("fixed_version"),
        dep_path=cell("dep_path"), vuln_ids=parse_vuln_ids(cell("cve")), cve=parse_cves(cell("cve")),
        licenses=cell("licenses"), location=cell("location"), extra=extra, sheet=sheet, row=int(row["_row"]))
    if not f.kind:
        f.kind = _kind_from_text(cell("kind")) or _guess_kind(f)
    if hub_rules and f.kind in ("SCA", "SCA-license") and f.severity:
        # у SCA отчёта Hub Severity – уровень политики, а не тяжесть уязвимости
        f.policy_severity, f.severity = f.policy_severity or f.severity, ""
    if f.kind in ("SCA", "SCA-license") and not f.cve:
        f.cve = parse_cves(rule)  # у SCA номер CVE бывает в названии правила
    if any(_DATE_CELL.fullmatch(cell(name)) for name in ("version", "line", "cvss", "cwe")):
        notes.add("date_cells", place)  # выгрузку пересохраняли в Excel: «3.2.1» стало датой
    if cut:
        notes.add("long_field", place)
    return f


def _json_size(value) -> int:
    """Сколько байт значение займёт в базе: JSON так же, как его пишет app/db.py (без ASCII-экранирования,
    с сортировкой ключей), в UTF-8. Управляющие знаки в JSON экранируются и занимают до 6 байт."""
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8", "replace"))


def _stored_bytes(f: Finding) -> int:
    """Сколько байт находка займёт в базе (поле data_json)."""
    return _json_size(f.__dict__)


# Подпись подвала – целым словом: «Итого:», «Total 73», «Сформировано», но не номер находки вроде «total-1».
_CAPTION = re.compile(r"(?:итого|всего|сформирован\w*|выгружен\w*|дата выгрузки|total|generated|exported)(?![-\w])",
                      re.I)


def _filled(row: dict) -> int:
    return sum(1 for k, v in row.items() if k != "_row" and v and str(v).strip() not in DASHES)


def _is_footer(row: dict, hub_id: str) -> bool:
    """Строка-подвал таблицы, а не находка: «Итого: 73», «Сформировано: | 13.10.2026». Строка с номером находки –
    подвал, только если «номер» похож на подпись."""
    if not hub_id:
        return _filled(row) <= 2
    caption = hub_id.rstrip().endswith(":") or bool(_CAPTION.match(hub_id.strip()))
    return _filled(row) <= 2 and caption


def _collect(rows: list[dict], mapping: dict[str, str], kind: str, sheet: str, hub_rules: bool,
             notes: _Notes, footers: bool, limits: _Limits) -> list[Finding]:
    findings = []
    for row in rows:
        f = _to_finding(row, mapping, kind, sheet, hub_rules, notes)
        place = f"{sheet}:{row['_row']}" if sheet else str(row["_row"])
        if footers and _is_footer(row, f.hub_id):
            notes.add("footer", place)
            continue
        if not f.hub_id:
            notes.add("no_id", place)
            continue
        if _filled(row) == 1:
            notes.add("id_only", place)  # строка с одним номером: находка, но без данных
        limits.stored.spend(_stored_bytes(f))
        findings.append(f)
    return findings


def _dedupe(findings: list[Finding], notes: _Notes) -> list[Finding]:
    """Повтор ID: остаётся первая строка, о повторах – предупреждение."""
    seen, result = {}, []
    for f in findings:
        if f.hub_id in seen:
            notes.add("duplicate", f"{f.hub_id} ({seen[f.hub_id]} и {f.sheet}:{f.row})")
            continue
        seen[f.hub_id] = f"{f.sheet}:{f.row}"
        result.append(f)
    return result


def _warnings(notes: _Notes) -> list[str]:
    c = notes.count
    texts = {
        "no_id": "Строки без ID находки пропущены ({n}): {places}.",
        "footer": "Строки-подвалы таблицы (итоги, подписи) пропущены ({n}): {places}.",
        "id_only": "Строки, где заполнен только номер находки ({n}), взяты как находки без данных – проверьте их: "
                   "{places}.",
        "wide_rows": "В строках больше ячеек, чем в строке заголовков: значения без заголовка сохранены как "
                     "«Колонка N» ({places}). Проверьте, не сдвинулись ли колонки.",
        "duplicate": "ID находки повторяется ({n}), взята первая строка: {places}.",
        "tail_mismatch": "Номер строки в хвосте Source code не совпал с Line number у {n} находок (верным считается "
                         "Line number): {places}.",
        "line_bad": "Номер строки не распознан у {n} находок: {places}.",
        "cvss_bad": "CVSS не распознан у {n} находок: {places}.",
        "date_cells": "У {n} находок версия, строка или CVSS выглядят как дата – похоже, выгрузку пересохраняли в "
                      "Excel и «3.2.1» стало датой. Выгрузите отчёт заново: {places}.",
        "long_field": "У {n} находок слишком длинные значения обрезаны: {places}.",
        "extra_cut": f"У {{n}} находок прочие колонки сохранены не все: у находки хранится до {MAX_EXTRA_COLUMNS} "
                     f"прочих колонок и до {MAX_EXTRA_BYTES // 1024} КБ их текста ({{places}}).",
        "formula_other": "В колонках, из которых сведения о находках не берутся, есть формулы ({places}): сохранены "
                         "значения, записанные в файле при последнем пересчёте в Excel, – они могут быть устаревшими.",
        "formula_summary": "На листе сводки ({places}) есть формулы, кроме проверенных ссылок HYPERLINK в значении "
                           "«Application»: прочитаны сохранённые значения, сверка со сводкой может оказаться "
                           "неточной.",
    }
    return [text.format(n=c[key], places=notes.listing(key)) for key, text in texts.items() if c[key]]


# ============================================================================ отчёт Hub

_FOREIGN_SHEET = "лист не из отчёта AppSec.Hub – пропущен"


def _hub_layout(names: list[str]) -> tuple[str, dict[str, str]]:
    """(лист сводки или "", {практика: лист}) по именам листов книги."""
    by_key = {}
    for name in names:
        by_key.setdefault(_norm_name(name), name)
    practices = {p: by_key[_norm_name(p)] for p in HUB_PRACTICES if _norm_name(p) in by_key}
    return by_key.get(_norm_name(HUB_SUMMARY), ""), practices


def _read_summary(grid) -> dict:
    """Лист «Summary Report» -> application, report_created, by_practice, by_severity, totals.

    Подписи ищутся в первой колонке: «Application», «Report created», «Practice» и «Severity type» со строками
    «Count» и «Total» под ними. Числа в отчёте Hub записаны строками."""
    result = {"application": "", "report_created": None, "by_practice": {}, "by_severity": {},
              "practices_total": None, "severities_total": None, "unparsed": []}
    rows = [(cells[0].strip().casefold() if cells else "", cells) for _, cells in grid]
    for i, (label, cells) in enumerate(rows):
        value = cells[1].strip() if len(cells) > 1 else ""
        if label == "application":
            result["application"] = value
        elif label == "report created":
            result["report_created"] = value or None
        elif label in ("practice", "severity type"):
            names = [n.strip() for n in cells[1:]]
            for below, row in rows[i + 1:i + 3]:
                if below == "count":
                    counts = {}
                    for k, n in enumerate(names, start=1):
                        if not n:
                            continue
                        if label == "practice":
                            key = next((p for p in HUB_PRACTICES if _norm_name(p) == _norm_name(n)), n)
                        else:
                            key = norm_severity(n) or n
                        counts[key] = _parse_count(row[k] if k < len(row) else "")
                        if counts[key] is None:  # ячейка пуста или не число: сверить нельзя
                            result["unparsed"].append(key)
                    result["by_practice" if label == "practice" else "by_severity"] = counts
                elif below == "total":
                    total = _parse_count(row[1] if len(row) > 1 else "")
                    result["practices_total" if label == "practice" else "severities_total"] = total
                    if total is None:
                        result["unparsed"].append("итог по практикам" if label == "practice"
                                                  else "итог по критичности")
    return result


def _summary_links_outside(formulas: _Formulas, grid) -> bool:
    """Ссылки HYPERLINK на листе сводки допустимы только в значении строки «Application» (колонка B)."""
    if formulas.link_cells is None:
        return False
    allowed = {num for num, cells in grid if cells and cells[0].strip().casefold() == "application"}
    for first_col, last_col, first_row, last_row in formulas.link_cells.areas:
        if first_col != 2 or last_col != 2 or last_row - first_row > len(allowed) or not all(r in allowed for r in range(first_row, last_row + 1)):
            return True
    return False


def _parse_count(value) -> int | None:
    """Счётчик из сводки: «120», «120.0» -> 120; не число -> None."""
    number = parse_float(value)
    return int(number) if number is not None and number.is_integer() and number >= 0 else None


def _summary_check(by_practice: dict, found: dict[str, int]) -> list[dict]:
    """Сводка против листов -> [{"practice", "expected", "actual", "ok"}]. Практика из сводки без листа – ноль
    находок; ok = None – сверить нельзя (счётчик в сводке не распознан или листа нет в сводке)."""
    result = []
    for practice, expected in by_practice.items():
        actual = found.get(practice, 0)
        result.append({"practice": practice, "expected": expected, "actual": actual,
                       "ok": None if expected is None else expected == actual})
    for practice, actual in found.items():
        if practice not in by_practice:
            result.append({"practice": practice, "expected": None, "actual": actual, "ok": None})
    return result


def _summary_warnings(summary: dict, check: list[dict], findings: list[Finding]) -> list[str]:
    """Предупреждения сверки со сводкой: счётчики практик, итоги и распределение по критичности (у SCA в отчёте
    Hub критичность – уровень политики)."""
    warnings = []
    bad = [c for c in check if c["ok"] is False]
    if bad:
        warnings.append("Сводка «Summary Report» не сходится с листами: "
                        + "; ".join(f"{c['practice']} – в сводке {c['expected']}, на листе {c['actual']}"
                                    for c in bad) + ".")
    if summary["unparsed"]:
        warnings.append("В сводке «Summary Report» не распознаны счётчики: " + ", ".join(summary["unparsed"])
                        + " – сверить их с листами нельзя.")
    totals = {name: value for name, value in (("по практикам", summary["practices_total"]),
                                              ("по критичности", summary["severities_total"])) if value is not None}
    wrong = [f"{name} – {value}" for name, value in totals.items() if value != len(findings)]
    if wrong:
        warnings.append(f"Итог сводки «Summary Report» не сходится с числом находок на листах ({len(findings)}): "
                        + "; ".join(wrong) + ".")
    if summary["by_severity"]:
        counted = Counter(f.severity or norm_severity(f.policy_severity) for f in findings)
        differs = [f"{level} – в сводке {expected}, на листах {counted.get(level, 0)}"
                   for level, expected in summary["by_severity"].items()
                   if expected is not None and expected != counted.get(level, 0)]
        if differs:
            warnings.append("Сводка «Summary Report» по критичности не сходится с листами (у SCA – уровень политики "
                            "Hub): " + "; ".join(differs) + ".")
    return warnings


def _parse_hub(wb, names, summary_sheet, practices, notes, limits: _Limits) -> ImportResult:
    summary_ws = wb[summary_sheet] if summary_sheet else None
    summary_grid = _sheet_grid(summary_ws, summary_sheet, limits) if hasattr(summary_ws, "iter_rows") else []
    summary = _read_summary(summary_grid)
    findings, sheets, found = [], [], {}
    if summary_sheet:
        marked = limits.book.sheets.get(summary_sheet)
        if marked is not None and (marked or _summary_links_outside(marked, summary_grid)):
            notes.add("formula_summary", f"лист «{summary_sheet}»")

    practice_of = {sheet: practice for practice, sheet in practices.items()}
    for name in names:
        if name == summary_sheet:
            sheets.append({"name": name, "rows": 0, "skipped": True, "findings": 0, "practice": "", "kind": "",
                           "reason": "сводка: с ней сверяются остальные листы"})
            continue
        practice = practice_of.get(name)
        if practice is None:
            sheets.append({"name": name, "rows": 0, "skipped": True, "findings": 0, "practice": "", "kind": "",
                           "reason": _FOREIGN_SHEET})
            continue
        ws = wb[name]
        if not hasattr(ws, "iter_rows"):
            sheets.append({"name": name, "rows": 0, "skipped": True, "findings": 0, "practice": practice,
                           "kind": HUB_KIND[practice], "reason": "лист без таблицы"})
            continue
        table = _grid_to_table(_sheet_grid(ws, name, limits), f"Лист «{name}»")
        headers, rows = table.headers, table.rows
        entry = {"name": name, "rows": len(rows), "skipped": False, "findings": 0, "practice": practice,
                 "kind": HUB_KIND[practice], "reason": ""}
        if not rows:
            entry.update(skipped=True, reason="лист пуст" if not headers else "лист без находок")
            sheets.append(entry)
            found[practice] = 0
            continue
        mapping = map_columns(headers, HUB_COLUMNS[practice])
        if "hub_id" not in mapping:
            raise ImportFailure(f"На листе «{name}» нет колонки «Issue id» с номером находки. Похоже, это не отчёт "
                                "AppSec.Hub или формат отчёта изменился: выгрузите отчёт из Hub заново.")
        _check_formulas(name, table, mapping, limits.book.sheets.get(name), notes)
        _note_wide_rows(headers, f"лист «{name}»", notes)
        taken = _collect(rows, mapping, HUB_KIND[practice], name, True, notes, footers=False, limits=limits)
        entry["findings"] = len(taken)
        found[practice] = found.get(practice, 0) + len(taken)
        findings.extend(taken)
        sheets.append(entry)
    unique = _dedupe(findings, notes)
    if len(unique) != len(findings):  # повторы уже не считаются находками своего листа
        found = Counter(next(p for p, s in practices.items() if s == f.sheet) for f in unique)
        for entry in sheets:
            if entry.get("practice") and not entry["skipped"]:
                entry["findings"] = found.get(entry["practice"], 0)
    check = _summary_check(summary["by_practice"], dict(found)) if summary_sheet else []
    for entry in sheets:
        row = next((c for c in check if c["practice"] == entry.get("practice")), None)
        entry["expected"] = row["expected"] if row else None
        entry["match"] = row["ok"] if row else None
    warnings = []
    if not summary_sheet:
        warnings.append(f"В книге нет листа «{HUB_SUMMARY}»: сверить число находок со сводкой нельзя.")
    else:
        warnings.extend(_summary_warnings(summary, check, unique))
    skipped = [s["name"] for s in sheets if s["reason"] == _FOREIGN_SHEET]
    if skipped:
        warnings.append("Листы не из отчёта AppSec.Hub пропущены: " + ", ".join(f"«{n}»" for n in skipped) + ".")
    warnings.extend(_warnings(notes))
    if not unique:
        warnings.append("В выгрузке нет ни одной находки.")
    total = summary["practices_total"] if summary["practices_total"] is not None else summary["severities_total"]
    result_summary = {"application": summary["application"], "by_practice": summary["by_practice"],
                      "by_severity": summary["by_severity"], "total": total,
                      "report_created": summary["report_created"], "check": check,
                      "skipped_findings": notes.count["no_id"]}
    return ImportResult(findings=unique, format="hub", sheets=sheets, summary=result_summary, warnings=warnings)


# ============================================================================ таблица

def _parse_table(table: _Table, sheet: str, label: str, notes: _Notes, other_sheets: list[dict], limits: _Limits,
                 formulas: _Formulas | None = None) -> ImportResult:
    headers, rows = table.headers, table.rows
    mapping = map_columns(headers, TABLE_COLUMNS)
    if "hub_id" not in mapping:
        raise ImportFailure(f"{label}: не найдена колонка с номером находки (Issue id, ID, «Идентификатор»). "
                            "Загрузите отчёт AppSec.Hub в формате .xlsx или таблицу с такой колонкой.")
    _note_wide_rows(headers, label, notes)
    hub_like = _norm_name(mapping["hub_id"]) == _norm_name("Issue id")
    if hub_like and "dep_path" not in mapping:  # таблица с колонками Hub: Path у SCA – путь зависимости, а не файл
        path_column = next((h for h in headers if _norm_name(h) == "path" and h not in mapping.values()), None)
        if path_column:
            mapping["dep_path"] = path_column
    _check_formulas(sheet, table, mapping, formulas, notes)  # карта колонок уже окончательная
    taken = _collect(rows, mapping, "", sheet, hub_like, notes, footers=True, limits=limits)
    unique = _dedupe(taken, notes)
    sheets = [{"name": sheet or label, "rows": len(rows), "skipped": False, "findings": len(unique), "practice": "",
               "kind": "", "reason": "", "expected": None, "match": None}] + other_sheets
    warnings = []
    skipped = [s["name"] for s in other_sheets if s["rows"]]
    if skipped:
        warnings.append("Книга прочитана как одна таблица (лист «" + (sheet or label) + "»); остальные листы "
                        "с данными пропущены: " + ", ".join(f"«{name}»" for name in skipped) + ".")
    warnings.extend(_warnings(notes))
    if not unique:
        warnings.append("В таблице нет ни одной находки.")
    apps = Counter(f.application for f in unique if f.application)
    summary = {"application": apps.most_common(1)[0][0] if len(apps) == 1 else "", "by_practice": {},
               "by_severity": {}, "total": None, "report_created": None, "check": [],
               "skipped_findings": notes.count["no_id"]}
    return ImportResult(findings=unique, format="table", sheets=sheets, summary=summary, warnings=warnings)


# ============================================================================ вход

def _open_workbook(fh):
    """Книга из открытого файла: openpyxl получает файловый объект, а не путь, поэтому имя и расширение файла
    (загрузка могла сохранить его под временным именем) не важны."""
    try:
        import openpyxl
    except ImportError:  # pragma: no cover – зависимость указана в requirements.txt
        raise ImportFailure("Не установлен пакет openpyxl: книги Excel не читаются.") from None
    try:
        return openpyxl.load_workbook(fh, read_only=True, data_only=True)
    except Exception as e:  # повреждённый файл, не XLSX, зашифрованный и т. п.
        raise ImportFailure(f"Не удалось открыть книгу Excel ({type(e).__name__}). Откройте файл в Excel и сохраните "
                            "заново как .xlsx.") from None


def _parse_xlsx(p: Path) -> ImportResult:
    limits = _Limits(_check_archive(p))
    with open(p, "rb") as fh:
        wb = _open_workbook(fh)
        try:
            return _read_xlsx(wb, limits)
        finally:
            wb.close()  # в режиме read_only книга держит архив открытым до close()


def _read_xlsx(wb, limits: _Limits) -> ImportResult:
    """Открытая книга -> отчёт Hub или таблица с первого листа с данными."""
    names = list(wb.sheetnames)
    summary_sheet, practices = _hub_layout(names)
    is_hub = bool(practices) and (bool(summary_sheet) or len(practices) >= 2)
    if not is_hub and len(practices) == 1:  # один лист практики без сводки: отчёт Hub, если в нём колонки Hub
        practice, name = next(iter(practices.items()))
        ws = wb[name]
        if hasattr(ws, "iter_rows"):
            # проба – первые 50 строк, со своим бюджетом текста: настоящий разбор листа посчитает их заново;
            # просмотр разметки листа (limits.book) общий – лист просматривается один раз
            probe = _sheet_grid(ws, name, _Limits(limits.size, limits.book), 50)
            headers, _, _ = _grid_to_rows(probe, f"Лист «{name}»")
            is_hub = "hub_id" in map_columns(headers, HUB_COLUMNS[practice])
    notes = _Notes()
    if is_hub:
        return _parse_hub(wb, names, summary_sheet, practices, notes, limits)
    chosen, table, others = "", _Table([], [], None, {}), []
    for name in names:
        ws = wb[name]
        grid = _sheet_grid(ws, name, limits) if hasattr(ws, "iter_rows") else []
        if not chosen and grid:
            chosen = name
            table = _grid_to_table(grid, f"Лист «{name}»")
            continue
        others.append({"name": name, "rows": len(grid), "skipped": True, "findings": 0, "practice": "", "kind": "",
                       "reason": "прочитан только первый лист с данными" if grid else "лист пуст",
                       "expected": None, "match": None})
    if not chosen:
        raise ImportFailure("В книге нет ни одного листа с данными.")
    return _parse_table(table, chosen, f"Лист «{chosen}»", notes, others, limits, limits.book.sheets.get(chosen))


def parse_workbook(path: Path, max_bytes: int = MAX_UPLOAD_BYTES) -> ImportResult:
    """Выгрузка AppSec.Hub -> ImportResult.

    Формат определяется по содержимому, а не по расширению: книга .xlsx (zip) – отчёт Hub, если в ней лист
    «Summary Report» и листы практик (или хотя бы два листа практик), иначе одна таблица с первого листа с данными;
    старый .xls и книга под паролем – отказ; остальное читается как CSV (UTF-8, UTF-16 с BOM или cp1251;
    разделитель «;», «,» или TAB определяется сам). Любая ошибка – ImportFailure с сообщением по-русски.
    """
    p = Path(path)
    try:
        if not p.is_file():
            raise ImportFailure("Файл выгрузки не найден.")
        size = p.stat().st_size
        if size == 0:
            raise ImportFailure("Файл выгрузки пуст.")
        if size > max_bytes:
            raise ImportFailure(f"Файл больше {max(1, max_bytes // (1024 * 1024))} МБ – так выгрузка AppSec.Hub не "
                                "выглядит. Проверьте, тот ли это файл.")
        with open(p, "rb") as fh:
            head = fh.read(8)
        if head.startswith(b"PK\x03\x04"):
            return _parse_xlsx(p)
        if head.startswith(b"\xd0\xcf\x11\xe0"):
            raise ImportFailure("Файл в старом формате .xls или защищён паролем. Откройте его в Excel и сохраните "
                                "как .xlsx без пароля.")
        if p.suffix.lower() in (".xlsx", ".xlsm"):
            raise ImportFailure("Файл назван как книга Excel (.xlsx), но ею не является. Выгрузите отчёт из "
                                "AppSec.Hub заново.")
        raw = p.read_bytes()
        limits = _Limits(len(raw))
        table = _grid_to_table(_csv_grid(raw, limits), "Таблица")
        if not table.headers:
            raise ImportFailure("Таблица пуста: нет строки заголовков.")
        return _parse_table(table, "", "Таблица", _Notes(), [], limits)
    except ImportFailure:
        raise
    except OSError as e:
        raise ImportFailure(f"Не удалось прочитать файл выгрузки ({type(e).__name__}). Проверьте, что файл доступен, "
                            "и загрузите его ещё раз.") from e
    except Exception as e:  # непредвиденное содержимое: сообщение по-русски, причина – в цепочке исключений
        raise ImportFailure(f"Не удалось разобрать выгрузку ({type(e).__name__}). Выгрузите отчёт из AppSec.Hub "
                            "заново; если ошибка повторится, сохраните файл в Excel как .xlsx.") from e


# ============================================================================ группы и срочность

def _get(f, name: str, default=None):
    """Поле находки: Finding или словарь (например, строка из базы)."""
    if isinstance(f, dict):
        return f.get(name, default)
    return getattr(f, name, default)


def group_key(f) -> str:
    """Ключ группы похожих находок: SAST – «rule|cwe|file|line» (CWE через запятую), SCA – «component|version»;
    лицензии – «license|component|version», DAST – «DAST|rule|cwe|location»."""
    kind = str(_get(f, "kind", "") or "")
    cwe = _get(f, "cwe", []) or []
    cwe_text = ",".join(str(c) for c in cwe) if isinstance(cwe, (list, tuple)) else str(cwe)
    if kind == "SCA":
        return f"{_get(f, 'component', '') or ''}|{_get(f, 'version', '') or ''}"
    if kind == "SCA-license":
        return f"license|{_get(f, 'component', '') or ''}|{_get(f, 'version', '') or ''}"
    if kind == "DAST":
        return f"DAST|{_get(f, 'rule', '') or ''}|{cwe_text}|{_get(f, 'location', '') or ''}"
    line = _get(f, "line")
    return f"{_get(f, 'rule', '') or ''}|{cwe_text}|{_get(f, 'file', '') or ''}|{'' if line is None else line}"


_CWE_NUM = re.compile(r"cwe-0*(\d+)", re.I)


def _cwe2(cwe) -> list[str]:
    """CWE находки как множество (ADR-0095 п. 1): `CWE-<число>` приводится к целому и сортируется по числу, прочие
    элементы – после, в лексикографическом порядке; повторы снимаются после приведения."""
    items = cwe if isinstance(cwe, (list, tuple)) else ([cwe] if cwe else [])
    numbers, other = set(), set()
    for raw in items:
        text = str(raw or "").strip()
        if not text:
            continue
        m = _CWE_NUM.fullmatch(text)
        if m:
            numbers.add(int(m.group(1)))
        else:
            other.add(text)
    return [f"CWE-{n}" for n in sorted(numbers)] + sorted(other)


def _file2(path: str, codebase: str) -> str:
    """Путь без префикса кодовой базы (ADR-0095 п. 1): снимается ровно один первый сегмент, если он без учёта регистра
    равен непустому имени кодовой базы без «/» и «\\» и после снятия путь не пуст. Остаток – как есть."""
    path, base = str(path or ""), str(codebase or "").strip()
    if not base or "/" in base or "\\" in base:
        return path
    head, sep, rest = path.partition("/")
    if sep and rest and head.casefold() == base.casefold():
        return rest
    return path


def group_parts2(f) -> dict | None:
    """Компоненты ключа группы второй редакции для находки SAST (ADR-0095 п. 1): rule, cwe2, file2, line; None –
    группа не образуется (нет правила, файла или строки) или находка не SAST."""
    if str(_get(f, "kind", "") or "") != "SAST":
        return None
    rule = str(_get(f, "rule", "") or "")
    file2 = _file2(str(_get(f, "file", "") or ""), str(_get(f, "codebase", "") or ""))
    line = _get(f, "line")
    if isinstance(line, bool) or not isinstance(line, int):
        try:
            line = int(str(line).strip()) if line not in (None, "") else None
        except ValueError:
            line = None
    if not rule or not file2 or line is None:
        return None
    return {"rule": rule, "cwe2": _cwe2(_get(f, "cwe", []) or []), "file2": file2, "line": line}


def _canon(value) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def group_key2(f) -> str:
    """Ключ группы второй редакции (ADR-0095 п. 2): SAST – канонический JSON `[rule, cwe2, file2, line]` (только для
    равенства; "" – группы нет); SCA, лицензии и DAST – прежний ключ."""
    if str(_get(f, "kind", "") or "") != "SAST":
        return group_key(f)
    parts = group_parts2(f)
    return "" if parts is None else _canon([parts["rule"], parts["cwe2"], parts["file2"], parts["line"]])


def near_columns2(f) -> tuple[str, str, int | None]:
    """Колонки подсказки «Рядом та же категория» (ADR-0095 пп. 2, 6): g2_cat – JSON `[rule, cwe2]`, g2_file, g2_line;
    у находок не SAST и без группы – пустые."""
    parts = group_parts2(f)
    if parts is None:
        return "", "", None
    return _canon([parts["rule"], parts["cwe2"]]), parts["file2"], parts["line"]


def is_urgent(f, sca_cvss: float = 9.0, sast_levels=("critical", "high")) -> bool:
    """Срочная ли находка.

    SAST и DAST – по критичности (sast_levels). SCA – по CVSS не ниже sca_cvss: в отчёте Hub колонка Severity у SCA –
    уровень политики, и у всех SCA там «Critical»; без CVSS SCA не срочная. Лицензии не срочные."""
    kind = str(_get(f, "kind", "") or "")
    if kind == "SCA":
        cvss = parse_float(_get(f, "cvss"))
        return cvss is not None and cvss >= float(sca_cvss)
    if kind == "SCA-license":
        return False
    return str(_get(f, "severity", "") or "").lower() in tuple(s.lower() for s in sast_levels)

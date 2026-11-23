"""Справочники уязвимостей без интернета: выгрузка БДУ ФСТЭК России (vulxml.zip) и каталог CWE MITRE
(cwec_latest.xml.zip). Файлы загружает пользователь на странице «Справочники»; приложение никуда не обращается.

Разбор – потоковый: архив читается кусками, XML разбирается по мере чтения (pyexpat), из файла строятся только
записи (<vul> БДУ, <Weakness> и <Category> CWE); готовая запись сразу обрабатывается и забывается, а всё, что вне
записей, не накапливается вовсе. Поэтому файл в сотни мегабайт не загружается в память целиком.

Защита от вредного XML:
* объявления DOCTYPE и ENTITY запрещены (внешние сущности, «бомба» из вложенных сущностей): поток проверяется
  на них кусками с перекрытием на стыках, а XML только в UTF-8 (в UTF-16 объявление не поймать по байтам);
  разборщику дополнительно запрещены параметрические и внешние сущности;
* пределы архива: размер распакованного файла (считается по прочитанному, а не по заголовку архива), степень
  сжатия, число файлов в архиве, число записей;
* пределы одной записи – проверяются в обработчиках разборщика, до накопления: глубина вложенности, число элементов,
  общий объём текста записи, число и длина атрибутов, длина имени элемента; текст одного элемента сверх
  MAX_ELEMENT_TEXT отбрасывается сразу. Длинная конструкция без единого события разборщика (огромный атрибут, имя
  элемента, комментарий) – отказ, когда без событий прошло больше MAX_SILENT_BYTES;
* пределы хранения: длина каждого сохраняемого поля и каждой ссылки, размер записи в базе (MAX_RECORD_JSON).

Хранение – схема feeds основной базы PostgreSQL (FeedStore, ADR-0133). Новая выгрузка пишется пачками в схему feeds_imp той же
структуры и подменяет прежнюю одной транзакцией в конце: пока идёт загрузка, карточки видят прежний справочник; сбой загрузки прежний
не трогает. Загрузка ограничена сроком (MAX_IMPORT_SECONDS), её можно остановить (FeedStore.cancel). Размер справочников проверяется
до записи каждой пачки. При любой остановке – на разборе, записи или подмене – feeds_imp очищается.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO
from xml.parsers import expat

import psycopg

from app import i18n
from app.storage import PostgresStore, conninfo_for

log = logging.getLogger("local_triage.feeds")

# подписи справочников (ADR-0158): ключи – виды справочников, значения переводятся при чтении
KINDS = i18n.Labels({"bdu": "БДУ ФСТЭК России", "cwe": "Каталог CWE", "capec": "Каталог CAPEC"})

CHUNK = 1024 * 1024
FEED_PIECE = 64 * 1024  # кусок, которым поток подаётся разборщику: события проверяются после каждого
MAX_XML_BYTES = 2 * 1024 * 1024 * 1024  # распакованный XML: реальная выгрузка БДУ – около 0,6 ГБ
MAX_RATIO = 200  # распакованный размер к сжатому
MAX_MEMBERS = 50
MAX_RECORDS = {"bdu": 500_000, "cwe": 50_000, "capec": 50_000}
BATCH = 1000
MAX_TEXT = 8000
MAX_SHORT = 1000
MAX_LIST = 50
MAX_SOFTWARE = 10  # уязвимого ПО на запись: у некоторых записей БДУ – сотни версий, для дефекта они не нужны
MAX_SOURCE = 500  # знаков в одной ссылке-источнике
MAX_SCORE = 10  # знаков в оценке CVSS («7,5»)
MAX_RECORD_JSON = 64 * 1024  # байт одной записи БДУ в базе
MAX_DESC = 16_000  # описание записи CWE целиком (самое длинное в каталоге 4.20 – около 4 тыс. знаков)
MAX_PARAS = 100  # абзацев в одном разделе записи CWE
MAX_OBSERVED = 60  # наблюдаемых примеров (CVE) на запись CWE (в каталоге 4.20 самое большее – 50)
MAX_CATEGORY_MEMBERS = 200  # членов категории CWE (в каталоге 4.20 самое большее – 156)
# пунктов в одном списке записи CWE: связи, платформы, обнаружение, устранение, таксономии, CAPEC, примечания
# (в каталоге 4.20 самое большее – 59 шаблонов атак CAPEC у CWE-200; предел БДУ MAX_LIST их обрезал бы)
MAX_CWE_LIST = 200
MAX_CWE_RECORD_JSON = 96 * 1024  # байт полной записи CWE в базе (самая большая в каталоге 4.20 – около 40 КБ)

# Пределы разбора одной записи (жёсткие – отказ файла, кроме текста одного элемента: лишний отбрасывается)
MAX_DEPTH = 64  # глубина вложенности во всём файле
MAX_RECORD_ELEMENTS = 100_000  # в выгрузке БДУ есть запись с 52 232 элементами; общий бюджет ниже
# Общий бюджет одной записи: знаки сохранённого текста, имён элементов, имён и значений атрибутов – вместе.
# Тысячи элементов с допустимыми по отдельности атрибутами не накопят больше этого.
MAX_RECORD_TEXT = 4 * 1024 * 1024
MAX_ELEMENT_TEXT = 64 * 1024  # знаков текста одного элемента; дальше текст отбрасывается
MAX_ATTRS = 32
MAX_ATTR_CHARS = 4096  # имя и значение одного атрибута
MAX_TAG_CHARS = 300  # имя элемента вместе с пространством имён
MAX_SILENT_BYTES = 4 * 1024 * 1024  # байт подряд без единого события разборщика

# Срок, место, размер
MAX_IMPORT_SECONDS = 30 * 60
MAX_DB_BYTES = 3 * 1024 * 1024 * 1024  # справочники и идущая загрузка вместе, по pg_total_relation_size
BATCH_SPACE_FACTOR = 3  # запас места на пачку к размеру её строк: индексы, служебные страницы

_FORBIDDEN = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)", re.I)
_OVERLAP = 32
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_CWE = re.compile(r"(\d{1,5})")
_CWE_ID = re.compile(r"\s*(?:CWE\s*-?\s*)?0*(\d{1,5})\s*", re.I)
_DATE = re.compile(r"(\d{2})\.(\d{2})\.(\d{4})")


class FeedError(ValueError):
    """Файл справочника не принят. Текст – по-русски, для показа на странице."""


BUSY = i18n.N_("Справочник уже загружается: дождитесь окончания.")
CANCELLED = i18n.N_("Загрузка остановлена: прежний справочник не изменился.")
IMPORT_LOCK = 7133001  # владение feeds_imp между процессами: pg_try_advisory_lock
_IMPORT_SLOT = threading.Lock()  # одна загрузка за раз во всём приложении


# ============================================================================ чтение архива

def _member(archive: zipfile.ZipFile, kind: str) -> zipfile.ZipInfo:
    """Файл XML в архиве: единственный .xml (у БДУ – export/vulxml.xml)."""
    infos = archive.infolist()
    if len(infos) > MAX_MEMBERS:
        raise FeedError(i18n._("В архиве больше {limit} файлов: это не выгрузка {feed}.", limit=MAX_MEMBERS, feed=KINDS[kind]))
    xml = [i for i in infos if not i.is_dir() and i.filename.lower().endswith(".xml")]
    if len(xml) != 1:
        raise FeedError(i18n._("В архиве нужен ровно один файл XML ({feed}), найдено: {count}.", feed=KINDS[kind], count=len(xml)))
    info = xml[0]
    if info.file_size > MAX_XML_BYTES:
        raise FeedError(i18n._("Файл XML в архиве слишком большой."))
    if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
        raise FeedError(i18n._("Файл XML в архиве сжат подозрительно сильно – архив не принят."))
    return info


def guarded_chunks(stream: BinaryIO, limit: int = MAX_XML_BYTES, compressed: int = 0) -> Iterator[bytes]:
    """Куски XML с проверками: только UTF-8, без DOCTYPE и ENTITY (с перекрытием на стыках кусков), не больше limit
    байт и не сильнее MAX_RATIO от сжатого размера compressed (считается по прочитанному)."""
    total = 0
    tail = b""
    first = True
    while True:
        chunk = stream.read(CHUNK)
        if not chunk:
            return
        if first:
            head = chunk[:200]
            if head.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in head:
                raise FeedError(i18n._("Поддерживается только XML в кодировке UTF-8."))
            first = False
        total += len(chunk)
        if total > limit:
            raise FeedError(i18n._("Файл XML больше допустимого размера."))
        if compressed and total > 64 * CHUNK and total / compressed > MAX_RATIO:
            raise FeedError(i18n._("Файл XML в архиве сжат подозрительно сильно – архив не принят."))
        window = tail + chunk
        if _FORBIDDEN.search(window):
            raise FeedError(i18n._("В XML есть объявление DOCTYPE или ENTITY – такие файлы не принимаются."))
        tail = window[-_OVERLAP:]
        yield chunk


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


class _Frame:
    """Открытый элемент записи: куски его текста и хвоста последнего дочернего элемента (как text и tail
    у ElementTree), сколько знаков текста уже принято."""

    __slots__ = ("elem", "text", "tail", "last", "chars")

    def __init__(self, elem: ET.Element) -> None:
        self.elem = elem
        self.text: list[str] = []
        self.tail: list[str] = []
        self.last: ET.Element | None = None
        self.chars = 0

    def close_tail(self) -> None:
        if self.last is not None and self.tail:
            self.last.tail = "".join(self.tail)
        self.tail = []


class _RecordBuilder:
    """Обработчики pyexpat: строят только записи record_tags, с пределами (см. MAX_* в начале модуля)."""

    def __init__(self, record_tags: set[str], on_root: Callable[[ET.Element], None] | None) -> None:
        self.record_tags = record_tags
        self.on_root = on_root
        self.depth = 0
        self.seen_root = False
        self.frames: list[_Frame] = []  # открытые элементы текущей записи; пусто – вне записи
        self.elements = 0
        self.text = 0
        self.ready: list[ET.Element] = []
        self.events = 0

    @staticmethod
    def _attrs(tag: str, attrs: dict[str, str]) -> dict[str, str]:
        if len(tag) > MAX_TAG_CHARS:
            raise FeedError(i18n._("В XML слишком длинное имя элемента – файл не принят."))
        if len(attrs) > MAX_ATTRS:
            raise FeedError(i18n._("У элемента XML слишком много атрибутов – файл не принят."))
        for name, value in attrs.items():
            if len(name) + len(value) > MAX_ATTR_CHARS:
                raise FeedError(i18n._("В XML слишком длинный атрибут – файл не принят."))
        return attrs

    def _spend(self, chars: int) -> None:
        """Знаки, сохраняемые в текущей записи (текст, имена элементов, атрибуты), – в общий бюджет записи."""
        self.text += chars
        if self.text > MAX_RECORD_TEXT:
            raise FeedError(i18n._("Запись справочника слишком большая (текста и атрибутов больше допустимого) "
                                   "– файл не принят."))

    def start(self, tag: str, attrs: dict[str, str]) -> None:
        self.events += 1
        attrs = self._attrs(tag, attrs)
        size = len(tag) + sum(len(k) + len(v) for k, v in attrs.items())
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise FeedError(i18n._("В XML слишком глубокая вложенность элементов – файл не принят."))
        if not self.seen_root:
            self.seen_root = True
            if self.on_root is not None:
                self.on_root(ET.Element(tag, attrs))
        if self.frames:
            parent = self.frames[-1]
            self.elements += 1
            if self.elements > MAX_RECORD_ELEMENTS:
                raise FeedError(i18n._("В записи справочника слишком много элементов – файл не принят."))
            self._spend(size)
            parent.close_tail()
            elem = ET.SubElement(parent.elem, tag, attrs)
            parent.last = elem
            self.frames.append(_Frame(elem))
        elif _local(tag) in self.record_tags:
            self.elements, self.text = 1, 0
            self._spend(size)
            self.frames.append(_Frame(ET.Element(tag, attrs)))

    def end(self, tag: str) -> None:
        self.events += 1
        self.depth -= 1
        if not self.frames:
            return
        frame = self.frames.pop()
        frame.elem.text = "".join(frame.text) if frame.text else None
        frame.close_tail()
        if not self.frames:
            self.ready.append(frame.elem)

    def data(self, text: str) -> None:
        self.events += 1
        if not self.frames:
            return  # текст вне записей не нужен
        frame = self.frames[-1]
        room = MAX_ELEMENT_TEXT - frame.chars
        if room <= 0:
            return
        if len(text) > room:
            text = text[:room]
        frame.chars += len(text)
        self._spend(len(text))
        (frame.tail if frame.last is not None else frame.text).append(text)


def _forbid(*_args: Any) -> None:
    raise FeedError(i18n._("В XML есть объявление DOCTYPE или ENTITY – такие файлы не принимаются."))


def iter_records(chunks: Iterable[bytes], record_tags: set[str],
                 on_root: Callable[[ET.Element], None] | None = None,
                 check: Callable[[], None] | None = None) -> Iterator[ET.Element]:
    """Записи record_tags по мере разбора (ElementTree.Element с потомками). Вне записей ничего не накапливается;
    пределы одной записи – в _RecordBuilder. on_root – корневой элемент при его открытии (только имя и атрибуты:
    версия и дата каталога). check – вызывается между кусками (срок и отмена загрузки)."""
    builder = _RecordBuilder(record_tags, on_root)
    parser = expat.ParserCreate(encoding="utf-8", namespace_separator="}")
    parser.buffer_text = True
    parser.buffer_size = FEED_PIECE
    parser.ordered_attributes = False
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartElementHandler = builder.start
    parser.EndElementHandler = builder.end
    parser.CharacterDataHandler = builder.data
    parser.StartDoctypeDeclHandler = _forbid
    parser.EntityDeclHandler = _forbid
    parser.ExternalEntityRefHandler = lambda *_a: 0
    silent = 0
    try:
        for chunk in chunks:
            for k in range(0, len(chunk), FEED_PIECE):
                if check is not None:
                    check()
                piece = chunk[k:k + FEED_PIECE]
                before = builder.events
                parser.Parse(piece, False)
                silent = silent + len(piece) if builder.events == before else 0
                if silent > MAX_SILENT_BYTES:
                    raise FeedError(i18n._("В XML слишком длинная конструкция (атрибут, имя элемента или "
                                           "комментарий) – файл не принят."))
                if builder.ready:
                    ready, builder.ready = builder.ready, []
                    yield from ready
        parser.Parse(b"", True)
        ready, builder.ready = builder.ready, []
        yield from ready
    except expat.ExpatError as e:
        raise FeedError(i18n._("XML повреждён или обрывается (строка {line}).", line=e.lineno)) from None
    finally:
        # обработчики держат ссылки на построитель: разрываем, чтобы не держать память
        parser.StartElementHandler = parser.EndElementHandler = parser.CharacterDataHandler = None


# ============================================================================ разбор записей

def _text(elem: ET.Element | None, limit: int = MAX_TEXT) -> str:
    if elem is None:
        return ""
    return " ".join("".join(elem.itertext()).split())[:limit]


def _child(elem: ET.Element, name: str) -> ET.Element | None:
    for child in elem:
        if _local(child.tag) == name:
            return child
    return None


def _path(elem: ET.Element | None, *names: str) -> ET.Element | None:
    """Вложенный элемент по цепочке имён; нет – None. Пустой элемент ложен для bool(), поэтому проверка – на None."""
    for name in names:
        if elem is None:
            return None
        elem = _child(elem, name)
    return elem


def _children(elem: ET.Element | None, name: str) -> list[ET.Element]:
    return [c for c in elem if _local(c.tag) == name] if elem is not None else []


def cwe_key(value: Any) -> str:
    m = _CWE.search(str(value or ""))
    return f"CWE-{int(m.group(1))}" if m else ""


def cwe_id(value: Any) -> str:
    """Номер класса из адреса или поискового запроса: вся строка – «CWE-89», «89» или «cwe-089», иначе "".
    cwe_key берёт первые цифры откуда угодно (так читаются поля выгрузок), здесь «ISO 27001» номером не станет."""
    m = _CWE_ID.fullmatch(str(value or ""))
    return f"CWE-{int(m.group(1))}" if m else ""


def _iso_date(text: str) -> str:
    m = _DATE.search(text or "")
    return f"{m.group(3)}-{m.group(2)}-{m.group(1)}" if m else ""


def _cvss(vector: ET.Element | None) -> str:
    if vector is None:
        return ""
    score = " ".join(str(vector.get("score") or "").split())[:MAX_SCORE]
    return f"{score} {_text(vector, 200)}".strip()


def _sources(elem: ET.Element | None) -> list[str]:
    """Ссылки-источники: первые MAX_LIST, каждая не длиннее MAX_SOURCE знаков. Текст элемента уже ограничен
    при разборе (MAX_ELEMENT_TEXT)."""
    if elem is None:
        return []
    result = []
    for s in re.split(r"\s+", "".join(elem.itertext())):
        if s:
            result.append(s[:MAX_SOURCE])
            if len(result) >= MAX_LIST:
                break
    return result


def _table_rows(table: ET.Element) -> list[str]:
    """Строки xhtml-таблицы текстом: ячейки <th>/<td> через « | », пустые строки пропускаются."""
    rows = []
    for tr in table.iter():
        if _local(tr.tag) != "tr":
            continue
        # части текста ячейки – через пробел: «decryption<br/>Default» не склеивается
        cells = [" ".join(" ".join(td.itertext()).split()) for td in tr if _local(td.tag) in ("th", "td")]
        row = " | ".join(c for c in cells if c)
        if row:
            rows.append(row)
    return rows


def _paragraphs(elem: ET.Element | None, limit: int = MAX_TEXT) -> list[str]:
    """Абзацы текста из xhtml-содержимого: <p> и <div> – абзацы, пункты списков <ul>/<ol> – абзацы с «- »,
    прочая разметка отбрасывается (её текст склеивается с абзацем). Абзац копится до границы блока (<p>, <div>,
    <br>, список), поэтому «Use <b>checked</b> input.» – один абзац. Пустых абзацев нет; каждый не длиннее
    limit, всего не больше MAX_PARAS."""
    out: list[str] = []
    buf: list[str] = []

    def flush() -> None:
        t = " ".join("".join(buf).split())
        buf.clear()
        if t and len(out) < MAX_PARAS:
            out.append(t[:limit])

    def walk(e: ET.Element) -> None:
        buf.append(e.text or "")
        for c in e:
            tag = _local(c.tag)
            if tag in ("p", "div"):
                flush()
                walk(c)
                flush()
            elif tag == "br":
                flush()
            elif tag == "table":  # строка таблицы – абзац «ячейка | ячейка»
                flush()
                for row in _table_rows(c):
                    if len(out) < MAX_PARAS:
                        out.append(row[:limit])
            elif tag in ("ul", "ol"):
                flush()
                for li in c:
                    if _local(li.tag) != "li":
                        continue
                    t = " ".join("".join(li.itertext()).split())
                    if t and len(out) < MAX_PARAS:
                        out.append(("- " + t)[:limit])
            else:  # <xhtml:i>, <xhtml:b> и прочие строковые элементы – текст остаётся в абзаце
                buf.append("".join(c.itertext()))
            buf.append(c.tail or "")

    if elem is not None:
        walk(elem)
        flush()
    return out


def _code_text(elem: ET.Element, max_lines: int = 400) -> str:
    """Код из Example_Code построчно, с отступами: перевод строки – <xhtml:br/> и граница <xhtml:div>, отступ –
    уровень вложенных <xhtml:div> с «margin-left» в style (4 пробела на уровень). Перевод строки самого XML
    вместе с пробелами вокруг него – служебный: в начале строки кода отбрасывается, внутри строки становится
    пробелом, как при показе xhtml («the NR⏎\t\tfile» – «the NR file»); табуляция внутри строки – пробел.
    Пробелы в начале строки без перевода строки XML («<br/>    run()») – отступ автора, они сохраняются.
    Строк не больше max_lines."""
    lines: list[str] = []
    cur: list[str] = []

    def flush() -> None:
        if len(lines) < max_lines:
            lines.append("".join(cur).rstrip()[:MAX_SHORT * 4])
        cur.clear()

    def add_text(text: str, indent: int) -> None:
        t = re.sub(r"[ \t]*\n[ \t\n]*", "\n", text.replace("\r", ""))
        if not cur and t[:1] in ("\n", "\t"):
            t = t.lstrip("\n\t")  # отступ разметки XML в начале строки кода
        t = re.sub(r"[ \t]*[\n\t][ \t\n]*", " ", t)  # табуляции подряд, как и перевод строки, – один пробел
        if not t or (not cur and not t.strip()):
            return
        if not cur and indent:
            cur.append("    " * indent)
        cur.append(t)

    def walk(e: ET.Element, indent: int) -> None:
        add_text(e.text or "", indent)
        for c in e:
            tag = _local(c.tag)
            if tag == "br":
                flush()
            elif tag == "div":
                if "".join(cur).strip():
                    flush()
                walk(c, indent + (1 if "margin-left" in (c.get("style") or "") else 0))
                if "".join(cur).strip():
                    flush()
            elif tag == "p":  # абзац внутри кода – с новой строки, без нового отступа
                if "".join(cur).strip():
                    flush()
                walk(c, indent)
                if "".join(cur).strip():
                    flush()
            elif tag in ("ul", "ol", "table"):
                if "".join(cur).strip():
                    flush()
                items = _table_rows(c) if tag == "table" else [
                    "- " + t for t in (" ".join("".join(li.itertext()).split()) for li in c
                                       if _local(li.tag) == "li") if t]
                for t in items:  # пункт списка или строка таблицы – отдельная строка кода
                    cur.clear()
                    if indent:
                        cur.append("    " * indent)
                    cur.append(t)
                    flush()
            else:  # <xhtml:i>, <xhtml:b> и прочие строковые элементы – текст остаётся в строке
                walk(c, indent)
            add_text(c.tail or "", indent)

    walk(elem, 0)
    if cur:
        flush()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def _record_refs(elem: ET.Element) -> list[dict]:
    """Ссылки записи на источники каталога CWE: [{ref_id, section}] (разворачиваются через cwe_refs)."""
    return [{"ref_id": str(r.get("External_Reference_ID") or "")[:60],
             "section": " ".join(str(r.get("Section") or "").split())[:MAX_SHORT]}
            for r in _children(_child(elem, "References"), "Reference")[:MAX_CWE_LIST]
            if str(r.get("External_Reference_ID") or "").strip()]


def _mapping_notes(elem: ET.Element) -> dict:
    """Mapping_Notes записи CWE: рекомендация по использованию и основания; пусто, если раздела нет."""
    notes = _child(elem, "Mapping_Notes")
    if notes is None:
        return {}
    return {"usage": _text(_child(notes, "Usage"), 100),
            "rationale": _text(_child(notes, "Rationale")),
            "comments": _text(_child(notes, "Comments")),
            "reasons": [t for t in (str(r.get("Type") or "").strip()[:60]
                                    for r in _children(_child(notes, "Reasons"), "Reason")[:MAX_LIST]) if t]}


def _cwe_notes(elem: ET.Element) -> list[dict]:
    """Notes записи CWE (и слабости, и категории): [{type, text}]."""
    return [{"type": str(n.get("Type") or "")[:60], "text": _text(n)}
            for n in _children(_child(elem, "Notes"), "Note")[:MAX_CWE_LIST]]


def _fit(record: dict) -> dict:
    """Запись не больше MAX_RECORD_JSON байт в базе: сначала короче списки и длинные тексты, затем отказ."""
    def size() -> int:
        return len(json.dumps(record, ensure_ascii=False).encode("utf-8"))

    steps = (
        lambda: record.update(sources=record["sources"][:10]),
        lambda: record.update(cwes=[{**c, "name": c["name"][:200]} for c in record["cwes"]][:10]),
        lambda: record.update(software=record["software"][:3]),
        lambda: record.update(description=record["description"][:3000], solution=record["solution"][:3000]),
        lambda: record.update(cves=record["cves"][:20], software=[]),
        lambda: record.update(description=record["description"][:1000], solution=record["solution"][:1000],
                              sources=record["sources"][:3]),
    )
    for step in steps:
        if size() <= MAX_RECORD_JSON:
            return record
        step()
    if size() > MAX_RECORD_JSON:
        raise FeedError(i18n._("Запись {id} слишком большая для справочника – файл не принят.", id=record.get('id', '')))
    return record


def _fit_cwe(record: dict) -> dict:
    """Полная запись CWE не больше MAX_CWE_RECORD_JSON байт в базе: сначала короче второстепенные разделы,
    затем отказ. Самая большая запись каталога 4.20 – около 40 КБ, поэтому обрезка – страховка, а не норма."""
    def size() -> int:
        return len(json.dumps(record, ensure_ascii=False).encode("utf-8"))

    def trim(key: str, n: int) -> None:
        if isinstance(record.get(key), list):
            record[key] = record[key][:n]

    steps = (
        lambda: trim("notes", 5),
        lambda: trim("observed", 20),
        lambda: trim("taxonomies", 10),
        lambda: trim("references", 10),
        lambda: trim("examples", 3),
        lambda: record.update(extended=[p[:2000] for p in record.get("extended", [])][:10]),
        lambda: trim("detection", 5),
        lambda: trim("mitigations", 5),
        lambda: trim("background", 3),
    )
    for step in steps:
        if size() <= MAX_CWE_RECORD_JSON:
            return record
        step()
    if size() > MAX_CWE_RECORD_JSON:
        raise FeedError(i18n._("Запись {id} слишком большая для справочника – файл не принят.", id=record.get('id', '')))
    return record


def parse_bdu(vul: ET.Element) -> dict | None:
    """Запись <vul> выгрузки БДУ -> словарь; без идентификатора BDU – None. Каждое поле ограничено по длине."""
    bdu_id = _text(_child(vul, "identifier"), 40)
    if not bdu_id.upper().startswith("BDU:"):
        return None
    cwes = []
    for cwe in _children(_child(vul, "cwes"), "cwe")[:MAX_LIST]:
        key = cwe_key(_text(_child(cwe, "identifier"), 40))
        if key:
            cwes.append({"id": key, "name": _text(_child(cwe, "name"), MAX_SHORT)})
    cves = []
    for ident in _children(_child(vul, "identifiers"), "identifier"):
        text = _text(ident, 60)
        if (ident.get("type") or "").upper() == "CVE" or _CVE.fullmatch(text):
            m = _CVE.search(text)
            if m and m.group(0).upper() not in cves:
                cves.append(m.group(0).upper())
                if len(cves) >= MAX_LIST:
                    break
    software = []
    for soft in _children(_child(vul, "vulnerable_software"), "soft")[:MAX_SOFTWARE]:
        software.append({"name": _text(_child(soft, "name"), 200), "vendor": _text(_child(soft, "vendor"), 200),
                         "version": _text(_child(soft, "version"), 200)})
    return _fit({
        "id": bdu_id, "name": _text(_child(vul, "name"), MAX_SHORT),
        "description": _text(_child(vul, "description")), "severity": _text(_child(vul, "severity"), MAX_SHORT),
        "solution": _text(_child(vul, "solution")),
        "cvss2": _cvss(_path(vul, "cvss", "vector")),
        "cvss3": _cvss(_path(vul, "cvss3", "vector")),
        "cwes": cwes, "cves": cves, "sources": _sources(_child(vul, "sources")),
        "fix_status": _text(_child(vul, "fix_status"), MAX_SHORT),
        "vul_status": _text(_child(vul, "vul_status"), MAX_SHORT),
        "published": _iso_date(_text(_child(vul, "publication_date"), 40)),
        "updated": _iso_date(_text(_child(vul, "last_upd_date"), 40)),
        "software": software,
    })


def parse_cwe(elem: ET.Element) -> dict | None:
    """Запись <Weakness> или <Category> каталога CWE -> полный словарь ("full": 1); без номера – None.

    Weakness сохраняется целиком, в структурированном виде: описания – списками абзацев из xhtml (_paragraphs),
    примеры кода – построчно с отступами (_code_text). Category – Summary, члены (Has_Member), ссылки, Mapping_Notes,
    Notes.
    Каждое поле ограничено по длине, вся запись – MAX_CWE_RECORD_JSON."""
    key = cwe_key(elem.get("ID"))
    if not key:
        return None
    kind = _local(elem.tag)
    name = " ".join(str(elem.get("Name") or "").split())[:MAX_SHORT]
    status = str(elem.get("Status") or "")[:40]
    if kind == "Category":
        summary = _text(_child(elem, "Summary"), MAX_DESC)
        return _fit_cwe({
            "id": key, "kind": "category", "name": name, "status": status, "full": 1,
            "summary": summary, "description": summary,
            "relationships": [{"cwe_id": cwe_key(m.get("CWE_ID")), "view_id": str(m.get("View_ID") or "")[:20]}
                              for m in _children(_child(elem, "Relationships"), "Has_Member")[:MAX_CATEGORY_MEMBERS]
                              if cwe_key(m.get("CWE_ID"))],
            "references": _record_refs(elem),
            "mapping_notes": _mapping_notes(elem),
            "notes": _cwe_notes(elem),
        })
    examples = []
    for ex in _children(_child(elem, "Demonstrative_Examples"), "Demonstrative_Example")[:20]:
        blocks: list[dict] = []
        for block in ex:
            tag = _local(block.tag)
            if tag == "Example_Code":
                code = _code_text(block)
                if code:
                    blocks.append({"kind": "code", "nature": str(block.get("Nature") or "")[:40],
                                   "language": str(block.get("Language") or "")[:60], "code": code})
            elif tag == "Body_Text":
                paragraphs = _paragraphs(block)
                if paragraphs:
                    blocks.append({"kind": "text", "paragraphs": paragraphs})
        examples.append({"intro": _paragraphs(_child(ex, "Intro_Text")), "blocks": blocks[:60],
                         "refs": [{"ref_id": str(r.get("External_Reference_ID") or "")[:60],
                                   "section": " ".join(str(r.get("Section") or "").split())[:MAX_SHORT]}
                                  for r in _children(_child(ex, "References"), "Reference")[:10]
                                  if str(r.get("External_Reference_ID") or "").strip()]})
    platforms = _child(elem, "Applicable_Platforms")
    return _fit_cwe({
        "id": key, "kind": "weakness", "name": name, "full": 1,
        "abstraction": str(elem.get("Abstraction") or "")[:40],
        "structure": str(elem.get("Structure") or "")[:40],
        "status": status,
        "description": _text(_child(elem, "Description"), MAX_DESC),
        "extended": _paragraphs(_child(elem, "Extended_Description")),
        "background": [_text(b, MAX_TEXT)
                       for b in _children(_child(elem, "Background_Details"), "Background_Detail")[:10]],
        "alt_terms": [{"term": _text(_child(t, "Term"), MAX_SHORT),
                       "description": _text(_child(t, "Description"), MAX_SHORT)}
                      for t in _children(_child(elem, "Alternate_Terms"), "Alternate_Term")[:MAX_CWE_LIST]],
        "related": [{"nature": str(r.get("Nature") or "")[:40], "cwe_id": cwe_key(r.get("CWE_ID")),
                     "view_id": str(r.get("View_ID") or "")[:20], "ordinal": str(r.get("Ordinal") or "")[:40]}
                    for r in _children(_child(elem, "Related_Weaknesses"), "Related_Weakness")[:MAX_CWE_LIST]
                    if cwe_key(r.get("CWE_ID"))],
        "ordinalities": [o for o in (_text(_child(x, "Ordinality"), 60) for x in
                                     _children(_child(elem, "Weakness_Ordinalities"), "Weakness_Ordinality")[:10])
                         if o],
        "platforms": [{"kind": _local(p.tag), "class": str(p.get("Class") or "")[:100],
                       "name": str(p.get("Name") or "")[:100], "prevalence": str(p.get("Prevalence") or "")[:60]}
                      for p in (platforms if platforms is not None else [])][:MAX_CWE_LIST],
        "modes": [{"phase": _text(_child(m, "Phase"), 200), "note": _text(_child(m, "Note"))}
                  for m in _children(_child(elem, "Modes_Of_Introduction"), "Introduction")[:MAX_CWE_LIST]],
        "likelihood": _text(_child(elem, "Likelihood_Of_Exploit"), 40),
        "consequences": [{"scope": [_text(s, 200) for s in _children(c, "Scope")[:10]],
                          "impact": [_text(i, 300) for i in _children(c, "Impact")[:10]],
                          "likelihood": _text(_child(c, "Likelihood"), 100),
                          "note": _text(_child(c, "Note"))}
                         for c in _children(_child(elem, "Common_Consequences"), "Consequence")[:MAX_CWE_LIST]],
        "detection": [{"method": _text(_child(d, "Method"), 300),
                       "description": _paragraphs(_child(d, "Description")),
                       "effectiveness": _text(_child(d, "Effectiveness"), 100),
                       "effectiveness_notes": _text(_child(d, "Effectiveness_Notes"))}
                      for d in _children(_child(elem, "Detection_Methods"), "Detection_Method")[:MAX_CWE_LIST]],
        "mitigations": [{"phases": [_text(p, 200) for p in _children(m, "Phase")[:10]],
                         "strategy": _text(_child(m, "Strategy"), 200),
                         "description": _paragraphs(_child(m, "Description")),
                         "effectiveness": _text(_child(m, "Effectiveness"), 100),
                         "effectiveness_notes": _text(_child(m, "Effectiveness_Notes"))}
                        for m in _children(_child(elem, "Potential_Mitigations"), "Mitigation")[:MAX_CWE_LIST]],
        "examples": examples,
        "observed": [{"reference": _text(_child(o, "Reference"), 60),
                      "description": _text(_child(o, "Description"), MAX_SHORT),
                      "link": _text(_child(o, "Link"), MAX_SOURCE)}
                     for o in _children(_child(elem, "Observed_Examples"), "Observed_Example")[:MAX_OBSERVED]],
        "functional_areas": [t for t in (_text(f, 200)
                                         for f in _children(_child(elem, "Functional_Areas"), "Functional_Area")
                                         [:MAX_CWE_LIST]) if t],
        "affected_resources": [t for t in (_text(f, 200)
                                           for f in _children(_child(elem, "Affected_Resources"), "Affected_Resource")
                                           [:MAX_CWE_LIST]) if t],
        "taxonomies": [{"name": str(t.get("Taxonomy_Name") or "")[:100],
                        "entry_id": _text(_child(t, "Entry_ID"), 100),
                        "entry_name": _text(_child(t, "Entry_Name"), 300),
                        "mapping_fit": _text(_child(t, "Mapping_Fit"), 100)}
                       for t in _children(_child(elem, "Taxonomy_Mappings"), "Taxonomy_Mapping")[:MAX_CWE_LIST]],
        "attack_patterns": [f"CAPEC-{a.get('CAPEC_ID').strip()}"
                            for a in _children(_child(elem, "Related_Attack_Patterns"), "Related_Attack_Pattern")
                            [:MAX_CWE_LIST] if re.fullmatch(r"\d{1,7}", str(a.get("CAPEC_ID") or "").strip())],
        "references": _record_refs(elem),
        "mapping_notes": _mapping_notes(elem),
        "notes": _cwe_notes(elem),
    })


def parse_cwe_ref(elem: ET.Element) -> dict | None:
    """Ссылка <External_Reference> каталога CWE -> словарь справочника источников; без Reference_ID – None."""
    ref_id = str(elem.get("Reference_ID") or "").strip()[:60]
    if not ref_id:
        return None
    date = "-".join(x for x in (_text(_child(elem, "Publication_Year"), 20),
                                _text(_child(elem, "Publication_Month"), 20).lstrip("-"),
                                _text(_child(elem, "Publication_Day"), 20).lstrip("-")) if x)
    return {"id": ref_id,
            "authors": [t for t in (_text(a, 300) for a in _children(elem, "Author")[:20]) if t],
            "title": _text(_child(elem, "Title"), MAX_SHORT),
            "edition": _text(_child(elem, "Edition"), 200),
            "publication": _text(_child(elem, "Publication"), MAX_SHORT),
            "publisher": _text(_child(elem, "Publisher"), 300),
            "date": date[:40],
            "url": _text(_child(elem, "URL"), MAX_SOURCE)}


# Виды обратных связей: на странице CWE-89 виден и родитель (ChildOf у записи), и дети (ParentOf – вычислен).
_REVERSE_NATURE = {"ChildOf": "ParentOf", "ParentOf": "ChildOf", "CanPrecede": "CanFollow",
                   "CanFollow": "CanPrecede", "PeerOf": "PeerOf", "CanAlsoBe": "CanAlsoBe",
                   "Requires": "RequiredBy", "RequiredBy": "Requires"}


def cwe_links_of(record: dict) -> list[tuple[str, str, str]]:
    """Связи записи для таблицы cwe_links: (номер, вид, другой номер) – прямые из записи и обратные вычисленные
    (ParentOf, CanFollow, MemberOf); симметричные (PeerOf, CanAlsoBe) пишутся в обе стороны."""
    owner = record["id"]
    rows = []
    if record["kind"] == "category":
        for member in record.get("relationships", []):
            rows.append((owner, "HasMember", member["cwe_id"]))
            rows.append((member["cwe_id"], "MemberOf", owner))
        return rows
    for rel in record.get("related", []):
        nature, other = rel["nature"], rel["cwe_id"]
        rows.append((owner, nature, other))
        back = _REVERSE_NATURE.get(nature)
        if back:
            rows.append((other, back, owner))
    return rows


# ============================================================================ хранилище

from .capec import TABLES as CAPEC_TABLES  # noqa: E402

# Таблицы создаёт миграция 0002 (ADR-0133): схема feeds – действующие справочники, feeds_imp – идущая загрузка той же структуры
_KIND_TABLES = {"bdu": ("bdu", "bdu_cve", "cwe_ru"),
                "cwe": ("cwe", "cwe_refs", "cwe_links", "cwe_index", "cwe_capec"),
                "capec": tuple(CAPEC_TABLES)}
_TABLES = tuple(table for tables in _KIND_TABLES.values() for table in tables)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _mb(value: int) -> int:
    return value // (1024 * 1024)


class FeedStore:
    """Справочники в схеме feeds базы PostgreSQL. target – хранилище приложения (одна база, один пул и общий замок экземпляра) или адрес
    базы для отдельного запуска. Загрузка пишет пачками по BATCH записей, каждая пачка – короткая транзакция без общего замка писателя:
    работа операторов не ждёт ни загрузки, ни подмены. Открытие хранилища ничего не пишет."""

    def __init__(self, target: Any, write_guard: Callable[[], None] | None = None):
        self._owns = not isinstance(target, PostgresStore)
        self._store = PostgresStore(conninfo_for(target)) if self._owns else target
        self._guard = write_guard
        self._lock = threading.RLock()
        self._cancel = threading.Event()
        self._capec_cache = None

    def close(self) -> None:
        with self._lock:
            self._capec_cache = None
            if self._owns:
                self._store.close()

    @property
    def _conn(self) -> Any:
        """Соединение текущего контекста (страницы или транзакции); вне контекста – отдельные запросы."""
        return self._store.current()

    @staticmethod
    def _rebuild_cwe_capec(conn) -> None:
        """Пары CWE и CAPEC из записей каталога CWE: в загрузке, до подмены."""
        from .capec import identifier
        for ident, raw in conn.execute("SELECT id,data_json FROM feeds_imp.cwe ORDER BY id").fetchall():
            pairs = [(ident, identifier(x)) for x in json.loads(raw).get('attack_patterns', [])]
            conn.executemany("INSERT INTO feeds_imp.cwe_capec VALUES (?,?) ON CONFLICT DO NOTHING", [(a,b) for a,b in pairs if b])

    def capec_data(self, *, shared: bool = False) -> dict:
        """Полный снимок. shared – общий снимок для чтения страницами; его записи изменять нельзя.

        Обычный вызов возвращает независимые данные. Общий снимок заменяется вместе с каталогом;
        уже открытая страница сохраняет прежний согласованный объект до окончания отрисовки.
        """
        with self.snapshot():
            # страница со своим снимком базы читает им: общий кэш от другого момента времени ей не подходит, а её данные не годятся другим
            shared = shared and not self._store.in_context()
            if shared and self._capec_cache is not None:
                return self._capec_cache
            def read(table):
                return {ident: json.loads(raw) for ident, raw in self._conn.execute(f"SELECT id,data_json FROM feeds.{table} ORDER BY id")}
            data = {"records": read('capec'), "refs": read('capec_refs'),
                    "profile": read('capec_meta').get('catalog', {}), "meta": self.status().get('capec', {})}
            if shared:
                self._capec_cache = data
            return data

    def capec_for_cwes(self, values) -> dict:
        from .capec import identifier
        keys = {identifier(x, 'CWE') for x in values} - {''}
        result = {}
        if not keys: return result
        with self.snapshot():
            for table, source, cwe_col in [('capec_cwe','CAPEC','cwe'), ('cwe_capec','CWE','cwe')]:
                # Каталог мал; фильтр значений применяется к двум нормализованным индексам, без JSON записей.
                for ident, cwe in self._conn.execute(f"SELECT id,{cwe_col} FROM feeds.{table} ORDER BY id,{cwe_col}"):
                    if cwe in keys:
                        item = result.setdefault(ident, {"sources": [], "cwes": []})
                        if source not in item['sources']: item['sources'].append(source)
                        if cwe not in item['cwes']: item['cwes'].append(cwe)
        return result

    @contextmanager
    def snapshot(self) -> Iterator[FeedStore]:
        """Несколько чтений одним согласованным снимком: COMMIT подмены (_swap, под той же блокировкой) не вклинится между ними, и страница
        не смешает запись одной версии каталога с подписью другой. У страницы с открытым контекстом базы снимок уже есть, блокировка ей не
        нужна: она держит соединение, а подмена держит соединение и ждёт блокировку, ждать друг друга им нельзя."""
        if self._store.in_context():
            yield self
            return
        with self._lock:
            yield self

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        """Транзакция справочников: чужие таблицы она не трогает, поэтому общего замка писателя не берёт."""
        with self._store.transaction(self._guard, exclusive=False) as conn:
            yield conn

    def _clear_staging(self) -> None:
        """Очистка feeds_imp. Вызывается только владельцем загрузки (IMPORT_LOCK)."""
        with self._tx() as c:
            c.execute("TRUNCATE " + ", ".join(f"feeds_imp.{table}" for table in _TABLES))

    def staging_rows(self) -> int:
        """Сколько строк сейчас в feeds_imp: после загрузки при любом исходе – ноль."""
        return sum(int(self._conn.execute(f"SELECT COUNT(*) FROM feeds_imp.{table}").fetchone()[0]) for table in _TABLES)

    def _used_bytes(self) -> int:
        """Сколько занимают справочники и идущая загрузка."""
        return int(self._store.read(lambda c: c.execute(
            "SELECT COALESCE(SUM(pg_total_relation_size(t.oid)), 0) FROM pg_class t JOIN pg_namespace n ON n.oid = t.relnamespace"
            " WHERE n.nspname IN ('feeds', 'feeds_imp') AND t.relkind = 'r'").fetchone()[0]))

    def _check_space(self, need: int = 0) -> None:
        """Проверка ДО записи need байт: справочники вместе с идущей загрузкой – не больше MAX_DB_BYTES. Свободное место на диске сервера
        приложению не видно: его нехватка – отказ PostgreSQL, откат и понятная ошибка загрузки."""
        if self._used_bytes() + need > MAX_DB_BYTES:
            raise FeedError(i18n._("Справочники выросли бы больше {limit} МБ – загрузка остановлена.", limit=_mb(MAX_DB_BYTES)))

    # ------------------------------------------------------------------ чтение

    def status(self) -> dict[str, dict]:
        """Что загружено: {kind: {filename, loaded_at, records, ref_records, version, source_date, xml_bytes, seconds}}."""
        with self.snapshot():
            cursor = self._conn.execute("SELECT * FROM feeds.feed_meta ORDER BY kind")
            names = [d[0] for d in cursor.description]
            rows = cursor.fetchall()
        return {row[0]: dict(zip(names, row, strict=True)) for row in rows}

    def reference_status(self, kind: str, key: str) -> str:
        """Пометка отсутствующей цели; исходный ID и ссылка остаются доступны оператору."""
        if kind not in {"cwe", "capec"}:
            return ""
        with self.snapshot():
            if not self._conn.execute("SELECT 1 FROM feeds.feed_meta WHERE kind=?", (kind,)).fetchone():
                return i18n._("каталог {catalog} не загружен", catalog=kind.upper())
            found = self._conn.execute(f"SELECT 1 FROM feeds.{kind} WHERE id=?", (key,)).fetchone()
        return "" if found else i18n._("нет в загруженном каталоге")

    def cwe_info(self, ids: Iterable[str]) -> dict[str, dict]:
        """Классы CWE: {«CWE-89»: {id, name, description, extended, kind, name_ru}}; name_ru – русское название
        из выгрузки БДУ, если она загружена. Неизвестных номеров в ответе нет."""
        keys = sorted({k for k in (cwe_key(x) for x in ids) if k})
        if not keys:
            return {}
        marks = ",".join("?" * len(keys))
        with self.snapshot():
            found = {row[0]: json.loads(row[1]) for row in self._conn.execute(
                f"SELECT id, data_json FROM feeds.cwe WHERE id IN ({marks})", keys)}
            ru = dict(self._conn.execute(f"SELECT id, name_ru FROM feeds.cwe_ru WHERE id IN ({marks})", keys).fetchall())
        result = {}
        for key in keys:
            if key in found or key in ru:
                info = found.get(key) or {"id": key, "name": "", "description": "", "extended": "", "kind": ""}
                # в выгрузке БДУ кавычки внутри названия бывают экранированы обратной косой чертой: \"…\"
                result[key] = {**info, "name_ru": ru.get(key, "").replace('\\"', '"')}
        return result

    def cwe_list(self) -> list[dict]:
        """Все записи каталога CWE для страницы «CWE»: [{id, kind, name, name_ru, abstraction, status}] по номеру.
        Каталог, загруженный прежней версией приложения (индекс пуст), читается из записей прежнего формата:
        абстракции в них нет, карточка такой записи покажет сокращённый вид с подсказкой перезагрузить каталог."""
        with self.snapshot():
            rows = self._conn.execute(
                "SELECT i.id, i.kind, i.name, i.abstraction, i.status, COALESCE(r.name_ru, '') FROM feeds.cwe_index i "
                "LEFT JOIN feeds.cwe_ru r ON r.id = i.id").fetchall()
            if not rows:
                rows = []
                for raw_id, data_json in self._conn.execute("SELECT id, data_json FROM feeds.cwe ORDER BY id"):
                    data = json.loads(data_json)
                    rows.append((raw_id, data.get("kind", ""), data.get("name", ""), "", data.get("status", ""), ""))
                if rows:
                    ru = dict(self._conn.execute("SELECT id, name_ru FROM feeds.cwe_ru").fetchall())
                    rows = [(i, k, n, a, s, ru.get(i, "")) for i, k, n, a, s, _ in rows]
        items = [{"id": i, "kind": k, "name": n, "abstraction": a, "status": s, "name_ru": ru.replace('\\"', '"')}
                 for i, k, n, a, s, ru in rows]
        items.sort(key=lambda x: int(x["id"][4:]) if x["id"][4:].isdigit() else 0)
        return items

    def cwe_page(self, key: str) -> dict | None:
        """Карточка класса CWE: {record, links, name_ru}; links – {вид связи: [номера]} (связи вычислены при
        загрузке каталога, cwe_links_of). None – такой записи нет."""
        key = cwe_id(key)
        if not key:
            return None
        with self.snapshot():
            row = self._conn.execute("SELECT data_json FROM feeds.cwe WHERE id = ?", (key,)).fetchone()
            if row is None:
                return None
            record = json.loads(row[0])
            grouped: dict[str, list[str]] = {}
            for rel, other in self._conn.execute("SELECT rel, other_id FROM feeds.cwe_links WHERE id = ?", (key,)):
                grouped.setdefault(rel, []).append(other)
            ru = self._conn.execute("SELECT name_ru FROM feeds.cwe_ru WHERE id = ?", (key,)).fetchone()
        for rel in grouped:
            grouped[rel] = sorted(set(grouped[rel]), key=lambda x: int(x[4:]) if x[4:].isdigit() else 0)
        return {"record": record, "links": grouped, "name_ru": (ru[0].replace('\\"', '"') if ru else "")}

    def cwe_refs(self, ids: Iterable[str]) -> dict[str, dict]:
        """Источники каталога CWE по номерам: {«REF-44»: {id, authors, title, edition, publication, publisher,
        date, url}}; неизвестных номеров в ответе нет."""
        keys = sorted({str(i).strip()[:60] for i in ids if str(i or "").strip()})
        if not keys:
            return {}
        marks = ",".join("?" * len(keys))
        with self.snapshot():
            return {row[0]: json.loads(row[1]) for row in self._conn.execute(
                f"SELECT id, data_json FROM feeds.cwe_refs WHERE id IN ({marks})", keys)}

    def bdu_by_cve(self, cves: Iterable[str]) -> dict[str, list[dict]]:
        """Записи БДУ, где CVE указан среди идентификаторов: {CVE: [запись]} (поля – parse_bdu)."""
        keys = sorted({str(c).upper() for c in cves if _CVE.fullmatch(str(c or ""))})
        result: dict[str, list[dict]] = {}
        if not keys:
            return result
        marks = ",".join("?" * len(keys))
        with self.snapshot():
            rows = self._conn.execute(
                f"SELECT c.cve, b.data_json FROM feeds.bdu_cve c JOIN feeds.bdu b ON b.id = c.bdu_id WHERE c.cve IN ({marks})"
                " ORDER BY c.cve, b.id", keys).fetchall()
        for cve, data in rows:
            result.setdefault(cve, []).append(json.loads(data))
        return result

    def counts(self) -> dict[str, int]:
        with self.snapshot():
            return {table: int(self._conn.execute(f"SELECT COUNT(*) FROM feeds.{table}").fetchone()[0])
                    for table in _TABLES}

    # ------------------------------------------------------------------ загрузка

    def cancel(self) -> bool:
        """Просьба остановить идущую загрузку: она прервётся на ближайшем куске или пачке, feeds_imp очистится,
        прежний справочник останется. True – загрузка шла."""
        if _IMPORT_SLOT.locked():
            self._cancel.set()
            return True
        return False

    def load(self, kind: str, archive_path: Path, filename: str, *, deadline_s: float | None = None) -> dict:
        """Загружает справочник kind из архива: разбор, запись в feeds_imp, подмена прежнего справочника одной транзакцией. Возвращает
        сведения feed_meta.

        FeedError – файл не принят, загрузка остановлена (cancel), не уложилась в срок deadline_s (по умолчанию MAX_IMPORT_SECONDS) или
        справочники больше предела; вторая загрузка во время первой, в том числе другим процессом, – FeedError(BUSY). При любом исходе
        feeds_imp очищается, прежний справочник остаётся."""
        if kind not in KINDS:
            raise FeedError(i18n._("Неизвестный справочник."))
        if not _IMPORT_SLOT.acquire(blocking=False):
            raise FeedError(i18n._(BUSY))
        self._cancel.clear()
        started = datetime.now(UTC)
        limit = MAX_IMPORT_SECONDS if deadline_s is None else deadline_s
        deadline = time.monotonic() + limit

        def check() -> None:
            if self._cancel.is_set():
                raise FeedError(i18n._(CANCELLED))
            if time.monotonic() > deadline:
                minutes = limit / 60
                shown = i18n._("{minutes:.0f} мин", minutes=minutes) if minutes >= 1 else i18n._("{limit:g} с", limit=limit)
                raise FeedError(i18n._("Загрузка не уложилась в {shown} и остановлена: прежний справочник не "
                                       "изменился.", shown=shown))

        owner = None
        try:
            owner = self._own_import()
            try:
                archive = zipfile.ZipFile(archive_path)
            except (zipfile.BadZipFile, OSError):
                raise FeedError(i18n._("Это не архив ZIP: загрузите файл .zip как он скачан с сайта.")) from None
            with archive:
                info = _member(archive, kind)
                self._check_space()
                self._clear_staging()
                meta = self._fill(kind, archive, info, check)
                if kind == "cwe":
                    with self._tx() as c:
                        self._rebuild_cwe_capec(c)
                check()
            seconds = round((datetime.now(UTC) - started).total_seconds(), 1)
            meta.update(kind=kind, filename=str(filename)[:200], loaded_at=_now(), xml_bytes=info.file_size,
                        seconds=seconds)
            self._swap(kind, meta)
            return meta
        except psycopg.errors.DiskFull:
            raise FeedError(i18n._("На диске базы закончилось место: загрузка остановлена, прежний справочник "
                                   "не изменился.")) from None
        finally:
            try:
                if owner is not None:
                    try:
                        self._clear_staging()
                    except Exception as e:  # исход загрузки уже известен; остаток убирает следующая загрузка
                        log.warning("после загрузки справочника не очищена feeds_imp: %s", type(e).__name__)
                    finally:
                        owner.close()
            finally:
                self._cancel.clear()
                _IMPORT_SLOT.release()

    def _own_import(self) -> Any:
        """Сессионная блокировка владения feeds_imp на отдельном соединении: второй процесс получает отказ и чужую загрузку не чистит.
        Соединение закрывается в конце загрузки, обрыв снимает блокировку сам."""
        conn = psycopg.connect(self._store.conninfo, autocommit=True, application_name="local-triage-feeds")
        if not conn.execute("SELECT pg_try_advisory_lock(%s)", (IMPORT_LOCK,)).fetchone()[0]:
            conn.close()
            raise FeedError(i18n._(BUSY))
        return conn

    def _swap(self, kind: str, meta: dict) -> None:
        """Подмена прежнего справочника новым одной транзакцией. Страница, начатая раньше, дочитывает прежнюю версию своим снимком; COMMIT –
        под блокировкой snapshot, поэтому несколько чтений страницы не разойдутся. Сбой внутри – откат: прежний справочник цел."""
        self._check_space(self._store.read(lambda c: c.execute(
            "SELECT COALESCE(SUM(pg_total_relation_size(t.oid)), 0) FROM pg_class t JOIN pg_namespace n ON n.oid = t.relnamespace"
            " WHERE n.nspname = 'feeds_imp' AND t.relkind = 'r'").fetchone()[0]))
        locked = False
        try:
            with self._tx() as c:
                if kind in {"cwe", "capec"}:
                    current = self.status().get(kind)
                    if current:
                        self._check_catalog_update(kind, current, meta)
                for table in _KIND_TABLES[kind]:
                    c.execute(f"DELETE FROM feeds.{table}")
                    c.execute(f"INSERT INTO feeds.{table} SELECT * FROM feeds_imp.{table}")
                c.execute("INSERT INTO feeds.feed_meta(kind, filename, loaded_at, records, version, source_date, ref_records, xml_bytes,"
                          " seconds) VALUES (%(kind)s, %(filename)s, %(loaded_at)s, %(records)s, %(version)s, %(source_date)s, %(ref_records)s,"
                          " %(xml_bytes)s, %(seconds)s) ON CONFLICT (kind) DO UPDATE SET filename = EXCLUDED.filename,"
                          " loaded_at = EXCLUDED.loaded_at, records = EXCLUDED.records, version = EXCLUDED.version,"
                          " source_date = EXCLUDED.source_date, ref_records = EXCLUDED.ref_records, xml_bytes = EXCLUDED.xml_bytes,"
                          " seconds = EXCLUDED.seconds", meta)
                c.execute("TRUNCATE " + ", ".join(f"feeds_imp.{table}" for table in _TABLES))
                self._lock.acquire()
                locked = True
                if kind == 'capec':
                    self._capec_cache = None
        finally:
            if locked:
                self._lock.release()

    @staticmethod
    def _check_catalog_update(kind: str, current: dict, incoming: dict) -> None:
        """Версии CWE/CAPEC – числовые компоненты; дату проверяем независимо, внутри подмены."""
        old, new = (str(item.get("version", "")).strip() for item in (current, incoming))
        pattern = r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,5}"
        if old != new:
            if re.fullmatch(pattern, old) and not re.fullmatch(pattern, new):
                raise FeedError(i18n._("Нельзя сравнить версию {kind} «{new}» с «{old}». Текущий каталог сохранён.",
                                       kind=kind.upper(), new=new or i18n._("не указана"), old=old))
            if re.fullmatch(pattern, old) and re.fullmatch(pattern, new):
                before, after = (tuple(map(int, v.split('.'))) for v in (old, new))
                width = max(len(before), len(after))
                if after + (0,) * (width-len(after)) < before + (0,) * (width-len(before)):
                    raise FeedError(i18n._("Версия {catalog} {new} старее загруженной {old}. Текущий каталог "
                                           "сохранён.", catalog=kind.upper(), new=new, old=old))
        dates = []
        for item in (current, incoming):
            value = str(item.get("source_date", ""))
            try:
                dates.append(datetime.strptime(value, "%Y-%m-%d").date() if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) else None)
            except ValueError:
                dates.append(None)
        if dates[0] and not dates[1]:
            raise FeedError(i18n._("Нельзя сравнить дату {catalog} с загруженным каталогом. Текущий каталог "
                                   "сохранён.", catalog=kind.upper()))
        if dates[0] and dates[1] and dates[1] < dates[0]:
            raise FeedError(i18n._("Дата источника {catalog} {date} старее загруженной {loaded}. Текущий "
                                   "каталог сохранён.", catalog=kind.upper(), date=dates[1], loaded=dates[0]))

    def _fill(self, kind: str, archive: zipfile.ZipFile, info: zipfile.ZipInfo, check: Callable[[], None]) -> dict:
        if kind == 'capec':
            from .capec import fill
            return fill(self, archive, info, check)
        root_attrs: dict[str, str] = {}
        records = 0
        ref_records = 0  # ссылки External_References каталога CWE: хранятся, но в счёт записей каталога не идут
        latest = ""
        batch: list[tuple[str, list[tuple]]] = []

        def flush() -> None:
            if not batch:
                return
            check()
            # место – до записи пачки: её размер с запасом на индексы и служебные страницы
            need = sum(len(str(v).encode("utf-8")) + 16 for _, rows in batch for row in rows for v in row)
            self._check_space(BATCH_SPACE_FACTOR * need + 64 * 1024)
            with self._tx() as c:
                for sql, rows in batch:
                    c.executemany(sql, rows)
            batch.clear()

        tags = {"vul"} if kind == "bdu" else {"Weakness", "Category", "External_Reference"}
        bdu_rows: list[tuple] = []
        cve_rows: list[tuple] = []
        ru: dict[str, str] = {}
        cwe_rows: list[tuple] = []
        ref_rows: list[tuple] = []
        link_rows: list[tuple] = []
        index_rows: list[tuple] = []
        bdu_sql = "INSERT INTO feeds_imp.bdu(id, data_json) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET data_json = EXCLUDED.data_json"
        cve_sql = "INSERT INTO feeds_imp.bdu_cve(cve, bdu_id) VALUES (?, ?) ON CONFLICT DO NOTHING"
        cwe_sql = "INSERT INTO feeds_imp.cwe(id, data_json) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET data_json = EXCLUDED.data_json"
        ref_sql = "INSERT INTO feeds_imp.cwe_refs(id, data_json) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET data_json = EXCLUDED.data_json"
        link_sql = "INSERT INTO feeds_imp.cwe_links(id, rel, other_id) VALUES (?, ?, ?) ON CONFLICT DO NOTHING"
        index_sql = ("INSERT INTO feeds_imp.cwe_index(id, kind, name, abstraction, status) VALUES (?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET"
                     " kind = EXCLUDED.kind, name = EXCLUDED.name, abstraction = EXCLUDED.abstraction, status = EXCLUDED.status")
        with archive.open(info) as stream:
            chunks = guarded_chunks(stream, compressed=info.compress_size)
            for elem in iter_records(chunks, tags, on_root=lambda r: root_attrs.update(r.attrib), check=check):
                if kind == "bdu":
                    record = parse_bdu(elem)
                elif _local(elem.tag) == "External_Reference":
                    record = parse_cwe_ref(elem)
                else:
                    record = parse_cwe(elem)
                if record is None:
                    continue
                if kind == "cwe" and _local(elem.tag) == "External_Reference":
                    ref_records += 1
                else:
                    records += 1
                if records + ref_records > MAX_RECORDS[kind]:
                    raise FeedError(i18n._("Записей больше {limit}: это не похоже на выгрузку {feed}.", limit=MAX_RECORDS[kind], feed=KINDS[kind]))
                if kind == "bdu":
                    latest = max(latest, record["updated"] or record["published"])
                    bdu_rows.append((record["id"], json.dumps(record, ensure_ascii=False)))
                    cve_rows += [(cve, record["id"]) for cve in record["cves"]]
                    for cwe in record["cwes"]:
                        if cwe["name"] and cwe["id"] not in ru:
                            ru[cwe["id"]] = cwe["name"]
                elif _local(elem.tag) == "External_Reference":
                    ref_rows.append((record["id"], json.dumps(record, ensure_ascii=False)))
                else:
                    link_rows += cwe_links_of(record)
                    index_rows.append((record["id"], record["kind"], record["name"],
                                       record.get("abstraction", ""), record.get("status", "")))
                    cwe_rows.append((record["id"], json.dumps(record, ensure_ascii=False)))
                if len(bdu_rows) + len(cwe_rows) + len(ref_rows) >= BATCH:
                    batch.extend([(bdu_sql, bdu_rows), (cve_sql, cve_rows), (cwe_sql, cwe_rows),
                                  (ref_sql, ref_rows), (link_sql, link_rows), (index_sql, index_rows)])
                    batch[:] = [(sql, rows) for sql, rows in batch if rows]
                    flush()
                    bdu_rows, cve_rows, cwe_rows = [], [], []
                    ref_rows, link_rows, index_rows = [], [], []
        if kind == "bdu":
            batch += [(bdu_sql, bdu_rows), (cve_sql, cve_rows),
                      ("INSERT INTO feeds_imp.cwe_ru(id, name_ru) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET name_ru = EXCLUDED.name_ru", list(ru.items()))]
        else:
            batch += [(cwe_sql, cwe_rows), (ref_sql, ref_rows), (link_sql, link_rows), (index_sql, index_rows)]
        batch[:] = [(sql, rows) for sql, rows in batch if rows]
        flush()
        if not records:
            raise FeedError(i18n._("В файле нет записей {feed}: проверьте, что загружен нужный архив.", feed=KINDS[kind]))
        version = str(root_attrs.get("Version") or "")[:40]
        source_date = str(root_attrs.get("Date") or "")[:40] if kind == "cwe" else latest
        # число ссылок каталога (External_References) в счёт записей не идёт, но в meta остаётся
        return {"records": records, "ref_records": ref_records, "version": version, "source_date": source_date}

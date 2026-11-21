"""Версия обновления в служебном блоке Hub у дефектов SCA (ADR-0132).

Hub один раз, при создании дефекта, формирует описание с «Версией исправления» из данных сканера, а рекомендацию команды
приложение берёт из исследования компонента. Читатель дефекта должен видеть одну версию: в блоке она заменяется на целевую
версию рекомендации, дальше описание синхронизируется целиком.

Заменяются только значения в формах Hub, не поиск по всему тексту: тот же номер встречается в ссылках и именах файлов.

- таблица «Сводка по уязвимостям»: колонка «Версия исправления»;
- таблица «поле – значение»: строка с заголовком «Версия исправления»;
- сводка одной находки: абзац «Версия исправления: X»;
- подробности находки: абзац «Обновление <компонент> до версии X».

Ссылка внутри значения остаётся: меняется текст, `href` нет. Значение со сложной разметкой не трогается, оператор видит пометку.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

_FLAGS = re.S | re.I
_TABLE = re.compile(r"<table\b.*?</table>", _FLAGS)
_ROW = re.compile(r"<tr\b[^>]*>.*?</tr>", _FLAGS)
_CELL = re.compile(r"<(t[hd])\b[^>]*>(.*?)</t[hd]>", _FLAGS)
_TAG = re.compile(r"<[^>]+>")
_VERSION_LIKE = re.compile(r"^v?\d")
_PARAGRAPH = re.compile(r"<p\b[^>]*>(.*?)</p>", _FLAGS)
_BREAK = re.compile(r"<br\b[^>]*>", _FLAGS)
# После «до версии» значение может быть пустым: `_plain` срезает хвостовой пробел, поэтому пробел перед значением необязателен.
_LINE_VALUE = re.compile(r"^(?:Версия исправления:\s*|Обновление\s+.+?\s+до\s+версии(?:\s+|$))(.*)$", re.S)
_TEXT_TARGET = re.compile(r"^[ \t]*Обновление\s+.+?\s+до\s+версии\s+(\S+?)[.;,]?[ \t]*$", re.M)
HEADER = "Версия исправления"
NO_TARGET_NOTE = ("В тексте дефекта нет одной строки «Обновление … до версии …»: версия в служебном блоке Hub оставлена как есть, "
                  "она может расходиться с рекомендацией.")
COMPLEX_NOTE = "В служебном блоке Hub есть версия со сложной разметкой, она не заменена: {values}. Проверьте её в предпросмотре."


@dataclass(frozen=True)
class Retarget:
    """Итог замены: block – блок после неё; target – целевая версия; previous – прежние значения; places – сколько мест изменено;
    notes – что оператору нужно знать: цели нет, значение не заменено."""

    block: str
    target: str = ""
    previous: tuple[str, ...] = ()
    places: int = 0
    notes: tuple[str, ...] = ()

    def view(self) -> dict:
        """Сведения для предпросмотра: пусто, если блок не менялся."""
        if not self.places:
            return {}
        return {"to": self.target, "from": list(self.previous), "places": self.places}


def _plain(value: str) -> str:
    return " ".join(html.unescape(_TAG.sub(" ", value)).split())


def target_of(command_text: str) -> str:
    """Целевая версия из рекомендации текста дефекта SCA: строка «Обновление X до версии V». Нет такой строки или версии
    в тексте разные – «»: выбирать за оператора нельзя, блок тогда не меняется."""
    text = str(command_text or "").replace("\r\n", "\n").replace("\r", "\n")  # форма карточки сохраняет переводы строк браузера
    versions = {m.group(1) for m in _TEXT_TARGET.finditer(text)}
    return versions.pop() if len(versions) == 1 else ""


def _form_lines(block: str) -> list[tuple[int, int, str, str]]:
    """Строки абзацев с формой версии: (начало, конец, разметка, текст абзаца после этой строки). Строка – часть абзаца между `<br>`:
    Hub может соединить заголовок «Рекомендации» и саму рекомендацию в один абзац."""
    found: list[tuple[int, int, str, str]] = []
    for para in _PARAGRAPH.finditer(block):
        start = para.start(1)
        pieces = _BREAK.split(para.group(1))
        breaks = [m.group(0) for m in _BREAK.finditer(para.group(1))] + [""]
        for at, (piece, gap) in enumerate(zip(pieces, breaks, strict=True)):
            if _LINE_VALUE.match(_plain(piece)):
                found.append((start, start + len(piece), piece, _plain(" ".join(pieces[at + 1:]))))
            start += len(piece) + len(gap)
    return found


def _line_places(block: str) -> tuple[list[tuple[int, int, str, str]], list[str]]:
    """Абзацы «Версия исправления: X» и «Обновление … до версии X»: где значение, какое и что вставить перед новым значением.
    Значение – конец последнего текстового узла: вложенные теги перед ним и ссылка вокруг него остаются. Значение не умещается в один
    узел – в список пропущенных, оператор видит пометку."""
    places: list[tuple[int, int, str, str]] = []
    skipped: list[str] = []
    for line_start, _, inner, after in _form_lines(block):
        found = _LINE_VALUE.match(_plain(inner))
        value = found.group(1).strip() if found else ""
        nodes = [m for m in re.finditer(r"[^<>]+", _TAG.sub(lambda t: "<" * len(t.group(0)), inner)) if m.group(0).strip()]
        text = nodes[-1].group(0).rstrip()
        end = nodes[-1].start() + len(text)
        if not value:
            if after and not _plain(inner).startswith("Версия исправления"):
                # «Обновление … до версии» без номера, а в том же абзаце дальше текст («<br>1.0», «<br>V1.0»): это может быть само
                # значение, вставка оставила бы две версии – абзац не трогается, оператор видит пометку. Форма «Версия исправления:»
                # заполняется как до 0.10.0.dev12: иначе маска ранее записанного блока разошлась бы с пустой заготовкой.
                skipped.append(after.split()[0])
                continue
            # пробел перед номером решается по видимому тексту: последняя буква может быть записана сущностью
            seen = html.unescape(nodes[-1].group(0))
            at = line_start + nodes[-1].end()
            # только после буквы или цифры («до версии»); после «:» – как раньше, без пробела: иначе маска записанной формы
            # «:2.0» и пустой «:» разошлась бы
            places.append((at, at, "", " " if seen[-1:].isalnum() else ""))
            continue
        raw = next((form for form in (value, html.escape(value, quote=False)) if text.endswith(form)), "")
        if not raw:
            skipped.append(value)
            continue
        places.append((line_start + end - len(raw), line_start + end, value, ""))
    return places, skipped


def _value_span(cell_start: int, inner: str) -> tuple[int, int] | None:
    """Где в ячейке само значение: единственный непустой текстовый узел, без ведущих и хвостовых пробелов. Узлов нет – пустое
    значение: место прямо внутри ячейки. Узлов несколько – разметка сложная, None."""
    nodes = [m for m in re.finditer(r"[^<>]+", _TAG.sub(lambda t: "\0" * len(t.group(0)), inner).replace("\0", "<"))
             if m.group(0).strip()]
    if not nodes:
        return cell_start, cell_start + len(inner) if not _TAG.search(inner) else cell_start
    if len(nodes) > 1:
        return None
    text = nodes[0].group(0)
    start = nodes[0].start() + len(text) - len(text.lstrip())
    return cell_start + start, cell_start + start + len(text.strip())


def _table_cells(block: str) -> tuple[list[tuple[int, int, str]], list[str]]:
    """Ячейки «Версии исправления» в таблицах блока: (начало внутренней части, конец, разметка) и значения, которые трогать нельзя. Два
    вида таблиц: колонка с заголовком в первой строке и строка «заголовок – значение» из двух ячеек. Заголовки колонок бывают и в `<td>`:
    две ячейки `<td>` подряд считаются парой, только если вторая похожа на версию или пуста, иначе понять нельзя, оператор видит пометку."""
    found: list[tuple[int, int, str]] = []
    unclear: list[str] = []
    for table in _TABLE.finditer(block):
        column: int | None = None
        for row in _ROW.finditer(table.group(0)):
            cells = list(_CELL.finditer(row.group(0)))
            names = [_plain(c.group(2)) for c in cells]
            base = table.start() + row.start()
            if HEADER in names:
                at = names.index(HEADER)
                if at == 0 and len(cells) == 2 and cells[1].group(1).lower() == "td":  # «заголовок – значение» в одной строке
                    cell = cells[1]
                    if cells[0].group(1).lower() == "th" or not names[1] or _VERSION_LIKE.match(names[1]):
                        found.append((base + cell.start(2), base + cell.end(2), cell.group(2)))
                    else:
                        unclear.append(names[1])
                    continue
                column = at
                continue
            if column is not None and column < len(cells):
                cell = cells[column]
                found.append((base + cell.start(2), base + cell.end(2), cell.group(2)))
    return found, unclear


def retarget(block: str, target: str) -> Retarget:
    """Заменить версию в формах блока на target. Без целевой версии блок не меняется. Диапазоны замен не пересекаются: абзац формы
    внутри ячейки считается абзацем, сама ячейка не заменяется. Повторный вызов ничего не меняет."""
    text = str(block or "")
    if not text or not target:
        return Retarget(text, target)
    spans, skipped = _line_places(text)
    paragraphs = [(start, end) for start, end, _, _ in _form_lines(text)]
    cells, unclear = _table_cells(text)
    skipped = skipped + unclear
    for start, end, inner in cells:
        if any(start <= a and b <= end for a, b in paragraphs):
            continue
        value = _plain(inner)
        if value == target:
            continue
        span = _value_span(start, inner)
        if span is None:
            skipped.append(value)
            continue
        spans.append((span[0], span[1], value, ""))
    changes = [s for s in spans if s[2] != target]
    notes = (COMPLEX_NOTE.format(values=", ".join(sorted(set(skipped)))),) if skipped else ()
    if not changes:
        return Retarget(text, target, notes=notes)
    escaped = html.escape(target, quote=False)
    out = text
    for start, end, _, glue in sorted(changes, key=lambda item: item[0], reverse=True):
        # glue – пробел перед номером у пустой рекомендации без пробела («до версии</p>»), чтобы номер не прилип к слову
        out = out[:start] + glue + escaped + out[end:]
    previous = tuple(sorted({value for _, _, value, _ in changes if value}))
    return Retarget(out, target, previous, len(changes), notes)


def has_version_places(block: str) -> bool:
    """В блоке есть хотя бы одна форма версии: без цели об этом нужно сказать оператору."""
    text = str(block or "")
    return bool(_form_lines(text) or any(_table_cells(text)))


def for_defect(kind: str, command_text: str, block: str) -> Retarget:
    """Замена для дефекта: только SCA, целевая версия – из его текста. Цели нет, а версия в блоке есть – пометка оператору."""
    text = str(block or "")
    if str(kind or "") != "SCA":
        return Retarget(text)
    target = target_of(command_text)
    if not target:
        return Retarget(text, notes=(NO_TARGET_NOTE,) if has_version_places(text) else ())
    return retarget(text, target)


VERSION_MASK = "0"  # одно значение на все формы версии: блоки сравниваются без них


def masked(description: str) -> str:
    """Описание, где значения версии в формах Hub заменены одним и тем же: так два блока, отличающиеся только версией, совпадают,
    а номера находок и компоненты в сравнении остаются. Hub дописывает исходную заготовку к описанию, уже несущему блок с целевой
    версией."""
    return retarget(description, VERSION_MASK).block

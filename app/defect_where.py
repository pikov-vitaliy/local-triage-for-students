"""Раздел «Где исправлять» в тексте дефекта (план dev7, раздел 11; ADR-0134).

Разработчикам нужны минимум кодовая база, ветка и коммит: у них много репозиториев, веток и коммитов. Служебный блок Hub
эти сведения содержит, но блока бывает нет: дефект занесён из Hub, а заготовку Hub не отдал или отдал без описания.
Тогда сведения связанных находок дописываются в конец текста дефекта отдельным разделом. Текст дефекта и описание в Hub
остаются одним текстом, поэтому раздел виден в черновике после записи и переживает «Pull из Hub».

Заголовок раздела нарочно другой: строкой «Информация об объекте сканирования:» Hub отмечает начало своего блока.
Проверка текста по шаблону команды смотрит на текст до раздела (split).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

HEAD = "Где исправлять:"
NOT_SET_M, NOT_SET_F = "не указан", "не указана"
_HEAD_LINE = re.compile(r"^[ \t]*Где исправлять[ \t]*:?[ \t]*$", re.M | re.I)
_COMMIT = re.compile(r"^(https?://\S+?)(?:/-)?/commit/([0-9a-fA-F]{7,64})/?$")
_FIELD = re.compile(r"^[^:\n]{1,40}:\s+\S")  # строка раздела – «поле: значение»
_TEMPLATE = re.compile(r"^(?:Обоснование|Рекомендация|Рекомендации|Описание|Объяснение|Источники)\s*(?::|$)")  # заголовки шаблона команды
_NOT_FIELD = re.compile(r"^(?:\d{1,3}[).]|-\s|Обоснование:|Рекомендация:|Рекомендации:)")  # пункт списка, заголовок шаблона команды


def split(text: Any) -> tuple[str, str]:
    """(текст до раздела, раздел со строкой заголовка). Раздела нет – (текст как есть, ""). Раздел – последняя строка с
    заголовком и всё после неё, если там только строки «поле: значение»: подзаголовок с тем же названием внутри обоснования
    разделом не считается, и текст проверяется по шаблону целиком (ревью, круг 1)."""
    value = str(text or "")
    normal = value.replace("\r\n", "\n")
    heads = list(_HEAD_LINE.finditer(normal))
    if not heads:
        return value, ""
    found = heads[-1]
    tail = [line.strip() for line in normal[found.end():].split("\n") if line.strip()]
    if not tail or not all(_FIELD.match(line) and not _NOT_FIELD.match(line) for line in tail):
        return value, ""
    return normal[:found.start()].rstrip(), normal[found.start():].strip()


def body_of(text: Any) -> str:
    """Текст решения для сравнения с генератором и текстом соседей группы: без раздела и без пустого хвоста – перед разделом
    join убирает хвост, поэтому сравнивать надо так с обеих сторон."""
    return split(text)[0].rstrip()


def own_tail(text: Any) -> str:
    """Что сохранить при «Тексте из решений»: последняя строка с заголовком и всё после неё, в том числе свободной формой.
    Если ниже стоят заголовки шаблона команды, это подзаголовок внутри обоснования: он пересобирается с решением, "" ."""
    normal = str(text or "").replace("\r\n", "\n")
    heads = list(_HEAD_LINE.finditer(normal))
    if not heads:
        return ""
    tail = normal[heads[-1].start():].strip()
    return "" if any(_TEMPLATE.match(line.strip()) for line in tail.split("\n")) else tail


def has_head(text: Any) -> bool:
    """В тексте есть строка с заголовком раздела, в том числе у раздела свободной формы."""
    return _HEAD_LINE.search(str(text or "").replace("\r\n", "\n")) is not None


def join(body: Any, section: str) -> str:
    """Текст и раздел; абзацы разделяет пустая строка, как в остальном тексте дефекта."""
    head = str(body or "").rstrip()
    return f"{head}\n\n{section}" if head and section else (head or section)


def same(one: str, other: str) -> bool:
    """Один и тот же раздел: без учёта пробелов на краях строк и пустых строк."""
    def lines(value: str) -> list[str]:
        return [" ".join(line.split()) for line in str(value or "").split("\n") if line.strip()]
    return lines(one) == lines(other)


def commit_of(link: Any) -> tuple[str, str]:
    """commitLink Hub -> (адрес репозитория, коммит). Вид адреса не узнан – ("", сам адрес): сведение не теряется."""
    value = str(link or "").strip()
    found = _COMMIT.match(value)
    return (found.group(1), found.group(2)) if found else ("", value)


def scan_date(value: Any) -> str:
    """lastScanTs Hub (миллисекунды эпохи) -> дата и время UTC; другое значение – ""."""
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc).strftime("%d.%m.%Y %H:%M")
    return ""


def _text(*values: Any) -> str:
    return next((str(v).strip() for v in values if isinstance(v, str) and v.strip()), "")


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _file(*values: Any) -> str:
    """Имя файла находки. У находки SCA Hub отдаёт «путь : компонент : версия»; путь бывает пустым, и строка начиналась
    с двоеточия («Файлы: : компонент : версия») – двоеточия и пробелы в начале убираются."""
    return re.sub(r"^[\s:]+", "", _text(*values)).strip()


def place_of(link: Mapping, state: Mapping | None, finding: Mapping | None) -> dict:
    """Сведения одной находки: связь из дефекта Hub (commitLink, scanObject, lastScanTs), подробное чтение находки из
    принятого состояния (currentBranch, fileName, codebase), запасной источник – данные находки в приложении. Признак hub –
    Hub сообщил коммит или ветку: без этого сказать разработчикам нечего."""
    detail, brief = _dict((state or {}).get("detail")), _dict((state or {}).get("brief"))
    scan = _dict(link.get("scanObject")) or _dict(brief.get("scanObject"))
    repository, commit = commit_of(link.get("commitLink"))
    branch = _text(detail.get("currentBranch"), brief.get("currentBranch"), link.get("currentBranch"), link.get("branch"), brief.get("branch"))
    return {"codebase": _text(_dict(detail.get("codebase")).get("name"), (finding or {}).get("codebase")),
            "repository": repository, "branch": branch, "commit": commit, "object": _text(scan.get("name")),
            "date": link.get("lastScanTs") if isinstance(link.get("lastScanTs"), (int, float)) else 0,
            "file": _file(detail.get("fileName"), link.get("fileName"), (finding or {}).get("file")),
            "hub": bool(commit or branch)}


def section(places: Iterable[Mapping]) -> str:
    """Раздел по сведениям находок дефекта; Hub не сообщил ни коммита, ни ветки – "". Находки с одной кодовой базой,
    репозиторием, веткой, коммитом и объектом сканирования – один абзац: файлы перечислены, дата – последнего сканирования.
    Разные коммиты и ветки перечислены все, по кодовым базам, без обобщения."""
    items = [dict(p) for p in places]
    if not any(p.get("hub") for p in items):
        return ""
    groups: dict[tuple, dict] = {}
    for p in items:
        key = tuple(str(p.get(k) or "") for k in ("codebase", "repository", "branch", "commit", "object"))
        group = groups.setdefault(key, {"date": 0, "files": set()})
        group["date"] = max(group["date"], p.get("date") or 0)
        if p.get("file"):
            group["files"].add(str(p["file"]))
    blocks = []
    for (codebase, repository, branch, commit, scanned), group in sorted(groups.items()):
        lines = [f"Кодовая база: {codebase or NOT_SET_F}", f"Репозиторий: {repository or NOT_SET_M}",
                 f"Ветка: {branch or NOT_SET_F}", f"Коммит: {commit or NOT_SET_M}"]
        if scanned:
            lines.append(f"Объект сканирования: {scanned}")
        if scan_date(group["date"]):
            lines.append(f"Дата сканирования: {scan_date(group['date'])} UTC")
        if group["files"]:
            lines.append("Файлы: " + ", ".join(sorted(group["files"])))
        blocks.append("\n".join(lines))
    return HEAD + "\n" + "\n\n".join(blocks)

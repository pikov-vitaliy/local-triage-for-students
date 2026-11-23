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

from app import i18n

# Заголовки разделов текста дефекта – одна таблица для генераторов и для разбора (ADR-0158): (русский, английский).
# Генератор пишет заголовок на языке интерфейса (i18n._ по русскому msgid; перевод в каталоге – английский вариант
# отсюда), разбор и проверка узнают оба варианта независимо от текущего языка (variants): текст, сохранённый на одном
# языке, после переключения языка разбирается так же.
HEADS = {
    "where": (i18n.N_("Где исправлять:"), "Where to fix:"),
    "reason": (i18n.N_("Обоснование:"), "Rationale:"),
    "recommendation": (i18n.N_("Рекомендация:"), "Recommendation:"),
    "description": (i18n.N_("Описание"), "Description"),
    "explanation": (i18n.N_("Объяснение"), "Explanation"),
    "recommendations": (i18n.N_("Рекомендации"), "Recommendations"),
    "sources": (i18n.N_("Источники"), "Sources"),
    "also_affected": (i18n.N_("Также затрагивают эту версию:"), "Also affecting this version:"),
}
# подписи строк раздела «Где исправлять» (section) и значение «не указан»: те же правила
FIELDS = {
    "codebase": (i18n.N_("Кодовая база:"), "Codebase:"),
    "repository": (i18n.N_("Репозиторий:"), "Repository:"),
    "branch": (i18n.N_("Ветка:"), "Branch:"),
    "commit": (i18n.N_("Коммит:"), "Commit:"),
    "object": (i18n.N_("Объект сканирования:"), "Scan object:"),
    "date": (i18n.N_("Дата сканирования:"), "Scan date:"),
    "files": (i18n.N_("Файлы:"), "Files:"),
}
HEAD = HEADS["where"][0]
NOT_SET_M, NOT_SET_F = i18n.N_("не указан"), i18n.N_("не указана")
NOT_SET_EN = "not specified"
# строка обновления дефекта SCA (sca_text.body): (русский, английский) шаблон с {component} и {target}
UPDATE_LINE = (i18n.N_("Обновление {component} до версии {target}"), "Update {component} to version {target}")


def variants(pair: tuple[str, str]) -> tuple[str, ...]:
    """Все написания заголовка: русское, английское из таблицы и перевод из каталога, если он другой (каталог правят
    отдельно – разбор от этого не должен ломаться)."""
    ru, en = pair
    return tuple(dict.fromkeys((ru, en, i18n.translate(ru, "en"))))


def variants_in(pair: tuple[str, str], lang: str) -> tuple[str, ...]:
    """Написания заголовка на одном языке документа: «ru» – русское (как до dev38), «en» – английское и перевод из
    каталога. Каркас текста проверяется на языке самого текста: английское слово «Rationale:» в русском обосновании –
    текст оператора, а не второй заголовок (ревью Codex dev38, круг 5)."""
    ru, en = pair
    return (ru,) if lang == "ru" else tuple(v for v in dict.fromkeys((en, i18n.translate(ru, "en"))) if v != ru)


def is_head_in(line: str, key: str, lang: str) -> bool:
    return line in variants_in(HEADS[key], lang)


def head_prefix_in(line: str, key: str, lang: str) -> str:
    return next((v for v in variants_in(HEADS[key], lang) if line.startswith(v)), "")


def head(key: str) -> str:
    """Заголовок раздела на языке интерфейса (для генераторов)."""
    return i18n._(HEADS[key][0])


def is_head(line: str, key: str) -> bool:
    """Строка – заголовок раздела key на любом языке (строка уже нормализована)."""
    return line in variants(HEADS[key])


def head_prefix(line: str, key: str) -> str:
    """Написание заголовка key, с которого начинается строка, или "" («Обоснование: текст» на той же строке)."""
    return next((v for v in variants(HEADS[key]) if line.startswith(v)), "")


def _alternation(*keys: str, colon: bool = True) -> str:
    words = []
    for key in keys:
        for v in variants(HEADS[key]):
            words.append(re.escape(v if colon else v.rstrip(":")))
    return "|".join(dict.fromkeys(words))


_patterns_cache: tuple[int, dict[str, re.Pattern]] | None = None


def _patterns() -> dict[str, re.Pattern]:
    """Выражения разбора на обоих языках; пересобираются, только когда каталог перечитан (body_of и split идут в
    циклах по строкам дефектов)."""
    global _patterns_cache
    key = id(i18n.catalog())
    if _patterns_cache is None or _patterns_cache[0] != key:
        template_keys = ("reason", "recommendation", "recommendations", "description", "explanation", "sources")
        _patterns_cache = (key, {
            "head": re.compile(r"^[ \t]*(?:" + _alternation("where", colon=False) + r")[ \t]*:?[ \t]*$", re.M | re.I),
            # заголовки шаблона команды: русские – как до dev38 (начало строки, в том числе «Обоснование: текст»),
            # английские и из каталога – только отдельной строкой: «Description: …» в ручном разделе – поле
            # оператора, а не заголовок (ревью Codex dev38, круг 3)
            "template": re.compile(r"^(?:(?:Обоснование|Рекомендация|Рекомендации|Описание|Объяснение|Источники)"
                                   r"\s*(?::|$)|(?:" + "|".join(dict.fromkeys(
                                       re.escape(v.rstrip(":")) for k in template_keys for v in variants(HEADS[k])
                                       if v != HEADS[k][0])) + r")\s*:?\s*$)"),
            # пункт списка, заголовок шаблона команды – как до dev38: английская строка «Rationale: …» после
            # «Where to fix:» – поле оператора (английские заголовки тела стоят отдельной строкой и полем не бывают)
            "not_field": re.compile(r"^(?:\d{1,3}[).]|-\s|Обоснование:|Рекомендация:|Рекомендации:)"),
        })
    return _patterns_cache[1]


def _head_line() -> re.Pattern:
    return _patterns()["head"]


def _template() -> re.Pattern:
    """Заголовки шаблона команды на обоих языках."""
    return _patterns()["template"]


def _not_field() -> re.Pattern:
    """Пункт списка, заголовок шаблона команды на обоих языках."""
    return _patterns()["not_field"]


_COMMIT = re.compile(r"^(https?://\S+?)(?:/-)?/commit/([0-9a-fA-F]{7,64})/?$")
_FIELD = re.compile(r"^[^:\n]{1,40}:\s+\S")  # строка раздела – «поле: значение»


def split(text: Any) -> tuple[str, str]:
    """(текст до раздела, раздел со строкой заголовка). Раздела нет – (текст как есть, ""). Раздел – последняя строка с
    заголовком и всё после неё, если там только строки «поле: значение»: подзаголовок с тем же названием внутри обоснования
    разделом не считается, и текст проверяется по шаблону целиком (ревью, круг 1)."""
    value = str(text or "")
    normal = value.replace("\r\n", "\n")
    heads = list(_head_line().finditer(normal))
    if not heads:
        return value, ""
    found = heads[-1]
    tail = [line.strip() for line in normal[found.end():].split("\n") if line.strip()]
    not_field = _not_field()
    if not tail or not all(_FIELD.match(line) and not not_field.match(line) for line in tail):
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
    heads = list(_head_line().finditer(normal))
    if not heads:
        return ""
    tail = normal[heads[-1].start():].strip()
    template = _template()
    return "" if any(template.match(line.strip()) for line in tail.split("\n")) else tail


def has_head(text: Any) -> bool:
    """В тексте есть строка с заголовком раздела, в том числе у раздела свободной формы."""
    return _head_line().search(str(text or "").replace("\r\n", "\n")) is not None


def join(body: Any, section: str) -> str:
    """Текст и раздел; абзацы разделяет пустая строка, как в остальном тексте дефекта."""
    head = str(body or "").rstrip()
    return f"{head}\n\n{section}" if head and section else (head or section)


def same(one: str, other: str) -> bool:
    """Один и тот же раздел: без учёта пробелов на краях строк и пустых строк."""
    def lines(value: str) -> list[str]:
        return [_canon(" ".join(line.split())) for line in str(value or "").split("\n") if line.strip()]
    return lines(one) == lines(other)


def _canon(line: str) -> str:
    """Строка раздела без языка: заголовок, подпись поля и «не указан» – ключом таблицы, чтобы раздел, собранный на
    другом языке интерфейса, не считался другим (сведения те же)."""
    if _head_line().fullmatch(line):
        return "\x00where"
    not_set = {NOT_SET_M, NOT_SET_F, NOT_SET_EN, i18n.translate(NOT_SET_M, "en"), i18n.translate(NOT_SET_F, "en")}
    for key, pair in FIELDS.items():
        for label in variants(pair):
            if line.startswith(label):
                rest = line[len(label):].strip()
                return f"\x00{key}:" + ("\x00not_set" if rest in not_set else " " + rest)
    return line


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
        lines = [f"{i18n._('Кодовая база:')} {codebase or i18n._(NOT_SET_F)}",
                 f"{i18n._('Репозиторий:')} {repository or i18n._(NOT_SET_M)}",
                 f"{i18n._('Ветка:')} {branch or i18n._(NOT_SET_F)}",
                 f"{i18n._('Коммит:')} {commit or i18n._(NOT_SET_M)}"]
        if scanned:
            lines.append(f"{i18n._('Объект сканирования:')} {scanned}")
        if scan_date(group["date"]):
            lines.append(f"{i18n._('Дата сканирования:')} {scan_date(group['date'])} UTC")
        if group["files"]:
            lines.append(i18n._("Файлы:") + " " + ", ".join(sorted(group["files"])))
        blocks.append("\n".join(lines))
    return head("where") + "\n" + "\n\n".join(blocks)

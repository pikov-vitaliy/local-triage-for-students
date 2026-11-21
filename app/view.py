"""Оформление страниц: подписи, форматирование чисел и времени, разметка текста модели, шаблоны Jinja2.

Только чистые функции без обращения к базе и к запросу: их используют шаблоны (фильтры и глобальные имена)
и разделы интерфейса (app/routes/*).
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup

from app.build_info import asset_version, build_info
from app.config import stand_mode
from app.defect import GOST_STATUS_BASIS, GOST_STATUS_NOTES
from app.feeds import cwe_key
from app.sca import norm_link, prerelease_versions
from app.textsafe import mark_invisible

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

TEST_DIRS = ("test", "tests")


def is_test_path(path: Any) -> bool:
    """Путь находки лежит в каталоге тестов: среди каталогов пути есть test или tests, регистр не важен (`src/test/…`, `Tests/…`).
    Только показ значка в карточке и списке, отбор не меняется. `contest/`, `latest/` и файл `test_x.py` в корне – не тесты."""
    parts = str(path or "").replace("\\", "/").split("/")[:-1]  # последняя часть – имя файла, не каталог
    return any(part.lower() in TEST_DIRS for part in parts)


VERDICT_LABELS = {"true_positive": "истинная", "false_positive": "ложная", "uncertain": "неясно"}
DECISION_LABELS = {"hub": "принято из Hub", "agree": "согласен", "disagree": "не согласен", "later": "отложено",
                   "risk_accepted": "риск принят"}
SEVERITY_LABELS = {"critical": "критическая", "high": "высокая", "medium": "средняя", "low": "низкая",
                   "info": "информационная"}
KIND_LABELS = {"SAST": "SAST", "SCA": "SCA", "SCA-license": "SCA, лицензии", "DAST": "DAST"}
RUN_STATE_LABELS = {"queued": "в очереди", "running": "идёт", "paused": "на паузе", "stopped": "остановлен",
                    "done": "завершён", "error": "ошибка"}
SCOPE_LABELS = {"live": "живые в Hub", "all": "все SAST", "urgent": "только срочные", "selected": "выбранные"}
ITEM_STATE_LABELS = {"pending": "ждёт", "done": "готово", "cached": "готовый", "skipped": "пропущено",
                     "error": "ошибка"}
CONTEXT_LABELS = {"ok": "код из клона", "export_line_only": "только строка из выгрузки",
                  "file_missing": "файл не найден в клоне", "no_repo": "нет клона", "too_large": "файл слишком большой",
                  "binary": "двоичный файл"}
# Причина отсутствия кода в срезе (бэклог 103, план dev18): по `reason` среза (app/context.py), статус не участвует –
# при строке выгрузки статус всегда `export_line_only`. Только представление: модели уходят прежние тексты.
CODE_REASON_LABELS = {"no_repo": "клон не подключён", "ambiguous": "файл найден неоднозначно или обход клона не завершён",
                      "unreadable": "файл не прочитан", "empty": "файл пуст",
                      "line_out_of_range": "строка за пределами файла", "binary": "двоичный файл",
                      "too_large": "файл слишком большой"}
_ARCHIVE_PART = re.compile(r"\.(?:jar|war|ear|aar|zip)(?:!?/)", re.IGNORECASE)


CODE_REASON_KEYS = ("file_missing", "no_file", *CODE_REASON_LABELS, "unknown")
CODE_REASON_KEY_LABELS = {"file_missing": "файла нет в клоне", "no_file": "в находке не указан файл",
                          **CODE_REASON_LABELS, "unknown": "причина не записана"}


def code_reason_key(status: str | None, reason: str | None, file: str | None) -> str:
    """Ключ причины отсутствия кода (CODE_REASON_KEYS) или "" – код есть или среза нет; тот же расчёт, что
    `db._CODE_REASON_KEY_SQL` (бэклог 103: одна таблица для карточки, списка и сводок)."""
    if not status or status == "ok":
        return ""
    reason = str(reason or "")
    if reason == "missing":
        return "file_missing" if str(file or "").strip() else "no_file"
    return reason if reason in CODE_REASON_LABELS else "unknown"


def in_archive(reason: str | None, file: str | None) -> bool:
    """Путь находки внутри архива (jar, war, ear, aar, zip); без клона (no_repo) путь ничего не говорит."""
    return str(reason or "") != "no_repo" and bool(_ARCHIVE_PART.search(str(file or "")))


def code_reason(status: str | None, reason: str | None, file: str | None, lines: int | None) -> str:
    """Почему у находки нет кода в клоне – словами для списка, карточки и сводок; код есть или среза нет – "".
    Рядом с причиной – «внутри архива» (не при `no_repo`) и «строки выгрузки нет»."""
    key = code_reason_key(status, reason, file)
    if not key:
        return ""
    label = CODE_REASON_KEY_LABELS[key]
    if in_archive(reason, file):
        label += ", внутри архива"
    if not lines:
        label += ", строки выгрузки нет"
    return label


MASKED_LABELS = {"SECRET": "секретов", "EMAIL": "адресов почты", "PHONE": "телефонов", "INN": "ИНН", "SNILS": "СНИЛС",
                 "PASSPORT": "паспортов"}
PHASE_LABELS = {"context": "собирается контекст", "model": "запрос модели",
                "waiting":"ожидание первого фрагмента", "generating":"модель формирует ответ",
                "validating":"проверяется ответ", "saving":"сохраняется результат"}


# ============================================================================ числа и время

def num(value: Any) -> float | None:
    """Число из значения любого вида (строка с запятой тоже); не число, бесконечность, NaN, bool – None."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(str(value).strip().replace(",", ".")) if isinstance(value, str) else float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def fmt_num(value: Any, digits: int = 1) -> str:
    number = num(value)
    if number is None:
        return "–"
    return f"{number:.{digits}f}".replace(".", ",")


def fmt_size(value: Any) -> str:
    """Байты -> «9,0 ГБ» / «512 МБ»."""
    number = num(value)
    if number is None or number <= 0:
        return "–"
    mib = number / (1024 * 1024)
    return f"{fmt_num(mib / 1024)} ГБ" if mib >= 1024 else f"{round(mib)} МБ"


def model_option(model: Any) -> str:
    """Подпись модели в списках выбора – одинаково во всех: имя (объём, параметры, рассуждение). «С рассуждением» –
    capabilities модели содержат thinking (такой модели приложение включает рассуждение, ADR-0102), «без рассуждения»
    – возможности известны, thinking нет; неизвестны – пометки нет."""
    m = model if isinstance(model, dict) else {}
    caps = m.get("capabilities")
    parts = [fmt_size(m.get("size")), str(m.get("params") or "")]
    if isinstance(caps, (list, tuple)):
        parts.append("с рассуждением" if "thinking" in caps else "без рассуждения")
    extra = ", ".join(p for p in parts if p and p != "–")
    name = str(m.get("name") or "")
    label = f"{name} ({extra})" if extra else name
    # сервер не отдал список моделей (ADR-0106 п. 7): откуда имя – видно в списке, есть ли модель у сервера, не проверено
    origin = {"profile": "имя из профиля, список моделей сервер не отдаёт",
              "verdict": "модель прежнего разбора, список моделей сервер не отдаёт"}.get(str(m.get("source") or ""))
    return f"{label} – {origin}" if origin else label


def fmt_mib(value: Any) -> str:
    number = num(value)
    if number is None:
        return "–"
    return f"{fmt_num(number / 1024)} ГБ" if number >= 1024 else f"{round(number)} МБ"


def fmt_duration(value: Any) -> str:
    number = num(value)
    if number is None:
        return "–"
    seconds = max(0, int(round(number)))
    if seconds < 60:
        return f"{seconds} с"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} мин {seconds:02d} с"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} ч {minutes:02d} мин"


def fmt_ts(value: Any) -> str:
    """ISO-время UTC -> «2026-10-14 20:59 UTC» (на странице скрипт покажет местное время)."""
    text = str(value or "")
    return f"{text[:10]} {text[11:16]} UTC" if len(text) >= 16 else text


_REPORT_DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::\d{2}(?:\.\d+)?)?)?")


def fmt_report_date(value: Any) -> str:
    """Дата из сводки отчёта Hub «2026-10-01 09:30:00» -> «01.10.2026, 09:30»; иначе – как есть."""
    text = str(value or "").strip()
    m = _REPORT_DATE.fullmatch(text)
    if not m:
        return text
    date = f"{m.group(3)}.{m.group(2)}.{m.group(1)}"
    return f"{date}, {m.group(4)}:{m.group(5)}" if m.group(4) else date


def plural(count: Any, one: str, few: str, many: str) -> str:
    """Форма слова для числа: 1 находка, 2 находки, 5 находок, 21 находка."""
    n = abs(int(count or 0))
    if n % 10 == 1 and n % 100 != 11:
        return one
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return few
    return many


def findings_genitive(count: int) -> str:
    """«у 1 находки», «у 2 находок», «у 21 находки»."""
    return "находки" if count % 10 == 1 and count % 100 != 11 else "находок"


def masked_summary(masked: dict[str, int]) -> str:
    """{"SECRET": 3, "EMAIL": 1} -> «секретов – 3, адресов почты – 1»."""
    return ", ".join(f"{MASKED_LABELS.get(kind, kind)} – {count}" for kind, count in sorted(masked.items()) if count)


# ============================================================================ пояснения

def reopened_note(count: int) -> str:
    """Пояснение к сообщению: у скольких находок снята отметка «Проверено» из-за смены папки с кодом."""
    return (f"У {count} {findings_genitive(count)} снята отметка «Проверено»: код для них теперь берётся из другой "
            "папки, посмотрите их заново.")


def revision_note(notice: dict | None) -> str:
    """Пояснение на странице проекта: у каких кодовых баз сменилась ревизия клона и что из-за этого сброшено."""
    if not notice or not notice.get("codebases"):
        return ""
    names = ", ".join(str(name) for name in notice["codebases"])
    count = int(notice.get("reopened") or 0)
    text = (f"Сменилась ревизия клона ({names}): код в папке другой, чем при прошлой сверке (git pull, другая ветка "
            "или другая папка с репозиториями). Срезы кода этих кодовых баз сброшены – запустите для них прогон заново")
    if count:
        text += f"; у {count} {findings_genitive(count)} снята отметка «Проверено», посмотрите их ещё раз"
    return text + "."


def code_change_note(notice: dict | None, reviewed: int | None = None) -> str:
    """Пояснение на странице проекта: у находок снята отметка «Проверено» – срез кода стал другим без смены папки и
    ревизии клона. Причина названа (бэклог 115): срез пересобран новой версией приложения, а код тот же (метки
    маскирования, сверка строки из выгрузки), или код в клоне изменился (правки в рабочей копии, папка без .git).
    reviewed – сколько находок пояснения сейчас снова отмечены «Проверено»: если все, пояснения нет. У пояснения,
    начатого до 0.10.0.dev21 (legacy), номеров всех находок нет – оно уходит только по «Понятно»."""
    if not notice or not notice.get("reopened"):
        return ""
    ids = notice.get("hub_ids") or []
    complete = not notice.get("legacy") and not notice.get("truncated")
    if ids and complete and reviewed is not None and reviewed >= len(ids):
        return ""
    names = ", ".join(str(name) for name in notice.get("codebases") or [] if name) or "без кодовой базы"
    count = int(notice["reopened"])
    rebuilt = min(int(notice.get("rebuilt") or 0), count)
    unclear = min(int(notice.get("unclear") or 0), count - rebuilt)
    changed = count - rebuilt - unclear
    parts = []
    if changed:
        parts.append(f"код в клоне изменился без смены ревизии у {changed} {findings_genitive(changed)} – правки в "
                     "рабочей копии или папка без .git")
    if rebuilt:
        parts.append(f"у {rebuilt} {findings_genitive(rebuilt)} срез пересобран новой версией приложения, код в клоне "
                     "тот же – изменились метки маскирования или сверка строки из выгрузки")
    if unclear:
        parts.append(f"у {unclear} {findings_genitive(unclear)} код сейчас не тот, по которому принято решение: "
                     "изменился код в клоне или срез пересобран новой версией приложения")
    # без «Модель разобрала эти находки заново»: отметку снимает и сверка срезов, когда модель недоступна (ревью
    # Codex ветки долга, круг 5)
    return f"Снята отметка «Проверено» ({names}): {'; '.join(parts)}. Посмотрите эти находки ещё раз."


# ============================================================================ текст модели

_CODE_SPAN = re.compile(r"`([^`\n]+)`")
_LINE_REF = re.compile(r"\b(строк[аеиуой]{1,2}|line)\s+(\d{1,7})\b", re.I)
_FENCE_BLOCK = re.compile(r"```[\w+.-]*[ \t]*\n(.*?)(?:\n[ \t]*```|\Z)", re.S)


def _link_lines(escaped: str, shown: set[int] | None) -> str:
    """«строка 25» -> ссылка на строку 25 показанного кода. Ссылка на строку, которой в показанном коде нет (модель
    её выдумала или ошиблась номером), помечается: перечёркнута и с подсказкой – такому доводу верить нельзя.
    shown=None – номера не сверяются (текст не про срез кода)."""
    if shown is None:
        return escaped

    def repl(m):
        n = int(m.group(2))
        if n in shown:
            return f'<a class="line-ref" href="#L{n}">{m.group(0)}</a>'
        return (f'<span class="line-ref-missing" title="Строки {n} нет в показанном коде – ссылка не подтверждена">'
                f'{m.group(0)}</span>')

    return _LINE_REF.sub(repl, escaped)


def missing_line_refs(text: Any, shown: set[int] | None) -> list[int]:
    """Номера строк, на которые ссылается текст («строка N»), но которых нет в показанном коде."""
    if shown is None:
        return []
    found = [int(m.group(2)) for m in _LINE_REF.finditer(str(text or ""))]
    return sorted({n for n in found if n not in shown})


def reveal_labels(text: Any, values: dict | None = None) -> Any:
    """Показ без масок (бэклог 111): метки маскирования в тексте модели – значениями, когда они известны карточке.
    Список (шаги «Почему», «Путь данных») – по элементам. Экранирует следующий фильтр, model_text."""
    from app import mask_display
    if isinstance(text, (list, tuple)):
        return [mask_display.reveal(part, values) for part in text]
    return mask_display.reveal(text, values)


def model_text(text: Any, shown: set[int] | None = None) -> Markup:
    """Текст модели для карточки: сначала экранирование, затем только своя разметка – отрезки в обратных кавычках
    становятся <code>, «строка N» – ссылкой на строку показанного кода. Сам текст модели разметкой не становится."""
    parts = _CODE_SPAN.split(str(mark_invisible(text)))
    return Markup("".join(f"<code>{part}</code>" if k % 2 else _link_lines(part, shown)
                          for k, part in enumerate(parts)))


def fix_text(text: Any, shown: set[int] | None = None) -> Markup:
    """Поле «как исправить»: блоки в ограде ``` – моноширинным блоком, остальное – как model_text."""
    source, out, pos = str(text or ""), [], 0
    for m in _FENCE_BLOCK.finditer(source):
        out.append(str(model_text(source[pos:m.start()], shown)))
        out.append(f'<pre class="fix-code"><code>{mark_invisible(m.group(1))}</code></pre>')
        pos = m.end()
    out.append(str(model_text(source[pos:], shown)))
    return Markup("".join(out))


# ============================================================================ ссылки справочников

def cwe_href(value: Any) -> str:
    """Адрес карточки класса CWE по номеру из любого поля находки или справочника ("89", "CWE-89", "CWE-89, CWE-79"
    берётся первый номер). Пусто – номера нет, ссылку показывать не на что."""
    key = cwe_key(value)
    return f"/cwe/{key}" if key else ""


def cwe_number(value: Any) -> str:
    """Номер класса CWE в виде CWE-89 из любого значения; пусто – номера нет."""
    return cwe_key(value)


# ============================================================================ шаблоны

def json_text(value, indent: int = 2):
    """JSON для чтения в <pre>: кириллица и знаки как есть, безопасность – автоэкранированием шаблона
    (иначе тело PUT шло бы кодами символов)."""
    import html
    import json
    from markupsafe import Markup
    # содержимое элемента: экранируются & < >, кавычки остаются как в JSON
    return Markup(html.escape(json.dumps(value, ensure_ascii=False, indent=indent, sort_keys=True, default=str),
                              quote=False))


def hub_text(value) -> str:
    """Описание дефекта Hub (HTML) – строками текста для чтения оператором (как «Описание в Hub»)."""
    from app.hub_defects import description_for_reading
    return "\n".join(description_for_reading(value))


TEXT_CHANGES_MAX_LINES = 2000
TEXT_CHANGES_TOO_LONG = "Описание слишком длинное, перечень не построен: сравните колонки «Было» и «Станет»."


def text_changes(before, after) -> list[str]:
    """Изменённые строки описания дефекта для предпросмотра: «− было», «+ станет». Колонки «Было» и «Станет» – окна с
    прокруткой, и правка в конце длинного текста без прокрутки не видна."""
    from difflib import SequenceMatcher

    def lines(value) -> list[str]:
        return [" ".join(line.split()) for line in hub_text(value).splitlines() if line.strip()]
    if not isinstance(before, str) or not isinstance(after, str):
        return []
    # сравнение целых строк, без посимвольного разбора; страница строится при каждом открытии, поэтому объём ограничен
    old, new = lines(before), lines(after)
    if len(old) + len(new) > TEXT_CHANGES_MAX_LINES:
        return [TEXT_CHANGES_TOO_LONG]
    out: list[str] = []
    for tag, i1, i2, j1, j2 in SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if tag != "equal":
            out += ["− " + line for line in old[i1:i2]] + ["+ " + line for line in new[j1:j2]]
    return out


def number_key(key: str) -> str:
    """Ключ номера дефекта словами: «sca:v3|[…]» – экосистема · компонент · версия (и набор), «sast:<ID>» – находка."""
    text = str(key or "")
    if text.startswith("sast:"):
        return "находка " + text[5:]
    if text.startswith("sca:") and "|" in text:
        body, _, set_no = text.split("|", 1)[1].partition("#")
        try:
            parts = json.loads(body)
        except ValueError:
            return text
        return " · ".join(str(p) for p in parts) + (f" · набор {set_no}" if set_no else "")
    return text


def make_templates() -> Jinja2Templates:
    """Шаблоны с автоэкранированием, фильтрами оформления и подписями. Общие шаблоны (base.html, macros.html,
    error.html) лежат в корне папки templates, страницы разделов – в её подпапках (projects/, findings/, runs/,
    settings/, sca/)."""
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=True, trim_blocks=True,
                      lstrip_blocks=True)
    from app.worklists import list_anchor  # якорь таблицы у видимой ссылки «К списку» (dev28)
    env.filters.update(num=fmt_num, size=fmt_size, mib=fmt_mib, duration=fmt_duration, ts=fmt_ts,
                       model_option=model_option, list_anchor=list_anchor,
                       report_date=fmt_report_date, model_text=model_text, fix_text=fix_text,
                       reveal_labels=reveal_labels,
                       masked_summary=masked_summary, plural=plural,
                       code_text=mark_invisible, norm_link=norm_link, hub_text=hub_text,
                       json_text=json_text, number_key=number_key, text_changes=text_changes,
                       prerelease_versions=prerelease_versions)
    env.globals.update(VERDICT_LABELS=VERDICT_LABELS, DECISION_LABELS=DECISION_LABELS,
                       SEVERITY_LABELS=SEVERITY_LABELS, KIND_LABELS=KIND_LABELS, RUN_STATE_LABELS=RUN_STATE_LABELS,
                       SCOPE_LABELS=SCOPE_LABELS, ITEM_STATE_LABELS=ITEM_STATE_LABELS,
                       CONTEXT_LABELS=CONTEXT_LABELS, PHASE_LABELS=PHASE_LABELS, asset_version=asset_version(), code_reason=code_reason,
                       CODE_REASON_KEY_LABELS=CODE_REASON_KEY_LABELS,
                       BUILD=build_info(), STAND=stand_mode(),  # «npm» – учебный стенд (ADR-0155): подсказки о нём
                       cwe_href=cwe_href, cwe_number=cwe_number, work_link=lambda value: value, is_test_path=is_test_path,
                       GOST_STATUS_NOTES=GOST_STATUS_NOTES, GOST_STATUS_BASIS=GOST_STATUS_BASIS)
    # tojson – без экранирования кириллицы: значения полей Hub читает оператор (<>&' Jinja экранирует всё равно)
    env.policies["json.dumps_kwargs"] = {"sort_keys": True, "ensure_ascii": False}
    return Jinja2Templates(env=env)


def review_json(review: dict | None) -> dict:
    """Отметки решения для скрипта карточки."""
    review = review or {}
    return {"revision": int(review.get("revision") or 0), "decision": review.get("decision") or "",
            "reviewed": bool(review.get("reviewed")), "reviewed_at": review.get("reviewed_at"),
            "copied_at": review.get("copied_at"), "entered": bool(review.get("entered_hub")),
            "kapo_state": review.get("kapo_state") or "", "decided_at": review.get("decided_at"),
            "entered_at": review.get("entered_hub_at")}

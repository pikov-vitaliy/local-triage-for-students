"""Ошибки находок прогона для страницы `/runs/{id}`: группа причины, короткая фраза для человека и технический текст.

Ошибки уже лежат в `run_items.error` (схема базы не меняется): модуль только читает их и раскладывает по группам.
Полный текст ошибки в основной строке не показывается – он уходит в раскрывающиеся подробности.

Язык (ADR-0158): в базу пишется прежний русский канонический текст – по нему идут классификация (`error_group`) и
отбор «результат неизвестен» (`Database.run_errors`). Перевод – только при показе: `shown_error` узнаёт известные
тексты и шаблоны (`known_text`); группа распознаёт и русские, и английские признаки независимо от языка.
"""

from __future__ import annotations

import functools
import re
import string
from collections.abc import Iterable, Mapping
from typing import Any

from app import i18n

# Группы причин: ключ, подпись, подсказка. Порядок – как показываются на странице. Подписи – msgid (перевод при показе).
ERROR_GROUPS = (
    ("format", i18n.N_("ответ не по формату"),
     i18n.N_("Модель оборвала ответ или не заполнила поля. Ответ не по формату обычно исправляет повторный разбор; "
             "обрыв по длине – больший предел ответа в профиле модели или другая модель: повтор с теми же настройками "
             "чаще всего даёт тот же обрыв.")),
    ("unavailable", i18n.N_("модель недоступна"),
     i18n.N_("Ollama не ответила или нужная модель не загружена. Проверьте Ollama и повторите.")),
    ("other", i18n.N_("прочие ошибки"),
     i18n.N_("Сбой при подготовке или сохранении данных. Технический текст – в подробностях.")),
    ("unknown", i18n.N_("результат неизвестен"),
     i18n.N_("Обращение к провайдеру ушло, ответа нет: запрос мог быть принят и оплачен. Повторно такие находки "
             "автоматически не отправляются ни «Продолжить», ни после перезапуска; «Повторить ошибочные» – новый "
             "платный запрос по вашему решению.")),
)
GROUP_LABELS = i18n.Labels({key: label for key, label, _ in ERROR_GROUPS})
# Метка в ленте «Последние вердикты»: короче подписи группы.
SHORT_LABELS = i18n.Labels({"unknown": "результат неизвестен", "format": "ошибка формата",
                            "unavailable": "модель недоступна", "other": "ошибка разбора"})
# Признаки групп – на обоих языках: текст ошибки из других модулей мог быть собран на английском (ADR-0158).
# Английские признаки сравниваются без учёта регистра.
UNKNOWN_MARKERS = ("Результат неизвестен",)
UNKNOWN_MARKERS_EN = ("result unknown", "outcome unknown", "result is unknown")

# Ответ модели не разобран, оборван или не прошёл проверку формата: один повтор уже был.
FORMAT_MARKERS = (
    "не по формату", "оборван", "не разобран", "ответ модели не разобран",
    "Некорректная строка JSON", "Поток модели", "Некорректное сообщение потока",
    "Некорректный текст в потоке", "лишние данные", "не является объектом JSON",
    "завершился без подтверждения",
)
FORMAT_MARKERS_EN = (
    "not in the expected format", "wrong format", "cut off", "truncated", "could not be parsed", "not parsed",
    "invalid json", "model stream", "invalid stream message", "invalid text in the stream", "extra data",
    "not a json object", "ended without confirmation",
)
# Ollama недоступна, связь прервалась или нужной модели нет на сервере.
UNAVAILABLE_MARKERS = (
    "Ollama не отвечает", "Связь с Ollama", "нет на сервере Ollama", "Модели «", "Модель недоступна",
    "Модель не ответила", "HTTP 500", "HTTP 502", "HTTP 503", "HTTP 504",
)
UNAVAILABLE_MARKERS_EN = (
    "ollama is not responding", "ollama did not respond", "connection to ollama", "not on the ollama server",
    "is not in ollama", "is not in the model list", "model is unavailable", "model unavailable",
    "model did not respond",
)
# Технические ошибки подготовки и сохранения – короткая причина для основной строки (признак – на обоих языках).
OTHER_REASONS = (
    (("Не удалось собрать контекст", "could not build the context"), i18n.N_("не удалось собрать срез кода")),
    (("Не удалось сохранить срез", "could not save the code excerpt"), i18n.N_("не удалось сохранить срез кода")),
    (("Не удалось собрать промпт", "could not build the prompt"), i18n.N_("не удалось собрать запрос к модели")),
    (("Не удалось сохранить вердикт", "could not save the verdict"), i18n.N_("не удалось сохранить ответ модели")),
    (("Журнал обмена", "model traffic log"), i18n.N_("недоступен журнал обмена с моделью")),
    (("Промпт", "prompt"), i18n.N_("промпт не поместился в окно модели")),
)


def _has(text: str, ru: Iterable[str], en: Iterable[str] = ()) -> bool:
    """Признак в тексте: русский – с учётом регистра (как прежде), английский – без учёта."""
    if any(marker in text for marker in ru):
        return True
    folded = text.casefold()
    return any(marker in folded for marker in en)


def error_group(text: str) -> str:
    """Группа причины по техническому тексту ошибки run_items.error."""
    text = str(text or "")
    if _has(text, UNKNOWN_MARKERS, UNKNOWN_MARKERS_EN):
        return "unknown"
    if _has(text, FORMAT_MARKERS, FORMAT_MARKERS_EN):
        return "format"
    if _has(text, UNAVAILABLE_MARKERS, UNAVAILABLE_MARKERS_EN):
        return "unavailable"
    return "other"


def error_label(text: str) -> str:
    """Короткая метка ошибки для ленты вердиктов."""
    return SHORT_LABELS[error_group(text)]


def error_reason(text: str) -> str:
    """Короткая причина человеческими словами – для строки списка ошибок."""
    text = str(text or "")
    group = error_group(text)
    if group == "unknown":
        return i18n._("обращение ушло, ответ не получен – запрос мог быть оплачен")
    if group == "format":
        if _has(text, ("не дошла до ответа",), ("did not reach the answer", "never reached the answer")):
            return i18n._("модель не закончила рассуждение – предел длины")
        if _has(text, ("оборван",), ("cut off", "truncated")):
            return i18n._("модель оборвала ответ по длине")
        if _has(text, ("не разобран",), ("could not be parsed", "not parsed")):
            return i18n._("ответ модели не разобран")
        if _has(text, ("не по формату",), ("not in the expected format", "wrong format")):
            return i18n._("ответ не по формату после повтора")
        return i18n._("сбой чтения ответа модели")
    if group == "unavailable":
        if _has(text, ("нет на сервере",), ("not on the ollama server", "is not in ollama")):
            return i18n._("модели нет в Ollama")
        if _has(text, ("Связь с",), ("connection to",)):
            return i18n._("связь с Ollama прервалась")
        return i18n._("модель недоступна")
    for (marker, marker_en), reason in OTHER_REASONS:
        if marker in text or marker_en in text.casefold():
            return i18n._(reason)
    return i18n._("сбой разбора")


# ============================================================================ показ хранимых текстов

@functools.lru_cache(maxsize=512)
def _pattern(msgid: str) -> re.Pattern[str]:
    """Шаблон msgid с подстановками {name} -> регулярное выражение для узнавания готового текста."""
    parts, seen = [], set()
    for literal, field, _spec, _conv in string.Formatter().parse(msgid):
        parts.append(re.escape(literal))
        if field:
            if field in seen:
                parts.append(f"(?P={field})")
            else:
                seen.add(field)
                parts.append(f"(?P<{field}>.+?)")
    return re.compile("".join(parts), re.S)


@functools.lru_cache(maxsize=16)
def _ordered(msgids: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(шаблоны – сначала с более длинной постоянной частью, фразы без подстановок – сначала длинные)."""
    def literal(msgid: str) -> int:
        return sum(len(lit) for lit, *_ in string.Formatter().parse(msgid))
    templates = tuple(sorted((m for m in set(msgids) if "{" in m), key=literal, reverse=True))
    fixed = tuple(sorted((m for m in set(msgids) if "{" not in m), key=len, reverse=True))
    return templates, fixed


def _known(text: str, msgids: tuple[str, ...], depth: int) -> str:
    cat = i18n.catalog()
    if text in cat:
        return cat[text]
    templates, fixed = _ordered(msgids)
    for msgid in templates:
        match = _pattern(msgid).fullmatch(text)
        if match:
            values = {key: _known(value, msgids, depth + 1) if depth < 3 else value
                      for key, value in match.groupdict().items()}
            return i18n._(msgid, **values)
    if "; " in text and depth < 4:  # заметка среза – части через «; »
        parts = text.split("; ")
        return "; ".join(_known(part, msgids, depth + 1) for part in parts)
    out = text  # составной текст: причина из другого модуля + известная подсказка
    for msgid in fixed:
        if msgid in out:
            out = out.replace(msgid, i18n.translate(msgid))
    return out


def known_text(text: Any, msgids: Iterable[str]) -> str:
    """Хранимый русский текст на языке интерфейса: точное совпадение с каталогом, шаблон msgid с подстановками
    (подставленные значения тоже узнаются) или известные фразы внутри составного текста. Неизвестное – как есть."""
    text = str(text or "")
    if not text or i18n.current() == "ru":
        return text
    return _known(text, tuple(msgids), 0)


def known_parts(text: Any, msgids: Iterable[str], sep: str = "; ") -> str:
    """Как known_text, но по частям текста, склеенного через sep (заметки среза кода)."""
    text = str(text or "")
    if not text or i18n.current() == "ru":
        return text
    ids = tuple(msgids)
    return sep.join(_known(part, ids, 0) for part in text.split(sep))


def stored_texts() -> tuple[str, ...]:
    """Известные хранимые тексты ошибок прогонов (msgid; часть – шаблоны с подстановками)."""
    from app import ask, context, db, model_traffic, triage
    extra = [getattr(db, name, "") for name in ("UNKNOWN_RESULT_NOTE", "UNKNOWN_AFTER_RESTART",
                                                 "UNKNOWN_BEFORE_RESUME", "QUESTION_UNKNOWN",
                                                 "QUESTION_UNKNOWN_RESTART")]
    extra.append(getattr(model_traffic, "KEY_IN_ANSWER", ""))
    from app import llm_ollama, logsafe
    extra.extend(llm_ollama.SHOWN_TEXTS)
    extra.extend((logsafe.FAILURE_TEXT, "Не удалось собрать контекст", "Не удалось сохранить срез",
                  "Не удалось собрать промпт", "Ответ модели не разобран", "Не удалось сохранить вердикт"))  # частые ошибки соединения с Ollama: «Проверить», профили, прогоны
    # заметки среза входят в «Нет кода для разбора: …»
    return (tuple(triage.STORED_TEXTS) + tuple(ask.STORED_TEXTS) + tuple(context.NOTE_TEXTS)
            + tuple(t for t in extra if t))


def shown_error(text: Any) -> str:
    """Текст ошибки прогона, находки или вопроса к модели (runs.last_error, run_items.error, questions.error, строка
    медленного режима) для показа."""
    return known_text(text, stored_texts())


def group_run_errors(items: Iterable[Mapping[str, Any]], project_id: int) -> dict[str, Any]:
    """Ошибки прогона -> блок для страницы: {total, retryable, groups}.

    groups – все три группы по порядку; у каждой count и rows. В строке: hub_id, url карточки, правило,
    короткая причина, полный технический текст и признак retryable (находка SAST есть в текущей выгрузке).
    """
    groups = [{"key": key, "label": i18n._(label), "hint": i18n._(hint), "count": 0, "rows": []}
              for key, label, hint in ERROR_GROUPS]
    by_key = {group["key"]: group for group in groups}
    total = retryable = unknown = resolved = 0
    for row in items:
        total += 1
        text = str(row.get("error") or "")
        group = by_key[error_group(text)]
        finding_id = row.get("finding_id")
        can_retry = bool(row.get("retryable"))
        later = row.get("resolved_run")
        # «результат неизвестен» (К11): запрос мог быть оплачен – в повтор только по отдельной отметке оператора
        if can_retry and group["key"] == "unknown":
            unknown += 1
        elif can_retry:
            retryable += 1
        elif later:  # уже разобрана более поздним прогоном – в повтор не идёт
            resolved += 1
        reason = error_reason(text)
        group["rows"].append({
            "hub_id": str(row.get("hub_id") or ""),
            "url": f"/projects/{project_id}/findings/{finding_id}" if finding_id else "",
            "rule": _rule_text(str(row.get("rule") or "")),  # правило учебного примера – на языке интерфейса
            "reason": i18n._("{reason}; уже разобрана в прогоне №{run}", reason=reason, run=later) if later
            else reason,
            "detail": shown_error(text) or i18n._("Технический текст ошибки не сохранён."),
            "retryable": can_retry, "resolved_run": later,
        })
        group["count"] += 1
    result = {"total": total, "retryable": retryable, "unknown": unknown, "resolved": resolved, "groups": groups}
    result["note"] = retry_note(result)
    return result


def retry_note(errors: Mapping[str, Any]) -> str:
    """Пояснение под кнопкой «Повторить ошибочные»: какие ошибки в повтор не идут и почему."""
    resolved = int(errors.get("resolved") or 0)
    absent = int(errors.get("total") or 0) - int(errors.get("retryable") or 0) - int(errors.get("unknown") or 0) \
        - resolved
    parts = []
    if resolved:
        parts.append(i18n._("{count} уже разобраны более поздним прогоном – повторный прогон их не берёт.",
                            count=resolved))
    if absent > 0:
        parts.append(i18n._("Ещё {count} ошибок у находок, которых нет в текущей выгрузке или это не SAST: повторный "
                            "прогон их не берёт.", count=absent))
    return " ".join(parts)


def _rule_text(rule: str) -> str:
    from app.examples import rule_text
    return rule_text(rule)

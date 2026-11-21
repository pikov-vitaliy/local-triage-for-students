"""Ошибки находок прогона для страницы `/runs/{id}`: группа причины, короткая фраза для человека и технический текст.

Ошибки уже лежат в `run_items.error` (схема базы не меняется): модуль только читает их и раскладывает по группам.
Полный текст ошибки в основной строке не показывается – он уходит в раскрывающиеся подробности.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

# Группы причин: ключ, подпись, подсказка. Порядок – как показываются на странице.
ERROR_GROUPS = (
    ("format", "ответ не по формату",
     "Модель оборвала ответ или не заполнила поля. Ответ не по формату обычно исправляет повторный разбор; "
     "обрыв по длине – больший предел ответа в профиле модели или другая модель: повтор с теми же настройками "
     "чаще всего даёт тот же обрыв."),
    ("unavailable", "модель недоступна",
     "Ollama не ответила или нужная модель не загружена. Проверьте Ollama и повторите."),
    ("other", "прочие ошибки",
     "Сбой при подготовке или сохранении данных. Технический текст – в подробностях."),
    ("unknown", "результат неизвестен",
     "Обращение к провайдеру ушло, ответа нет: запрос мог быть принят и оплачен. Повторно такие находки "
     "автоматически не отправляются ни «Продолжить», ни после перезапуска; «Повторить ошибочные» – новый платный "
     "запрос по вашему решению."),
)
GROUP_LABELS = {key: label for key, label, _ in ERROR_GROUPS}
# Метка в ленте «Последние вердикты»: короче подписи группы.
SHORT_LABELS = {"unknown": "результат неизвестен", "format": "ошибка формата", "unavailable": "модель недоступна",
                "other": "ошибка разбора"}
UNKNOWN_MARKERS = ("Результат неизвестен",)

# Ответ модели не разобран, оборван или не прошёл проверку формата: один повтор уже был.
FORMAT_MARKERS = (
    "не по формату", "оборван", "не разобран", "ответ модели не разобран",
    "Некорректная строка JSON", "Поток модели", "Некорректное сообщение потока",
    "Некорректный текст в потоке", "лишние данные", "не является объектом JSON",
    "завершился без подтверждения",
)
# Ollama недоступна, связь прервалась или нужной модели нет на сервере.
UNAVAILABLE_MARKERS = (
    "Ollama не отвечает", "Связь с Ollama", "нет на сервере Ollama", "Модели «", "Модель недоступна",
    "Модель не ответила", "HTTP 500", "HTTP 502", "HTTP 503", "HTTP 504",
)
# Технические ошибки подготовки и сохранения – короткая причина для основной строки.
OTHER_REASONS = (
    ("Не удалось собрать контекст", "не удалось собрать срез кода"),
    ("Не удалось сохранить срез", "не удалось сохранить срез кода"),
    ("Не удалось собрать промпт", "не удалось собрать запрос к модели"),
    ("Не удалось сохранить вердикт", "не удалось сохранить ответ модели"),
    ("Журнал обмена", "недоступен журнал обмена с моделью"),
    ("Промпт", "промпт не поместился в окно модели"),
)


def error_group(text: str) -> str:
    """Группа причины по техническому тексту ошибки run_items.error."""
    text = str(text or "")
    if any(marker in text for marker in UNKNOWN_MARKERS):
        return "unknown"
    if any(marker in text for marker in FORMAT_MARKERS):
        return "format"
    if any(marker in text for marker in UNAVAILABLE_MARKERS):
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
        return "обращение ушло, ответ не получен – запрос мог быть оплачен"
    if group == "format":
        if "не дошла до ответа" in text:
            return "модель не закончила рассуждение – предел длины"
        if "оборван" in text:
            return "модель оборвала ответ по длине"
        if "не разобран" in text:
            return "ответ модели не разобран"
        if "не по формату" in text:
            return "ответ не по формату после повтора"
        return "сбой чтения ответа модели"
    if group == "unavailable":
        if "нет на сервере" in text:
            return "модели нет в Ollama"
        if "Связь с" in text:
            return "связь с Ollama прервалась"
        return "модель недоступна"
    for marker, reason in OTHER_REASONS:
        if marker in text:
            return reason
    return "сбой разбора"


def group_run_errors(items: Iterable[Mapping[str, Any]], project_id: int) -> dict[str, Any]:
    """Ошибки прогона -> блок для страницы: {total, retryable, groups}.

    groups – все три группы по порядку; у каждой count и rows. В строке: hub_id, url карточки, правило,
    короткая причина, полный технический текст и признак retryable (находка SAST есть в текущей выгрузке).
    """
    groups = [{"key": key, "label": label, "hint": hint, "count": 0, "rows": []}
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
            "rule": str(row.get("rule") or ""),
            "reason": f"{reason}; уже разобрана в прогоне №{later}" if later else reason,
            "detail": text or "Технический текст ошибки не сохранён.",
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
        parts.append(f"{resolved} уже разобраны более поздним прогоном – повторный прогон их не берёт.")
    if absent > 0:
        parts.append(f"Ещё {absent} ошибок у находок, которых нет в текущей выгрузке или это не SAST: повторный "
                     "прогон их не берёт.")
    return " ".join(parts)

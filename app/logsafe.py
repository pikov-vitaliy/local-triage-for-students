"""Журнал без данных находок: что делалось, тип ошибки, её номер и где она случилась – без текста исключения.

Текст исключения может содержать код находки, ответ модели, путь или строку из выгрузки, а журнал контейнера
смотрят и пересылают при сбоях. Поэтому в журнал попадают только: своё сообщение (что делалось), тип исключения
и типы причин в цепочке, короткий номер ошибки (его же видит человек в интерфейсе) и кадры трассировки – имя
файла, номер строки и функция, без текста строк, значений и путей папок.
"""

from __future__ import annotations

import logging
import os
import secrets
import traceback

MAX_FRAMES = 12  # сколько последних кадров трассировки писать
MAX_CHAIN = 5  # сколько причин в цепочке исключений называть


def error_id() -> str:
    """Короткий номер ошибки: по нему запись журнала находится по сообщению в интерфейсе."""
    return secrets.token_hex(4)


def error_types(exc: BaseException) -> str:
    """Тип исключения и типы его причин (raise … from …, ошибка при обработке другой): «ValueError ← KeyError»."""
    names, seen = [], set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen and len(names) < MAX_CHAIN:
        seen.add(id(current))
        names.append(type(current).__name__)
        current = current.__cause__ or (None if current.__suppress_context__ else current.__context__)
    return " ← ".join(names)


def error_frames(exc: BaseException) -> str:
    """Где случилась ошибка: «triage.py:470 _process_item ← triage.py:373 _loop» (последний кадр – первым)."""
    frames = traceback.extract_tb(exc.__traceback__)[-MAX_FRAMES:]
    return " ← ".join(f"{os.path.basename(f.filename)}:{f.lineno} {f.name}" for f in reversed(frames)) or "–"


def log_failure(logger: logging.Logger, what: str, exc: BaseException, *args: object,
                level: int = logging.ERROR) -> str:
    """Записать сбой без текста исключения; возвращает номер ошибки для показа человеку.

    what – что делалось, с подстановками %s из args (номера прогона, проекта – не имена и не код)."""
    eid = error_id()
    logger.log(level, f"{what}: %s [ошибка {eid}]; где: %s", *args, error_types(exc), error_frames(exc))
    return eid


def failure_text(what: str, exc: BaseException, eid: str) -> str:
    """Текст для интерфейса: «Не удалось собрать контекст: OSError (ошибка 1a2b3c4d)»."""
    return f"{what}: {type(exc).__name__} (ошибка {eid})"

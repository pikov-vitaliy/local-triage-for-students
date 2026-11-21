"""Журнал обмена приложения с моделью: скрытый файловый журнал «что ушло в Ollama и что вернулось».

По одному JSONL-файлу на день (UTC): `<папка>/ГГГГ-ММ-ДД.jsonl`, обычно `data/model-traffic`. Каждое обращение
к модели – событие `request` (до отправки) и следом `response` или `error`; у всех событий одного обращения
общий `id`. Запись только дописывается, после каждого события файл сбрасывается на диск (`flush` и `os.fsync`).
Журнал скрытый: из веб-интерфейса недоступен, читается с диска (сценарий `scripts/model_traffic.py`).

Регистратор задаётся один раз при запуске приложения (`app/main.py`, `set_recorder`); без заданного регистратора
(тесты, сценарии) запись не ведётся. Назначение и привязка обращения (прогон, находка, проект) помечаются
менеджером контекста `context()` на `contextvars`: значения читаются при записи события, в текущем потоке.

Сбой записи события `request` поднимается наверх, а клиент модели (ADR-0083) учитывает его (`note_failure`) и
отправляет запрос без записи этого обращения; оператор видит предупреждение на странице прогона. Сбой записи
`response`/`error` работу не ломает: сбой пишется в журнал приложения через `app/logsafe.log_failure` (без
текста запроса и кода).
"""

from __future__ import annotations

import base64
import contextvars
import hashlib
import json
import logging
import math
import os
import re
import threading
import unicodedata
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from app.logsafe import log_failure
from app.textsafe import FILLER_CHARS, remove_markup, strip_invisible

log = logging.getLogger("local_triage.model_traffic")


@dataclass(frozen=True)
class _Call:
    """Назначение обращения и его привязка к прогону, находке и проекту (значения из `context()`)."""

    purpose: str | None = None
    run_id: int | None = None
    hub_id: str | None = None
    project_id: int | None = None


_CALL: contextvars.ContextVar[_Call | None] = contextvars.ContextVar("model_traffic_call", default=None)


@contextmanager
def context(purpose: str | None = None, run_id: int | None = None, hub_id: str | None = None,
            project_id: int | None = None) -> Iterator[None]:
    """Пометить обращения к модели в текущем потоке. Не заданные значения наследуются из внешнего контекста
    (вложенные вызовы не обнуляют прогон и находку). Назначения: `triage`, `ask`, `models`, `status`, `reload`,
    `version`, `check` (пробная генерация профиля), `warmup` (прогрев модели ВМ); без контекста – `other`."""
    previous = _CALL.get()
    token = _CALL.set(_Call(
        purpose=purpose if purpose is not None else (previous.purpose if previous else None),
        run_id=run_id if run_id is not None else (previous.run_id if previous else None),
        hub_id=hub_id if hub_id is not None else (previous.hub_id if previous else None),
        project_id=project_id if project_id is not None else (previous.project_id if previous else None),
    ))
    try:
        yield
    finally:
        _CALL.reset(token)


def _encode(data: bytes) -> tuple[str, str]:
    """Байты для журнала: (вид, текст). `utf-8`, если это корректный UTF-8, иначе `base64`."""
    try:
        return "utf-8", data.decode("utf-8")
    except UnicodeDecodeError:
        return "base64", base64.b64encode(data).decode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _body_fields(data: bytes) -> dict[str, Any]:
    encoding, text = _encode(data)
    return {"body": text, "body_encoding": encoding, "body_sha256": _sha256(data), "body_len": len(data)}


def _context_fields() -> dict[str, Any]:
    call = _CALL.get() or _Call()
    return {"purpose": call.purpose or "other", "run_id": call.run_id, "hub_id": call.hub_id,
            "project_id": call.project_id}


# Заголовки авторизации не попадают в журнал ни в одной ветви (ADR-0102 п. 12): ни в request_headers, ни в точных
# байтах запроса (обычный ответ, поток, HTTP-ошибка, обрыв, частично отправленный запрос). «Точные байты» – точные,
# кроме этих заголовков; длины и контрольные суммы считаются по очищенному представлению.
SECRET_HEADERS = ("authorization", "proxy-authorization", "x-api-key", "api-key")


def redact_headers(headers: dict[str, str] | None) -> dict[str, str] | None:
    if not headers:
        return headers
    return {k: v for k, v in headers.items() if str(k).strip().lower() not in SECRET_HEADERS}


def redact_wire(wire: bytes | None) -> bytes | None:
    """Байты запроса без строк заголовков авторизации. Тело (после пустой строки) не трогается; без пустой строки
    (запрос отправлен не целиком) весь буфер – заголовки: обрезанная строка авторизации тоже вырезается."""
    if not wire:
        return wire
    head, sep, body = bytes(wire).partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    names = [name.encode() for name in SECRET_HEADERS]

    def secret(index: int, line: bytes) -> bool:
        if index == 0:  # строка запроса («POST /api/chat HTTP/1.1»)
            return False
        low = line.lstrip().lower()
        if any(low.startswith(name + b":") for name in names):
            return True
        # запрос оборвался на этой строке: начало имени заголовка авторизации тоже вырезается
        return not sep and index == len(lines) - 1 and bool(low) and any(name.startswith(low) for name in names)

    kept = [line for index, line in enumerate(lines) if not secret(index, line)]
    return b"\r\n".join(kept) + sep + body


def scrub(data: Any, secrets: Any) -> Any:
    """Значения секретов (ключ, «Bearer ключ») в байтах или тексте – «***»: сервер или шлюз может вернуть
    переданный ключ в тексте ошибки или ответа. Пусто – без изменений."""
    values = _values(secrets)
    values += [v.replace("/", "\\/") for v in values if "/" in v]  # «\/» – вид «/» у иных кодировщиков JSON
    if not values or data is None:
        return data
    for value in sorted(values, key=len, reverse=True):
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).replace(value.encode("utf-8"), b"***")
        elif isinstance(data, str):
            data = data.replace(value, "***")
    return data


_ESC = re.compile(r"\\(u[0-9a-fA-F]{4}|[\\/\"])")
DECODE_DEPTH = 32  # сколько вложений раскрывается (слой экранирования или JSON в строке); глубже – ключ «виден»
# работа раскрытия одной строки – не больше DECODE_WORK её длин (плюс запас): больше – ключ «виден»; разбор JSON
# стоит JSON_COST знаков сверх длины разбираемого текста
DECODE_WORK = 16
DECODE_SPARE = 1 << 16
JSON_COST = 256
HIDDEN_TEXT = "[текст скрыт: в нём был ключ профиля]"
HIDDEN_NAME = "[имя скрыто: в нём был ключ профиля]"
_NOT_JSON = object()


class _Pairs(list):
    """Пары «имя – значение» объекта JSON при проверочном разборе: повторяющиеся имена не теряются."""


def _values(secrets: Any) -> list[str]:
    """Значения ключа, которые ищутся (ключ и «Bearer ключ»); короче 4 знаков не ищутся."""
    return [str(s) for s in (secrets or ()) if s and len(str(s)) >= 4]


def _unescape(text: str) -> str:
    """Один слой экранирования JSON для знаков ASCII (\\uXXXX, \\\\, \\/, \\") – в обычный вид."""

    def plain(m: re.Match) -> str:
        escape = m.group(1)
        if escape[0] != "u":
            return escape
        code = int(escape[1:], 16)
        return chr(code) if code < 128 else m.group(0)

    return _ESC.sub(plain, text)


def _json_strings(value: Any) -> Iterator[str]:
    """Строки разобранного JSON на любой глубине – значения и имена полей, в том числе повторяющихся (без рекурсии
    Python)."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, _Pairs):
            for name, inner in item:
                yield str(name)
                stack.append(inner)
        elif isinstance(item, dict):
            for name, inner in item.items():
                yield str(name)
                stack.append(inner)
        elif isinstance(item, list):
            stack.extend(item)


class _Budget:
    """Бюджет работы раскрытия – общий для всех строк одного тела ответа (clean_value), иначе – на одну строку."""

    __slots__ = ("left",)

    def __init__(self, units: int) -> None:
        self.left = units


def _size(value: Any) -> int:
    """Примерный размер разобранного значения в знаках (длины строк и имён плюс по 8 на элемент) – для бюджета."""
    total, stack = 0, [value]
    while stack:
        item = stack.pop()
        total += 8
        if isinstance(item, str):
            total += len(item)
        elif isinstance(item, dict):
            total += sum(len(str(name)) for name in item)
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return total


_WHITESPACE = {9: None, 10: None, 13: None}  # \t \n \r – управляющие, но не невидимые: textsafe их оставляет


def _views(text: str) -> tuple[str, ...]:
    """Виды строки, в которых ключ не должен встречаться буквально, – все сочетания очистки и записи, которые делает
    приложение: строка как есть, после очистки невидимых знаков (`textsafe.strip_invisible` – ответы модели и
    агента), после очистки для Hub (`textsafe.hub_clean` – ещё и теги HTML), без всех управляющих и невидимых знаков;
    каждая – и как есть, и в записи JSON с экранированием не-ASCII и без (так её сохранят база и журнал: управляющий
    знак станет «\\u0001»). Части ключа, которые сомкнёт очистка или сериализация, так находятся заранее."""
    plain = text.translate(_WHITESPACE)
    # нет управляющих (кроме \t \n \r) и невидимых знаков (заполнители Хангыль печатаемы, но невидимы) – их очистка
    # ничего не меняет
    if plain.isprintable() and not any(filler in text for filler in FILLER_CHARS):
        bases = {text, plain}
    else:
        bases = {text, strip_invisible(text),
                 "".join(ch for ch in text if unicodedata.category(ch) not in ("Cc", "Cf", "Co", "Cn", "Cs"))}
    if "<" in text or ":" in text:  # hub_clean: невидимые знаки, затем теги и схемы адресов
        bases |= {remove_markup(base) for base in bases}
    return tuple(view for base in bases for view in (base, json.dumps(base), json.dumps(base, ensure_ascii=False)))


def _reveals(text: str, values: list[str], budget: _Budget | None = None) -> bool:
    """Виден ли ключ в тексте, если раскрывать его, как раскрыл бы читатель: буквально; текст – JSON (объект, массив
    или строка JSON) – в каждой его строке и в каждом числе после разбора, имена повторяющихся полей не теряются;
    иначе – после снятия слоя экранирования JSON. Вложений больше DECODE_DEPTH или исчерпан бюджет работы (своя
    строка – DECODE_WORK её длин; общий бюджет тела – см. clean_value), а раскрывать ещё есть что, – ключ считается
    видимым. Без рекурсии: прежние большие строки не удерживаются."""
    budget = budget or _Budget(DECODE_WORK * len(text) + DECODE_SPARE)
    stack = [(text, 0)]
    while stack:
        current, depth = stack.pop()
        budget.left -= len(current) + 16
        if budget.left < 0:
            return True
        if any(value in view for view in _views(current) for value in values):
            return True
        parsed = _NOT_JSON
        if current.lstrip()[:1] in ('"', "{", "["):
            budget.left -= JSON_COST
            try:
                parsed = json.loads(current, object_pairs_hook=_Pairs)
            except (ValueError, RecursionError):
                parsed = _NOT_JSON
        if parsed is not _NOT_JSON:
            if depth >= DECODE_DEPTH:
                return True
            stack.extend((inner, depth + 1) for inner in _json_strings(parsed))
            continue
        plain = _unescape(current)
        if plain != current:
            if depth >= DECODE_DEPTH:
                return True
            stack.append((plain, depth + 1))
    return False


def contains_secret(data: Any, secrets: Any, budget: _Budget | None = None) -> bool:
    """Виден ли в байтах или тексте ключ: буквально; если текст – JSON, то в любой его строке после разбора (значения и
    имена полей, повторяющиеся тоже; строка, которая сама JSON или строка JSON, разбирается тоже); в тексте не JSON –
    после снятия слоёв экранирования JSON знаков ASCII. Слишком глубокое или слишком дорогое раскрытие – ключ
    считается видимым (_reveals)."""
    values = _values(secrets)
    if not values or data is None:
        return False
    text = bytes(data).decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    return _reveals(text, values, budget)


def scrub_text(text: Any, secrets: Any, budget: _Budget | None = None) -> Any:
    """Текст для показа и хранения (сообщение, подробности, начало ответа модели): ключ – «***»; если ключ остался в
    экранированном или разбитом виде – текст скрывается целиком."""
    if not isinstance(text, str):
        return text
    cleaned = scrub(text, secrets)
    return HIDDEN_TEXT if contains_secret(cleaned, secrets, budget) else cleaned


def clean_value(value: Any, secrets: Any, budget: _Budget | None = None) -> Any:
    """Разобранное значение без ключа: строки на любой глубине и имена полей – через scrub_text (имя с ключом –
    HIDDEN_NAME), число, в записи которого ключ (ключ из одних цифр), – None. Бюджет раскрытия – общий на всё
    значение (DECODE_WORK его размеров): исчерпан – оставшиеся строки скрываются без разбора. Слишком глубокая
    вложенность – RecursionError (вызывающий не сохраняет и не показывает значение)."""
    values = _values(secrets)
    if not values:
        return value
    if budget is None:
        budget = _Budget(DECODE_WORK * _size(value) + DECODE_SPARE)
    if isinstance(value, str):
        return scrub_text(value, secrets, budget)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float) and not math.isfinite(value):  # Infinity, NaN: в JSON – литерал, ключом может быть он
        return None
    if isinstance(value, (int, float)):
        return None if any(v in text for text in (str(value), json.dumps(value)) for v in values) else value
    if isinstance(value, list):
        return [clean_value(v, secrets, budget) for v in value]
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for name, inner in value.items():
            safe = scrub_text(str(name), secrets, budget)
            cleaned[HIDDEN_NAME if safe == HIDDEN_TEXT else safe] = clean_value(inner, secrets, budget)
        return cleaned
    return value


KEY_IN_ANSWER = "Ответ модели содержал ключ профиля: ответ не сохранён."


def shows_secret(value: Any, secrets: Any) -> bool:
    """Последняя проверка перед сохранением ответа модели, уже разобранного и нормализованного приложением (вердикт,
    ответ на вопрос, статистика): ключ буквально в записи JSON значения – с экранированием не-ASCII и без, как её
    пишет база. Очистки после этой точки не бывает – что прошло проверку, то и сохраняется."""
    values = _values(secrets)
    if not values:
        return False
    texts = (json.dumps(value, ensure_ascii=False, sort_keys=True, default=str),
             json.dumps(value, sort_keys=True, default=str))
    return any(v in text for text in texts for v in values)


def _now() -> str:
    """Сейчас по UTC в ISO с микросекундами (первые 10 знаков – дата файла журнала)."""
    return datetime.now(timezone.utc).isoformat()


class Recorder:
    """Потокобезопасная запись событий обмена с моделью в файлы `<папка>/ГГГГ-ММ-ДД.jsonl` (день по UTC).

    Каждое событие – одна строка JSON; файл только дописывается, после каждой записи – `flush` и `os.fsync`.
    Файл дня выбирается по моменту события `request`: `response` и `error` того же обращения попадают в тот же
    файл (день приходит в `request_ts`). Сбой записи события `request` поднимается наверх, сбой подготовки или записи
    `response`/`error` не ломает работу и пишется в журнал приложения (`log_failure`).

    Журнал хранит весь обмен байт в байт – и у сервера с ключом (журнал локальный, его
    конфиденциальность обеспечивает пользователь); вырезается только заголовок авторизации запроса (ADR-0102 п. 8).
    """

    def __init__(self, folder: Path | str) -> None:
        self.folder = Path(folder)
        self._lock = threading.Lock()

    def _write(self, event: dict[str, Any], day: str) -> None:
        line = json.dumps(event, ensure_ascii=False) + "\n"
        self.folder.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with open(self.folder / f"{day}.jsonl", "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())

    # ---------------------------------------------------------------- события

    def request(self, *, method: str, url: str, body: bytes | None = None,
                provider: dict[str, Any] | None = None) -> tuple[str, str]:
        """Событие `request` (пишется до отправки) -> (id события, его ts). provider – профиль исполнителя
        (номер, версия, класс доверия; ADR-0102 п. 12). Сбой записи поднимается наверх."""
        event_id = str(uuid.uuid4())
        ts = _now()
        event: dict[str, Any] = {"event": "request", "id": event_id, "ts": ts, "method": method, "url": url,
                                 **_context_fields()}
        if provider:
            event["provider"] = dict(provider)
        if body is not None:
            event.update(_body_fields(body))
        else:
            event.update(body=None, body_encoding=None, body_sha256=None, body_len=0)
        self._write(event, ts[:10])
        return event_id, ts

    def response(self, **fields: Any) -> None:
        """Событие `response` после чтения ответа целиком (поля – как у _response_event). Сбой подготовки или записи
        работу не ломает: пишется в журнал приложения."""
        try:
            event, day = self._response_event(**fields)
        except Exception as e:
            log_failure(log, "событие response журнала обмена с моделью не подготовлено", e)
            return
        self._safe_write(event, day, "событие response журнала обмена с моделью не записано")

    def _response_event(self, *, event_id: str, request_ts: str, duration_ms: int, status: int,
                        headers: dict[str, str], body: bytes, chunks: int | None = None, peer: str | None = None,
                        request_headers: dict[str, str] | None = None,
                        request_wire: bytes | None = None) -> tuple[dict[str, Any], str]:
        """Событие `response` и день его файла: тело ответа – как прочитано (у потока – все куски подряд)."""
        event: dict[str, Any] = {"event": "response", "id": event_id, "ts": _now(), "duration_ms": duration_ms,
                                 "status": status, "headers": headers or {}, **_body_fields(body)}
        if chunks is not None:
            event["chunks"] = chunks
        if peer:
            event["peer"] = peer
        request_headers = redact_headers(request_headers)
        if request_headers:
            event["request_headers"] = request_headers
        self._wire_fields(event, redact_wire(request_wire))
        return event, request_ts[:10]

    def error(self, **fields: Any) -> None:
        """Событие `error` после обрыва обмена (поля – как у _error_event). Сбой подготовки или записи работу не
        ломает: пишется в журнал приложения."""
        try:
            event, day = self._error_event(**fields)
        except Exception as e:
            log_failure(log, "событие error журнала обмена с моделью не подготовлено", e)
            return
        self._safe_write(event, day, "событие error журнала обмена с моделью не записано")

    def _error_event(self, *, event_id: str, request_ts: str, duration_ms: int, error_type: str, error_text: str,
                     received: bytes | None = None, peer: str | None = None,
                     request_headers: dict[str, str] | None = None,
                     request_wire: bytes | None = None) -> tuple[dict[str, Any], str]:
        """Событие `error` (байты ответа, успевшие прийти) и день его файла."""
        event: dict[str, Any] = {"event": "error", "id": event_id, "ts": _now(), "duration_ms": duration_ms,
                                 "error_type": error_type, "error": error_text,
                                 "received_len": len(received) if received is not None else 0}
        if received:
            encoding, text = _encode(received)
            event.update(received=text, received_encoding=encoding, received_sha256=_sha256(received))
        if peer:
            event["peer"] = peer
        request_headers = redact_headers(request_headers)
        if request_headers:
            event["request_headers"] = request_headers
        self._wire_fields(event, redact_wire(request_wire))
        return event, request_ts[:10]

    @staticmethod
    def _wire_fields(event: dict[str, Any], request_wire: bytes | None) -> None:
        """Точные байты запроса, ушедшие в сокет (строка запроса, заголовки без авторизации, тело), – в событие."""
        if request_wire is None:
            return
        encoding, text = _encode(request_wire)
        event.update(request_wire=text, request_wire_encoding=encoding, request_wire_sha256=_sha256(request_wire),
                     request_wire_len=len(request_wire))

    def _safe_write(self, event: dict[str, Any], day: str, what: str) -> None:
        try:
            self._write(event, day)
        except Exception as e:
            log_failure(log, what, e)


_recorder: Recorder | None = None
_failures_lock = threading.Lock()
# Сбои записи события request с запуска приложения: всего и по прогонам (ADR-0083). Обмен с моделью из-за них
# не останавливается, оператор видит предупреждение на странице прогона.
_failures: dict[str, Any] = {"count": 0, "last_at": None, "last_error": "", "runs": {}}
JOURNAL_FAILURE_ADVICE = "Обратитесь к автору программы."


def note_failure(error: BaseException) -> None:
    """Событие request не записано: запомнить сбой (всего и для прогона из текущего контекста)."""
    text = str(error) or type(error).__name__
    call = _CALL.get() or _Call()
    with _failures_lock:
        _failures["count"] += 1
        _failures["last_at"] = _now()
        _failures["last_error"] = text
        if call.run_id is not None:
            run = _failures["runs"].setdefault(call.run_id, {"count": 0, "last_error": ""})
            run["count"] += 1
            run["last_error"] = text


def failure_text(run_id: int | None = None) -> str:
    """Предупреждение оператору о незаписанном журнале: для прогона (run_id) или с запуска приложения; пусто –
    сбоев не было."""
    with _failures_lock:
        info = _failures["runs"].get(run_id) if run_id is not None else (
            {"count": _failures["count"], "last_error": _failures["last_error"]} if _failures["count"] else None)
        if not info:
            return ""
        count, error = info["count"], info["last_error"]
    return (f"Журнал обмена с моделью не записан для {count} обращений к модели (последняя ошибка: {error}). "
            f"Разбор продолжается, но эти обращения в журнале не сохранены. {JOURNAL_FAILURE_ADVICE}")


def reset_failures() -> None:
    """Сбросить учёт сбоев (тесты)."""
    with _failures_lock:
        _failures.update(count=0, last_at=None, last_error="", runs={})


def set_recorder(recorder: Recorder | None) -> None:
    """Задать или убрать регистратор журнала обмена (при запуске приложения). Без регистратора запись
    не ведётся, и обмен с моделью от неё не зависит."""
    global _recorder
    _recorder = recorder


def get_recorder() -> Recorder | None:
    """Регистратор, заданный при запуске приложения, или None (тесты, сценарии)."""
    return _recorder

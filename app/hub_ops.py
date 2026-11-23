"""Операции в AppSec.Hub через исполнителя (ADR-0114).

В режиме исполнителя (сейчас единственном; прямой режим – ADR-0129) приложение к Hub само не обращается: оно
ставит в очередь операцию – один HTTP-запрос к REST Hub, – а исполнитель
(`deploy/hub-worker/hub_worker.py`), запущенный там, где виден Hub (ВМ с VPN или сам компьютер), забирает задание,
выполняет его под сессией оператора и возвращает ответ как есть. Здесь – чистые правила: белый список запросов,
ключи операций, разбор результатов. Хранение – app/db.py (таблицы hub_ops, hub_attempts), адреса – app/routes/hub.py.

Белый список – точные пары «метод + образец пути» с допустимыми параметрами строки запроса: запрос вне списка в
очередь не встаёт. Тот же список держит исполнитель у себя (защита с двух сторон).
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import urllib.parse
from app import i18n
from app.hub_sync_contract import SYNC_PATHS, sync_query_value, validate_sync_purpose

from typing import Any

REST = "/hub/rest"
WORKER_KEY_HEADER = "X-Hub-Worker-Key"
_KEY_RE = re.compile(r"[0-9a-f]{64}")
LEASE_S = 120  # аренда задания исполнителем: запрос к Hub (до 30 с) и доставка результата должны уложиться
WAIT_MAX_S = 25  # долгий опрос очереди, не дольше (у исполнителя таймаут чтения 40 с)
RESULT_MAX = 1024 * 1024  # предел тела ответа Hub в результате (байт); длиннее – усекается с пометкой truncated
READ_PURPOSES = ("probe", "read", "defect_blank", "defect_read", "defect_reference", "sync_read")
# запись: второй раз с тем же ключом не уходит; defect_update – `PUT /defects/{id}`, согласованные поля существующего
# дефекта (ADR-0126 dev1b)
WRITE_PURPOSES = ("status", "defect_create", "defect_link", "defect_update")
PURPOSES = READ_PURPOSES + WRITE_PURPOSES
STATES = ("queued", "taken", "done", "failed", "unknown", "cancelled")
OPEN_STATES = ("queued", "taken", "unknown")  # операция не закрыта: новая с тем же ключом или целями не заводится

# (метод, образец пути, допустимые параметры). {id} – целое число, {type} – тип находки Hub. PUT – только
# `PUT /defects/{id}`: поля существующего дефекта (ADR-0126 dev1b); DELETE и прочие PUT – вне списка
_INT = r"[0-9]{1,12}"
_TYPE = r"(?:SAST|SCA_S|SCA_L|DAST)"
ALLOWED: tuple[tuple[str, str, frozenset[str]], ...] = (
    ("GET", "/auth/user", frozenset()),
    ("GET", "/defects/blank", frozenset({"appId", "issueIds", "type"})),
    ("GET", "/templates/defects/model", frozenset({"issueType", "issueId", "appId"})),
    ("POST", "/defects", frozenset()),
    ("GET", "/defects", frozenset({"appId", "pageIndex", "pageSize", "sort"})),
    ("GET", "/defects/{id}", frozenset()),
    ("POST", "/defects/{id}/link", frozenset()),
    ("POST", "/issue/status/update", frozenset()),
    ("POST", "/issue/status/change", frozenset()),
    ("GET", "/issue/status", frozenset({"issueId", "issueType"})),
    ("GET", "/issue/sast/{id}", frozenset({"branch"})),
    ("GET", "/issue/sca/security/{id}", frozenset({"branch"})),
    ("GET", "/issue/{type}/{id}/comment", frozenset()),
    ("GET", "/defects/serviceInfo", frozenset()),
    ("GET", "/application/{id}/structureUnits", frozenset()),
    ("GET", "/releaseObject/filters", frozenset({"appId"})),
    ("PUT", "/defects/{id}", frozenset()),
)
ALLOWED += tuple(entry for entry in SYNC_PATHS if entry not in ALLOWED)
METHODS = ("GET", "POST", "PUT")  # методы белого списка; DELETE, PATCH и прочие – отказ до сверки пути
# Предел значения параметра issueIds (`GET /defects/blank`): номера находок через запятую. У библиотеки с десятками
# уязвимостей в один дефект входят десятки находок (десятки пятизначных номеров длиннее прежнего общего предела
# 200 знаков, и дефект было бы не создать). Hub принимает длинные строки запроса; остальные параметры – по-прежнему до 200 знаков.
ISSUE_IDS_MAX = 2000
_ISSUE_IDS = re.compile(r"[0-9]{1,12}(?:,[0-9]{1,12})*")
_PARAM_VALUE = re.compile(r"[A-Za-z0-9_,.-]{1,200}")


def _pattern(template: str) -> re.Pattern:
    return re.compile("^" + re.escape(template).replace(r"\{id\}", _INT).replace(r"\{type\}", _TYPE) + "$")


def _param_ok(name: str, value: str) -> bool:
    """Значение параметра белого списка: `branch` – по правилу синхронизации, `issueIds` – номера через запятую не длиннее
    ISSUE_IDS_MAX, остальные – до 200 знаков из букв, цифр, «_,.-»."""
    if name == "branch":
        return bool(sync_query_value(name, value))
    if name == "issueIds":
        return len(value) <= ISSUE_IDS_MAX and _ISSUE_IDS.fullmatch(value) is not None
    return _PARAM_VALUE.fullmatch(value) is not None


_ALLOWED = tuple((method, _pattern(path), params) for method, path, params in ALLOWED)


class HubRequestRejected(ValueError):
    """Запрос не из белого списка; текст – по-русски."""


def check_request(method: str, path: str) -> None:
    """Запрос к Hub (метод и путь с параметрами, относительно /hub/rest) должен быть из белого списка:
    точный путь, только допустимые параметры, без фрагмента и повторов параметров. Иначе HubRequestRejected."""
    method = str(method or "").upper()
    if method not in METHODS:
        raise HubRequestRejected(f"Метод {method or '«»'} к Hub не разрешён.")
    if not path.startswith("/") or "#" in path or "//" in path or ".." in path or any(ch.isspace() for ch in path):
        raise HubRequestRejected("Путь запроса к Hub должен начинаться с «/», без пробелов, «..» и «#».")
    base, _, query = path.partition("?")
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, strict_parsing=bool(query))
    names = [k for k, _ in pairs]
    for allowed_method, pattern, params in _ALLOWED:
        if allowed_method == method and pattern.match(base):
            extra = set(names) - params
            if extra:
                raise HubRequestRejected(f"Параметры {', '.join(sorted(extra))} у {method} {base} не разрешены.")
            if len(names) != len(set(names)):
                raise HubRequestRejected(f"Повтор параметра у {method} {base}.")
            if not all(_param_ok(k, v) for k, v in pairs):
                raise HubRequestRejected(f"Недопустимое значение параметра у {method} {base}.")
            return
    raise HubRequestRejected(f"Запрос {method} {base} не входит в белый список запросов к Hub.")


def check_operation(purpose: str, request: dict, app_id: int | None) -> None:
    from app.defect_dto import validate_operation
    validate_sync_purpose(purpose, request, app_id)
    check_request(request.get("method", ""), request.get("path", ""))
    try:
        validate_operation(purpose, request, app_id)
    except ValueError as exc:
        raise HubRequestRejected(str(exc)) from exc


def hub_base(hub_url: str) -> str:
    """Адрес Hub из настроек -> «https://host» без хвоста."""
    parts = urllib.parse.urlsplit(str(hub_url or "").strip())
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""


def text_hash(text: str) -> str:
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def normalize_text(text: str) -> str:
    """Текст для сверки: пробелы схлопнуты, концы обрезаны – Hub может переформатировать переводы строк."""
    return " ".join(str(text or "").split())


def is_write(purpose: str) -> bool:
    return purpose in WRITE_PURPOSES


def op_key(hub_url: str, app_id: int | None, purpose: str, targets: list[dict], text: str = "",
           request: dict | None = None, key_extra: str = "") -> str:
    """Ключ операции: тот же Hub, то же приложение, то же назначение, те же находки, тот же текст и тот же запрос
    (метод, путь, тело – другой срок, статус или страница чтения дают другую операцию). key_extra – чем ещё
    различаются операции: у записей цепочки дефекта – строка дефекта (ADR-0121: новая строка – новое явное действие
    оператора, повтор той же строки отклоняется); пусто – ключ прежний."""
    ids = sorted(f"{t.get('issue_type', '')}:{t.get('issue_id', '')}" for t in targets)
    req = request or {}
    body = json.dumps(req.get("body"), ensure_ascii=False, sort_keys=True) if req.get("body") is not None else ""
    parts = [hub_base(hub_url), str(app_id or ""), purpose, ",".join(ids), text_hash(text),
             str(req.get("method", "")).upper(), str(req.get("path", "")), body]
    if key_extra:
        parts.append(str(key_extra))
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:40]


NOT_SENT = "запрос в Hub не отправлен"  # начало ошибки операции, которую исполнитель в Hub не отправлял
UNKNOWN = "результат неизвестен"  # начало ошибки записи, исход которой не установлен
# Ошибки операций хранятся в hub_ops.error по-русски: по их началу идёт разбор (NOT_SENT, «результат неизвестен»,
# «белый список»). На языке интерфейса – только при показе, error_text (ADR-0158).
_NO_REASON = i18n.N_("причина не указана")
_TRUNCATED = i18n.N_("ответ Hub усечён")
_NO_ANSWER = i18n.N_("ответа от Hub нет")
_CODED = re.compile(r"Hub ответил кодом ([0-9]+)(?:: (.*))?\Z", re.S)


def outcome_state(purpose: str, result: dict) -> tuple[str, str]:
    """Состояние операции по результату исполнителя -> (state, error).
    done – только 2xx с полным (не усечённым) телом и без ошибки. Запись: нет ответа (статус 0 – тайм-аут после
    отправки, обрыв), усечённое тело или ошибка сервера 5xx (запись могла состояться) – «результат неизвестен»,
    повторной отправки нет; определённый отказ 4xx – failed. Чтение без побочных эффектов: всё, что не done, –
    failed."""
    status = int(result.get("status") or 0)
    error = str(result.get("error") or "")
    if result.get("not_sent"):  # исполнитель не отправлял запрос в Hub (отказ белого списка, Hub недоступен)
        return "failed", f"{NOT_SENT}: {error or _NO_REASON}"
    if 200 <= status < 300 and not error and not result.get("truncated"):
        return "done", ""
    if is_write(purpose) and not 400 <= status < 500:
        # всё, кроме определённого отказа 4xx: нет ответа, 2xx с ошибкой доставки или усечением, 3xx, 5xx –
        # запись могла состояться
        said = hub_message(result.get("body_text")) if status and not 200 <= status < 300 else ""
        coded = (f"Hub ответил кодом {status}" + (f": {said}" if said else "")) if status else ""
        if error:  # ошибка доставки или чтения – вместе с известным кодом и пояснением Hub
            note = f"{coded}; {error}" if coded else error
        else:
            note = _TRUNCATED if 200 <= status < 300 else coded or _NO_ANSWER
        return "unknown", f"{UNKNOWN}: {note}"
    if status:  # отказ Hub: код и его короткое пояснение из тела ответа – оператор видит, что поправить; ошибка
        # чтения ответа дописывается к пояснению, а не заменяет его
        said = "; ".join(part for part in (hub_message(result.get("body_text")), error) if part)
        return "failed", f"Hub ответил кодом {status}" + (f": {said}" if said else "")
    return "failed", error or _NO_ANSWER


def error_text(text: Any) -> str:
    """Сохранённая ошибка операции Hub (русский текст из outcome_state, пояснения сверки) -> текст для показа на языке
    интерфейса. Известные начала переводятся, пояснение Hub и ошибка исполнителя остаются как есть; при русском – без
    изменений."""
    text = str(text or "")
    if not text or i18n.current() == "ru":
        return text
    if text.startswith(NOT_SENT + ": "):
        return i18n._("запрос в Hub не отправлен: {reason}", reason=error_text(text[len(NOT_SENT) + 2:]))
    if text.startswith(UNKNOWN + ": "):
        return i18n._("результат неизвестен: {note}", note=error_text(text[len(UNKNOWN) + 2:]))
    coded = _CODED.match(text)
    if coded:
        if coded.group(2) is None:
            return i18n._("Hub ответил кодом {status}", status=coded.group(1))
        return i18n._("Hub ответил кодом {status}: {said}", status=coded.group(1), said=coded.group(2))
    return i18n._(text)


def hub_message(body_text: Any) -> str:
    """Короткое пояснение отказа из тела ответа Hub; иначе «». Hub отдаёт ошибку по своей схеме HubErrorDto:
    errorMessage и ошибки проверки полей requestValidationError ({поле: {code, message}}) – отказ Hub приходит
    так; запасные поля – message, error, detail."""
    try:
        data = json.loads(str(body_text or ""))
    except (TypeError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    parts = []
    for name in ("errorMessage", "message", "error", "detail"):
        value = data.get(name)
        if isinstance(value, str) and value.strip():
            parts.append(" ".join(value.split()))
            break
    fields = data.get("requestValidationError")
    if isinstance(fields, dict):
        for field, problem in list(fields.items())[:5]:
            said = problem.get("message") if isinstance(problem, dict) else problem
            if isinstance(said, str) and said.strip():
                parts.append(f"{field}: {' '.join(said.split())}")
    return "; ".join(parts)[:300]


def lock_keys(hub_url: str, app_id: int | None, purpose: str, targets: list[dict]) -> list[str]:
    """Ключи блокировки целей: у каждой находки – одна открытая операция данного назначения."""
    base = f"{hub_base(hub_url)}|{app_id or ''}|{purpose}|"
    return sorted({base + f"{t.get('issue_type', '')}:{t.get('issue_id', '')}" for t in targets})


def probe_request() -> dict[str, Any]:
    return {"method": "GET", "path": "/auth/user", "body": None}


def parse_json(body_text: str) -> Any:
    try:
        return json.loads(body_text) if body_text else None
    except ValueError:
        return None


def probe_outcome(result: dict) -> dict:
    """Итог проверки связи по результату исполнителя: {ok, user, roles, detail}."""
    status = int(result.get("status") or 0)
    body = parse_json(str(result.get("body_text") or ""))
    if status == 200 and isinstance(body, dict) and body.get("name"):
        name = " ".join(str(body.get(k) or "") for k in ("firstName", "lastName")).strip() or str(body["name"])
        return {"ok": True, "user": name, "login": str(body["name"]), "roles": list(body.get("roles") or []),
                "detail": ""}
    if status in (401, 403):
        return {"ok": False, "user": "", "login": "", "roles": [],
                "detail": i18n._("Hub не принял сессию исполнителя: войдите в исполнителе заново.")}
    if status == 0:
        return {"ok": False, "user": "", "login": "", "roles": [],
                "detail": i18n._("Исполнитель не дозвонился до Hub: {error}.",
                                 error=result.get('error') or i18n._("сбой соединения"))}
    return {"ok": False, "user": "", "login": "", "roles": [], "detail": i18n._("Hub ответил кодом {status}.", status=status)}


def clip_result(result: dict) -> dict:
    """Результат от исполнителя -> что хранится: только известные поля, тело – до предела."""
    body = str(result.get("body_text") or "")
    truncated = bool(result.get("truncated"))
    if len(body.encode("utf-8")) > RESULT_MAX:
        body = body.encode("utf-8")[:RESULT_MAX].decode("utf-8", "ignore")
        truncated = True
    raw_headers = result.get("headers")
    headers: dict = raw_headers if isinstance(raw_headers, dict) else {}
    kept = {str(k).lower(): str(v)[:2000] for k, v in headers.items() if str(k).lower() in ("location", "content-type")}
    try:
        status = int(result.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    try:
        took = int(result.get("took_ms") or 0)
    except (TypeError, ValueError):
        took = 0
    return {"status": status, "headers": kept, "body_text": body, "truncated": truncated,
            "error": str(result.get("error") or "")[:2000], "took_ms": max(0, took),
            "not_sent": result.get("not_sent") is True}


# ============================================================================ ключ исполнителя


def load_or_create_worker_key(keys: Any) -> str:
    """Ключ исполнителя (ADR-0114 п. 3, ADR-0133): в базе, нет – создаётся один раз (32 случайных байта в виде hex). Испорченное значение –
    ValueError с понятным текстом: молча подменять ключ нельзя, исполнитель перестал бы подключаться без объяснения."""
    from app.storage.local_state import WORKER_SECRET
    key = keys.ensure_secret(WORKER_SECRET, lambda: secrets.token_hex(32)).strip()
    if not _KEY_RE.fullmatch(key):
        raise ValueError(i18n._("Ключ исполнителя в базе повреждён. Выпустите ключ заново в настройках (раздел «AppSec.Hub») и "
                                "впишите новый в настройки исполнителя."))
    return key


def rotate_worker_key(keys: Any) -> str:
    """Новый ключ исполнителя."""
    from app.storage.local_state import WORKER_SECRET
    key = secrets.token_hex(32)
    keys.put_secret(WORKER_SECRET, key)
    return key


def key_matches(supplied: str, expected: str) -> bool:
    """Ключ из заголовка совпадает с ключом в базе (сравнение за постоянное время)."""
    return bool(expected) and bool(supplied) and secrets.compare_digest(str(supplied).strip().encode("ascii", "replace"),
                                                                        expected.encode("ascii"))


# ============================================================================ проверка связи: текст для страницы


def probe_view(op: dict | None) -> dict:
    """Состояние операции «Проверить связь» для страницы настроек: {state, final, ok, text}."""
    if op is None:
        return {"state": "", "final": True, "ok": False, "text": ""}
    state = op["state"]
    if state == "queued":
        return {"state": state, "final": False, "ok": False,
                "text": i18n._("Ждём исполнителя: он заберёт проверку при следующем обращении к приложению.")}
    if state == "taken":
        return {"state": state, "final": False, "ok": False, "text": i18n._("Исполнитель выполняет запрос к Hub…")}
    result = parse_json(op.get("result_json") or "") or {}
    if state == "done":
        outcome = probe_outcome(result)
        if outcome["ok"]:
            roles = ", ".join(outcome["roles"]) or i18n._("не указаны")
            return {"state": state, "final": True, "ok": True,
                    "text": i18n._("Связь с Hub есть: вошли как {user} ({login}), роли: {roles}.",
                                   user=outcome['user'], login=outcome['login'], roles=roles)}
        return {"state": state, "final": True, "ok": False, "text": outcome["detail"] or i18n._("Hub ответил без имени.")}
    if state == "failed" and result:
        return {"state": state, "final": True, "ok": False, "text": probe_outcome(result)["detail"]}
    if state == "cancelled":
        return {"state": state, "final": True, "ok": False, "text": i18n._("Проверка отменена.")}
    return {"state": state, "final": True, "ok": False,
            "text": i18n._("Проверка не удалась: {error}.",
                           error=error_text(op.get('error')) or i18n._("исполнитель не вернул результат"))}

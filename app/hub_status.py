"""Статус находки в Hub из приложения (этап 2, ADR-0115): «Ложное срабатывание» и «Риск принят» с комментарием
оператора и сроком действия уходят в Hub одним запросом через исполнителя (ADR-0114).

Здесь – чистые правила: тип находки Hub по виду находки, машинное значение статуса (русские подписи статусов в
настройках – только для текста), срок действия (дата из календаря или быстрого срока → expiredAt), сборка запроса –
одна находка `POST /issue/status/update`, группа `POST /issue/status/change`, – и сверка «результата неизвестен» по
чтению `GET /issue/status`. Постановку в очередь и отметки делают маршруты карточек (app/routes/hub_status_routes.py).
"""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime, timedelta
from typing import Any

from app import hub_ops

HUB_ISSUE_TYPE = {"SAST": "SAST", "SCA": "SCA_S", "SCA-license": "SCA_L", "DAST": "DAST"}
# итог разбора -> машинное значение статуса в API Hub (IssueStatusChangeRequestDto.status)
API_STATUS = {"false_positive": "False Positive", "risk_accepted": "Accepted risk"}
API_STATUS_LABEL = {"False Positive": "Ложное срабатывание", "Accepted risk": "Риск принят"}
EXPIRY_MAX_DAYS = 5 * 366  # срок действия статуса – не дальше пяти лет
# Замена комментария у статуса, который уже стоит в Hub (dev29): Hub принимает комментарий только со
# сменой статуса и отклоняет повтор того же статуса («issue already has the requested status»), а исходный
# «To verify» ручной сменой не ставит (Hub отвечает 400 «To verify is not available for status change»).
# Замена идёт двумя операциями по явному подтверждению оператора: промежуточный статус «Confirmed» (dev31; из статусов,
# которые Hub принимает в этом запросе, единственный без решения приложения) со служебным пояснением, затем прежний
# итог с новым комментарием и сроком. Первый шаг отметки «Внесено в Hub» не ставит.
RESET_STATUS = "Confirmed"
RESET_LABEL = "Подтверждено"
RESET_REASON = ("Технический шаг приложения «Локальный триаж»: прежний статус снимается для замены комментария, "
                "следующая запись возвращает его с новым обоснованием.")
ALREADY_RE = re.compile(r"already has the requested status", re.IGNORECASE)
REASON_MAX = 4000  # знаков комментария к статусу
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class StatusRefused(ValueError):
    """Статус не отправляется; текст – по-русски, для карточки."""


def issue_type(kind: str) -> str:
    """Вид находки приложения -> тип находки Hub; неизвестный вид – StatusRefused."""
    value = HUB_ISSUE_TYPE.get(str(kind or ""))
    if not value:
        raise StatusRefused(f"Для находки вида «{kind}» отправка статуса в Hub не поддерживается.")
    return value


def issue_id(hub_id: str) -> int:
    """Номер находки Hub (колонка «Issue id» выгрузки) – целое число."""
    text = str(hub_id or "").strip()
    if not (text.isascii() and text.isdigit() and 0 < int(text) < 10**12):
        raise StatusRefused(f"Номер находки «{text}» – не номер Hub: отправить статус нельзя.")
    return int(text)


def api_status(outcome: str) -> str:
    value = API_STATUS.get(outcome)
    if not value:
        raise StatusRefused("В Hub из приложения уходят только «Ложное срабатывание» и «Риск принят».")
    return value


def expired_at(raw: str, today: date) -> str:
    """Срок действия статуса из поля карточки (ГГГГ-ММ-ДД, обязателен) -> expiredAt (ISO 8601, UTC, начало дня).
    Дата – позже сегодняшней и не дальше пяти лет."""
    text = str(raw or "").strip()
    if not text:
        raise StatusRefused("Укажите срок действия статуса: дату или быстрый срок +30, +90, +180 дней.")
    if not _DATE.fullmatch(text):
        raise StatusRefused("Срок действия статуса – дата в виде ГГГГ-ММ-ДД.")
    try:
        day = date.fromisoformat(text)
    except ValueError:
        raise StatusRefused("Срок действия статуса – такой даты нет.") from None
    if day <= today:
        raise StatusRefused("Срок действия статуса должен быть позже сегодняшней даты.")
    if day > today + timedelta(days=EXPIRY_MAX_DAYS):
        raise StatusRefused("Срок действия статуса – не дальше пяти лет.")
    return f"{day.isoformat()}T00:00:00Z"


def clean_reason(text: str) -> str:
    """Комментарий к статусу как уходит в Hub: без пустых строк по краям и хвостовых пробелов, отступ первой строки –
    как написан (ADR-0149 п. 5); пустой или длиннее REASON_MAX – отказ."""
    from app.defect import edges
    reason = edges(text)
    if not reason.strip():
        raise StatusRefused("Комментария к статусу нет: сохраните решение с обоснованием.")
    if len(reason) > REASON_MAX:
        raise StatusRefused(f"Комментарий к статусу длиннее {REASON_MAX} знаков: сократите обоснование.")
    return reason


def status_request(issues: list[dict], status: str, reason: str, expired: str) -> dict:
    """Запрос смены статуса: одна находка – update, несколько – change (одним запросом)."""
    if not issues:
        raise StatusRefused("Нет находок для отправки статуса.")
    if len(issues) == 1:
        body: dict[str, Any] = {"issueId": issues[0]["issue_id"], "issueType": issues[0]["issue_type"],
                                "status": status, "reason": reason, "expiredAt": expired}
        request = {"method": "POST", "path": "/issue/status/update", "body": body}
    else:
        body = {"issues": [{"issueId": t["issue_id"], "issueType": t["issue_type"]} for t in issues],
                "status": status, "reason": reason, "expiredAt": expired}
        request = {"method": "POST", "path": "/issue/status/change", "body": body}
    hub_ops.check_request(request["method"], request["path"])
    return request


def replace_request(target: dict, status: str, reason: str, expired: str) -> dict:
    """Первый шаг замены комментария (dev29): промежуточный статус (RESET_STATUS) со служебным пояснением и тем же
    сроком; второй шаг –
    `then` – тот же статус с новым комментарием, ставится после ответа Hub на первый (hub_effects.chain_replace).
    Hub хранит `then` не видит: это часть записи операции, не тела запроса."""
    request = status_request([target], RESET_STATUS, RESET_REASON, expired)
    request["then"] = {"status": status, "reason": clean_reason(reason), "expiredAt": expired}
    return request


def _request_of(op: dict | None) -> dict:
    raw = (op or {}).get("request_json")
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def is_reset(op: dict | None) -> bool:
    """Операция статуса – первый шаг замены комментария: в её записи есть второй шаг (`then`). Признак – не статус
    тела: первые шаги до dev31 уходили с «To verify» (Hub их отклонил), с dev31 – с RESET_STATUS."""
    return bool(op and op.get("purpose") == "status" and chain_of(op))


def chain_of(op: dict | None) -> dict:
    """Второй шаг замены, записанный в операции первого: {status, reason, expiredAt}; нет – {}."""
    then = _request_of(op).get("then")
    return then if isinstance(then, dict) and then.get("status") and then.get("reason") else {}


def already_refused(op: dict | None) -> bool:
    """Отказ Hub «issue already has the requested status»: статус у находки уже стоит, комментарий в Hub прежний."""
    return bool(op and op.get("purpose") == "status" and op.get("state") == "failed"
                and ALREADY_RE.search(str(op.get("error") or "")))


_REFUSED_ISSUE = re.compile(r"issue\s*#\s*([0-9]{1,12})", re.IGNORECASE)


def refused_issue_ids(op: dict | None) -> set[str]:
    """Находки, о которых отказ Hub «already has the requested status» говорит точно: у операции с одной целью – она;
    у групповой – только номера, названные в пояснении Hub («SAST issue #101 …»); остальных находок группы отказ не
    касается (ревью dev29, круг 2). Пусто – отказ ни к кому не привязан."""
    if not already_refused(op):
        return set()
    try:
        targets = json.loads((op or {}).get("targets_json") or "[]") if not isinstance((op or {}).get("targets_json"), list) \
            else (op or {}).get("targets_json")
    except (TypeError, ValueError):
        targets = []
    pairs = [(str(t.get("hub_id") or ""), str(t.get("issue_id") or "")) for t in targets if isinstance(t, dict)]
    if len(pairs) == 1:
        return {pairs[0][0]}
    # Hub называет числовой номер (issueId): локальный номер с ведущими нулями («00101») сопоставляется по числу
    # (ревью dev29, круг 15)
    named = {str(int(n)) for n in _REFUSED_ISSUE.findall(str((op or {}).get("error") or ""))}
    return {hub_id for hub_id, issue in pairs if issue and str(int(issue)) in named}


def sent_status(op: dict | None) -> str:
    """Статус из тела запроса операции статуса; нет – «»."""
    body = _request_of(op).get("body") or {}
    return str(body.get("status") or "") if isinstance(body, dict) else ""


def read_request(target: dict) -> dict:
    """Чтение сведений о смене статуса находки (для сверки «результата неизвестен»)."""
    request = {"method": "GET", "path": f"/issue/status?issueId={int(target['issue_id'])}"
                                         f"&issueType={target['issue_type']}", "body": None}
    hub_ops.check_request(request["method"], request["path"])
    return request


_ISO_OFFSET = re.compile(r"([+-][0-9]{2})([0-9]{2})$")  # +0300 -> +03:00 (так отдаёт время Java)


def _day(value: Any) -> str:
    """Дата из ответа Hub -> ГГГГ-ММ-ДД по UTC; не разобрать – «». Принимается: миллисекунды с эпохи, дата
    ГГГГ-ММ-ДД, дата и время ISO 8601 целиком (смещение приводится к UTC, без смещения – UTC). Строка с лишними
    знаками (`2027-01-26мусор`) не разбирается: сверка срока по ней не проходит."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value / 1000, UTC).date().isoformat()
        except (OverflowError, OSError, ValueError):
            return ""
    text = str(value or "").strip()
    if _DATE.fullmatch(text):
        try:
            return date.fromisoformat(text).isoformat()
        except ValueError:
            return ""
    if not _DATE.match(text) or len(text) < 11 or text[10] not in "Tt ":
        return ""
    text = _ISO_OFFSET.sub(r"\1:\2", text[:-1] + "+00:00" if text[-1:] in "Zz" else text)
    try:
        moment = datetime.fromisoformat(text)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        return moment.astimezone(UTC).date().isoformat()
    except (ValueError, OverflowError):  # нет такой даты или перевод в UTC за пределами календаря
        return ""


def status_matches(answer: Any, status: str, reason: str, expired: str, target: dict | None = None) -> bool:
    """Ответ `GET /issue/status` (IssueChangeStatusInfoDto) совпадает с отправленным: статус, комментарий (по
    нормализованному тексту) и дата срока. Пустой ответ (статус не менялся) или иное – не совпадает. target – цель
    чтения {issue_id, issue_type}: ответ должен нести номер и тип той же находки (issueId – целое число, как требует
    и чтение синхронизации; issueType – и по имени, которое Hub пишет в ручной записи, «SCA Security»). Ответ о другой
    находке, без номера или без типа не совпадает: исход остаётся неизвестным, решает оператор (бэклог 118)."""
    if not isinstance(answer, dict):
        return False
    if target is not None:
        from app.hub_sync_api import same_issue_type
        ident = answer.get("issueId")
        if not isinstance(ident, int) or isinstance(ident, bool) or str(ident) != str(target.get("issue_id") or ""):
            return False
        kind = answer.get("issueType")
        if not isinstance(kind, str) or not same_issue_type(kind, str(target.get("issue_type") or "")):
            return False
    return (str(answer.get("status") or "") == status
            and hub_ops.normalize_text(answer.get("reason")) == hub_ops.normalize_text(reason)
            and _day(answer.get("expiredAt")) == expired[:10])

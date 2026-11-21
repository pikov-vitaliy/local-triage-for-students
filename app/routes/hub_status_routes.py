"""Отправка статуса находки в Hub из карточки (этап 2, ADR-0115): «Ложное срабатывание» SAST (группа «та же
строка, категория и код» – одним запросом) и «Ложное срабатывание» / «Риск принят» SCA – с комментарием оператора и
сроком действия. Запросы выполняет исполнитель (ADR-0114); отметку «Внесено в Hub» ставит ответ Hub (hub_effects).

  POST /projects/{id}/findings/{finding_id}/hub-status      – SAST
  POST /projects/{id}/sca/findings/{finding_id}/hub-status  – SCA
  GET  /projects/{id}/hub/ops/{op_id}                       – состояние операции для опроса из карточки
  POST /projects/{id}/hub/verify                            – сверка «результата неизвестен» чтением статуса (op_id
                                                              в форме: кнопка появляется в карточке без перезагрузки)

Замена комментария у статуса, который уже стоит в Hub (dev29, ADR-0130): те же адреса отправки с полем формы
replace=1 и подтверждением replace_confirm=1 – первый шаг – промежуточный статус «Подтверждено», второй ставит hub_effects.chain_replace.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any, Callable

from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app import hub_defects, hub_effects, hub_ops, hub_status, hub_sync, hub_sync_compare
from app.db import Database, finding_data_sig, hub_verdict, loads, text_hash
from app.defect import edges
from app.models import Finding
from app.routes.common import (
    CommentNeedsCheck,
    comment_check_text,
    comment_confirm_valid,
    db_of,
    error_response,
    form_int,
    project_or_404,
    redirect,
    register_messages,
    settings_of,
    web_of,
)
from app.sca_research import review_presets

router = APIRouter()

SAST_STATUS_OUTCOMES = ("false_positive",)
SCA_STATUS_OUTCOMES = ("false_positive", "risk_accepted")
STALE_REVISION = ("Решение изменилось в другой вкладке, пока карточка была открыта: обновите карточку и отправьте "
                  "ещё раз.")


DATA_CHANGED = ("Выгрузка обновилась, пока карточка была открыта: данные находки изменились. Обновите карточку, "
                "проверьте решение и отправьте ещё раз.")
TEXT_CHANGED = ("Текст для Hub изменился с тех пор, как карточка его показала (например, пришло соответствие номеров "
                "или новый ответ агента): обновите карточку, проверьте текст и отправьте ещё раз.")
TEXT_NOT_SHOWN = ("Карточка не показала текст для Hub (решение не сохранено или данные менялись при её сборке): "
                  "сохраните решение или обновите карточку и отправьте ещё раз.")
DRAFT_NOTE = "Решение не сохранено: отправить в Hub можно после сохранения – уйдёт сохранённый текст."
UNSETTLED_NOTE = "Данные этой версии компонента менялись, пока собиралась карточка: обновите её, затем отправляйте."
NOT_REVIEWED = ("Находка не отмечена как проверенная (после обновления выгрузки её нужно проверить снова): "
                "отметьте «Проверено» и сохраните решение.")
TARGET_CHANGED = ("Приложение Hub или адрес Hub изменились, пока собирался запрос (в другой вкладке – «Параметры "
                  "проекта» или «Настройки»): ничего не отправлено – обновите карточку и повторите.")
# «Отправить в Hub» из карточки: форма несёт назначение, которое показала карточка (KIMI-12)
CARD_TARGET_CHANGED = ("Приложение Hub или адрес Hub изменились, пока карточка была открыта (в другой вкладке – "
                       "«Параметры проекта» или «Настройки»): ничего не отправлено – обновите карточку и отправьте ещё "
                       "раз.")


# форма без назначения (страница открыта до обновления приложения, 0.9.23.dev2) – не «изменилось», а «устарела»
CARD_FORM_OUTDATED = ("Страница открыта до обновления приложения: обновите карточку и отправьте ещё раз – ничего не "
                      "отправлено.")
# статус уже стоит в Hub у самой находки (dev29): повторно Hub его не принимает – обычная отправка отклоняется до
# запроса, комментарий заменяется двумя шагами по подтверждению
ALREADY_IN_HUB = ("В Hub у находки уже стоит статус «{label}»: повторно тот же статус Hub не принимает, комментарий "
                  "в Hub остаётся прежним. Чтобы заменить комментарий, подтвердите «Обновить комментарий в Hub».")
REPLACE_CONFIRM = ("Подтвердите замену комментария: отметьте, что статус в Hub сменится на «Подтверждено» и обратно, а "
                   "в истории Hub появятся две записи.")
REPLACE_NOT_NEEDED = ("Статуса «{label}» у находки в Hub сейчас нет: обновите карточку и отправьте решение кнопкой "
                      "«Отправить в Hub».")
REPLACE_DONE = ("Текущий текст решения уже внесён в Hub: заменять нечего. Обновите карточку.")
REPLACE_NOTE = ("В Hub у находки уже стоит «{label}», а комментарий там прежний: повторно тот же статус Hub не "
                "принимает. «Обновить комментарий в Hub» сменит статус на «Подтверждено» (Confirmed) и сразу вернёт «{label}» с "
                "текущим комментарием и сроком из поля – в истории статусов Hub появятся две записи. Соседи по группе "
                "не затрагиваются: их комментарий меняется из их карточек.")
REPLACE_CHECK = ("Понимаю: статус в Hub сменится на «Подтверждено» и обратно на «{label}», в истории Hub будет две "
                 "записи")


class StaleTarget(hub_status.StatusRefused):
    """Решение или данные одной из находок операции изменились между сборкой запроса и постановкой."""


def shown_target(form) -> tuple[str, int]:
    """Назначение записи в Hub, которое показала форма (KIMI-12, бэклог 44): скрытые поля hub_base (основа адреса Hub,
    hub_ops.hub_base) и hub_app_id (номер приложения Hub проекта) – их ставят «Отправить в Hub» карточки и «Отправить
    выбранные в Hub», со скриптом и без. Поля нет или оно испорчено – ("", 0): hub_target_check откажет."""
    app_id = str(form.get("hub_app_id") or "").strip()
    return hub_ops.hub_base(str(form.get("hub_base") or "")), int(app_id) if app_id.isdigit() else 0


def same_target(hub_url: str, app_id: Any, shown: tuple[str, int]) -> bool:
    """Назначение, прочитанное маршрутом (адрес Hub из настроек и номер приложения проекта), – то, что показала форма
    (shown_target): по нему собраны состав и запрос."""
    return bool(shown[0] and shown[1]) and (hub_ops.hub_base(hub_url), int(app_id or 0)) == shown


def hub_target_check(request: Request, project_id: int, hub_url: str, app_id: Any, message: str = TARGET_CHANGED,
                     shown: tuple[str, int] | None = None):
    """Проверка в транзакции постановки записи в Hub (KIMI-12, бэклог 44): номер приложения Hub проекта и адрес Hub из
    настроек сейчас – те же, что показаны оператору, и те же, по которым собрана операция (hub_url, app_id; адрес
    сравнивается по основе hub_ops.hub_base, как у ключа операции). Показанное назначение: у «Отправить в Hub» из
    карточки и «Отправить выбранные в Hub» – из полей формы (shown, shown_target: что видел оператор, а не прочитанное
    в начале POST), у «Создать» – назначение строки дефекта, по которому собран предпросмотр, у «Подготовить дефект» и
    «Привязать к дефекту» – прочитанное маршрутом (заготовки ещё нет; готовый дефект выбран по нему и сверяется формой).
    Их сменили в другой вкладке – отказ StaleTarget(message) до записи: ни строки операции, ни запроса к Hub.
    Действующий адрес – как у settings_of: сохранённый в базе поверх значения из окружения (Database.hub_target_in).
    Ставится первой проверкой транзакции: при другой цели прочие отказы ничего не объясняют."""
    base = web_of(request).base
    used = (hub_ops.hub_base(hub_url), int(app_id or 0))
    seen = used if shown is None else (str(shown[0] or ""), int(shown[1] or 0))

    def check(c) -> None:
        current_app, stored = Database.hub_target_in(c, project_id)
        current = (hub_ops.hub_base(base.with_stored(stored).hub_url), int(current_app or 0))
        if not seen[0] or not seen[1] or used != seen or current != seen:
            raise StaleTarget(message)
    return check


register_messages({
    "hub_queued": "Поставлено в очередь исполнителю: состояние – в блоке «Отправить в Hub».",
    "hub_queued_skipped": "Поставлено в очередь исполнителю: состояние – в блоке «Отправить в Hub». Соседи по группе, "
                          "чей статус уже внесён в Hub, не отправляются: тот же статус Hub повторно не ставит.",
    "hub_queued_defect": "Поставлено в очередь исполнителю: состояние – в блоке «Отправить в Hub». Соседи по группе, входящие в дефект, не отправляются: их статус в Hub идёт через дефект.",
    "hub_queued_skipped_defect": "Поставлено в очередь исполнителю: состояние – в блоке «Отправить в Hub». Не отправляются соседи по группе, чей статус уже внесён в Hub, и соседи, входящие в дефект (их статус идёт через дефект); номера называет отправка со скриптом.",
    "hub_verify_queued": "Сверка поставлена в очередь исполнителю: итог – в блоке «Отправить в Hub».",
})


def today() -> date:
    return date.today()


# ============================================================================ условия и вид для карточки


def send_blocker(settings, project: dict) -> str:
    """Почему отправка в Hub недоступна для проекта: «» – доступна."""
    if not settings.hub_url:
        return "Адрес Hub не задан: «Настройки» → раздел «AppSec.Hub»."
    if not project.get("hub_app_id"):
        return "Номер приложения в Hub не задан: «Параметры проекта» → «Приложение в Hub»."
    return ""


def until_moment(expired_at: Any) -> str:
    """Конец срока так, как его хранит Hub: конец выбранного дня по UTC (ГГГГ-ММ-ДДT23:59:59Z,
    docs/hub-format.md). Интерфейс Hub показывает это время в часовом поясе браузера – карточка тоже; нет даты – «»."""
    day = str(expired_at or "")[:10]
    if len(day) != 10:
        return ""
    try:
        date.fromisoformat(day)
    except ValueError:
        return ""
    return f"{day}T23:59:59Z"


SUPERSEDED_NOTE = " Позже статус в Hub изменили (принято «Pull из Hub»): отметка снята, отправить можно снова."


def _reset_view(op: dict, checking: bool) -> dict:
    """Состояние первого шага замены комментария (промежуточный статус «Подтверждено», dev29/dev31) для карточки."""
    state = op["state"]
    then = hub_status.chain_of(op)
    label = hub_status.API_STATUS_LABEL.get(str(then.get("status") or ""), str(then.get("status") or ""))
    error = str(op.get("error") or "")
    if state == "unknown" and checking:
        text, tone, verify, final = "Сверяем с Hub: исполнитель читает статус…", "warn", False, False
    else:
        texts = {
            "queued": (f"В очереди: ждём исполнителя – замена комментария в Hub: сначала «Подтверждено», затем «{label}» "
                       "с новым комментарием.", "", False),
            "taken": ("Исполнитель снимает прежний статус в Hub (ставит «Подтверждено»)…", "", False),
            # выполнен: второй шаг поставлен (карточка обычно уже показывает его), ещё ставится (последствия ответа
            # не доставлены – опрос продолжается, ревью круг 5) или не поставлен – пояснение из записи операции
            "done": ((f"Прежний статус в Hub снят (стоит «Подтверждено»): {hub_effects.CHAIN_NOTE_QUEUED}.", "ok", False)
                     if then.get("chained") else
                     ("Прежний статус в Hub снят (стоит «Подтверждено»); ставлю второй шаг – прежний статус с новым "
                      "комментарием…", "", False) if then.get("chained") is None else
                     (f"Прежний статус в Hub снят (стоит «Подтверждено»): {error or 'второй шаг не поставлен'}.", "warn", False)),
            "failed": (f"Hub не принял снятие прежнего статуса: {error or 'ошибка'}. Статус и комментарий в Hub "
                       "прежние; можно повторить.", "err", False),
            "unknown": (f"Результат первого шага неизвестен ({error or 'ответа нет'}). Нажмите «Pull из Hub»: "
                        "приложение прочитает статус; повторно само не отправит.", "warn", True),
            "cancelled": (op.get("error") or "Отправка отменена.", "", False),
        }
        text, tone, verify = texts.get(state, ("", "", False))
        final = state not in ("queued", "taken") and not (state == "done" and then.get("chained") is None)
    return {"state": state, "final": final, "text": text, "tone": tone, "verify": verify, "op_id": op["id"],
            "time": None}


def op_view(op: dict | None, checking: bool = False, pending: bool = False, superseded: bool = False,
            hub_id: str = "", refusal_stale: bool = False, replace_active: bool = True,
            text_current: bool = False) -> dict:
    """Состояние операции статуса для карточки: {state, final, text, tone, verify, op_id, time}. checking – у операции
    «результат неизвестен» идёт сверка (чтение статуса в очереди или у исполнителя): опрос продолжается. time –
    текст со сроком частями {prefix, datetime, fallback, suffix}: скрипт показывает срок в часовом поясе браузера,
    как интерфейс Hub; без скрипта – fallback по UTC (тот же момент); у состояний без срока – None. superseded –
    запись выполнена, но по последней принятой версии (status_in_hub) этого статуса в Hub уже нет: текст называет её
    историей (ревью dev16, B1). hub_id – находка карточки: отказ группового запроса «already has the requested
    status» относится только к названным Hub находкам (ревью dev29, круг 3)."""
    if op is None:
        return {"state": "", "final": True, "text": "", "tone": "", "verify": False, "op_id": None, "time": None}
    if hub_status.is_reset(op):
        return _reset_view(op, checking)
    state = op["state"]
    body = (loads(op.get("request_json"), {}) or {}).get("body") or {}
    label = hub_status.API_STATUS_LABEL.get(str(body.get("status") or ""), str(body.get("status") or ""))
    moment = until_moment(body.get("expiredAt"))
    fallback = f"{moment[8:10]}.{moment[5:7]}.{moment[0:4]}, 23:59 UTC" if moment else "–"
    count = len(loads(op.get("targets_json"), []))
    head, tail = f"«{label}», срок до ", (f", находок: {count}" if count > 1 else "")
    dated = {  # состояния, в тексте которых есть срок: (начало, конец, тон, «Сверить»)
        "queued": ("В очереди: ждём исполнителя – ", ".", "", False),
        "taken": ("Исполнитель отправляет в Hub ", "…", "", False),
        "done": ("Записано в Hub: ", ".", "ok", False),
    }
    legacy = hub_effects.legacy_status_needs_read(op)
    if (state == "unknown" or legacy) and checking:
        lead, end, tone, verify, final = "Сверяем с Hub: исполнитель читает статус ", "…", "warn", False, False
    elif legacy:
        return {"state": state, "final": True, "text": "Отправка завершена до обновления приложения. Для отметки "
                "«Внесено в Hub» подтвердите новое чтение кнопкой «Pull из Hub». " + str(op.get("error") or ""),
                "tone": "warn", "verify": True, "op_id": op["id"], "time": None}
    elif state == "done" and pending:  # ответ записан, отметки – после повторной доставки (hub_effects.effects_pending)
        lead, end, tone, verify, final = "Записано в Hub: ", ". Ставлю отметку «Внесено в Hub»…", "ok", False, False
    elif state in dated:
        lead, end, tone, verify = dated[state]
        final = state not in ("queued", "taken")
        if state == "done" and superseded:
            end, tone = end + SUPERSEDED_NOTE, "warn"
    else:
        named = hub_status.refused_issue_ids(op)
        texts = {
            "failed": ((f"Hub не принял тогда: статус «{label}» у находки уже стоял. Позже принята другая версия "
                        "находки – это история, отправить можно снова.", "", False)
                       if hub_status.already_refused(op) and (not hub_id or hub_id in named) and refusal_stale else
                       (f"Hub не принял: статус «{label}» у находки уже стоит, комментарий в Hub прежний. Заменить "
                        "комментарий можно кнопкой «Обновить комментарий в Hub».", "warn", False)
                       if hub_status.already_refused(op) and (not hub_id or hub_id in named) and replace_active else
                       (f"Hub не принял: статус «{label}» у находки уже стоит; текущий текст решения совпадает с "
                        "внесённым – отправлять нечего.", "", False)
                       if hub_status.already_refused(op) and (not hub_id or hub_id in named) and text_current else
                       # решение с тех пор другое (другой итог): отказ прежней отправки – без утверждения о доставке
                       # (ревью dev29, круг 7)
                       (f"Hub не принял прежнюю отправку: статус «{label}» у находки уже стоит. Текущее решение "
                        "другое – отправьте его.", "", False)
                       if hub_status.already_refused(op) and (not hub_id or hub_id in named) else
                       (f"Hub не принял групповую отправку: статус «{label}» уже стоит у "
                        f"{', '.join(sorted(named)) or 'одной из находок группы'}; эта находка не отправлена – "
                        "отправьте ещё раз, названные соседи в группу не войдут.", "err", False)
                       if hub_status.already_refused(op) else
                       (f"Hub не принял: {op.get('error') or 'ошибка'}. Можно отправить ещё раз.", "err", False)),
            "unknown": (f"Результат неизвестен ({op.get('error') or 'ответа нет'}). Нажмите «Сверить»: приложение "
                        "прочитает статус в Hub; повторно само не отправит.", "warn", True),
            "cancelled": (op.get("error") or "Отправка отменена.", "", False),
        }
        text, tone, verify = texts.get(state, ("", "", False))
        return {"state": state, "final": True, "text": text, "tone": tone, "verify": verify, "op_id": op["id"],
                "time": None}
    time = {"prefix": lead + head, "datetime": moment, "fallback": fallback, "suffix": tail + end} if moment else None
    return {"state": state, "final": final, "text": lead + head + fallback + tail + end, "tone": tone,
            "verify": verify, "op_id": op["id"], "time": time}


def checking_of(db: Database, op: dict | None) -> bool:
    """Идёт ли сверка операции «результат неизвестен»: есть незакрытое чтение статуса с verify_of = её номер."""
    if op is None or (op["state"] != "unknown" and not hub_effects.legacy_status_needs_read(op)):
        return False
    return any(v["state"] in ("queued", "taken") for v in db.hub_verifications(int(op["id"])))


def card_context(request: Request, project: dict, hub_id: str, text: str = "", note: str = "") -> dict:
    """Блок «Отправить в Hub» карточки: доступна ли отправка, последняя операция статуса, быстрые сроки. text – текст
    для Hub по сохранённому решению, та же строка, что карточка показывает в предпросмотре и что уйдёт в reason: его
    отпечаток едет с формой (ADR-0115 п. 3). Черновик (решение не сохранено) и карточка, собранная из несогласованных
    чтений, текста не передают – отпечатка нет, отправка откажет; note – почему. hub_base и hub_app_id – назначение
    (основа адреса Hub и номер приложения), которое форма отправляет с запросом: сменили после показа – отказ
    (shown_target, KIMI-12)."""
    db = db_of(request)
    db.hub_expire_leases()
    now = today()
    settings = settings_of(request)
    found = _finding_of(db, int(project["id"]), str(hub_id))
    now_view = status_now(db, project, settings, found) if found else {}
    fixed = is_fixed(now_view)
    last = db.hub_last_op(int(project["id"]), str(hub_id), "status",
                          hub_url=settings.hub_url, app_id=project.get("hub_app_id"))
    review = db.get_review(int(project["id"]), str(hub_id)) or {}
    pending = hub_effects.effects_pending(db, last)
    superseded = False
    if last is not None and last["state"] == "done" and not pending:
        sent = str(((loads(last.get("request_json"), {}) or {}).get("body") or {}).get("status") or "")
        # отметки нет (снята при Pull) и отправленного статуса в Hub нет; при принятом из Hub другом решении (FP →
        # «Риск принят», отметка Pull) подписи нет (ревью dev16, B2)
        superseded = (bool(sent) and not review.get("entered_hub")
                      and not db.status_in_hub(int(project["id"]), str(hub_id), sent, status_in_hub,
                                               settings.hub_url, project.get("hub_app_id")))
    replace = replace_view(db, project, settings, str(hub_id), review, text)
    # отказ «already has…», погашенный более поздней принятой версией (и Pull с тем же статусом), – история
    # (ревью dev29, круги 5 и 6)
    refusal_stale = bool(last is not None and hub_status.already_refused(last)
                         and str(hub_id) in hub_status.refused_issue_ids(last)
                         and not db.on_connection(lambda c: refusal_current_in(
                             c, int(project["id"]), str(hub_id), last, settings.hub_url, project.get("hub_app_id"))))
    last_view = op_view(last, checking_of(db, last), pending, superseded, hub_id=str(hub_id),
                        refusal_stale=refusal_stale, replace_active=replace["active"],
                        text_current=bool(replace.get("current")))
    if fixed and last_view.get("final") and last_view.get("tone") == "err":
        # статус «Fixed»: прежний отказ с «Можно отправить ещё раз» спорил бы с «Отправлять нечего» (проход в браузере 06.11);
        # незавершённая операция остаётся на виду
        last_view = {**last_view, "text": "", "tone": "", "time": None}
    return {"blocker": send_blocker(settings, project) or hub_sync.resync_blocker(db, project["id"]),
            "expires": hub_status._day(review.get("desired_hub_expired_at")) or replace["expires"],
            "replace": replace,
            "last": last_view,
            "presets": review_presets(now), "min": (now + timedelta(days=1)).isoformat(),
            "max": (now + timedelta(days=hub_status.EXPIRY_MAX_DAYS)).isoformat(),
            "hub_base": hub_ops.hub_base(settings.hub_url), "hub_app_id": project.get("hub_app_id") or "",
            "hub_url": settings.hub_url, "sig": db.finding_sig(int(project["id"]), str(hub_id)), "hub_id": str(hub_id),
            "text_hash": text_hash(text) if text else "", "note": note,
            # находка входит в дефект (dev32): панели отправки нет – пояснение и ссылка на дефект
            "in_defect": in_defect_view(db, int(project["id"]), str(hub_id)),
            # статус «Fixed» (dev7): формы отправки нет, причина названа
            "fixed": fixed_refusal(now_view) if fixed else "", "fixed_from_export": fixed and now_view.get("source") == "из выгрузки"}


def in_defect_view(db: Database, project_id: int, hub_id: str) -> dict:
    """Находка входит в дефект (строка «создан», «привязка» и т. п. – hub_defect_bound): {text, url, label}; нет – {}."""
    row = db.hub_defect_bound(project_id, hub_id)
    if row is None:
        return {}
    return {"text": hub_defects.in_defect_text(row), "label": hub_defects.bound_label(row),
            "url": f"/projects/{project_id}/defects/{int(row['id'])}"}


# последние отказы отправки этого статуса по находке (ревью dev29, круг 4: неудавшийся первый шаг замены или другой
# отказ свидетельство «already has…» не стирают – его гасит только смена принятой версии)
# отказы Hub «already has the requested status» по находке – все, без усечения (ревью, круг 11): прочие отказы
# (не отправлено, иной код) свидетельством не считаются и из выборки исключены
REFUSED_OPS_SQL = ("SELECT * FROM hub_ops WHERE project_id = ? AND purpose = 'status' AND hub_url = ? AND app_id IS NOT DISTINCT FROM ?"
                   " AND state = 'failed' AND error ILIKE '%already has the requested status%'"
                   " AND EXISTS (SELECT 1 FROM json_array_elements(hub_ops.targets_json::json) AS t(value)"
                   " WHERE (t.value ->> 'hub_id') = ?) ORDER BY id DESC")


def status_already_in(c, project_id: int, hub_id: str, status: str, hub_url: str, app_id: int | None) -> bool:
    """Статус status у самой находки уже стоит в Hub (dev29): по последней принятой версии (status_in_hub); версии
    в назначении нет – по отказу Hub «already has the requested status» на последнюю отправку этого статуса (Hub сам
    так сказал: статус поставлен руками и не прочитан). Принятая версия (Pull или подтверждённая запись) всегда
    главнее отказа: после принятого «To verify» старый отказ свидетельством не считается (ревью dev29, круг 2).
    c – соединение базы (или транзакция постановки)."""
    base, app = hub_ops.hub_base(hub_url), (int(app_id) if app_id else None)
    # свежий непогашенный отказ Hub «already has…» по находке (среди всех статусов) – последнее слово Hub: он
    # подтверждает названный в нём статус и опровергает остальные (ревью, круг 10); отказ группового запроса
    # называет находку («SAST issue #101») – свидетельство только для неё (круг 2)
    refusal = next((dict(r) for r in c.execute(REFUSED_OPS_SQL, (project_id, base, app, str(hub_id)))
                    if str(hub_id) in hub_status.refused_issue_ids(dict(r))
                    and refusal_current_in(c, project_id, hub_id, dict(r), hub_url, app_id)), None)
    if refusal is not None:
        return hub_status.sent_status(refusal) == status
    return status_in_hub(c, project_id, hub_id, status, hub_url, app_id)


def refusal_current_in(c, project_id: int, hub_id: str, op: dict, hub_url: str, app_id: int | None) -> bool:
    """Отказ Hub «already has…» (op) по находке ещё действует (ревью, круги 3 и 6): принятая версия цели та же, что была
    у операции в момент выдачи исполнителю (accepted_issue_bases); принятие Pull или подтверждённая запись после
    отказа меняют версию и гасят его, а принятие до отказа новый отказ не гасит. Отдельно от наличия статуса: Pull с
    тем же статусом тоже гасит отказ."""
    from app.hub_entity_versions import current
    base, app = hub_ops.hub_base(hub_url), (int(app_id) if app_id else None)
    kind = c.execute("SELECT kind FROM findings WHERE project_id = ? AND hub_id = ?",
                     (project_id, str(hub_id))).fetchone()
    typ = hub_status.HUB_ISSUE_TYPE.get(str(kind[0])) if kind else None
    try:
        ident = str(hub_status.issue_id(hub_id))
    except hub_status.StatusRefused:
        return False
    if not typ:
        return False
    key = f"{typ}:{ident}"
    bases = (loads(dict(op).get("request_json"), {}) or {}).get("accepted_issue_bases") or {}
    recorded = bases.get(key) if isinstance(bases, dict) else None
    if not isinstance(recorded, dict):
        recorded = {"accepted_epoch": 0, "accepted_hash": ""}
    now = current(c, project_id, base, app, "issue", key)
    return int(recorded.get("accepted_epoch") or 0) == int(now.get("accepted_epoch") or 0) and \
        str(recorded.get("accepted_hash") or "") == str(now.get("accepted_hash") or "")


def accepted_hub_reason(db: Database, project: dict, settings, hub_id: str, *, raw: bool = False) -> str:
    """Комментарий к статусу находки по принятому состоянию Hub (hub_issue_states, принятие Pull); нет – «»."""
    base, app = hub_ops.hub_base(settings.hub_url), (int(project["hub_app_id"]) if project.get("hub_app_id") else None)

    def read(c) -> str:
        kind = c.execute("SELECT kind FROM findings WHERE project_id = ? AND hub_id = ?",
                         (int(project["id"]), str(hub_id))).fetchone()
        typ = hub_status.HUB_ISSUE_TYPE.get(str(kind[0])) if kind else None
        try:
            ident = str(hub_status.issue_id(hub_id))
        except hub_status.StatusRefused:
            return ""
        if not typ or app is None:
            return ""
        state = c.execute(STATE_SQL, (int(project["id"]), base, app, typ, ident)).fetchone()
        if state is None or state[1] != "present":
            return ""
        hub, key = loads(state[0], {}) or {}, f"{typ}:{ident}"
        if raw:  # исходный комментарий принятой записи Hub, без схлопывания пробелов (ADR-0149, ревью Codex круга 7)
            source = hub_sync_compare.decision_source(hub, key) or {}
            status = (hub.get("detail") or {}).get("status")
            return str(source.get("comment" if status == "Accepted risk" else "reason") or "")
        return str(hub_sync_compare.issue_values(hub, key).get("reason") or "")
    return str(db.on_connection(read) or "")


DELIVERED_OPS_SQL = ("SELECT * FROM hub_ops WHERE project_id = ? AND purpose = 'status' AND state = 'done' AND hub_url = ?"
                     " AND app_id IS NOT DISTINCT FROM ? AND (request_json::json -> 'body' ->> 'status') = ? AND text_hash = ?"
                     " AND EXISTS (SELECT 1 FROM json_array_elements(hub_ops.targets_json::json) AS t(value)"
                     " WHERE (t.value ->> 'hub_id') = ? AND (t.value ->> 'revision') = ?)"
                     " ORDER BY id DESC")


def text_delivered_in(c, project_id: int, hub_id: str, status: str, reason: str, revision: int, hub_url: str,
                      app_id: int | None) -> bool:
    """Этот текст решения (той же редакции) уже записан в Hub выполненной операцией статуса, и её подтверждение –
    текущая принятая версия находки (ревью dev29, круг 13): независимо от доставки отметки «Внесено в Hub». Операция в
    другом назначении (другой Hub или приложение) не считается."""
    from app.hub_entity_versions import confirmable
    base, app = hub_ops.hub_base(hub_url), (int(app_id) if app_id else None)
    for row in c.execute(DELIVERED_OPS_SQL, (project_id, base, app, status, hub_ops.text_hash(reason), str(hub_id),
                                             str(int(revision)))):
        op = dict(row)
        # отпечаток text_hash схлопывает пробелы и переводы строк: тот же текст – буква в букву, иначе комментарий,
        # отличающийся только ими (формат 0.10.0.dev21, ADR-0149), считался бы уже внесённым (ревью Codex круга 6)
        sent = ((loads(op.get("request_json"), {}) or {}).get("body") or {}).get("reason")
        if str(sent or "") != str(reason or ""):
            continue
        target = next((t for t in loads(op.get("targets_json"), []) if str(t.get("hub_id") or "") == str(hub_id)), None)
        if target is None:
            continue
        _, confirmed, _, _ = confirmable(c, project_id, {**target, "entered_op_id": int(op["id"])})
        if confirmed:
            return True
    return False


def status_already(db: Database, project: dict, settings, hub_id: str, status: str) -> bool:
    """status_already_in на общем соединении (панель и отказ обычной отправки); транзакция постановки повторяет."""
    return bool(db.on_connection(lambda c: status_already_in(c, int(project["id"]), hub_id, status, settings.hub_url,
                                                             project.get("hub_app_id"))))


def replace_view(db: Database, project: dict, settings, hub_id: str, review: dict, text: str) -> dict:
    """Режим «Обновить комментарий в Hub» панели (dev29): итог сохранённого решения уже стоит в Hub у этой находки,
    а текущего текста решения там нет (отметки «Внесено в Hub» с его отпечатком нет). {active, already, status,
    label, note, check}; у черновика (text пуст) режим не определяется."""
    empty = {"active": False, "already": False, "current": False, "status": "", "label": "", "note": "", "check": "",
             "expires": ""}
    if not review or not review.get("decision") or not text:
        return empty
    row = db.get_finding_by_hub_id(int(project["id"]), hub_id)
    allowed = SAST_STATUS_OUTCOMES if row is not None and row["kind"] == "SAST" else SCA_STATUS_OUTCOMES
    outcome = hub_verdict(review.get("decision") or "", review.get("final_verdict") or "")
    if outcome not in allowed or not send_blocker(settings, project) == "":
        return empty
    status = hub_status.API_STATUS[outcome]
    label = hub_status.API_STATUS_LABEL.get(status, status)
    if not status_already(db, project, settings, hub_id, status):
        return {**empty, "status": status, "label": label}
    current = bool(review.get("entered_hub")) and (
        str(review.get("entered_text_hash") or "") == text_hash(text)
        # отметка принятого Pull без отпечатка (hub_pull): текущим считается текст, равный принятому комментарию Hub
        # (ревью dev29, круг 5)
        # (ревью dev29, круг 5); тот же текст – буква в букву, кроме краёв текста (ADR-0149 п. 5): комментарий нового
        # формата, отличающийся от принятого только пробелами и пустыми строками, можно заменить (ревью Codex круга 7)
        or (review.get("entered_origin") == "hub_sync" and not review.get("entered_text_hash")
            and edges(accepted_hub_reason(db, project, settings, hub_id, raw=True)) == edges(text)))
    expires = hub_status._day(review.get("desired_hub_expired_at")) or ""
    if not current and not expires:  # прежний срок – из последней выполненной записи этого статуса
        done = db.hub_last_op(int(project["id"]), hub_id, "status", hub_url=settings.hub_url,
                              app_id=project.get("hub_app_id"), state="done")
        if done is not None and hub_status.sent_status(done) == status:
            expires = hub_status._day(((loads(done.get("request_json"), {}) or {}).get("body") or {}).get("expiredAt"))
    return {"active": not current, "already": True, "current": current, "status": status, "label": label,
            "expires": expires, "note": REPLACE_NOTE.format(label=label), "check": REPLACE_CHECK.format(label=label)}


def replace_answer(request: Request, project_id: int, hub_id: str, review: dict | None, text: str) -> dict:
    """Режим панели для ответа сохранения решения (AJAX): скрипт переключает кнопку и подтверждение без
    перезагрузки карточки."""
    db = db_of(request)
    settings = settings_of(request)
    project = project_or_404(request, project_id)
    view = replace_view(db, project, settings, str(hub_id), review or {}, text)
    answer = {"active": view["active"], "note": view["note"], "check": view["check"], "expires": view["expires"]}
    # строка последней операции зависит от решения: отказ «already has…» после смены решения или текста называется
    # заново (ревью dev29, круг 8); операции в работе опрашиваются и здесь не трогаются
    last = db.hub_last_op(int(project["id"]), str(hub_id), "status", hub_url=settings.hub_url,
                          app_id=project.get("hub_app_id"))
    if last is not None and hub_status.already_refused(last):
        refusal_stale = bool(str(hub_id) in hub_status.refused_issue_ids(last)
                             and not db.on_connection(lambda c: refusal_current_in(
                                 c, int(project["id"]), str(hub_id), last, settings.hub_url, project.get("hub_app_id"))))
        shown = op_view(last, hub_id=str(hub_id), refusal_stale=refusal_stale, replace_active=view["active"],
                        text_current=bool(view.get("current")))
        answer.update(status_text=shown["text"], status_tone=shown["tone"])
    return answer


# ============================================================================ цели


def _finding_of(db: Database, project_id: int, hub_id: str) -> Finding | None:
    source = db.case_input(project_id, hub_id)
    if source is None or source.get("missing"):
        return None
    return Finding.from_dict(source["data"])


def sast_targets(request: Request, db: Database, project_id: int, f: Finding, review: dict,
                 sig: str, status: str, app_id: int | None = None) -> tuple[list[dict], str, list[str], list[str]]:
    """Цели статуса SAST: эта находка и находки её группы «та же строка, категория и код» с тем же сохранённым решением
    «Ложное срабатывание» и тем же обоснованием (у остальных своё решение – они не уходят). Текст – короткий
    комментарий карточки. Третье значение – соседи, пропущенные потому, что статус status у них уже стоит в Hub
    (status_in_hub): Hub не ставит находке тот статус, который у неё уже есть, и отклоняет такой запрос целиком
    (ADR-0116); четвёртое – соседи, входящие в дефект (dev32): их статус в Hub идёт через дефект, в группу они не
    входят; состав группы ещё раз сверяется в транзакции постановки (_revisions_check)."""
    from app.routes import findings as card
    settings = settings_of(request)
    text = card.saved_hub_text(f, review, settings.hub_status_map)
    targets = [_target(f, review, text, card.entered_parts(settings, review), sig)]
    already: list[str] = []
    in_defect: list[str] = []
    mine_cmp = card.own_code_cmp(db, project_id, f.hub_id)
    for row in card.same_code(db.group_rows(project_id, card.group_key(f), f.hub_id), mine_cmp):
        if row.get("missing"):
            continue
        # итог, текст и редакция соседа – из одного чтения его решения; редакции всех целей ещё раз сверяются в
        # транзакции постановки (_enqueue)
        sibling_review = db.get_review(project_id, row["hub_id"])
        if not sibling_review or hub_verdict(sibling_review.get("decision") or "",
                                             sibling_review.get("final_verdict") or "") != "false_positive":
            continue
        if not sibling_review.get("reviewed"):  # выгрузка сняла «Проверено»: сосед уходит своей карточкой после проверки
            continue
        if db.hub_defect_bound(project_id, row["hub_id"]) is not None:  # сосед в дефекте – статус через дефект (dev32)
            in_defect.append(str(row["hub_id"]))
            continue
        if (hub_ops.normalize_text(sibling_review.get("final_comment"))
                != hub_ops.normalize_text(review["final_comment"])):
            continue
        neighbor = _finding_of(db, project_id, row["hub_id"])
        if neighbor is not None and is_fixed(db.on_connection(lambda c, n=neighbor: status_now_in(
                c, project_id, n.hub_id, n.kind, n.status, settings.hub_url, app_id))):  # Hub отклонил бы всю группу (dev7)
            continue
        if db.status_in_hub(project_id, row["hub_id"], status, status_already_in, settings.hub_url,
                            app_id):  # Hub отклонил бы всю группу (и по его отказу, назвавшему соседа, – dev29)
            already.append(str(row["hub_id"]))
            continue
        sibling_sig = db.finding_sig(project_id, row["hub_id"])  # до чтения данных: проверка в транзакции поймёт обновление
        other = _finding_of(db, project_id, row["hub_id"])
        if other is None:
            continue
        sibling_text = card.saved_hub_text(other, sibling_review, settings.hub_status_map)
        # группа уходит одним reason, а отметка соседа считается по его тексту: соседом идёт только точно тот же
        # текст – с 0.10.0.dev21 пробелы и пустые строки оператора часть текста (ADR-0149, ревью Codex)
        if sibling_text != text:
            continue
        targets.append(_target(other, sibling_review, sibling_text, card.entered_parts(settings, sibling_review),
                               sibling_sig))
    return targets, text, already, in_defect


# Статус доказан последней принятой версией находки в назначении (hub_entity_versions; ADR-0116, уточнение 01.11 по
# HUB-AUD-09): принятие «Pull из Hub» – состоянием Hub из hub_issue_states, подтверждённая запись приложения – статусом
# её операции; что принято позже, то и действует. Нет версии (операции до схемы 31) – любая выполненная операция с
# тем же статусом в том же назначении (IN_HUB_SQL). Ручная/унаследованная отметка без области не подтверждает статус.
# Проверяется и в транзакции постановки.
IN_HUB_SQL = ("SELECT EXISTS ("
              " SELECT 1 FROM hub_ops WHERE project_id = ? AND purpose = 'status' AND state = 'done'"
              " AND hub_url = ? AND app_id IS NOT DISTINCT FROM ? AND (request_json::json -> 'body' ->> 'status') = ? AND EXISTS ("
              "  SELECT 1 FROM json_array_elements(hub_ops.targets_json::json) AS t(value) WHERE (t.value ->> 'hub_id') = ?)) AS sent")
VERSION_SQL = ("SELECT accepted_source_json FROM hub_entity_versions WHERE project_id = ? AND hub_url = ?"
               " AND app_id = ? AND entity_kind = 'issue' AND entity_key = ?")
STATE_SQL = ("SELECT confirmed_json, confirmed_presence FROM hub_issue_states WHERE project_id = ? AND hub_url = ?"
             " AND app_id = ? AND issue_type = ? AND issue_id = ?")
STATUS_RUN_SQL = "SELECT closed_at FROM hub_defect_sync_runs WHERE id = ?"
RESEARCH_CONFLICT = ("Совет агента «не применимо» расходится с исследованием, принятым после решения ({conflict}). Проверьте находку: "
                     "подтвердите совет или измените решение и сохраните, затем отправляйте.")
FIXED_REFUSAL = ("Статус находки в Hub – «Fixed»: находка исправлена, Hub отклоняет смену её статуса (ответ «issue was fixed»). "
                 "Отправлять нечего.")
CONFIRMED_OP_SQL = ("SELECT state, request_json FROM hub_ops WHERE id = ? AND project_id = ? AND purpose = 'status'"
                    " AND hub_url = ? AND app_id IS NOT DISTINCT FROM ?")


def status_in_hub(c, project_id: int, hub_id: str, status: str, hub_url: str, app_id: int | None) -> bool:
    """Статус status уже стоит в Hub у находки – по последней принятой версии находки в назначении (см. выше);
    c – соединение базы (или транзакция постановки), hub_url – адрес Hub из настроек (сравнивается его основа, как в
    операциях), app_id – номер приложения Hub проекта."""
    base, app = hub_ops.hub_base(hub_url), (int(app_id) if app_id else None)
    kind = c.execute("SELECT kind FROM findings WHERE project_id = ? AND hub_id = ?",
                     (project_id, str(hub_id))).fetchone()
    typ = hub_status.HUB_ISSUE_TYPE.get(str(kind[0])) if kind else None
    try:  # ключ версии и состояния – номер Hub целым числом, как у Pull и подтверждения операции (ревью dev16, A2)
        ident = str(hub_status.issue_id(hub_id))
    except hub_status.StatusRefused:
        ident = ""
    version = (c.execute(VERSION_SQL, (project_id, base, app, f"{typ}:{ident}")).fetchone()
               if typ and ident and app is not None else None)
    if version is None:
        row = c.execute(IN_HUB_SQL, (project_id, base, app, status, str(hub_id))).fetchone()
        return bool(row and row[0])
    source = loads(version[0], {})
    if source.get("origin") == "status_confirmation":
        op = c.execute(CONFIRMED_OP_SQL, (source.get("op_id"), project_id, base, app)).fetchone()
        return bool(op and op[0] == "done" and (loads(op[1], {}).get("body") or {}).get("status") == status)
    state = c.execute(STATE_SQL, (project_id, base, app, typ, ident)).fetchone()
    if state is None or state[1] != "present":
        return False
    return hub_sync_compare.issue_values(loads(state[0], {}) or {}, f"{typ}:{ident}").get("status") == status


def status_now_in(c, project_id: int, hub_id: str, kind: str, exported: str, hub_url: str, app_id: int | None) -> dict:
    """Действующий статус находки в Hub (план dev7, раздел 4): {status, source, at}. Источник – что доказывает его по последней
    принятой версии, как у status_in_hub: подтверждённая запись приложения, принятая сверка; ни того ни другого – выгрузка.
    Статус считается только по текущему назначению Hub."""
    loaded = c.execute("SELECT i.created_at FROM findings f JOIN imports i ON i.id = f.import_id WHERE f.project_id = ? AND f.hub_id = ?",
                       (project_id, str(hub_id))).fetchone()
    fallback = {"status": str(exported or ""), "source": "из выгрузки", "at": str(loaded[0] or "") if loaded else ""}
    base, app = hub_ops.hub_base(hub_url), (int(app_id) if app_id else None)
    typ = hub_status.HUB_ISSUE_TYPE.get(str(kind))
    try:
        ident = str(hub_status.issue_id(hub_id))
    except hub_status.StatusRefused:
        return fallback
    if not typ or app is None:
        return fallback

    def written(op_id) -> dict | None:
        op = c.execute("SELECT state, request_json, closed_at FROM hub_ops WHERE id = ? AND project_id = ? AND purpose = 'status'"
                       " AND hub_url = ? AND app_id IS NOT DISTINCT FROM ?", (op_id, project_id, base, app)).fetchone()
        status = (loads(op[1], {}).get("body") or {}).get("status") if op and op[0] == "done" else ""
        return {"status": str(status), "source": "подтверждённая запись", "at": str(op[2] or "")} if status else None

    version = c.execute(VERSION_SQL, (project_id, base, app, f"{typ}:{ident}")).fetchone()
    source = loads(version[0], {}) if version else {}
    if source.get("origin") == "status_confirmation":
        return written(source.get("op_id")) or fallback
    if version is None:  # выполненная запись без строки версии: её признаёт и status_in_hub
        op = c.execute("SELECT id FROM hub_ops WHERE project_id = ? AND purpose = 'status' AND state = 'done' AND hub_url = ?"
                       " AND app_id IS NOT DISTINCT FROM ? AND EXISTS (SELECT 1 FROM json_array_elements(hub_ops.targets_json::json) AS t(value)"
                       " WHERE (t.value ->> 'hub_id') = ?) ORDER BY id DESC LIMIT 1", (project_id, base, app, str(hub_id))).fetchone()
        found = written(op[0]) if op else None
        if found:
            return found
    state = c.execute("SELECT confirmed_json, confirmed_presence, confirmed_run_id FROM hub_issue_states WHERE project_id = ?"
                      " AND hub_url = ? AND app_id = ? AND issue_type = ? AND issue_id = ?", (project_id, base, app, typ, ident)).fetchone()
    status = (loads(state[0], {}).get("detail") or {}).get("status") if state and state[1] == "present" else ""
    if status:
        run = c.execute(STATUS_RUN_SQL, (state[2],)).fetchone() if state[2] else None
        return {"status": str(status), "source": "принятая сверка", "at": str(run[0] or "") if run else ""}
    return fallback


def status_now(db: Database, project: dict, settings, f: Finding) -> dict:
    return db.on_connection(lambda c: status_now_in(c, int(project["id"]), f.hub_id, f.kind, f.status, settings.hub_url,
                                                    project.get("hub_app_id")))


def entered_scope_note(review: dict | None, view: dict) -> str:
    """Пометка об отметке «Внесено в Hub» для карточки. Ручная отметка сама статус не подтверждает, но если подтверждённая запись
    или принятая сверка показывают в Hub тот же статус, что в решении, пометка спорила бы с шапкой карточки (проход в браузере
    06.11)."""
    note = str((review or {}).get("entered_scope_note") or "")
    if not note or review.get("entered_origin") in ("status", "defect", "hub_sync") or not review.get("entered_hub"):
        return note
    wanted = hub_status.API_STATUS.get(hub_verdict(review.get("decision") or "", review.get("final_verdict") or ""), "")
    same = bool(wanted) and str(view.get("status") or "").strip().casefold() == wanted.casefold()
    return "" if same and view.get("source") in ("подтверждённая запись", "принятая сверка") else note


def is_fixed(view: dict) -> bool:
    return str(view.get("status") or "").strip().lower() == "fixed"


def fixed_refusal(view: dict) -> str:
    """Причина отказа: статус из выгрузки мог устареть – находку могли вновь открыть, поэтому названо основание и что сделать."""
    if view.get("source") == "из выгрузки":
        return FIXED_REFUSAL + (" Статус взят из выгрузки и мог устареть: если находку вновь открыли, выполните сверку с Hub на вкладке "
                                "«Дефекты» (кнопка «Синхронизировать») – форма отправки вернётся.")
    return FIXED_REFUSAL


def _target(f: Finding, review: dict, text: str, parts: str = "", sig: str = "") -> dict:
    return {"hub_id": f.hub_id, "issue_id": hub_status.issue_id(f.hub_id), "issue_type": hub_status.issue_type(f.kind),
            "revision": int(review.get("revision") or 0), "entered_hash": text_hash(text), "entered_parts": parts,
            "sig": sig}


# ============================================================================ постановка


def _json_error(detail: str, status: int) -> JSONResponse:
    return JSONResponse({"ok": False, "detail": detail}, status_code=status)


def wants_json(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "")


async def _refused(request: Request, as_json: bool, detail: str, status: int):
    """Отказ: со скриптом – JSON для карточки, без скрипта – страница ошибки с тем же текстом; страница читает
    настройки из базы – в пуле потоков, не в цикле событий."""
    if not as_json:
        return await run_in_threadpool(error_response, request, status, detail)
    return _json_error(detail, status)


def _op_card_url(request: Request, project_id: int, op: dict) -> str:
    """Карточка первой находки операции (ответ «Сверить» без скрипта); находки уже нет – страница проекта."""
    targets = loads(op.get("targets_json"), [])
    hub_id = str(targets[0].get("hub_id") or "") if targets and isinstance(targets[0], dict) else ""
    row = db_of(request).get_finding_by_hub_id(project_id, hub_id) if hub_id else None
    if row is None:
        return f"/projects/{project_id}"
    section = "findings" if row["kind"] == "SAST" else "sca/findings"
    return f"/projects/{project_id}/{section}/{int(row['id'])}"


def _card_url(request: Request, suffix: str, ok: str) -> str:
    """Адрес карточки для ответа без скрипта: путь действия без suffix, прежние параметры и ok=…, якорь блока."""
    path = request.url.path[: -len(suffix)] if request.url.path.endswith(suffix) else request.url.path
    query = "&".join(p for p in request.url.query.split("&") if p and not p.startswith("ok="))
    return f"{path}?{query + '&' if query else ''}ok={ok}#hub-send"


def _answer(project_id: int, op: dict, message: str = "", checking: bool = False, pending: bool = False,
            hub_id: str = "") -> dict:
    """Ответ постановки, опроса и сверки: текст состояния, номер операции для «Сверить» и видимость кнопки.
    Находка карточки – первая цель операции (она её и поставила); соседи по группе после перезагрузки видят свой
    текст (op_view с их hub_id)."""
    first = loads(op.get("targets_json"), [])
    anchor = hub_id or (str(first[0].get("hub_id") or "") if first and isinstance(first[0], dict) else "")
    view = op_view(op, checking, pending, hub_id=anchor)
    status_url = f"/projects/{project_id}/hub/ops/{op['id']}" + (f"?hub_id={quote(anchor, safe='')}" if anchor else "")
    return {"ok": True, "op_id": op["id"], "status_url": status_url,
            "done": view["final"], "text": {"hub-send-status": view["text"]},
            # срок – элементом времени: скрипт покажет его в часовом поясе браузера, как интерфейс Hub
            **({"times": {"hub-send-status": {k: view["time"][k] for k in ("prefix", "datetime", "suffix")}}}
               if view["time"] else {}),
            "value": {"hub-verify-op": str(op["id"])},
            "show": ["hub-send-status"] + (["hub-verify-form"] if view["verify"] else []),
            "hide": [] if view["verify"] else ["hub-verify-form"],
            # отказ «already has…»: режим панели («Обновить комментарий в Hub» или обычный) собирает сервер –
            # карточка перезагружается (ревью dev29, круг 4)
            **({"reload": True} if op.get("state") == "failed" and hub_status.already_refused(op) else {}),
            **({"message": message} if message else {})}


def _revisions_check(project_id: int, targets: list[dict], status: str = "", left_out: list[str] | None = None,
                     hub_url: str = "", app_id: int | None = None, check_all: bool = False):
    """Проверка в транзакции постановки: у всех целей та же редакция решения, решение отмечено проверенным, данные
    находки те же (повторная выгрузка не меняла её) и находка есть в выгрузке – как при сборке запроса. Состав
    группы (ADR-0116): у соседей-целей статуса в Hub по-прежнему нет, у пропущенных соседей – по-прежнему есть;
    отметка «Внесено в Hub» меняется без новой редакции, поэтому сверяется отдельно. check_all – у операции нет
    открытой карточки-якоря («Отправить выбранные», ADR-0119): статус в Hub сверяется у всех целей."""
    def check(c) -> None:
        if status:
            moved = ([t["hub_id"] for t in (targets if check_all else targets[1:])
                      if status_already_in(c, project_id, t["hub_id"], status, hub_url, app_id)]
                     + [h for h in (left_out or []) if not status_already_in(c, project_id, h, status, hub_url, app_id)])
            if moved:
                raise StaleTarget("Состав группы изменился, пока собирался запрос (статус в Hub или отметка «Внесено в "
                                  f"Hub» у находки {moved[0]}): обновите карточку и отправьте ещё раз.")
        for target in targets:
            row = c.execute("SELECT revision, reviewed FROM reviews WHERE project_id = ? AND hub_id = ?",
                            (project_id, str(target["hub_id"]))).fetchone()
            data = c.execute("SELECT data_json, missing, kind FROM findings WHERE project_id = ? AND hub_id = ?",
                             (project_id, str(target["hub_id"]))).fetchone()
            if status and data is not None:  # Pull принёс «Fixed», пока собирался запрос: Hub отклонил бы смену статуса (dev7)
                view = status_now_in(c, project_id, str(target["hub_id"]), data["kind"], str(loads(data["data_json"], {}).get("status") or ""), hub_url, app_id)
                if is_fixed(view):
                    raise StaleTarget(fixed_refusal(view))
            fresh = (row is not None and int(row["revision"] or 0) == int(target["revision"]) and row["reviewed"]
                     and data is not None and not data["missing"]
                     and finding_data_sig(data["data_json"]) == target.get("sig"))
            if not fresh:
                raise StaleTarget(STALE_REVISION if len(targets) == 1 else
                                  f"Решение или данные находки {target['hub_id']} из группы изменились, пока "
                                  "собирался запрос: обновите карточку и отправьте ещё раз.")
    return check


def _enqueue_replace(page: Request, db: Database, settings, project: dict, target: dict, status: str, reason: str,
                     expired: str, shown: tuple[str, int]) -> dict:
    """Постановка первого шага замены комментария (dev29): промежуточный статус «Подтверждено» для одной находки с записанным вторым шагом.
    Ключ операции учитывает редакцию решения и новый комментарий: другая правка – другая операция, а возврат к
    прежнему тексту после новой редакции – тоже новая (ревью dev29, круг 2). Проверки в транзакции – как у обычной
    отправки; статус должен по-прежнему стоять в Hub (status_already_in на соединении транзакции)."""
    request = hub_status.replace_request(target, status, reason, expired)
    hub_target = hub_target_check(page, int(project["id"]), settings.hub_url, project["hub_app_id"],
                                  CARD_TARGET_CHANGED, shown)
    revisions = _revisions_check(int(project["id"]), [target], "", None, settings.hub_url, int(project["hub_app_id"]))

    def check(c) -> None:
        hub_target(c)
        revisions(c)
        if not status_already_in(c, int(project["id"]), target["hub_id"], status, settings.hub_url,
                                 int(project["hub_app_id"])):
            raise StaleTarget("Статус в Hub у находки изменился, пока собирался запрос: обновите карточку и отправьте "
                              "ещё раз.")
        # этот текст уже записан выполненной операцией, чьё подтверждение – текущая версия (цепочка выполнена,
        # отметка может ещё не стоять): заменять нечего (ревью dev29, круг 13)
        if text_delivered_in(c, int(project["id"]), str(target["hub_id"]), status, reason,
                             int(target.get("revision") or 0), settings.hub_url, int(project["hub_app_id"])):
            raise StaleTarget(REPLACE_DONE)
        hub_defects.refuse_in_defect(c, int(project["id"]), [target["hub_id"]], own=str(target["hub_id"]))

    return db.hub_enqueue(purpose="status", request=request, hub_url=settings.hub_url, app_id=int(project["hub_app_id"]),
                          project_id=int(project["id"]), targets=[target], text=hub_status.RESET_REASON, check=check,
                          # новая подтверждённая замена после отказа второго шага (статус вернули в Hub извне) – при
                          # тех же тексте и редакции другая принятая версия цели, другая операция (ревью, круг 9)
                          key_extra=f"replace:{int(target.get('revision') or 0)}:{text_hash(reason)}:"
                                    + versions_key(db, int(project["id"]), settings.hub_url,
                                                   int(project["hub_app_id"]), [target]))


def in_defect_check(project_id: int, in_defect: list[str] | None) -> Callable:
    """Проверка в транзакции постановки (dev32, ревью круг 1): соседи, исключённые из группы как входящие в дефект,
    всё ещё в дефекте; сосед освободился (другая вкладка применила Pull) – StaleTarget: состав собирается заново."""
    def check(c) -> None:
        for hub_id in in_defect or []:
            if Database.hub_defect_bound_in(c, int(project_id), str(hub_id)) is None:
                raise StaleTarget(f"Находка {hub_id} вышла из дефекта, пока собирался запрос: обновите карточку и "
                                  "отправьте ещё раз.")
    return check


def _enqueue(page: Request, db: Database, settings, project: dict, targets: list[dict], status: str, reason: str,
             expired: str, left_out: list[str] | None = None, shown: tuple[str, int] = ("", 0),
             in_defect: list[str] | None = None) -> dict:
    request = hub_status.status_request(targets, status, reason, expired)
    # цель – показанная карточкой (поля формы, shown) и та же, по которой собраны состав и запрос (KIMI-12)
    hub_target = hub_target_check(page, int(project["id"]), settings.hub_url, project["hub_app_id"],
                                  CARD_TARGET_CHANGED, shown)
    # статус сверяется у всех целей, включая открытую находку (ревью dev29, круг 3): вторая вкладка, чья проверка до
    # постановки прошла раньше выполнения первой, в транзакции видит подтверждённую версию и отклоняется
    revisions = _revisions_check(int(project["id"]), targets, status, left_out, settings.hub_url,
                                 int(project["hub_app_id"]), check_all=True)

    still_bound = in_defect_check(int(project["id"]), in_defect)

    def check(c) -> None:
        hub_target(c)
        revisions(c)
        # находка или сосед вошли в дефект, пока собирался запрос: статус через дефект (dev32; раньше – подтверждение)
        hub_defects.refuse_in_defect(c, int(project["id"]), [t["hub_id"] for t in targets],
                                     own=str(targets[0]["hub_id"]) if targets else "")
        still_bound(c)  # исключённые соседи всё ещё в дефекте

    return db.hub_enqueue(purpose="status", request=request, hub_url=settings.hub_url, app_id=int(project["hub_app_id"]),
                          project_id=int(project["id"]), targets=targets, text=reason, check=check,
                          key_extra=versions_key(db, int(project["id"]), settings.hub_url, int(project["hub_app_id"]),
                                                 targets))


def versions_key(db: Database, project_id: int, hub_url: str, app_id: int, targets: list[dict]) -> str:
    """Часть ключа обычной отправки – принятые версии целей (hub_entity_versions.current): тот же запрос после смены
    принятой версии (например, после первого шага замены, снявшего статус, когда второй не поставлен) – новая
    операция, а не «уже выполнена» (ревью dev29, круг 2). Повтор без смены версии по-прежнему отклоняется."""
    from app.hub_entity_versions import current
    base = hub_ops.hub_base(hub_url)

    def read(c) -> str:
        parts = []
        for t in targets:
            key = f"{t.get('issue_type')}:{t.get('issue_id')}"
            parts.append(f"{key}={current(c, project_id, base, app_id, 'issue', key)['accepted_epoch']}")
        return ",".join(parts)
    return "v:" + str(db.on_connection(read))


async def _send(request: Request, project_id: int, finding_id: int, kind: str):
    form = await request.form(max_fields=12, max_files=0)
    shown = str(form.get("review_revision") or "")
    shown_sig = str(form.get("finding_sig") or "")
    shown_text = str(form.get("text_hash") or "")
    target_shown = shown_target(form)  # адрес Hub и приложение, которые показала карточка (KIMI-12)
    replace = str(form.get("replace") or "") == "1"  # «Обновить комментарий в Hub» (dev29)
    replace_confirmed = str(form.get("replace_confirm") or "") == "1"

    def apply():
        project = project_or_404(request, project_id)
        settings = settings_of(request)
        db = db_of(request)
        blocker = send_blocker(settings, project) or hub_sync.resync_blocker(db, project_id)
        if blocker:
            raise hub_status.StatusRefused(blocker)
        row = db.get_finding(project_id, finding_id)
        if row is None or (kind == "SAST") != (row["kind"] == "SAST"):
            raise LookupError("Находка не найдена.")
        bound = db.hub_defect_bound(project_id, row["hub_id"])
        if bound is not None:  # статус находки в дефекте – через дефект (dev32): отказ до проверок формы
            raise hub_status.StatusRefused(hub_defects.in_defect_text(bound))
        # назначение сменили после показа карточки: состав и запрос собрались бы для другого Hub или приложения –
        # отказ до их сборки; в транзакции постановки – ещё раз (hub_target_check)
        if not same_target(settings.hub_url, project.get("hub_app_id"), target_shown):
            raise StaleTarget(CARD_FORM_OUTDATED if not (target_shown[0] and target_shown[1]) else CARD_TARGET_CHANGED)
        sig = db.finding_sig(project_id, row["hub_id"])  # до чтения данных: обновление выгрузки поймает транзакция
        f = _finding_of(db, project_id, row["hub_id"])
        if f is None:
            raise hub_status.StatusRefused("Находки нет в текущей выгрузке: статус в Hub не отправляется.")
        now_view = status_now(db, project, settings, f)
        if is_fixed(now_view):
            raise hub_status.StatusRefused(fixed_refusal(now_view))
        review = db.get_review(project_id, f.hub_id)
        if not review or not review.get("decision"):
            raise hub_status.StatusRefused("Сначала сохраните решение по находке.")
        if not shown.isdigit() or int(shown) != int(review.get("revision") or 0):
            raise hub_status.StatusRefused(STALE_REVISION)
        if not shown_sig or shown_sig != sig:  # карточку открыли до обновления выгрузки: текст собран бы по новым данным
            raise hub_status.StatusRefused(DATA_CHANGED)
        if not review.get("reviewed"):
            raise hub_status.StatusRefused(NOT_REVIEWED)
        outcome = hub_verdict(review["decision"], review["final_verdict"])
        allowed = SAST_STATUS_OUTCOMES if kind == "SAST" else SCA_STATUS_OUTCOMES
        if outcome not in allowed:
            raise hub_status.StatusRefused("Из карточки в Hub уходит статус только для «Ложное срабатывание»"
                                           + ("" if kind == "SAST" else " и «Риск принят»") + ".")
        status = hub_status.api_status(outcome)
        expired = hub_status.expired_at(str(form.get("expires") or ""), today())
        in_defect: list[str] = []  # соседи группы SAST, входящие в дефект (dev32)
        if kind == "SAST":
            from app.routes import findings as card
            origin = card.comment_origin(db, db.get_case(project_id, f.hub_id), review,
                                         review.get("final_comment") or "", project_id=project_id, hub_id=f.hub_id)
            if origin and origin != outcome and not comment_confirm_valid(form, review):
                raise CommentNeedsCheck(comment_check_text(origin, outcome))
            if replace:  # замена комментария – только открытая находка: соседи по группе не собираются (круг 14)
                text = card.saved_hub_text(f, review, settings.hub_status_map)
                targets, already = [_target(f, review, text, card.entered_parts(settings, review), sig)], []
            else:
                targets, text, already, in_defect = sast_targets(request, db, project_id, f, review, sig, status,
                                                                 int(project["hub_app_id"]))
        else:
            already = []
            from app.routes import sca as sca_card
            conflict = sca_card.unconfirmed_conflict(db, project_id, f, review)
            if conflict:
                raise hub_status.StatusRefused(RESEARCH_CONFLICT.format(conflict=conflict))
            origin = sca_card.comment_origin(db, project_id, f, review.get("final_comment") or "")
            if origin and origin != outcome and not comment_confirm_valid(form, review):
                raise CommentNeedsCheck(comment_check_text(origin, outcome))
            text = sca_card.saved_hub_text(db, settings, project_id, f, review)
            targets = [_target(f, review, text, sig=sig)]
        # уходит ровно показанный текст: любая его зависимость (данные, соответствия номеров, ответ агента, подписи
        # статусов) изменилась – отпечаток другой, отправки нет
        if not shown_text:  # черновик или несогласованная карточка: текста для Hub карточка не показала
            raise hub_status.StatusRefused(TEXT_NOT_SHOWN)
        if shown_text != text_hash(text):
            raise hub_status.StatusRefused(TEXT_CHANGED)
        reason = hub_status.clean_reason(text)
        # статус у самой находки уже стоит в Hub (dev29): обычная отправка отклоняется до запроса (Hub ответил бы
        # 400 «already has the requested status»); замена комментария – двумя шагами по подтверждению
        label = hub_status.API_STATUS_LABEL.get(status, status)
        if replace:
            if not status_already(db, project, settings, f.hub_id, status):
                raise hub_status.StatusRefused(REPLACE_NOT_NEEDED.format(label=label))
            # повтор той же формы после выполненной замены (ревью dev29, круги 12–13): текущий текст уже внесён –
            # по отметке или по подтверждённой операции (отметка ещё не доставлена)
            if replace_view(db, project, settings, f.hub_id, review, text).get("current") or db.on_connection(
                    lambda c: text_delivered_in(c, project_id, f.hub_id, status, reason,
                                                int(review.get("revision") or 0), settings.hub_url,
                                                project.get("hub_app_id"))):
                raise hub_status.StatusRefused(REPLACE_DONE)
            if not replace_confirmed:
                raise hub_status.StatusRefused(REPLACE_CONFIRM)
            return project, _enqueue_replace(request, db, settings, project, targets[0], status, reason, expired,
                                             target_shown), [], []
        if status_already(db, project, settings, f.hub_id, status):
            raise hub_status.StatusRefused(ALREADY_IN_HUB.format(label=label))
        return project, _enqueue(request, db, settings, project, targets, status, reason, expired, already,
                                 target_shown, in_defect), already, in_defect

    as_json = wants_json(request)
    row = None
    try:
        project, op, already, in_defect = await run_in_threadpool(apply)
        row = db_of(request).get_finding(project_id, finding_id)
    except HTTPException as e:  # «проект не найден»: тот же ответ без скрипта через пул потоков, не общий обработчик
        return await _refused(request, as_json, str(e.detail), e.status_code)
    except CommentNeedsCheck as e:  # комментарий модели к другому итогу: «Текст проверен» (ADR-0115 п. 3)
        if not as_json:
            return await _refused(request, False, str(e), 409)
        return JSONResponse({"ok": False, "detail": str(e), "reason": "comment"}, status_code=409)
    except hub_defects.DefectBound as e:  # находка вошла в дефект, пока собирался запрос (dev32): статус через дефект
        return await _refused(request, as_json, str(e), 409)
    except hub_status.StatusRefused as e:
        return await _refused(request, as_json, str(e), 400)
    except LookupError as e:
        return await _refused(request, as_json, str(e), 404)
    except ValueError as e:  # очередь: такая операция уже есть или у находки есть незакрытая
        return await _refused(request, as_json, str(e), 409)
    if not as_json:  # без скрипта – обратно в карточку с сообщением (пропущенные соседи – отдельным сообщением)
        ok = ("hub_queued_skipped_defect" if already and in_defect else "hub_queued_skipped" if already else
              "hub_queued_defect" if in_defect else "hub_queued")
        return redirect(_card_url(request, "/hub-status", ok))
    count = len(loads(op.get("targets_json"), []))
    note = ("Поставлено в очередь исполнителю: сначала «Подтверждено», затем прежний статус с новым комментарием."
            if hub_status.is_reset(op) else
            f"Поставлено в очередь исполнителю: находок – {count}." if count > 1 else "Поставлено в очередь исполнителю.")
    if already:
        note += (" Уже внесены в Hub и не отправляются: " if len(already) > 1 else
                 " Уже внесена в Hub и не отправляется: ") + ", ".join(already) + "."
    if in_defect:
        note += (" Входят в дефект и не отправляются (статус через дефект): " if len(in_defect) > 1 else
                 " Входит в дефект и не отправляется (статус через дефект): ") + ", ".join(in_defect) + "."
    return _answer(project_id, op, note, hub_id=str(row["hub_id"]))


@router.post("/projects/{project_id}/findings/{finding_id}/hub-status")
async def send_sast_status(request: Request, project_id: int, finding_id: int):
    """«Отправить в Hub» в карточке SAST: «Ложное срабатывание», комментарий и срок – для находки и её группы."""
    return await _send(request, project_id, finding_id, "SAST")


@router.post("/projects/{project_id}/sca/findings/{finding_id}/hub-status")
async def send_sca_status(request: Request, project_id: int, finding_id: int):
    """«Отправить в Hub» в карточке SCA: «Ложное срабатывание» или «Риск принят», комментарий и срок."""
    return await _send(request, project_id, finding_id, "SCA")


# ============================================================================ состояние и сверка


def _project_op(request: Request, project_id: int, op_id: int) -> dict | None:
    project_or_404(request, project_id)
    db = db_of(request)
    db.hub_expire_leases()
    op = db.hub_op(op_id)
    if op is None or op.get("project_id") != project_id or op["purpose"] != "status":
        return None
    return op


@router.get("/projects/{project_id}/hub/ops/{op_id}")
def status_state(request: Request, project_id: int, op_id: int):
    """Состояние операции статуса для опроса из карточки (раз в 2 с); выполнена – страница перезагружается, чтобы
    показать отметку «Внесено в Hub»."""
    try:
        op = _project_op(request, project_id, op_id)
    except HTTPException as e:  # опрос из скрипта – всегда JSON
        return _json_error(str(e.detail), e.status_code)
    if op is None:
        return _json_error("Операция не найдена.", 404)
    db = db_of(request)
    if hub_effects.chain_pending(op):  # первый шаг записан, а его последствия не доставлены (сбой между записью
        hub_effects.status_done(db, op)  # результата и последствиями): довести при опросе (ревью dev29, круг 9)
        op = db.hub_op(op_id) or op
    pending = hub_effects.effects_pending(db, op)
    answer = _answer(project_id, op, checking=checking_of(db, op), pending=pending,
                     hub_id=str(request.query_params.get("hub_id") or "")[:40])
    if op["state"] == "done" and not pending and not hub_effects.legacy_status_needs_read(op) and answer["done"]:
        answer["reload"] = True  # первый шаг замены без поставленного второго – ещё не окончателен (ревью, круг 5)
    return answer


@router.post("/projects/{project_id}/hub/verify")
async def verify_status(request: Request, project_id: int):
    """«Сверить»: круг чтений статуса из Hub по каждой находке операции «результат неизвестен» – одной транзакцией;
    совпадёт у всех – операция выполнена и отметки поставлены, иначе остаётся неизвестной (hub_effects.verify_read).
    Номер операции – поле op_id формы: кнопка появляется в карточке по ответу опроса, без перезагрузки."""
    form = await request.form(max_fields=5, max_files=0)
    op_id = form_int(form.get("op_id"))

    def apply():
        op = _project_op(request, project_id, op_id) if op_id is not None else None
        if op is None:
            raise LookupError("Операция не найдена.")
        if op["state"] != "unknown" and not hub_effects.legacy_status_needs_read(op):
            raise hub_status.StatusRefused("Сверка нужна только операции с результатом «неизвестен».")
        db = db_of(request)
        if checking_of(db, op):
            return op, 0, True
        round_no = hub_effects.next_round(db, op["id"])
        items = [dict(purpose="read", request=read, hub_url=op["hub_url"], app_id=op.get("app_id"),
                      project_id=project_id, targets=targets)
                 for read, targets in hub_effects.verify_requests(op, round_no)]

        def still_unknown(c) -> None:  # пока ставили круг, операцию могла закрыть сверка прежнего круга
            hub_target_check(request, project_id, op["hub_url"], op["app_id"])(c)
            row = c.execute("SELECT * FROM hub_ops WHERE id = ?", (op["id"],)).fetchone()
            if row is None or (row["state"] != "unknown" and not hub_effects.legacy_status_needs_read(dict(row))):
                raise hub_status.StatusRefused("Операция уже сверена: обновите карточку.")

        try:
            db.hub_enqueue_many(items, check=still_unknown)
        except hub_status.StatusRefused:
            raise
        except ValueError:  # чтение по одной из находок уже в очереди (вторая вкладка): круг не ставится целиком
            return op, 0, checking_of(db, op)
        return op, len(items), checking_of(db, op)

    as_json = wants_json(request)
    try:
        op, queued, checking = await run_in_threadpool(apply)
    except HTTPException as e:
        return await _refused(request, as_json, str(e.detail), e.status_code)
    except hub_status.StatusRefused as e:
        return await _refused(request, as_json, str(e), 400)
    except LookupError as e:
        return await _refused(request, as_json, str(e), 404)
    if not as_json:
        return redirect(await run_in_threadpool(_op_card_url, request, project_id, op) + "?ok=hub_verify_queued#hub-send")
    message = (f"Сверка поставлена в очередь: чтений – {queued}." if queued else
               "Сверка уже идёт: дождитесь ответа исполнителя.")
    return _answer(project_id, op, message, checking=checking, hub_id=str(form.get("hub_id") or "")[:40])

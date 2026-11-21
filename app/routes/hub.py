"""Запись в AppSec.Hub через исполнителя (ADR-0114): адреса исполнителя и раздела «AppSec.Hub» в настройках.

Исполнитель (`deploy/hub-worker/hub_worker.py`) работает там, где виден Hub, и обращается к приложению сам:

  POST /api/hub/worker/hello             – на связи: кто вошёл в Hub, адрес Hub, версия исполнителя
  GET  /api/hub/jobs?worker_id&hub_url&wait – долгий опрос очереди (не дольше 25 с): задание с арендой или null
  POST /api/hub/jobs/{attempt_id}/result – ответ Hub как есть; принимается только с токеном аренды

Каждый запрос исполнителя несёт ключ (заголовок X-Hub-Worker-Key, файл hub-worker.key в папке данных); POST
проходит обычную защиту источника (GuardMiddleware): исполнитель шлёт заголовок Origin с адресом приложения.
Адреса страницы настроек: «Проверить связь» (операция probe – GET /auth/user) и её состояние, «Выпустить ключ
заново». Сейчас приложение к Hub само не обращается: прямой режим (основной,
ADR-0129) ещё не сделан.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from typing import Any

from app.hub_sync_contract import SYNC_PROTOCOL

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app import hub_effects, hub_ops, hub_sync
from app.db import HubResyncRequired, HubUnknownWrites, loads, now_iso
from app.storage.postgresql import CommitUnknown
from app.routes.common import db_of, redirect, register_messages, settings_of

router = APIRouter()

WORKER_ONLINE_S = 60  # исполнитель «на связи», если обращался не позже: опрос – раз в 25 с
WORKERS_KEPT = 20  # сколько исполнителей помнить (по последнему обращению)
HELLO_MAX = 16 * 1024  # байт тела приветствия
RESULT_BODY_MAX = hub_ops.RESULT_MAX + 64 * 1024  # байт тела результата: ответ Hub до предела и служебные поля
PAUSE_S = 1.0  # пауза между попытками захвата в долгом опросе
POLLS_MAX = 8  # одновременных долгих опросов (каждый ждёт без потока, но держит соединение)

# подменяются в тестах: долгий опрос без настоящего ожидания
_monotonic = time.monotonic
_pause = asyncio.sleep

register_messages({
    "hub_write_paused": "Запись в Hub на паузе: исполнитель получает только чтение.",
    "hub_write_resumed": "Пауза записи в Hub снята.",
    "hub_write_unknown": "Пауза не снята: есть операции записи с неизвестным исходом. Сверьте их с Hub: «Pull из Hub» и «Синхронизировать». Если сверка показала расхождение и решение принято, отметьте это рядом с кнопкой.",
    "hub_write_resync": "Пауза не снята: база восстановлена из копии, а «Синхронизировать» и «Принять состояние Hub» прошли не по всем проектам с приложением Hub. Если это невозможно и решение принято, отметьте рядом с кнопкой.",
    "hub_key_rotated": "Выпущен новый ключ исполнителя. Прежний больше не действует: впишите новый в настройки "
                       "исполнителя и перезапустите его.",
    "hub_no_url": "Сначала укажите адрес Hub и сохраните настройки.",
}, errors=("hub_no_url",))

DENIED = "Нет ключа исполнителя или ключ неверный: скопируйте его в «Настройках», раздел «AppSec.Hub»."


# ============================================================================ ключ и исполнители


log = logging.getLogger(__name__)
_KEY_ROTATION = threading.Lock()


def worker_key(request: Request) -> str:
    """Действующий ключ исполнителя: из памяти приложения, читается из базы при запуске и обновляется при замене (ADR-0133). Обращения
    исполнителя не ждут соединения с базой."""
    key = getattr(request.app.state, "hub_worker_key", "")
    if not key:
        raise ValueError(getattr(request.app.state, "hub_worker_key_error", "") or "Ключ исполнителя не загружен: перезапустите приложение.")
    return key


def denied(request: Request) -> JSONResponse | None:
    """403, если ключа в заголовке нет или он не совпадает с действующим."""
    try:
        expected = worker_key(request)
    except (OSError, ValueError) as e:
        return JSONResponse({"ok": False, "detail": str(e)}, status_code=503)
    if not hub_ops.key_matches(request.headers.get(hub_ops.WORKER_KEY_HEADER, ""), expected):
        return JSONResponse({"ok": False, "detail": DENIED}, status_code=403)
    return None


def workers(request: Request) -> dict[str, dict]:
    store = getattr(request.app.state, "hub_workers", None)
    if store is None:
        store = request.app.state.hub_workers = {}
    return store


def clean_text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def touch_worker(request: Request, worker_id: str, **fields: Any) -> None:
    """Последнее обращение исполнителя; прежние сведения (кто вошёл) сохраняются."""
    store = workers(request)
    record = store.get(worker_id, {"worker_id": worker_id, "hub_user": "", "hub_login": "", "roles": [],
                                   "hub_url": "", "version": ""})
    record.update(fields)
    record["seen_at"] = now_iso()
    record["seen_mono"] = _monotonic()
    store[worker_id] = record
    if len(store) > WORKERS_KEPT:
        for old in sorted(store.values(), key=lambda r: r["seen_mono"])[:len(store) - WORKERS_KEPT]:
            store.pop(old["worker_id"], None)


def worker_summary(request: Request) -> dict:
    """Самый свежий исполнитель для страницы: {online, worker_id, hub_user, hub_login, roles, hub_url, ago_s}."""
    store = workers(request)
    if not store:
        return {"online": False, "seen": False}
    last = max(store.values(), key=lambda r: r["seen_mono"])
    ago = max(0, int(_monotonic() - last["seen_mono"]))
    return {"online": ago <= WORKER_ONLINE_S, "seen": True, "ago_s": ago,
            **{k: last.get(k) for k in ("worker_id", "hub_user", "hub_login", "roles", "hub_url", "version",
                                        "seen_at", "sync_protocol")}}


def worker_id_of(value: Any) -> str:
    text = clean_text(value, 80)
    return text if text and all(ch.isalnum() or ch in "-_.:" for ch in text) else ""


async def read_json(request: Request, limit: int) -> tuple[dict | None, JSONResponse | None]:
    """Тело JSON не длиннее limit байт -> (объект, None) или (None, ответ с ошибкой)."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        return None, JSONResponse({"ok": False, "detail": f"Тело запроса длиннее {limit} байт."}, status_code=413)
    raw = await request.body()
    if len(raw) > limit:
        return None, JSONResponse({"ok": False, "detail": f"Тело запроса длиннее {limit} байт."}, status_code=413)
    try:
        data = json.loads(raw.decode("utf-8")) if raw else {}
    except (ValueError, UnicodeDecodeError):
        return None, JSONResponse({"ok": False, "detail": "Тело запроса – не JSON."}, status_code=400)
    if not isinstance(data, dict):
        return None, JSONResponse({"ok": False, "detail": "Тело запроса – не объект JSON."}, status_code=400)
    return data, None


# ============================================================================ адреса исполнителя


@router.post("/api/hub/worker/hello")
async def worker_hello(request: Request):
    """Исполнитель на связи: вошёл в Hub как … (GET /auth/user исполнитель делает сам при запуске)."""
    refused = denied(request)
    if refused is not None:
        return refused
    data, error = await read_json(request, HELLO_MAX)
    if data is None:
        return error
    worker_id = worker_id_of(data.get("worker_id"))
    if not worker_id:
        return JSONResponse({"ok": False, "detail": "worker_id: латиница, цифры и - _ . :, до 80 знаков."},
                            status_code=400)
    roles = data.get("roles") if isinstance(data.get("roles"), list) else []
    touch_worker(request, worker_id, hub_url=hub_ops.hub_base(clean_text(data.get("hub_url"), 300)),
                 hub_user=clean_text(data.get("hub_user"), 200), hub_login=clean_text(data.get("hub_login"), 200),
                 roles=[clean_text(r, 60) for r in roles[:20]], version=clean_text(data.get("version"), 40))
    hub_url = await run_in_threadpool(lambda: settings_of(request).hub_url)  # чтение настроек – база, не цикл событий
    return {"ok": True, "server_time": now_iso(), "hub_url": hub_url}


@router.get("/api/hub/jobs")
async def worker_jobs(request: Request, worker_id: str = "", hub_url: str = "", wait: str = "0", sync_protocol: str = "0"):
    """Долгий опрос очереди: первая операция для Hub исполнителя с арендой или {"job": null} по истечении wait."""
    refused = denied(request)
    if refused is not None:
        return refused
    wid = worker_id_of(worker_id)
    base = hub_ops.hub_base(hub_url)
    if not wid or not base.startswith("https://"):
        return JSONResponse({"ok": False, "detail": "Нужны worker_id и hub_url (https://…)."}, status_code=400)
    try:
        seconds = max(0, min(int(wait), hub_ops.WAIT_MAX_S))
    except ValueError:
        seconds = 0
    state = request.app.state
    if getattr(state, "hub_polls", 0) >= POLLS_MAX:
        return JSONResponse({"ok": False, "detail": "Слишком много одновременных опросов: повторите позже."},
                            status_code=429)
    touch_worker(request, wid, hub_url=base, sync_protocol=SYNC_PROTOCOL if sync_protocol == str(SYNC_PROTOCOL) else 0)
    db = db_of(request)

    def claim():
        if request.app.state.settings.maintenance:  # обслуживание: исполнитель не получает ничего (ADR-0128, п. 6.6)
            return None
        db.hub_expire_leases()
        return db.hub_claim(wid, base, hub_ops.LEASE_S, sync_protocol=SYNC_PROTOCOL if sync_protocol == str(SYNC_PROTOCOL) else 0)

    # Ожидание – без потока (asyncio), к базе – короткими шагами в пуле потоков. Перед каждым захватом: клиент ещё
    # ждёт (оборванный опрос задание не забирает) и ключ всё тот же (выпущенный заново ключ отзывает и идущий опрос)
    state.hub_polls = getattr(state, "hub_polls", 0) + 1
    try:
        deadline = _monotonic() + seconds
        while True:
            if await request.is_disconnected():
                return JSONResponse({"ok": False, "detail": "клиент отключился"}, status_code=499)
            refused = denied(request)
            if refused is not None:
                return refused
            got = await run_in_threadpool(claim)
            left = deadline - _monotonic()
            if got is not None or left <= 0:
                break
            await _pause(min(PAUSE_S, left))
    finally:
        state.hub_polls -= 1
    if got is None:
        return {"ok": True, "job": None}
    op, attempt = got["op"], got["attempt"]
    req = loads(op["request_json"], {})
    return {"ok": True, "job": {"op_id": op["id"], "attempt_id": attempt["id"], "purpose": op["purpose"],
                                "lease_token": attempt["lease_token"], "lease_until": attempt["taken_until"],
                                "hub_url": op["hub_url"], "method": req.get("method"), "path": req.get("path"),
                                "body": req.get("body"), "app_id": op["app_id"],
                                **({"sync_protocol": req["sync_protocol"]} if "sync_protocol" in req else {}),
                                **({"contract_version": req["contract_version"]} if "contract_version" in req else {})}}


@router.post("/api/hub/jobs/{attempt_id}/result")
async def worker_result(request: Request, attempt_id: int):
    """Ответ Hub на задание. Принимается только с токеном аренды; повтор – идемпотентно; поздний – записывается,
    но запись в Hub считается неизвестной (ADR-0114 п. 5)."""
    refused = denied(request)
    if refused is not None:
        return refused
    data, error = await read_json(request, RESULT_BODY_MAX)
    if data is None:
        return error
    if request.app.state.settings.maintenance:  # результат доставится позже: до записи и последствий (ADR-0128, п. 6.6)
        return JSONResponse({"ok": False, "detail": "Приложение в режиме обслуживания: результат не принят, повторите позже."},
                            status_code=503, headers={"Retry-After": "30"})
    db = db_of(request)
    # кто в Hub у этого исполнителя (из приветствия) – записывается в дефект, созданный его операцией (ADR-0120)
    login = str((workers(request).get(worker_id_of(data.get("worker_id"))) or {}).get("hub_login") or "")

    def deliver():
        from app.routes.hub_defect_routes import update_preparer  # на месте, как ссылки маршрутов дефектов сюда
        out = db.hub_result(attempt_id, str(data.get("lease_token") or ""), data)
        if out["outcome"] in ("accepted", "late", "duplicate"):
            # отметки «Внесено в Hub», сверка (ADR-0115), цепочка дефекта (ADR-0120); при повторной доставке – снова:
            # последствия идемпотентны, и сбой после записи результата (ответ 500 – исполнитель доставит ещё раз)
            # доводится до конца. «Push в Hub» (ADR-0125) – с подготовкой по текущим решениям этого запроса
            hub_effects.after_result(db, out["op"], login, prepare=update_preparer(request))
        return out

    out = await run_in_threadpool(deliver)
    if out["outcome"] == "rejected":
        return JSONResponse({"ok": False, "outcome": "rejected",
                             "detail": "Аренда не найдена или токен неверный: результат не принят."}, status_code=409)
    worker = worker_id_of(data.get("worker_id"))
    if worker:
        touch_worker(request, worker)
    return {"ok": True, "outcome": out["outcome"], "state": out["op"]["state"]}


# ============================================================================ страница настроек


def hub_context(request: Request) -> dict:
    """Раздел «AppSec.Hub» страницы настроек: ключ, исполнитель, состояние проверки связи (?probe=N)."""
    if request.app.state.settings.hub_disabled:  # учебный стенд npm (ADR-0155): вместо раздела – объяснение
        from app.db import HUB_DISABLED_TEXT
        return {"disabled": True, "disabled_text": HUB_DISABLED_TEXT}
    try:
        key, key_error = worker_key(request), ""
    except (OSError, ValueError) as e:
        key, key_error = "", str(e)
    probe = None
    raw = request.query_params.get("probe", "")
    if raw.isdigit():
        if not request.app.state.settings.maintenance:
            db_of(request).hub_expire_leases()
        op = db_of(request).hub_op(int(raw))
        if op is not None and op["purpose"] == "probe":
            probe = {"op_id": op["id"], **hub_ops.probe_view(op)}
    return {"key": key, "key_error": key_error, "worker": worker_summary(request), "probe": probe,
            "key_header": hub_ops.WORKER_KEY_HEADER, "write_paused": db_of(request).hub_write_paused(),
            "unknown_writes": db_of(request).hub_unknown_writes(),
            "resync_projects": len(db_of(request).on_connection(hub_sync.resync_pending_in))}


def wants_json(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "")


def open_probe(db) -> dict | None:
    rows = db.hub_ops_list(states=("queued", "taken"), limit=50)
    return next((r for r in rows if r["purpose"] == "probe"), None)


def probe_answer(op: dict, message: str = "") -> dict:
    view = hub_ops.probe_view(op)
    return {"ok": True, "op_id": op["id"], "status_url": f"/settings/hub/probe/{op['id']}", "final": view["final"],
            "done": view["final"],  # опрос страницы (data-poll) останавливается по done
            "probe_ok": view["ok"], "text": {"hub-probe-status": view["text"]}, "show": ["hub-probe-status"],
            **({"message": message} if message else {})}


@router.post("/settings/hub/probe")
async def hub_probe(request: Request):
    """«Проверить связь»: операция probe (GET /auth/user) в очередь исполнителю."""
    db = db_of(request)
    if request.app.state.settings.hub_disabled:  # стенд npm: ни прежней проверки, ни новой – исполнителя нет
        from app.db import HUB_DISABLED_TEXT
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": HUB_DISABLED_TEXT}, status_code=409)
        return redirect("/settings#hub")

    def enqueue():
        settings = settings_of(request)  # настройки – из базы: в пуле потоков, не в цикле событий
        if not settings.hub_url:
            return None, ""
        db.hub_expire_leases()
        current = open_probe(db)
        if current is not None and current["hub_url"] == hub_ops.hub_base(settings.hub_url):
            return current, "Проверка связи уже идёт – показываю её состояние."
        return db.hub_enqueue(purpose="probe", request=hub_ops.probe_request(), hub_url=settings.hub_url,
                              app_id=None), ""

    try:
        op, note = await run_in_threadpool(enqueue)
    except ValueError as e:
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e)}, status_code=409)
        return redirect("/settings#hub")
    if op is None:
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": "Сначала укажите адрес Hub и сохраните настройки."},
                                status_code=400)
        return redirect("/settings?ok=hub_no_url#hub")
    if wants_json(request):
        return probe_answer(op, note)
    return redirect(f"/settings?probe={op['id']}#hub")


@router.get("/settings/hub/probe/{op_id}")
def hub_probe_state(request: Request, op_id: int):
    """Состояние проверки связи для опроса со страницы (раз в 2 с)."""
    if request.app.state.settings.hub_disabled:  # стенд npm: аренды не трогаются, проверок нет
        from app.db import HUB_DISABLED_TEXT
        return JSONResponse({"ok": False, "detail": HUB_DISABLED_TEXT}, status_code=409)
    db = db_of(request)
    db.hub_expire_leases()  # исполнитель мог остановиться: зависшая аренда не держит проверку бессрочно
    op = db.hub_op(op_id)
    if op is None or op["purpose"] != "probe":
        return JSONResponse({"ok": False, "detail": "Проверка не найдена."}, status_code=404)
    return {**probe_answer(op), "worker_online": worker_summary(request)["online"]}


@router.post("/settings/hub/write-pause")
async def hub_write_pause(request: Request):
    """Пауза выдачи записи в Hub (ADR-0128, п. 6.6): исполнитель получает только чтение; значение сохраняется в базе."""
    form = await request.form()
    paused = str(form.get("paused") or "") == "1"
    db = request.app.state.db
    try:
        # неизвестный исход повторно не выдаётся, но снятие паузы до сверки – решение оператора, поэтому отдельная отметка
        await run_in_threadpool(db.set_hub_write_paused, paused, accept_unknown=bool(form.get("accept_unknown")))
    except HubUnknownWrites:
        return redirect("/settings?ok=hub_write_unknown#hub")
    except HubResyncRequired:
        return redirect("/settings?ok=hub_write_resync#hub")
    return redirect("/settings?ok=hub_write_paused#hub" if paused else "/settings?ok=hub_write_resumed#hub")


@router.post("/settings/hub/key/rotate")
async def hub_key_rotate(request: Request):
    """Новый ключ исполнителя; прежний сразу перестаёт действовать."""
    db, state = db_of(request), request.app.state
    if state.settings.hub_disabled:  # учебный стенд npm: исполнителя нет – ключ не выпускается
        from app.db import HUB_DISABLED_TEXT
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": HUB_DISABLED_TEXT}, status_code=409)
        return redirect("/settings#hub")

    def rotate() -> None:
        with _KEY_ROTATION:  # запись в базу и память – одним шагом: две замены не разойдутся
            try:
                state.hub_worker_key = hub_ops.rotate_worker_key(db)
            except CommitUnknown:  # записался ли ключ, неизвестно: действует то, что в базе, прежний ключ из памяти не показывается
                state.hub_worker_key = ""
                state.hub_worker_key_error = "Исход замены ключа неизвестен: база не ответила. Перезапустите приложение или выпустите ключ заново."
                try:
                    state.hub_worker_key = hub_ops.load_or_create_worker_key(db)
                    state.hub_worker_key_error = ""
                except Exception as e:  # исходная ошибка важнее; настройки покажут причину
                    log.warning("ключ исполнителя после неизвестного исхода замены не прочитан: %s", type(e).__name__)
                raise
            state.hub_worker_key_error = ""

    await run_in_threadpool(rotate)
    return redirect("/settings?ok=hub_key_rotated#hub")

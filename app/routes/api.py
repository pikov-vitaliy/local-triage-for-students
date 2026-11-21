"""Служебные JSON-адреса: проверка живости и метрики видеокарты и загруженных моделей."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse

from app import __version__
from app.build_info import build_info
from app import model_traffic
from app.executors import generation, service_client
from app.llm import LlmError, gate_for
from app.storage import DatabaseBusy
from app.routes.common import db_of, metrics_of, profile_for, server_of, settings_of, web_of

router = APIRouter()

BACKUP_STALE_HOURS = 48  # проверенная копия базы старше – «давно не было»: ежедневная задача могла не отработать


def backup_state(note: Mapping[str, Any] | None, now: datetime | None = None) -> dict[str, Any]:
    """Поле backup в /healthz по отметке о последней проверенной копии базы (Database.last_checked_backup): время проверки,
    возраст в целых часах и признак stale – копия старше BACKUP_STALE_HOURS. Отметки нет или её время не читается – времени
    и возраста нет, stale – true. На status и код ответа поле не влияет."""
    value = (note or {}).get("checked_at")
    try:
        checked = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        checked = None
    if checked is None:
        return {"checked_at": None, "age_hours": None, "stale": True}
    if checked.tzinfo is None:
        checked = checked.replace(tzinfo=UTC)
    age = max(0.0, ((now or datetime.now(UTC)) - checked).total_seconds())  # часы компьютера могли отстать от отметки
    return {"checked_at": checked.astimezone(UTC).isoformat(timespec="seconds"), "age_hours": int(age // 3600),
            "stale": age > BACKUP_STALE_HOURS * 3600}


@router.get("/healthz")
def healthz(request: Request):
    """Готовность: база отвечает, схема подходит; обслуживание – отдельное состояние (ADR-0128, раздел 10). 503 – не готово.
    backup – возраст последней проверенной копии базы (бэклог 76): сведение для оператора, готовность от него не зависит."""
    info = build_info()
    answer = {"status": "ok", "version": __version__, "commit": info["commit"], "dirty": info["dirty"]}
    settings = request.app.state.settings
    if settings.stand == "npm":  # учебный стенд (ADR-0155): обёртка узнаёт свой процесс по метке запуска
        from app.llm_net import external_enabled
        answer["stand"] = {"token": settings.stand_token, "external": external_enabled()}
    db = getattr(request.app.state, "db", None)
    if db is None:
        return answer
    try:
        ready = db.ready()
    except DatabaseBusy:
        return JSONResponse({**answer, "status": "database_unavailable"}, status_code=503)
    answer["schema"] = ready["schema"]
    if not ready["ok"]:
        return JSONResponse({**answer, "status": "schema_mismatch"}, status_code=503)
    if ready["instance_lost"]:
        return JSONResponse({**answer, "status": "instance_lost"}, status_code=503)
    try:
        answer["backup"] = backup_state(db.last_checked_backup())
    except DatabaseBusy:  # база перестала отвечать уже после проверки готовности – тот же ответ, что у неё
        return JSONResponse({**answer, "status": "database_unavailable"}, status_code=503)
    if request.app.state.settings.maintenance:
        answer["status"] = "maintenance"
    elif db.hub_write_paused():
        answer["status"] = "hub_write_paused"
    return answer


@router.get("/api/metrics")
def api_metrics(request: Request) -> dict:
    return metrics_of(request)


@router.get('/api/metrics/history')
def metrics_history(request:Request,window:str='15m',run:int|None=None):
    """История ресурсов сервера модели: прогона run (его снимка исполнителя; прогон до 0.9.12 – профиль приложения)
    или профиля приложения – ряды других серверов на графике не смешиваются (ADR-0102 п. 9)."""
    if window not in ('15m','24h'):raise HTTPException(400,'Выберите окно 15m или 24h.')
    observer=request.app.state.telemetry
    db=db_of(request)
    if run is None:
        return {'window':window,'points':observer.history(window,server=observer.server_tag(server_of(profile_for(request))))}
    row=db.get_run(run)
    if row is None:raise HTTPException(404,'Прогон не найден.')
    execution=db.get_execution(row.get('execution_id'))
    # прогон до 0.9.12: сервер не записан – его история тоже без метки сервера (ряд '')
    tag=observer.server_tag(server_of(execution)) if execution else ''
    return {'window':window,'points':observer.history(window,server=tag)}


@router.get('/api/runs/active')
def active_run(request:Request):
    from app.routes.common import db_of
    from app.routes.runs import status_payload
    db=db_of(request)
    runs=db.active_runs()
    if not runs:return {'run':None}
    runs.sort(key=lambda r:({'running':0,'queued':1,'paused':2}.get(r['state'],3),r['id']))
    result=status_payload(request,runs[0]['id'])
    if result is None:return {'run':None}
    result['project_name']=(db.get_project(runs[0]['project_id']) or {}).get('name','Проект')
    return result



@router.get('/api/research/active')
def active_research(request: Request, last: int | None = None):
    """Полоса «идёт получение» на любой странице (как «ход разбора» у прогона): идущее
    получение исследования компонентов – номер, проект, строки и ссылка на страницу хода. Идущего нет, но страница
    его уже показывала (last) – его итог, чтобы полоса сказала «завершено», а не пропала молча."""
    from app.routes.common import db_of
    from app.routes.components import RUN_STATE_LABELS
    db = db_of(request)
    running = db.running_research_runs()
    run = running[-1] if running else (db.research_run(int(last)) if last else None)
    if run is None:
        return {'run': None}
    project = db.get_project(int(run['project_id'])) or {}
    keys = ('id', 'project_id', 'state', 'rows_total', 'rows_saved', 'rows_unchanged', 'rows_failed', 'rows_unknown')
    return {'run': {**{k: run.get(k) for k in keys}, 'state_label': RUN_STATE_LABELS.get(run['state'], run['state'])},
            'project_name': project.get('name') or 'Проект', 'running': len(running),
            'url': f"/projects/{run['project_id']}/components/research/{run['id']}"}


@router.post("/api/model/warmup")
def model_warmup(request: Request) -> dict:
    """Прогрев модели профиля по умолчанию для разбора кода (загрузка ВМ, ADR-0102 п. 10): только включённый профиль
    класса local – общий сервер в сети выполняет чужие задачи и не прогревается; под общим правом на генерацию без
    ожидания – занято: «холодный старт», а не ошибка. Ответ: {state: warm | cold | busy | skipped, ...}."""
    db, settings = db_of(request), settings_of(request)
    profile = profile_for(request)
    if not profile.get("enabled") or profile.get("trust") != "local":
        return {"state": "skipped", "reason": "профиль по умолчанию выключен или это сервер в сети"}
    model = str(profile.get("default_model") or settings.default_model)
    gate = gate_for(profile)
    if not gate.try_acquire("warmup"):
        return {"state": "busy", "reason": f"модель ({gate.label}) занята разбором или вопросом"}
    try:
        client = service_client(web_of(request).make_client, server_of(profile), db)
        with model_traffic.context(purpose="warmup"):
            client.warm_model(model, int(generation(profile).get("num_ctx") or settings.num_ctx))
        return {"state": "warm", "model": model}
    except LlmError as e:
        return {"state": "cold", "model": model, "error": str(e)}
    finally:
        gate.release()

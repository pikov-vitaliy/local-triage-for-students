"""Раздел «Прогоны»: запуск триажа, страница прогона с живыми метриками, состояние (JSON), поток событий (SSE),
пауза, продолжение и стоп.

Шаблоны – templates/runs/: run.html (страница прогона).
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

from app.db import FINAL_RUN_STATES
from app.llm import norm_model_name
from app.executors import executor_label
from app.routes.common import (MAX_NAME, collector_of, db_of, metrics_of, project_or_404, redirect, render,
                               runner_of)
from app.routes.projects import project_response
from app import i18n
from app.run_errors import error_label, group_run_errors, shown_error
from app.triage import TriageError
from app.view import ITEM_STATE_LABELS, PHASE_LABELS, RUN_STATE_LABELS, VERDICT_LABELS

router = APIRouter()

MAX_SELECTED = 5000  # находок в прогоне «выбранные»
SSE_INTERVAL_S = 1.0


def run_model_entry(metrics: dict, model: str) -> dict | None:
    """Запись /api/ps (metrics_view["models"]) именно для модели прогона: имена сравниваются без регистра
    и с «:latest» по умолчанию. Модель прогона не загружена – None (загружена другая модель – это не она)."""
    wanted = norm_model_name(model)
    return next((m for m in metrics.get("models") or [] if norm_model_name(m.get("name")) == wanted), None)


def run_notice(run: dict) -> str:
    """Сообщение о состоянии самого прогона, а не о последней ошибке находки.

    Ошибка находки теперь живёт в блоке «Ошибки» и не окрашивает страницу завершённого прогона: для done и
    stopped сообщения нет, для paused – только если паузу поставил сам прогон (Ollama не отвечает или
    приложение перезапускалось), а не последняя ошибка находки.
    """
    # last_error – русский канонический текст (ADR-0158): признак паузы ищется на обоих языках, перевод – при показе
    text = str(run["last_error"] or "")
    if run["state"] == "error":
        return shown_error(text) or i18n._("Прогон завершился ошибкой.")
    if run["state"] == "paused" and ("на паузе" in text or "на паузу" in text or "pause" in text.casefold()):
        return shown_error(text)
    return ""


def status_payload(request: Request, run_id: int) -> dict | None:
    """Состояние прогона для страницы и потока событий: счётчики, оценка времени, текущая находка, лента, ошибки,
    метрики видеокарты и запись о модели прогона в памяти Ollama (run_model)."""
    status = runner_of(request).run_status(run_id)
    if status is None:
        return None
    pid = status["run"]["project_id"]
    status["run"]["state_label"] = RUN_STATE_LABELS.get(status["run"]["state"], status["run"]["state"])
    status["run"]["notice"] = run_notice(status["run"])
    from app.examples import rule_text
    if status["current"] and status["current"].get("rule"):
        status["current"]["rule"] = rule_text(status["current"]["rule"])
    if status["current"]:
        status["current"]["phase_label"] = PHASE_LABELS.get(status["current"]["phase"], "")
        fid = status["current"].get("finding_id")
        status["current"]["url"] = f"/projects/{pid}/findings/{fid}" if fid else None
    for item in status["feed"]:
        item["url"] = f"/projects/{pid}/findings/{item['finding_id']}" if item.get("finding_id") else None
        item["verdict_label"] = VERDICT_LABELS.get(item.get("verdict") or "", "")
        item["state_label"] = ITEM_STATE_LABELS.get(item["state"], item["state"])
        item["error_label"] = error_label(item["error"]) if item.get("error") else ""
        item["error"] = shown_error(item.get("error"))  # видимый текст – на языке интерфейса, в базе – русский
        if item.get("rule"):  # категория учебных примеров – на языке интерфейса, в базе – как в выгрузке
            item["rule"] = rule_text(item["rule"])
    status["errors"] = group_run_errors(db_of(request).run_errors(run_id), pid)
    if status.get("slow_model"):  # строка медленного режима хранится в журнале прогона по-русски
        status["slow_model"]["text"] = shown_error(status["slow_model"].get("text"))
    run_row = db_of(request).get_run(run_id)
    # метрики сервера, на котором идёт этот прогон (снимок исполнителя); прогон до 0.9.12 – профиль приложения
    status["metrics"] = metrics_of(request, db_of(request).get_execution((run_row or {}).get("execution_id")))
    status['observed_at'] = time.time()
    status["run_model"] = run_model_entry(status["metrics"], status["run"]["model"])
    status["collector"] = collector_of(request)  # сборщик метрик компьютера: предупреждение на странице (HOSTCOL-01)
    return status


def run_or_404(request: Request, run_id: int) -> dict:
    run = db_of(request).get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=i18n._("Прогон не найден."))
    return run


@router.post("/projects/{project_id}/runs")
async def start_run(request: Request, project_id: int):
    form = await request.form(max_fields=MAX_SELECTED + 20)
    model = str(form.get("model") or "").strip()[:MAX_NAME]
    scope = str(form.get("scope") or "live")  # по умолчанию – живые в Hub (бэклог 104)
    hub_ids = [str(x) for x in form.getlist("hub_id")][:MAX_SELECTED]
    fresh = str(form.get("fresh") or "") == "1"
    if any(ord(ch) < 32 for ch in model):
        model = ""
    try:
        run_id = await run_in_threadpool(runner_of(request).enqueue, project_id, model, scope, hub_ids, fresh,
                                        "project")
    except TriageError as e:
        return await run_in_threadpool(project_response, request, project_id, str(e), 400)
    return redirect(f"/runs/{run_id}")


@router.get("/runs/{run_id}", response_class=HTMLResponse)
def run_page(request: Request, run_id: int, error: str = ""):
    run = run_or_404(request, run_id)
    project = project_or_404(request, run["project_id"])
    status = status_payload(request, run_id)
    # готовые находки можно проверять, не дожидаясь конца прогона
    db = db_of(request)
    first = db.neighbor_unreviewed(project["id"], -1, "next", filters={"verdict": "any"})
    # вкладки проекта, как на остальных его страницах
    executor = executor_label(db_of(request), db_of(request).get_execution(run.get("execution_id")))
    return render(request, "runs/run.html", {"project": project, "run": run, "status": status,
                                             "collector": status["collector"],
                                             "executor": executor, "excluded": db.run_excluded(run_id),
                                             "summary": db.run_summary(run_id),
                                             "run_final": run["state"] in FINAL_RUN_STATES,
                                             "first_unreviewed": first, "counts": db.count_findings(project["id"]),
                                             "review_stats": db.review_stats(project["id"]), "error": error[:500]})


@router.get("/runs/{run_id}/status")
def run_status(request: Request, run_id: int):
    run_or_404(request, run_id)
    return status_payload(request, run_id)


@router.get("/runs/{run_id}/events")
async def run_events(request: Request, run_id: int):
    await run_in_threadpool(run_or_404, request, run_id)

    async def stream():
        last = ""
        yield "retry: 3000\n\n"
        while True:
            if await request.is_disconnected():
                return
            status = await run_in_threadpool(status_payload, request, run_id)
            if status is None:
                return
            data = json.dumps(status, ensure_ascii=False)
            if data != last:
                yield f"event: status\ndata: {data}\n\n"
                last = data
            if status["run"]["state"] in FINAL_RUN_STATES:
                yield "event: end\ndata: {}\n\n"
                return
            await asyncio.sleep(SSE_INTERVAL_S)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@router.post("/runs/{run_id}/retry-errors")
async def retry_errors(request: Request, run_id: int):
    """«Повторить ошибочные»: новый прогон выбранных находок этого прогона – по сохранённым срезам, без готовых
    вердиктов и той же моделью. Клоны для этого не нужны: код берётся из cases (triage.snapshot_code). Находки
    «результат неизвестен» (К11: запрос внешнему провайдеру мог быть оплачен) – только по отдельной отметке формы."""
    form = await request.form(max_fields=4, max_files=0)
    include_unknown = str(form.get("include_unknown") or "") == "1"
    return await run_in_threadpool(_retry_errors, request, run_id, include_unknown)


def _retry_errors(request: Request, run_id: int, include_unknown: bool):
    run = run_or_404(request, run_id)
    if run["state"] not in ("done", "stopped", "error", "paused"):
        return redirect(f"/runs/{run_id}?error=" + quote(
            i18n._("Повторить ошибочные можно после завершения прогона или на паузе.")))
    db = db_of(request)
    hub_ids = [row["hub_id"] for row in db.run_errors(run_id)
               if row["retryable"] and (include_unknown or not row["unknown"])]
    if not hub_ids:
        return redirect(f"/runs/{run_id}?error=" + quote(
            i18n._("В этом прогоне нет находок SAST с ошибкой, которые есть в текущей выгрузке и идут в повтор без "
                   "отдельной отметки: повторять нечего.")))
    # Снимок исполнителя переносится, если профиль включён и адрес не менялся; иначе – отказ до остановки прежнего
    # прогона; прогон до 0.9.12 – новый прогон на профиле проекта (ADR-0102 п. 5). Прежний прогон на паузе
    # останавливается той же транзакцией, что создаёт новый.
    try:
        new_id = runner_of(request).retry_errors(run_id, hub_ids)
    except TriageError as e:
        return redirect(f"/runs/{run_id}?error=" + quote(str(e)))
    return redirect(f"/runs/{new_id}")


def run_action(request: Request, run_id: int, action: Callable[[int], bool]) -> RedirectResponse:
    run_or_404(request, run_id)
    action(run_id)
    return redirect(f"/runs/{run_id}")


@router.post("/runs/{run_id}/pause")
def pause_run(request: Request, run_id: int):
    return run_action(request, run_id, runner_of(request).pause)


@router.post("/runs/{run_id}/resume")
def resume_run(request: Request, run_id: int):
    """«Продолжить». Прогон без снимка исполнителя (до 0.9.12) или с выключенным профилем продолжается новым прогоном на
    действующем профиле проекта (ADR-0102, П22): исполнитель разобранной части не подменяется."""
    run = run_or_404(request, run_id)
    runner = runner_of(request)
    if run["state"] == "paused" and runner.continuation_reason(run):
        try:
            new_id = runner.continue_as_new(run_id)
        except TriageError as e:
            return redirect(f"/runs/{run_id}?error=" + quote(str(e)))
        return redirect(f"/runs/{new_id}")
    return run_action(request, run_id, runner.resume)


@router.post("/runs/{run_id}/stop")
def stop_run(request: Request, run_id: int):
    return run_action(request, run_id, runner_of(request).stop)

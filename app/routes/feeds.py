"""Раздел «Справочники»: загрузка выгрузки БДУ ФСТЭК России и каталога CWE, что загружено и когда.

Файл сохраняется во временную папку данных (DATA_DIR/tmp) и разбирается в фоновом потоке (app/feeds.py): выгрузка
БДУ – это около 0,6 ГБ XML, разбор идёт около минуты. Страница показывает ход загрузки и сама обновляется, когда
она закончится (data-poll); идущую загрузку можно остановить кнопкой «Остановить загрузку». Шаблон – templates/feeds/index.html.
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile

from app import i18n
from app.feeds import BUSY, KINDS, FeedError, FeedStore
from app.logsafe import log_failure
from app.routes.common import MAX_NAME, redirect, register_messages, render, settings_of

log = logging.getLogger("local_triage.web")

router = APIRouter()

register_messages({
    "feed_started": "Файл получен. Идёт разбор – ход виден ниже, страница обновится сама.",
    "feed_cancel": "Загрузка останавливается: прежний справочник не изменится.",
})


class FeedJob:
    """Загрузка справочника в фоновом потоке: одна за раз. state – idle, running, done, error."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.state = "idle"
        self.kind = ""
        self.filename = ""
        self.message = ""
        self.started = 0.0

    def snapshot(self) -> dict:
        with self._lock:
            return {"state": self.state, "kind": self.kind, "label": KINDS.get(self.kind, ""),
                    "filename": self.filename, "message": self.message,
                    "elapsed": int(time.monotonic() - self.started) if self.state == "running" else 0}

    def start(self, store: FeedStore, kind: str, path: Path, filename: str) -> None:
        with self._lock:
            if self.state == "running":
                path.unlink(missing_ok=True)
                raise FeedError(i18n._(BUSY))
            self.state, self.kind, self.filename, self.message = "running", kind, filename, ""
            self.started = time.monotonic()
        thread = threading.Thread(target=self._run, args=(store, kind, path, filename), name="feed-load", daemon=True)
        thread.start()

    def _run(self, store: FeedStore, kind: str, path: Path, filename: str) -> None:
        try:
            meta = store.load(kind, path, filename)
            if meta.get("source_date"):
                message = i18n._("Готово: {feed} загружен, записей – {records}, дата выгрузки {date}, разбор занял "
                                 "{seconds} с. Сведения из него уже видны в карточках находок.", feed=KINDS[kind],
                                 records=meta["records"], date=meta["source_date"], seconds=meta["seconds"])
            else:
                message = i18n._("Готово: {feed} загружен, записей – {records}, разбор занял {seconds} с. Сведения "
                                 "из него уже видны в карточках находок.", feed=KINDS[kind], records=meta["records"],
                                 seconds=meta["seconds"])
            state = "done"
        except FeedError as e:
            state, message = "error", i18n._("{feed} не загружен: файл не принят. {reason} Прежний справочник не "
                                             "изменился.", feed=KINDS[kind], reason=e)
        except Exception as e:  # текст исключения в журнал не пишется (ADR 0016)
            eid = log_failure(log, "справочник не загружен", e)
            state, message = "error", i18n._("{feed}: внутренняя ошибка при загрузке (номер в журнале {eid}).",
                                             feed=KINDS[kind], eid=eid)
        finally:
            path.unlink(missing_ok=True)
        with self._lock:
            self.state, self.message = state, message


def store_of(request: Request) -> FeedStore:
    return request.app.state.feeds


def job_of(request: Request) -> FeedJob:
    return request.app.state.feed_job


def page_context(request: Request) -> dict:
    store = store_of(request)
    status = store.status()
    job = job_of(request).snapshot()
    context = {"kinds": KINDS, "status": status, "job": job,
               "max_upload_mb": settings_of(request).max_upload_mb}
    context['capec_profile'] = store.capec_data(shared=True)['profile'] if 'capec' in status else {}
    # После обновления страницы ?ok= остаётся в адресе, но завершённая загрузка уже не идёт.
    if job["state"] != "running" and request.query_params.get("ok") in {"feed_started", "feed_cancel"}:
        context["ok_message"] = ""
    return context


@router.get("/feeds", response_class=HTMLResponse)
def feeds_page(request: Request):
    return render(request, "feeds/index.html", page_context(request))


@router.get("/feeds/job")
def feeds_job(request: Request) -> dict:
    """Ход загрузки для страницы (data-poll): done и reload – загрузка закончилась, страницу пора обновить."""
    job = job_of(request).snapshot()
    finished = job["state"] != "running"
    return {**job, "done": finished, "reload": finished}


@router.post("/feeds/cancel")
def cancel_feed(request: Request):
    """«Остановить загрузку»: разбор прервётся на ближайшем куске, временные таблицы удалятся, прежний справочник
    останется. Загрузки нет – просто возврат на страницу."""
    stopping = job_of(request).snapshot()["state"] == "running" and store_of(request).cancel()
    return redirect("/feeds?ok=feed_cancel" if stopping else "/feeds")


@router.post("/feeds/{kind}")
async def upload_feed(request: Request, kind: str):
    if kind not in KINDS:
        raise HTTPException(status_code=404, detail=i18n._("Такого справочника нет."))
    settings = await run_in_threadpool(settings_of, request)
    form = await request.form(max_files=1, max_fields=5)
    try:
        upload = form.get("file")
        try:
            if not isinstance(upload, UploadFile) or not upload.filename:
                raise FeedError(i18n._("Выберите файл архива (.zip)."))
            filename = Path(upload.filename.replace("\\", "/")).name[:MAX_NAME]
            if not filename.lower().endswith(".zip"):
                raise FeedError(i18n._("Нужен архив .zip – в том виде, как он скачан с сайта."))
            settings.tmp_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=settings.tmp_dir, prefix="feed-", suffix=".zip")
            tmp = Path(tmp_name)
            try:
                size = 0
                with os.fdopen(fd, "wb") as out:
                    while chunk := await upload.read(1024 * 1024):
                        size += len(chunk)
                        if size > settings.max_upload_bytes:
                            raise FeedError(i18n._("Архив больше {limit} МБ – это предел приложения "
                                                   "(MAX_UPLOAD_MB).", limit=settings.max_upload_mb))
                        out.write(chunk)
                job_of(request).start(store_of(request), kind, tmp, filename)
            except BaseException:
                tmp.unlink(missing_ok=True)
                raise
        except FeedError as e:
            message = str(e)  # имя e после блока except не видно: текст – в переменную до лямбды
            return await run_in_threadpool(lambda: render(request, "feeds/index.html",
                                                          {**page_context(request), "error": message}, 400))
    finally:
        await form.close()
    return redirect("/feeds?ok=feed_started")

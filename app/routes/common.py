"""Общее для разделов интерфейса: состояние приложения, действующие настройки, отрисовка страниц, переходы, кэши
списка моделей и метрик.

Состояние приложения лежит в request.app.state: db, runner и mask_key создаются при запуске (main.py, lifespan),
web – WebState: настройки из переменных окружения, фабрика клиента Ollama, шаблоны, кэши. Разделы обращаются
к нему через функции этого модуля: db_of, runner_of, settings_of (действующие настройки – из базы поверх
окружения), client_of, models_of, metrics_of.
"""

from __future__ import annotations

import logging
import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import metrics, model_traffic
from app.navigation import page_context
from app.config import Settings
from app.db import Database
from app.executors import Server, server_of, service_client
from app.llm import LlmError
from app.llm_ollama import OllamaClient
from app.triage import TriageRunner
from app.view import VERDICT_LABELS, num, reopened_note

log = logging.getLogger("local_triage.web")

MAX_NAME = 200
MODELS_TTL_S = 15.0
METRICS_TTL_S = 1.5
COUNT = re.compile(r"[0-9]{1,6}")  # число из адреса: только цифры ASCII, без «²» и подобного

# Сообщения после действий (?ok=ключ): каждый раздел добавляет свои через register_messages
OK_MESSAGES: dict[str, str] = {}
# ключи ?ok=, сообщающие о неудаче (например, модель не ответила): строка над страницей – плашкой ошибки
OK_ERRORS: set[str] = set()

# Стандартные ошибки HTTP – по-русски
HTTP_ERRORS = {
    400: "Неверный запрос.",
    403: "Доступ запрещён.",
    404: "Страница не найдена.",
    405: "Такой запрос здесь не поддерживается.",
    409: "Данные изменились: обновите страницу.",
    413: "Слишком большой запрос.",
    422: "Неверный адрес или параметры запроса.",
    500: "Внутренняя ошибка приложения.",
}


def copy_missing_message(prior: dict | None) -> str:
    """Находки нет в текущей выгрузке, текст для Hub не копируется. Запрос при этом ничего не записывает: введённое в форме не
    сохранено, а то, что было сохранено раньше (prior – прежняя запись решения), осталось как есть."""
    kept = bool(prior and (prior.get("decision") or prior.get("final_verdict") or prior.get("final_comment")))
    tail = ("Решение, сохранённое раньше, осталось в истории без изменений." if kept
            else "Раньше сохранённого решения по этой находке нет.")
    return ("Находки нет в текущей выгрузке: текст для Hub не копируется, а введённое в форме не сохранено. " + tail)


class CommentNeedsCheck(Exception):
    """Текст для Hub с комментарием модели, написанным к другому вердикту: копирование требует правки текста или
    явного подтверждения (поле comment_confirmed)."""


CONFIRM_STALE = ("Решение изменилось после того, как вы отметили «Текст проверен» (например, в другой вкладке): "
                 "обновите карточку, проверьте обоснование и отметьте ещё раз.")


def form_int(value: Any) -> int | None:
    """Целое из поля формы (только цифры ASCII); нет поля или не число – None."""
    text = str(value or "").strip()
    return int(text) if text.isascii() and text.isdigit() and len(text) <= 9 else None


def comment_confirm_valid(form, review: dict | None, strict: bool = True) -> bool:
    """«Текст проверен» из формы относится к решению, которое человек видел: редакция из формы совпадает с текущей.
    Одно правило для всех путей выдачи текста SAST и SCA – сохранения, короткого текста, дефекта и отметок. Без поля
    редакции (страница до обновления приложения) или с прежней редакцией подтверждение не принимается: strict –
    отказ CommentNeedsCheck с просьбой обновить карточку, иначе просто False (сохранение без выдачи текста)."""
    if str(form.get("comment_confirmed") or "") != "1":
        return False
    shown = form_int(form.get("review_revision"))
    if shown is None or int((review or {}).get("revision") or 0) != shown:
        if strict:
            raise CommentNeedsCheck(CONFIRM_STALE)
        return False
    return True


def comment_check_text(origin: str, target: str) -> str:
    return (f"Комментарий написан моделью к вердикту «{VERDICT_LABELS.get(origin, origin)}», а в Hub уйдёт вердикт "
            f"«{VERDICT_LABELS.get(target, target)}». Поправьте текст или отметьте «Текст проверен» – и скопируйте "
            "ещё раз.")


def entered_check_text(origin: str, target: str) -> str:
    return (f"Комментарий написан моделью к вердикту «{VERDICT_LABELS.get(origin, origin)}», а в Hub уйдёт вердикт "
            f"«{VERDICT_LABELS.get(target, target)}». Поправьте текст и сохраните решение или отметьте «Текст проверен» – "
            "и поставьте отметку ещё раз.")


def register_messages(messages: dict[str, str], errors: tuple[str, ...] = ()) -> None:
    """Сообщения раздела для строки над страницей после действия: {ключ из ?ok=: текст}; errors – ключи, которые
    сообщают о неудаче и показываются плашкой ошибки, а не успеха."""
    OK_MESSAGES.update(messages)
    OK_ERRORS.update(errors)


# ============================================================================ кэши и метрики

class Cached:
    """Значения по ключу (профиль и адрес сервера модели, ADR-0102), каждое пересчитывается не чаще раза в ttl
    секунд; ключей – не больше max_keys (старые вытесняются); потокобезопасно."""

    def __init__(self, ttl: float, compute: Callable[[Any], Any], max_keys: int = 8) -> None:
        self.ttl = ttl
        self.compute = compute
        self.max_keys = max_keys
        self._lock = threading.Lock()
        self._items: dict[Any, tuple[float, Any]] = {}
        self._busy: dict[Any, threading.Lock] = {}  # один опрос на ключ; другие ключи им не задерживаются

    def get(self, key: Any = None, fresh: bool = False) -> Any:
        with self._lock:
            at, value = self._items.get(key, (-math.inf, None))
            if not fresh and time.monotonic() - at < self.ttl:
                return value
            busy = self._busy.setdefault(key, threading.Lock())
        with busy:  # опрос сервера – без общего замка: медленный сервер не задерживает страницы других
            with self._lock:
                at, value = self._items.get(key, (-math.inf, None))
                if not fresh and time.monotonic() - at < self.ttl:  # пока ждали, значение посчитал другой
                    return value
            value = self.compute(key)
            with self._lock:
                self._items.pop(key, None)
                self._items[key] = (time.monotonic(), value)
                while len(self._items) > self.max_keys:
                    old = next(iter(self._items))
                    self._items.pop(old)
                    self._busy.pop(old, None)
            return value


def metrics_view(snapshot: Any) -> dict:
    """Снимок metrics.snapshot -> вид для страницы прогона и /api/metrics.

    {"gpu": {name, mem_used_mb, mem_total_mb, temp_c, util_pct, power_w} | None,
     "models": [{name, size_mb, vram_mb, vram_pct, context}], "vram_used_mb", "vram_total_mb",
     "vram_source": "nvidia-smi" | "ollama" | "", "error": текст или None}
    """
    snap = snapshot if isinstance(snapshot, dict) else {}
    raw_gpu = snap.get("gpu")
    gpu = None
    if isinstance(raw_gpu, dict):
        gpu = {"name": str(raw_gpu.get("name") or ""), "mem_used_mb": num(raw_gpu.get("memory_used_mb")),
               "mem_total_mb": num(raw_gpu.get("memory_total_mb")), "temp_c": num(raw_gpu.get("temperature_c")),
               "util_pct": num(raw_gpu.get("utilization_pct")), "power_w": num(raw_gpu.get("power_w")),
               "gpus": raw_gpu.get("gpus", [])}
    models = []
    for m in snap.get("models") or []:
        if isinstance(m, dict):
            share = num(m.get("vram_share"))
            models.append({"name": str(m.get("name") or ""), "size_mb": num(m.get("size_mb")),
                           "vram_mb": num(m.get("vram_mb")), "context": m.get("context"),
                           "vram_pct": round(100 * share) if share is not None else None})
    return {"gpu": gpu, "models": models, "vram_used_mb": num(snap.get("vram_used_mb")),
            "vram_total_mb": num(snap.get("vram_total_mb")), "vram_source": str(snap.get("vram_source") or ""),
            "error": str(snap.get("ollama_error") or snap.get("error") or "") or None}


def compute_models(make_client: Callable[[str], OllamaClient], key: Any, db: Any = None) -> dict:
    """Версия Ollama и список моделей: {"models", "version", "error"} (error – текст по-русски или ""). key – адрес
    сервера или Server профиля: служебный клиент по правилам профиля (executors.service_client – класс доверия,
    действующие подтверждения из db, ключ из базы, допуск, граница правки профиля)."""
    if isinstance(key, Server):
        c = service_client(make_client, key, db() if callable(db) else db)
    else:
        c = make_client(key[-1] if isinstance(key, tuple) else key)
    try:
        # Назначения в журнале обмена с моделью: опрос версии и списка моделей помечается отдельно от прогона.
        with model_traffic.context(purpose="version"):
            version = c.version()
        with model_traffic.context(purpose="models"):
            models = c.list_models()
    except LlmError as e:
        return {"models": [], "version": "", "error": str(e)}
    return {"models": models, "version": version, "error": ""}


def compute_metrics(make_client: Callable[[str], OllamaClient], key: Any, db: Any = None) -> dict:
    """Метрики видеокарты и загруженных моделей (metrics_view); сбой метрик страницу не ломает. key – адрес сервера
    или (адрес, данные хоста): видеокарта этого компьютера – только у профиля local (ADR-0102 п. 9)."""
    url, host = (key[0], bool(key[1])) if isinstance(key, tuple) else (key, True)
    try:
        client = (service_client(make_client, key, db() if callable(db) else db) if isinstance(key, Server)
                  else make_client(url))
        with model_traffic.context(purpose="status"):
            snap = metrics.snapshot(client, host=host)
    except Exception as e:
        log.warning("метрики недоступны: %s", type(e).__name__)
        snap = {"gpu": None, "models": [], "error": f"Метрики недоступны: {type(e).__name__}"}
    # server – чей это снимок: наблюдение и страницы не выдают метрики одного сервера за метрики другого
    return {**metrics_view(snap), "measured_at": time.time(), "server": server_identity((str(url), bool(host)))}


# ============================================================================ состояние приложения

@dataclass
class WebState:
    """Общее для всех запросов (request.app.state.web)."""

    base: Settings  # настройки из переменных окружения
    make_client: Callable[[str], OllamaClient]
    templates: Jinja2Templates
    models_cache: Cached
    metrics_cache: Cached


def web_of(request: Request) -> WebState:
    return request.app.state.web


def db_of(request: Request) -> Database:
    return request.app.state.db


def runner_of(request: Request) -> TriageRunner:
    return request.app.state.runner


def mask_key_of(request: Request) -> bytes:
    return request.app.state.mask_key


def settings_of(request: Request) -> Settings:
    """Действующие настройки: сохранённые в интерфейсе (таблица settings) поверх переменных окружения."""
    return web_of(request).base.with_stored(db_of(request).get_settings())


def client_of(request: Request) -> OllamaClient:
    return web_of(request).make_client(settings_of(request).ollama_url)


def profile_for(request: Request, project: dict | None = None) -> dict:
    """Профиль, которым пойдёт разбор кода (ADR-0102): профиль проекта или приложения; профиль 1 создаётся, если его
    ещё нет. Для показа – и выключенный (страница скажет об этом), постановка прогона его отклонит."""
    from app.db import DEFAULT_PROVIDER_ID
    db, settings = db_of(request), settings_of(request)
    chosen = (project or {}).get("provider_id") or settings.default_provider_id or DEFAULT_PROVIDER_ID
    profile = db.get_provider(int(chosen))
    if profile is None:
        profile = db.get_provider(DEFAULT_PROVIDER_ID) or db.ensure_default_profile(settings.ollama_url,
                                                                                  settings.default_model)
    return profile


def models_of(request: Request, fresh: bool = False, profile: dict | None = None) -> dict:
    """Версия сервера и список моделей профиля (по умолчанию – профиля приложения); кэш на MODELS_TTL_S секунд по
    профилю, его версии и адресу: разные серверы не делят список."""
    profile = profile or profile_for(request)
    return web_of(request).models_cache.get(server_of(profile), fresh)


def server_identity(server: tuple[str, bool]) -> dict:
    """Метка сервера в снимке метрик (поле server)."""
    return {"base_url": str(server[0]), "local": bool(server[1])}


def metrics_of(request: Request, executor: dict | None = None) -> dict:
    """Метрики видеокарты и загруженных моделей. executor – профиль или снимок исполнителя прогона. Сервер тот же, что
    у профиля приложения (или executor не задан), – снимок фонового наблюдения; другой сервер – его метрики (кэш на
    METRICS_TTL_S) с теми же служебными полями: время измерения, свежесть, данные хоста (у lan – «remote»: видеокарты
    и памяти этого компьютера на странице нет, ADR-0102 п. 9)."""
    observer = getattr(request.app.state, 'telemetry', None)
    server = server_of(executor or profile_for(request))
    if observer:
        snap = observer.snapshot()
        # снимок наблюдения – только если он этого же сервера: после смены профиля приложения прежний снимок
        # чужой, пока наблюдение не измерило новый сервер
        if snap.get("server") == server_identity(server):
            return snap
        remembered = observer.server_snapshot(server)  # сервер идущего прогона, измеренный наблюдением
        if remembered is not None:
            return remembered
        # наблюдение этот сервер ещё не измерило: оно измерит его в ближайший цикл, страница сеть не ждёт
        observer.want(server)
        return observer.pending(server, metrics_view({}))
    return dict(web_of(request).metrics_cache.get(server))


def default_model(settings: Settings, models: list[dict], project: dict | None = None,
                  profile: dict | None = None) -> str:
    """Модель, выбранная в списке по умолчанию: модель проекта, иначе модель профиля, которым пойдёт запрос
    (ADR-0102), иначе модель из настроек – первая из них, что есть на сервере; иначе первая из списка."""
    from app.executors import same_model

    names = [m["name"] for m in models]
    key = same_model(str((profile or {}).get("kind") or "ollama"))  # Ollama – без регистра и «:latest»
    for wanted in ((project or {}).get("model") or "", (profile or {}).get("default_model") or "",
                   settings.default_model):
        if wanted:
            found = next((name for name in names if key(name) == key(wanted)), None)
            if found is not None:
                return found
    return names[0] if names else ""


# ============================================================================ страницы и переходы

def external_enabled() -> bool:
    from app import llm_net
    return llm_net.external_enabled()


def collector_of(request: Request) -> dict:
    """Состояние сборщика метрик компьютера для предупреждений на страницах (telemetry.collector_state)."""
    from app import llm_net
    from app.telemetry import collector_state
    return collector_state(settings_of(request).data_dir / "telemetry" / "host.json", llm_net.in_container())


def render(request: Request, name: str, context: dict, status_code: int = 200) -> HTMLResponse:
    """Страница по шаблону: сообщение после действия (?ok=…, ?reopened=N), действующие настройки, контекст."""
    ok = request.query_params.get("ok", "")
    message = OK_MESSAGES.get(ok, "")
    reopened = request.query_params.get("reopened", "")
    if message and COUNT.fullmatch(reopened) and int(reopened) > 0:
        message += " " + reopened_note(int(reopened))
    db = db_of(request)
    providers = db.list_providers()
    base = {"ok_message": message, "ok_error": bool(message) and ok in OK_ERRORS, "error": "",
            "settings": settings_of(request),
            # подвал говорит правду о том, куда уходит код (ADR-0102): есть включённый сервер в сети – и туда
            "lan_in_use": any(p.get("enabled") and p.get("trust") == "lan" for p in providers),
            # ...а есть включённый внешний профиль – и об интернете: код уходит ему только у проектов с отметкой «код не
            # секретный» (ADR-0104); прежний текст «внешних запросов интерфейс не делает» был неправдой
            "external_in_use": any(p.get("enabled") and p.get("trust") == "external" for p in providers),
            # сборщик метрик компьютера: предупреждение с инструкцией там, где без него что-то не работает (HOSTCOL-01)
            "collector": context.get("collector") or collector_of(request), "external_on": external_enabled()}
    base.update(page_context(request, context, db))
    if name in ("findings/card.html", "sca/card.html", "projects/defect_card.html"):
        from app import hub_pull
        from app.hub_ops import hub_base
        from app.hub_status import HUB_ISSUE_TYPE
        project = context["project"]
        kind = "defect" if name == "projects/defect_card.html" else "issue"
        key = (str(context["row"]["hub_defect_id"]) if kind == "defect" else
               f"{HUB_ISSUE_TYPE.get(context['f'].kind, 'UNMAPPED')}:{context['f'].hub_id}")
        base["pull_state"] = hub_pull.card_context(db, project["id"], hub_base(base["settings"].hub_url),
                                                 project.get("hub_app_id"), kind, key)
    reference_cache = {}

    def reference_status(kind, key):
        pair = (kind, key)
        if pair not in reference_cache:
            reference_cache[pair] = request.app.state.feeds.reference_status(kind, key)
        return reference_cache[pair]

    base["reference_status"] = reference_status
    return web_of(request).templates.TemplateResponse(request, name, {**base, **context}, status_code=status_code)


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def project_or_404(request: Request, project_id: int) -> dict:
    project = db_of(request).get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Проект не найден.")
    return project


def with_reopened(url: str, count: int) -> str:
    """Адрес перехода после сохранения: добавляет reopened=N перед якорем, если отметки снимались."""
    if count <= 0:
        return url
    path, _, anchor = url.partition("#")
    return f"{path}&reopened={count}" + (f"#{anchor}" if anchor else "")


def query(params: dict[str, Any], **changes: Any) -> str:
    """Строка параметров адреса без пустых значений."""
    merged = {**params, **changes}
    # повторяющиеся параметры (кортеж значений, бэклог 99) – по одному на значение
    return urlencode({k: v for k, v in merged.items() if v not in (None, "", False, ())}, doseq=True)


def error_response(request: Request, status_code: int, detail: str, headers: dict | None = None,
                   settings: Any = None):
    """Ошибка по-русски: страница для браузера, JSON для запросов из скрипта. settings – готовые настройки для
    страницы: при занятой базе их передаёт обработчик (чтение настроек из базы в цикле событий ждало бы соединение)."""
    if "text/html" in request.headers.get("accept", ""):
        try:
            settings = settings or settings_of(request)
        except Exception:  # база недоступна – страница ошибки всё равно нужна
            settings = web_of(request).base
        return web_of(request).templates.TemplateResponse(
            request, "error.html", {"status": status_code, "message": detail, "settings": settings,
                                    "ok_message": "", "error": ""}, status_code=status_code, headers=headers)
    return JSONResponse({"detail": detail}, status_code=status_code, headers=headers)

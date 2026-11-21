"""Веб-интерфейс локального триажа: сборка приложения FastAPI.

Запуск: uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8765 (в контейнере порт опубликован только
на 127.0.0.1). Здесь – только сборка: замок папки данных, база и очередь триажа на время работы, защита запросов,
статические файлы, шаблоны, разделы интерфейса (app/routes/*) и страницы ошибок по-русски.

Защита: имя хоста – только из разрешённых (подмена DNS), POST – только со страниц этого же приложения
(Origin или Referer), предел размера тела запроса, строгая политика CSP (никаких внешних адресов и встроенных
скриптов), экранирование всего вывода, пути к репозиториям – только внутри REPOS_ROOT.
"""

from __future__ import annotations

import functools
import logging
import secrets
import re
import threading
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__, hub_ops
from app.config import Settings
from app.db import Database, DatabaseBusy
from app.storage.postgresql import MAINTENANCE_TEXT, PAGE_VIEW, CommitUnknown, MaintenanceMode
from app.feeds import FeedStore
from app.storage import local_state
from app.guard import GuardMiddleware
from app.llm_ollama import OllamaClient
from app.lockfile import InstanceLock, LockBusy, LockLost, LockUnsure
from app.logsafe import log_failure
from app.model_traffic import Recorder, set_recorder
from app.routes import (api, capec, components, cwe, examples, feeds, findings, hub, hub_bulk, hub_defect_routes, defect_card_routes,
                        hub_status_routes, hub_sync_routes, journal, projects, decision_selected, defect_add, defect_selected,
                        providers, runs, sca)
from app.routes import settings as settings_routes
from app.routes.common import (HTTP_ERRORS, METRICS_TTL_S, MODELS_TTL_S, Cached, WebState, compute_metrics,
                               compute_models, error_response)
from app.triage import TriageRunner, sync_revisions
from app.telemetry import Telemetry
from app.view import make_templates

# Прежние имена для импорта из app.main
from app.routes.projects import auto_folder, list_codebase_dirs, list_project_dirs  # noqa: F401
from app.view import fix_text, fmt_report_date, model_text  # noqa: F401

log = logging.getLogger("local_triage.web")

# Запуск не взял замок папки данных из-за свежего чужого замка (LockBusy): app/serve.py отвечает обёртке стенда npm
# отдельным кодом выхода, и она повторяет запуск, когда отметка прежнего процесса устареет (ADR-0155)
STARTUP_LOCK_BUSY = threading.Event()
# Запуск приложения (lifespan) прошёл: если после этого uvicorn не запустился, порт занят – app/serve.py отвечает своим
# кодом, и обёртка берёт следующий свободный порт
STARTUP_COMPLETE = threading.Event()

STATIC_DIR = Path(__file__).resolve().parent / "static"
BODY_OVERHEAD = 256 * 1024  # запас на служебные части multipart сверх MAX_UPLOAD_MB

_CYRILLIC = re.compile(r"[А-Яа-яЁё]")


def clear_tmp(tmp_dir: Path) -> int:
    """Удаляет копии выгрузок, оставшиеся в DATA_DIR/tmp после сбоя (процесс завершён посреди разбора). Вызывается
    сразу после замка папки данных: других разборов в этот момент нет. Возвращает, сколько файлов удалено."""
    removed = 0
    try:
        entries = list(tmp_dir.iterdir())
    except OSError:
        return 0
    for entry in entries:
        try:
            if entry.is_file() and not entry.is_symlink():
                entry.unlink()
                removed += 1
        except OSError:
            continue
    if removed:
        log.info("удалено временных файлов выгрузок после прошлого запуска: %d", removed)
    return removed


def create_app(settings: Settings | None = None,
               client_factory: Callable[[str], OllamaClient] | None = None) -> FastAPI:
    """Приложение. settings – по умолчанию из переменных окружения; client_factory – клиент Ollama по адресу."""
    settings = settings or Settings.from_env()
    make_client = client_factory or OllamaClient
    # свежие адреса компьютера-хоста от сборщика метрик: внешний профиль модели не ведёт на сам компьютер (ADR-0104)
    from app import llm_net
    from app.telemetry import host_addresses_from
    host_file = settings.data_dir / "telemetry" / "host.json"
    llm_net.HOST_SOURCE = lambda: host_addresses_from(host_file)

    def maintenance_guard() -> None:
        raise MaintenanceMode(MAINTENANCE_TEXT)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Замок папки данных – до любых записей в базу: второй экземпляр на той же папке (например, запуск без
        # Docker рядом с работающим контейнером) не стартует, а не теряет чужие записи.
        who = "текущему пользователю" if settings.stand == "npm" else "пользователю контейнера"
        no_access = (f"Нет доступа к папке данных DATA_DIR={settings.data_dir}. Проверьте, что папка существует и "
                     f"доступна на запись {who}.")
        # замок охраняет то, что осталось в папке данных: телеметрию (ADR-0133); базу охраняет замок базы
        lock = InstanceLock(settings.data_dir / "telemetry")
        try:
            (settings.data_dir / "telemetry").mkdir(parents=True, exist_ok=True)
            lock.acquire()
        except LockBusy:
            STARTUP_LOCK_BUSY.set()
            raise
        except OSError as e:
            raise RuntimeError(no_access) from e
        db: Database | None = None
        store: FeedStore | None = None
        runner: TriageRunner | None = None
        try:
            settings.tmp_dir.mkdir(parents=True, exist_ok=True)
            clear_tmp(settings.tmp_dir)
            # Журнал обмена с моделью (model_traffic): пока регистратор задан, каждое обращение к Ollama
            # записывается до отправки; сбой записи не останавливает запрос, а показывается оператору (ADR-0083).
            # MODEL_TRAFFIC_LOG=off выключает журнал целиком; без регистратора работа не меняется.
            if settings.model_traffic_log == "on":
                set_recorder(Recorder(settings.model_traffic_dir))
            else:
                set_recorder(None)
            db = Database(settings.db_path, write_guard=maintenance_guard if settings.maintenance else lock.check)
            db.read_only = settings.maintenance
            db.hub_disabled = settings.hub_disabled  # учебный стенд npm: Hub выключен на стороне сервера (ADR-0155)
            db.hold_instance()  # вторая установка на ту же базу с другой папкой данных не стартует (ADR-0128, п. 6.5)
            # Справочники уязвимостей – в своей базе: долгая загрузка не держит основную
            local_state.require_imported(db, settings.data_dir)
            store = FeedStore(db.store, write_guard=maintenance_guard if settings.maintenance else lock.check)
            if not settings.maintenance:
                # Настройки из интерфейса: переменные окружения дают им значения только при первом запуске
                db.seed_settings(settings.editable())
                # Профиль 1 (ADR-0102, П11): по действующим «Адресу Ollama» и «Модели по умолчанию» – один раз, вместе
                # с умолчаниями назначений; дальше их правка в «Настройках» меняет профиль (П23)
                seeded = settings.with_stored(db.get_settings())
                db.ensure_default_profile(seeded.ollama_url, seeded.default_model)
            mask_key = db.mask_key()
            # ключ исполнителя записи в Hub (ADR-0114): создаётся один раз, показывается в «Настройках»; испорченный
            # файл запуск не останавливает – «Настройки» покажут причину и выпустят ключ заново
            if settings.hub_disabled:  # учебный стенд npm (ADR-0155): исполнителя нет, ключ не создаётся
                from app.db import HUB_DISABLED_TEXT
                app.state.hub_worker_key_error = HUB_DISABLED_TEXT
            else:
                try:
                    app.state.hub_worker_key = hub_ops.load_or_create_worker_key(db)
                except (OSError, ValueError) as e:
                    app.state.hub_worker_key_error = str(e)
                    log_failure(log, "ключ исполнителя записи в Hub не прочитан", e)
            current = settings.with_stored(db.get_settings())
            from app import affiliation
            affiliation.configure(current.affiliation_words)  # маска принадлежности (ADR-0118) – до первого запроса
            # Клоны могли обновить или подменить, пока приложение было остановлено (git pull, другая папка
            # REPOS_ROOT с теми же именами): решения по прежнему коду не должны остаться «проверенными».
            for project in ([] if settings.maintenance else db.list_projects(archived=None)):
                try:
                    changed = sync_revisions(db, current, project)["changed"]
                    if changed:  # имена кодовых баз в журнал не пишутся: журнал пересылают при сбоях
                        log.info("проект %s: сменилась ревизия клонов у %d кодовых баз", project["id"], len(changed))
                except Exception as e:
                    log_failure(log, "ревизии клонов проекта %s не сверены", e, project["id"])
            # исследование провайдером (ADR-0105, К11): получения, шедшие в момент остановки, – «прервано», их
            # строки «отправлено» – «результат неизвестен»; повторной отправки при старте нет
            interrupted = 0 if settings.maintenance else db.interrupt_research_runs()
            if interrupted:
                log.info("исследование провайдером: прервано получений при остановке – %d", interrupted)
            runner = TriageRunner(db, settings, client_factory=make_client, mask_key=mask_key)
            if not settings.maintenance:  # обслуживание: очередь не идёт и прерванные прогоны не трогаются
                runner.start()
            from app.executors import client_for
            from app.sca_research_net import ResearchRunner
            app.state.research = ResearchRunner(
                db, lambda execution: client_for(make_client, execution, db=db))
            app.state.research_secret = secrets.token_bytes(32)  # метки предпросмотра согласия – на время работы
        except BaseException as e:  # запуск не удался: всё, что успели открыть, закрывается, замок отпускается
            try:
                if runner is not None:
                    runner.shutdown()
            finally:
                try:
                    lock.revoke()
                    if db is not None:
                        db.close()
                    if store is not None:
                        store.close()
                finally:
                    set_recorder(None)
                    lock.release()
            if isinstance(e, OSError):
                raise RuntimeError(no_access) from e
            raise
        if not settings.maintenance and not settings.hub_disabled:  # в стенде npm операций Hub нет (ADR-0155)
            from app.hub_sync import recover
            recover(db)
            from app.hub_effects import recover_chains
            recover_chains(db)  # незавершённые цепочки замены комментария (ADR-0130)
        app.state.db = db
        app.state.feeds = store
        app.state.feed_job = feeds.FeedJob()
        app.state.runner = runner
        app.state.mask_key = mask_key
        def observed_metrics():
            """Метрики профиля приложения для страниц и ресурсы каждого идущего прогона – по серверу его снимка
            исполнителя (ADR-0102): прогон с профилем проекта не получает чужих ресурсов, данные этого компьютера –
            только у профиля local."""
            from app.db import DEFAULT_PROVIDER_ID
            from app.journal import resources
            from app.routes.common import server_of
            from app.telemetry import host_snapshot
            current = settings.with_stored(db.get_settings())
            profile = db.get_provider(current.default_provider_id or DEFAULT_PROVIDER_ID) or {
                "base_url": current.ollama_url, "trust": "local"}
            key_of = server_of
            measured = {key_of(profile): compute_metrics(make_client, key_of(profile), db)}
            data = measured[key_of(profile)]
            try:
                host = host_snapshot(settings.data_dir / 'telemetry' / 'host.json')
                groups: dict = {}
                for run in db.active_runs():
                    execution = db.get_execution(run.get("execution_id")) if run["state"] == "running" else None
                    if execution is not None:
                        groups.setdefault(key_of(execution), []).append(run["id"])
                watcher = getattr(app.state, 'telemetry', None)
                # ряд истории сервера – одна точка за цикл: ряд сервера приложения пишет record, остальные – первый
                # из профилей этого сервера
                from app.telemetry import Telemetry
                pointed = {Telemetry.server_tag(key_of(profile))}

                def point_for(key) -> bool:
                    tag = Telemetry.server_tag(key)
                    fresh = tag not in pointed
                    pointed.add(tag)
                    return fresh
                # серверы, метрики которых попросили страницы (прогон на паузе, профиль проекта) – тоже измеряются
                for key in (watcher.wanted() if watcher is not None else []):
                    if key not in measured and key not in groups:
                        measured[key] = compute_metrics(make_client, key, db)
                        watcher.remember(key, measured[key], point=point_for(key))
                for key, run_ids in groups.items():
                    if key not in measured:
                        measured[key] = compute_metrics(make_client, key, db)
                        if watcher is not None:  # страница прогона берёт этот снимок, а не опрашивает сервер сама
                            # ряд истории сервера профиля приложения пишет record – здесь только снимок
                            watcher.remember(key, measured[key], point=point_for(key))
                    resources(db, measured[key], host if key[1] else {'status': 'remote'}, run_ids)
            except Exception as e:
                log_failure(log, 'Статистика ресурсов прогона не сохранена', e)
            return data
        observer = Telemetry(settings.data_dir, observed_metrics)
        app.state.telemetry = observer
        if not settings.maintenance:
            observer.start()
        STARTUP_COMPLETE.set()  # для app/serve.py: дальше запуск может сорваться только на занятом порту
        if not settings.maintenance:
            try:  # сменился корень примеров (другой -ReposRoot с той же базой) – прежние отметки снимаются (ADR-0157)
                examples.revoke_marks_on_root_change(db, settings)
            except Exception as e:  # noqa: BLE001 – не мешает запуску; отправка без отметки всё равно не пройдёт
                log_failure(log, "отметки проектов из каталога не сверены с корнем примеров", e)
            examples.start_background(settings)  # стенд npm: недостающие учебные примеры – в фоне (ADR-0156)
        try:
            yield
        finally:
            observer.close()
            try:
                if not runner.shutdown():  # поток ждёт ответа модели: результат не запишется, прогон станет «на паузе»
                    log.warning("поток триажа не завершился за отведённое время")
            finally:
                # Замок отпускается, только когда писать в базу этот экземпляр уже не может: сначала запрет записей,
                # затем закрытие базы (дожидается начатой транзакции).
                try:
                    lock.revoke()
                    db.close()
                    store.close()  # идущая загрузка справочника прервётся: временные таблицы уберёт следующий запуск
                finally:
                    set_recorder(None)
                    lock.release()

    async def internal_error_page(scope: dict, eid: str):
        """Страница необработанной ошибки: текст по-русски и номер записи в журнале (GuardMiddleware)."""
        return error_response(Request(scope), 500, f"{HTTP_ERRORS[500]} Подробности – в журнале контейнера, "
                                                   f"номер ошибки {eid}.")

    app = FastAPI(title="Локальный триаж", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    if settings.maintenance:  # добавленный позже слой – внешний: защита запросов снаружи этого
        @app.middleware("http")
        async def page_view(request: Request, call_next):
            # любая форма отклоняется сразу: запись идёт не только в основную базу (файл ключа исполнителя, справочники). Запросы
            # исполнителя (/api/hub/) отвечают сами: заданий нет, результат доставится позже
            if request.method not in ("GET", "HEAD", "OPTIONS") and not request.url.path.startswith("/api/hub/"):
                return error_response(request, 503, MAINTENANCE_TEXT, {"Retry-After": "5"}, settings=request.app.state.web.base)
            token = PAGE_VIEW.set(request.method in ("GET", "HEAD"))
            try:
                return await call_next(request)
            finally:
                PAGE_VIEW.reset(token)
    app.add_middleware(GuardMiddleware, trusted_hosts=settings.trusted_hosts,
                       max_body=settings.max_upload_bytes + BODY_OVERHEAD, on_error=internal_error_page)
    from app.timing import TimingMiddleware
    # снаружи GuardMiddleware: замер видит окончательный ответ, в том числе страницу ошибки (бэклог 123)
    app.add_middleware(TimingMiddleware)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.state.settings = settings
    app.state.hub_workers = {}  # исполнители записи в Hub: последнее обращение, кто вошёл (ADR-0114)
    app.state.web = WebState(base=settings, make_client=make_client, templates=make_templates(),
                             # база открывается при запуске (lifespan) – кэшам она передаётся функцией
                             models_cache=Cached(MODELS_TTL_S, functools.partial(
                                 compute_models, make_client,
                                 db=lambda: getattr(app.state, "db", None))),
                             metrics_cache=Cached(METRICS_TTL_S, functools.partial(
                                 compute_metrics, make_client,
                                 db=lambda: getattr(app.state, "db", None))))
    for section in (api, projects, examples, findings, runs, settings_routes, providers, sca, components, feeds, cwe, capec,
                    journal, hub, hub_status_routes, hub_sync_routes, hub_bulk, hub_defect_routes, defect_card_routes,
                    defect_selected, decision_selected, defect_add):
        app.include_router(section.router)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        detail = exc.detail if isinstance(exc.detail, str) else ""
        if not _CYRILLIC.search(detail):  # служебные английские тексты фреймворка заменяются русскими
            if detail:
                log.info("ошибка запроса %s: %s", exc.status_code, detail[:200])
            detail = HTTP_ERRORS.get(exc.status_code, "Ошибка запроса.")
        return error_response(request, exc.status_code, detail, getattr(exc, "headers", None))

    @app.exception_handler(DatabaseBusy)
    async def database_busy(request: Request, exc: DatabaseBusy):
        # база занята (запрос слишком долго ждёт соединение из пула или замок писателя) или недоступна: данные не
        # изменились; это не конфликт версии решения (409), а временный отказ с советом повторить
        log.warning("база занята: %s", type(exc).__name__)
        # настройки – без базы: иначе страница ошибки сама ждала бы занятое соединение в цикле событий
        return error_response(request, 503, str(exc), {"Retry-After": "5"}, settings=request.app.state.web.base)

    @app.exception_handler(CommitUnknown)
    async def commit_unknown(request: Request, exc: CommitUnknown):
        # соединение оборвалось на COMMIT: повторять запись нельзя, состояние нужно перечитать (ADR-0128, п. 6.4)
        log.warning("результат записи неизвестен: %s", type(exc).__name__)
        return error_response(request, 503, str(exc), settings=request.app.state.web.base)

    @app.exception_handler(LockUnsure)
    async def lock_unsure(request: Request, exc: LockUnsure):
        # файл замка папки данных на миг не прочитался: запись не выполнена, данные не изменились – повторить
        log.warning("запись отложена: владелец папки данных не установлен")
        return error_response(request, 503, str(exc), {"Retry-After": "5"})

    @app.exception_handler(LockLost)
    async def lock_lost(request: Request, exc: LockLost):
        # папку забрал другой экземпляр (или приложение останавливается): записи этого экземпляра прекращены
        log.error("запись отклонена: %s", exc)
        return error_response(request, 503, str(exc))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return error_response(request, 422, HTTP_ERRORS[422])

    @app.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception):
        # Запасной путь: ошибки запросов перехватывает GuardMiddleware (без текста исключения в журнале сервера);
        # сюда попадает только сбой самой защиты запросов
        eid = log_failure(log, "необработанная ошибка вне разделов", exc)
        return error_response(request, 500, f"{HTTP_ERRORS[500]} Подробности – в журнале контейнера, номер ошибки "
                                            f"{eid}.")

    return app

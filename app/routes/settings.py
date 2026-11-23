"""Раздел «Настройки»: адрес Ollama и его проверка, модель по умолчанию, статусы Hub по вердиктам, порог
срочности SCA, что видно приложению (корень папок с репозиториями). Плюс GET /api/ollama – что видит приложение
по действующему адресу Ollama (его спрашивает start.ps1 после запуска).

Настройки хранятся в базе (app/settings_store.py); переменные окружения дают им только начальные значения
при первом запуске. Шаблон – templates/settings/index.html. Страница работает без скриптов: «Проверить»
и «Сохранить» – кнопки одной формы, проверка показывает введённый, ещё не сохранённый адрес.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool

from app import i18n
from app.config import DEFAULT_STATUS_MAP, ConfigError, normalize_setting
from app.routes.hub import hub_context
from app.routes.common import (db_of, models_of, profile_for, redirect, register_messages, render, settings_of,
                               web_of)
from app.settings_store import (STATUS_FIELDS, check_ollama, environment, form_values,
                                model_found, ollama_report, read_form, save)

router = APIRouter()
log = logging.getLogger(__name__)

MAX_FIELDS = 30  # полей в форме настроек

register_messages({
    "language_saved": "Язык интерфейса сохранён.",
    "settings_saved": "Настройки сохранены.",
    "settings_reordered": "Настройки сохранены. Порог срочности SCA изменился – порядок разбора находок "
                          "во всех проектах пересчитан.",
})


def page(request: Request, values: dict, errors: dict | None = None, check: dict | None = None,
         error: str = "", status_code: int = 200) -> HTMLResponse:
    """Страница настроек. values – значения полей; check – состояние Ollama: результат кнопки «Проверить» или,
    если её не нажимали, состояние по сохранённому адресу (из кэша списка моделей)."""
    settings = settings_of(request)
    from app.db import DEFAULT_PROVIDER_ID

    base_profile = db_of(request).get_provider(DEFAULT_PROVIDER_ID)
    default_profile = profile_for(request)
    if check is None:
        # блок «Ollama» – профиль 1, даже когда профилем по умолчанию выбран другой (например DeepSeek)
        state = models_of(request, profile=base_profile) if base_profile else models_of(request)
        check = {"url": settings.ollama_url, "version": state["version"], "models": state["models"],
                 "error": state["error"], "checked": False}
    models = check["models"]
    context = {
        "values": values, "errors": errors or {}, "check": check, "models": models,
        "default_profile_name": str(default_profile.get("name") or ""),
        "default_is_base": default_profile.get("id") == DEFAULT_PROVIDER_ID,
        "model_listed": model_found(values.get("default_model", ""), models),
        "status_fields": STATUS_FIELDS, "default_statuses": DEFAULT_STATUS_MAP,
        "env": environment(settings), "error": error,
        "traffic_log_on": settings.model_traffic_log == "on",  # ADR-0083: предупреждение у выбора модели
        "hub": hub_context(request),  # ADR-0114: ключ исполнителя, его состояние, проверка связи
    }
    return render(request, "settings/index.html", context, status_code)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    return page(request, form_values(settings_of(request)))


@router.post("/settings/language")
async def save_language(request: Request):
    """Язык интерфейса (ADR-0158): английский или русский. Сохраняется в базе (ключ ui_language) и сразу действует
    во всём приложении; данные, решения и кэш вердиктов не меняются."""
    form = await request.form(max_fields=4, max_files=0)
    lang = i18n.normalize(form.get("lang"))

    def apply():
        if lang is None:
            return page(request, form_values(settings_of(request)), status_code=400,
                        error=i18n._("Язык не сохранён: выберите English или Русский."))
        db_of(request).set_settings({i18n.SETTING_KEY: lang})
        i18n.set_saved(lang)
        return redirect("/settings?ok=language_saved#language")

    return await run_in_threadpool(apply)


@router.post("/settings")
async def save_settings(request: Request):
    form = await request.form(max_fields=MAX_FIELDS, max_files=0)
    action = str(form.get("action") or "save")

    def apply():
        parsed = read_form(form)
        if action == "check":
            # Проверяется введённый адрес, а не сохранённый: сохранять его до проверки не нужно
            url_error = parsed.errors.get("ollama_url", "")
            check = None
            if not url_error:
                check = {**check_ollama(web_of(request).make_client, parsed.clean["ollama_url"]), "checked": True}
            return page(request, parsed.values, {"ollama_url": url_error} if url_error else {},
                        check or {"url": parsed.values["ollama_url"], "version": "", "models": [], "error": "",
                                  "checked": False})
        if parsed.errors:
            return page(request, parsed.values, parsed.errors,
                        error=i18n._("Настройки не сохранены: исправьте отмеченные поля."), status_code=400)
        settings, db = settings_of(request), db_of(request)
        new_hub = parsed.clean.get("hub_url")
        # адрес Hub пишет только операция смены назначения (п. 4.5 плана dev17): совпадение с действующим адресом и
        # последствия она определяет в своей транзакции (ревью Codex шага 4, круг 2); остальные настройки – как обычно
        clean = {k: v for k, v in parsed.clean.items() if k != "hub_url"}
        env_url = web_of(request).base.hub_url
        try:
            from app.sca_research_net import composition_change
            with composition_change():  # настройки отбора компонентов – часть состава заданий на исследование
                result = save(db, settings, clean)
        except TimeoutError:  # профиль 1 занят отправкой запросов дольше срока ожидания (app/profile_gate.py)
            return page(request, parsed.values, {}, status_code=503,
                        error=i18n._("Настройки не сохранены: запросы к серверу модели по адресу Ollama отправляются "
                                     "дольше обычного. Повторите сохранение через минуту."))
        if new_hub is not None:
            preview = db.change_hub_url(new_hub, dry=True, env_url=env_url)
            if preview.get("affects"):  # что-то меняет – сначала подтверждение с итогом по проектам
                return hub_url_page(request, settings.hub_url, new_hub, preview)
            try:  # без последствий – сразу, но по отпечатку расчёта: изменилось между ними – подтверждение
                db.change_hub_url(new_hub, expect=preview.get("token"), env_url=env_url)
            except ValueError:
                return hub_url_page(request, settings.hub_url, new_hub,
                                    db.change_hub_url(new_hub, dry=True, env_url=env_url))
        return redirect("/settings?ok=" + ("settings_reordered" if result["reordered"] else "settings_saved"))

    return await run_in_threadpool(apply)


def hub_url_page(request: Request, old_url: str, new_url: str, preview: dict, error: str = "",
                 status_code: int = 200) -> HTMLResponse:
    """Подтверждение смены адреса Hub (план dev17, п. 4.5): по каждому затронутому проекту – сколько сведений Hub о
    библиотеках сбрасывается и решений из Hub уходит в историю. Итог считается в откатываемой транзакции."""
    db = db_of(request)
    rows = []
    for pid, summary in sorted((preview.get("projects") or {}).items()):
        if summary.get("identity_cleared") or summary.get("hub_decisions_withdrawn") or summary.get("findings"):
            project = db.get_project(int(pid)) or {}
            from app.package_transition import entity_rows
            rows.append({"name": project.get("name") or i18n._("Проект {id}", id=pid), "summary": summary,
                         "entities": entity_rows(summary)})
    from app.package_transition import TABLE_LABELS
    return render(request, "settings/hub_url.html", {"old_url": old_url, "new_url": new_url, "rows": rows,
                                                     "table_labels": TABLE_LABELS,
                                                     "token": preview.get("token", ""), "error": error},
                  status_code)


@router.post("/settings/hub-url")
async def hub_url_apply(request: Request):
    """Смена адреса Hub по подтверждению: отпечаток входов страницы подтверждения сверяется в той же транзакции;
    изменилось что-либо – страница подтверждения заново с новым итогом, ничего не записано."""
    form = await request.form(max_fields=4, max_files=0)
    raw = str(form.get("url") or "")
    token = str(form.get("token") or "")

    def apply():
        settings, db = settings_of(request), db_of(request)
        try:
            url = normalize_setting("hub_url", raw)
        except ConfigError as e:
            return page(request, form_values(settings), {"hub_url": str(e)}, status_code=400,
                        error=i18n._("Адрес Hub не сменён: исправьте адрес."))
        env_url = web_of(request).base.hub_url
        try:
            db.change_hub_url(url, expect=token, env_url=env_url)
        except ValueError as e:
            again = db.change_hub_url(url, dry=True, env_url=env_url)
            if again.get("unchanged"):  # адрес уже такой – сброса данных действующего адреса нет
                return redirect("/settings?ok=settings_saved")
            return hub_url_page(request, settings.hub_url, url, again, str(e), 409)
        log.info("адрес Hub сменён (план dev17, п. 4.5)")
        return redirect("/settings?ok=settings_saved")

    return await run_in_threadpool(apply)


@router.get("/api/ollama")
def api_ollama(request: Request) -> dict:
    """Что видит приложение по действующему адресу Ollama: {url, version, models, default_model,
    default_model_found, error}. Список моделей запрашивается заново (и обновляет кэш страниц)."""
    profile = profile_for(request)  # один профиль для моделей и подписи: умолчание могут сменить между вызовами
    return ollama_report(settings_of(request), models_of(request, fresh=True, profile=profile), profile)

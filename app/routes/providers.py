"""Раздел «Настройки → Провайдеры моделей» (ADR-0102, 0.9.12): профили серверов моделей.

Список профилей и форма профиля: название, протокол (Ollama, API чат-завершений – 0.9.13, Anthropic Messages API –
0.9.14), где работает модель
(этот компьютер, сервер в сети организации или внешний провайдер в интернете – только при LLM_EXTERNAL=1), адрес,
модель, окно контекста, рассуждение, пределы и сроки ответа, ключ сервера в сети, подтверждение адресов, умолчание для
разбора кода, включён ли профиль. Профилей может быть сколько угодно – сохранение одного не трогает другие.
«Проверить» – версия и модели сервера по введённым значениям (у сервера в сети – после подтверждения
адресов, в которые разрешилось имя); «Пробный ответ» – короткая генерация сохранённым профилем под общим правом на
генерацию. Профиль 1 – «Адрес Ollama» и «Модель по умолчанию» страницы «Настройки» (П23): адрес, модель и класс
правятся там, здесь – остальное. Страница работает без скриптов.
"""

from __future__ import annotations

import json
import logging
import secrets
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool

from app import model_traffic
from app.db import DEFAULT_PROVIDER_ID
from app.executors import (CHAT_TIMEOUT_S, REMOTE_KINDS, ProbeBusy, apply_chat, chat_settings, generation,
                           new_client, probe_generation, same_model, server_of, service_client)
from app.llm_net import external_enabled
from app.llm import LlmError, outcome_unknown
from app.provider_keys import PendingKeys, key_headers, key_hint, load_key
from app import profile_gate
from app.providers import (CHAT_NUMBERS, EFFORT_LABELS, KEY_DISABLED, KIND_LABELS, MESSAGES_RESPONSE_LABELS,
                           NUMBER_FIELDS, RESPONSE_LABELS, THINK_LABELS, THINKING_LABELS, TRUST_LABELS, WHERE,
                           ProfileInvalid, confirmed_of, form_of, local_hosts_hint, read_form, resolve_addresses,
                           save_profile)
from app.routes.common import db_of, redirect, register_messages, render, settings_of, web_of

from app.providers import ADVANCED_HINTS, DEEPSEEK_RECOMMENDED, PRESETS, preset_form  # noqa: E402

router = APIRouter()
log = logging.getLogger(__name__)

MAX_FIELDS = 60
NO_KEY = ("Введите ключ: отмечено «Сервер требует ключ», а ключа нет ни в поле, ни в сохранённых для этого адреса – "
          "без ключа сервер ответит отказом. Запрос не отправлен.")


def pending_of(request: Request) -> PendingKeys:
    """Ключи из форм до «Сохранить» – в памяти этого процесса (provider_keys.PendingKeys)."""
    state = request.app.state
    if getattr(state, "pending_keys", None) is None:
        state.pending_keys = PendingKeys()
    return state.pending_keys

register_messages({
    "provider_saved": "Профиль сохранён.",
    "provider_key_dropped": "Профиль сохранён. Адрес сервера или подтверждённые адреса изменились – прежний ключ "
                            "удалён: введите ключ заново.",
})


def profile_row(profile: dict, default_id: int, db: Any) -> dict:
    """Строка списка профилей: класс словами, ключ – только «задан, …последние 4 знака»."""
    return {**profile, "where": WHERE.get(str(profile["trust"]), str(profile["trust"])),
            "protocol": KIND_LABELS.get(str(profile.get("kind") or "ollama"), str(profile.get("kind"))),
            "default_code": profile["id"] == default_id, "key": key_hint(db, profile["id"]),
            "confirmed": confirmed_of(profile)}


@router.get("/settings/providers", response_class=HTMLResponse)
def providers_list(request: Request):
    db, settings = db_of(request), settings_of(request)
    db.ensure_default_profile(settings.ollama_url, settings.default_model)
    default_id = settings.default_provider_id or DEFAULT_PROVIDER_ID
    rows = [profile_row(p, default_id, db) for p in db.list_providers()]
    return render(request, "settings/providers.html", {"profiles": rows})


def form_page(request: Request, profile: dict | None, values: dict, errors: dict | None = None,
              check: dict | None = None, notice: str = "", error: str = "", status_code: int = 200) -> HTMLResponse:
    settings = settings_of(request)
    pid = profile["id"] if profile else None
    context = {
        "profile": profile, "values": values, "errors": errors or {}, "check": check or {}, "notice": notice,
        "error": error, "fixed": pid == DEFAULT_PROVIDER_ID, "trust_labels": TRUST_LABELS,
        "think_labels": THINK_LABELS, "number_fields": NUMBER_FIELDS, "app_num_ctx": settings.num_ctx,
        "kind_labels": KIND_LABELS, "response_labels": RESPONSE_LABELS,
        "messages_response_labels": MESSAGES_RESPONSE_LABELS, "thinking_labels": THINKING_LABELS,
        "effort_labels": EFFORT_LABELS, "chat_numbers": CHAT_NUMBERS, "external_on": external_enabled(),
        "advanced_hints": ADVANCED_HINTS, "deepseek_recommended": DEEPSEEK_RECOMMENDED,
        "key": key_hint(db_of(request), pid) if pid else "", "local_hosts": local_hosts_hint(),
        "action": f"/settings/providers/{pid}" if pid else "/settings/providers/new",
    }
    return render(request, "settings/provider.html", context, status_code)


def profile_or_404(request: Request, pid: int) -> dict:
    profile = db_of(request).get_provider(pid)
    if profile is None:
        raise HTTPException(status_code=404, detail="Профиль не найден.")
    return profile


@router.get("/settings/providers/new", response_class=HTMLResponse)
def provider_new(request: Request):
    """Новый профиль; ?preset=deepseek или ?preset=ollama-local – предзаполненная заготовка (ADR-0157)."""
    name = request.query_params.get("preset", "")
    values = preset_form(name)
    if values is None:
        return form_page(request, None, form_of(None))
    notice = ("Заготовка DeepSeek: вставьте свой ключ API, нажмите «Проверить», затем «Сохранить». Без ключа профиль "
              "ничего не отправляет. Данные обрабатываются провайдером в КНР; поставьте лимит расхода ключа в кабинете "
              "провайдера." if name == "deepseek" else
              "Заготовка Ollama на этом компьютере: нажмите «Проверить» – если модели нет, выполните "
              "ollama pull gpt-oss:20b и проверьте снова." if name in PRESETS else "")
    if name == "ollama-local" and settings_of(request).stand != "npm":
        # Docker-установка: Ollama этого компьютера – по адресу из настроек (обычно host.docker.internal), а не
        # 127.0.0.1 контейнера приложения
        values = {**values, "base_url": settings_of(request).ollama_url}
    return form_page(request, None, {**values, "preset": name, "examples_profile": "1"}, notice=notice)


@router.get("/settings/providers/{pid}", response_class=HTMLResponse)
def provider_edit(request: Request, pid: int):
    profile = profile_or_404(request, pid)
    settings = settings_of(request)
    return form_page(request, profile, form_of(profile, settings.default_provider_id or DEFAULT_PROVIDER_ID))


def run_check(request: Request, profile: dict | None, values: dict, key: str, use_saved: bool = True) -> dict:
    """«Проверить» по введённым значениям: у сервера в сети – сначала адреса имени (без запросов к серверу); когда
    все они частные и отмечены как подтверждённые – версия и модели сервера по этим адресам (с введённым ключом или
    сохранённым, если он привязан к этим же адресам)."""
    keyed = values["trust"] in ("lan", "external")  # ключ – у сервера в сети и внешнего провайдера
    check: dict[str, Any] = {"checked": True, "addresses": [], "version": "", "models": [], "error": "",
                             "key_entered": keyed and bool(key), "kind": values["kind"]}  # поле ключа вернётся пустым
    try:
        if values["trust"] == "lan":
            check["addresses"] = resolve_addresses(values["base_url"], "lan", values["kind"])
            public = [a["address"] for a in check["addresses"] if not a["private"]]
            if public:
                check["error"] = (f"Имя сервера разрешается в адрес {', '.join(public)} – это не частная сеть: сервер "
                                  "в сети организации должен иметь частный адрес (10.x, 172.16–31.x, 192.168.x, "
                                  "fc00::/7).")
                return check
            if not check["addresses"]:
                check["error"] = "Имя сервера не разрешилось ни в один адрес IPv4 или IPv6: проверьте адрес."
                return check
            confirmed = set(values["confirmed"])
            if not all(a["address"] in confirmed for a in check["addresses"]):
                check["need_confirm"] = True  # запросов к серверу не было: сначала подтверждение адресов
                return check
        pid = profile["id"] if profile else None
        if keyed and values.get("requires_key") and use_saved and not key:
            saved = load_key(db_of(request), pid) if pid is not None else None
            bound = bool(saved) and saved["base_url"] == str(values["base_url"]).rstrip("/") and (
                values["trust"] != "lan" or set(saved["addresses"]) == set(values["confirmed"]))
            if not bound:  # иначе проверка без ключа уходила бы провайдеру и получала 401
                check["error"] = NO_KEY
                return check
        client = new_client(web_of(request).make_client, values["kind"], values["base_url"])
        client.trust = values["trust"]
        client.confirmed = tuple(values["confirmed"])
        wanted = str(values.get("default_model") or "").strip()
        if hasattr(client, "fallback_model"):  # Messages API: /models недоступен – имя модели из формы (п. 2.7)
            client.fallback_model = wanted
        if keyed and key:
            client.auth = lambda: key_headers(values["kind"], key)  # введённый ключ – только для этой проверки
            check["key_used"] = True
        elif keyed and pid is not None and use_saved:
            # сохранённый ключ – под блокировкой профиля, только у включённого профиля и только при привязке к этим
            # же адресам: читается и проверяется на каждый запрос, правка профиля между проверкой и отправкой его не
            # подменит
            base, addresses, db = values["base_url"], set(values["confirmed"]), db_of(request)

            def saved_auth() -> dict[str, str]:
                now = db.get_provider(pid)
                entry = load_key(db, pid) if now and now.get("enabled") and values["enabled"] else None
                if entry and entry["base_url"] == str(base).rstrip("/") and set(entry["addresses"]) == addresses:
                    return key_headers(values["kind"], entry["key"])
                return {}

            client.auth = saved_auth
            client.gate = profile_gate.gate(pid).read
        with model_traffic.context(purpose="version"):
            check["version"] = client.version()
        with model_traffic.context(purpose="models"):
            check["models"] = client.list_models()
        check["models_unavailable"] = bool(getattr(client, "models_unavailable", False))
        name_of = same_model(values["kind"])  # удалённые API – точное имя, Ollama – без регистра и «:latest»
        match = next((m["name"] for m in check["models"] if wanted and name_of(m["name"]) == name_of(wanted)), "")
        check["selected"] = match  # пункт списка, который выбирается (у Ollama «m» – это «m:latest»)
        if wanted and not match:
            check["model_missing"] = wanted  # выбор оператора сохраняется, но в списке сервера его нет
    except LlmError as e:
        check["error"] = str(e)
        # сбой «Проверить» – и в журнал приложения (без ключа: тексты ошибок клиента ключа не содержат)
        log.info("проверка профиля провайдера не прошла: профиль %s, протокол %s, класс %s: %s",
                 profile["id"] if profile else "новый", values["kind"], values["trust"], e)
    return check


@router.post("/settings/providers/new")
async def provider_create(request: Request):
    return await provider_post(request, None)


@router.post("/settings/providers/{pid}")
async def provider_update(request: Request, pid: int):
    return await provider_post(request, pid)


async def provider_post(request: Request, pid: int | None):
    form = await request.form(max_fields=MAX_FIELDS, max_files=0)
    action = str(form.get("action") or "save")

    def apply():
        db, settings = db_of(request), settings_of(request)
        profile = profile_or_404(request, pid) if pid is not None else None
        fixed = pid == DEFAULT_PROVIDER_ID
        parsed = read_form(form, profile, fixed=fixed)
        if pid is None and str(form.get("preset") or "") in PRESETS:
            parsed.values["preset"] = str(form.get("preset"))
            parsed.values["examples_profile"] = "1" if form.get("examples_profile") == "1" else "0"
        pending, base = pending_of(request), str(parsed.values.get("base_url") or "")
        handle = str(form.get("key_handle") or "")[:64]
        # владелец метки: профиль или черновик нового профиля (случайная метка в скрытом поле, чтобы метка одного
        # черновика не выдала ключ другому); привязка – как у сохранённого ключа: адрес и подтверждённые адреса
        draft = str(form.get("key_draft") or "")[:64] if pid is None else ""
        if pid is None and not draft:
            draft = secrets.token_urlsafe(18)
        owner = f"profile:{pid}" if pid is not None else f"draft:{draft}"
        bound = parsed.values["confirmed"] if parsed.values["trust"] == "lan" else ()
        wants_key = parsed.values["requires_key"] and not parsed.delete_key
        # страница ключ не показывает: годный введённый ключ запоминается в памяти до «Сохранить» по метке формы
        # – вводить его второй раз не нужно, пока адрес и подтверждённые адреса те же
        entered: dict[str, Any] = {"key_entered": bool(str(form.get("key") or "").strip()), "key_draft": draft}
        if handle and not wants_key:  # «Сервер требует ключ» снято или «Удалить ключ» – ключ из памяти забывается
            pending.forget(handle, owner)
            handle = ""
        if parsed.key and "key" not in parsed.errors and not fixed and wants_key:
            entered["key_handle"] = handle = pending.remember(parsed.key, owner, base, bound, previous=handle)
        elif handle and pending.peek(handle, owner, base, bound):
            entered["key_handle"] = handle
            entered["key_pending"] = True
        else:
            handle = ""

        def persist():
            """Сохранение формы; (профиль, прежний ключ удалён) или ответ с ошибкой."""
            if parsed.errors:
                return form_page(request, profile, parsed.values, parsed.errors, entered,
                                 error="Профиль не сохранён: исправьте отмеченные поля.", status_code=400)
            claimed = bool(handle) and not parsed.key
            key = parsed.key or (pending.claim(handle, owner, base, bound) if handle else "")
            if claimed and not key:  # метку уже сохраняет другой запрос или она истекла – ключ вводится заново
                return form_page(request, profile, parsed.values, {"key": "Введите ключ ещё раз."},
                                 {**entered, "key_handle": ""}, error="Профиль не сохранён: ключ не найден в памяти.",
                                 status_code=400)
            written = {"key": False}
            try:
                result = save_profile(db, pid, parsed.clean, key=key, requires_key=wants_key,
                                      make_default=parsed.default_code,
                                      key_written=lambda: written.update(key=True))
            except BaseException as e:
                # ключ уже на диске – метка гасится; записи ключа не было – метка возвращается, ключ остаётся в
                # памяти (ревью A8, круг 3: сбой бывает и после записи ключа, и не только ProfileInvalid)
                if claimed:
                    (pending.forget if written["key"] else pending.release)(handle, owner)
                if not isinstance(e, ProfileInvalid):
                    raise
                field = ({"enabled": str(e)} if "не выключается" in str(e) else
                         {"key": str(e)} if str(e) == KEY_DISABLED else {})
                return form_page(request, profile, parsed.values, field, entered, error=str(e), status_code=400)
            if handle:
                pending.forget(handle, owner)  # сохранено файлом – ключ в памяти больше не нужен
            return result

        if action == "check":
            blocking = {k: v for k, v in parsed.errors.items() if k in ("base_url", "trust", "key")}
            if blocking:  # ошибки полей, по которым идёт запрос: ключ с ошибкой не отправляется
                return form_page(request, profile, parsed.values, blocking, entered)
            # «Сервер требует ключ» снято или «Удалить ключ»: проверка без ключа – ни введённого, ни из памяти, ни
            # сохранённого (ревью A8, круг 2)
            key = (parsed.key or (pending.peek(handle, owner, base, bound) if handle else "")) if wants_key else ""
            return form_page(request, profile, parsed.values, {},
                             {**run_check(request, profile, parsed.values, key, use_saved=wants_key), **entered,
                              "key_used": bool(key) and parsed.values["trust"] in ("lan", "external")})
        if action in ("probe", "search_check") and profile is not None and not fixed:
            # кнопки работают с сохранённым профилем: сначала – сохранение формы (иначе поля
            # заполнены, а проверка шла бы по прежнему профилю)
            saved = persist()
            if not isinstance(saved, tuple):
                return saved
            profile = profile_or_404(request, pid)
            entered = {"saved_first": True, "key_dropped": saved[1]}
            parsed.values = form_of(profile, settings.default_provider_id or DEFAULT_PROVIDER_ID)
        if action == "probe":
            if profile is None:
                return form_page(request, None, parsed.values, check=entered, error="Сначала сохраните профиль.",
                                 status_code=400)
            model = str(profile.get("default_model") or "")
            if not model:
                return form_page(request, profile, parsed.values, check=entered, error="У профиля не выбрана модель.",
                                 status_code=400)
            client = apply_chat(service_client(web_of(request).make_client, server_of(profile), db),
                                chat_settings(profile))
            if str(profile.get("kind") or "ollama") != "ollama":
                # срок одного обращения – как у разбора по этому профилю (ревью круг 16): проба проверяет его настройки
                client.timeout = float(generation(profile).get("timeout_s") or CHAT_TIMEOUT_S)
            try:
                seconds = probe_generation(client, model)
            except (ProbeBusy, LlmError) as e:
                record_check(db, profile, "probe", False)
                # общий классификатор (ревью круг 15, находка 2): известная причина (обрыв по длине, фильтр, отказ)
                # – не «результат неизвестен»
                unknown = str(profile.get("trust")) == "external" and outcome_unknown(e)
                return form_page(request, profile, parsed.values, check=entered,
                                 error=f"Пробный ответ не получен: {e}" + (
                                     " Результат неизвестен: запрос мог быть принят и оплачен – повторять ли, решите "
                                     "сами." if unknown else ""))
            record_check(db, profile, "probe", True)
            return form_page(request, profile, parsed.values, check=entered,
                             notice=f"Модель {model} ответила за {seconds:.1f} с.".replace(".", ",", 1))
        if action == "search_check":
            return search_check(request, profile, parsed.values, entered)
        saved = persist()
        if not isinstance(saved, tuple):
            return saved
        ok = "provider_key_dropped" if saved[1] else "provider_saved"
        if pid is None and str(form.get("preset") or "") in PRESETS:
            # заготовка из «Начала работы»: по отметке – сразу профиль для примеров (план стенда, раздел 6); затем
            # страница созданного профиля – там «Сохранить и пробный ответ» и «Проверить поиск» (раздел 5)
            if form.get("examples_profile") == "1" and saved[0].get("enabled"):
                db.set_settings({"examples_provider_id": int(saved[0]["id"])})
            return redirect(f"/settings/providers/{saved[0]['id']}?ok={ok}")
        return redirect("/settings/providers?ok=" + ok)

    return await run_in_threadpool(apply)


CHECKS_KEY = "provider_checks"  # итоги «пробного ответа» и «проверки поиска» для панели «Начало работы»


def record_check(db, profile: dict | None, kind: str, ok: bool) -> None:
    """Итог проверки профиля (probe – пробный ответ, search – поиск) вместе с версией профиля: после правки профиля
    итог считается устаревшим (план стенда, раздел 5)."""
    if not profile:
        return
    from app.db import now_iso

    current = db.get_settings().get(CHECKS_KEY)
    entry = (current or {}).get(str(profile["id"])) if isinstance(current, dict) else None
    entry = dict(entry) if isinstance(entry, dict) else {}
    entry[kind] = {"ok": bool(ok), "at": now_iso(), "version": int(profile.get("version") or 0),
                   "key": key_print(db, profile["id"])}
    db.update_json_entry(CHECKS_KEY, str(profile["id"]), entry)


def key_print(db, provider_id: int) -> str:
    """Отпечаток сохранённого ключа (SHA-256, 16 знаков) – не сам ключ: замена ключа на любой другой меняет его."""
    import hashlib

    entry = load_key(db, provider_id)
    return hashlib.sha256(str(entry["key"]).encode("utf-8")).hexdigest()[:16] if entry else ""


def check_state(db, profile: dict, kind: str) -> str:
    """passed, failed или none (не проверялся или профиль менялся после проверки)."""
    current = db.get_settings().get(CHECKS_KEY)
    entry = ((current or {}).get(str(profile["id"])) or {}).get(kind) if isinstance(current, dict) else None
    if not isinstance(entry, dict) or int(entry.get("version") or 0) != int(profile.get("version") or 0):
        return "none"
    if entry.get("key", "") != key_print(db, profile["id"]):
        return "none"  # ключ заменён или удалён после проверки
    return "passed" if entry.get("ok") else "failed"


def search_check(request: Request, profile: dict | None, values: dict, entered: dict) -> HTMLResponse:
    """«Проверить поиск»: один запрос к поисковому API сохранённого профиля (расходует запрос у провайдера)."""
    db = db_of(request)
    caps: Any = {}
    if profile:
        try:
            caps = json.loads(str(profile.get("capabilities_json") or "{}"))
        except ValueError:
            caps = {}
    search = caps.get("search") if isinstance(caps, dict) else None
    if not profile or str(profile.get("kind")) not in REMOTE_KINDS or not isinstance(search, dict):
        return form_page(request, profile, values, check=entered, status_code=400,
                         error="Поиск не настроен: сохраните профиль удалённого API (чат-завершения или Messages) с "
                               "путями поиска.")
    client = service_client(web_of(request).make_client, server_of(profile), db)
    try:
        with model_traffic.context(purpose="search_check"):
            data = client.search(str(search.get("search_path") or ""), "OpenSSL security advisory", 1)
    except LlmError as e:
        record_check(db_of(request), profile, "search", False)
        return form_page(request, profile, values, check=entered, error=f"Поиск не ответил: {e}")
    found = next((len(v) for v in data.values() if isinstance(v, list)), 0) if isinstance(data, dict) else 0
    record_check(db_of(request), profile, "search", True)
    return form_page(request, profile, values, check=entered,
                     notice=f"Поиск ответил: результатов – {found}.")

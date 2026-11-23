"""Настройки из интерфейса: форма страницы «Настройки» (разбор и проверка), сохранение, состояние Ollama и то,
что видно приложению (корень папок с репозиториями, папка данных).

Значения хранятся в базе (таблица settings: Database.get_settings, set_settings). Переменные окружения дают им
только начальные значения при первом запуске (Database.seed_settings в main.py); действующие настройки –
Settings.with_stored(значения из базы), см. routes.common.settings_of.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app import i18n, model_traffic
from app.config import DEFAULT_STATUS_MAP, EDITABLE_SETTINGS, MAX_STATUS, ConfigError, Settings, normalize_setting
from app.db import Database
from app.llm import LlmError, norm_model_name
from app.llm_net import in_container
from app.llm_ollama import OllamaClient
from app.triage import reorder_project

# Поля статусов Hub в форме: (итог разбора, имя поля, подпись – msgid, перевод при выводе)
STATUS_FIELDS = (
    ("true_positive", "status_true_positive", i18n.N_("истинная")),
    ("false_positive", "status_false_positive", i18n.N_("ложная")),
    ("uncertain", "status_uncertain", i18n.N_("неясно")),
    ("risk_accepted", "status_risk_accepted", i18n.N_("риск принят")),
)
FORM_FIELDS = ("ollama_url", "default_model", *(name for _, name, _ in STATUS_FIELDS), "sca_urgent_cvss",
               "team_name", "sca_internal_prefixes", "hub_url", "affiliation_words")
MAX_FIELD = 1000  # знаков в поле формы: длиннее не бывает ни адреса, ни модели, ни статуса
MAX_WORDS_FIELD = 12000  # поле «Слова принадлежности»: 200 слов по 50 букв с «*» и разделителями (ADR-0118)
MAX_LISTED = 2000  # сколько папок корня считать для сведений на странице

_DRIVE_ONLY = re.compile(r"[A-Za-z]:")
# где работает модель профиля – подпись для /api/ollama (start.ps1 печатает её как есть)
WHERE_LABELS = i18n.Labels({"local": "этот компьютер", "lan": "сеть организации", "external": "интернет"})


# ============================================================================ форма

@dataclass
class SettingsForm:
    """Разобранная форма: values – что ввёл человек (для повторного показа), clean – проверенные значения
    для базы (ключи EDITABLE_SETTINGS), errors – {поле формы: текст ошибки}."""

    values: dict[str, str]
    clean: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


def fmt_cvss(value: Any) -> str:
    """Порог CVSS для поля формы: 9.0 -> «9,0»."""
    try:
        return f"{float(value):.1f}".replace(".", ",")
    except (TypeError, ValueError):
        return str(value or "")


def form_values(settings: Settings) -> dict[str, str]:
    """Значения полей формы из действующих настроек."""
    values = {"ollama_url": settings.ollama_url, "default_model": settings.default_model,
              "sca_urgent_cvss": fmt_cvss(settings.sca_urgent_cvss), "team_name": settings.team_name,
              "sca_internal_prefixes": ", ".join(settings.sca_internal_prefixes), "hub_url": settings.hub_url,
              "affiliation_words": ", ".join(settings.affiliation_words)}
    for verdict, name, _ in STATUS_FIELDS:
        values[name] = settings.hub_status_map.get(verdict, DEFAULT_STATUS_MAP[verdict])
    return values


def check_ollama_url(value: str) -> str:
    """Адрес Ollama из формы -> адрес для базы; ConfigError с понятным текстом. Кроме вида адреса проверяется
    и хост: адрес, на который приложение не отправит ни одного запроса (чужой хост), не сохраняется. Сеть
    не нужна – куда указывает имя, клиент Ollama проверяет при каждом запросе."""
    url = normalize_setting("ollama_url", value)
    try:
        OllamaClient(url).check_url()
    except LlmError as e:
        from app.run_errors import shown_error
        raise ConfigError(shown_error(str(e))) from None
    return url


def read_form(form: Mapping[str, Any]) -> SettingsForm:
    """Форма страницы «Настройки» -> SettingsForm. Пустой статус Hub – ошибка: текст для Hub без статуса
    вставлять бессмысленно (значение по умолчанию подсказано рядом с полем)."""
    values = {name: " ".join(str(form.get(name) or "").split())[:MAX_FIELD] for name in FORM_FIELDS}
    values["ollama_url"] = str(form.get("ollama_url") or "").strip()[:MAX_FIELD]
    # список слов длиннее обычного поля: свой предел, превышение – ошибка, а не молчаливое усечение
    words_text = " ".join(str(form.get("affiliation_words") or "").split())
    values["affiliation_words"] = words_text[:MAX_WORDS_FIELD]
    result = SettingsForm(values=values)
    if len(words_text) > MAX_WORDS_FIELD:
        result.errors["affiliation_words"] = i18n._("Слова принадлежности: не больше {limit} знаков",
                                                     limit=MAX_WORDS_FIELD)
    try:
        result.clean["ollama_url"] = check_ollama_url(values["ollama_url"])
    except ConfigError as e:
        result.errors["ollama_url"] = str(e)
    try:
        model = normalize_setting("default_model", values["default_model"])
        if not model:
            raise ConfigError(i18n._("Модель по умолчанию: выберите модель из списка или впишите её имя"))
        result.clean["default_model"] = model
    except ConfigError as e:
        result.errors["default_model"] = str(e)
    statuses = {}
    for verdict, name, label in STATUS_FIELDS:
        text = values[name]
        if not text:
            result.errors[name] = i18n._("Укажите статус Hub для вердикта «{verdict}»", verdict=i18n._(label))
        elif len(text) > MAX_STATUS:
            result.errors[name] = i18n._("Статус Hub – до {limit} знаков", limit=MAX_STATUS)
        else:
            statuses[verdict] = text
    if len(statuses) == len(STATUS_FIELDS):
        try:
            result.clean["hub_status_map"] = normalize_setting("hub_status_map", statuses)
        except ConfigError as e:
            result.errors[STATUS_FIELDS[0][1]] = str(e)
    try:
        result.clean["sca_urgent_cvss"] = normalize_setting("sca_urgent_cvss", values["sca_urgent_cvss"])
    except ConfigError as e:
        result.errors["sca_urgent_cvss"] = str(e)
    for name in ("team_name", "sca_internal_prefixes", "hub_url", "affiliation_words"):  # необязательные
        if name in result.errors:
            continue
        try:
            result.clean[name] = normalize_setting(name, values[name])
        except ConfigError as e:
            result.errors[name] = str(e)
    return result


def save(db: Database, current: Settings, clean: Mapping[str, Any]) -> dict:
    """Сохраняет проверенные настройки одной транзакцией. Если сменился порог срочности SCA, заново
    упорядочивает находки всех проектов, в том числе архивных: срочность SCA зависит от порога.
    Возвращает {"changed": [ключи изменившихся настроек], "reordered": у скольких находок сменились порядок или
    срочность}."""
    values = {key: clean[key] for key in EDITABLE_SETTINGS if key in clean}
    changed = [key for key, value in values.items() if value != getattr(current, key)]
    if "ollama_url" in values or "default_model" in values:
        # «Адрес Ollama» и «Модель» – представление профиля 1 (ADR-0102, П23): запись – под блокировкой профиля 1,
        # сменился ли адрес – по профилю в базе внутри блокировки (не по снимку настроек до неё); сменился – ключ
        # профиля 1 (если задан) удаляется до записи
        from app import profile_gate
        from app.db import DEFAULT_PROVIDER_ID
        from app.provider_keys import delete_key
        with profile_gate.gate(DEFAULT_PROVIDER_ID).write():
            stored = db.get_provider(DEFAULT_PROVIDER_ID)
            if "ollama_url" in values and stored is not None and str(stored["base_url"]) != str(values["ollama_url"]):
                delete_key(db, DEFAULT_PROVIDER_ID)
            db.set_settings(values)
    else:
        db.set_settings(values)
    if "affiliation_words" in values:  # маска принадлежности действует сразу (ADR-0118)
        from app import affiliation
        affiliation.configure(values["affiliation_words"])
    reordered = 0
    if "sca_urgent_cvss" in changed:
        for project in db.list_projects(archived=None):
            reordered += reorder_project(db, project["id"], values["sca_urgent_cvss"])
    return {"changed": changed, "reordered": reordered}


# ============================================================================ Ollama

def check_ollama(make_client: Callable[[str], OllamaClient], url: str) -> dict:
    """Проверка адреса Ollama: {"url", "version", "models" (как OllamaClient.list_models), "error"}. Запросы –
    только если адрес проходит проверку хоста; ошибка – текстом по-русски."""
    client = make_client(url)
    try:
        client.check_url()
        # Назначения в журнале обмена с моделью: опрос версии и списка моделей помечается отдельно от прогона.
        with model_traffic.context(purpose="version"):
            version = client.version()
        with model_traffic.context(purpose="models"):
            models = client.list_models()
    except LlmError as e:
        from app.run_errors import shown_error
        return {"url": url, "version": "", "models": [], "error": shown_error(str(e))}  # LlmError – русский, показ (ADR-0158)
    return {"url": url, "version": version, "models": models, "error": ""}


def model_found(name: str, models: list[dict]) -> bool:
    """Модель есть в списке Ollama (имена сравниваются так, как их понимает Ollama: без тега – «:latest»)."""
    wanted = norm_model_name(name)
    return bool(wanted) and any(norm_model_name(m.get("name")) == wanted for m in models)


def _model_in(name: str, models: list[dict], profile: Mapping[str, Any] | None) -> bool:
    """Модель есть на сервере профиля: у удалённого API – имя как есть (executors.same_model), у Ollama – model_found."""
    from app.executors import same_model

    kind = str((profile or {}).get("kind") or "ollama")
    if kind == "ollama":
        return model_found(name, models)
    key = same_model(kind)
    return bool(name) and any(key(m.get("name")) == key(name) for m in models)


def ollama_report(settings: Settings, state: Mapping[str, Any], profile: Mapping[str, Any] | None = None) -> dict:
    """Ответ GET /api/ollama: что видит приложение на сервере профиля по умолчанию для разбора кода (ADR-0102; без
    профиля – по адресу Ollama из настроек). state – {"models", "version", "error"} (routes.common.models_of).
    profile – {name, trust, where}: start.ps1 говорит, кто разбирает код. Сценарий запуска сам имена моделей не
    сравнивает: default_model_found считается здесь."""
    error = str(state.get("error") or "")
    models = [] if error else list(state.get("models") or [])
    url = str((profile or {}).get("base_url") or settings.ollama_url)
    model = str((profile or {}).get("default_model") or settings.default_model)
    trust = str((profile or {}).get("trust") or "local")
    return {"url": url, "version": "" if error else str(state.get("version") or ""),
            "models": [str(m.get("name") or "") for m in models], "default_model": model,
            "default_model_found": False if error else _model_in(model, models, profile), "error": error,
            "profile": {"name": str((profile or {}).get("name") or i18n._("Ollama из «Настроек»")), "trust": trust,
                        "kind": str((profile or {}).get("kind") or "ollama"),
                        "where": WHERE_LABELS.get(trust, WHERE_LABELS["lan"])}}


# ============================================================================ что видно приложению

def repos_display(settings: Settings) -> str:
    """Корень папок с репозиториями так, как его видит пользователь: путь на его компьютере (REPOS_ROOT_HOST),
    если он известен, иначе путь внутри приложения. Прямые слэши; диск целиком – «D:/», а не «D:»."""
    text = (settings.repos_root_host or str(settings.repos_root)).replace("\\", "/")
    if len(text) > 1:
        text = text.rstrip("/")
    return text + "/" if _DRIVE_ONLY.fullmatch(text) else text


def folder_display(settings: Settings, rel: str) -> str:
    """Папка внутри корня так, как её видит пользователь: «D:/work/team»."""
    root = repos_display(settings)
    rel = str(rel or "").strip("/")
    if not rel:
        return root
    return f"{root}{rel}" if root.endswith("/") else f"{root}/{rel}"


def environment(settings: Settings) -> dict:
    """Сведения для страницы «Настройки»: корень папок с репозиториями (путь у пользователя и внутри приложения,
    найден ли, только ли для чтения, сколько в нём папок), папка данных, запущено ли приложение в контейнере."""
    root = settings.repos_root
    exists = root.is_dir()
    folders, more = 0, False
    if exists:
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    if entry.name.startswith("."):
                        continue
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        continue
                    if is_dir:
                        folders += 1
                        if folders >= MAX_LISTED:
                            more = True
                            break
        except OSError:
            exists = False
    container = in_container()
    return {
        "repos_display": repos_display(settings),
        "repos_inside": str(root).replace("\\", "/"),
        "repos_exists": exists,
        "repos_readonly": exists and not os.access(root, os.W_OK),
        "repos_folders": folders,
        "repos_more": more,
        "in_container": container,
        "data_dir": str(Path(settings.data_dir)).replace("\\", "/"),
        "max_upload_mb": settings.max_upload_mb,
        "num_ctx": settings.num_ctx,
    }

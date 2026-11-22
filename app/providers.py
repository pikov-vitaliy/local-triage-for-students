"""Правка профилей провайдеров моделей (ADR-0102): проверка значений и правила ключа.

Сервер принимает только известные значения: вид – ollama (чат-завершения – с 0.9.13, Messages API – с 0.9.14), класс
доверия – local, lan или
external (внешний сервер – только по протоколу внешнего API и только при LLM_EXTERNAL=1 на установке, ADR-0104), вход –
без ключа или ключом в заголовке. Каждая правка значимых полей – новая версия профиля
(Database.update_provider). Смена адреса сервера или подтверждённых адресов и выключение профиля удаляют файл ключа:
ключ привязан к адресу, оператор вводит его заново (app/provider_keys.py).
"""

from __future__ import annotations

import json
import socket
import threading
from dataclasses import dataclass, field
from collections.abc import Callable
from typing import Any, Mapping

from app import profile_gate
from app.storage.postgresql import CommitUnknown
from app.executors import KINDS, MAX_NUM_CTX, MIN_NUM_CTX, REMOTE_KINDS, THINK_RULES
from app.llm import LlmError
from app.llm_net import (ALLOWED_HOSTS, TRUST_CLASSES, _getaddrinfo, _ip, external_enabled, lan_address_ok,
                         normalize_addresses)
from app.provider_keys import KeyRejected, delete_key, load_key, save_key

EXTERNAL_KINDS = REMOTE_KINDS  # протоколы, которым доступен класс external (Ollama – нет)
EXTERNAL_OFF = ("Внешние провайдеры на этой установке выключены: профиль «интернет» создаётся и включается, только если "
                "приложение запущено с LLM_EXTERNAL=1.")
EXTERNAL_KIND = "Сервер в интернете – только по API внешнего провайдера; Ollama – этот компьютер или сеть организации."
AUTH_MODES = ("none", "bearer")


class ProfileInvalid(ValueError):
    """Значение профиля не принято; текст – по-русски."""


def check_values(values: Mapping[str, Any]) -> dict[str, Any]:
    """Проверенные значения правки: вид, класс доверия и способ входа – только известные; подтверждённые адреса –
    в едином виде."""
    clean = dict(values)
    if "kind" in clean and clean["kind"] not in KINDS:
        raise ProfileInvalid(f"Протокол сервера «{clean['kind']}» не поддерживается: Ollama, API чат-завершений или "
                             "Anthropic Messages API.")
    if "trust" in clean and clean["trust"] not in TRUST_CLASSES:
        raise ProfileInvalid(f"Класс доверия «{clean['trust']}» не поддерживается: только «этот компьютер» (local) и "
                             "«сеть организации» (lan).")
    if "auth" in clean and clean["auth"] not in AUTH_MODES:
        raise ProfileInvalid(f"Способ входа «{clean['auth']}» не поддерживается.")
    if "confirmed_addresses" in clean:
        clean["confirmed_addresses_json"] = json.dumps(normalize_addresses(clean.pop("confirmed_addresses")))
    return clean


def check_external(planned: Mapping[str, Any], creating: bool = False) -> None:
    """Профиль после правки (ADR-0104 п. 1): класс external – только у протоколов внешнего API; создать внешний профиль
    (даже выключенным) и включить его – только при LLM_EXTERNAL=1. Уже существующий выключенный внешний профиль
    остаётся читаемым и правится."""
    if str(planned.get("trust") or "") != "external":
        return
    if str(planned.get("kind") or "ollama") not in EXTERNAL_KINDS:
        raise ProfileInvalid(EXTERNAL_KIND)
    if (creating or planned.get("enabled", 1)) and not external_enabled():
        raise ProfileInvalid(EXTERNAL_OFF)


DEFAULT_UNFIT = ("Профиль по умолчанию для разбора кода: Ollama – только на этом компьютере или на сервере в сети "
                 "организации; API чат-завершений или Messages API – только внешний провайдер (интернет).")
MESSAGES_LOCAL = ("Anthropic Messages API – внешний провайдер или шлюз в сети организации: вариант «этот компьютер» "
                  "для него не предлагается.")


def code_default_ok(planned: Mapping[str, Any]) -> bool:
    """Годится ли профиль в умолчание для разбора кода: Ollama (local или lan) или внешний удалённый API (external) –
    решение владельца 21.11.2026. Внешнему API код уходит только проекту с отметкой «код не секретный»: это проверяет
    executors.choose_profile при каждом разборе, проекту без отметки разбор откажет с объяснением."""
    kind, trust = str(planned.get("kind") or "ollama"), str(planned.get("trust") or "")
    if kind == "ollama":
        return trust in ("local", "lan")
    # удалённый API разбирает код только как внешний профиль (executors.code_profile_fits): локальный или сетевой
    # сервер API чат-завершений умолчанием для кода не годится – разбор с ним не запустился бы ни у одного проекта
    return trust == "external"


def confirmed_of(profile: Mapping[str, Any] | None) -> list[str]:
    try:
        return normalize_addresses(json.loads(str((profile or {}).get("confirmed_addresses_json") or "[]")))
    except ValueError:
        return []


def update_profile(db: Any, provider_id: int, values: Mapping[str, Any]) -> dict[str, Any]:
    """Правка профиля под исключительной блокировкой профиля (app/profile_gate.py): начатые запросы дописывают байты
    до правки, новые видят её целиком. Сменятся адрес или подтверждённые адреса, профиль выключается – файл ключа
    удаляется ДО записи правки: не удалось удалить – правка не записывается (ProfileInvalid), профиль и ключ остаются
    согласованными; запись правки не удалась после удаления – ключ просто вводится заново."""
    clean = check_values(values)
    with profile_gate.gate(int(provider_id)).write():
        before = db.get_provider(int(provider_id))
        if before is None:
            raise ProfileInvalid(f"Профиль провайдера модели №{provider_id} не найден.")
        planned = {**before, **clean}
        check_external(planned)
        if (not planned.get("enabled") or str(planned["base_url"]) != str(before["base_url"])
                or set(confirmed_of(planned)) != set(confirmed_of(before))):
            try:
                delete_key(db, int(provider_id))
            except OSError as e:
                raise ProfileInvalid(f"Ключ профиля не удалось удалить ({type(e).__name__}): правка не сохранена.") \
                    from None
        return db.update_provider(int(provider_id), clean)


_DEFAULT_LOCK = threading.Lock()  # выбор профиля по умолчанию и выключение профиля – согласованно
# выключение профиля удаляет его ключ (ADR-0102): новый ключ выключенному профилю не записывается
KEY_DISABLED = "Ключ не сохраняется у выключенного профиля: включите профиль или очистите поле ключа."


def _must_drop_key(before: Mapping[str, Any], planned: Mapping[str, Any]) -> bool:
    return (not planned.get("enabled") or str(planned.get("auth") or "none") != "bearer"
            or str(planned["base_url"]) != str(before["base_url"])
            or set(confirmed_of(planned)) != set(confirmed_of(before)))


def _write_key(db: Any, provider_id: int, key: str, saved: Mapping[str, Any], key_written: Any) -> None:
    """Ключ профиля. Исход записи неизвестен (ответ на COMMIT потерян): ключ мог записаться, метка формы гасится, чтобы повтор той же формы не
    создал второй профиль с тем же ключом; оператор видит ошибку и проверяет данные."""
    try:
        save_key(db, provider_id, key, str(saved["base_url"]), confirmed_of(saved))
    except CommitUnknown:
        if key_written is not None:
            key_written()
        raise
    if key_written is not None:
        key_written()


def save_profile(db: Any, provider_id: int | None, values: Mapping[str, Any], *, key: str = "",
                 requires_key: bool = False, make_default: bool = False,
                 key_written: Callable[[], None] | None = None) -> tuple[dict[str, Any], bool]:
    """Сохранение формы профиля одной операцией (ADR-0102): правка профиля, способ входа, ключ и умолчание для
    разбора кода – под блокировкой профиля и общей блокировкой выбора умолчания. Ключ привязывается к тем адресу и
    подтверждённым адресам, которые записаны в этой же операции; сменились адрес или подтверждения, профиль выключен
    или ключ больше не нужен – прежний ключ удаляется до записи. Профиль по умолчанию не выключается. Возвращает
    (профиль, прежний ключ удалён без замены). key_written – вызывается сразу после записи ключа файлом: вызывающий
    знает, что ключ на диске, даже если дальше (умолчание) произошёл сбой."""
    from app.db import DEFAULT_PROVIDER_ID
    clean = check_values({**values, "auth": "bearer" if requires_key else "none"})
    with _DEFAULT_LOCK:
        default_id = int(db.get_settings().get("default_provider_id") or DEFAULT_PROVIDER_ID)
        if provider_id is not None and int(provider_id) == default_id and not clean.get("enabled", 1):
            raise ProfileInvalid("Профиль по умолчанию для разбора кода не выключается: сначала выберите другой.")
        if provider_id is None and requires_key and key and not clean.get("enabled", 1):
            raise ProfileInvalid(KEY_DISABLED)
        before_default = db.get_provider(int(provider_id)) if provider_id is not None else None
        planned_default = {"kind": "ollama", **(before_default or {}), **clean}
        # умолчание для кода – только пригодный профиль: и при назначении, и при правке действующего умолчания
        if (make_default or (provider_id is not None and int(provider_id) == default_id)) \
                and not code_default_ok(planned_default):
            raise ProfileInvalid(DEFAULT_UNFIT)
        dropped = False
        if provider_id is None:
            check_external({"kind": "ollama", **clean}, creating=True)
            saved = db.create_provider({"kind": "ollama", "purposes_json": json.dumps(["code", "research"]), **clean})
            provider_id = int(saved["id"])
            if requires_key and key:
                with _write(provider_id):
                    _write_key(db, provider_id, key, saved, key_written)
        else:
            with _write(int(provider_id)):
                before = db.get_provider(int(provider_id))
                if before is None:
                    raise ProfileInvalid(f"Профиль провайдера модели №{provider_id} не найден.")
                if requires_key and key and not {**before, **clean}.get("enabled"):
                    raise ProfileInvalid(KEY_DISABLED)
                check_external({**before, **clean})
                had = load_key(db, int(provider_id)) is not None
                if _must_drop_key(before, {**before, **clean}):
                    try:
                        delete_key(db, int(provider_id))
                    except OSError as e:
                        raise ProfileInvalid(f"Ключ профиля не удалось удалить ({type(e).__name__}): правка не "
                                             "сохранена.") from None
                    dropped = had and not key
                saved = db.update_provider(int(provider_id), clean)
                if requires_key and key:
                    _write_key(db, int(provider_id), key, saved, key_written)
        if make_default and saved.get("enabled"):
            db.set_settings({"default_provider_id": int(provider_id)})
    return saved, dropped


def _write(provider_id: int):
    """Исключительная блокировка профиля; занят слишком долго – ProfileInvalid с понятным текстом."""
    from contextlib import contextmanager

    @contextmanager
    def held():
        try:
            with profile_gate.gate(provider_id).write():
                yield
        except TimeoutError:
            raise ProfileInvalid("Профиль сейчас отправляет запросы модели: правка не сохранена – повторите.") \
                from None
    return held()


def set_key(db: Any, provider_id: int, key: str) -> None:
    """Задать или заменить ключ профиля: привязка – к адресу и подтверждённым адресам профиля в этот момент, под той
    же блокировкой, что и правка профиля (ключ не привяжется к адресу, который уже меняется)."""
    with profile_gate.gate(int(provider_id)).write():
        profile = db.get_provider(int(provider_id))
        if profile is None:
            raise ProfileInvalid(f"Профиль провайдера модели №{provider_id} не найден.")
        if not profile.get("enabled"):
            raise ProfileInvalid(KEY_DISABLED)
        save_key(db, int(provider_id), key, str(profile["base_url"]), confirmed_of(profile))


def clear_key(db: Any, provider_id: int) -> bool:
    """Удалить ключ профиля под блокировкой профиля: начатые запросы допишут байты, новые уйдут уже без ключа."""
    with profile_gate.gate(int(provider_id)).write():
        return delete_key(db, int(provider_id))


def create_profile(db: Any, values: Mapping[str, Any]) -> dict[str, Any]:
    """Новый профиль с проверенными значениями (по умолчанию – вид ollama; класс external – по check_external)."""
    clean = check_values({"kind": "ollama", "purposes_json": json.dumps(["code", "research"]), **values})
    check_external(clean, creating=True)
    return db.create_provider(clean)


# ============================================================================ форма профиля («Настройки → Провайдеры»)

TRUST_LABELS = {"local": "Этот компьютер – код не покидает компьютер",
                "lan": "Сервер в сети организации – код уходит только на подтверждённые адреса",
                "external": "Интернет – внешний провайдер по ключу API (код – только проектам с отметкой «код не "
                            "секретный»; исследование компонентов – обезличенный состав)"}
KIND_LABELS = {"ollama": "Ollama", "chat_completions": "API чат-завершений (внешний провайдер или совместимый сервер)",
               "messages": "Anthropic Messages API (внешний провайдер или совместимый шлюз)"}
WHERE = {"local": "этот компьютер", "lan": "сеть организации", "external": "интернет"}
RESPONSE_LABELS = {"json_object": "json_object – ответ объектом JSON, проверка приложением",
                   "json_schema": "json_schema – сервер проверяет ответ по схеме (если поддерживает)",
                   "none": "без формата – только проверка приложением"}
# формат ответа Messages API – своим полем формы (два списка на странице, виден список выбранного протокола)
MESSAGES_RESPONSE_LABELS = {"tool": "tool – ответ вызовом инструмента answer, проверка приложением",
                            "tool_strict": "tool_strict – инструмент answer со строгой схемой (если сервер "
                                           "поддерживает), проверка приложением",
                            "none": "без формата – ответ текстом, только проверка приложением"}
RESPONSE_FIELDS = {"chat_completions": ("response_mode", RESPONSE_LABELS),  # протокол: (поле формы, варианты)
                   "messages": ("messages_response_mode", MESSAGES_RESPONSE_LABELS)}
THINKING_LABELS = {"": "не передавать", "enabled": "включено", "disabled": "выключено"}
EFFORT_LABELS = {"": "не передавать", "none": "none", "minimal": "minimal", "low": "low", "medium": "medium",
                 "high": "high", "max": "max"}
CHAT_NUMBERS = {  # поле формы: (ключ generation_json, наименьшее, наибольшее, что это)
    "context_window": ("context_window", 1024, 10_000_000, "Окно контекста модели"),
    "max_output": ("max_output", 16, 1_000_000, "Предел ответа"),
    "tool_steps": ("tool_steps", 1, 40, "Шагов поиска на компонент"),
    "chat_timeout_s": ("timeout_s", 30, 86400, "Срок одного обращения"),
}
SEARCH_PATH_MAX = 200
# пути поиска и получения страницы по умолчанию: галочка поиска без путей – эти (серые
# подсказки в пустых полях выглядели заполненными)
SEARCH_DEFAULTS = {"search_path": "/v1/tools/search", "fetch_path": "/v1/tools/fetch"}
THINK_LABELS = {"auto": "авто – моделям, которые умеют рассуждать, рассуждение включено (gpt-oss – низкий уровень)",
                "off": "выключено (gpt-oss рассуждает всегда – низкий уровень)",
                "low": "низкий уровень", "medium": "средний уровень", "high": "высокий уровень"}
NUMBER_FIELDS = {  # поле формы: (ключ generation_json, наименьшее, наибольшее, что это)
    "num_ctx": ("num_ctx", MIN_NUM_CTX, MAX_NUM_CTX, "Окно контекста"),
    "num_predict": ("num_predict", 256, 1_000_000, "Предел ответа разбора"),
    "think_num_predict": ("think_num_predict", 256, 1_000_000, "Предел ответа с рассуждением"),
    "timeout_s": ("timeout_s", 30, 86400, "Срок ответа"),
    "think_timeout_s": ("think_timeout_s", 30, 86400, "Срок ответа с рассуждением"),
}
TEXT_LIMITS = {"name": 100, "base_url": 300, "default_model": 200}


@dataclass
class ProfileForm:
    values: dict[str, Any]
    clean: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    key: str = ""
    delete_key: bool = False
    default_code: bool = False


def _generation_of(profile: Mapping[str, Any] | None) -> dict[str, Any]:
    try:
        raw = json.loads(str((profile or {}).get("generation_json") or "{}"))
    except ValueError:
        raw = {}
    return raw if isinstance(raw, dict) else {}


def _caps_of(profile: Mapping[str, Any] | None) -> dict[str, Any]:
    try:
        raw = json.loads(str((profile or {}).get("capabilities_json") or "{}"))
    except ValueError:
        raw = {}
    return raw if isinstance(raw, dict) else {}


def _chat_values(profile: Mapping[str, Any] | None) -> dict[str, Any]:
    gen, caps = _generation_of(profile), _caps_of(profile)
    search = caps.get("search") if isinstance(caps.get("search"), dict) else {}
    messages = str((profile or {}).get("kind") or "") == "messages"
    mode = str(caps.get("response_mode") or "")
    return {"response_mode": mode if not messages and mode else "json_object",
            "messages_response_mode": mode if messages and mode in MESSAGES_RESPONSE_LABELS else "tool",
            "thinking": str(caps.get("thinking") or ""), "effort": str(caps.get("effort") or ""),
            "retry_on_drop": caps.get("retry_on_drop") is True,
            "search_on": bool(search), "search_path": str(search.get("search_path") or ""),
            "fetch_path": str(search.get("fetch_path") or ""),
            **{name: str(gen.get(key) or "") for name, (key, *_rest) in CHAT_NUMBERS.items()}}


# Рекомендуемые значения раздела «Дополнительно» для DeepSeek (слово владельца 22.11.2026: студенты не должны искать
# их сами). Сверено с документацией DeepSeek 22.11.2026: deepseek-flash – окно контекста 1M; рассуждение по умолчанию
# включено, уровень high; max_tokens по умолчанию с рассуждением – 64K (до 384K); ответ json_object поддерживается;
# поиск – /v1/tools/search и /v1/tools/fetch (api-docs.deepseek.com: quick_start/pricing, api/create-chat-completion,
# guides/thinking_mode, guides/json_mode, guides/search). Шагов поиска 12 и срок 600 с – значения рабочего профиля
# владельца. Новая модель или другие пределы у провайдера – поправить здесь.
DEEPSEEK_RECOMMENDED: dict[str, Any] = {
    "response_mode": "json_object", "thinking": "enabled", "effort": "high", "context_window": "1000000",
    "max_output": "65536", "tool_steps": "12", "chat_timeout_s": "600", "retry_on_drop": True, "search_on": True,
    "search_path": "/v1/tools/search", "fetch_path": "/v1/tools/fetch",
}
# Подсказки к полям раздела «Дополнительно»: что это простыми словами и что ставить для DeepSeek
ADVANCED_HINTS = {
    "response_mode": "В каком виде модель присылает ответ. Для DeepSeek – json_object: приложение само проверит, что "
                     "ответ полный.",
    "thinking": "Модель сначала рассуждает, потом отвечает: точнее, но дольше. Для DeepSeek – «включено» (так у "
                "провайдера по умолчанию).",
    "effort": "Насколько глубоко рассуждать: low – быстрее, high – точнее, max – дольше всех. Для DeepSeek – high.",
    "context_window": "Сколько текста модель видит за раз: задание, код и ответ вместе. У deepseek-flash – 1 000 000.",
    "max_output": "Самый длинный ответ модели вместе с рассуждением. Для DeepSeek – 65536: так у провайдера по "
                  "умолчанию при рассуждении. Меньше – ответ может оборваться.",
    "tool_steps": "Сколько раз модель может искать и открывать источники, исследуя один компонент. Для DeepSeek – 12.",
    "chat_timeout_s": "Сколько секунд ждать один ответ. С рассуждением ответ идёт минутами; для DeepSeek – 600.",
}

# Заготовки нового профиля для учебного стенда (план стенда, раздел 5; ADR-0157): форма предзаполнена, ключ студент
# вводит сам, «Проверить» сверяет имя модели со списком /models. Без ключа профиль ничего не отправляет.
PRESETS: dict[str, dict[str, Any]] = {
    "deepseek": {"name": "DeepSeek", "kind": "chat_completions", "trust": "external",
                 "base_url": "https://api.deepseek.com", "default_model": "deepseek-flash", "requires_key": True,
                 **DEEPSEEK_RECOMMENDED},
    "ollama-local": {"name": "Ollama на этом компьютере", "kind": "ollama", "trust": "local",
                     "base_url": "http://127.0.0.1:11434", "default_model": "gpt-oss:20b", "requires_key": False},
}


def preset_form(name: str) -> dict[str, Any] | None:
    """Значения формы нового профиля по заготовке; неизвестное имя – None."""
    preset = PRESETS.get(str(name or ""))
    return None if preset is None else {**form_of(None), **preset}


def form_of(profile: Mapping[str, Any] | None, default_id: int | None = None) -> dict[str, Any]:
    """Значения полей формы из профиля (новый профиль – Ollama, сервер в сети, включён)."""
    if profile is None:
        return {"name": "", "kind": "ollama", "trust": "lan", "base_url": "", "default_model": "", "think": "auto",
                "enabled": True, "allows_unload": False, "confirmed": [], "default_code": False, "requires_key": False,
                **{name: "" for name in NUMBER_FIELDS}, **_chat_values(None)}
    gen = _generation_of(profile)
    return {"name": str(profile.get("name") or ""), "kind": str(profile.get("kind") or "ollama"),
            **(_chat_values(profile) if str(profile.get("kind") or "ollama") in REMOTE_KINDS
               else _chat_values(None)),
            "trust": str(profile.get("trust") or "local"),
            "base_url": str(profile.get("base_url") or ""), "default_model": str(profile.get("default_model") or ""),
            "think": str(gen.get("think") or "auto"), "enabled": bool(profile.get("enabled")),
            "allows_unload": _caps_of(profile).get("allows_unload") is True,
            "confirmed": confirmed_of(profile), "default_code": default_id == profile.get("id"),
            "requires_key": str(profile.get("auth") or "none") == "bearer",
            **{name: str(gen.get(key) or "") for name, (key, *_rest) in NUMBER_FIELDS.items()}}


def read_form(form: Any, profile: Mapping[str, Any] | None, fixed: bool = False) -> ProfileForm:
    """Форма профиля -> ProfileForm. fixed – профиль 1 (П23): адрес, модель и класс правятся на странице «Настройки»,
    здесь – только параметры генерации и название."""
    def text(name: str) -> str:
        return " ".join(str(form.get(name) or "").split())[:TEXT_LIMITS.get(name, 100)]

    values: dict[str, Any] = {name: text(name) for name in TEXT_LIMITS}
    values["base_url"] = str(form.get("base_url") or "").strip()[:TEXT_LIMITS["base_url"]].rstrip("/")
    values["trust"] = str(form.get("trust") or "lan")
    values["kind"] = str(form.get("kind") or "ollama")
    values["response_mode"] = str(form.get("response_mode") or "json_object")
    values["messages_response_mode"] = str(form.get("messages_response_mode") or "tool")
    values["thinking"] = str(form.get("thinking") or "")
    values["effort"] = str(form.get("effort") or "")
    values["search_on"] = form.get("search_on") == "1"
    values["retry_on_drop"] = form.get("retry_on_drop") == "1"
    for name in ("search_path", "fetch_path"):
        values[name] = str(form.get(name) or "").strip()[:SEARCH_PATH_MAX]
    for name in CHAT_NUMBERS:
        values[name] = str(form.get(name) or "").strip()[:12]
    values["think"] = str(form.get("think") or "auto")
    values["enabled"] = form.get("enabled") == "1"
    values["allows_unload"] = form.get("allows_unload") == "1"
    values["confirmed"] = normalize_addresses(form.getlist("confirm") if hasattr(form, "getlist") else [])
    values["default_code"] = form.get("default_code") == "1"
    values["requires_key"] = form.get("requires_key") == "1"
    for name in NUMBER_FIELDS:
        values[name] = str(form.get(name) or "").strip()[:12]
    if fixed and profile is not None:  # профиль 1: адрес, модель и класс – из «Настроек»
        for name in ("base_url", "default_model", "trust"):
            values[name] = str(profile.get(name) or "")
        values["confirmed"] = []
        values["kind"] = "ollama"
    result = ProfileForm(values=values, key=str(form.get("key") or "").strip(),
                         delete_key=form.get("delete_key") == "1", default_code=values["default_code"])
    errors = result.errors
    if not values["name"]:
        errors["name"] = "Назовите профиль, например «Сервер в сети» или «Ollama на этом компьютере»."
    chat = values["kind"] in REMOTE_KINDS  # удалённый API: чат-завершения или Messages
    messages = values["kind"] == "messages"
    if values["kind"] not in KINDS:
        errors["kind"] = "Выберите протокол сервера из списка."
    if values["trust"] not in TRUST_CLASSES:
        errors["trust"] = "Выберите, где работает модель."
    elif values["trust"] == "external" and not chat:  # Ollama – только этот компьютер или сеть организации
        errors["trust"] = EXTERNAL_KIND
    elif values["trust"] == "local" and messages:  # план 0.9.14 п. 2.4: Messages – внешний провайдер или шлюз
        errors["trust"] = MESSAGES_LOCAL
    elif values["trust"] == "external" and (values["enabled"] or profile is None) and not external_enabled():
        errors["trust"] = EXTERNAL_OFF
    if values["think"] not in THINK_RULES:
        errors["think"] = "Выберите режим рассуждения из списка."
    if not errors.get("trust") and not errors.get("kind"):
        try:
            check_address(values["base_url"], values["trust"], values["kind"])
        except LlmError as e:
            errors["base_url"] = str(e)
    chat_gen: dict[str, Any] = {}
    if chat:
        field_name, labels = RESPONSE_FIELDS[values["kind"]]
        if values[field_name] not in labels:
            errors[field_name] = "Выберите формат ответа из списка."
        if messages:
            # Messages API: рассуждение не передаётся (ADR-0106 п. 10) – поля рассуждения у этого протокола скрыты и
            # не сохраняются, значение, оставшееся от другого протокола, сбрасывается
            values["thinking"] = values["effort"] = ""
        if values["thinking"] not in THINKING_LABELS:
            errors["thinking"] = "Выберите режим рассуждения из списка."
        if values["effort"] not in EFFORT_LABELS:
            errors["effort"] = "Выберите уровень рассуждения из списка."
        for name, (key, low, high, label) in CHAT_NUMBERS.items():
            raw = values[name]
            if not raw:
                continue
            if not raw.isdigit() or not low <= int(raw) <= high:
                errors[name] = f"{label}: целое число от {low} до {high} или пусто – по умолчанию."
            else:
                chat_gen[key] = int(raw)
        if chat_gen.get("max_output") and chat_gen.get("context_window") and \
                chat_gen["max_output"] >= chat_gen["context_window"]:
            errors["max_output"] = "Предел ответа должен быть меньше окна контекста модели."
        if values["search_on"]:
            for name in ("search_path", "fetch_path"):
                values[name] = values[name] or SEARCH_DEFAULTS[name]
                path = values[name]
                if not path.startswith("/") or path.startswith("//") or any(c in path for c in "?#@ \\"):
                    errors[name] = "Путь от корня адреса профиля, например /v1/tools/search – без «?», «#» и пробелов."
        # удалённый API может быть профилем по умолчанию (решение владельца 21.11.2026): код ему уходит только у
        # проектов с отметкой «код не секретный», остальным разбор откажет (executors.external_code_allowed)
    gen: dict[str, Any] = {}
    for name, (key, low, high, label) in NUMBER_FIELDS.items():
        raw = values[name]
        if not raw or chat:  # поля Ollama у другого протокола не проверяются
            continue
        if not raw.isdigit() or not low <= int(raw) <= high:
            errors[name] = f"{label}: целое число от {low} до {high} или пусто – «авто»."
        else:
            gen[key] = int(raw)
    if values["think"] != "auto":
        gen["think"] = values["think"]
    if result.key:
        try:  # проверка вида ключа – до записи
            _check_key(result.key)
        except KeyRejected as e:
            errors["key"] = str(e)
    if values["trust"] == "local" and (result.key or values["requires_key"]):
        errors["key"] = "Ключ нужен только серверу в сети или внешнему провайдеру: этот компьютер работает без ключа."
    if result.key and not values["requires_key"] and not errors.get("key"):
        errors["key"] = "Ключ введён, но «Сервер требует ключ» не отмечено: отметьте или очистите поле ключа."
    if not errors and chat:
        caps = {"supports_ps": False, "allows_unload": False,
                "response_mode": values[RESPONSE_FIELDS[values["kind"]][0]],
                "thinking": values["thinking"], "effort": values["effort"],
                "retry_on_drop": bool(values["retry_on_drop"]),
                "search": ({"search_path": values["search_path"], "fetch_path": values["fetch_path"]}
                           if values["search_on"] else None)}
        result.clean = {"name": values["name"], "kind": values["kind"], "trust": values["trust"],
                        "base_url": values["base_url"], "default_model": values["default_model"],
                        "enabled": 1 if values["enabled"] else 0,
                        "generation_json": json.dumps(chat_gen, ensure_ascii=False, sort_keys=True),
                        "capabilities_json": json.dumps(caps, ensure_ascii=False, sort_keys=True),
                        "confirmed_addresses": values["confirmed"] if values["trust"] == "lan" else []}
    elif not errors:
        # выгрузка модели в медленном режиме: на этом компьютере – как до 0.9.12, на сервере в сети – по отметке
        caps = {**_caps_of(profile), "supports_ps": True,
                "allows_unload": True if values["trust"] == "local" else values["allows_unload"]}
        result.clean = {"name": values["name"], "kind": "ollama", "trust": values["trust"],
                        "base_url": values["base_url"],
                        "default_model": values["default_model"], "enabled": 1 if values["enabled"] else 0,
                        "generation_json": json.dumps(gen, ensure_ascii=False, sort_keys=True),
                        "capabilities_json": json.dumps(caps, sort_keys=True),
                        "confirmed_addresses": values["confirmed"] if values["trust"] == "lan" else []}
        if fixed:
            for name in ("base_url", "default_model", "trust", "confirmed_addresses", "kind"):
                result.clean.pop(name, None)
    return result


def _check_key(key: str) -> None:
    from app.provider_keys import _KEY, KEY_FORMAT
    if not _KEY.fullmatch(key):
        raise KeyRejected(KEY_FORMAT)


def check_address(base_url: str, trust: str, kind: str = "ollama") -> tuple[str, int]:
    """Проверка адреса сервера без сети: вид адреса и хост по классу доверия и протоколу -> (хост, порт); LlmError."""
    from app.llm_chat import ChatCompletionsClient
    from app.llm_messages import MessagesClient
    from app.llm_ollama import OllamaClient
    client = (ChatCompletionsClient(base_url) if kind == "chat_completions" else
              MessagesClient(base_url) if kind == "messages" else OllamaClient(base_url))
    client.trust = trust
    target = client._target()
    return target.host, target.port


def resolve_addresses(base_url: str, trust: str, kind: str = "ollama") -> list[dict[str, Any]]:
    """Адреса, в которые сейчас разрешается имя сервера (для подтверждения оператором): [{address, private}].
    Запросов к серверу нет – только служба имён. Сбой – LlmError."""
    host, port = check_address(base_url, trust, kind)
    result: list[dict[str, Any]] = []
    for info in _getaddrinfo(host, port, 5.0, trust):
        if info[0] not in (socket.AF_INET, socket.AF_INET6):
            continue
        ip = _ip(str(info[4][0]))
        if ip is not None and not any(item["address"] == str(ip) for item in result):
            result.append({"address": str(ip), "private": lan_address_ok(ip)})
    return result


def key_binding_matches(db: Any, provider_id: int | None, base_url: str, addresses: Any) -> bool:
    """Сохранённый ключ профиля привязан именно к этому адресу и этим подтверждённым адресам."""
    entry = load_key(db, provider_id) if provider_id is not None else None
    return bool(entry) and entry["base_url"] == str(base_url).rstrip("/") and \
        set(entry["addresses"]) == set(normalize_addresses(addresses))


def local_hosts_hint() -> str:
    return ", ".join(ALLOWED_HOSTS)

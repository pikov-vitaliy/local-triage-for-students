"""Выбор профиля провайдера модели и снимок исполнителя (ADR-0102).

Профиль выбирается по порядку «прогон или вопрос → проект → приложение» для назначения «разбор кода». Снимок
исполнителя – неизменяемая копия настроек профиля без ключа на момент постановки прогона или вопроса: адрес,
класс, модель, параметры генерации (окно, предел длины ответа по виду операции, temperature, seed), срок одного
обращения к /api/chat, правило уровня рассуждения и режим схемы ответа. Возобновление берёт значения из снимка, а
не из текущих настроек. Фактический уровень рассуждения зависит от модели, которая лежит на сервере под этим именем
в момент запроса, поэтому он вычисляется при каждом запросе (applied_think) и уходит и в тело запроса, и в ключ
кэша. Прежние прогоны, ответы и вопросы (до 0.9.12) снимка не имеют – «прежние разборы».
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Mapping
from typing import Any, NamedTuple

from app.llm import DEFAULT_OPTIONS, LlmError, SendNotAllowed, gate_for, is_gpt_oss
from app.llm_net import normalize_addresses

OPERATIONS = ("triage", "ask")  # разбор и пересмотр находки; вопрос к модели
TRIAGE_NUM_PREDICT = int(DEFAULT_OPTIONS["num_predict"])  # предел ответа разбора по умолчанию: 3072
ASK_NUM_PREDICT = 1536  # предел ответа на вопрос по умолчанию: ответ короче разбора
DEFAULT_TIMEOUT_S = 900.0  # срок одного обращения к /api/chat (каждой попытки)
CHAT_TIMEOUT_S = 600.0  # срок одного обращения к API чат-завершений по умолчанию (К3 плана 0.9.13)
THINK_LEVELS = ("low", "medium", "high")
THINK_RULES = ("auto", "off", *THINK_LEVELS)  # правило уровня рассуждения в профиле
# Рассуждающий запрос (модель с capabilities thinking, не gpt-oss): рассуждение тратит тот же предел ответа, что и
# сам ответ, поэтому у него свой предел и свой срок
TRIAGE_THINK_PREDICT = 8192
ASK_THINK_PREDICT = 4096
THINK_TIMEOUT_S = 2400.0
MAX_TIMEOUT_S = 24 * 3600.0
MIN_NUM_CTX, MAX_NUM_CTX = 4096, 262144  # окно контекста профиля – в тех же границах, что MODEL_NUM_CTX
MAX_NUM_PREDICT = 1_000_000


class ProfileError(Exception):
    """Профиль провайдера не подходит: выключен, нет такого, не для этого назначения. Текст – по-русски."""


class ProbeBusy(Exception):
    """Право на генерацию занято (идёт разбор, вопрос или другая проверка): пробная генерация не начата."""


class Server(NamedTuple):
    """Сервер модели профиля или снимка – для служебных запросов страниц (версия, модели, метрики) и ключ их кэшей:
    адрес, данные этого компьютера (только у local), класс доверия, подтверждённые адреса, ключ (номер профиля и
    способ входа). Первые два поля – как прежний кортеж (адрес, данные хоста)."""
    base_url: str
    local: bool
    trust: str = "local"
    confirmed: tuple[str, ...] = ()
    provider_id: int | None = None
    auth: str = "none"
    kind: str = "ollama"  # протокол сервера: ollama, chat_completions (0.9.13) или messages (0.9.14)
    # модель профиля или снимка – резервное имя списка моделей Messages API при недоступном /models (ADR-0106 п. 7);
    # у других протоколов пусто: ключи кэшей и наблюдения за сервером прежние
    model: str = ""


KINDS = ("ollama", "chat_completions", "messages")  # протоколы, клиенты которых есть в этой версии
REMOTE_KINDS = ("chat_completions", "messages")  # удалённые API: параметры клиента – из профиля (chat_settings)
# формат ответа chat_json по протоколу: первое значение – по умолчанию (ADR-0106 п. 5)
RESPONSE_MODES = {"chat_completions": ("json_object", "json_schema", "none"), "messages": ("tool", "tool_strict", "none")}
CHAT_DEFAULTS = {"response_mode": "json_object", "thinking": "", "effort": "", "max_output": 8192,
                 "context_window": None, "tool_steps": 12,
                 # один автоматический повтор после обрыва без ответа; по умолчанию – нет
                 "retry_on_drop": False}
# защита от каскада обрывов: столько находок подряд с обрывом или больше этой доли прогона
# (но не меньше DROP_STREAK_PAUSE обрывов) – прогон встаёт на паузу, а не отправляет дальше
DROP_STREAK_PAUSE = 3
DROP_SHARE_PAUSE = 0.10
DROP_PAUSE_NOTE = ("Провайдер обрывает соединения без ответа: {drops} из {done} находок этого прогона ({streak} подряд). "
                   "Прогон на паузе, чтобы не тратить запросы впустую; когда провайдер заработает, нажмите «Продолжить».")


def drop_retry_allowed(execution: Mapping[str, Any]) -> bool:
    """Повторять ли запрос внешнему провайдеру один раз после обрыва без ответа – по снимку исполнителя."""
    return str(execution.get("trust") or "") == "external" and chat_settings(execution).get("retry_on_drop") is True


def same_model(kind: str) -> Callable[[str], str]:
    """Ключ сравнения имён моделей: у Ollama – norm_model_name (регистр, «:latest»), у удалённых API – имя как есть:
    у провайдера «Model» и «model» – разные модели (ADR-0106 п. 7)."""
    from app.llm import norm_model_name
    return (lambda name: str(name or "")) if str(kind) in REMOTE_KINDS else norm_model_name


def chat_settings(executor: Mapping[str, Any] | None) -> dict[str, Any]:
    """Параметры клиента чат-завершений из профиля (generation_json и capabilities_json) или снимка исполнителя
    (options_json): формат ответа, поля рассуждения, предел ответа, окно модели, шагов инструментов."""
    source = executor or {}
    if "options_json" in source:
        data = _snapshot_data(source)
        raw = {**dict(data.get("chat") or {})}
    else:
        raw = {}
        for column in ("generation_json", "capabilities_json"):
            try:
                part = json.loads(str(source.get(column) or "{}"))
            except ValueError:
                part = {}
            raw.update(part if isinstance(part, dict) else {})
    result = dict(CHAT_DEFAULTS)
    for name in CHAT_DEFAULTS:
        if raw.get(name) not in (None, ""):
            result[name] = raw[name]
    if str(source.get("kind") or "") == "messages":
        # Messages API: свой набор форматов ответа, рассуждение не передаётся (ADR-0106 п. 5, 10)
        if result["response_mode"] not in RESPONSE_MODES["messages"]:
            result["response_mode"] = RESPONSE_MODES["messages"][0]
        result["thinking"] = result["effort"] = ""
    # поисковый API профиля – в снимок как есть (К3, ADR-0105): исследование идёт по путям снимка, а не профиля сейчас
    search = raw.get("search")
    result["search"] = dict(search) if isinstance(search, dict) and search.get("search_path") else None
    return result


def new_client(make_client: Callable[[str], Any], kind: str, url: str) -> Any:
    """Клиент по протоколу: Ollama – через make_client (в тестах – подмена), чат-завершения – ChatCompletionsClient,
    Messages API – MessagesClient. Неизвестный протокол – LlmError: запрос не отправляется."""
    if kind == "chat_completions":
        from app.llm_chat import ChatCompletionsClient
        return ChatCompletionsClient(url)
    if kind == "messages":
        from app.llm_messages import MessagesClient
        return MessagesClient(url)
    if kind != "ollama":
        raise LlmError(f"Протокол сервера модели «{kind}» этой версией не поддерживается: запрос не отправлен.")
    return make_client(url)


def fit_options(execution: Mapping[str, Any], options: Mapping[str, Any], overhead: int = 0) -> dict[str, Any]:
    """Параметры подгонки промпта под окно (prompt_fits, prompt_budget): у Ollama – параметры генерации снимка; у
    удалённого API – окно и предел ответа профиля (снимка), по которым его клиент проверяет запрос перед отправкой.
    overhead – что клиент добавит к сообщениям в той же проверке (схема ответа или инструмент answer –
    client.json_overhead): из окна вычитается. Раньше срез подгонялся под окно Ollama (num_ctx/num_predict) – лишнее
    сокращение при большом окне провайдера и поздний отказ клиента при маленьком (KIMI-01, аудит 25.10). Окно в
    профиле не задано – подгонки нет: клиент размер тоже не проверяет."""
    if str(execution.get("kind") or "ollama") not in REMOTE_KINDS:
        return dict(options)
    chat = chat_settings(execution)
    window = chat.get("context_window")
    return {"num_ctx": max(1, int(window) - max(0, int(overhead))) if window else None,
            "num_predict": int(chat.get("max_output") or CHAT_DEFAULTS["max_output"])}


def prompt_size(execution: Mapping[str, Any]) -> Callable[[Any], int] | None:
    """Оценка длины сообщений для подгонки – та же, что у клиента, который проверит запрос перед отправкой: у
    удалённого API – по всему JSON сообщения (llm_chat.message_tokens, с экранированием), у Ollama – по тексту (None –
    оценка по умолчанию). Разные оценщики давали поздний отказ клиента после подгонки (ревью Codex, круг 18)."""
    if str(execution.get("kind") or "ollama") not in REMOTE_KINDS:
        return None
    from app.llm_chat import message_tokens
    return message_tokens


def json_overhead(client: Any, fields: Mapping[str, str], required: Any, enums: Mapping[str, Any],
                  types: Mapping[str, str] | None = None) -> int:
    """Добавка клиента удалённого API к сообщениям в проверке размера (0 у Ollama и у клиента без метода)."""
    method = getattr(client, "json_overhead", None)
    return int(method(fields, required, enums, types)) if callable(method) else 0


def apply_chat(client: Any, settings: Mapping[str, Any], model: str = "") -> Any:
    """Параметры профиля или снимка – клиенту удалённого API (у клиента Ollama их нет – он не меняется). model – имя
    модели снимка или профиля: резервный список моделей Messages API при недоступном /models (ADR-0106 п. 7)."""
    from app.llm_chat import ChatCompletionsClient
    from app.llm_messages import MessagesClient
    if isinstance(client, ChatCompletionsClient):
        client.response_mode = str(settings.get("response_mode") or "json_object")
        client.thinking = str(settings.get("thinking") or "")
        client.effort = str(settings.get("effort") or "")
        client.max_output = int(settings.get("max_output") or CHAT_DEFAULTS["max_output"])
        window = settings.get("context_window")
        client.context_window = int(window) if window else None
    if isinstance(client, MessagesClient):
        if client.response_mode not in RESPONSE_MODES["messages"]:
            client.response_mode = RESPONSE_MODES["messages"][0]
        client.thinking = client.effort = ""  # рассуждение протоколу Messages не передаётся (ADR-0106 п. 10)
        if model:
            client.fallback_model = str(model)
    return client


def generation(profile: Mapping[str, Any] | None) -> dict[str, Any]:
    """Параметры генерации профиля (generation_json): только известные и допустимые значения; пусто – «авто, как
    сейчас»."""
    try:
        raw = json.loads(str((profile or {}).get("generation_json") or "{}"))
    except ValueError:
        raw = {}
    raw = raw if isinstance(raw, dict) else {}
    result: dict[str, Any] = {}
    for key in ("timeout_s", "think_timeout_s"):
        timeout = raw.get(key)
        if isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and 0 < timeout <= MAX_TIMEOUT_S:
            result[key] = float(timeout)
    for key in ("num_predict", "ask_num_predict", "think_num_predict", "ask_think_num_predict"):
        value = raw.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 < value <= MAX_NUM_PREDICT:
            result[key] = value
    if raw.get("think") in THINK_RULES[1:]:
        result["think"] = raw["think"]
    num_ctx = raw.get("num_ctx")  # окно контекста профиля
    if isinstance(num_ctx, int) and not isinstance(num_ctx, bool) and MIN_NUM_CTX <= num_ctx <= MAX_NUM_CTX:
        result["num_ctx"] = num_ctx
    return result


def operation_options(operation: str, num_ctx: int, gen: Mapping[str, Any]) -> dict[str, Any]:
    """Полный набор параметров генерации операции: temperature и seed – как у приложения, окно – общая настройка,
    предел ответа – по виду операции (разбор и пересмотр – min(3072, окно/4), вопрос – min(1536, окно/4)); явное
    число из профиля – тоже не больше четверти окна, чтобы в окне оставалось место под промпт."""
    if operation not in OPERATIONS:
        raise ValueError(f"неизвестная операция {operation!r}")
    num_ctx = int(num_ctx)
    quarter = num_ctx // 4
    explicit = gen.get("num_predict" if operation == "triage" else "ask_num_predict")
    default = TRIAGE_NUM_PREDICT if operation == "triage" else ASK_NUM_PREDICT
    return {"temperature": DEFAULT_OPTIONS["temperature"], "seed": DEFAULT_OPTIONS["seed"], "num_ctx": num_ctx,
            "num_predict": min(int(explicit or default), quarter)}


def thinking_predict(operation: str, num_ctx: int, gen: Mapping[str, Any]) -> int:
    """Предел ответа рассуждающего запроса: явное число профиля или авто (разбор – 8192, вопрос – 4096), не больше
    половины окна – в окне остаётся место под промпт."""
    explicit = gen.get("think_num_predict" if operation == "triage" else "ask_think_num_predict")
    default = TRIAGE_THINK_PREDICT if operation == "triage" else ASK_THINK_PREDICT
    return min(int(explicit or default), int(num_ctx) // 2)


def think_rule(gen: Mapping[str, Any]) -> str:
    """Правило уровня рассуждения: auto, off или уровень low/medium/high из профиля; по умолчанию auto."""
    return str(gen["think"]) if gen.get("think") in THINK_RULES[1:] else "auto"


class ThinkChanged(LlmError):
    """Сведения о модели к отправке изменились: рассуждение было бы другим, чем у предела ответа, срока и ключа кэша
    запроса. Запрос не отправлен – находку разбирают повторно."""


def planned_think(rule: str, model: str, planned: Any) -> Callable[[Mapping[str, Any]], Any]:
    """Значение think на каждую отправку – то же, что рассчитано заранее (по нему выбраны предел ответа, срок и ключ
    кэша); модель на сервере изменилась так, что значение было бы другим, – ThinkChanged, запрос не уходит."""
    def per_send(info: Mapping[str, Any]) -> Any:
        actual = applied_think(rule, model, info)
        if actual != planned:
            raise ThinkChanged(f"Сведения о модели «{model}» на сервере изменились во время разбора (рассуждение): "
                               "запрос не отправлен – повторите разбор.")
        return actual
    return per_send


def model_thinks(info: Mapping[str, Any] | None) -> bool:
    """Модель умеет рассуждать: capabilities записи /api/tags (Ollama 0.40) содержат thinking."""
    caps = (info or {}).get("capabilities")
    return isinstance(caps, list) and "thinking" in caps


def applied_think(rule: str, model: str, info: Mapping[str, Any] | None) -> str | bool | None:
    """Значение поля think этого запроса (решает вызывающий, не клиент; ADR-0102):
      * gpt-oss (по сведениям сервера, без них – по имени): уровень low/medium/high; auto и off – low (ниже нельзя);
      * другая модель, которая умеет рассуждать (capabilities thinking): off – false, иначе true – рассуждение
        включено явно, с отдельным пределом ответа и сроком (request_options);
      * модель без рассуждения или без сведений о ней – None: поле не передаётся."""
    if is_gpt_oss(model, info):
        return rule if rule in THINK_LEVELS else "low"
    if not model_thinks(info):
        return None
    return rule != "off"


def code_profile_fits(profile: Mapping[str, Any], project: Mapping[str, Any] | None) -> bool:
    """Годится ли профиль для разбора кода этого проекта: Ollama своего контура (local, lan) – всегда; внешний профиль
    удалённого API (чат-завершения или Messages) – только при отметке проекта «код не секретный»; остальное – нет."""
    trust, kind = str(profile.get("trust") or ""), str(profile.get("kind") or "ollama")
    if kind == "ollama" and trust in ("local", "lan"):
        return True
    return kind in REMOTE_KINDS and trust == "external" and bool((project or {}).get("external_allowed"))


def choose_profile(db: Any, settings: Any, project: Mapping[str, Any] | None = None,
                   provider_id: int | None = None) -> dict[str, Any]:
    """Профиль для разбора кода: заданный явно → профиль проекта → профиль приложения по умолчанию. Профиль 1 из
    «Настроек», если его ещё нет (база до первого запуска 0.9.12, тестовая база), создаётся по действующим
    настройкам. Выключенный, несуществующий или не предназначенный для разбора кода – ProfileError."""
    from app.db import DEFAULT_PROVIDER_ID
    chosen = provider_id or (project or {}).get("provider_id") or getattr(settings, "default_provider_id", None) \
        or DEFAULT_PROVIDER_ID
    profile = db.get_provider(int(chosen))
    if profile is None and int(chosen) == DEFAULT_PROVIDER_ID:
        profile = db.ensure_default_profile(settings.ollama_url, settings.default_model)
    if profile is None:
        raise ProfileError(f"Профиль провайдера модели №{chosen} не найден: выберите профиль на странице проекта "
                           "или «Настройки».")
    if not profile.get("enabled"):
        raise ProfileError(f"Профиль провайдера модели «{profile.get('name')}» выключен: включите его на странице "
                           "«Настройки» или выберите для проекта другой профиль.")
    # разбор кода: Ollama – этот компьютер или сеть организации; внешний провайдер по удалённому API – только
    # проекту с действующей отметкой «код не секретный» (ADR-0104 п. 3, К9)
    if not code_profile_fits(profile, project):
        if str(profile.get("trust")) == "external" and str(profile.get("kind")) in REMOTE_KINDS:
            raise ProfileError(f"Профиль провайдера модели «{profile.get('name')}» – внешний: код уходит ему только "
                               "проекту с отметкой «код не секретный». Поставьте отметку в параметрах проекта.")
        raise ProfileError(f"Профиль провайдера модели «{profile.get('name')}»: класс доверия «{profile.get('trust')}» "
                           f"или вид «{profile.get('kind')}» не поддерживаются для разбора кода.")
    try:
        purposes = json.loads(str(profile.get("purposes_json") or "[]"))
    except ValueError:
        purposes = []
    if "code" not in purposes:
        raise ProfileError(f"Профиль провайдера модели «{profile.get('name')}» не предназначен для разбора кода.")
    return profile


def execution_values(profile: Mapping[str, Any], model: str, operation: str, num_ctx: int,
                     schema_mode: str, purpose: str = "code") -> dict[str, Any]:
    """Значения снимка исполнителя (строка llm_executions без id и даты): копия профиля без ключа и вычисленные
    параметры операции."""
    gen = generation(profile)
    num_ctx = int(gen.get("num_ctx") or num_ctx)  # окно профиля, иначе – общая настройка (MODEL_NUM_CTX)
    options = operation_options(operation, num_ctx, gen)
    return {
        "provider_id": int(profile["id"]), "provider_version": int(profile["version"]),
        "kind": str(profile["kind"]), "base_url": str(profile["base_url"]), "trust": str(profile["trust"]),
        "purpose": str(purpose), "model": str(model),
        # подтверждённые адреса и способ входа – копией (ADR-0102 п. 7–8): исполнение идёт только на эти адреса,
        # ключ берётся из файла при каждом запросе и только при совпадении привязки
        "options_json": json.dumps({"operation": operation, "options": options,
                                    "timeout_s": gen.get("timeout_s", CHAT_TIMEOUT_S if str(profile.get("kind"))
                                                         in REMOTE_KINDS else DEFAULT_TIMEOUT_S),
                                    # рассуждающий запрос (think true): свой предел ответа и срок
                                    "think_options": {"num_predict": thinking_predict(operation, num_ctx, gen)},
                                    "think_timeout_s": gen.get("think_timeout_s", THINK_TIMEOUT_S),
                                    "think": think_rule(gen), "allows_unload": unload_allowed(profile),
                                    "host_metrics": str(profile.get("trust")) == "local",
                                    "confirmed": confirmed_of(profile), "auth": str(profile.get("auth") or "none"),
                                    # удалённые API: формат ответа, рассуждение, предел, окно – копией профиля
                                    **({"chat": chat_settings(profile)}
                                       if str(profile.get("kind")) in REMOTE_KINDS else {})},
                                   ensure_ascii=False, sort_keys=True),
        "schema_mode": str(schema_mode or ""), "digest": "", "note": "",
    }


def confirmed_of(profile: Mapping[str, Any] | None) -> list[str]:
    """Подтверждённые адреса профиля (confirmed_addresses_json) в едином виде."""
    try:
        return normalize_addresses(json.loads(str((profile or {}).get("confirmed_addresses_json") or "[]")))
    except ValueError:
        return []


def _snapshot_data(execution: Mapping[str, Any] | None) -> dict[str, Any]:
    try:
        data = json.loads(str((execution or {}).get("options_json") or "{}"))
    except ValueError:
        data = {}
    return data if isinstance(data, dict) else {}


def server_of(executor: Mapping[str, Any]) -> Server:
    """Сервер профиля (поля llm_providers) или снимка исполнителя (llm_executions с options_json)."""
    trust = str(executor.get("trust") or "local")
    kind = str(executor.get("kind") or "ollama")
    if "options_json" in executor:  # снимок
        data = _snapshot_data(executor)
        confirmed, auth = normalize_addresses(data.get("confirmed") or []), str(data.get("auth") or "none")
        provider_id = executor.get("provider_id")
    else:
        confirmed, auth, provider_id = confirmed_of(executor), str(executor.get("auth") or "none"), executor.get("id")
    # резервное имя модели – только у Messages API (у снимка – модель прогона, у профиля – модель по умолчанию):
    # смена имени в профиле меняет ключ кэша списка моделей
    model = str(executor.get("model" if "options_json" in executor else "default_model") or "") \
        if kind == "messages" else ""
    return Server(str(executor.get("base_url") or ""), trust == "local", trust, tuple(confirmed),
                  int(provider_id) if provider_id is not None else None, auth, kind, model)


def configure(client: Any, server: Server, keys: Any = None, current_confirmed: Callable[[], Any] | None = None,
              provider: Mapping[str, Any] | None = None, admission: Callable[[], None] | None = None) -> Any:
    """Настроить клиент на сервер: класс доверия, подтверждённые адреса (current_confirmed – функция, которая на каждый
    запрос отдаёт действующие адреса), ключ с привязкой (только при auth = bearer), профиль – в журнал обмена,
    допуск (admission) и граница правки профиля (app/profile_gate.py) – на каждый запрос."""
    from app import profile_gate
    from app.provider_keys import auth_headers
    client.trust = server.trust
    client.confirmed = current_confirmed or server.confirmed
    if server.auth == "bearer":
        client.auth = lambda: auth_headers(keys, server.provider_id, server.base_url, server.confirmed,
                                           kind=server.kind)
    else:
        client.auth = None
    if provider is not None:
        client.provider = dict(provider)
    if server.provider_id is not None:
        client.gate = profile_gate.gate(server.provider_id).read
    if admission is not None:
        client.admission = admission
    return client


def _current_confirmed(db: Any, server: Server) -> Callable[[], tuple[str, ...]] | None:
    """У lan – функция действующих адресов: пересечение адресов снимка (или профиля) с профилем сейчас."""
    if server.trust != "lan" or db is None or server.provider_id is None:
        return None

    def current() -> tuple[str, ...]:
        now = set(confirmed_of(db.get_provider(server.provider_id)))
        return tuple(a for a in server.confirmed if a in now)

    return current


def service_client(make_client: Callable[[str], Any], server: Server, db: Any = None) -> Any:
    """Клиент служебных запросов страниц и наблюдения (версия, модели, метрики) к серверу профиля – по тем же
    правилам, что разбор: класс доверия, действующие подтверждённые адреса, ключ с привязкой, допуск (профиль
    включён) и граница правки профиля; профиль – в журнал обмена."""
    admission = send_guard(db, {"provider_id": server.provider_id}) if db is not None else None
    client = new_client(make_client, server.kind, server.base_url)
    if server.model and hasattr(client, "fallback_model"):  # Messages API: имя из профиля при недоступном /models
        client.fallback_model = server.model
    return configure(client, server, db, _current_confirmed(db, server),
                     {"id": server.provider_id, "trust": server.trust}, admission)


def snapshot_mismatch(profile: Mapping[str, Any] | None, execution: Mapping[str, Any]) -> str:
    """Почему по снимку уже нельзя работать или переносить его («Повторить ошибочные»), "" – можно: профиль выключен,
    адрес профиля сменился, у lan – изменились подтверждённые адреса (ADR-0102 п. 5, 7)."""
    if profile is None or not profile.get("enabled"):
        return f"Профиль провайдера модели «{(profile or {}).get('name') or execution.get('base_url')}» выключен."
    if str(profile.get("base_url")) != str(execution.get("base_url")):
        return f"Адрес профиля «{profile.get('name')}» изменился после этого прогона."
    if str(execution.get("trust")) == "lan" and set(server_of(profile).confirmed) != set(server_of(execution).confirmed):
        return f"Подтверждённые адреса профиля «{profile.get('name')}» изменились после этого прогона."
    return ""


LEGACY_EXECUTOR = "профиль не записан – разбор до 0.9.12"


def executor_info(db: Any, execution: Mapping[str, Any] | None, providers: Mapping[int, Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Кто исполнял (для страниц и журнала прогонов): {id, name, version, trust, where} профиля снимка; снимка нет –
    {"name": LEGACY_EXECUTOR, "trust": "", "where": ""}. Адреса сервера здесь нет – выгрузки журнала идут в общую
    таблицу команды."""
    if not execution:
        return {"id": None, "name": LEGACY_EXECUTOR, "version": None, "trust": "", "where": ""}
    pid = execution.get("provider_id")
    # providers – уже прочитанные профили, когда подпись нужна для целого списка
    profile = None if pid is None else (providers.get(int(pid)) if providers is not None else db.get_provider(int(pid)))
    trust = str(execution.get("trust") or "")
    where = {"local": "этот компьютер", "lan": "сеть организации", "external": "интернет"}.get(trust, trust)
    if not str(execution.get("base_url") or ""):  # снимок без адреса (ответ получен при сборке образа ВМ)
        where = str(execution.get("note") or "адрес не сохранён")
    return {"id": pid, "name": str((profile or {}).get("name") or f"профиль №{pid}"),
            "version": execution.get("provider_version"), "trust": trust, "where": where}


def executor_label(db: Any, execution: Mapping[str, Any] | None, providers: Mapping[int, Mapping[str, Any]] | None = None) -> str:
    """«Имя профиля (этот компьютер)» или «профиль не записан – разбор до 0.9.12»."""
    info = executor_info(db, execution, providers)
    return f"{info['name']} ({info['where']})" if info["where"] else info["name"]


def probe_generation(client: Any, model: str) -> float:
    """Пробная генерация под общим правом на генерацию (ADR-0099): во время прогона или вопроса – понятный отказ."""
    from app import model_traffic
    gate = gate_for({"trust": getattr(client, "trust", "local"), "base_url": getattr(client, "url", "")})
    if not gate.try_acquire("check"):
        raise ProbeBusy(f"Сейчас модель ({gate.label}) занята разбором или вопросом: проверьте генерацию после них.")
    try:
        with model_traffic.context(purpose="check"):
            return float(client.probe(model))
    finally:
        gate.release()


def capabilities(profile: Mapping[str, Any] | None) -> dict[str, Any]:
    try:
        value = json.loads(str((profile or {}).get("capabilities_json") or "{}"))
    except ValueError:
        value = {}
    return value if isinstance(value, dict) else {}


def unload_allowed(profile: Mapping[str, Any]) -> bool:
    """Можно ли выгружать модель на сервере профиля (медленный режим, ADR-0102 п. 9): у local – да, если профиль не
    запретил; у lan – только если разрешено в профиле (общий сервер может выполнять чужие задачи)."""
    caps = capabilities(profile)
    if str(profile.get("trust")) == "local":
        return caps.get("allows_unload") is not False
    return caps.get("allows_unload") is True


def snapshot_flag(execution: Mapping[str, Any] | None, name: str, default: bool) -> bool:
    """Признак из снимка исполнителя (allows_unload, host_metrics); снимка нет или признак не записан – default."""
    try:
        data = json.loads(str((execution or {}).get("options_json") or "{}"))
    except ValueError:
        data = {}
    value = data.get(name) if isinstance(data, dict) else None
    return value if isinstance(value, bool) else default


def _local(execution: Mapping[str, Any] | None) -> bool:
    """Снимок класса local или его нет (прогон до 0.9.12 шёл по Ollama этого компьютера)."""
    return execution is None or str(execution.get("trust") or "local") == "local"


def host_metrics_of(execution: Mapping[str, Any] | None) -> bool:
    """Показывать ли видеокарту, память и процессор этого компьютера для исполнителя: по снимку, а если признака в
    нём нет (снимки промежуточной 0.9.12) – только у local (ADR-0102 п. 9)."""
    return snapshot_flag(execution, "host_metrics", _local(execution))


def unload_allowed_of(execution: Mapping[str, Any] | None) -> bool:
    """Можно ли медленному режиму выгружать модель: по снимку, а если признака нет – только у local: у lan отсутствие
    разрешения не означает разрешения (ADR-0102 п. 9)."""
    return snapshot_flag(execution, "allows_unload", _local(execution))


def provider_key(execution: Mapping[str, Any] | None) -> tuple[int, int] | None:
    """(профиль, версия) снимка – часть ключа кэша вердиктов (ADR-0102 п. 13): разные серверы с одной моделью не
    делят кэш; снимка нет – None."""
    if not execution or execution.get("provider_id") is None:
        return None
    return int(execution["provider_id"]), int(execution.get("provider_version") or 0)


def thinking_limit(execution: Mapping[str, Any], think: Any) -> tuple[int | None, float]:
    """(предел ответа рассуждающего запроса, срок одного обращения) для значения think: рассуждающему (think true) –
    из снимка (у снимка без них – авто от окна), иначе (None, обычный срок)."""
    options, timeout, _ = snapshot_options(execution)
    if think is not True:
        return None, timeout
    data = _snapshot_data(execution)
    limit = (data.get("think_options") or {}).get("num_predict") or thinking_predict(
        str(data.get("operation") or "triage"), int(options.get("num_ctx") or DEFAULT_OPTIONS["num_ctx"]), {})
    return int(limit), float(data.get("think_timeout_s") or THINK_TIMEOUT_S)


def fit_thinking(options: Mapping[str, Any], limit: int | None, messages: Any) -> dict[str, Any]:
    """Параметры рассуждающего запроса: наибольший предел ответа не больше limit, при котором промпт помещается в
    окно. Промпт (срез кода) подбирается под обычный предел, как у любого запроса, – рассуждение получает остаток окна
    и кода у модели не отнимает; места нет – обычный предел."""
    from app.llm import prompt_fits
    base = {str(k): v for k, v in options.items()}
    low = int(base.get("num_predict") or 0)
    if not limit:
        return base
    if limit <= low:  # предел рассуждения меньше обычного – он и есть верхняя граница
        return {**base, "num_predict": int(limit)}
    if not prompt_fits(messages, base):
        return base
    if prompt_fits(messages, {**base, "num_predict": int(limit)}):
        return {**base, "num_predict": int(limit)}
    high = int(limit)
    while high - low > 64:  # наибольший подходящий предел с точностью до 64 токенов
        middle = (low + high) // 2
        if prompt_fits(messages, {**base, "num_predict": middle}):
            low = middle
        else:
            high = middle
    return {**base, "num_predict": low}


def snapshot_options(execution: Mapping[str, Any]) -> tuple[dict[str, Any], float, str]:
    """(параметры генерации, срок одного обращения, правило уровня рассуждения) из снимка исполнителя."""
    data = json.loads(str(execution.get("options_json") or "{}"))
    options = {str(k): v for k, v in dict(data.get("options") or {}).items()}
    timeout = float(data.get("timeout_s") or DEFAULT_TIMEOUT_S)
    rule = str(data.get("think") or "auto")
    return options, timeout, rule


def client_for(factory: Callable[[str], Any], execution: Mapping[str, Any],
               before_send: Callable[[], None] | None = None, *, db: Any = None,
               project_id: int | None = None) -> Any:
    """Клиент по снимку исполнителя: адрес, срок одного обращения, класс доверия и подтверждённые адреса из снимка;
    проверка допуска перед каждой отправкой (before_send). У lan адреса на каждый запрос – пересечение снимка и
    действующего профиля (оператор снял подтверждение – запрос не уходит). Ключ (auth = bearer) – из файла папки
    базы при каждом запросе, только при совпадении привязки с адресами снимка. У внешнего снимка с
    project_id – общая блокировка проекта вместе с блокировкой профиля до передачи байтов (К2): снятие отметки «код не
    секретный» ждёт начатую отправку, следующая её уже не проходит."""
    client = apply_chat(new_client(factory, str(execution.get("kind") or "ollama"), str(execution["base_url"])),
                        chat_settings(execution), str(execution.get("model") or ""))
    _, timeout, _ = snapshot_options(execution)
    client.timeout = timeout
    if before_send is not None:
        client.before_send = before_send
    server = server_of(execution)
    client = configure(client, server, db, _current_confirmed(db, server),
                       {"id": server.provider_id, "version": execution.get("provider_version"), "trust": server.trust},
                       before_send)
    if server.trust == "external" and project_id is not None:
        client.gate = _with_project_gate(client.gate, project_gate(project_id))
    return client


def _with_project_gate(profile_read: Callable[[], Any] | None, pgate: Any) -> Callable[[], Any]:
    """Контекст отправки: блокировка профиля (если есть) и общая блокировка проекта – до передачи байтов."""
    from contextlib import ExitStack, contextmanager

    @contextmanager
    def both():
        with ExitStack() as stack:
            if profile_read is not None:
                stack.enter_context(profile_read())
            stack.enter_context(pgate.read())
            yield

    return both


EXTERNAL_MARK_NOTE = ("Прогон на паузе. Поставьте отметку «код не секретный» в параметрах проекта или выберите "
                      "проекту профиль Ollama и нажмите «Продолжить».")


def project_gate(project_id: int) -> Any:
    """Блокировка проекта (К2): отправка кода внешнему провайдеру держит общую до передачи байтов, снятие отметки
    «код не секретный» – исключительную. Реестр отдельный от блокировок профилей."""
    from app import profile_gate
    with _project_gates_lock:
        return _project_gates.setdefault(int(project_id), profile_gate.ProfileGate())


_project_gates: dict[int, Any] = {}
_project_gates_lock = threading.Lock()


def external_code_allowed(db: Any, execution: Mapping[str, Any], project_id: int | None) -> None:
    """Код внешнему провайдеру – только проекту с действующей отметкой «код не секретный» (ADR-0104 п. 3, К9):
    проверяется перед каждой отправкой под блокировкой проекта (К2). Снимок своего контура (local, lan) отметки не
    требует."""
    if str(execution.get("trust") or "") != "external":
        return
    project = db.get_project(int(project_id)) if project_id is not None else None
    if not project or not project.get("external_allowed"):
        raise SendNotAllowed("Код этого проекта внешнему провайдеру не отправляется: отметки «код не секретный» нет.",
                             note=EXTERNAL_MARK_NOTE)
    link = db.catalog_link(int(project_id)) if hasattr(db, "catalog_link") else None
    if link is not None:  # и Demo Library из каталога: согласие – для корня, где дано (ревью круга 7)
        # проект из каталога: согласие давалось на код папки примеров, где оно поставлено; папка сменилась (другой
        # корень с той же базой) или сверка корня при запуске не прошла – отправки нет (ADR-0157)
        from app.examples import ROOT_NOW
        now = ROOT_NOW["value"]  # корень этого процесса после успешной сверки при запуске; не сверено – None
        if not now or link.get("mark_root") != now:
            raise SendNotAllowed("Код проекта из каталога внешнему провайдеру не отправляется: отметка «код не "
                                 "секретный» дана для другой папки примеров. Поставьте отметку заново на странице "
                                 "предпросмотра.", note=EXTERNAL_MARK_NOTE)


def send_guard(db: Any, execution: Mapping[str, Any], project_id: int | None = None) -> Callable[[], None]:
    """Проверка непосредственно перед отправкой /api/chat (и перед повтором): профиль снимка включён; у внешнего
    снимка – отметка проекта «код не секретный» действует. Иначе SendNotAllowed: запрос не уходит."""
    provider_id = execution.get("provider_id")

    def check() -> None:
        if provider_id is None:
            return
        profile = db.get_provider(int(provider_id))
        if profile is None or not profile.get("enabled"):
            name = (profile or {}).get("name") or f"№{provider_id}"
            raise SendNotAllowed(f"Профиль провайдера модели «{name}» выключен: запрос к модели не отправлен.")
        external_code_allowed(db, execution, project_id)

    return check

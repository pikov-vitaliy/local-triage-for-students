"""Клиент сервера модели по API чат-завершений (0.9.13, ADR-0104): список моделей (/models), ответ модели объектом
JSON (/chat/completions) и один ход диалога с инструментами (chat_turn) – для исследования компонентов (ADR-0105).
Соединение, допуск, ключ и журнал обмена – общий транспорт app/llm_http.py.

Отличия от Ollama:
  * у класса external – только https и глобальные адреса (app/llm_net.external_target); у local и lan – как у Ollama;
  * отпечатка весов, загруженных моделей и выгрузки нет: кэш вердиктов у таких моделей не ведётся (ADR-0084);
  * длительностей сервер не отдаёт: время – часами приложения (LlmStats.timing = "app"), скорость токенов и время
    загрузки – «неизвестно»: 0 в LlmStats (все потребители считают 0 отсутствием: фильтры > 0, показ по условию –
    формат записей 0.9.12 не меняется); токены рассуждения и попадания в кэш провайдера – отдельными полями;
  * повторы по одному бюджету на обращение (К3 плана 0.9.13): не больше трёх отправок всего – повтор после 429 и
    временных ошибок сервера (один раз, с ожиданием Retry-After, не дольше 60 с) и повтор не по формату считаются
    вместе; 402 и сбой после начала передачи («результат неизвестен», LlmError.sent) – без повтора;
  * имена моделей – как у провайдера, без нормализации Ollama (`:latest`, регистр).
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import time
import urllib.parse
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from app import model_traffic
from app.llm import (RAW_KEEP, LlmError, PromptOverflowError, ResolveError, _one_line, _seconds, answer_schema, check_answer,
                     estimate_tokens, extract_answer, retry_message)
from app.llm_http import ServerClient, _scrub_error, _scrub_value, track_sent, tracked
from app.llm_net import ALLOWED_HOSTS, _ip, _os_error_text, _Target, _TooLarge, external_target, lan_address_ok
from app.models import LlmStats

RESPONSE_MODES = ("json_schema", "json_object", "none")  # формат ответа модели (поле response_format)
THINKING_MODES = ("", "enabled", "disabled")  # поле thinking: не передавать / включено / выключено
EFFORT_LEVELS = ("", "none", "minimal", "low", "medium", "high", "max")  # поле reasoning_effort
MAX_SENDS = 3  # отправок на одно обращение – всего, вместе с повторами
MAX_WAIT_S = 60.0  # дольше не ждём, даже если сервер просит (Retry-After)
DEFAULT_WAIT_S = 2.0  # временная ошибка сервера без Retry-After
# 429 и временные ошибки сервера (К3). 502 и 504 – шлюз не дождался провайдера: запрос мог быть обработан и оплачен,
# поэтому не повторяются (неизвестный результат, ревью A4)
RETRY_STATUSES = (429, 500, 503)
STOP_STATUSES = (401, 402, 403)  # ключ или оплата: повтор бесполезен, работа останавливается с причиной
_FINISH_ERRORS = {
    "content_filter": "ответ остановлен фильтром содержимого провайдера",
    "insufficient_system_resource": "у провайдера не хватило ресурсов – ответ прерван",
    "aborted": "ответ прерван сервером",
}


def _status_text(status: int) -> str:
    return {
        400: "запрос не принят (неверный формат)",
        401: "ключ API не принят – проверьте ключ в профиле",
        402: "на счёте провайдера нет средств – пополните баланс в личном кабинете",
        403: "доступ запрещён – проверьте ключ и права в личном кабинете",
        404: "адрес или модель не найдены – проверьте адрес профиля и имя модели",
        422: "параметры запроса не приняты – проверьте модель, формат ответа и рассуждение в профиле",
        429: "превышен предел запросов провайдера",
        500: "сбой сервера провайдера",
        502: "сбой шлюза провайдера",
        503: "сервер провайдера перегружен",
        504: "сервер провайдера не дождался ответа",
    }.get(status, "ошибка сервера")


def _error_detail(body: bytes) -> str:
    """Текст ошибки из тела ответа: {"error": {"message": ...}}, {"error": "..."} или {"message": ...}."""
    text = body[:64 * 1024].decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):
        return _one_line(text)
    if isinstance(parsed, dict):
        error = parsed.get("error")
        if isinstance(error, dict) and error.get("message"):
            return _one_line(error["message"])
        if isinstance(error, str) and error:
            return _one_line(error)
        if parsed.get("message"):
            return _one_line(parsed["message"])
    return _one_line(text)


def _retry_after(headers: Mapping[str, str], now: float | None = None) -> float | None:
    """Retry-After в секундах или датой HTTP -> секунды ожидания (не меньше 0); нераспознанное – None."""
    import email.utils
    for key, value in headers.items():
        if key.lower() == "retry-after":
            text = str(value).strip()
            try:
                return max(0.0, float(text))
            except ValueError:
                pass
            try:
                when = email.utils.parsedate_to_datetime(text)
            except (TypeError, ValueError, IndexError):
                return None
            if when is None or when.tzinfo is None:
                return None
            return max(0.0, when.timestamp() - (time.time() if now is None else now))
    return None


def message_tokens(messages: Iterable[Mapping[str, Any]]) -> int:
    """Оценка длины истории сверху – по всем полям сообщения (рассуждение, вызовы инструментов, их результаты), а не
    только по content (К5 плана 0.9.13)."""
    return sum(estimate_tokens(json.dumps(m, ensure_ascii=False)) for m in messages)


@dataclass
class TurnResult:
    """Один ход диалога: сообщение ассистента целиком (как пришло – с рассуждением и вызовами инструментов, его
    возвращают в историю), причина завершения, расход по usage."""

    message: dict[str, Any]
    finish_reason: str
    usage: dict[str, int] = field(default_factory=dict)
    seconds: float = 0.0
    sends: int = 1
    http_retries: int = 0  # повторов транспорта (429, временные ошибки) внутри хода – на строку он один (К3)

    @property
    def content(self) -> str:
        return str(self.message.get("content") or "")

    @property
    def tool_calls(self) -> list[dict[str, Any]]:
        calls = self.message.get("tool_calls")
        return [c for c in calls if isinstance(c, dict)] if isinstance(calls, list) else []


def usage_stats(model: str, usage: Mapping[str, int], sends: int) -> LlmStats:
    """Замеры известной ошибки после полученного ответа (finish_error, stop_reason, ответ не по протоколу): расход
    ответа не теряется – его суммируют прогон, вопрос и исследование (ревью круг 15, находка 5)."""
    return LlmStats(model=model, prompt_tokens=int(usage.get("prompt_tokens") or 0),
                    output_tokens=int(usage.get("completion_tokens") or 0), eval_tps=0.0, prompt_tps=0.0, total_s=0.0,
                    load_s=0.0, attempts=int(sends), think="-", reasoning_tokens=int(usage.get("reasoning_tokens") or 0),
                    cache_hit_tokens=int(usage.get("cache_hit_tokens") or 0), timing="app")


def _usage(data: Any) -> dict[str, int]:
    raw = data.get("usage") if isinstance(data, dict) and isinstance(data.get("usage"), dict) else {}
    details = raw.get("completion_tokens_details") if isinstance(raw.get("completion_tokens_details"), dict) else {}

    def count(value: Any) -> int:
        return int(value) if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0
    return {"prompt_tokens": count(raw.get("prompt_tokens")), "completion_tokens": count(raw.get("completion_tokens")),
            "reasoning_tokens": count(details.get("reasoning_tokens")),
            "cache_hit_tokens": count(raw.get("prompt_cache_hit_tokens"))}


class ChatCompletionsClient(ServerClient):
    """Клиент API чат-завершений. Параметры профиля (снимка исполнителя) задаёт вызывающий: response_mode, thinking,
    effort, max_output, context_window."""

    def __init__(self, url: str, timeout: float = 600) -> None:
        super().__init__(url, timeout)
        self.trust = "external"
        self.response_mode = "json_object"
        self.thinking = ""  # поле thinking: "" – не передавать
        self.effort = ""  # поле reasoning_effort: "" – не передавать
        self.max_output = 8192  # предел ответа (max_tokens), если вызывающий не задал своего
        self.context_window: int | None = None  # окно модели из профиля: промпт + ответ; None – не проверять
        self.sleep: Callable[[float], None] = time.sleep  # ожидание перед повтором (точка подмены в тестах)
        self.generate_path = "/chat/completions"  # путь генерации протокола (у Messages API – /messages)
        self.retry_statuses: tuple[int, ...] = RETRY_STATUSES  # статусы с одним повтором (у Messages API + 529)
        self.protocol_name = "API чат-завершений"  # в текстах диагностики

    # ---------------------------------------------------------------- адрес

    def _target(self) -> _Target:
        if self.trust == "external":
            return external_target(self.url)
        if self.trust not in ("local", "lan"):
            raise LlmError(f"Класс доверия «{self.trust}» не поддерживается: запрос к модели не отправлен.")
        hint = (f"нужен адрес вида http://127.0.0.1:8080/v1; разрешённые хосты: {', '.join(ALLOWED_HOSTS)}"
                if self.trust == "local" else "нужен адрес сервера в сети организации, например http://10.0.0.5:8000/v1")
        if not self.url:
            raise LlmError(f"Адрес сервера модели не задан: {hint}.")
        try:
            parts = urllib.parse.urlsplit(self.url)
        except ValueError:
            raise LlmError(f"Адрес сервера модели не распознан: {hint}.") from None
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.netloc or "@" in parts.netloc:
            raise LlmError(f"Адрес сервера модели не распознан (без имени и пароля): {hint}.")
        host = (parts.hostname or "").lower()
        if self.trust == "local" and host not in ALLOWED_HOSTS:
            raise LlmError(f"Сервер «{host}» не входит в разрешённые – запрос не отправлен, код находок не должен "
                           f"покидать компьютер: {hint}.")
        if self.trust == "lan":
            ip = _ip(host)
            if not host or ip is not None and not lan_address_ok(ip):
                raise LlmError(f"Адрес сервера «{host}» – не частная сеть: запрос не отправлен, {hint}.")
        try:
            port = parts.port
        except ValueError:
            raise LlmError(f"В адресе сервера модели неверный порт: {hint}.") from None
        if parts.query or parts.fragment:
            raise LlmError(f"В адресе сервера модели не должно быть «?» и «#»: {hint}.")
        prefix = parts.path.rstrip("/")
        base = urllib.parse.urlunsplit((scheme, parts.netloc, prefix, "", ""))
        return _Target(scheme, host, port or (443 if scheme == "https" else 80), prefix, base)

    # ---------------------------------------------------------------- ответ сервера

    def _finish(self, t: _Target, path: str, status: int, body: bytes, secrets: tuple[str, ...],
                headers: dict[str, str]) -> Any:
        if 300 <= status < 400:
            raise LlmError(f"Сервер {t.base} ответил перенаправлением (HTTP {status}) на {path}. Перенаправления не "
                           "выполняются: укажите адрес сервера напрямую.", status=status)
        if status >= 400:
            detail = model_traffic.scrub(_error_detail(body), secrets)
            error = LlmError(f"Сервер модели ({t.base}) ответил HTTP {status} на {path}: {_status_text(status)}."
                             + (f" Ответ сервера: {detail[:200]}" if detail else ""), status=status, detail=detail)
            error.retry_after = _retry_after(headers)
            raise _scrub_error(error, secrets)
        if not body.strip():
            if getattr(self, "strict_body", False):  # клиент OSV (app/osv.py): пустое тело – не ответ, а сбой
                raise LlmError(f"Сервер {t.base} ответил на {path} пустым телом: ответа нет.", reason="bad_response")
            return {}
        try:
            return _scrub_value(json.loads(body.decode("utf-8")), secrets)
        except (ValueError, RecursionError):
            # ответ получен целиком, но не JSON – исход известен (ревью круг 16): обрыв и 502/504 классифицируются отдельно
            raise LlmError(f"Ответ сервера {t.base} на {path} – не JSON: по этому адресу, похоже, не "
                           f"{self.protocol_name}.", reason="bad_response") from None

    @staticmethod
    def _connect_timeout_error(t: _Target, timeout: float) -> LlmError:
        return LlmError(f"Сервер модели не отвечает по адресу {t.base}: соединение не установлено. Проверьте адрес "
                        "в профиле и доступ к сети.")

    @staticmethod
    def _transport_error(error: BaseException, t: _Target, path: str, timeout: float, expired: bool) -> LlmError:
        if expired or isinstance(error, TimeoutError):
            return LlmError(f"Нет ответа от сервера модели ({t.base}) за {_seconds(timeout)} на {path}.")
        if isinstance(error, _TooLarge):
            return LlmError(f"Ответ сервера модели ({t.base}) на {path} слишком большой.")
        if isinstance(error, ConnectionRefusedError):
            return LlmError(f"Сервер модели не отвечает по адресу {t.base}: соединение отклонено.")
        if isinstance(error, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError,
                              http.client.HTTPException)):
            return LlmError(f"Связь с сервером модели ({t.base}) прервана на {path}: сервер закрыл соединение, не "
                            "дослав ответ.")
        if type(error).__name__ in ("SSLCertVerificationError", "SSLError", "CertificateError"):
            return LlmError(f"Сертификат сервера {t.base} не прошёл проверку: соединение не установлено.")
        return LlmError(f"Сервер модели не отвечает по адресу {t.base} ({path}): {_os_error_text(error)}.")

    # ---------------------------------------------------------------- сведения о сервере

    MODELS_REUSE_S = 5.0

    def _models_once(self) -> list[dict[str, Any]]:
        """Список /models для version() и list_models() одного опроса: ответ, полученный не раньше MODELS_REUSE_S
        секунд назад, используется снова – опрос версии и списка стоит один GET /models, а не два (модель и
        провайдера не спрашиваем лишний раз)."""
        memo = getattr(self, "_models_memo", None)
        now = time.monotonic()
        if memo is not None and now - memo[0] <= self.MODELS_REUSE_S:
            return memo[1]
        items = self._models()
        self._models_memo = (now, items)
        return items

    def _models(self) -> list[dict[str, Any]]:
        data = self._request("/models")
        items = data.get("data") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise LlmError(f"В ответе /models нет списка моделей: по адресу {self.check_url()}, похоже, не "
                           f"{self.protocol_name}.")
        return [item for item in items if isinstance(item, dict) and str(item.get("id") or "").strip()]

    @tracked
    def version(self) -> str:
        """Сервер жив: /models отвечает. Генерацию выбранной моделью это не доказывает – это «Пробный ответ»."""
        return f"API чат-завершений, моделей: {len(self._models_once())}"

    @tracked
    def list_models(self) -> list[dict[str, Any]]:
        """Модели провайдера в общем виде (как у Ollama): name = id; объём, параметры и возможности неизвестны."""
        result = [{"name": str(item["id"]).strip(), "size": 0, "digest": "", "params": "", "quant": "",
                   "family": str(item.get("owned_by") or ""), "context_length": None, "capabilities": None}
                  for item in self._models_once()]
        return sorted(result, key=lambda x: x["name"].casefold())

    def ps(self) -> list[dict[str, Any]]:
        return []

    def unload_model(self, model: str) -> dict[str, Any]:
        raise LlmError("Выгрузка модели у провайдера по API чат-завершений не поддерживается.")

    @tracked
    def model_info(self, model: str) -> dict[str, Any]:
        """Запись модели из /models (точное совпадение имени) или {"name": …}: отпечатка весов нет никогда."""
        name = str(model or "").strip()
        for item in self.list_models():
            if item["name"] == name:
                return item
        return {"name": name, "digest": ""}

    # ---------------------------------------------------------------- запрос модели

    def _body(self, model: str, messages: list[dict[str, Any]], max_tokens: int,
              response_format: dict[str, Any] | None, tools: list[dict[str, Any]] | None) -> dict[str, Any]:
        body: dict[str, Any] = {"model": model, "messages": messages, "stream": False, "max_tokens": int(max_tokens)}
        if response_format is not None:
            body["response_format"] = response_format
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"  # принудить к вызову в режиме рассуждения нельзя (справка провайдера)
        if self.thinking:
            body["thinking"] = {"type": self.thinking}
        if self.effort:
            body["reasoning_effort"] = self.effort
        return body

    def _response_format(self, fields: Mapping[str, str], required: Iterable[str],
                         enums: Mapping[str, Iterable[str]], types: Mapping[str, str] | None = None
                         ) -> dict[str, Any] | None:
        """Поле response_format chat_json по режиму профиля: json_schema со схемой ответа, json_object или None."""
        if self.response_mode == "json_schema":
            schema = answer_schema(fields, list(required), {k: list(v) for k, v in enums.items()}, types)
            return {"type": "json_schema", "json_schema": {"name": "answer", "schema": schema}}
        return {"type": "json_object"} if self.response_mode == "json_object" else None

    def json_overhead(self, fields: Mapping[str, str], required: Iterable[str], enums: Mapping[str, Iterable[str]],
                      types: Mapping[str, str] | None = None) -> int:
        """Сколько токенов (оценка сверху) chat_json добавит к сообщениям в проверке размера (_check_size): формат
        ответа по профилю. Подгонка среза вычитает это из окна профиля (KIMI-01)."""
        response_format = self._response_format(fields, required, enums, types)
        return estimate_tokens(json.dumps(response_format, ensure_ascii=False)) if response_format else 0

    def _check_size(self, messages: list[dict[str, Any]], max_tokens: int, extra: Any = None) -> None:
        if not self.context_window:
            return
        estimate = message_tokens(messages) + (estimate_tokens(json.dumps(extra, ensure_ascii=False)) if extra else 0)
        if estimate + max_tokens > self.context_window:
            raise PromptOverflowError(f"Промпт (до {estimate} токенов) вместе с ответом ({max_tokens}) не помещается в "
                                      f"окно модели из профиля ({self.context_window} токенов): запрос не отправлен.")

    def _post(self, body: dict[str, Any], budget: dict[str, Any]) -> dict[str, Any]:
        """Одна отправка с допуском и не больше одного повтора после 429 и временных ошибок сервера – в общем
        бюджете обращения (budget: sends, deadline)."""
        limit = int(budget.get("max_sends") or MAX_SENDS)
        while True:
            # предел отправок и общий срок проверяются до отправки и до счётчика: запрос не уходит, исход известен
            # (reason) – прежние ответы получены, новая отправка не начата (ревью круг 15, находка 7)
            if budget["sends"] >= limit:
                raise LlmError(f"Исчерпан предел отправок на одно обращение ({limit}): ответ не получен.",
                               reason="budget")
            left = budget["deadline"] - time.monotonic()
            if left <= 0:
                raise LlmError(f"Истёк срок обращения к модели ({int(self.timeout)} с): ответ не получен.",
                               reason="deadline")
            if self.before_send is not None:
                self.before_send()
            budget["sends"] += 1
            try:
                return self._request(self.generate_path, body, timeout=left)
            except LlmError as e:
                if isinstance(e, ResolveError):
                    budget["sends"] -= 1  # имя сервера не разрешилось – запрос не отправлен и отправкой не считается
                if (e.status in self.retry_statuses and not budget["http_retried"] and budget["sends"] < limit):
                    wait = min(MAX_WAIT_S, e.retry_after if e.retry_after is not None else DEFAULT_WAIT_S)
                    if time.monotonic() + wait < budget["deadline"]:
                        budget["http_retried"] = True
                        budget["http_retries"] = int(budget.get("http_retries") or 0) + 1
                        self.sleep(wait)
                        continue
                raise

    def chat_turn(self, model: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
                  max_tokens: int | None = None, response_format: dict[str, Any] | None = None,
                  max_sends: int | None = None, deadline: float | None = None,
                  allow_http_retry: bool = True) -> TurnResult:
        """Один ход диалога (цикл инструментов исследования, ADR-0105): сообщение ассистента целиком, как пришло, без
        проверки контракта. max_sends, deadline и allow_http_retry – остаток общего бюджета строки (К3): повтор
        транспорта не выходит за него и на строку бывает один. Ошибки – LlmError с sent (К11) и числом отправок
        (LlmError.sends)."""
        limit = int(max_tokens or self.max_output)
        self._check_size(messages, limit, [tools, response_format])
        own = time.monotonic() + self.timeout
        budget = {"sends": 0, "http_retried": not allow_http_retry, "http_retries": 0,
                  "deadline": min(own, deadline) if deadline else own,
                  "max_sends": max(1, min(MAX_SENDS, int(max_sends))) if max_sends else MAX_SENDS}
        started = time.monotonic()
        try:
            with track_sent():
                data = self._post(self._body(str(model), messages, limit, response_format, tools), budget)
                got = _usage(data)  # расход – до проверки структуры: он оплачен и при ответе не по протоколу
                try:
                    choice = _first_choice(data)
                except LlmError as e:
                    e.stats = usage_stats(str(model), got, budget["sends"])
                    raise
                message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
                finish = str(choice.get("finish_reason") or "")
                if finish in _FINISH_ERRORS:
                    raise LlmError(f"Модель не ответила: {_FINISH_ERRORS[finish]}.", detail=finish,
                                   reason="finish_error", stats=usage_stats(str(model), got, budget["sends"]))
        except LlmError as e:
            e.sends = budget["sends"]
            e.http_retries = budget["http_retries"]  # повтор транспорта был, даже если отправок осталось одна (DNS после 429)
            raise _scrub_error(e, self._secrets) from None
        return TurnResult(message=dict(message), finish_reason=finish, usage=_usage(data),
                          seconds=round(time.monotonic() - started, 3), sends=budget["sends"],
                          http_retries=budget["http_retries"])

    def chat_json(self, model: str, messages: list[dict[str, Any]], fields: Mapping[str, str],
                  required: Iterable[str], enums: Mapping[str, Iterable[str]], options: Mapping[str, Any] | None = None,
                  think: Any = None, types: Mapping[str, str] | None = None,
                  validate: Callable[[dict[str, Any]], Iterable[str]] | None = None, progress=None,
                  json_schema: str = "", max_tokens: int | None = None) -> tuple[dict[str, Any], LlmStats]:
        """Ответ модели объектом JSON -> (объект, замеры) – тот же контракт, что у клиента Ollama (fields, required,
        enums, types, validate). Формат ответа – по профилю (response_mode); рассуждение – поля профиля (think
        вызывающего здесь не применяется: у провайдера свои поля). Предел ответа – max_output профиля (снимка);
        options.num_predict – параметр Ollama и здесь не применяется: предел 3072 разбора
        обрывает ответы рассуждающей модели при пределе профиля 8192 (ADR-0106 п. 9). max_tokens – явный предел
        вызывающего (пробный ответ)."""
        name = str(model or "").strip()
        required = list(required)
        enums = {k: list(v) for k, v in enums.items()}
        limit = int(max_tokens or self.max_output)
        response_format = self._response_format(fields, required, enums, types)
        history = [dict(m) for m in messages]
        budget = {"sends": 0, "http_retried": False, "deadline": time.monotonic() + self.timeout}
        started = time.monotonic()
        totals = {"prompt_tokens": 0, "completion_tokens": 0, "reasoning_tokens": 0, "cache_hit_tokens": 0}
        content = ""
        problems: list[str] = []
        think_label = ",".join(p for p in (self.thinking, self.effort) if p) or "-"

        def stats() -> LlmStats:
            return LlmStats(model=name, prompt_tokens=totals["prompt_tokens"], output_tokens=totals["completion_tokens"],
                            eval_tps=0.0, prompt_tps=0.0, total_s=round(time.monotonic() - started, 3), load_s=0.0,
                            attempts=budget["sends"], think=think_label, reasoning_tokens=totals["reasoning_tokens"],
                            cache_hit_tokens=totals["cache_hit_tokens"], timing="app")

        try:
            with track_sent():
                while True:
                    self._check_size(history, limit, response_format)
                    data = self._post(self._body(name, history, limit, response_format, None), budget)
                    usage = _usage(data)  # расход – до проверки структуры: он оплачен и при ответе не по протоколу
                    for key in totals:
                        totals[key] += usage[key]
                    choice = _first_choice(data)  # null или [] вместо объекта – известная ошибка bad_response
                    message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
                    content = str(message.get("content") or "")
                    finish = str(choice.get("finish_reason") or "")
                    if finish in _FINISH_ERRORS:
                        raise LlmError(f"Модель не ответила: {_FINISH_ERRORS[finish]}.", detail=finish, stats=stats(),
                                       reason="finish_error")
                    obj, why = extract_answer(content, [*fields, *required])
                    if obj is None:
                        problems = [why or ("пустой ответ" if not content.strip() else "в ответе нет объекта JSON")]
                    else:
                        obj, problems = check_answer(obj, required, enums, types)
                        if not problems and validate is not None:
                            problems = [str(p) for p in validate(obj) if str(p).strip()]
                    if not problems:
                        # объект JSON, закрытый до обрыва по длине и прошедший проверку, принимается – как у Ollama:
                        # он целый (К3 в редакции 4 плана)
                        return _scrub_value(obj, self._secrets), stats()
                    if finish == "length":
                        raise LlmError(f"Ответ модели оборван: исчерпан предел длины ответа ({limit} токенов). "
                                       "Увеличьте предел ответа в профиле.", stats=stats(), reason="length", raw=content[:RAW_KEEP])
                    if budget["sends"] >= MAX_SENDS:
                        raise LlmError(f"Модель ответила не по формату: {'; '.join(problems[:5])}.", stats=stats(), reason="bad_format",
                                       raw=content[:RAW_KEEP])
                    history = [dict(m) for m in messages] + [
                        {"role": "assistant", "content": content[:RAW_KEEP]},
                        {"role": "user", "content": retry_message(problems, fields, enums)}]
        except LlmError as e:
            if e.stats is None:
                e.stats = stats()
            raise _scrub_error(e, self._secrets) from None

    @tracked
    def probe(self, model: str, timeout: float | None = None) -> float:
        """«Пробный ответ»: один короткий ответ выбранным форматом и рассуждением -> секунды. Расходует токены. Предел
        ответа и срок – те же, что у разбора (профиль): проба проверяет настройки, с которыми пойдёт работа
        (ревью круг 15, находка 4); timeout – только если вызывающий задал свой."""
        saved = self.timeout
        if timeout is not None:
            self.timeout = float(timeout)
        started = time.monotonic()
        try:
            self.chat_json(model, [{"role": "user", "content": "Ответь объектом JSON {\"ok\": true}."}],
                           {"ok": "true"}, ["ok"], {}, types={"ok": "bool"}, max_tokens=self.max_output)
        finally:
            self.timeout = saved
        return round(time.monotonic() - started, 3)


    # ---------------------------------------------------------------- поисковый API провайдера (исследование)

    @tracked
    def search(self, path: str, query: str, count: int = 5, deadline: float | None = None) -> dict[str, Any]:
        """Поиск поисковым API провайдера: POST <путь от корня адреса профиля> {query, count}. Тот же адрес, класс
        доверия и ключ, что у модели (ADR-0105). Ответ – как прислал провайдер (без ключа)."""
        query = " ".join(str(query or "").split())[:128]
        if not query:
            raise LlmError("Пустой поисковый запрос: не отправлен.")
        if self.before_send is not None:
            self.before_send()
        data = self._tool_call(path, {"query": query, "count": max(1, min(int(count or 5), 20))}, deadline,
                               "выполнить поиск")
        return data if isinstance(data, dict) else {"results": data}

    def _tool_call(self, path: str, payload: dict[str, Any], deadline: float | None, action: str) -> Any:
        """Запрос инструмента: 404 от поискового API – не «адрес или модель не найдены» (это про сервер модели), а
        отказ провайдера выполнить действие (страница недоступна, запрос отклонён); статус сохраняется."""
        try:
            return self._request(path, payload, timeout=self._tool_timeout(deadline), origin_path=True)
        except LlmError as e:
            if e.status == 404:
                raise LlmError(f"Провайдер не смог {action}: страница или запрос отклонены (HTTP 404)"
                               + (f". Ответ сервера: {e.detail}" if e.detail else ""), status=404, detail=e.detail,
                               stats=e.stats) from None
            raise

    def post_json(self, path: str, payload: dict[str, Any], timeout: float) -> Any:
        """POST JSON по пути от корня адреса, не чат: точный запрос OSV (app/osv.py, ADR-0112). Те же правила адреса,
        соединения и журнала обмена, что у запросов модели; ответ – разобранный JSON или LlmError."""
        return self._request(path, payload, timeout=timeout, origin_path=True)

    def _tool_timeout(self, deadline: float | None) -> float:
        """Срок запроса инструмента: не больше 120 с, срока профиля и остатка общего срока строки (К3)."""
        limit = min(self.timeout, 120.0)
        if deadline is not None:
            limit = min(limit, max(0.1, deadline - time.monotonic()))
        return limit

    @tracked
    def fetch(self, path: str, url: str, deadline: float | None = None) -> dict[str, Any]:
        """Страница по адресу через провайдера: POST <путь от корня адреса профиля> {url}. Приложение адрес само не
        открывает; проверка адреса – check_fetch_url (вызывающий)."""
        if self.before_send is not None:
            self.before_send()
        data = self._tool_call(path, {"url": url}, deadline, "получить страницу")
        return data if isinstance(data, dict) else {"content": data}


def _first_choice(data: Any) -> dict[str, Any]:
    choices = data.get("choices") if isinstance(data, dict) else None
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        # ответ получен (HTTP 200), но не по протоколу – исход известен (ответ получен –
        # обычная ошибка и обычный повтор)
        raise LlmError("В ответе сервера нет выбора модели (choices): ответ не по протоколу чат-завершений.",
                       reason="bad_response")
    return choices[0]


def check_fetch_url(url: Any) -> str:
    """Адрес страницы для fetch от модели (ADR-0105): только http(s), без имени и пароля, не длиннее 2000 знаков, не
    localhost и не адрес-число внутренней сети. Что делает с адресом сам провайдер, приложение не контролирует. LlmError.
    Возвращает канонический адрес (ADR-0111, ревью Codex круги 30–31): схема и имя узла в нижнем регистре, без точки
    в конце имени, числовой IPv6 – в сжатой записи в скобках, без стандартного порта (80/443), пустой путь – «/»;
    пустые «?» и «#» отпадают; непустые путь, параметры и якорь не меняются – они могут обозначать разные страницы
    (якорь уходит провайдеру как часть аргумента; что он с ним делает – приложение не знает). Один и тот же адрес в
    разной записи даёт один отпечаток и один запрос."""
    from app import llm_net  # правило адресов – из модуля при каждом вызове (подменяется в тестах там)
    text = str(url or "").strip()
    if not text or len(text) > 2000:
        raise LlmError("Адрес страницы пуст или длиннее 2000 знаков.")
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        raise LlmError("Адрес страницы не распознан.") from None
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc or "@" in parts.netloc:
        raise LlmError("Адрес страницы – только http(s) без имени и пароля.")
    host = (parts.hostname or "").lower().rstrip(".")
    ip = _ip(host)
    if not host or host == "localhost" or host.endswith(".localhost") or host.endswith(".local")             or "." not in host and ip is None or ip is not None and not llm_net.external_address_ok(ip):
        raise LlmError(f"Адрес страницы «{host}» – не адрес в интернете: не запрошен.")
    scheme = parts.scheme.lower()
    try:
        port = parts.port
    except ValueError:
        raise LlmError("Адрес страницы: порт не распознан.") from None
    if ":" in host:
        # числовой IPv6 – в сжатой записи того же семейства: [2606:4700:4700:0:0:0:0:1111] и [2606:4700:4700::1111],
        # [::ffff:8.8.8.8] и [0:0:0:0:0:ffff:808:808] – один адрес (_ip отдаёт для mapped-адреса IPv4 – он здесь не
        # подходит, ревью Codex круг 32)
        try:
            host = str(ipaddress.IPv6Address(host))
        except ValueError:
            pass
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != (443 if scheme == "https" else 80):
        netloc += f":{port}"
    return urllib.parse.urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))

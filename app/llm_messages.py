"""Клиент сервера модели по Messages API (0.9.14, ADR-0106): второй формат внешних провайдеров. Наследует клиент
API чат-завершений (адреса по классу доверия, разбор статусов, бюджет отправок, поисковый API) и переопределяет
то, что у протокола другое:
  * `POST /messages`: системное сообщение – отдельным полем `system`, содержимое – блоками (`text`, `tool_use`,
    `tool_result`), `max_tokens` обязателен; секрет ключа – заголовок `x-api-key` (app/provider_keys.key_headers),
    служебный заголовок `anthropic-version` – через protocol_headers() общего транспорта (не секрет);
  * ответ по схеме (chat_json) – инструментом `answer` с `input_schema` и принудительным выбором (режимы `tool`,
    `tool_strict`), либо текстом с извлечением JSON приложением (`none`); проверка приложением всегда;
  * ход с инструментами (chat_turn) – вызовы нормализуются в формат приложения (`function.arguments` – строка JSON),
    результаты одного хода уходят одним сообщением user из блоков `tool_result`, ответ ассистента воспроизводится
    исходными блоками (`_blocks` в сообщении приложения);
  * `stop_reason` → `finish_reason` приложения; `refusal`, `pause_turn`, `model_context_window_exceeded` и
    неизвестные причины – известные ошибки (LlmError.reason) без повторной генерации;
  * рассуждение (`thinking`, `reasoning_effort`) не передаётся; входящие блоки thinking текста не дают и
    воспроизводятся при следующем ходе; неподдерживаемые блоки – известная ошибка;
  * `/models` недоступен (404/405/501) – сервер считается живым, список – из резервного имени модели
    (fallback_model: из формы, профиля или снимка); 401/403 – ошибка ключа как есть.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from app import i18n
from app.llm import RAW_KEEP, LlmError, answer_schema, check_answer, estimate_tokens, extract_answer, retry_message
from app.llm_chat import (MAX_SENDS, ChatCompletionsClient, TurnResult, _scrub_error, _scrub_value, message_tokens,
                          track_sent, tracked, usage_stats)
from app.models import LlmStats

API_VERSION = "2023-06-01"  # версия Messages API в заголовке anthropic-version (служебный, не секрет)
RESPONSE_MODES = ("tool", "tool_strict", "none")  # формат ответа chat_json по профилю
RETRY_STATUSES = (429, 500, 503, 529)  # 529 overloaded_error – как 429 (один повтор с ожиданием)
MODELS_UNAVAILABLE = (404, 405, 501)  # /models у шлюза нет – список из резервного имени (п. 2.7 плана)
STOP_MAP = {"end_turn": "stop", "stop_sequence": "stop", "tool_use": "tool_calls", "max_tokens": "length"}
KNOWN_STOP_ERRORS = {
    "refusal": ("refusal", "модель отказалась отвечать (stop_reason refusal)"),
    "pause_turn": ("pause_turn", "провайдер прервал ход (stop_reason pause_turn): серверные инструменты не "
                                 "поддерживаются"),
    "model_context_window_exceeded": ("context_window", "запрос не поместился в окно модели (stop_reason "
                                                        "model_context_window_exceeded)"),
}
ASSISTANT_BLOCKS = ("text", "tool_use", "thinking", "redacted_thinking")
ANSWER_TOOL = "answer"


def _blocks_of(message: Mapping[str, Any]) -> list[dict[str, Any]]:
    blocks = message.get("_blocks")
    return [b for b in blocks if isinstance(b, dict)] if isinstance(blocks, list) else []


def _text_of(blocks: Iterable[Mapping[str, Any]]) -> str:
    return "\n".join(str(b.get("text") or "") for b in blocks if b.get("type") == "text").strip()


def _usage_of(data: Any) -> dict[str, int]:
    raw = data.get("usage") if isinstance(data, dict) and isinstance(data.get("usage"), dict) else {}

    def count(value: Any) -> int:
        return int(value) if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0
    return {"prompt_tokens": count(raw.get("input_tokens")), "completion_tokens": count(raw.get("output_tokens")),
            "reasoning_tokens": 0, "cache_hit_tokens": count(raw.get("cache_read_input_tokens"))}


def to_app_message(data: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    """Ответ Messages API -> (сообщение ассистента в формате приложения, finish_reason приложения). Известные
    причины-ошибки и неподдерживаемые блоки – LlmError с reason (исход известен)."""
    # ответ получен (HTTP 200): любое нарушение протокола – известный исход (reason), а не «результат неизвестен»;
    # блоки не отбрасываются молча (ревью круг 15, находка 6)
    if not isinstance(data, Mapping):
        raise LlmError("Ответ сервера – не объект: ответ не по протоколу Messages API.", reason="bad_response")
    content = data.get("content")
    if not isinstance(content, list):
        raise LlmError("В ответе сервера нет списка блоков content: ответ не по протоколу Messages API.",
                       reason="bad_response")
    if not all(isinstance(b, dict) for b in content):
        raise LlmError("В списке блоков ответа есть элемент, который не является блоком: ответ не по протоколу "
                       "Messages API.", reason="bad_response")
    blocks = list(content)
    for b in blocks:
        if b.get("type") not in ASSISTANT_BLOCKS:
            raise LlmError(f"Ответ содержит неподдерживаемый блок «{b.get('type')}»: такие ответы приложение не "
                           "разбирает.", reason="unsupported_block")
        if b.get("type") == "text" and not isinstance(b.get("text"), str):
            raise LlmError("Текстовый блок ответа без строки text: ответ не по протоколу Messages API.",
                           reason="bad_response")
    stop = str(data.get("stop_reason") or "")
    if stop in KNOWN_STOP_ERRORS:
        reason, text = KNOWN_STOP_ERRORS[stop]
        raise LlmError(f"Модель не ответила: {text}.", detail=stop, reason=reason)
    if stop not in STOP_MAP:
        raise LlmError(f"Неизвестная причина завершения ответа: «{stop or 'нет'}» – ответ не принят.", detail=stop,
                       reason="unknown_stop")
    calls = []
    seen: set[str] = set()
    for b in blocks:
        if b.get("type") != "tool_use":
            continue
        call_id, name, payload = str(b.get("id") or ""), str(b.get("name") or ""), b.get("input")
        if not call_id or not name or not isinstance(payload, dict):
            raise LlmError("Вызов инструмента без id, имени или объекта аргументов: ответ не принят.", reason="bad_tool")
        if call_id in seen:
            raise LlmError(f"Повторный идентификатор вызова инструмента «{call_id}»: ответ не принят.", reason="bad_tool")
        seen.add(call_id)
        calls.append({"id": call_id, "type": "function",
                      "function": {"name": name, "arguments": json.dumps(payload, ensure_ascii=False)}})
    message: dict[str, Any] = {"role": "assistant", "content": _text_of(blocks), "_blocks": blocks}
    if calls:
        message["tool_calls"] = calls
    return message, STOP_MAP[stop]


def to_wire_messages(messages: Iterable[Mapping[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """История приложения -> (system, messages Messages API): системные сообщения – в поле system; подряд идущие
    сообщения role=tool одного хода – одно сообщение user из блоков tool_result (перед текстом); подряд идущие
    user – одно сообщение; ассистент – исходными блоками (_blocks), иначе из текста и tool_calls."""
    system: list[str] = []
    out: list[dict[str, Any]] = []

    def push_user(blocks: list[dict[str, Any]]) -> None:
        if out and out[-1]["role"] == "user":
            existing = out[-1]["content"]
            results = [b for b in existing + blocks if b.get("type") == "tool_result"]
            texts = [b for b in existing + blocks if b.get("type") != "tool_result"]
            out[-1]["content"] = results + texts
        else:
            out.append({"role": "user", "content": blocks})

    for m in messages:
        role = str(m.get("role") or "")
        if role == "system":
            system.append(str(m.get("content") or ""))
        elif role == "tool":
            push_user([{"type": "tool_result", "tool_use_id": str(m.get("tool_call_id") or ""),
                        "content": str(m.get("content") or "")}])
        elif role == "user":
            content = m.get("content")
            blocks = [b for b in content if isinstance(b, dict)] if isinstance(content, list) else [
                {"type": "text", "text": str(content or "")}]
            push_user(blocks)
        elif role == "assistant":
            blocks = _blocks_of(m)
            if not blocks:
                text = str(m.get("content") or "")
                blocks = [{"type": "text", "text": text}] if text else []
                for call in m.get("tool_calls") or []:
                    if not isinstance(call, dict):
                        continue
                    fn = call.get("function") or {}
                    try:
                        payload = json.loads(str(fn.get("arguments") or "{}"))
                    except ValueError:
                        payload = {}
                    blocks.append({"type": "tool_use", "id": str(call.get("id") or ""), "name": str(fn.get("name") or ""),
                                   "input": payload if isinstance(payload, dict) else {}})
            if blocks:
                out.append({"role": "assistant", "content": blocks})
        else:
            raise LlmError(f"Сообщение с ролью «{role}» протоколу Messages API не передаётся.")
    return "\n\n".join(s for s in system if s), out


class MessagesClient(ChatCompletionsClient):
    """Клиент Messages API. Параметры профиля задаёт вызывающий: response_mode (tool, tool_strict, none),
    max_output, context_window, fallback_model; рассуждение не передаётся."""

    def __init__(self, url: str, timeout: float = 600) -> None:
        super().__init__(url, timeout)
        self.response_mode = "tool"
        self.generate_path = "/messages"
        self.retry_statuses = RETRY_STATUSES  # + 529 overloaded_error
        self.protocol_name = "Messages API"
        self.fallback_model = ""  # имя модели из формы, профиля или снимка – список при недоступном /models
        self.models_unavailable = False  # последний запрос /models ответил 404/405/501

    def protocol_headers(self) -> dict[str, str]:
        return {"anthropic-version": API_VERSION}

    # ---------------------------------------------------------------- сведения о сервере

    def _models(self) -> list[dict[str, Any]]:
        try:
            data = self._request("/models")
        except LlmError as e:
            if e.status in MODELS_UNAVAILABLE:
                self.models_unavailable = True
                name = str(self.fallback_model or "").strip()
                if not name:
                    raise LlmError("Список моделей у этого сервера недоступен, а имя модели не задано: укажите имя "
                                   "модели в профиле.", status=e.status) from None
                return [{"id": name, "source": "profile"}]
            raise
        self.models_unavailable = False
        items = data.get("data") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise LlmError(f"В ответе /models нет списка моделей: по адресу {self.check_url()}, похоже, не Messages API.")
        return [item for item in items if isinstance(item, dict) and str(item.get("id") or "").strip()]

    @tracked
    def version(self) -> str:
        models = self._models_once()
        if self.models_unavailable:
            return i18n._("Messages API, список моделей недоступен – имя из профиля")
        return i18n._("Messages API, моделей: {n}", n=len(models))

    @tracked
    def list_models(self) -> list[dict[str, Any]]:
        result = [{"name": str(item["id"]).strip(), "size": 0, "digest": "", "params": "", "quant": "",
                   "family": str(item.get("display_name") or ""), "context_length": None, "capabilities": None,
                   "source": str(item.get("source") or "server")} for item in self._models_once()]
        return sorted(result, key=lambda x: x["name"].casefold())

    def unload_model(self, model: str) -> dict[str, Any]:
        raise LlmError("Выгрузка модели у провайдера по Messages API не поддерживается.")

    # ---------------------------------------------------------------- запрос модели

    def _body(self, model: str, messages: list[dict[str, Any]], max_tokens: int,
              response_format: dict[str, Any] | None, tools: list[dict[str, Any]] | None,
              tool_choice: dict[str, Any] | None = None) -> dict[str, Any]:
        system, wire = to_wire_messages(messages)
        body: dict[str, Any] = {"model": model, "max_tokens": int(max_tokens), "messages": wire}
        if system:
            body["system"] = system
        if tools:
            body["tools"] = [self._tool(t) for t in tools]
            body["tool_choice"] = tool_choice or {"type": "auto"}
        return body

    def _answer_tool(self, fields: Mapping[str, str], required: Iterable[str], enums: Mapping[str, Iterable[str]],
                     types: Mapping[str, str] | None = None) -> dict[str, Any] | None:
        """Инструмент answer chat_json по режиму профиля (tool, tool_strict); у режима none – None."""
        if self.response_mode not in ("tool", "tool_strict"):
            return None
        tool: dict[str, Any] = {
            "name": ANSWER_TOOL, "description": "Ответ по правилам системного сообщения: один объект с полями "
            + ", ".join(fields), "input_schema": answer_schema(fields, list(required),
                                                               {k: list(v) for k, v in enums.items()}, types)}
        if self.response_mode == "tool_strict":
            tool["strict"] = True
        return tool

    @staticmethod
    def _answer_choice(tool: Mapping[str, Any] | None) -> dict[str, Any] | None:
        return {"type": "tool", "name": ANSWER_TOOL} if tool else None

    def json_overhead(self, fields: Mapping[str, str], required: Iterable[str], enums: Mapping[str, Iterable[str]],
                      types: Mapping[str, str] | None = None) -> int:
        """Сколько токенов (оценка сверху) chat_json добавит к сообщениям в проверке размера (_check_size):
        инструмент answer и выбор инструмента. Подгонка среза вычитает это из окна профиля (KIMI-01)."""
        tool = self._answer_tool(fields, required, enums, types)
        if tool is None:
            return 0
        return estimate_tokens(json.dumps([[tool], self._answer_choice(tool)], ensure_ascii=False))

    @staticmethod
    def _tool(tool: Mapping[str, Any]) -> dict[str, Any]:
        """Инструмент приложения ({"type": "function", "function": {name, description, parameters}}) или уже в
        формате Messages ({name, description, input_schema}) -> формат Messages."""
        if "input_schema" in tool:
            return dict(tool)
        fn = tool.get("function") or {}
        return {"name": str(fn.get("name") or ""), "description": str(fn.get("description") or ""),
                "input_schema": dict(fn.get("parameters") or {"type": "object"})}

    def _turn(self, model: str, messages: list[dict[str, Any]], max_tokens: int, tools: list[dict[str, Any]] | None,
              tool_choice: dict[str, Any] | None, budget: dict[str, Any],
              allowed: Iterable[str] | None = None) -> tuple[dict[str, Any], str, dict[str, int]]:
        """Одна отправка с бюджетом: (сообщение приложения, finish_reason, usage). Известные ошибки после ответа
        несут usage в stats. allowed – имена инструментов хода исследования (вызов другого – bad_tool)."""
        self._check_size(messages, max_tokens, [tools, tool_choice])
        data = self._post(self._body(model, messages, max_tokens, None, tools, tool_choice), budget)
        usage = _usage_of(data)
        try:
            message, finish = to_app_message(data)
            if allowed is not None:  # ход исследования: инструмент вне переданного набора – известная ошибка (п. 2.5)
                unknown = sorted({c["function"]["name"] for c in message.get("tool_calls") or []} - set(allowed))
                if unknown:
                    raise LlmError(f"Модель вызвала инструмент, которого нет в запросе: {', '.join(unknown)} – ответ не "
                                   "принят.", reason="bad_tool")
        except LlmError as e:
            if e.stats is None:
                e.stats = usage_stats(model, usage, budget["sends"])
            raise
        return message, finish, usage

    def chat_turn(self, model: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
                  max_tokens: int | None = None, response_format: dict[str, Any] | None = None,
                  max_sends: int | None = None, deadline: float | None = None,
                  allow_http_retry: bool = True) -> TurnResult:
        """Один ход диалога с инструментами (исследование, ADR-0105): выбор инструмента – за моделью (auto)."""
        limit = int(max_tokens or self.max_output)
        own = time.monotonic() + self.timeout
        budget = {"sends": 0, "http_retried": not allow_http_retry, "http_retries": 0,
                  "deadline": min(own, deadline) if deadline else own,
                  "max_sends": max(1, min(MAX_SENDS, int(max_sends))) if max_sends else MAX_SENDS}
        started = time.monotonic()
        try:
            with track_sent():
                message, finish, usage = self._turn(str(model), messages, limit, tools, None, budget,
                                                    allowed=[self._tool(t)["name"] for t in tools or []])
        except LlmError as e:
            e.sends = budget["sends"]
            e.http_retries = budget["http_retries"]  # повтор транспорта внутри хода был – на строку он один (К3)
            raise _scrub_error(e, self._secrets) from None
        return TurnResult(message=message, finish_reason=finish, usage=usage,
                          seconds=round(time.monotonic() - started, 3), sends=budget["sends"],
                          http_retries=budget["http_retries"])

    def chat_json(self, model: str, messages: list[dict[str, Any]], fields: Mapping[str, str],
                  required: Iterable[str], enums: Mapping[str, Iterable[str]], options: Mapping[str, Any] | None = None,
                  think: Any = None, types: Mapping[str, str] | None = None,
                  validate: Callable[[dict[str, Any]], Iterable[str]] | None = None, progress=None,
                  json_schema: str = "", max_tokens: int | None = None) -> tuple[dict[str, Any], LlmStats]:
        """Ответ объектом JSON – тот же контракт, что у Ollama и чат-завершений. Режим tool/tool_strict – инструмент
        answer с принудительным выбором, проверка приложением; none – текст и извлечение JSON. Предел ответа –
        max_output профиля (снимка) или явный max_tokens вызывающего; options.num_predict – параметр Ollama, здесь не
        применяется (ADR-0106 п. 9)."""
        name = str(model or "").strip()
        required = list(required)
        enums = {k: list(v) for k, v in enums.items()}
        limit = int(max_tokens or self.max_output)
        tool = self._answer_tool(fields, required, enums, types)
        use_tool = tool is not None
        history = [dict(m) for m in messages]
        budget = {"sends": 0, "http_retried": False, "deadline": time.monotonic() + self.timeout}
        started = time.monotonic()
        totals = {"prompt_tokens": 0, "completion_tokens": 0, "reasoning_tokens": 0, "cache_hit_tokens": 0}

        def stats() -> LlmStats:
            return LlmStats(model=name, prompt_tokens=totals["prompt_tokens"], output_tokens=totals["completion_tokens"],
                            eval_tps=0.0, prompt_tps=0.0, total_s=round(time.monotonic() - started, 3), load_s=0.0,
                            attempts=budget["sends"], think="-", reasoning_tokens=0,
                            cache_hit_tokens=totals["cache_hit_tokens"], timing="app")

        try:
            with track_sent():
                while True:
                    try:
                        message, finish, usage = self._turn(name, history, limit, [tool] if tool else None,
                                                            self._answer_choice(tool), budget)
                    except LlmError as e:
                        if e.stats is not None:
                            totals["prompt_tokens"] += int(e.stats.prompt_tokens or 0)
                            totals["completion_tokens"] += int(e.stats.output_tokens or 0)
                            totals["cache_hit_tokens"] += int(e.stats.cache_hit_tokens or 0)
                        e.stats = stats()
                        raise
                    for key in totals:
                        totals[key] += usage[key]
                    calls = [c for c in message.get("tool_calls") or []]
                    answers = [c for c in calls if c["function"]["name"] == ANSWER_TOOL]
                    content = str(message.get("content") or "")
                    obj: dict[str, Any] | None = None
                    problems: list[str] = []
                    if use_tool:
                        if answers:
                            parsed = json.loads(answers[0]["function"]["arguments"])
                            obj = parsed if isinstance(parsed, dict) else None
                            if obj is None:
                                problems = ["аргумент инструмента answer – не объект"]
                        else:
                            problems = ["ответ нужен вызовом инструмента answer, а не текстом"
                                        if not calls else "вызван не тот инструмент: нужен answer"]
                    else:
                        obj, why = extract_answer(content, [*fields, *required])
                        if obj is None:
                            problems = [why or ("пустой ответ" if not content.strip() else "в ответе нет объекта JSON")]
                    if obj is not None and not problems:
                        obj, problems = check_answer(obj, required, enums, types)
                        if not problems and validate is not None:
                            problems = [str(p) for p in validate(obj) if str(p).strip()]
                    if not problems and obj is not None:
                        return _scrub_value(obj, self._secrets), stats()
                    raw = content if not use_tool else (answers[0]["function"]["arguments"] if answers else content)
                    if finish == "length":
                        raise LlmError(f"Ответ модели оборван: исчерпан предел длины ответа ({limit} токенов). "
                                       "Увеличьте предел ответа в профиле.", stats=stats(), reason="length", raw=raw[:RAW_KEEP])
                    if budget["sends"] >= MAX_SENDS:
                        raise LlmError(f"Модель ответила не по формату: {'; '.join(problems[:5])}.", stats=stats(), reason="bad_format",
                                       raw=raw[:RAW_KEEP])
                    note = retry_message(problems, fields, enums)
                    if use_tool:
                        results = [{"type": "tool_result", "tool_use_id": c["id"],
                                    "content": note if c is (answers[0] if answers else None) else "не использован"}
                                   for c in calls]
                        history = [dict(m) for m in messages] + [message, {"role": "user", "content": results + [
                            {"type": "text", "text": "Исправьте ответ вызовом инструмента answer: " + note}]}]
                    else:
                        history = [dict(m) for m in messages] + [{"role": "assistant", "content": content[:RAW_KEEP]},
                                                                 {"role": "user", "content": note}]
        except LlmError as e:
            if e.stats is None:
                e.stats = stats()
            raise _scrub_error(e, self._secrets) from None



__all__ = ["API_VERSION", "MessagesClient", "RESPONSE_MODES", "RETRY_STATUSES", "to_app_message", "to_wire_messages",
           "message_tokens"]

"""Клиент локального сервера Ollama: версия, список моделей, загруженные модели и вызов модели с ответом JSON
(вынесен из app/llm.py в 0.9.12, ADR-0102). Соединение – app/llm_net.py; разбор и проверка ответа – app/llm.py.

Облачные модели Ollama отвергаются: по слову cloud в имени и по признакам remote_host, remote_model в /api/tags;
проверка – перед каждой попыткой вызова модели.
"""

from __future__ import annotations

import http.client
import json
import re
import time
import urllib.parse
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from app import model_traffic
from app.config import model_json_schema_mode
from app.llm import (DEFAULT_OPTIONS, RAW_KEEP, LlmError, PromptOverflowError, _check_prompt_size, _count,
                     _one_line, _retry_messages, _seconds, _token_budget, answer_schema, check_answer, extract_answer,
                     is_cloud_model, norm_model_name, retry_message)
from app.llm_http import ServerClient, _scrub_error, _scrub_value, track_sent, tracked
from app.llm_net import (ALLOWED_HOSTS, CONNECT_TIMEOUT_S, MAX_RESPONSE_BYTES, _ip, _os_error_text,
                         _PinnedHTTPSConnection, _Target, _TooLarge, lan_address_ok)
from app.models import LlmStats
from app.i18n import N_

# Частые ошибки соединения с Ollama (ADR-0158): текст – русский канонический (уходит в LlmError, ошибки прогонов
# классифицируются по нему), шаблоны – msgid каталога: на языке интерфейса их показывает run_errors.shown_error
OLLAMA_NOT_JSON = N_("Ответ сервера {base} на {path} – не JSON: по этому адресу, похоже, не Ollama.")
OLLAMA_TIMEOUT = N_("Нет ответа от Ollama ({base}) за {seconds} на {path}.")
OLLAMA_TOO_LARGE = N_("Ответ Ollama ({base}) на {path} слишком большой.")
OLLAMA_REFUSED = N_("Ollama не отвечает по адресу {base}: соединение отклонено. Запустите Ollama и проверьте адрес "
                    "Ollama на странице «Настройки».")
OLLAMA_DROPPED = N_("Связь с Ollama ({base}) прервана на {path}: сервер закрыл соединение, не дослав ответ.")
OLLAMA_NO_VERSION = N_("В ответе /api/version нет версии: по адресу {url}, похоже, не Ollama.")
OLLAMA_NO_MODELS = N_("В ответе /api/tags нет списка моделей: по адресу {url}, похоже, не Ollama.")
OLLAMA_CONNECT_TIMEOUT = N_("Ollama не отвечает по адресу {base}: соединение не установлено за {seconds}. Проверьте "
                            "адрес Ollama на странице «Настройки» и что Ollama запущена.")
SHOWN_TEXTS = (OLLAMA_CONNECT_TIMEOUT, OLLAMA_NOT_JSON, OLLAMA_TIMEOUT, OLLAMA_TOO_LARGE, OLLAMA_REFUSED, OLLAMA_DROPPED, OLLAMA_NO_VERSION,
               OLLAMA_NO_MODELS)

PS_TIMEOUT_S = 5.0  # /api/ps опрашивается часто (метрики), долго ждать нельзя
UNLOAD_TIMEOUT_S = 30.0  # /api/generate с keep_alive 0 отвечает сразу, но выгрузка большой модели не мгновенна
THINK_LEVELS = ("low", "medium", "high")


def _emit_progress(callback, event):
    if callback is not None:
        try:
            callback(event)
        except Exception:
            pass  # Отказ необязательного наблюдателя не меняет ответ и проверку модели.


def read_chat_stream(chunks, progress):
    """NDJSON собирается до done; частичный текст не становится ответом или вердиктом."""
    pending=b''
    size=0
    content=[]
    thinking=[]
    final=None

    def line(raw):
        nonlocal final
        if not raw.strip():return
        if final is not None:raise LlmError('После завершения потока модели получены лишние данные.')
        try:item=json.loads(raw.decode('utf-8'))
        except (ValueError,UnicodeError,RecursionError):raise LlmError('Некорректная строка JSON в потоке модели.') from None
        if not isinstance(item,dict):raise LlmError('Строка потока модели не является объектом JSON.')
        if item.get('error'):raise LlmError(_one_line(item['error']))
        message=item.get('message') or {}
        if not isinstance(message,dict):raise LlmError('Некорректное сообщение потока модели.')
        part=message.get('content') or ''
        thought=message.get('thinking') or ''
        if not isinstance(part,str) or not isinstance(thought,str):raise LlmError('Некорректный текст в потоке модели.')
        if part:content.append(part)
        if thought:thinking.append(thought)
        if part or thought:_emit_progress(progress, {'event':'fragment','received_chars':len(part)+len(thought)})
        if item.get('done') is True:
            final=item
            _emit_progress(progress, {'event':'response_done'})

    for chunk in chunks:
        size+=len(chunk)
        if size>MAX_RESPONSE_BYTES:raise LlmError('Поток модели превысил предел размера ответа.')
        pending+=chunk
        while b'\n' in pending:
            raw,pending=pending.split(b'\n',1)
            line(raw)
    if pending.strip():line(pending)
    if final is None:raise LlmError('Поток модели завершился без подтверждения завершения ответа.')
    final['message']={'role':'assistant','content':''.join(content),'thinking':''.join(thinking)}
    return final


# Сообщения Ollama -> понятное описание; исходный текст остаётся в LlmError.detail.
_SERVER_ERRORS = (
    (re.compile(r"out of memory|cudamalloc|insufficient memory|requires more system memory|unable to allocate", re.I),
     "модели не хватает памяти (видеопамяти или оперативной): выберите модель меньше или уменьшите окно контекста"),
    (re.compile(r"does not support (?:chat|generate|completion)", re.I),
     "модель не умеет отвечать на сообщения (например, это модель для эмбеддингов)"),
    (re.compile(r"not found", re.I), "модель или путь не найдены на сервере"),
    (re.compile(r"context (?:length|window|size)|prompt is too long|input (?:is )?too long|"
                r"exceeds? (?:the )?(?:maximum )?context", re.I), "промпт не помещается в окно контекста модели"),
    (re.compile(r"runner|terminated|exit status", re.I), "процесс модели на сервере Ollama остановился"),
)


def capability_list(value: Any) -> list[str] | None:
    """Возможности модели (capabilities Ollama) в едином виде: непустой список – списком строк; пусто или иной вид
    (строка, число) – None, «неизвестно»."""
    return [str(c) for c in value] if isinstance(value, list) and value else None


def _describe_server_error(detail: str) -> str:
    return next((text for pattern, text in _SERVER_ERRORS if pattern.search(detail)), "")


def _server_error_text(body: bytes) -> str:
    """Текст ошибки из тела ответа (Ollama присылает {"error": "..."}), одной строкой."""
    text = body[:64 * 1024].decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict) and parsed.get("error"):
            text = str(parsed["error"])
    except (ValueError, RecursionError):
        pass
    return _one_line(text)


def _server_error_message(prefix: str, detail: str) -> str:
    """Сообщение об ошибке сервера для интерфейса: своё описание, а исходный текст сервера (до 200 знаков) – только
    если своего описания нет. Исходный текст целиком (до DETAIL_MAX знаков) остаётся в LlmError.detail."""
    meaning = _describe_server_error(detail)
    if meaning:
        return f"{prefix}: {meaning}."
    return f"{prefix} (ответ сервера: {detail[:200]})." if detail else f"{prefix}."


# ============================================================================ клиент

class OllamaClient(ServerClient):
    """Клиент Ollama. Каждый запрос – отдельное соединение; отказ схемы запоминается потокобезопасной меткой.

    url – адрес сервера (настройка «Адрес Ollama»); timeout – общий срок ответа модели в chat_json, секунды
    (без потоковой выдачи сервер молчит до конца генерации). Адрес проверяется при каждом запросе (check_url),
    поэтому неверный адрес не мешает создать клиент: ошибка придёт понятным LlmError при первом обращении.
    """

    # ---------------------------------------------------------------- адрес и запросы

    def _target(self) -> _Target:
        if self.trust not in ("local", "lan"):
            raise LlmError(f"Класс доверия «{self.trust}» не поддерживается: запрос к модели не отправлен.")
        hint = (f"нужен адрес вида http://127.0.0.1:11434; разрешённые хосты: {', '.join(ALLOWED_HOSTS)}"
                if self.trust == "local" else "нужен адрес сервера в сети организации, например http://10.0.0.5:11434")
        if not self.url:
            raise LlmError(f"Адрес сервера Ollama не задан (страница «Настройки»): {hint}.")
        try:
            parts = urllib.parse.urlsplit(self.url)
        except ValueError:  # например, незакрытая «[» в адресе IPv6
            raise LlmError(f"Адрес сервера Ollama не распознан: {hint}.") from None
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.netloc:
            raise LlmError(f"Адрес сервера Ollama не распознан: {hint}.")
        if scheme == "https" and _PinnedHTTPSConnection is None:
            raise LlmError("В этой сборке Python нет поддержки https: укажите адрес Ollama с http://.")
        if "@" in parts.netloc:
            raise LlmError(f"В адресе сервера Ollama не должно быть имени пользователя и пароля: {hint}.")
        host = (parts.hostname or "").lower()
        if self.trust == "local" and host not in ALLOWED_HOSTS:
            raise LlmError(f"Сервер Ollama «{host}» не входит в разрешённые – запрос не отправлен, код находок "
                           f"не должен покидать компьютер: {hint}.")
        if self.trust == "lan":
            ip = _ip(host)
            if not host or ip is not None and not lan_address_ok(ip):
                raise LlmError(f"Адрес сервера «{host}» – не частная сеть: запрос не отправлен, {hint}.")
        try:
            port = parts.port
        except ValueError:
            raise LlmError(f"В адресе сервера Ollama неверный порт: {hint}.") from None
        if parts.query or parts.fragment:
            raise LlmError(f"В адресе сервера Ollama не должно быть «?» и «#»: {hint}.")
        prefix = parts.path.rstrip("/")
        base = urllib.parse.urlunsplit((scheme, parts.netloc, prefix, "", ""))
        return _Target(scheme, host, port or (443 if scheme == "https" else 80), prefix, base)

    def _read_stream(self, pieces, progress) -> Any:
        return read_chat_stream(pieces, progress)

    @staticmethod
    def _connect_timeout_error(t: _Target, timeout: float) -> LlmError:
        return LlmError(OLLAMA_CONNECT_TIMEOUT.format(base=t.base, seconds=_seconds(min(timeout, CONNECT_TIMEOUT_S))))

    @staticmethod
    def _finish(t: _Target, path: str, status: int, body: bytes, secrets: tuple[str, ...],
                headers: dict[str, str]) -> Any:
        """Ответ Ollama после обмена: перенаправление и ошибка HTTP – LlmError, иначе разобранный JSON без ключа."""
        if 300 <= status < 400:
            raise LlmError(f"Сервер {t.base} ответил перенаправлением (HTTP {status}) на {path}. Перенаправления "
                           "не выполняются: укажите адрес Ollama напрямую.", status=status)
        if status >= 400:
            detail = model_traffic.scrub(_server_error_text(body), secrets)
            message = _server_error_message(f"Ollama ({t.base}) ответила ошибкой HTTP {status} на {path}", detail)
            raise _scrub_error(LlmError(message, status=status, detail=detail), secrets)
        try:
            return _scrub_value(json.loads(body.decode("utf-8")), secrets) if body.strip() else {}
        except (ValueError, RecursionError):
            raise LlmError(OLLAMA_NOT_JSON.format(base=t.base, path=path)) from None

    @staticmethod
    def _transport_error(error: BaseException, t: _Target, path: str, timeout: float, expired: bool) -> LlmError:
        """Сбой на уровне соединения -> LlmError по-русски."""
        if expired or isinstance(error, TimeoutError):
            return LlmError(OLLAMA_TIMEOUT.format(base=t.base, seconds=_seconds(timeout), path=path))
        if isinstance(error, _TooLarge):
            return LlmError(OLLAMA_TOO_LARGE.format(base=t.base, path=path))
        if isinstance(error, ConnectionRefusedError):
            return LlmError(OLLAMA_REFUSED.format(base=t.base))
        if isinstance(error, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError,
                              http.client.HTTPException)):
            return LlmError(OLLAMA_DROPPED.format(base=t.base, path=path))
        return LlmError(f"Ollama не отвечает по адресу {t.base} ({path}): {_os_error_text(error)}.")

    # ---------------------------------------------------------------- сведения о сервере

    @tracked
    def version(self) -> str:
        data = self._request("/api/version")
        value = data.get("version") if isinstance(data, dict) else None
        if not isinstance(value, str) or not value.strip():
            raise LlmError(OLLAMA_NO_VERSION.format(url=self.check_url()))
        return value.strip()

    def _tags(self) -> list[dict[str, Any]]:
        data = self._request("/api/tags")
        models = data.get("models") if isinstance(data, dict) else None
        if not isinstance(models, list):
            raise LlmError(OLLAMA_NO_MODELS.format(url=self.check_url()))
        # имя модели – только строка: иное значение (объект, число) сервером подставлено и в запросы не уходит
        return [m for m in models if isinstance(m, dict) and isinstance(m.get("name") or m.get("model"), str)
                and str(m.get("name") or m.get("model")).strip()]

    def _capabilities(self, entry: Mapping[str, Any]) -> list[str] | None:
        """Возможности модели: из /api/tags, а если их там нет или они не списком (старая Ollama, пустой список) – из
        /api/show; неизвестно – None. Одно правило для списка моделей и для сведений о модели (model_info)."""
        capabilities = capability_list(entry.get("capabilities"))
        if capabilities is not None:
            return capabilities
        try:
            info = self._request("/api/show", {"model": str(entry.get("name") or entry.get("model"))})
        except LlmError:
            return None
        return capability_list(info.get("capabilities") if isinstance(info, dict) else None)

    @tracked
    def list_models(self) -> list[dict[str, Any]]:
        """Локальные модели, пригодные для разбора, по имени: name, size (байты), params, quant, family,
        context_length, capabilities. Облачные модели и модели без генерации текста (эмбеддинги) не входят;
        если возможности модели неизвестны, модель с «embed» в имени или семейства bert считается эмбеддингом."""
        result = []
        for m in self._tags():
            if is_cloud_model(m):
                continue
            name = str(m.get("name") or m.get("model")).strip()
            details = m.get("details") if isinstance(m.get("details"), dict) else {}
            capabilities = self._capabilities(m)
            if capabilities is not None:
                if "completion" not in capabilities:
                    continue
            elif "embed" in name.casefold() or "bert" in str(details.get("family") or "").casefold():
                continue
            context = details.get("context_length")
            result.append({
                "name": name,
                "size": _count(m.get("size")),
                "digest": str(m.get("digest") or "")[:128],
                "params": str(details.get("parameter_size") or ""),
                "quant": str(details.get("quantization_level") or ""),
                "family": str(details.get("family") or ""),
                "context_length": context if _count(context) else None,
                "capabilities": capabilities,
            })
        return sorted(result, key=lambda x: x["name"].casefold())

    @tracked
    def ps(self) -> list[dict[str, Any]]:
        """Загруженные в память модели: name, size и size_vram (байты), context (окно контекста или None)."""
        data = self._request("/api/ps", timeout=PS_TIMEOUT_S)
        models = data.get("models") if isinstance(data, dict) else None
        if not isinstance(models, list):
            raise LlmError("В ответе /api/ps нет списка моделей: по этому адресу, похоже, не Ollama.")
        result = []
        for m in models:
            if not isinstance(m, dict):
                continue
            context = m.get("context_length")
            result.append({
                "name": str(m.get("name") or m.get("model") or ""),
                "size": _count(m.get("size")),
                "size_vram": _count(m.get("size_vram")),
                "context": context if _count(context) else None,
            })
        return result

    @tracked
    def unload_model(self, model: str) -> dict[str, Any]:
        """Выгрузить модель из памяти Ollama: POST /api/generate с keep_alive 0. Это не запрос к модели: текст
        находки не отправляется, ответ сервера – только подтверждение выгрузки. Нужна перезагрузка модели заново,
        когда она работает заметно медленнее обычного (app/triage.py). Любой сбой – LlmError."""
        name = str(model or "").strip()
        if not name:
            raise LlmError("Не выбрана модель.")
        data = self._request("/api/generate", {"model": name, "keep_alive": 0}, timeout=UNLOAD_TIMEOUT_S)
        return data if isinstance(data, dict) else {}

    @tracked
    def warm_model(self, model: str, num_ctx: int, timeout: float = 600.0) -> None:
        """Загрузить модель в память заранее (прогрев ВМ при загрузке): POST /api/generate без текста, с окном
        контекста профиля и keep_alive 24h. Модель – та, что на сервере под этим именем, и не облачная. Право на
        генерацию берёт вызывающий. Загрузка подтверждается ответом с done = true без ошибки; иначе (и при сбое) –
        LlmError."""
        name = str(model or "").strip()
        self.model_info(name)
        data = self._request("/api/generate", {"model": name, "keep_alive": "24h",
                                               "options": {"num_ctx": int(num_ctx)}}, timeout=timeout)
        if not isinstance(data, dict) or data.get("error") or data.get("done") is not True:
            reason = _one_line(data.get("error")) if isinstance(data, dict) and data.get("error") else \
                "в ответе нет подтверждения загрузки (done)"
            raise LlmError(f"Модель «{name}» не прогрета: {reason}.")

    @tracked
    def probe(self, model: str, timeout: float = 120.0) -> float:
        """Пробная генерация («Проверить» в профиле, ADR-0102): один короткий ответ модели -> секунды. Модель – та,
        что лежит на сервере под этим именем, и не облачная. Право на генерацию берёт вызывающий
        (executors.probe_generation)."""
        name = str(model or "").strip()
        if self.before_send is not None:
            self.before_send()
        self.model_info(name)
        started = time.monotonic()
        data = self._request("/api/chat", {"model": name, "stream": False,
                                           "messages": [{"role": "user", "content": "Ответь одним словом: готов."}],
                                           "options": {"num_predict": 8, "temperature": 0}}, timeout=timeout)
        message = data.get("message") if isinstance(data, dict) else None
        text = [message.get(k) for k in ("content", "thinking")] if isinstance(message, dict) else []
        if (not isinstance(data, dict) or data.get("error") or data.get("done") is not True
                or not any(isinstance(v, str) and v.strip() for v in text)
                or any(v is not None and not isinstance(v, str) for v in text)):
            raise LlmError(f"Пробная генерация не удалась: сервер {self.check_url()} не вернул ответ модели.")
        return time.monotonic() - started

    @tracked
    def model_info(self, model: str) -> dict[str, Any]:
        """Запись /api/tags о модели. Модели нет на сервере или она облачная – LlmError. Без кэша: перед каждой
        отправкой кода проверяется то, что сейчас лежит на сервере под этим именем."""
        name = str(model or "").strip()
        if not name:
            raise LlmError("Не выбрана модель.")
        if "cloud" in name.casefold():
            raise LlmError(_cloud_text(name))
        key = norm_model_name(name)
        entry = next((m for m in self._tags()
                      if key in (norm_model_name(m.get("name")), norm_model_name(m.get("model")))), None)
        if entry is None:
            raise LlmError(f"Модели «{name}» нет на сервере Ollama ({self.check_url()}). Загрузите её командой: "
                           f"ollama pull {name}")
        if is_cloud_model(entry):
            raise LlmError(_cloud_text(name))
        # возможности – в едином виде (список строк или None, «неизвестно»): старая Ollama, пустой список или иной вид –
        # из /api/show, как в списке моделей
        return {**entry, "capabilities": self._capabilities(entry)}

    # ---------------------------------------------------------------- вызов модели

    def chat_json(self, *args: Any, **kwargs: Any) -> tuple[dict[str, Any], LlmStats]:
        """Ответ модели в виде объекта JSON (см. _chat_json). Разобранный объект и ошибки – без значений ключа
        профиля: модель или сервер могли вернуть ключ внутри JSON ответа, в экранированном виде."""
        try:
            with track_sent():  # ушёл хоть один запрос обращения – у ошибки sent = True (К11 плана 0.9.13)
                obj, stats = self._chat_json(*args, **kwargs)
        except LlmError as e:
            raise _scrub_error(e, self._secrets) from None
        return _scrub_value(obj, self._secrets), stats

    def _chat_json(self, model: str, messages: list[dict[str, Any]], fields: Mapping[str, str],
                  required: Iterable[str], enums: Mapping[str, Iterable[str]], options: Mapping[str, Any] | None = None,
                  think: str | bool | None | Callable[[Mapping[str, Any]], str | bool | None] = None,
                  types: Mapping[str, str] | None = None,
                  validate: Callable[[dict[str, Any]], Iterable[str]] | None = None, progress=None,
                  json_schema: str = ""
                  ) -> tuple[dict[str, Any], LlmStats]:
        """Один ответ модели в виде объекта JSON -> (объект, замеры).

        fields – ключ -> описание (ключи называются в сообщении при повторе; сами поля перечисляет промпт);
        required – обязательные ключи; enums – допустимые значения; types – необязательно: ключ -> тип из TYPE_NAMES
        для мягкого приведения и проверки; validate – необязательно: проверка ответа по существу после приведения
        типов (объект -> список замечаний по-русски; например, поле, которое может быть пустым только при одном
        вердикте). Замечания validate, как и ошибки формата, ведут к повтору. options – параметры генерации поверх
        DEFAULT_OPTIONS. think – уровень рассуждения, разрешённый вызывающим (executors.applied_think): значение (low,
        medium, high или None – поле не передаётся) или функция от записи /api/tags модели – тогда уровень
        вычисляется на каждую отправку по модели, которая в этот момент лежит на сервере. Клиент сам уровень не
        выбирает; ушедшие уровни – в stats.think. before_send (проверка допуска профиля) вызывается до любых
        обращений попытки и перед самой отправкой; при сбое предварительного обращения допуск проверяется снова.

        Перед каждой попыткой модель заново проверяется на сервере (есть и не облачная), а промпт – на размер окна
        контекста. Объект JSON, закрытый до обрыва по длине (done_reason = length), принимается: он целый и прошёл
        проверку; оборванный объект – LlmError без повтора. Сбой сервера и два ответа не по формату – LlmError;
        в её stats – замеры сделанных попыток.
        """
        name = str(model or "").strip()
        opts = dict(DEFAULT_OPTIONS)
        opts.update(options or {})
        _check_prompt_size(messages, opts)
        required = list(required)
        enums = {k: list(v) for k, v in enums.items()}
        mode = model_json_schema_mode(json_schema)
        schema = answer_schema(fields, required, enums, types)
        base_messages = [dict(m) for m in messages]
        body: dict[str, Any] = {"model": name, "messages": base_messages, "stream": progress is not None, "options": opts}
        started = time.monotonic()
        totals = {"prompt_eval_count": 0, "eval_count": 0, "prompt_eval_duration": 0, "eval_duration": 0,
                  "load_duration": 0}
        problems: list[str] = []
        content = ""
        window = _token_budget(opts, safety=False)
        sent_think: list[str] = []  # уровень каждой попытки отправки после успешного допуска
        level_now = ["-"]

        def put_think(info: Mapping[str, Any]) -> None:
            """Уровень рассуждения этой отправки – решение вызывающего (ADR-0102), клиент не выбирает сам."""
            level = think(info) if callable(think) else think
            body.pop("think", None)
            if level in THINK_LEVELS or isinstance(level, bool):  # уровень gpt-oss или true/false другим моделям
                body["think"] = level
            level_now[0] = (level if level in THINK_LEVELS else "on" if level is True else "off" if level is False
                            else "-")

        def admit() -> None:
            if self.before_send is not None:
                self.before_send()

        def send() -> dict[str, Any]:
            """Допуск непосредственно перед отправкой и сама отправка; уровень записывается у попытки, прошедшей
            допуск (сбой сети до передачи байтов её не отменяет – это попытка, а не ответ)."""
            admit()
            sent_think.append(level_now[0])
            return self._chat(body, name, progress=progress) if progress is not None else self._chat(body, name)

        def stats(attempts: int) -> LlmStats:
            result = _stats(name, totals, attempts, started)
            result.think = ",".join(sent_think)
            return result

        for attempt in (1, 2):
            try:
                admit()  # допуск – до любых обращений попытки, даже к списку моделей
                body.pop("format", None)
                if not self._schema_unsupported.is_set() and (mode == "always" or mode == "retry" and attempt == 2):
                    body["format"] = schema
                put_think(self.model_info(name))  # перед каждой отправкой кода: модель есть и не облачная
                if progress is not None:
                    _emit_progress(progress, {'event':'request_started','attempt':attempt})
                try:
                    data = send()
                except LlmError as e:
                    if ("format" not in body or e.status != 400
                            or not re.search(r"\b(?:format|schema)\b", e.detail, re.IGNORECASE)):
                        raise
                    self._schema_unsupported.set()
                    body.pop("format")
                    admit()  # повтор без схемы: допуск – снова до проверки модели
                    put_think(self.model_info(name))
                    data = send()
            except LlmError as e:
                if self.before_send is not None:
                    try:  # сбой предварительного обращения (модели нет и т. п.): сначала – не выключен ли профиль
                        self.before_send()
                    except LlmError as refused:
                        refused.stats = stats(attempt)
                        raise refused from None
                e.stats = stats(attempt)
                raise
            for key in totals:
                totals[key] += _count(data.get(key))
            message = data.get("message") if isinstance(data.get("message"), dict) else {}
            content = str(message.get("content") or "")
            # Оценка длины – эвристика: сверяется счёт самой модели, у каждой попытки отдельно (до сложения
            # замеров). Не поместилось – ответу этой попытки не доверяем, повтор не нужен.
            used = _count(data.get("prompt_eval_count"))
            if window and used > window:
                raise PromptOverflowError(
                    f"Промпт, по счёту модели ({used} токенов), не поместился в окно контекста вместе с ответом "
                    f"({window} токенов): начало могло быть обрезано, ответ не принят.",
                    stats=stats(attempt), raw=content[:RAW_KEEP])
            obj, why = extract_answer(content, [*fields, *required])
            if obj is None:
                problems = [why or _no_json_reason(content, message)]
            else:
                obj, problems = check_answer(obj, required, enums, types)
                if not problems and validate is not None:
                    problems = [str(p) for p in validate(obj) if str(p).strip()]
            if not problems:
                return obj, stats(attempt)
            if str(data.get("done_reason") or "") == "length":
                raise LlmError(_length_text(opts.get("num_predict"), content, message, body.get("think")),
                               stats=stats(attempt), raw=content[:RAW_KEEP])
            if attempt == 1:
                try:
                    body["messages"] = _retry_messages(base_messages, content,
                                                       retry_message(problems, fields, enums), opts, echo=mode == "off")
                    if mode != "off" and opts.get("seed") is not None:
                        body["options"] = {**opts, "seed": opts["seed"] + 1}
                except LlmError as e:
                    e.stats, e.raw = stats(attempt), content[:RAW_KEEP]
                    raise
        raise LlmError(f"Модель дважды ответила не по формату: {'; '.join(problems[:5])}.",
                       stats=stats(2), raw=content[:RAW_KEEP])

    def _chat(self, body: dict[str, Any], name: str, progress=None) -> dict[str, Any]:
        try:
            data = self._request("/api/chat", body, timeout=self.timeout, progress=progress) if progress is not None else self._request("/api/chat",body,timeout=self.timeout)
        except LlmError as e:
            if e.status == 404 and "not found" in e.detail.casefold():
                raise LlmError(f"Модели «{name}» нет на сервере Ollama ({self.check_url()}). Загрузите её "
                               f"командой: ollama pull {name}", status=404, detail=e.detail) from None
            raise
        if not isinstance(data, dict):
            raise LlmError("Ответ /api/chat – не объект JSON.")
        if data.get("error"):
            detail = _one_line(data["error"])
            raise LlmError(_server_error_message("Ollama вернула ошибку на /api/chat", detail), detail=detail)
        return data


def _cloud_text(name: str) -> str:
    return (f"Модель «{name}» облачная: запросы к ней уходят с компьютера, а код находок должен оставаться "
            "на месте. Выберите локальную модель.")


def _length_text(limit: Any, content: str, message: Mapping[str, Any], think: Any) -> str:
    """Обрыв по длине (done_reason = length) – что произошло и какое поле профиля менять. Отдельный предел с
    рассуждением действует только при think = true (executors.request_options): тогда поле – «Предел ответа с
    рассуждением» (не больше половины окна контекста) и рассуждение можно выключить. У gpt-oss (уровень low, medium,
    high – выключить нельзя) и без рассуждения действует «Предел ответа разбора» (не больше четверти окна). Совет
    «увеличьте num_predict» без названия поля уводил не туда."""
    if not content.strip() and str(message.get("thinking") or "").strip():
        what = f"модель рассуждала и не дошла до ответа за {limit} токенов (num_predict = {limit})"
    else:
        what = f"исчерпан предел длины ответа (num_predict = {limit})"
    if think is True:
        how = ("Для разбора находок поднимите «Предел ответа с рассуждением» в профиле модели (не больше половины "
               "окна контекста – при нехватке поднимите и окно), выключите рассуждение или выберите другую модель.")
    else:
        how = ("Для разбора находок поднимите «Предел ответа разбора» в профиле модели (не больше четверти окна "
               "контекста) или выберите другую модель.")
    return f"Ответ модели оборван: {what}. {how}"


def _no_json_reason(content: str, message: Mapping[str, Any]) -> str:
    if not content.strip():
        if str(message.get("thinking") or "").strip():
            return "ответ пуст: модель не закончила рассуждение"
        return "пустой ответ"
    return "в ответе нет объекта JSON"


def _stats(model: str, totals: Mapping[str, int], attempts: int, started: float) -> LlmStats:
    """Замеры по всем попыткам: токены и длительности сервера суммируются; ток/с = токены / время генерации."""
    eval_s = totals["eval_duration"] / 1e9
    prompt_s = totals["prompt_eval_duration"] / 1e9
    return LlmStats(
        model=model,
        prompt_tokens=totals["prompt_eval_count"],
        output_tokens=totals["eval_count"],
        eval_tps=round(totals["eval_count"] / eval_s, 2) if eval_s > 0 else 0.0,
        prompt_tps=round(totals["prompt_eval_count"] / prompt_s, 2) if prompt_s > 0 else 0.0,
        total_s=round(time.monotonic() - started, 3),
        load_s=round(totals["load_duration"] / 1e9, 3),
        attempts=attempts,
    )

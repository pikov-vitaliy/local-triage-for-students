"""Общее для клиентов модели: право на генерацию, ошибки, разбор и проверка ответа JSON, бюджет промпта,
интерфейс клиента (LlmClient).

Клиент Ollama – в app/llm_ollama.py, соединение с проверенным адресом – в app/llm_net.py (разделение 0.9.12,
ADR-0102); прежний импорт ``from app.llm import OllamaClient`` работает (ленивая ссылка, __getattr__ модуля).
Закрытые сетевые имена отсюда не видны: подменять их в тестах нужно в app.llm_net.

Схема format строится из контракта ответа и по умолчанию передаётся при каждом запросе (always).
Повтор выполняется без эха прежнего ответа.
Ответом считается единственный объект JSON верхнего уровня с ключами ответа (ограда
```json и пояснения вокруг допустимы). Если таких объектов несколько – например, модель процитировала подложенный
в коде «готовый ответ», – это ошибка формата: угадывать, какой из них настоящий, нельзя. Затем проверяются
обязательные поля, перечисления, типы (тип text – текст по существу, а не пустая строка или прочерк) и, если задана,
проверка ответа по существу (validate). Ответ не по формату – один повтор с перечнем ошибок; после второй
неудачи – LlmError.

Промпт должен помещаться в окно контекста вместе с ответом (num_predict), иначе Ollama обрежет его начало вместе
с системным сообщением. Длина в токенах оценивается сверху, с запасом (estimate_tokens, правила – у
CHARS_PER_TOKEN): слова, знаки препинания, переводы строк и служебные токены шаблона чата считаются отдельно.
"""

from __future__ import annotations

import importlib
import json
import logging
import math
import re
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any, Protocol, runtime_checkable

from app.models import LlmStats

log = logging.getLogger(__name__)

class GenerationGate:
    """Право обращаться к модели за генерацией – одно на группу серверов (ADR-0099, уточнено ADR-0104 п. 6): прогон,
    вопрос к модели, проба и выгрузка модели в медленном режиме одной группы не идут одновременно. holder – кто держит
    право: "triage", "ask", "check", "warmup"; label – группа словами (для отказа «занято»)."""

    def __init__(self, label: str = "Ollama этого компьютера и сети организации") -> None:
        self._lock = threading.Lock()
        self.holder = ""
        self.label = label

    def try_acquire(self, holder: str) -> bool:
        """Взять право, если оно свободно; занято – False без ожидания."""
        if not self._lock.acquire(blocking=False):
            return False
        self.holder = holder
        return True

    def acquire(self, holder: str, interrupted: Callable[[], bool], poll_s: float = 0.25) -> bool:
        """Дождаться права; interrupted() – прекратить ожидание (остановка приложения, «Пауза», «Стоп»): тогда False.
        Проверяется и сразу после получения права – отменённое ожидание не начинает новую работу."""
        while not self._lock.acquire(timeout=poll_s):
            if interrupted():
                return False
        if interrupted():
            self._lock.release()
            return False
        self.holder = holder
        return True

    def release(self) -> None:
        self.holder = ""
        self._lock.release()

    def busy(self) -> str:
        """Кто сейчас держит право ("" – свободно)."""
        return self.holder if self._lock.locked() else ""


GENERATION = GenerationGate()  # группа «свой контур»: все профили local и lan – одна видеокарта под разными именами
_EXTERNAL_GATES: dict[str, GenerationGate] = {}
_GATES_LOCK = threading.Lock()


def gate_key(executor: Any) -> str:
    """Группа права на генерацию по профилю, снимку исполнителя или серверу (executors.Server): "own" – свой контур
    (local и lan, как в ADR-0099), "external:<хост>:<порт>" – внешний провайдер."""
    def field(name: str) -> str:
        value = executor.get(name) if isinstance(executor, Mapping) else getattr(executor, name, "")
        return str(value or "")
    if field("trust") != "external":
        return "own"
    import urllib.parse
    try:
        parts = urllib.parse.urlsplit(field("base_url") or field("url"))
        host, port = (parts.hostname or "").lower().rstrip("."), parts.port or 443
    except ValueError:
        host, port = field("base_url"), 443
    try:  # адрес-число – в одном виде: [2606:4700::1111] и полная запись того же адреса – одна группа
        import ipaddress
        host = str(ipaddress.ip_address(host))
    except ValueError:
        try:  # имя – в виде IDNA (как в заголовке Host): «bücher.example» и «xn--bcher-kva.example» – одна группа
            host = host.encode("idna").decode("ascii").lower().rstrip(".")  # «。» тоже точка
        except UnicodeError:
            pass
    return f"external:{host}:{port}"


def gate_for(executor: Any) -> GenerationGate:
    """Право на генерацию группы этого исполнителя: свой контур – общее GENERATION; внешний провайдер – своё на
    каждый хост и порт (одновременно с локальным разбором, к одному провайдеру – по одному запросу)."""
    key = gate_key(executor)
    if key == "own":
        return GENERATION
    with _GATES_LOCK:
        gate = _EXTERNAL_GATES.get(key)
        if gate is None:
            gate = _EXTERNAL_GATES[key] = GenerationGate(f"внешний провайдер {key.split(':', 1)[1].rsplit(':', 1)[0]}")
        return gate
RAW_KEEP = 4000  # сколько знаков неудачного ответа хранить для разбора и отдавать модели при повторе
DETAIL_MAX = 300  # сколько знаков текста ошибки сервера сохранять

# Параметры генерации по умолчанию. Окно контекста задаётся явно: если промпт в него не влезет, Ollama обрежет
# его начало вместе с системным сообщением. Низкая температура и постоянный seed – ответы повторяемы (кэш вердиктов).
DEFAULT_OPTIONS: dict[str, Any] = {"temperature": 0.1, "seed": 42, "num_ctx": 16384, "num_predict": 3072}
# Оценка длины промпта в токенах – сверху, с запасом (локального токенизатора выбранной модели в приложении нет).
# На русском тексте и обычном коде замерено 3,2–3,4 знака на токен, но плотные строки (хеши, base64, случайные
# ключи) и знаки препинания кода дают гораздо больше токенов на знак. Поэтому считается по частям:
# * слово из букв и цифр ASCII – по CHARS_PER_TOKEN знака на токен, «случайное» слово (длинное, в разных регистрах
#   и с цифрами) – по DENSE_CHARS_PER_TOKEN; каждое слово – не меньше одного токена;
# * каждый знак препинания ASCII и каждый управляющий знак – отдельный токен; каждый перевод строки – токен;
# * пробелы и табуляции (отступы, выравнивание) – все вместе по CHARS_PER_TOKEN знака на токен: длинный отступ
#   не проходит бесплатно;
# * кириллица – по CHARS_PER_TOKEN знака на токен; остальные знаки (эмодзи, иероглифы) – по байтам UTF-8;
# * на каждое сообщение – MESSAGE_OVERHEAD_TOKENS служебных токенов шаблона чата, на запрос – TEMPLATE_RESERVE_TOKENS.
# Итог: ни один знак не остаётся неучтённым; любой байт ASCII – не меньше половины токена, байт вне ASCII
# и кириллицы – токен. Строгая верхняя граница «токен на байт» для байтовых BPE-токенизаторов здесь не берётся:
# по ней собственный русский системный промпт (около 12 КБ) занял бы почти всё окно.
# Это эвристика, а не токенизатор модели: верхней границей для любой модели она не доказана. Поэтому срез
# сокращается заранее, если оценка не укладывается в окно за вычетом запаса PROMPT_SAFETY_SHARE (место под ответ
# не трогается), а после ответа сверяется счёт самой модели (prompt_eval_count): больше окна – ответ не принимается.
CHARS_PER_TOKEN = 2.0
PROMPT_SAFETY_SHARE = 0.15  # доля окна (без места под ответ), оставляемая на ошибку оценки
DENSE_CHARS_PER_TOKEN = 1.3
MESSAGE_OVERHEAD_TOKENS = 8
TEMPLATE_RESERVE_TOKENS = 64
ANSWER_RESERVE_TOKENS = 1024  # место под ответ, если num_predict не задан
MIN_ECHO_CHARS = 200  # короче этого прежний ответ модели при повторе не возвращается
_WIDE_CHARS = re.compile(r"[^\x00-\x7fЀ-ӿ]+")  # знаки вне ASCII и кириллицы
_ASCII_WORD = re.compile(r"[A-Za-z0-9_]+")
_CYRILLIC_RUN = re.compile(r"[Ѐ-ӿ]+")
_ASCII_PUNCT = re.compile(r"[!-/:-@\[-^`{-~]")
_LINE_BREAK = re.compile(r"\r\n|[\r\n]")
_BLANKS = re.compile(r"[ \t\f\v]")
_CONTROL = re.compile(r"[\x00-\x08\x0e-\x1f\x7f]")

TYPE_NAMES = {"str": "строка", "text": "текст по существу", "int": "целое число", "number": "число",
              "percent": "целое число от 0 до 100", "bool": "true или false", "list[str]": "список строк",
              "list[int]": "список номеров строк",
              "list[quote]": "список объектов {\"line\": номер строки, \"code\": фрагмент строки}"}
_MEANINGFUL = re.compile(r"\w")  # текст по существу: хоть одна буква или цифра, а не пустая строка или прочерк


class LlmError(Exception):
    """Сбой обращения к модели. Текст – по-русски и без кода находки: его можно показать в интерфейсе.

    status – код HTTP ответа сервера (если был), detail – исходный текст ошибки от сервера одной строкой (до
    DETAIL_MAX знаков; в сам текст исключения он попадает, только если своего описания ошибки нет), stats – замеры
    сделанных попыток (LlmStats) или None, raw – начало последнего ответа модели (для разбора, не для показа всем).
    """

    def __init__(self, message: str, *, status: int | None = None, detail: str = "",
                 stats: LlmStats | None = None, raw: str = "", reason: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.detail = detail
        self.stats = stats
        self.raw = raw
        # известный исход без HTTP-статуса (ADR-0106): «refusal», «pause_turn», «context_window», «unknown_stop»,
        # «bad_tool», «unsupported_block», «length», «bad_format», «finish_error» – ответ получен и разобран,
        # результат известен, повтор обычный
        self.reason = reason
        # передача байтов запроса началась до сбоя: исход для сервера неизвестен (app/llm_http.py, К11 плана 0.9.13)
        self.sent = False
        # сколько секунд сервер просит подождать перед повтором (заголовок Retry-After ответа 429 или 503), None – не просил
        self.retry_after: float | None = None


class ResolveError(LlmError):
    """Имя сервера не разрешилось службой имён (DNS) – ни один байт запроса не ушёл, исход известен: запрос не
    отправлен и не оплачен, повтор безопасен (ADR-0113). sent всегда False, status и reason – None."""


class SendNotAllowed(LlmError):
    """Перед отправкой выяснилось, что запрос к этому серверу не допускается (ADR-0102): профиль выключен, адрес сервера
    не подтверждён, ключ профиля не задан или задан для другого адреса. Запрос не отправлен, прогон встаёт на паузу.
    note – что делать оператору (текст паузы прогона); пусто – общий текст о профиле."""

    def __init__(self, message: str, *, note: str = "", stats: LlmStats | None = None) -> None:
        super().__init__(message, stats=stats)
        self.note = note


UNKNOWN_STATUSES = (None, 502, 504)  # ответа сервера нет или он от посредника: обработал ли запрос провайдер, неизвестно


# Причины, которые клиент ставит сам до отправки (предел отправок, общий срок обращения): запрос не ушёл, ответа
# модели нет – исход прежней оборвавшейся попытки остаётся неизвестным (ревью Codex, круг 19)
NOT_SENT_REASONS = frozenset({"budget", "deadline"})


def model_answered(error: Exception) -> bool:
    """Ошибка несёт исход, полученный от модели (LlmError.reason: ответ получен и разобран), а не отказ клиента до
    отправки (NOT_SENT_REASONS)."""
    reason = getattr(error, "reason", None)
    return bool(reason) and reason not in NOT_SENT_REASONS


def outcome_unknown(error: Exception) -> bool:
    """Исход обращения неизвестен (К11): байты запроса ушли (LlmError.sent), а статуса сервера нет или он от
    посредника (502/504) – запрос мог быть принят и оплачен. Ошибка без статуса, но с известной причиной
    (LlmError.reason – ответ получен и разобран, ADR-0106) исходом неизвестным не считается. Повторной отправки
    неизвестного запроса нет ни на каком пути."""
    if not bool(getattr(error, "sent", False)):
        return False
    status = getattr(error, "status", None)
    if status is None:
        return getattr(error, "reason", None) is None
    return status in UNKNOWN_STATUSES


class JournalError(LlmError):
    """Журнал обмена с моделью недоступен. С 0.8.3 (ADR-0083) не поднимается: сбой записи события request
    учитывается (model_traffic.note_failure), запрос уходит без записи. Класс оставлен для совместимости."""


class PromptOverflowError(LlmError):
    """По счёту самой модели (prompt_eval_count) промпт одной из попыток длиннее окна контекста за вычетом места
    под ответ: начало промпта могло быть обрезано вместе с системным сообщением, ответу не доверяем. Повтора нет:
    промпт повтора длиннее. Замеры полные (stats_partial = False)."""

    stats_partial = False


def _seconds(value: float) -> str:
    return f"{value:g} с".replace(".", ",")


def _one_line(text: Any, limit: int = DETAIL_MAX) -> str:
    return " ".join(str(text).split())[:limit]


MAX_COUNTER = 10 ** 15  # больше – не счётчик Ollama, а мусор (и float из него уже не получить)


def _count(value: Any) -> int:
    """Счётчик или размер из ответа сервера: целое от 1 до MAX_COUNTER, иначе 0."""
    ok = isinstance(value, int) and not isinstance(value, bool) and 0 < value <= MAX_COUNTER
    return value if ok else 0


def norm_model_name(name: Any) -> str:
    """Имя модели для сравнения: без регистра и пробелов; без тега – «:latest», как считает Ollama."""
    n = str(name or "").strip().casefold()
    if n and ":" not in n.rsplit("/", 1)[-1]:
        n += ":latest"
    return n


def is_cloud_model(entry: Mapping[str, Any]) -> bool:
    """Облачная модель Ollama: слово cloud в имени или признаки remote_host, remote_model."""
    names = f"{entry.get('name') or ''} {entry.get('model') or ''}".casefold()
    return "cloud" in names or bool(entry.get("remote_host") or entry.get("remote_model"))


def is_gpt_oss(model: str, info: Mapping[str, Any] | None = None) -> bool:
    """Модель семейства gpt-oss: по семейству из сведений Ollama, а если его нет – по началу имени. Ollama пишет
    семейство по-разному в зависимости от сборки модели: gptoss или gpt-oss."""
    details = (info or {}).get("details")
    family = str(details.get("family") or "").strip().casefold() if isinstance(details, dict) else ""
    if family:
        return family.replace("-", "") == "gptoss"
    return str(model).strip().casefold().rsplit("/", 1)[-1].startswith("gpt-oss")


# ============================================================================ разбор и проверка ответа модели

_THINK_BLOCK = re.compile(r"^\s*<think>.*?</think>", re.S | re.I)  # рассуждение – только в начале ответа
_PAIRS = {"{": "}", "[": "]"}
MAX_JSON_DEPTH = 32  # глубже ответ модели не бывает; глубокая вложенность – мусор или попытка уронить разбор


ABORTED = -1  # _top_level_starts: просмотр прекращён на испорченном объекте, дальше ответ не просмотрен


def _top_level_starts(text: str, pos: int = 0) -> Iterator[int]:
    """Позиции «{», с которых начинаются объекты верхнего уровня (поиск с позиции pos). Вне объектов текст считается
    пояснением: кавычки и квадратные скобки там не учитываются. Внутри объекта строки JSON пропускаются, скобки
    проверяются стеком: при несовпадении скобок или слишком глубокой вложенности объект испорчен, и поиск
    прекращается – последним значением приходит ABORTED, а вложенные части испорченного объекта кандидатами
    не становятся."""
    stack: list[str] = []
    in_string = escaped = False
    for i in range(pos, len(text)):
        ch = text[i]
        if not stack:
            if ch == "{":
                stack.append("}")
                yield i
            continue
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in _PAIRS:
            stack.append(_PAIRS[ch])
            if len(stack) > MAX_JSON_DEPTH:
                yield ABORTED
                return
        elif ch in "}]":
            if stack.pop() != ch:
                yield ABORTED
                return


def _depth_ok(value: Any, limit: int = MAX_JSON_DEPTH) -> bool:
    """Вложенность объекта не глубже limit (без рекурсии)."""
    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        if depth > limit:
            return False
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    return True


_MAX_PROSE_BRACES = 200  # сколько «{» из пояснений пропустить, прежде чем сдаться
_JSON_OBJECT_START = re.compile(r"\{\s*[\"}]")


def _decode_at(decoder: json.JSONDecoder, s: str, start: int) -> dict[str, Any] | None:
    """Объект JSON, начинающийся в позиции start; не объект, испорчен или слишком глубок – None."""
    try:
        obj, _ = decoder.raw_decode(s, start)
    except (ValueError, RecursionError):
        return None
    return obj if isinstance(obj, dict) and _depth_ok(obj) else None


_MAX_OBJECTS = 200  # больше объектов верхнего уровня в ответе – ответ не разбирается совсем


def _json_objects(text: Any, limit: int = _MAX_OBJECTS) -> tuple[list[dict[str, Any]], list[str], str]:
    """Объекты JSON верхнего уровня из ответа модели по порядку -> (объекты, тексты испорченных объектов,
    почему просмотрен не весь ответ: "" – просмотрен весь, "limit" – предел объектов limit или скобок из пояснений,
    "aborted" – несовпадение скобок или слишком глубокая вложенность внутри объекта).

    Ограда ```json и пояснения вокруг объектов допустимы (ограда не содержит «{» и просто пропускается), блок
    <think>…</think> в начале ответа не рассматривается. Объект внутри массива верхнего уровня («[{…}]»)
    принимается. Скобка, которая не может начинать объект JSON (за «{» не идёт «"» или «}»: например, цитата кода
    «for (;;) {» в пояснении), считается частью пояснения – поиск продолжается после неё. Похожий на JSON объект,
    который не разобрался, попадает в список испорченных (текст от его начала до следующего объекта или до конца
    ответа), а его вложенные части кандидатами не становятся никогда."""
    s = _THINK_BLOCK.sub("", str(text or ""), count=1)
    decoder = json.JSONDecoder(strict=False)  # strict=False: переводы строк внутри строк JSON – обычная ошибка моделей
    found: list[dict[str, Any]] = []
    broken: list[str] = []
    pos = 0
    for _ in range(_MAX_PROSE_BRACES):
        restart, bad = None, None  # bad – начало последнего испорченного объекта
        for start in _top_level_starts(s, pos):
            if start == ABORTED:  # испорченный объект: что после него – неизвестно
                broken.append(s[bad:] if bad is not None else "")
                return found, broken, "aborted"
            if bad is not None:
                broken.append(s[bad:start])
                bad = None
            obj = _decode_at(decoder, s, start)
            if obj is not None:
                found.append(obj)
                if len(found) >= limit:
                    return found, broken, "limit"
                continue  # сканер сам проходит объект до его конца: дальше – следующий объект верхнего уровня
            if not _JSON_OBJECT_START.match(s, start):
                restart = start + 1  # «{» из пояснения: дальше снова текст, а не внутренность объекта
                break
            bad = start
        if bad is not None:
            broken.append(s[bad:])
        if restart is None:
            return found, broken, ""
        pos = restart
    return found, broken, "limit"  # скобок из пояснений больше предела: дальше ответ не просмотрен


def extract_json_object(text: Any) -> dict[str, Any] | None:
    """Первый объект JSON верхнего уровня из ответа модели (см. _json_objects); объекта нет – None."""
    found, _, _ = _json_objects(text, limit=1)
    return found[0] if found else None


AMBIGUOUS = "в ответе несколько объектов JSON с ключами ответа – нужен ровно один"
BROKEN = "объект JSON в ответе не разобран: проверь кавычки, запятые и скобки"
TOO_MANY = "в ответе слишком много объектов JSON или фигурных скобок – нужен ровно один объект ответа"


_JSON_STRING = re.compile(r'"(?:\\.|[^"\\\n])*"')


def _mentions_key(part: str, wanted: set[str]) -> bool:
    """В тексте испорченного объекта есть строка JSON, равная ключу ответа (с учётом экранирования «\\u0076»)."""
    for m in _JSON_STRING.finditer(part):
        try:
            if json.loads(m.group(0)) in wanted:
                return True
        except ValueError:
            continue
    return False


def extract_answer(text: Any, keys: Iterable[str]) -> tuple[dict[str, Any] | None, str]:
    """Ответ модели -> (объект, "") или (None, причина).

    Ответ – единственный объект верхнего уровня с хотя бы одним ключом ответа (keys); испорченный объект, в тексте
    которого есть ключ ответа в кавычках, тоже считается. Таких объектов несколько (модель процитировала объект из
    анализируемого кода и дала свой ответ) – (None, AMBIGUOUS): какой из них настоящий, не угадать, а «последний»
    или «в ограде» подделать так же легко, как «первый». Единственный такой объект испорчен – (None, BROKEN).
    Объектов с ключами ответа нет – первый объект JSON (check_answer перечислит недостающие ключи) или (None, "").
    Ответ просмотрен не весь (сотни объектов или скобок) – (None, TOO_MANY), просмотр прерван испорченным объектом
    (несовпадение скобок, слишком глубокая вложенность) – (None, BROKEN): второй объект ответа мог остаться
    за пределом просмотра."""
    wanted = set(keys)
    found, broken, cut = _json_objects(text)
    if cut == "limit":
        return None, TOO_MANY
    if cut == "aborted":
        return None, BROKEN
    answers = [obj for obj in found if wanted & set(obj)]
    broken_answers = [part for part in broken if _mentions_key(part, wanted)]
    if len(answers) + len(broken_answers) > 1:
        return None, AMBIGUOUS
    if answers:
        return answers[0], ""
    if broken_answers:
        return None, BROKEN
    return (found[0] if found else None), ""


_ENUM_SEPARATORS = re.compile(r"[\s_\-" + chr(0x2013) + chr(0x2014) + r"]+")


def _enum_key(value: str) -> str:
    return _ENUM_SEPARATORS.sub("_", value.strip().strip("\"'«».,;:!").casefold())


def match_enum(value: Any, allowed: Iterable[str]) -> str | None:
    """Значение из перечисления без учёта регистра, пробелов и дефисов («True-Positive» -> true_positive)."""
    if not isinstance(value, str):
        return None
    key = _enum_key(value)
    return next((a for a in allowed if _enum_key(a) == key), None)


_NUMBER = re.compile(r"[-+]?\d{1,15}(?:[.,]\d{1,15})?")
# Номер строки: «57», «Foo.java:57», «строка 57», «line 57», «L57», диапазон «60-62», «60–62», «60..62».
_LINE_ITEM = re.compile(r"^(?:[^\n]*:)?\s*(?:строк[аи]?|line|l)?\s*(\d{1,9})"
                        r"(?:\s*(?:[-" + chr(0x2013) + chr(0x2014) + r"]|\.\.)\s*(\d{1,9}))?\s*\.?$", re.I)
MAX_RANGE = 200  # диапазон строк длиннее – только его концы
MAX_LINE = 10_000_000  # номер строки больше – ошибка формата
_BULLET = re.compile(r"^\s*(?:[-*•]|" + chr(0x2013) + r"|\d+[.)])\s+")


def _number(value: Any) -> float | int | None:
    """Число из значения ответа: int, конечный float или строка вида «85», «85%», «0,85»; иначе None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        s = value.strip().rstrip("%").strip()
        if _NUMBER.fullmatch(s):
            n = float(s.replace(",", "."))
            return int(n) if n.is_integer() and "." not in s and "," not in s else n
    return None


def _percent(value: Any) -> int | None:
    """Уверенность по шкале 0–100. Дробь строго между 0 и 1 без знака «%» – доля (0,85 -> 85); иначе число
    понимается как проценты. Вне 0–100 или не число – None."""
    explicit = isinstance(value, str) and value.strip().endswith("%")
    n = _number(value)
    if n is None:
        return None
    if isinstance(n, int):
        return n if 0 <= n <= 100 else None
    if not explicit and 0 < n < 1:
        n *= 100
    return int(round(n)) if 0 <= n <= 100 else None


def _line_item(value: Any, strict: bool = True) -> list[int] | None:
    """Номера строк из одного значения; формат не распознан или номер вне 1..MAX_LINE – None. Пустая часть строки
    («12,,14», «12;») – ошибка при strict=True и пропускается при strict=False."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        value = int(value)
    if isinstance(value, int):
        return [value] if 1 <= value <= MAX_LINE else None
    if isinstance(value, dict):
        return _line_item(value.get("line"), strict)
    if isinstance(value, str):
        result: list[int] = []
        for part in re.split(r"[,;]", value):
            if not part.strip():
                if strict:
                    return None
                continue
            m = _LINE_ITEM.match(part.strip())
            if not m:
                return None
            a = int(m.group(1))
            b = int(m.group(2)) if m.group(2) else a
            if not (1 <= a <= MAX_LINE and 1 <= b <= MAX_LINE):
                return None
            result.extend(range(a, b + 1) if 0 <= b - a <= MAX_RANGE else [a, b])
        return result or None
    return None


def parse_line_numbers(value: Any, strict: bool = True) -> list[int] | None:
    """Номера строк из ответа модели: число, строка («Foo.java:57», «60-62», «12, 14») или список таких значений.

    strict=True – любой нераспознанный, пустой или неположительный элемент делает весь ответ ошибочным (None),
    так что настоящий пустой список отличим от списка из мусора; strict=False – такие элементы пропускаются.
    Результат – по возрастанию, без повторов.
    """
    items = value if isinstance(value, (list, tuple)) else [value]
    result: list[int] = []
    for item in items:
        lines = None if isinstance(item, (list, tuple)) else _line_item(item, strict)
        if lines is None:
            if strict:
                return None
            continue
        result.extend(lines)
    return sorted(set(result))


def _text_item(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool):
        return "да" if value else "нет"
    if isinstance(value, (int, float)):
        return f"{value:g}" if isinstance(value, float) else str(value)
    if isinstance(value, dict):
        parts = [_text_item(v) for v in value.values()]
        return " – ".join(p for p in parts if p)
    return None


def coerce_value(value: Any, kind: str) -> tuple[bool, Any]:
    """Мягкое приведение значения из ответа модели к типу kind (ключ TYPE_NAMES) -> (удалось, значение).

    «85%» -> 85 (число), 0,85 -> 85 (percent), «a\\nb» -> ["a", "b"] (список строк),
    ["Foo.java:57", "60-62"] -> [57, 60, 61, 62] (список номеров строк). text – строка, как str, но пустая строка
    и строка без букв и цифр («-», «...») не подходят.
    """
    if kind == "text":
        ok, text = coerce_value(value, "str")
        return (ok and _MEANINGFUL.search(text) is not None), text
    if kind == "str":
        if isinstance(value, (list, tuple)):
            parts = [_text_item(x) for x in value]
            if any(p is None for p in parts):
                return False, value
            return True, "\n".join(p for p in parts if p)
        text = None if isinstance(value, dict) else _text_item(value)
        return (text is not None), (text if text is not None else value)
    if kind in ("int", "number"):
        n = _number(value)
        if n is None:
            return False, value
        return True, (int(round(n)) if kind == "int" else n)
    if kind == "percent":
        p = _percent(value)
        return (p is not None), (p if p is not None else value)
    if kind == "bool":
        if isinstance(value, bool):
            return True, value
        key = value.strip().casefold() if isinstance(value, str) else ""
        if key in ("true", "да", "yes"):
            return True, True
        if key in ("false", "нет", "no"):
            return True, False
        return False, value
    if kind == "list[str]":
        if isinstance(value, str):
            items = [_BULLET.sub("", line).strip() for line in value.splitlines()]
            return True, [x for x in items if x]
        if isinstance(value, (list, tuple)):
            items = [_text_item(x) for x in value if x is not None]
            if any(x is None for x in items):
                return False, value
            return True, [x for x in items if x]
        return False, value
    if kind == "list[int]":
        lines = parse_line_numbers(value, strict=True)
        return (lines is not None), (lines if lines is not None else value)
    if kind == "list[quote]":
        # цитаты кода (sast-v7): элемент берётся как есть – code строкой без обрезки пробелов, line целым; прочие
        # ключи (status и т. п.) отбрасываются – статус вычисляет приложение (prompts.check_quotes). Неверный
        # элемент (дробный или логический номер, code не строкой) – элемент с пометкой invalid, а не ошибка формата
        # всего ответа: не по формату только значение не списком
        if not isinstance(value, (list, tuple)):
            return False, value
        quotes = []
        for item in value:
            data = item if isinstance(item, Mapping) else {}
            line, code = data.get("line"), data.get("code")
            line_ok = isinstance(line, int) and not isinstance(line, bool)  # номер строки обязателен
            if data.get("invalid") is True:  # пометка первого прохода (check_answer) переживает повторную проверку
                quotes.append({"line": line if line_ok else None, "code": code if isinstance(code, str) else "",
                               "invalid": True})
            elif isinstance(code, str) and line_ok:
                quotes.append({"line": line, "code": code})
            else:
                quotes.append({"line": line if line_ok else None, "code": code if isinstance(code, str) else "",
                               "invalid": True})
        return True, quotes
    return True, value  # тип не задан – как есть


def check_answer(obj: Mapping[str, Any], required: Iterable[str], enums: Mapping[str, Iterable[str]],
                 types: Mapping[str, str] | None = None) -> tuple[dict[str, Any], list[str]]:
    """Проверка объекта из ответа модели -> (объект с приведёнными значениями, список ошибок по-русски).

    Обязательное поле – есть и не null. Поле перечисления – строка из списка (регистр, пробелы и дефисы не важны;
    в результат пишется значение из списка). Поле с типом из types – приводится мягко (coerce_value); поле типа
    text после приведения должно быть текстом по существу, а не пустой строкой или прочерком.
    """
    out = dict(obj)
    problems = [f"нет ключа «{key}»" for key in required if out.get(key) is None]
    for key, allowed in enums.items():
        if out.get(key) is None:
            continue
        allowed = list(allowed)
        value = match_enum(out[key], allowed)
        if value is None:
            problems.append(f"«{key}»: значение не из списка ({', '.join(allowed)})")
        else:
            out[key] = value
    for key, kind in (types or {}).items():
        if key in enums or out.get(key) is None:
            continue
        ok, value = coerce_value(out[key], kind)
        if ok:
            out[key] = value
        elif kind == "text" and coerce_value(out[key], "str")[0]:
            problems.append(f"«{key}»: пусто – нужен текст по существу")
        else:
            problems.append(f"«{key}»: нужен тип «{TYPE_NAMES.get(kind, kind)}»")
    return out, problems


def _dense(word: str) -> bool:
    """«Случайное» слово – длинное, с цифрами и буквами разных регистров (хеш, base64, ключ): токенизатор режет его
    на короткие куски."""
    return (len(word) >= 12 and any(c.isdigit() for c in word) and any(c.islower() for c in word)
            and any(c.isupper() for c in word)) or (len(word) >= 16 and sum(c.isdigit() for c in word) * 4 >= len(word))


def estimate_tokens(text: Any) -> int:
    """Оценка числа токенов текста сверху (правила – у CHARS_PER_TOKEN): слова ASCII, знаки препинания, переводы
    строк, кириллица и прочие знаки – по отдельности; у байтовых BPE-токенизаторов токен не короче байта."""
    s = str(text or "")
    total = 0
    for word in _ASCII_WORD.findall(s):
        total += math.ceil(len(word) / (DENSE_CHARS_PER_TOKEN if _dense(word) else CHARS_PER_TOKEN))
    total += len(_ASCII_PUNCT.findall(s)) + len(_LINE_BREAK.findall(s)) + len(_CONTROL.findall(s))
    total += math.ceil(len(_BLANKS.findall(s)) / CHARS_PER_TOKEN)
    total += sum(math.ceil(len(run) / CHARS_PER_TOKEN) for run in _CYRILLIC_RUN.findall(s))
    total += len("".join(_WIDE_CHARS.findall(s)).encode("utf-8", "surrogatepass"))
    return total


def retry_message(problems: list[str], fields: Mapping[str, str], enums: Mapping[str, Iterable[str]]) -> str:
    """Сообщение для повтора: что не так и каким должен быть ответ."""
    allowed = "; ".join(f"{key} – {', '.join(values)}" for key, values in enums.items())
    text = (f"Предыдущий ответ не принят: {'; '.join(problems[:8])}. Ответь заново: только один объект JSON, "
            f"без Markdown и без текста до и после него. Ключи: {', '.join(fields)}.")
    return text + (f" Допустимые значения: {allowed}." if allowed else "")


# ============================================================================ вспомогательное

def answer_schema(fields: Mapping[str, str], required: Iterable[str], enums: Mapping[str, Iterable[str]],
                  types: Mapping[str, str] | None = None) -> dict[str, Any]:
    """JSON Schema из того же контракта, который проверяет chat_json; без ограничений содержательности."""
    required = list(required)
    types = types or {}
    properties: dict[str, Any] = {}
    scalar = {"str": "string", "text": "string", "int": "integer", "percent": "integer",
              "number": "number", "bool": "boolean"}
    for key in dict.fromkeys([*fields, *required, *enums, *types]):
        kind = types.get(key, "str")
        if key == "terms":
            prop = {"type": "array", "items": {"type": "object", "properties": {
                "term": {"type": "string"}, "meaning": {"type": "string"}},
                "required": ["term", "meaning"], "additionalProperties": False}}
        elif kind == "list[quote]":
            prop = {"type": "array", "items": {"type": "object", "properties": {
                "line": {"type": "integer"}, "code": {"type": "string"}},
                "required": ["line", "code"], "additionalProperties": False}}
        elif kind in ("list[str]", "list[int]"):
            prop = {"type": "array", "items": {"type": "string" if kind == "list[str]" else "integer"}}
        else:
            prop = {"type": scalar.get(kind, "string")}
        if key in enums:
            prop = {"type": "string", "enum": list(enums[key])}
        properties[key] = prop
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


def _token_budget(opts: Mapping[str, Any], safety: bool = True) -> int | None:
    """Сколько токенов промпта помещается в окно контекста вместе с ответом: окно минус весь предел длины ответа
    (num_predict; не задан – ANSWER_RESERVE_TOKENS). safety – ещё минус запас PROMPT_SAFETY_SHARE на ошибку
    оценки (estimate_tokens – эвристика, а не токенизатор модели): по этому бюджету срез сокращается заранее, а место
    под ответ не трогается. Окно не задано – None."""
    num_ctx = _count(opts.get("num_ctx"))
    if not num_ctx:
        return None
    window = num_ctx - (_count(opts.get("num_predict")) or ANSWER_RESERVE_TOKENS)
    return int(window * (1 - PROMPT_SAFETY_SHARE)) if safety else window


def _tokens(messages: Iterable[Mapping[str, Any]]) -> int:
    """Оценка длины сообщений сверху вместе со служебными токенами шаблона чата."""
    items = [m for m in messages if isinstance(m, Mapping)]
    return (TEMPLATE_RESERVE_TOKENS + MESSAGE_OVERHEAD_TOKENS * len(items)
            + sum(estimate_tokens(m.get("content")) for m in items))


def prompt_budget(options: Mapping[str, Any] | None = None, safety: bool = True) -> int | None:
    """Сколько токенов промпта помещается в окно контекста вместе с ответом (параметры – поверх DEFAULT_OPTIONS):
    с запасом на ошибку оценки (safety) или всё окно без запаса (safety=False); окно не задано – None."""
    return _token_budget({**DEFAULT_OPTIONS, **(options or {})}, safety)


def prompt_tokens(messages: Iterable[Mapping[str, Any]]) -> int:
    """Оценка длины сообщений в токенах сверху (estimate_tokens)."""
    return _tokens(messages)


def prompt_fits(messages: Iterable[Mapping[str, Any]], options: Mapping[str, Any] | None = None,
                size: Callable[[Any], int] | None = None) -> bool:
    """Помещается ли промпт в окно контекста вместе с ответом с запасом на ошибку оценки (параметры – поверх
    DEFAULT_OPTIONS). Не помещается – срез или история вопросов сокращаются (триаж, «Спросить модель»). size – оценка
    длины сообщений того клиента, который проверит запрос перед отправкой (у удалённого API – по всему JSON
    сообщения, llm_chat.message_tokens; ревью Codex, круг 18); по умолчанию – по тексту, как у Ollama."""
    budget = prompt_budget(options)
    messages = list(messages)
    return budget is None or (size or _tokens)(messages) <= budget


def _check_prompt_size(messages: list[dict[str, Any]], opts: Mapping[str, Any]) -> None:
    """Промпт должен помещаться в окно контекста вместе с ответом, иначе Ollama обрежет его начало вместе
    с системным сообщением. Длина в токенах оценивается сверху (estimate_tokens); здесь – по всему окну без запаса:
    запас нужен, чтобы сократить срез заранее, а промпт, который сократить уже нельзя, ещё может поместиться.
    Что промпт действительно поместился, видно по счёту самой модели (triage, PROMPT_DOUBT_NOTE)."""
    budget = _token_budget(opts, safety=False)
    if budget is None:
        return
    estimate = _tokens(messages)
    if estimate > budget:
        raise LlmError(f"Промпт (до {estimate} токенов) не помещается в окно контекста модели "
                       f"({_count(opts.get('num_ctx'))} токенов) вместе с ответом. Уменьшите фрагмент кода "
                       "или увеличьте окно контекста (MODEL_NUM_CTX).")

def _retry_messages(messages: list[dict[str, Any]], content: str, retry_text: str,
                    opts: Mapping[str, Any], *, echo: bool = False) -> list[dict[str, Any]]:
    """Исходные сообщения и замечания; эхо прежнего ответа оставлено только для режима off."""
    if not echo:
        result = [dict(m) for m in messages] + [{"role": "user", "content": retry_text}]
        _check_prompt_size(result, opts)
        return result
    full = content.strip()
    keep = min(RAW_KEEP, len(full))
    budget = _token_budget(opts)
    if budget is not None:
        room = budget - _tokens(messages) - estimate_tokens(retry_text)
        while keep > 0 and estimate_tokens(full[:keep]) > room:  # укоротить прежний ответ до свободного места
            keep = min(keep - 1, keep * max(0, room) // max(1, estimate_tokens(full[:keep])))
    echo = full[:max(0, keep)]
    # слишком короткий обрывок прежнего ответа модели не поможет – тогда только перечень ошибок
    useful = bool(echo) and len(echo) >= min(MIN_ECHO_CHARS, len(full))
    extra = [{"role": "assistant", "content": echo}] if useful else []
    result = [dict(m) for m in messages] + extra + [{"role": "user", "content": retry_text}]
    _check_prompt_size(result, opts)
    return result


# ============================================================================ интерфейс клиента

@runtime_checkable
class LlmClient(Protocol):
    """Клиент сервера модели (ADR-0102): то, чем пользуются прогон, вопросы, метрики и настройки. Сейчас его
    реализует OllamaClient (app/llm_ollama.py)."""

    url: str

    def check_url(self) -> str: ...

    def version(self) -> str: ...

    def list_models(self) -> list[dict[str, Any]]: ...

    def ps(self) -> list[dict[str, Any]]: ...

    def unload_model(self, model: str) -> dict[str, Any]: ...

    def model_info(self, model: str) -> dict[str, Any]: ...

    def schema_dropped(self) -> bool: ...

    def chat_json(self, model: str, messages: list[dict[str, Any]], fields: Mapping[str, str],
                  required: Iterable[str], enums: Mapping[str, Iterable[str]], options: Mapping[str, Any] | None = None,
                  think: str | bool | None | Callable[[Mapping[str, Any]], str | bool | None] = None,
                  types: Mapping[str, str] | None = None,
                  validate: Callable[[dict[str, Any]], Iterable[str]] | None = None, progress=None,
                  json_schema: str = "") -> tuple[dict[str, Any], LlmStats]: ...


# Клиент Ollama переехал в app/llm_ollama.py, проверка контейнера – в app/llm_net.py (0.9.12): прежний импорт
# из app.llm продолжает работать. Подменять эти имена в тестах – в их модулях (tests/test_llm_modules.py).
_MOVED = {"OllamaClient": "app.llm_ollama", "read_chat_stream": "app.llm_ollama", "in_container": "app.llm_net"}


def __getattr__(name: str) -> Any:
    module = _MOVED.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(module), name)

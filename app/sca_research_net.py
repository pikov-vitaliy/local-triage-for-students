"""Исследование компонентов провайдером из профиля (ADR-0105, план 0.9.13, К2, К3, К7, К11): тот же контракт ответа и
тот же валидатор, что у файлового задания, но исполнитель – модель по API чат-завершений с инструментами поиска.

Единица работы – один компонент: отдельный диалог «инструкции + строка задания», цикл инструментов search и fetch
(их выполняет приложение запросом к поисковому API того же профиля), итоговая строка ответа. Строка оборачивается в
ответ на подзадание и проверяется тем же validate_answer; годная – новая ревизия с execution_id получения, негодная
после повторов – без изменений с причиной (П20). Метка «отправлено» ставится до
сетевого вызова, успешный результат снимает её в той же транзакции; после неопределённого исхода автоматического
повтора нет ни на каком пути (К11).

Допуск и отзыв (К2): проверка согласия, получения, профиля и задания идёт под общей блокировкой согласия вместе с
передачей байтов запроса (транспорт держит client.gate до конца отправки); отзыв согласия и «Остановить» берут
исключительную – ждут начатую отправку и запрещают следующие.

Что уходит провайдеру: системная часть (инструкции того же источника, что task.md: порядок исследования, открытые
источники, протокол поиска и происхождение, независимые состояния – явно выбранные разделы, без разделов о файлах и
самопроверке) и одна строка задания (row_text: input_ref, экосистема, имя, версия, вид идентичности, кандидат
исправления из выгрузки, публичные идентификаторы уязвимостей) с датой среза и схемой строки ответа. Не уходят:
название системы, кодовые базы, пути, номера находок Hub, внутренние номера анализатора, код, решения оператора,
счётчики находок.
"""

from __future__ import annotations

import hmac
import json
import math
import logging
import re
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from datetime import UTC, date, datetime
from typing import Any

from app import i18n, model_traffic, osv, profile_gate, sca_research as research
from app.executors import DROP_STREAK_PAUSE, drop_retry_allowed
from app.llm import UNKNOWN_STATUSES as llm_unknown_statuses
from app.llm import LlmError, PromptOverflowError, ResolveError, SendNotAllowed, gate_for, model_answered, outcome_unknown
from app.llm_chat import check_fetch_url
from app.llm_http import track_sent
from app.sca_contract import ANSWER_CONTRACT, ROW_SCHEMA, VALIDATOR_VERSION, canonical, sha256, validate_answer

log = logging.getLogger(__name__)

SELECTIONS = i18n.Labels({"all": "все строки задания", "unresearched": "без исследования",
                          "review_due": "требующие пересмотра", "no_defect": "без дефекта",
                          "picked": "отмеченные в таблице", "followup": "доисследование оставшихся"})
MAX_TOOL_RESULT_CHARS = 12_000  # результат инструмента – модели с обрезкой по бюджету
MAX_SEARCH_COUNT = 8
ROW_RETRIES = 2  # повторов не по формату на строку
ROW_SENDS_MAX = 3 + ROW_RETRIES  # отправок /chat/completions на строку сверх ходов инструментов (К3: общий бюджет)
CORRECTION_TOOL_STEPS = 2  # шагов поиска сверх предела после замечания проверки: дочитать источник для исправления
EXTRA_STEPS_MAX = ROW_RETRIES * CORRECTION_TOOL_STEPS  # весь запас на строку: замечаний проверки не больше ROW_RETRIES
ROW_SECONDS_MAX = 20 * 60.0  # срок строки целиком (ходы и инструменты); дольше – строка не получена
TOOL_RETRY_STATUSES = (408, 429, 500, 503)  # поиск: один повтор допустимых статусов; неизвестный исход – никогда
UNKNOWN_STATUSES = llm_unknown_statuses
RESOLVE_ROW_WAIT_S = 10.0  # пауза перед повтором хода модели после сбоя службы имён (ADR-0113): запрос не ушёл
RESOLVE_TOOL_WAIT_S = 5.0  # пауза перед повтором запроса инструмента после сбоя службы имён
RESOLVE_RETRY_NOTE = i18n.N_("Единственный повтор после сбоя службы имён в этой строке уже использован.")
_sleep = time.sleep  # пауза перед повтором (тесты подменяют)
_now = time.monotonic  # часы паузы (тесты подменяют)
# Причины строк и получения пишутся в базу на русском (канонический текст); N_ – перевод при показе (reason_text)
UNKNOWN_NOTE = i18n.N_("Результат неизвестен: запрос мог быть принят и оплачен.")
DROP_STOPPED = i18n.N_("Обрыв без ответа, автоматический повтор не отправлен: получение остановлено.")
DROP_THEN_STOPPED = DROP_STOPPED + " " + UNKNOWN_NOTE
TOOL_UNKNOWN_NOTE = i18n.N_("В строке был запрос инструмента с неизвестным исходом – он мог быть принят и оплачен.")
TOOL_UNKNOWN_STOPPED = i18n.N_("Получение остановлено до ответа модели после неизвестного исхода инструмента: строка "
                               "в очередь не возвращается, доисследовать – по отметке.")
TOOL_UNKNOWN_THEN_STOPPED = TOOL_UNKNOWN_STOPPED + " " + TOOL_UNKNOWN_NOTE
RESEARCH_DROP_STOP = i18n.N_("провайдер обрывает соединения без ответа: {streak} строки подряд – получение "
                             "остановлено, чтобы не тратить запросы впустую; оставшиеся строки можно получить новым "
                             "запуском")

TOOLS = [
    {"type": "function", "function": {
        "name": "search", "description": "Поиск по открытым источникам через поисковый API провайдера. Возвращает "
                                         "список результатов: url, title, snippet.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "поисковый запрос"},
            "count": {"type": "integer", "minimum": 1, "maximum": MAX_SEARCH_COUNT}}, "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "fetch", "description": "Текст страницы по адресу через провайдера (только публичные http(s)-адреса).",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "answer", "description": "Итоговая строка ответа по исследуемому компоненту (объект строки по схеме).",
        # схема строки – в параметрах инструмента, а не только текстом инструкции: заметная часть
        # исправлений – о структуре (список вместо значения, пропущенное обязательное поле)
        "parameters": {"type": "object", "properties": {"row": ROW_SCHEMA}, "required": ["row"]}}},
]
TOOLS_NO_SEARCH = [TOOLS[2]]

# Разделы task.md, которые уходят модели как есть (К7: контракт, доказательства, пределы – побайтно те же, что в
# файловом задании); «Результат и файлы» заменяется своим текстом, «Самопроверка» и прочие файловые – не уходят
SHARED_SECTIONS = ("## Порядок исследования каждой строки", "## Открытые источники", "## Протокол поиска и происхождение",
                   "## Независимые состояния")


# ------------------------------------------------------------------ текст задания для сети

def _sections(text: str) -> dict[str, str]:
    """Разделы task.md по заголовкам второго уровня: {заголовок: тело}."""
    parts = re.split(r"(?m)^(## .+)$", text)
    result: dict[str, str] = {}
    for i in range(1, len(parts) - 1, 2):
        result[parts[i].strip()] = parts[i + 1].strip("\n")
    return result


OSV_ADDRESS_RE = re.compile(r"адрес запроса OSV: (\S+)\)")


def osv_url_from(instructions_text: str) -> str:
    """Адрес OSV из текста инструкций согласия (ADR-0112): запрос делается только по согласию, в котором он назван;
    согласия до 0.9.18 и согласия с OSV_URL=off адреса не содержат – OSV не запрашивается."""
    m = OSV_ADDRESS_RE.search(str(instructions_text or ""))
    return m.group(1) if m else ""


def instructions(search_enabled: bool, osv_url: str = "") -> str:
    """Системная часть диалога: явно выбранные разделы task.md (research.task_text) и свой раздел «Результат»;
    раздел о режиме говорит о различиях сетевого режима перечнем (К7) и называет адрес точного запроса OSV, который
    делает приложение (ADR-0112; osv_url пуст – запроса нет)."""
    sections = _sections(research.task_text({"task_id": "-"}, []))
    missing = [name for name in SHARED_SECTIONS if name not in sections]
    assert not missing, f"в task_text нет разделов {missing}"
    result = ("## Результат\n\n"
              "Исследуйте одну строку задания (сообщение пользователя) по открытым источникам и верните одну строку "
              "ответа по схеме строки: либо объектом JSON в тексте ответа, либо вызовом инструмента answer с аргументом "
              "row. Ответ проверяется той же программой, что и файловый ответ; замечания проверки вернутся вам для "
              "исправления. Исходные input_ref, ecosystem, component, current_version должны совпадать с заданием. "
              "hub_fix_candidate – непроверенный кандидат из исходной выгрузки, а не готовый совет. vulnerability_ids – "
              "публичные идентификаторы (CVE, GHSA, БДУ), которые указал анализатор в исходной выгрузке: подсказка, с "
              "чего начать поиск, а не доказательство применимости – проверьте каждый по источникам и ищите и другие. "
              "Внутренние номера анализатора (AST-…) не исследуйте, не восстанавливайте и не включайте в ответ. "
              "В research_coverage[].query указывайте то, что проверяли для этой строки: ecosystem и version – ровно "
              "из задания (version = current_version), а не последнюю или целевую версию; coordinates – те же, что в "
              "identity_resolution.coordinates. Проверки других версий (исправления, цели) – в version_checks. Типы и "
              "обязательные поля – строго по схеме строки (она же – параметры инструмента answer): списки – списками, "
              "все обязательные поля заполнены.\n")
    if osv_url:
        osv_note = ("Точный запрос к API OSV приложение делает само до обращения к вам (адрес запроса OSV: "
                    f"{osv_url}) и кладёт ответ в поле osv первого сообщения: status ok – уязвимости OSV для этой пары "
                    "координаты/версия (id, aliases, summary, диапазоны affected по этому пакету, ссылки; списки versions "
                    "опущены); empty – OSV уязвимостей этой пары не знает (покрытие OSV – complete с пустым результатом); "
                    "partial – ответ OSV неполный (есть продолжение или часть записей не показана, см. note; покрытие OSV – "
                    "partial); unsupported или error – запрос не делался или не удался, причина в note (покрытие OSV – "
                    "error с этой причиной). Поисковая выдача ответ OSV не заменяет, а ответ OSV не заменяет проверку "
                    "advisories разработчика и GitHub Advisory Database.")
    else:
        osv_note = ("Точного запроса к API OSV в этом режиме нет и приложение его не делает (поля osv в сообщении нет): "
                    "покрытие источника «OSV» отмечайте partial или error с причиной, поисковая выдача успешный запрос "
                    "OSV не заменяет.")
    if search_enabled:
        mode = ("## Режим: поиск через инструменты\n\n"
                "Доступны инструменты search (поисковый API провайдера) и fetch (текст страницы); к API OSV они не "
                f"обращаются. {osv_note} Остальные требования к доказательствам и протоколу те же. Число вызовов "
                "инструментов ограничено: получив сообщение «предел шагов исчерпан», дайте ответ по собранному.\n")
    else:
        osv_except = ", кроме OSV," if osv_url else ""
        osv_cov = " покрытие OSV – по полю osv;" if osv_url else ""
        mode = ("## Режим: без поиска по источникам\n\n"
                f"Инструментов поиска нет: отвечайте по собственным знаниям, каждую запись research_coverage{osv_except} "
                "помечайте partial с причиной «без поиска по источникам» и указывайте источники, которые следует "
                f"проверить;{osv_cov} {osv_note} Выдумывать URL и цитаты запрещено.\n")
    body = "\n\n".join(f"{name}\n\n{sections[name]}" for name in SHARED_SECTIONS)
    # язык ответа (ADR-0158): при английском интерфейсе – отдельная последняя строка, не раздел «## »; первое сообщение
    # пользователя – чистый JSON строки задания и не меняется. Строка входит в текст инструкций, а он – в отпечаток
    # согласия: язык ответа – часть того, на что дано согласие, и получение отправляет сохранённый текст согласия
    language = "".join(f"\n{line}\n" for line in research.answer_language_lines())
    return ("# Исследование компонента программного обеспечения\n\n" + mode + "\n" + result + "\n" + body
            + "\n\n## Схема строки ответа\n\n" + json.dumps(ROW_SCHEMA, ensure_ascii=False, sort_keys=True) + "\n"
            + language)


def row_message(row: Mapping[str, Any], cutoff_date: str, osv_answer: Mapping[str, Any] | None = None) -> str:
    """Первое сообщение пользователя: одна строка задания, дата среза и ответ OSV на её пару координаты/версия
    (ADR-0112; None – запрос OSV выключен, поля нет) – ничего сверх перечня ADR-0105 п. 1."""
    payload: dict[str, Any] = {"cutoff_date": cutoff_date, "row": research.row_text(row)}
    if osv_answer is not None:
        payload["osv"] = {k: v for k, v in dict(osv_answer).items() if k != "seconds"}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def consent_fingerprint(instructions_text: str, cutoff_date: str, rows: Sequence[str], model: str,
                        search_mode: str, tool_steps: int, components_sha256: str,
                        execution: Mapping[str, Any], project_id: int = 0, task_id: str = "") -> str:
    """Отпечаток согласия: проект и задание, инструкции, дата среза, строки, модель, режим поиска, ограничитель,
    состав и полный снимок исполнителя (адрес, версия профиля, параметры рассуждения и поиска) – изменилось любое, в
    том числе профиль при тех же модели и поиске, – новое согласие. Проект и задание в отпечатке: форма одного проекта
    не подходит другому с теми же координатами строк (ревью, круг 3)."""
    snapshot = {k: v for k, v in dict(execution).items() if k not in ("digest", "note")}
    return sha256(canonical([int(project_id), str(task_id), instructions_text, cutoff_date, list(rows), model,
                             search_mode, int(tool_steps), components_sha256, snapshot]))


def preview_token(secret: bytes, fingerprint: str, nonce: str) -> str:
    """Серверная метка предпросмотра: HMAC по отпечатку и одноразовому номеру страницы. Получить её можно только
    отрисовкой предпросмотра на этом экземпляре: прямой POST с пересчитанным отпечатком не проходит. Та же метка –
    ключ согласия: повтор той же формы возвращает прежнее согласие и получение, а не второе."""
    return hmac.new(bytes(secret), f"{fingerprint}:{nonce}".encode("utf-8"), "sha256").hexdigest()


def calls_estimate(rows: int, tool_steps: int) -> int:
    """Верхняя оценка числа обращений к провайдеру: на строку – ходы диалога (не больше ROW_SENDS_MAX сверх шагов
    инструментов) и запросы инструментов (каждый шаг – до двух попыток); шагов – предел профиля и запас на
    исправления после замечаний проверки (EXTRA_STEPS_MAX, ревью Codex, круг 19)."""
    steps = int(tool_steps) + EXTRA_STEPS_MAX
    return int(rows) * (steps + ROW_SENDS_MAX + 2 * steps)


def today_cutoff() -> str:
    return date.today().isoformat()


# ------------------------------------------------------------------ блокировка согласия (К2)

_consent_gates: dict[int, profile_gate.ProfileGate] = {}
_consent_lock = threading.Lock()


def consent_gate(consent_id: int) -> profile_gate.ProfileGate:
    """Блокировка согласия (одна на процесс): отправка держит общую до передачи байтов, отзыв и остановка – исключительную."""
    with _consent_lock:
        return _consent_gates.setdefault(int(consent_id), profile_gate.ProfileGate())


composition_gate = profile_gate.ProfileGate()
"""Граница «состав проекта – отправка» (ревью, круг 3): отправка строки держит общую блокировку вместе с проверкой
состава (допуск), а запись новой выгрузки, подтверждения сомнительных имён и настройки отбора компонентов – исключительную:
состав не меняется между проверкой отпечатка и передачей байтов."""


@contextmanager
def composition_change() -> Iterator[None]:
    """Запись, меняющая состав проекта (выгрузка, подтверждения имён, настройки отбора): ждёт конца начатых отправок
    исследования и не даёт начать новые, пока идёт."""
    with composition_gate.write():
        yield


# ------------------------------------------------------------------ проверка строки

def _subtask(task: Mapping[str, Any], row: Mapping[str, Any]) -> dict[str, Any]:
    return {"task_id": task["task_id"], "manifest_sha256": task.get("manifest_sha256", ""), "row_count": 1,
            "rows": [research.row_text(row)]}


def check_row(task: Mapping[str, Any], row: Mapping[str, Any], answer_row: Mapping[str, Any]) -> Any:
    """Строка ответа модели – в ответ на подзадание и тем же валидатором; generated_at – время приложения."""
    answer = {"contract": ANSWER_CONTRACT, "task_id": task["task_id"],
              "manifest_sha256": task.get("manifest_sha256", ""), "validator_version": VALIDATOR_VERSION,
              "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "row_count": 1,
              "rows": [dict(answer_row)]}
    # замечания проверки уходят модели (инструкции на русском) и в причину строки в базе (канонический русский текст,
    # перевод – при показе, reason_text) – поэтому всегда на русском, при любом языке интерфейса (ADR-0158)
    with i18n.use("ru"):
        return validate_answer(json.dumps(answer, ensure_ascii=False), _subtask(task, row))


def _calls(message: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [c for c in message.get("tool_calls") or [] if isinstance(c, dict)]


def _call_name(call: Mapping[str, Any]) -> str:
    return str((call.get("function") or {}).get("name") or "")


def _call_args(call: Mapping[str, Any]) -> dict[str, Any]:
    try:
        args = json.loads(str((call.get("function") or {}).get("arguments") or "{}"))
    except ValueError:
        return {}
    return args if isinstance(args, dict) else {}


def _answer_from(message: Mapping[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Конец цикла: строка либо вызовом инструмента answer, либо в content (один объект JSON) (К7)."""
    for call in _calls(message):
        if _call_name(call) == "answer":
            row = _call_args(call).get("row")
            return (row, "") if isinstance(row, dict) else (None, "в вызове answer нет объекта row")
    content = str(message.get("content") or "").strip()
    if not content:
        return None, ""
    from app.llm import extract_answer
    obj, why = extract_answer(content, ["input_ref", "package_status"])
    return (obj, "") if obj is not None else (None, why or "в ответе нет объекта JSON строки")


def _trim(text: str, limit: int = MAX_TOOL_RESULT_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + "\n…[обрезано приложением]"


# ------------------------------------------------------------------ цикл одного компонента

class RowOutcome:
    def __init__(self, on_change: Callable[[], None] | None = None) -> None:
        self.tools: list[dict[str, Any]] = []
        self.usage: dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0, "reasoning_tokens": 0,
                                      "cache_hit_tokens": 0, "search_calls": 0, "fetch_calls": 0, "osv_calls": 0,
                                      "sends": 0}
        self.sent = False  # байты хоть одного запроса переданы (признак транспорта, К11)
        self.on_change = on_change  # ход строки – в живое состояние получения (страница хода, B4)
        self.deadline: float | None = None  # общий срок строки (К3): инструменты его не переживают
        # один автоматический повтор хода после обрыва без ответа (отметка профиля)
        self.retry_on_drop = False
        self.drop_retries = 0
        # ход оборвался без ответа, и повтор ещё не получил ответа модели: строка при любом выходе (остановка, срок,
        # отказ допуска, ошибка повтора) – «результат неизвестен», а не очередь (ревью Codex, круг 18)
        self.pending_unknown = False
        # неизвестный исход запроса инструмента (ADR-0111): строка продолжается, но тот же запрос повторно не
        # отправляется (отпечатки – инструмент и фактические аргументы), а остановка до ответа модели даёт
        # «результат неизвестен», не очередь (ревью Codex, круг 29)
        self.tool_unknown = False
        self.unknown_calls: set[tuple[str, str]] = set()
        # имя сервера не разрешилось до отправки хода (ADR-0113): один повтор хода на строку после паузы
        self.resolve_retries = 0
        self.stop: Callable[[], bool] = lambda: False  # проверка остановки для пауз инструментов (ставит research_component)

    def changed(self) -> None:
        if self.on_change is not None:
            self.on_change()

    def add_usage(self, usage: Mapping[str, Any]) -> None:
        for key in ("prompt_tokens", "completion_tokens", "reasoning_tokens", "cache_hit_tokens"):
            self.usage[key] += int(usage.get(key) or 0)


class ResearchStopped(Exception):
    """Остановка оператором или отзыв согласия: текущая строка не отправляется."""


class UnknownOutcome(LlmError):
    """Обращение ушло, исход неизвестен. Ход модели: цикл прекращается, строка – «результат неизвестен» (К11).
    Инструмент: строка продолжается, модель получает «результат неизвестен», тот же запрос повторно не отправляется
    (ADR-0111)."""


def _unknown(e: LlmError) -> bool:
    return outcome_unknown(e)


def _pause(stop: Callable[[], bool], seconds: float, deadline: float | None) -> bool:
    """Пауза перед повтором запроса, который не был отправлен (ADR-0113): по полсекунды с проверкой остановки. False –
    ждать некогда (срок строки истечёт раньше), повтора нет; остановка получения во время паузы прерывает её, повтор
    не отправляется – остановку видит проверка stop() перед следующим запросом."""
    if deadline is not None and _now() + seconds >= deadline:
        return False
    slices = max(1, math.ceil(seconds / 0.5))  # по числу долей, не по часам: подменённая пауза не крутит цикл
    for i in range(slices):
        if stop():
            break
        step = min(0.5, seconds - 0.5 * i)
        if deadline is not None and _now() + step >= deadline:
            return False  # срок строки подошёл во время паузы: повтора нет
        _sleep(step)
    return True


def research_component(client: Any, model: str, task: Mapping[str, Any], row: Mapping[str, Any], system: str,
                       cutoff_date: str, search: Mapping[str, str] | None, tool_steps: int,
                       stop: Callable[[], bool], outcome: RowOutcome,
                       osv_answer: Mapping[str, Any] | None = None) -> tuple[dict[str, Any] | None, str]:
    """Диалог по одному компоненту до строки ответа. Вызовы инструментов – фактически выполненные, включая несколько
    tool_calls в одном ответе; каждый tool_call_id закрывается сообщением tool; сверх предела – «предел шагов
    исчерпан»; ответ ассистента возвращается в историю целиком (включая reasoning_content). Бюджет отправок на
    строку сверх ходов инструментов – ROW_SENDS_MAX (К3). Возвращает (строка, причина отказа)."""
    tools = TOOLS if search else TOOLS_NO_SEARCH
    messages: list[dict[str, Any]] = [{"role": "system", "content": system},
                                      {"role": "user", "content": row_message(row, cutoff_date, osv_answer)}]
    # К3: один бюджет на строку – фактические отправки /chat/completions (с повторами транспорта) не больше
    # ROW_SENDS_MAX сверх фактически сделанных шагов инструментов (каждый шаг – один ход), повтор транспорта на
    # строку – один, срок строки – ROW_SECONDS_MAX; ход только с вызовами инструментов тоже расходует бюджет
    deadline = time.monotonic() + ROW_SECONDS_MAX
    outcome.deadline = deadline
    steps_used = retries = extra_steps = 0
    http_retried = False
    outcome.stop = stop
    while True:
        if stop():
            raise ResearchStopped()
        sends_limit = steps_used + ROW_SENDS_MAX
        if outcome.usage["sends"] >= sends_limit:
            return None, f"исчерпан бюджет отправок на строку ({sends_limit}) – ответа нет"
        if time.monotonic() >= deadline:
            return None, f"исчерпан срок строки ({int(ROW_SECONDS_MAX)} с) – ответа нет"
        with track_sent() as tracker:
            try:
                # остаток бюджета, общий срок и право на единственный повтор транспорта – внутрь хода; отправки
                # сорвавшегося хода тоже учитываются (LlmError.sends)
                turn = client.chat_turn(model, messages, tools=tools, max_sends=sends_limit - outcome.usage["sends"],
                                        deadline=deadline, allow_http_retry=not http_retried)
            except LlmError as e:
                outcome.usage["sends"] += int(getattr(e, "sends", 0) or 0)
                if int(getattr(e, "http_retries", 0) or 0):
                    http_retried = True  # повтор транспорта внутри сорвавшегося хода был – на строку он один (К3)
                stats = getattr(e, "stats", None)
                if stats is not None:  # расход полученного ответа известной ошибки (ревью круг 15, находка 5)
                    outcome.add_usage({"prompt_tokens": stats.prompt_tokens, "completion_tokens": stats.output_tokens,
                                       "reasoning_tokens": stats.reasoning_tokens,
                                       "cache_hit_tokens": stats.cache_hit_tokens})
                outcome.changed()
                # обрыв без ответа: один повтор того же хода на строку (отметка профиля), в пределах бюджета отправок
                # и срока строки; второй обрыв – «результат неизвестен», как раньше
                if model_answered(e):
                    # ответ модели получен – исход известен; срок или предел отправок до отправки – не ответ (ревью
                    # Codex, круг 19): исход прежнего обрыва остаётся неизвестным
                    outcome.pending_unknown = False
                if isinstance(e, ResolveError) and not outcome.resolve_retries:
                    # имя сервера не разрешилось – этот запрос не отправлен и не оплачен (ADR-0113), даже если прежние
                    # отправки того же хода (429 с повтором) ушли: один повтор того же хода на строку после паузы;
                    # остановка во время паузы – через проверку в начале цикла. Пауза не состоялась (срок) – повтора нет
                    if _pause(stop, RESOLVE_ROW_WAIT_S, deadline):
                        outcome.resolve_retries = 1
                        continue
                if (outcome.retry_on_drop and not outcome.drop_retries and _unknown(e)
                        and not isinstance(e, (SendNotAllowed, PromptOverflowError))
                        and not getattr(e, "reason", None)):
                    outcome.drop_retries = 1
                    outcome.pending_unknown = True
                    continue
                raise
            finally:
                outcome.sent = outcome.sent or tracker.sent
        outcome.add_usage(turn.usage)
        outcome.usage["sends"] += int(turn.sends or 1)
        outcome.pending_unknown = False  # ход получил ответ модели – исход прежнего обрыва больше не открыт
        if int(getattr(turn, "http_retries", 0) or 0):
            http_retried = True  # повтор после 429 внутри хода был – на строку он один (ревью Codex, круг 18)
        outcome.changed()
        message = dict(turn.message)
        messages.append(message)
        calls = _calls(message)
        tool_calls = [c for c in calls if _call_name(c) != "answer"]
        has_answer = any(_call_name(c) == "answer" for c in calls)
        if turn.finish_reason == "length":
            # ответ оборван по длине: инструменты не выполняются (аргументы вызовов могли не дописаться), повтора нет;
            # закрытый объект строки в тексте или в вызове answer, прошедший проверку, принимается (К3, К7)
            answer_row, why = _answer_from(message)
            if answer_row is None:
                return None, "ответ модели оборван по длине (предел ответа профиля) – повтора нет"
            report = check_row(task, row, apply_osv_outcome(answer_row, row, osv_answer, cutoff_date))
            if report.ok:
                return dict(report.answer["rows"][0]), ""
            problems = "; ".join(f"{e.get('path')}: {e.get('message')}" for e in report.errors[:12])
            return None, f"ответ оборван по длине и не прошёл проверку – повтора нет: {problems}"
        if tool_calls:
            for call in tool_calls:
                if steps_used >= tool_steps + extra_steps:
                    result = "предел шагов исчерпан: дайте ответ по собранному"
                else:
                    steps_used += 1
                    result = _run_tool(client, search, _call_name(call), _call_args(call), outcome, steps_used)
                messages.append({"role": "tool", "tool_call_id": str(call.get("id") or ""), "content": result})
            if not has_answer:
                continue
        answer_row, why = _answer_from(message)
        for call in calls:  # вызов answer тоже закрывается сообщением tool – протокол требует ответа на каждый
            if _call_name(call) == "answer":
                messages.append({"role": "tool", "tool_call_id": str(call.get("id") or ""), "content": "строка принята на проверку"})
        if answer_row is None:
            if turn.finish_reason == "length":
                return None, "ответ модели оборван по длине (предел ответа профиля) – повтора нет"
            if tool_calls:  # смешанный набор: инструменты выполнены, ответа нет – следующий ход
                continue
            retries += 1
            if retries > ROW_RETRIES:
                return None, why or "ответ без строки"
            messages.append({"role": "user", "content": "Ответ не содержит строки: верните один объект JSON строки ответа "
                                                        "по схеме или вызовите инструмент answer с аргументом row."})
            continue
        # покрытие OSV приложение приводит к исходу своего запроса (ADR-0112) до проверки: валидатор пересчитает статус
        # строки по покрытию, и ложный «уязвимостей нет» при неудавшемся OSV уйдёт в цикл исправления
        report = check_row(task, row, apply_osv_outcome(answer_row, row, osv_answer, cutoff_date))
        if report.ok:
            return dict(report.answer["rows"][0]), ""
        problems = "; ".join(f"{e.get('path')}: {e.get('message')}" for e in report.errors[:12])
        if turn.finish_reason == "length":
            return None, f"ответ оборван по длине и не прошёл проверку – повтора нет: {problems}"
        retries += 1
        if retries > ROW_RETRIES:
            return None, f"ответ не прошёл проверку после {ROW_RETRIES} повторов: {problems}"
        # запас шагов поиска на исправление: замечание может требовать источника, а предел шагов уже исчерпан – без
        # них модель переписывает ответ по памяти и ошибается снова.
        # После замечания доступно не меньше CORRECTION_TOOL_STEPS шагов; замечание называет ровно столько, сколько
        # осталось, и только если поиск есть (ревью Codex, круг 19)
        hint = ""
        if search:
            left = tool_steps + extra_steps - steps_used
            if left < CORRECTION_TOOL_STEPS:
                extra_steps += CORRECTION_TOOL_STEPS - left
                left = CORRECTION_TOOL_STEPS
            word = "шага" if 2 <= left % 10 <= 4 and not 12 <= left % 100 <= 14 else "шагов"
            hint = f" Если для исправления нужен источник, доступно ещё {left} {word} поиска."
        messages.append({"role": "user", "content": "Проверка строки нашла замечания – исправьте и верните строку "
                                                    f"заново: {problems}.{hint}"})


OSV_HOSTS = frozenset({"osv.dev", "www.osv.dev", "api.osv.dev"})
OSV_WRAP = "`*_~|()[]<>\"'«»,;:!?."  # оформление и пунктуация по краям слова
OSV_WORDS = frozenset({"osv", "osv.dev", "google", "api", "database", "db"})  # слова названия OSV
OSV_HOST_START_RE = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+(?=$|[:/?#])", re.IGNORECASE)


def _osv_host(url: str) -> str:
    """Имя узла адреса без конечной точки (из authority: userinfo и порт его не меняют); нечитаемый адрес – пустая
    строка."""
    try:
        return (urllib.parse.urlsplit(url if url.lower().startswith("http") else "https:" + url).hostname or "").rstrip(".").casefold()
    except ValueError:
        return ""


def _osv_word(token: str) -> bool | None:
    """Слово названия источника (без пробелов; оформление и пунктуация по краям снимаются): True – само OSV («osv»,
    «osv.dev») или адрес с узлом OSV (со схемой, с «//» или начинающийся с «узел.домен»; узел – только из authority);
    False – слово названия OSV без самого OSV («google», «api», «database», «db») или пустое; None – чужое: любое
    другое слово, чужой адрес, markdown-ссылка, «http:osv.dev», «OSV/NVD», «osv-vulnerability-db»."""
    word = token.strip(OSV_WRAP)
    if not word:
        return False
    lowered = word.casefold()
    if lowered.startswith(("//", "http://", "https://")):
        return True if _osv_host(word) in OSV_HOSTS else None
    if OSV_HOST_START_RE.match(word):
        return True if _osv_host("//" + word) in OSV_HOSTS else None
    if lowered in ("osv", "osv.dev"):
        return True
    return False if lowered in OSV_WORDS else None


def _osv_source(name: Any) -> bool:
    """Запись покрытия относится к OSV – только при строгом совпадении названия: строка делится по пробелам, каждое
    слово – слово названия OSV или адрес узла OSV (_osv_word), и хотя бы одно слово – само OSV. Распознаются OSV,
    osv.dev, api.osv.dev, Google OSV, OSV (Google), OSV.dev API, OSV database, OSV (https://osv.dev),
    https://api.osv.dev:443/v1/query, `https://osv.dev`, **OSV**, https://user:pass@osv.dev/, example.invalid:443@osv.dev/.
    Всё остальное – не OSV, в том числе формы с OSV внутри («[OSV](https://osv.dev)», «OSV/NVD», «osv-vulnerability-db»,
    «см. OSV») и любые чужие названия и адреса («ProsVuln», «nvd.nist.gov/?u=https://osv.dev»,
    «osv.dev:443@example.invalid/», «[NVD](https://nvd.nist.gov/?q=osv)», «https://nvd.nist.gov/?q=[OSV](x)»).
    Строгость намеренная (ревью кругов 41–49): распознавание OSV в свободном тексте не сходится, а цена ошибки
    несимметрична – переписанная чужая запись искажает покрытие, тогда как нераспознанная запись OSV безвредна:
    apply_osv_outcome добавляет рядом свою запись OSV с настоящим исходом, и статус строки считается честно."""
    marks = [_osv_word(token) for token in str(name or "").split()]
    return bool(marks) and None not in marks and any(marks)


def apply_osv_outcome(answer_row: Mapping[str, Any], row: Mapping[str, Any], osv_answer: Mapping[str, Any] | None,
                      checked_at: str) -> dict[str, Any]:
    """Покрытие OSV в ответе модели – по исходу запроса OSV, который приложение знает само (ADR-0112): после
    error, unsupported или partial каждая запись research_coverage по источнику OSV (строгое распознавание _osv_source:
    нераспознанная форма остаётся как есть, запись OSV добавляется рядом) получает статус error (для
    unsupported – тоже error: запрос не делался) или partial и complete false с причиной; если записи OSV с назначением
    vulnerabilities нет – она добавляется (запись OSV другого назначения её не заменяет). Делается до проверки
    валидатором: статус строки он пересчитывает по покрытию, поэтому ложный «no_known_vulnerabilities» при
    неудавшемся OSV отвергается как несовпадение статуса и уходит в цикл исправления. Исход ok или empty и выключенный
    OSV (None) ответ не меняют; research_coverage не список (кроме отсутствующего поля и null – они считаются пустым
    списком) – не трогается, валидатор отвергнет структуру; в ветке обрыва по длине исправления нет – отказ.
    Координаты добавленной записи – как разрешила модель (identity_resolution.coordinates: валидатор сверяет с ними
    каждую запись), иначе из задания. Возвращает копию строки."""
    result = {**dict(answer_row)}
    if not osv_answer:
        return result
    status = str(osv_answer.get("status") or "")
    if status not in ("error", "unsupported", "partial"):
        return result
    source = result.get("research_coverage")
    if source is None:
        source = []
    if not isinstance(source, list):
        return result
    forced = "partial" if status == "partial" else "error"
    reason = f"по данным приложения: ответ OSV – {status}" + (f" ({str(osv_answer.get('note') or '')[:300]})" if osv_answer.get("note") else "")
    coverage = []
    has_vulns_record = False
    for item in source:
        if not isinstance(item, Mapping) or not _osv_source(item.get("source")):
            coverage.append(item)
            continue
        if str(item.get("purpose") or "") == "vulnerabilities":
            has_vulns_record = True
        own = str(item.get("note") or "").strip()[:1500]  # место для причины приложения остаётся всегда
        coverage.append({**dict(item), "status": forced, "complete": False, "note": f"{own}; {reason}" if own else reason})
    if not has_vulns_record:
        identity = result.get("identity_resolution")
        resolved = str(identity.get("coordinates") or "").strip() if isinstance(identity, Mapping) else ""
        coverage.append({"source": "OSV", "purpose": "vulnerabilities",
                         "query": {"ecosystem": str(row.get("ecosystem") or ""),
                                   "coordinates": resolved or str(row.get("component") or row.get("name") or ""),
                                   "version": str(row.get("version") or "")},
                         "source_refs": [], "checked_at": checked_at, "status": forced, "complete": False, "note": reason})
    result["research_coverage"] = coverage
    return result


def _int_arg(value: Any, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError):
        return default


def _run_tool(client: Any, search: Mapping[str, str] | None, name: str, args: Mapping[str, Any],
              outcome: RowOutcome, step: int) -> str:
    """Выполнить инструмент модели: search и fetch – запросом к поисковому API того же профиля (журнал обмена пишет
    запрос и ответ байт в байт до обрезки; контекст – назначение с номером шага). Ошибка с неизвестным исходом –
    результат «не удалось» для модели без повтора запроса (ADR-0111; до 0.9.17 – обрыв строки, К11); допустимые
    статусы – один повтор."""
    started = time.monotonic()
    entry: dict[str, Any] = {"step": step, "tool": name, "status": "", "results": 0, "seconds": 0.0}
    outcome.tools.append(entry)
    outcome.changed()
    try:
        if not search or name not in ("search", "fetch"):
            entry["status"] = "unavailable"
            return f"инструмент {name} недоступен"
        if outcome.deadline is not None and time.monotonic() >= outcome.deadline:
            entry["status"] = "error"
            entry["error"] = "срок строки исчерпан"
            return f"сбой инструмента {name}: срок строки исчерпан – дайте ответ по собранному"
        if name == "search":
            query = str(args.get("query") or "")[:128]
            entry["query"] = query
            count = _int_arg(args.get("count"), 5, 1, MAX_SEARCH_COUNT)
            if not query.strip():
                entry["status"] = "error"
                return "сбой инструмента search: пустой запрос"
            # отпечаток – нормализованный запрос, как его отправит клиент (llm_chat.search)
            key = ("search", " ".join(query.split())[:128])
            if key in outcome.unknown_calls:
                return _repeat_refused(entry, name)
            data = _tool_request(client, outcome, f"research:search:{step}",
                                 lambda: client.search(search["search_path"], query, count, deadline=outcome.deadline),
                                 "search_calls")
            results = next((v for v in data.values() if isinstance(v, list)), []) if isinstance(data, dict) else []
            entry["status"], entry["results"] = "ok", len(results)
            return _trim(json.dumps(results, ensure_ascii=False)) if results else "поиск выполнен: результатов нет"
        url = check_fetch_url(args.get("url"))
        entry["url"] = url[:500]
        key = ("fetch", url)
        if key in outcome.unknown_calls:
            return _repeat_refused(entry, name)
        data = _tool_request(client, outcome, f"research:fetch:{step}",
                             lambda: client.fetch(search["fetch_path"], url, deadline=outcome.deadline), "fetch_calls")
        text = str((data.get("content") if isinstance(data, dict) else data) or "")
        entry["status"], entry["results"] = ("ok", 1) if text else ("empty", 0)
        return _trim(text) if text else "страница получена: содержимого нет"
    except UnknownOutcome as e:
        # ADR-0111 (п. 22 бэклога): инструмент – не ответ модели; его неизвестный исход
        # (обрыв, 502/504 посредника) не обрывает строку – модель получает «страница не получена» и завершает
        # строку по собранному. Запрос инструмента мог быть оплачен: признак outcome.sent остаётся, шаг – «unknown»,
        # тот же запрос повторно не отправляется (отпечаток в outcome.unknown_calls, ревью Codex круг 29).
        entry["status"] = "unknown"
        entry["error"] = str(e)[:300]
        outcome.tool_unknown = True
        outcome.unknown_calls.add(key)
        return (f"сбой инструмента {name}: результат неизвестен ({e}); эту страницу или выдачу получить не удалось – "
                f"дайте ответ по собранному, не повторяя запрос")
    except ResearchStopped:
        entry["status"] = "error"
        entry["error"] = "получение остановлено во время паузы перед повтором"
        raise
    except LlmError as e:
        entry["status"] = "error"
        entry["error"] = str(e)[:300]
        if getattr(e, "status", None) == 402:
            raise  # «пополните баланс» – остановка исследования (К7)
        return f"сбой инструмента {name}: {e}"
    finally:
        entry["seconds"] = round(time.monotonic() - started, 3)
        outcome.changed()


def _repeat_refused(entry: dict[str, Any], name: str) -> str:
    """Тот же запрос инструмента уже закончился неизвестным исходом: повтор не отправляется (К11 для инструментов,
    ADR-0111 п. 1) – модель получает отказ без сети, шаг записан как ошибка."""
    entry["status"] = "error"
    entry["error"] = "повтор запроса с неизвестным исходом не отправлен"
    return (f"сбой инструмента {name}: этот же запрос уже закончился неизвестным исходом – повтор не отправлен; "
            f"дайте ответ по собранному")


def _tool_request(client: Any, outcome: RowOutcome, purpose: str, call: Callable[[], Any], usage_key: str) -> Any:
    """Запрос инструмента: один повтор допустимых статусов; сбой после передачи байтов с неизвестным исходом –
    UnknownOutcome; признак отправки – у транспорта. Расход (usage_key) – по фактическим попыткам, не по вызовам."""
    attempts = 0
    while True:
        attempts += 1
        if outcome.deadline is not None and time.monotonic() >= outcome.deadline:
            raise LlmError("срок строки исчерпан: запрос инструмента не отправлен")
        outcome.usage[usage_key] += 1
        with model_traffic.context(purpose=purpose), track_sent() as tracker:
            try:
                return call()
            except LlmError as e:
                outcome.sent = outcome.sent or tracker.sent
                if _unknown(e):
                    raise UnknownOutcome(str(e), status=getattr(e, "status", None)) from e
                # ответ сервера получен (статус известен) – исход известен, один повтор допустим; неизвестный исход
                # отсеян выше
                if isinstance(e, ResolveError):
                    # имя сервера не разрешилось – запрос инструмента не ушёл (ADR-0113): попытка без отправки – не вызов
                    # инструмента при любом исходе (ревью круга 51, В1); один повтор после паузы, остановка во время
                    # паузы – ResearchStopped до нового запроса: строка в очередь, не «сохранена» (В3)
                    outcome.usage[usage_key] -= 1
                    if attempts == 1 and _pause(outcome.stop, RESOLVE_TOOL_WAIT_S, outcome.deadline):
                        if outcome.stop():
                            raise ResearchStopped() from None
                        continue
                    raise
                if attempts == 1 and getattr(e, "status", None) in TOOL_RETRY_STATUSES:
                    wait = min(float(getattr(e, "retry_after", 0) or 1.0), 5.0)
                    if outcome.deadline is not None and time.monotonic() + wait >= outcome.deadline:
                        raise  # ждать повтора некогда: срок строки
                    time.sleep(wait)
                    continue
                raise
            finally:
                outcome.sent = outcome.sent or tracker.sent


# ------------------------------------------------------------------ показ причин

# Причины строк и получения, ошибки шагов хода строки хранятся в базе прежним русским текстом: по нему классифицируют
# («Результат неизвестен» – app/run_errors.py) и его же видят прежние записи. Перевод – только при показе (ADR-0158):
# известные части текста заменяются переводом, данные (ответ провайдера, замечания проверки) остаются как есть.
_REASON_PARTS = sorted((
    DROP_STOPPED, TOOL_UNKNOWN_STOPPED, UNKNOWN_NOTE, TOOL_UNKNOWN_NOTE, RESOLVE_RETRY_NOTE,
    i18n.N_("Автоматический повтор после обрыва тоже остался без ответа."),
    i18n.N_("Автоматический повтор после обрыва не получил ответа модели."),
    i18n.N_("ответ модели оборван по длине (предел ответа профиля) – повтора нет"),
    i18n.N_("ответ оборван по длине и не прошёл проверку – повтора нет:"),
    i18n.N_("в вызове answer нет объекта row"), i18n.N_("в ответе нет объекта JSON строки"),
    i18n.N_("ответ без строки"),
    i18n.N_("Согласие на исследование отозвано: запрос не отправлен."),
    i18n.N_("Получение остановлено: запрос не отправлен."),
    i18n.N_("Профиль провайдера выключен: запрос не отправлен."),
    i18n.N_("Задание устарело: состав проекта изменился – запрос не отправлен."),
    i18n.N_("задание или согласие больше не действуют"), i18n.N_("строки нет в текущем задании"),
    i18n.N_("остановлено оператором"), i18n.N_("пополните баланс у провайдера: сервер ответил 402"),
    i18n.N_("задание устарело: состав проекта изменился"),
    i18n.N_("срок строки исчерпан: запрос инструмента не отправлен"), i18n.N_("срок строки исчерпан"),
    i18n.N_("получение остановлено во время паузы перед повтором"),
    i18n.N_("повтор запроса с неизвестным исходом не отправлен"),
), key=len, reverse=True)
_REASON_PATTERNS = (
    (re.compile(r"исчерпан бюджет отправок на строку \((\d+)\) – ответа нет"),
     lambda m: i18n._("исчерпан бюджет отправок на строку ({limit}) – ответа нет", limit=m.group(1))),
    (re.compile(r"исчерпан срок строки \((\d+) с\) – ответа нет"),
     lambda m: i18n._("исчерпан срок строки ({seconds} с) – ответа нет", seconds=m.group(1))),
    (re.compile(r"ответ не прошёл проверку после (\d+) повторов:"),
     lambda m: i18n._("ответ не прошёл проверку после {retries} повторов:", retries=m.group(1))),
    (re.compile(r"провайдер обрывает соединения без ответа: (\d+) строки подряд – получение остановлено, чтобы не "
                r"тратить запросы впустую; оставшиеся строки можно получить новым запуском"),
     lambda m: i18n._(RESEARCH_DROP_STOP, streak=m.group(1))),
    (re.compile(r"^не сохранено: "), lambda m: i18n._("не сохранено: ")),
    (re.compile(r"^сбой приложения: "), lambda m: i18n._("сбой приложения: ")),
)


def reason_text(text: Any) -> str:
    """Причина строки или получения на языке интерфейса для показа: при русском – как сохранена."""
    value = str(text or "")
    if not value or i18n.current() == "ru":
        return value
    for part in _REASON_PARTS:
        if part in value:
            value = value.replace(part, i18n._(part))
    for pattern, render in _REASON_PATTERNS:
        value = pattern.sub(render, value)
    return value


# ------------------------------------------------------------------ получение целиком

class ResearchRunner:
    """Исполнитель получения: берёт строки очереди атомарно, исследует по одной под правом на генерацию группы
    провайдера, сохраняет годные строки сразу (П20), фиксирует неизвестный результат (К11)."""

    def __init__(self, db: Any, make_client: Callable[[Mapping[str, Any]], Any]) -> None:
        self.db = db
        self.make_client = make_client
        self._stops: set[int] = set()
        self._lock = threading.Lock()
        self._threads: dict[int, threading.Thread] = {}
        self._live: dict[int, dict[str, Any]] = {}  # ход текущей строки получения: {input_ref, tools, sends, since}

    def live(self, run_id: int) -> dict[str, Any] | None:
        """Ход текущей строки идущего получения (для страницы хода): None – строка не обрабатывается."""
        with self._lock:
            state = self._live.get(int(run_id))
            return {**state, "tools": [dict(t) for t in state["tools"]]} if state else None

    def _set_live(self, run_id: int, state: dict[str, Any] | None) -> None:
        with self._lock:
            if state is None:
                self._live.pop(int(run_id), None)
            else:
                self._live[int(run_id)] = state

    def stop(self, run_id: int) -> None:
        """«Остановить»: под исключительной блокировкой согласия – начатая отправка дописывает байты, новые не идут."""
        run = self.db.research_run(run_id)
        with self._lock:
            self._stops.add(int(run_id))
        if run is not None:
            with consent_gate(run["consent_id"]).write():
                pass

    def _osv(self, run_id: int, project_id: int, input_ref: str, row: Mapping[str, Any], outcome: RowOutcome,
             osv_url: str, client: Any) -> dict[str, Any] | None:
        """Точный запрос OSV по строке до обращения к модели (ADR-0112): шаг 0 «osv» в ходе строки (только когда
        запрос делается; живое состояние видит шаг до ответа; при отказе допуска шаг убирается), расход osv_calls –
        по попытке передачи байтов (транспорт начал отправку), обмен – в журнале (purpose research:osv). Согласие без
        адреса OSV – None, в сообщении поля osv нет. Отказ допуска (SendNotAllowed) – наружу: получение
        останавливается, как при отказе перед обращением к модели."""
        if not osv_url or client is None:
            return None
        if osv.query_for(dict(row))[0] is None:
            return osv.lookup(osv_url, dict(row), client)  # без сети: unsupported с причиной, шага в ходе строки нет
        entry: dict[str, Any] = {"step": 0, "tool": "osv", "status": "", "results": 0, "seconds": 0.0}
        outcome.tools.append(entry)
        outcome.changed()
        try:
            with model_traffic.context(purpose="research:osv", run_id=run_id, hub_id=input_ref, project_id=project_id):
                answer = osv.lookup(osv_url, dict(row), client)
        except SendNotAllowed:
            outcome.tools.remove(entry)  # запроса не было – шага в ходе строки нет
            outcome.changed()
            raise
        if answer["sent"]:
            outcome.usage["osv_calls"] += 1
        # запрос OSV бесплатен и не считается отправкой провайдеру: outcome.sent не трогаем – строка, у которой был
        # только запрос OSV, при остановке или отказе допуска остаётся в очереди, а не «результат неизвестен»
        entry.update(status=answer["status"], results=len(answer["vulns"]), seconds=answer["seconds"])
        if answer["status"] in ("error", "unsupported"):
            entry["error"] = answer["note"][:300]
        outcome.changed()
        return {k: v for k, v in answer.items() if k != "sent"}

    def _stopped(self, run_id: int) -> bool:
        with self._lock:
            return int(run_id) in self._stops

    def running(self, run_id: int) -> bool:
        thread = self._threads.get(int(run_id))
        return bool(thread and thread.is_alive())

    def start(self, run_id: int) -> None:
        """Получение – в своём потоке; второй запуск того же получения не создаётся, стоп снимается только при
        действительном новом запуске."""
        with self._lock:
            thread = self._threads.get(int(run_id))
            if thread and thread.is_alive():
                return
            self._stops.discard(int(run_id))
            thread = threading.Thread(target=self.run, args=(int(run_id),), name=f"research-{run_id}", daemon=True)
            self._threads[int(run_id)] = thread
            thread.start()

    def run(self, run_id: int) -> None:
        current: dict[str, Any] = {"ref": None, "sent": False}
        try:
            self._run(run_id, current)
        except Exception as e:  # noqa: BLE001 – получение не роняет приложение; состояние строки – согласованно
            log.exception("исследование провайдером: получение %s прервано ошибкой", run_id)
            # аварийно закрывается только действительно незавершённая строка («отправлено»): уже сохранённая строка,
            # после которой упало взятие следующей, не переписывается (ревью B3 круг 2)
            open_ref = next((r["input_ref"] for r in self.db.research_run_rows(run_id) if r["state"] == "sending"), None)
            if open_ref:
                try:
                    sent = current["sent"] if open_ref == current["ref"] else True
                    self.db.finish_research_row(run_id, open_ref, "unknown" if sent else "failed",
                                                f"сбой приложения: {type(e).__name__}")
                except Exception:  # noqa: BLE001
                    log.exception("исследование провайдером: строка %s не закрыта", open_ref)
            self.db.finish_research_run(run_id, "interrupted", f"сбой приложения: {type(e).__name__}")
        finally:
            self._set_live(run_id, None)

    def _run(self, run_id: int, current: dict[str, Any]) -> None:
        run = self.db.research_run(run_id)
        if run is None or run["state"] != "running":
            return
        consent = self.db.research_consent(run["consent_id"])
        execution = self.db.get_execution(run["execution_id"])
        task = self.db.current_task(run["project_id"])
        if consent is None or execution is None or task is None or task["id"] != run["task_id"]:
            self.db.finish_research_run(run_id, "stopped", "задание или согласие больше не действуют")
            return
        rows_by_ref = {r["input_ref"]: r for r in self.db.task_rows(task["id"])}
        chat = dict(json.loads(execution.get("options_json") or "{}").get("chat") or {})
        search = chat.get("search") if consent["search_mode"] != "none" else None
        search = dict(search) if isinstance(search, dict) and search.get("search_path") else None
        tool_steps = int(consent.get("tool_steps") or chat.get("tool_steps") or 12)
        system, model = str(consent["instructions"]), str(consent["model"])
        gate = gate_for(execution)
        cgate = consent_gate(consent["id"])
        provider_id = execution.get("provider_id")

        def allowed() -> None:
            """Допуск непосредственно перед отправкой, под блокировками (К2): согласие действует, получение идёт и не
            останавливается, профиль включён, задание – то же и текущее."""
            now = self.db.research_consent(run["consent_id"])
            if now is None or now["state"] != "active":
                raise SendNotAllowed("Согласие на исследование отозвано: запрос не отправлен.")
            state = self.db.research_run(run_id)
            if state is None or state["state"] != "running" or self._stopped(run_id):
                raise SendNotAllowed("Получение остановлено: запрос не отправлен.")
            profile = self.db.get_provider(int(provider_id)) if provider_id is not None else None
            if profile is None or not profile.get("enabled"):
                raise SendNotAllowed("Профиль провайдера выключен: запрос не отправлен.")
            # состав проекта – по фактическому отпечатку (новая выгрузка и подтверждения имён задание не меняют,
            # ревью B3 круг 2, блокирующее 3), а не только по номеру задания
            if not self.db.task_composition_current(run["project_id"], run["task_id"]):
                raise SendNotAllowed("Задание устарело: состав проекта изменился – запрос не отправлен.")

        client = self.make_client(execution)
        profile_read = client.gate  # блокировка профиля из client_for

        @contextmanager
        def both() -> Iterator[None]:
            # общие блокировки состава проекта, профиля и согласия – до передачи байтов: изменение состава, правка
            # профиля и отзыв согласия ждут начатую отправку, а следующая видит их целиком. Порядок – как у записи
            # настроек (состав, затем профиль 1): встречного захвата нет
            with ExitStack() as stack:
                stack.enter_context(composition_gate.read())
                if profile_read is not None:
                    stack.enter_context(profile_read())
                stack.enter_context(cgate.read())
                yield

        client.gate = both
        client.admission = allowed
        client.before_send = allowed
        # точный запрос OSV (ADR-0112) – только по согласию, которое его называет (адрес в тексте инструкций), под теми
        # же допуском и блокировками, что и обращение к модели
        osv_url = osv_url_from(system)
        osv_client = osv.make_client(osv_url) if osv_url else None
        if osv_client is not None:
            osv_client.gate = both
            osv_client.admission = allowed
            osv_client.before_send = allowed
        stop_reason = ""
        retry_on_drop = drop_retry_allowed(execution)
        drop_streak = 0  # строк подряд с обрывом без ответа: DROP_STREAK_PAUSE – остановка получения с причиной
        while True:
            if stop_reason:  # серия обрывов у провайдера: строка записана, следующие не отправляются
                break
            if self._stopped(run_id):
                stop_reason = "остановлено оператором"
                break
            item = self.db.take_research_row(run_id)
            if item is None:
                break
            current["ref"], current["sent"] = item["input_ref"], False
            row = rows_by_ref.get(item["input_ref"])
            live_state: dict[str, Any] = {"input_ref": item["input_ref"], "tools": [], "sends": 0,
                                          "since": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
            outcome = RowOutcome()
            outcome.retry_on_drop = retry_on_drop
            self._set_live(run_id, live_state)

            def changed(o: RowOutcome = outcome, s: dict[str, Any] = live_state) -> None:
                with self._lock:
                    s["tools"], s["sends"] = [dict(t) for t in o.tools], int(o.usage["sends"])
            outcome.on_change = changed
            if row is None:
                self.db.finish_research_row(run_id, item["input_ref"], "failed", "строки нет в текущем задании")
                continue
            if not gate.acquire("research", lambda: self._stopped(run_id)):
                self.db.finish_research_row(run_id, item["input_ref"], "queued")
                stop_reason = "остановлено оператором"
                break
            answer_row, why = None, ""
            try:
                osv_answer = self._osv(run_id, run["project_id"], item["input_ref"], row, outcome, osv_url, osv_client)
                with model_traffic.context(purpose="research", run_id=run_id, hub_id=item["input_ref"],
                                           project_id=run["project_id"]):
                    answer_row, why = research_component(client, model, task, row, system, consent["cutoff_date"],
                                                         search, tool_steps, lambda: self._stopped(run_id), outcome,
                                                         osv_answer=osv_answer)
            except ResearchStopped:
                # ход оборвался без ответа, а повтор уже не отправлен – строка «результат неизвестен», а не очередь:
                # иначе продолжение отправило бы её снова (ревью Codex, круг 18)
                if outcome.pending_unknown:
                    self.db.finish_research_row(run_id, item["input_ref"], "unknown", DROP_THEN_STOPPED, outcome.tools,
                                                outcome.usage)
                elif outcome.tool_unknown:
                    # запрос инструмента мог быть оплачен, а «Продолжить» начало бы строку заново с первого сообщения –
                    # строка не в очередь, а «результат неизвестен»: новый запуск только по отметке (ревью Codex, круг 29)
                    self.db.finish_research_row(run_id, item["input_ref"], "unknown", TOOL_UNKNOWN_THEN_STOPPED,
                                                outcome.tools, outcome.usage)
                else:
                    self.db.finish_research_row(run_id, item["input_ref"], "queued", "", outcome.tools, outcome.usage)
                stop_reason = "остановлено оператором"
                break
            except SendNotAllowed as e:
                state = "unknown" if outcome.sent else "queued"
                self.db.finish_research_row(run_id, item["input_ref"], state, str(e) if state == "unknown" else "",
                                            outcome.tools, outcome.usage)
                stop_reason = str(e)
                break
            except PromptOverflowError as e:
                state = "unknown" if outcome.pending_unknown else "failed"
                reason = f"{e} {UNKNOWN_NOTE}" if state == "unknown" else str(e)
                if state == "failed" and outcome.tool_unknown:
                    reason += f" {TOOL_UNKNOWN_NOTE}"
                self.db.finish_research_row(run_id, item["input_ref"], state, reason, outcome.tools, outcome.usage)
                # серия обрывов (ADR-0107) считается и здесь: строка без обрыва хода модели её сбрасывает (круг 30)
                drop_streak = drop_streak + 1 if state == "unknown" or outcome.drop_retries else 0
                if drop_streak >= DROP_STREAK_PAUSE:
                    stop_reason = RESEARCH_DROP_STOP.format(streak=drop_streak)
                    break
                continue
            except LlmError as e:
                unknown = isinstance(e, UnknownOutcome) or _unknown(e) or outcome.pending_unknown
                reason = f"{e} {UNKNOWN_NOTE}" if unknown else str(e)
                if not unknown and outcome.tool_unknown:
                    reason += f" {TOOL_UNKNOWN_NOTE}"
                if isinstance(e, ResolveError) and outcome.resolve_retries:
                    reason += f" {RESOLVE_RETRY_NOTE}"
                if unknown and outcome.drop_retries:
                    reason += (" Автоматический повтор после обрыва тоже остался без ответа."
                               if isinstance(e, UnknownOutcome) or _unknown(e) else
                               " Автоматический повтор после обрыва не получил ответа модели.")
                self.db.finish_research_row(run_id, item["input_ref"], "unknown" if unknown else "failed", reason,
                                            outcome.tools, outcome.usage)
                if getattr(e, "status", None) == 402:
                    stop_reason = "пополните баланс у провайдера: сервер ответил 402"
                    break
                drop_streak = drop_streak + 1 if unknown or outcome.drop_retries else 0
                if drop_streak >= DROP_STREAK_PAUSE:
                    stop_reason = RESEARCH_DROP_STOP.format(streak=drop_streak)
                    break
                continue
            finally:
                current["sent"] = outcome.sent
                gate.release()
                self._set_live(run_id, None)
            # обрыв, после которого повтор ответил, – тоже признак сбоев у провайдера: серия не прерывается
            drop_streak = drop_streak + 1 if outcome.drop_retries else 0
            if drop_streak >= DROP_STREAK_PAUSE:
                stop_reason = RESEARCH_DROP_STOP.format(streak=drop_streak)
            if answer_row is None:
                # срок или бюджет строки кончились после обрыва, на который повтор ответа не получил, – исход
                # оборванного запроса неизвестен (ревью Codex, круг 18)
                state = "unknown" if outcome.pending_unknown else "failed"
                if state == "failed" and outcome.tool_unknown:
                    why = f"{why} {TOOL_UNKNOWN_NOTE}"
                self.db.finish_research_row(run_id, item["input_ref"], state,
                                            f"{why} {UNKNOWN_NOTE}" if state == "unknown" else why, outcome.tools,
                                            outcome.usage)
                current["ref"] = None
                continue
            result = research.research_results({"rows": [answer_row], "validator_version": VALIDATOR_VERSION},
                                               [row])[0]
            try:
                self.db.finish_research_row(run_id, item["input_ref"], "saved", "", outcome.tools, outcome.usage,
                                            result=result)
            except Exception as e:  # TaskSuperseded и прочее: строка не сохранена, причина – в записи
                note = f" {TOOL_UNKNOWN_NOTE}" if outcome.tool_unknown else ""
                self.db.finish_research_row(run_id, item["input_ref"], "failed", f"не сохранено: {e}{note}",
                                            outcome.tools, outcome.usage)
                stop_reason = "задание устарело: состав проекта изменился"
                break
            current["ref"] = None
        current["ref"] = None
        self.db.finish_research_run(run_id, "stopped" if stop_reason else "done", stop_reason)

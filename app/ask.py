"""«Спросить модель»: вопрос специалиста по находке и ответ локальной модели.

Модель получает то же, что при разборе: сведения о находке и срез кода, который она видела (cases.context_json),
свой прежний разбор (вердикт, привязанный к находке) и прежние вопросы с ответами по этой находке. Вопрос
специалиста идёт вне блока данных (prompts.build_ask_messages). Перед отправкой текст сообщения с данными
маскируется ещё раз, как в прогоне. Модель – только локальная: клиент Ollama проверяет адрес (разрешённые хосты)
и саму модель (облачные отклоняются) перед каждой отправкой.

Вопрос и ответ сохраняются (таблица questions): сначала вопрос без ответа, затем ответ с замерами скорости или
ошибка. Если приложение перезапустится, пока модель отвечает, вопрос без ответа закроется с пояснением
(Database.recover_interrupted). Одновременно модель отвечает только на один вопрос: видеокарта одна, а прогон
триажа может идти параллельно. Текст вопроса и ответа в журнал не пишется.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import Any

from app import model_traffic
from app.config import Settings
from app.db import QUESTION_UNKNOWN, Database
from app.executors import (REMOTE_KINDS, ProfileError, applied_think, choose_profile, client_for, execution_values,
                           fit_options, fit_thinking, json_overhead, planned_think, prompt_size, send_guard,
                           snapshot_options, thinking_limit)
from app.llm import (GENERATION, LlmError, PromptOverflowError, gate_for, outcome_unknown, prompt_budget,
                     prompt_fits, prompt_tokens)
from app.llm_ollama import OllamaClient
from app.logsafe import failure_text, log_failure
from app.masking import mask_text
from app.models import CodeContext, Finding, Verdict
from app.prompts import (ASK_ENUMS, ASK_FIELDS, ASK_HISTORY_MAX, ASK_REQUIRED, ASK_TYPES, build_ask_messages,
                         parse_ask)

log = logging.getLogger("local_triage.ask")

MAX_QUESTION = 2000  # знаков в вопросе
ASK_NUM_PREDICT = 1536  # предел длины ответа, токенов: ответ на вопрос короче разбора
MIN_CODE_LINES = 9  # меньше строк вокруг строки срабатывания срез для вопроса не сокращается
PROMPT_DOUBT = ("Вопрос с кодом, по счёту модели, не поместился в окно контекста вместе с ответом: начало могло быть "
                "обрезано, ответ не принят. Сократите вопрос или увеличьте окно контекста в настройках.")

# К модели – по одному обращению на процесс (ADR-0099): вопрос, пока модель отвечает на другой вопрос или разбирает
# находку в прогоне, получает понятный отказ; текст вопроса остаётся в форме
ASK_BUSY = "Модель ещё отвечает на предыдущий вопрос – дождитесь ответа и спросите снова."
RUN_BUSY = ("Модель сейчас разбирает находки в прогоне – спросите, когда прогон закончится или встанет на паузу. "
            "Текст вопроса сохранён в форме.")
REANALYZED = ("Пока вопрос ждал модель, разбор находки обновился: проверьте вопрос по новому разбору и спросите "
              "снова.")


class AskError(Exception):
    """Вопрос не задан. Текст – по-русски, для показа в интерфейсе; status – код ответа HTTP."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def clean_question(text: Any) -> str:
    """Вопрос из формы: переводы строк – «\\n», без пробелов по краям и лишних пустых строк."""
    lines = [line.rstrip() for line in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    out: list[str] = []
    for line in lines:
        if not line.strip() and out and not out[-1].strip():
            continue
        out.append(line)
    return "\n".join(out).strip()


def ask_options(settings: Settings) -> dict[str, int]:
    """Параметры генерации ответа на вопрос: окно контекста из настроек, предел ответа – не больше четверти окна."""
    num_ctx = int(settings.num_ctx)
    return {"num_ctx": num_ctx, "num_predict": min(ASK_NUM_PREDICT, num_ctx // 4)}


def _around_target(ctx: CodeContext, keep: int) -> CodeContext:
    """Срез, сокращённый до keep строк вокруг строки срабатывания (номера строк сохраняются)."""
    if len(ctx.lines) <= keep:
        return ctx
    if ctx.start_line >= 1 and ctx.target_line:
        center = ctx.target_line - ctx.start_line
    else:
        center = len(ctx.lines) // 2
    first = max(0, min(center - keep // 2, len(ctx.lines) - keep))
    start = ctx.start_line + first if ctx.start_line >= 1 else ctx.start_line
    end = start + keep - 1 if ctx.start_line >= 1 else ctx.end_line
    return CodeContext(**{**ctx.to_dict(), "lines": ctx.lines[first:first + keep], "start_line": start,
                          "end_line": end})


def fit_messages(f: Finding, ctx: CodeContext, verdict: Verdict, question: str,
                 history: list[tuple[str, str]], mask_key: bytes | None,
                 options: dict[str, int], size: Any = None) -> list[dict[str, str]]:
    """Сообщения, которые помещаются в окно контекста вместе с ответом. Что сокращается по очереди: прежние
    вопросы и ответы (от ранних), подробности прежнего разбора, затем срез кода вокруг строки срабатывания.
    Не помещается и так – AskError."""
    def build(code: CodeContext, past: list[tuple[str, str]], brief: bool) -> list[dict[str, str]]:
        messages = build_ask_messages(f, code, verdict, question, past, mask_key=mask_key, brief=brief)
        # последняя сетка перед отправкой – как в прогоне: маскирование всего текста с данными находки
        return [{**m, "content": mask_text(m["content"], mask_key, env_style=False)[0]}
                if mask_key and m["role"] == "user" else m for m in messages]

    past = list(history)
    while True:
        messages = build(ctx, past, False)
        if prompt_fits(messages, options, size):
            return messages
        if not past:
            break
        past = past[1:]
    messages = build(ctx, [], True)
    if prompt_fits(messages, options, size):
        return messages
    keep = len(ctx.lines)
    while keep > MIN_CODE_LINES:
        keep = max(MIN_CODE_LINES, keep * 2 // 3)
        messages = build(_around_target(ctx, keep), [], True)
        if prompt_fits(messages, options, size):
            return messages
    # Наименьший срез не уложился в запас на ошибку оценки (llm.PROMPT_SAFETY_SHARE), но всё окно ещё не занимает:
    # он и уходит модели – меньше уже некуда; что промпт действительно поместился, сверяет счёт самой модели
    full = prompt_budget(options, safety=False)
    if full is None or (size or prompt_tokens)(messages) <= full:
        return messages
    # size задан только у удалённого API (executors.prompt_size): окно и предел ответа – из профиля провайдера, а не
    # из настроек Ollama (ревью Codex, круг 19)
    where = ("увеличьте «Окно контекста модели» или уменьшите «Предел ответа» в профиле провайдера" if size is not None
             else "увеличьте окно контекста в настройках")
    raise AskError(f"Вопрос вместе с кодом находки не помещается в окно контекста модели: сократите вопрос или {where}.")


def history_for(questions: Iterable[dict], verdict_id: Any) -> list[tuple[str, str]]:
    """Прежние вопросы с ответами к этому же ответу модели (verdict_id) – последние ASK_HISTORY_MAX: вопросы
    к прежнему вердикту относятся к другому разбору."""
    done = [(q["question"], q["answer"]) for q in questions
            if q.get("state") == "done" and q.get("answer") and q.get("verdict_id") == verdict_id]
    return done[-ASK_HISTORY_MAX:]


def ask_question(db: Database, settings: Settings, client: OllamaClient | Callable[[str], OllamaClient],
                 mask_key: bytes | None, project_id: int, hub_id: str, question: str, model: str) -> dict:
    """Задать модели вопрос по находке и дождаться ответа. Возвращает сохранённый вопрос (Database.get_question):
    state = done и answer, или state = error и текст ошибки (модель не ответила, ответ не по формату). Вопрос
    не задан (пустой, длинный, нет разбора модели, модель уже отвечает на другой вопрос, промпт не помещается
    в окно, профиль модели выключен) – AskError, и ничего не сохраняется.

    Профиль (ADR-0102 п. 4): у ответа модели есть снимок исполнителя – тем же профилем, если он включён, выключен –
    отказ; ответ до 0.9.12 (снимка нет) – профиль проекта. Снимок вопроса пишется вместе с вопросом. client – фабрика
    клиента по адресу (как у прогона) или готовый клиент (тесты)."""
    text = clean_question(question)
    if not text:
        raise AskError("Напишите вопрос.")
    if len(text) > MAX_QUESTION:
        raise AskError(f"Вопрос слишком длинный: не больше {MAX_QUESTION} знаков.")
    name = str(model or "").strip()
    if not name or any(ord(ch) < 32 for ch in name):
        raise AskError("Не выбрана модель.")
    case = db.get_case(project_id, hub_id)
    source = db.case_input(project_id, hub_id)
    if source is None:
        raise AskError("Находка не найдена.", 404)
    if case is None or not case.get("verdict"):
        raise AskError("Модель эту находку ещё не разбирала: сначала запустите разбор, потом задавайте вопросы.",
                       409)
    f = Finding.from_dict(source["data"])
    ctx = CodeContext.from_dict(case["context"])  # ровно тот срез, который видела модель
    verdict = Verdict.from_dict(case["verdict"]["data"])
    history = history_for(db.list_questions(project_id, hub_id), case["verdict_id"])
    profile = question_profile(db, settings, project_id, case["verdict_id"])
    execution = execution_values(profile, name, "ask", settings.num_ctx, settings.model_json_schema)
    options, _, rule = snapshot_options(execution)
    # фабрика (класс клиента или функция от адреса) или готовый клиент (тесты): у класса тоже есть chat_json
    ready = hasattr(client, "chat_json") and not isinstance(client, type)
    factory = (lambda url, given=client: given) if ready else client
    # рассуждает ли модель – до сборки промпта: у рассуждающего вопроса свой предел ответа, а с ним и место под срез
    # удалённый API сведений о рассуждении не отдаёт – запись модели у него не запрашивается (лишний GET /models)
    remote = str(execution.get("kind") or "ollama") in REMOTE_KINDS
    planned = client_for(factory, execution, send_guard(db, execution, project_id=project_id), db=db,
                         project_id=project_id)
    try:
        info = {} if remote else dict(planned.model_info(name))
    except (LlmError, AttributeError):
        info = {}
    think = applied_think(rule, name, info or None)
    think_limit, call_timeout = thinking_limit(execution, think)
    # окно и предел ответа – того сервера, куда уйдёт вопрос (у удалённого API – из профиля за вычетом схемы ответа,
    # которую клиент добавит к сообщениям; KIMI-01)
    messages = fit_messages(f, ctx, verdict, text, history, mask_key,
                            fit_options(execution, options,
                                        json_overhead(planned, ASK_FIELDS, ASK_REQUIRED, ASK_ENUMS, ASK_TYPES)),
                            prompt_size(execution))
    if think_limit:  # рассуждающий вопрос: остаток окна после промпта, не больше предела рассуждения
        options = fit_thinking(options, think_limit, messages)
    gate = gate_for(execution)  # группа права – из снимка вопроса (ADR-0104 п. 6), не пересчитывается
    if not gate.try_acquire("ask"):
        raise AskError(busy_text(gate), 409)
    try:
        # срез и разбор для вопроса собраны до права на генерацию: если разбор находки за это время сменился,
        # вопрос к прежнему разбору не задаётся
        now = db.get_case(project_id, hub_id) or {}
        if now.get("verdict_id") != case["verdict_id"] or now.get("case_hash") != case["case_hash"]:
            raise AskError(REANALYZED, 409)
        question_id = db.add_question(project_id, hub_id, text, name, case_hash=case["case_hash"],
                                      verdict_id=case["verdict_id"], execution=execution)
        saved = db.get_question(question_id) or {}
        snapshot = db.get_execution(saved.get("execution_id")) or execution
        asking = client_for(factory, snapshot, send_guard(db, snapshot, project_id=project_id), db=db,
                            project_id=project_id)
        asking.timeout = call_timeout
        try:
            # Контекст журнала обмена с моделью: обращения вопроса помечаются назначением ask и находкой.
            with model_traffic.context(purpose="ask", project_id=project_id, hub_id=hub_id):
                # уровень рассуждения – на каждую отправку, по модели, которая в этот момент лежит на сервере
                obj, stats = asking.chat_json(name, messages, ASK_FIELDS, ASK_REQUIRED, ASK_ENUMS, options=options,
                                              think=planned_think(rule, name, think), types=ASK_TYPES,
                                              json_schema=str(snapshot.get("schema_mode") or
                                                              settings.model_json_schema))
            answer = parse_ask(obj)
            # последняя проверка перед сохранением – после всей нормализации ответа (сервер с ключом мог вернуть его)
            if model_traffic.shows_secret([answer, stats.to_dict()], getattr(asking, "secrets", ())):
                raise LlmError(model_traffic.KEY_IN_ANSWER)
        except PromptOverflowError as e:
            # по счёту модели промпт одной из попыток длиннее окна: начало могло быть обрезано – ответу не доверяем;
            # у удалённого API это отказ его клиента до отправки по окну профиля – совет про профиль (ревью круг 18)
            text = (f"{e} Увеличьте «Окно контекста модели» или уменьшите «Предел ответа» в профиле провайдера."
                    if remote and not getattr(e, "sent", False) else PROMPT_DOUBT)
            db.finish_question(question_id, error=text, stats=e.stats.to_dict() if e.stats else None)
        except LlmError as e:
            # К11: вопрос ушёл внешнему провайдеру без ответа – «результат неизвестен», повторно не отправляется
            unknown = str(snapshot.get("trust") or "") == "external" and outcome_unknown(e)
            db.finish_question(question_id, error=f"{QUESTION_UNKNOWN} {e}" if unknown else str(e),
                               stats=e.stats.to_dict() if e.stats else None)
        except Exception as e:  # сбой разбора или записи – ошибка этого вопроса, без текста вопроса в журнале
            eid = log_failure(log, "вопрос к модели не обработан", e)
            db.finish_question(question_id, error=failure_text("Не удалось получить ответ модели", e, eid))
        else:
            db.finish_question(question_id, answer=answer["answer"], answer_data=answer, stats=stats.to_dict())
        return db.get_question(question_id) or {}
    finally:
        gate.release()


def answer_execution(db: Database, verdict_id: int | None) -> dict | None:
    """Снимок исполнителя ответа, профилем которого задаётся вопрос по нему (ADR-0102 п. 4): с профилем и адресом.
    Ответ до 0.9.12 и ответ, полученный при сборке образа (адрес исполнителя не сохраняется), – None: вопрос идёт
    профилем проекта. Одно правило для формы вопроса в карточке и для его обработки."""
    execution = db.verdict_execution(verdict_id)
    if execution is not None and execution.get("provider_id") and str(execution.get("base_url") or ""):
        return execution
    return None


def question_profile(db: Database, settings: Settings, project_id: int, verdict_id: int | None) -> dict:
    """Профиль вопроса (ADR-0102 п. 4): ответ модели получен известным исполнителем – его профиль (выключен – отказ);
    ответ до 0.9.12 и ответ сборки образа – профиль проекта (выключен – отказ)."""
    execution = answer_execution(db, verdict_id)
    try:
        if execution is not None:
            profile = db.get_provider(int(execution["provider_id"]))
            if profile is None or not profile.get("enabled"):
                name = (profile or {}).get("name") or execution.get("base_url")
                raise AskError(f"Разбор получен моделью профиля «{name}», а он выключен: включите профиль на странице "
                               "«Настройки» или пересмотрите находку на действующем профиле. Текст вопроса сохранён "
                               "в форме.", 409)
            return choose_profile(db, settings, db.get_project(project_id), int(profile["id"]))
        return choose_profile(db, settings, db.get_project(project_id))
    except ProfileError as e:
        raise AskError(f"{e} Текст вопроса сохранён в форме.", 409) from None


def busy_text(gate: Any) -> str:
    """Почему вопрос не задан: кто держит право на генерацию группы (ADR-0104 п. 6) – словами."""
    holder = gate.busy()
    if holder == "triage":
        return RUN_BUSY
    if holder == "ask":
        return ASK_BUSY
    return (f"Модель ({gate.label}) сейчас занята проверкой или прогревом – спросите через минуту. Текст вопроса "
            "сохранён в форме.")


def card_executor(db: Database, settings: Settings, project_id: int, verdict_id: int | None) -> Any:
    """Исполнитель, которым пойдёт вопрос по этому разбору (question_profile), – для подсказок занятости в карточке;
    профиль недоступен – None (свой контур)."""
    try:
        return question_profile(db, settings, project_id, verdict_id)
    except AskError:
        return None


def busy(executor: Any = None) -> bool:
    """Модель группы этого исполнителя (по умолчанию – свой контур) сейчас отвечает на вопрос."""
    return (gate_for(executor) if executor is not None else GENERATION).busy() == "ask"


def run_busy(executor: Any = None) -> bool:
    """Модель группы этого исполнителя сейчас разбирает находку в прогоне: вопрос получит отказ."""
    return (gate_for(executor) if executor is not None else GENERATION).busy() == "triage"

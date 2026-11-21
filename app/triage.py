"""Очередь триажа SAST: фоновый поток разбирает находки по одной.

Для каждой находки: кодовая база → папка с клоном, срез кода (build_context, секреты и ПДн маскируются),
отпечаток случая (case_hash), готовый вердикт из кэша или вызов модели, сохранение. Между находками поток
выполняет принятые команды «пауза» и «стоп». Прогоны выполняются по одному: видеокарта одна.

Порядок разбора задаётся при загрузке выгрузки (order_findings): срочные, затем по критичности, дубли (один ключ
группы) рядом – дубль с тем же отпечатком берёт уже готовый вердикт.

Команды и переходы состояний идущего прогона выполняются под общей блокировкой, поэтому принятая команда
не теряется: стоп важнее паузы, а после стопа прогон не уходит на паузу даже при сбое Ollama. Принятая команда
хранится и в базе (runs.control): «Стоп», принятый перед перезапуском приложения, при запуске останавливает прогон.

Настройки работы (адрес Ollama) берутся из базы поверх переменных окружения в начале каждого прогона
(current_settings): их меняют на странице «Настройки».
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import statistics
import threading
import time
from collections.abc import Callable, Iterable, Mapping
import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app import model_traffic
from app.config import Settings
from app.context import build_context, clone_revision, export_fragment_view, file_presence, norm_path, resolve_repo
from app.db import (ACTIVE_RUN_STATES, FINAL_RUN_STATES, UNKNOWN_RESULT_NOTE, Database, DatabaseBusy,
                    EmptyQueue, ProfileChanged)
from app.hub_import import group_key, group_key2, is_urgent, near_columns2
from app.executors import (DROP_PAUSE_NOTE, DROP_SHARE_PAUSE, DROP_STREAK_PAUSE, REMOTE_KINDS, ProfileError,
                           SendNotAllowed, applied_think, choose_profile, client_for, drop_retry_allowed,
                           execution_values, fit_options, fit_thinking, host_metrics_of, json_overhead, planned_think,
                           prompt_size, provider_key, same_model, send_guard, snapshot_mismatch, snapshot_options, thinking_limit,
                           unload_allowed_of)
from app.llm import (DEFAULT_OPTIONS, LlmError, PromptOverflowError, estimate_tokens, gate_for,
                     model_answered, norm_model_name, outcome_unknown, prompt_budget, prompt_fits, prompt_tokens)
from app.llm_ollama import OllamaClient
from app.lockfile import LockUnsure
from app.storage import CommitUnknown
from app.logsafe import failure_text, log_failure
from app.masking import mask_text
from app.models import CodeContext, Finding, LlmStats
from app.prompts import (PROMPT_VERSION, VERDICT_ENUMS, VERDICT_FIELDS, VERDICT_REQUIRED, VERDICT_TYPES,
                         build_sast_messages, check_verdict_answer, parse_verdict, request_key, steering_fields,
                         steering_lines)

log = logging.getLogger("local_triage.triage")

SCOPES = ("live", "all", "urgent", "selected")  # live – по умолчанию (бэклог 104)
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
KIND_RANK = {"SAST": 0, "SCA": 1, "SCA-license": 2, "DAST": 3}
FEED_SIZE = 12  # сколько последних находок показывать в ленте прогона
WORKER_POLL_S = 1.0  # как часто поток проверяет очередь, если его не разбудили
CONTEXT_CHARS = 14000  # срез кода для модели, знаков; не помещается в окно контекста – сокращается
MIN_CONTEXT_CHARS = 1000  # …но не меньше: дальше промпт отклоняется с понятной ошибкой
CLONE_GONE_NOTE = ("Код находки в клоне сейчас не прочитать: файл пропал во время разбора или не найден однозначно. "
                   "Сохранённый срез не изменён. Проверьте клон или удалите его – тогда модель получит срез из базы.")
FIT_ATTEMPTS = 3  # сколько раз сокращать срез
CHANGED_NOTE = ("Находка или папка с клоном изменились, пока шёл разбор (новая выгрузка или другое соответствие "
                "папок): результат не привязан, запустите прогон для неё заново.")
CODE_CHANGED_NOTE = ("Код в клоне изменился, пока отвечала модель: ответ относится к прежнему коду и к находке "
                     "не привязан. Запустите разбор этой находки заново.")
PARTIAL_NOTE = " Замеры скорости по этой находке неполные: ответа модели целиком нет."
# Занятая база или нечитаемый замок папки данных при записи результата находки (Э2): это не ошибка находки –
# запись повторяется, затем прогон встаёт на паузу, а находка остаётся в очереди
# Неизвестный исход COMMIT в прогоне – как занятая база: повтор и пауза, находка не считается ошибкой. Все записи под retry_busy
# безопасно повторить: вердикт с заранее полученным номером, срез, завершение находки только из pending, состояние прогона
# (ADR-0128, п. 6.4). Прямые записи без повтора при таком исходе дают паузу; «Продолжить» берёт следующую незавершённую находку.
BUSY_ERRORS = (DatabaseBusy, LockUnsure, CommitUnknown)
DB_UNKNOWN_PAUSE = ("Связь с базой оборвалась во время подтверждения записи, записалась ли она, неизвестно. Прогон на паузе. "
                    "Нажмите «Продолжить», когда база снова доступна: завершённые находки повторно не разбираются, а незавершённая "
                    "может быть разобрана заново.")
DB_RUN_PAUSE = ("База данных занята или недоступна либо не читается файл замка папки данных, и состояние прогона записать не "
                "удалось. Прогон на паузе, разобранные находки сохранены. Нажмите «Продолжить», когда это пройдёт.")
DB_WRITE_RETRIES = 3
DB_RETRY_WAIT_S = 2.0
DB_BUSY_PAUSE = ("База данных занята (её держит другой запрос) или файл замка папки данных не прочитался: результат "
                 "находки не записан. Прогон на паузе, находка осталась в очереди. Нажмите «Продолжить», когда база "
                 "освободится: модель может разобрать эту находку заново.")
# Прогон без снимка исполнителя (начат до 0.9.12) и прогон с выключенным профилем (ADR-0102): исполнителя не
# подменяем – «Продолжить» создаёт новый прогон на действующем профиле проекта (TriageRunner.continue_as_new)
LEGACY_RUN_NOTE = ("Прогон начат до 0.9.12: сервер модели, на котором он шёл, не записан. Нажмите «Продолжить» – "
                   "неразобранные находки пойдут новым прогоном на профиле модели проекта.")
DISABLED_PROFILE_NOTE = ("Прогон на паузе. Включите профиль на странице «Настройки» или нажмите «Продолжить» – "
                         "неразобранные находки пойдут новым прогоном на действующем профиле проекта.")
PAUSE_OLLAMA_NOTE = "Прогон на паузе: проверьте Ollama и нажмите «Продолжить»."
PAUSE_PROVIDER_NOTE = "Прогон на паузе: устраните причину у провайдера и нажмите «Продолжить»."
PAYMENT_NOTE = "Провайдер ответил 402: нужна оплата (пополните баланс в личном кабинете провайдера)."


def pause_note(execution: Mapping[str, Any] | None) -> str:
    """Подсказка паузы по классу исполнителя: Ollama своего контура или внешний провайдер."""
    return PAUSE_PROVIDER_NOTE if str((execution or {}).get("trust") or "") == "external" else PAUSE_OLLAMA_NOTE


def pause_text(error: Exception) -> str:
    """Текст паузы прогона при отказе перед отправкой: причина и что делать (SendNotAllowed.note; по умолчанию – о
    выключенном профиле)."""
    return f"{error} {getattr(error, 'note', '') or DISABLED_PROFILE_NOTE}"


def retry_busy(write: Callable[[], Any]) -> Any:
    """Запись при занятой базе: несколько попыток с паузой; не вышло – исключение BUSY_ERRORS дальше."""
    unknown = None
    for attempt in range(DB_WRITE_RETRIES):
        try:
            return write()
        except BUSY_ERRORS as e:
            if isinstance(e, CommitUnknown):
                unknown = e  # следующая ошибка не снимает неопределённость: запись могла подтвердиться
            if attempt + 1 == DB_WRITE_RETRIES:
                if unknown is not None and unknown is not e:
                    raise unknown from e
                raise
            time.sleep(DB_RETRY_WAIT_S)
        except Exception as e:  # другая ошибка повтора тоже не значит, что прежняя запись не подтвердилась
            if unknown is not None:
                log_failure(log, "повтор записи после неизвестного исхода COMMIT не прошёл", e)  # журнал покажет место этой ошибки
                raise unknown from e
            raise
    return None
PROMPT_DOUBT_NOTE = ("Промпт, по счёту модели, не поместился в окно контекста вместе с ответом: начало могло быть "
                     "обрезано, ответ не принят. Увеличьте окно контекста (MODEL_NUM_CTX) и разберите находку ещё раз.")
# удалённый API: запрос не поместился в окно профиля даже с наименьшим срезом – совет про профиль, не про Ollama
REMOTE_WINDOW_NOTE = ("Увеличьте «Окно контекста модели» или уменьшите «Предел ответа» в профиле провайдера и "
                      "разберите находку ещё раз.")

# Медленный режим модели. Причина такого режима не доказана: у процесса модели часть памяти может оказаться
# в общей памяти Windows, и генерация идёт в несколько раз медленнее. Приложение только замечает замедление
# и перезагружает модель между находками; причину в интерфейсе не утверждает.
SLOW_TPS_SHARE = 0.35  # медленно – ниже этой доли обычной скорости (медианы последних ответов)
SLOW_TPS_ABSOLUTE = 30.0  # без ориентира: абсолютный порог ток/с для первых двух ответов подряд
SLOW_TPS_KNOWN_FAST = 80.0  # быстрая модель: раньше давала больше этого, иначе абсолютный порог не применяется
SLOW_STREAK = 2  # сколько медленных ответов подряд нужно, чтобы считать режим медленным
SLOW_MAX_RELOADS = 2  # не больше двух попыток перезагрузки за прогон, включая неудачные
SLOW_BASELINE_MIN = 3  # ориентир – медиана, для неё нужно не меньше трёх успешных ответов
SLOW_BASELINE_WINDOW = 20  # сколько последних ответов прогона берётся для ориентира
SLOW_HISTORY_WINDOW = 200  # сколько ответов прошлых прогонов той же модели смотреть
SLOW_RELOAD_WAIT_S = 15.0  # сколько ждать, пока /api/ps покажет модель выгруженной
SLOW_RELOAD_POLL_S = 0.2  # как часто спрашивать /api/ps во время ожидания


def slow_model_status_text(tps: float, baseline: float, reloaded: bool) -> str:
    """Строка оператору о медленном режиме. Причина не называется: она не доказана."""
    measured = f"{_tps_number(tps)} ток/с при обычных {_tps_number(baseline)}"
    if reloaded:
        return f"Модель работала медленно ({measured}) – перезагружена"
    return (f"Модель работала медленно ({measured}) – перезагрузка не помогла: закройте программы, "
            "использующие видеокарту, и нажмите «Пауза» → «Продолжить»")


def _tps_number(value: float) -> str:
    """Ток/с в строке оператору: целое, если оно не меньше 10, иначе один знак после запятой."""
    return f"{value:.0f}" if abs(value) >= 10 else f"{value:.1f}"


def _median(values: Iterable[float]) -> float | None:
    items = list(values)
    return float(statistics.median(items)) if items else None


@dataclass
class _SlowState:
    """Замедление одного прогона: последние скорости, серия медленных ответов, перезагрузки и строка оператору."""

    samples: list[float] = field(default_factory=list)
    history_median: float | None = None  # ориентир: медиана прошлых прогонов, только если замеров хватает
    history_typical: float | None = None  # та же медиана для строки оператору, даже по одному-двум замерам
    history_fast: bool = False
    streak: int = 0
    reloads: int = 0
    reload_pending: bool = False
    unload_allowed: bool = True  # снимок исполнителя разрешает выгрузку модели (профиль lan – только по разрешению)
    after_reload: bool = False
    pending_tps: float = 0.0
    pending_baseline: float = 0.0
    text: str = ""
    warning: bool = False


class TriageError(Exception):
    """Прогон не запустить или не изменить. Текст – по-русски, для показа в интерфейсе."""


# ============================================================================ порядок разбора

def severity_rank(f: Finding) -> int:
    """Ранг критичности: 0 – критическая. У SCA отчёта Hub критичности нет – ранг по полосам CVSS v3."""
    if f.severity in SEVERITY_RANK:
        return SEVERITY_RANK[f.severity]
    if f.cvss is not None:
        if f.cvss >= 9.0:
            return 0
        if f.cvss >= 7.0:
            return 1
        if f.cvss >= 4.0:
            return 2
        return 3 if f.cvss > 0 else 4
    return 5


def order_findings(findings: Iterable[Finding], sca_cvss: float = 9.0) -> list[dict]:
    """Находки → строки для Database.save_import (и reorder_findings) в порядке разбора.

    SAST впереди остальных видов; внутри вида – срочные, затем по критичности, затем по порядку выгрузки.
    Находки с одним ключом группы (дубли) идут подряд, на месте самой срочной из них.
    """
    items = []
    for index, f in enumerate(findings):
        urgent = bool(is_urgent(f, sca_cvss=sca_cvss))
        gk = group_key2(f)  # дубли идут подряд по ключу второй редакции (ADR-0095)
        key = (KIND_RANK.get(f.kind, 9), 0 if urgent else 1, severity_rank(f), index)
        items.append((f, urgent, gk, key, (f.kind, gk or f"id:{f.hub_id}")))
    best: dict[tuple[str, str], tuple] = {}
    for _, _, _, key, group in items:
        if group not in best or key < best[group]:
            best[group] = key
    items.sort(key=lambda item: (best[item[4]], item[3]))
    rows = []
    for pos, (f, urgent, gk, _, _) in enumerate(items):
        cat, file2, line = near_columns2(f)
        rows.append({"hub_id": f.hub_id, "pos": pos, "kind": f.kind, "severity": f.severity, "cvss": f.cvss,
                     "urgent": urgent, "codebase": f.codebase, "group_key": group_key(f), "group_key2": gk,
                     "g2_cat": cat, "g2_file": file2, "g2_line": line, "data": f.to_dict()})
    return rows


def reorder_project(db: Database, project_id: int, sca_cvss: float) -> int:
    """Заново упорядочить находки проекта и пересчитать срочность (например, после смены порога срочности SCA
    на странице «Настройки»). Порядок выгрузки восстанавливается по листу и строке. Возвращает, у скольких находок
    изменились порядок или срочность."""
    findings = [Finding.from_dict(row["data"]) for row in db.findings_data(project_id)]
    findings.sort(key=lambda f: (KIND_RANK.get(f.kind, 9), f.sheet, f.row))
    return db.reorder_findings(project_id, order_findings(findings, sca_cvss))


# ============================================================================ случай для модели

def repo_dir_for(settings: Settings, project: dict, codebase_map: dict[str, dict],
                 f: Finding) -> tuple[Path | None, str]:
    """Папка клона кодовой базы находки: (путь, "") или (None, причина). Отвязанный клон (detached, ADR-0072) не
    читается, даже если папка на месте: код кодовой базы – срезы в базе."""
    entry = codebase_map.get(f.codebase) or {}
    folder = str(entry.get("folder") or "").strip()
    if not folder:
        return None, "кодовая база не сопоставлена с папкой"
    if entry.get("detached"):
        return None, "клон отвязан: код берётся из срезов в базе"
    rel = "/".join(part for part in (str(project.get("repos_dir") or "").strip("/"), folder) if part)
    try:
        path = resolve_repo(settings.repos_root, rel)
    except ValueError as e:
        return None, str(e)
    if not path.is_dir():
        return None, "папка с клоном не найдена"
    if empty_dir(path):
        # Пустая папка на месте удалённого клона – тоже клона нет: иначе сверка ревизий сочла бы её другим
        # кодом и сбросила сохранённые срезы (ADR-0072)
        return None, "папка с клоном пуста"
    return path, ""


def empty_dir(path: Path) -> bool:
    """В папке нет ни одной записи. Не удалось прочитать – не пустая: решает обычная проверка файла."""
    try:
        with os.scandir(path) as entries:
            return next(entries, None) is None
    except OSError:
        return False


def stored_code(case: dict | None) -> CodeContext | None:
    """Сохранённый в базе срез находки (cases.context_json) или None, если среза нет. Срез с кодом из файла клона –
    статус «ok»; срез из одной строки выгрузки (файла в клоне не было) и срез без строк тоже возвращаются: без
    клона каждый остаётся тем, что видела модель, и отпечаток решения по нему не меняется."""
    context = (case or {}).get("context") or {}
    if not context.get("status"):
        return None
    try:
        return CodeContext.from_dict(context)
    except (TypeError, ValueError, KeyError):
        return None


def snapshot_code(settings: Settings, source: dict, case: dict | None) -> tuple[CodeContext, str] | None:
    """Код находки из базы вместо клона (ADR-0072): папки клона её кодовой базы нет (удалена, пуста, другой корень
    папок с клонами) или в клоне нет файла находки, а срез сохранён при разборе или кнопкой «Сохранить срезы кода» –
    (срез, отпечаток). Файл в клоне на месте или среза нет – None: код читается из клона, как раньше. Код проекта
    после выгрузки не меняется, поэтому сохранённый срез без клона считается текущим кодом: он не перезаписывается
    и не сверяется."""
    ctx = stored_code(case)
    if ctx is None:
        return None
    f = Finding.from_dict(source["data"])
    repo_dir, _ = repo_dir_for(settings, {"repos_dir": source["repos_dir"]}, source_codebases(source, f), f)
    if repo_dir is not None and _code_file_present(repo_dir, f, ctx.file):
        return None
    return ctx, case_hash(f, ctx)


def degrades(case: dict | None, ctx: CodeContext) -> bool:
    """Новый срез хуже сохранённого: в базе код из файла (статус «ok»), а сейчас – только строка выгрузки или ничего.
    Такой срез автоматически не записывается (ADR-0072): файл пропал во время разбора или не найден однозначно,
    а полноценный срез в базе – единственная копия кода, если клон потом удалят."""
    return ((case or {}).get("context") or {}).get("status") == "ok" and ctx.status != "ok"


def source_codebases(source: dict, f: Finding) -> dict[str, dict]:
    """Сопоставление кодовой базы находки по снимку Database.case_input() – для repo_dir_for."""
    return {f.codebase: {"folder": source["folder"], "detached": bool(source.get("detached"))}}


def _code_file_present(repo_dir: Path, f: Finding, stored_file: str = "") -> bool:
    """Файл находки есть в клоне или это не определить (файл не читается). Нет только тогда, когда это доказано:
    клон удалён не целиком – осталась .git или часть папок – и файла нет ни по пути сохранённого среза, ни по пути
    из выгрузки. Несколько подходящих файлов или неполный обход клона – файл считается на месте: код читается из
    клона, и его изменения видны, как раньше."""
    try:
        for rel in dict.fromkeys(r for r in (norm_path(stored_file), norm_path(f.file)) if r):
            if file_presence(repo_dir, rel) != "missing":
                return True
    except (OSError, ValueError):
        return True
    return False


def observed_revisions(settings: Settings, project: dict, codebase_map: dict[str, dict]) -> dict[str, str]:
    """Ревизии клонов кодовых баз проекта, папка которых сейчас на месте: {кодовая база: ревизия}; "" – папка
    не клон git. Кодовые базы без папки или с пропавшей папкой не входят: о них ничего не известно."""
    result = {}
    for codebase, entry in codebase_map.items():
        if not str((entry or {}).get("folder") or "").strip():
            continue
        repo_dir, _ = repo_dir_for(settings, project, codebase_map, Finding(hub_id="", kind="SAST", codebase=codebase))
        if repo_dir is not None:
            result[codebase] = clone_revision(repo_dir)
    return result


def sync_revisions(db: Database, settings: Settings, project: dict) -> dict:
    """Сверка ревизий клонов проекта с запомненными (Database.sync_revisions): при смене ревизии срезы находок
    этой кодовой базы сбрасываются, а отметки «проверено» снимаются. Перед сверкой удалённые клоны с полными срезами
    отвязываются (detach_removed_clones): клон другой выгрузки, положенный потом на то же место, срезы не сбросит."""
    detach_removed_clones(db, settings, project)
    return db.sync_revisions(project["id"], observed_revisions(settings, project,
                                                               db.get_codebase_map(project["id"], with_detached=True)))


def detach_removed_clones(db: Database, settings: Settings, project: dict) -> list[str]:
    """Отвязать клоны, которые удалили после разбора (ADR-0072): у кодовой базы выбрана папка, клона нет (папка
    удалена, пуста или вне корня), срез полон у каждой её находки SAST и хотя бы в одном срезе код из файла
    (клон был: кодовую базу, которую разбирали без клона, не отвязываем). Отвязанный клон больше не читается,
    пока человек не подключит клоны снова (Database.clear_detached) или не выберет другую папку. Возвращает
    отвязанные сейчас кодовые базы."""
    pid = int(project["id"])
    if not settings.repos_root.is_dir():
        return []  # корень папок с клонами не подключён: это не удаление клонов, отвязывать нельзя
    counts = db.snapshot_counts(pid)
    cmap = db.get_codebase_map(pid, with_detached=True)
    removed = []
    for codebase, entry in cmap.items():
        n = counts.get(codebase) or {}
        if (not str(entry.get("folder") or "").strip() or entry.get("detached") or not n.get("sast")
                or n.get("none") or n.get("incomplete") or not n.get("code")):
            continue
        repo_dir, _ = repo_dir_for(settings, project, cmap, Finding(hub_id="", kind="SAST", codebase=codebase))
        if repo_dir is None:
            removed.append(codebase)
    if removed:
        db.set_detached(pid, removed)
    return removed


def save_snapshots(db: Database, settings: Settings, project: dict, mask_key: bytes) -> dict:
    """«Сохранить срезы кода» (ADR-0072): находкам SAST текущей выгрузки без сохранённого среза, у которых клон на
    месте, строится и записывается срез – так же, как его строит прогон (маскирование, CONTEXT_CHARS), но без
    модели. Удалять клоны можно после проверки полноты срезов. Срез без вердикта с причиной missing, unreadable
    или неизвестной причиной, а также no_repo сопоставленного неотвязанного клона заменяется, только если файл
    теперь доступен и прочитан; прежний вердикт по no_repo к новому коду не привязывается.
    Возвращает {"saved": сколько записано, "skipped": {причина: сколько}}."""
    pid = int(project["id"])
    saved, skipped = 0, {}
    for hub_id, upgrade in db.snapshot_candidates(pid):
        source = db.case_input(pid, hub_id)
        if source is None or source.get("missing"):
            continue
        f = Finding.from_dict(source["data"])
        repo_dir, why = repo_dir_for(settings, {"repos_dir": source["repos_dir"]}, source_codebases(source, f), f)
        if repo_dir is None:
            skipped[why] = skipped.get(why, 0) + 1
            continue
        if upgrade and file_presence(repo_dir, f.file) != "found":
            continue
        # срез без строк тоже сохраняется – как в прогоне («Нет кода для разбора»): без клона он останется тем же
        ctx = build_context(repo_dir, f, max_chars=CONTEXT_CHARS, mask_key=mask_key, no_repo_note=why)
        if upgrade and ctx.status != "ok":
            continue  # полноценный срез не получен: прежний срез остаётся
        if db.save_case(pid, hub_id, case_hash(f, ctx), {**case_context(f, ctx), "max_chars": CONTEXT_CHARS},
                        None, source, only_new=not upgrade, replace_line_only=upgrade):
            saved += 1
    return {"saved": saved, "skipped": skipped}


def case_hash(f: Finding, ctx: CodeContext) -> str:
    """Отпечаток случая – всё, что модель видит в сведениях о находке и в коде: правило, место, маскированный срез
    кода и сведения о нём. ID находки, имя кодовой базы, анализатор и критичность в промпт не входят (prompts.py),
    поэтому нет их и здесь: дубль от другого анализатора или с другой критичностью получает тот же вердикт.
    Шаблон промпта учитывает PROMPT_VERSION в ключе кэша, параметры генерации – константы (окно контекста на вход
    не влияет: промпт, который в него не помещается, не отправляется)."""
    payload = {
        "kind": f.kind, "rule": f.rule, "cwe": list(f.cwe), "file": f.file, "line": f.line,
        "language": f.language, "snippet": " ".join(str(f.snippet or "").split()),
        "ctx": {"status": ctx.status, "file": ctx.file, "language": ctx.language, "start": ctx.start_line,
                "target": ctx.target_line, "lines": list(ctx.lines), "enclosing": ctx.enclosing,
                "export_line_check": ctx.export_line_check, "note": ctx.note},
    }
    if ctx.export_line_check_version >= 2:
        # ADR-0082: в отпечатке – сверка версии 1 по тому же коду, чтобы уточнённая сверка не меняла отпечаток
        # неизменного кода (иначе карточка сочла бы код изменившимся и решение потеряло бы «Проверено»)
        payload["ctx"]["export_line_check"] = ctx.hash_check
        payload["ctx"]["export_line_at"] = ctx.hash_check_at
    elif ctx.export_line_check_version >= 1:
        payload["ctx"]["export_line_at"] = ctx.export_line_at  # новые срезы; старые отпечатки остаются прежними
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def think_for(model: str) -> str | None:
    """Режим рассуждений передаётся только моделям gpt-oss."""
    return "low" if "gpt-oss" in model.casefold() else None


def model_options(num_ctx: int) -> dict[str, int]:
    """Параметры генерации прогона: окно контекста из настроек; предел длины ответа – не больше четверти окна,
    чтобы в маленьком окне оставалось место под промпт."""
    return {"num_ctx": int(num_ctx), "num_predict": min(int(DEFAULT_OPTIONS["num_predict"]), int(num_ctx) // 4)}


def case_context(f: Finding, ctx: CodeContext) -> dict[str, Any]:
    """Срез для хранения (cases.context_json): CodeContext и признаки попытки повлиять на разбор – номера строк
    кода и названия полей находки с текстом, похожим на указания для модели. Карточка и список показывают их
    человеку: вердикт, полученный под влиянием таких указаний, не должен выглядеть как обычный."""
    return {**ctx.to_dict(), "steering_lines": steering_lines(ctx), "steering_fields": steering_fields(f, ctx)}


def current_code(settings: Settings, source: dict, mask_key: bytes, max_chars: int = CONTEXT_CHARS,
                 case: dict | None = None) -> tuple[Finding, CodeContext, str]:
    """Срез текущего кода находки по снимку Database.case_input() – так же, как его строит прогон: (находка,
    срез, отпечаток case_hash). Отпечаток сравнивается с тем, что видела модель (cases.case_hash) или человек
    (reviews.code_hash): изменился – код в клоне другой. max_chars – размер среза, с которым считался отпечаток,
    с которым идёт сравнение. case – сохранённый срез находки: если клона нет, текущий код – он (snapshot_code).
    Без клона срез другого размера не построить: возвращается отпечаток сохранённого среза, и решение, принятое при
    другом размере, не совпадёт – его актуальность не доказана (code_changed), решение сохраняют заново."""
    f, ctx, chash, _ = current_code_origin(settings, source, mask_key, max_chars, case)
    return f, ctx, chash


def current_code_origin(settings: Settings, source: dict, mask_key: bytes, max_chars: int = CONTEXT_CHARS,
                        case: dict | None = None) -> tuple[Finding, CodeContext, str, bool]:
    """То же, что current_code, и признак: срез подставлен из базы (клона или файла находки нет, snapshot_code).
    Признак – у того же чтения: повторная проверка клона позже может увидеть уже вернувшийся файл, код которого
    никто не читал (ревью Codex ветки долга, круг 5)."""
    f = Finding.from_dict(source["data"])
    snapshot = snapshot_code(settings, source, case)
    if snapshot is not None:
        return f, snapshot[0], snapshot[1], True
    repo_dir, why = repo_dir_for(settings, {"repos_dir": source["repos_dir"]}, source_codebases(source, f), f)
    ctx = build_context(repo_dir, f, max_chars=max_chars, mask_key=mask_key, no_repo_note=why)
    return f, ctx, case_hash(f, ctx), False


def _merged_stats(first: LlmStats | None, second: LlmStats | None) -> LlmStats | None:
    """Замеры двух обращений одной находки (оборванное и автоматический повтор, ADR-0107): токены, попытки и время
    складываются, скорость – последнего ответа."""
    if first is None or second is None:
        return second if second is not None else first
    return dataclasses.replace(
        second, prompt_tokens=first.prompt_tokens + second.prompt_tokens,
        output_tokens=first.output_tokens + second.output_tokens, attempts=first.attempts + second.attempts,
        total_s=round(first.total_s + second.total_s, 3), load_s=first.load_s + second.load_s,
        reasoning_tokens=first.reasoning_tokens + second.reasoning_tokens,
        cache_hit_tokens=first.cache_hit_tokens + second.cache_hit_tokens,
        think=",".join(p for p in (first.think, second.think) if p))


def _after_drop(drop_error: LlmError, retry_error: Exception) -> LlmError:
    """Обрыв без ответа, после которого повтор не получил ответа модели (не ушёл, 402, ошибка сервера): находка –
    «результат неизвестен» первого запроса, причина повтора – в тексте (ревью Codex, круг 18)."""
    drop_error.drop_retries = 1  # type: ignore[attr-defined]
    drop_error.retry_error = str(retry_error)  # type: ignore[attr-defined]
    # 402 повтора – провайдер просит оплату: прогон встаёт на паузу по оплате (ревью Codex, круг 19)
    drop_error.retry_status = getattr(retry_error, "status", None)  # type: ignore[attr-defined]
    drop_error.stats = _merged_stats(drop_error.stats, getattr(retry_error, "stats", None))
    return drop_error


def _stats_partial(error: LlmError) -> bool:
    """Замеры неудачного ответа неполные: попытку прервал сбой связи или сервера, и что модель успела
    сгенерировать в ней, неизвестно (ответ не по формату, оборванный по длине ответ – замерены полностью).
    Признак – ответа модели в ошибке нет (raw пуст), хотя попытка была; если клиент сам сообщает признак
    (stats_partial), берётся он."""
    explicit = getattr(error, "stats_partial", None)
    if explicit is not None:
        return bool(explicit)
    if getattr(error, "drop_retries", 0):
        # одна из попыток оборвалась без ответа: её расход неизвестен, как бы ни закончился повтор (ревью Codex, круг 19)
        return True
    if getattr(error, "reason", None):
        # известный исход (LlmError.reason, ADR-0106 п. 8): ответ получен целиком, его расход в stats – замеры полные,
        # даже если текста ответа нет (отказ модели, неизвестная причина остановки, ответ не по протоколу; KIMI-05)
        return False
    return error.stats is not None and error.stats.attempts > 0 and not error.raw


# ============================================================================ очередь

class TriageRunner:
    """Фоновый поток триажа. Состояние прогонов – в базе; принятые команды паузы и стопа – в памяти процесса
    и в базе (runs.control), чтобы принятый «Стоп» пережил перезапуск."""

    def __init__(self, db: Database, settings: Settings,
                 client_factory: Callable[[str], OllamaClient] | None = None,
                 mask_key: bytes | None = None) -> None:
        self.db = db
        self.settings = settings
        self._client_factory = client_factory or OllamaClient
        self._mask_key = mask_key if mask_key is not None else db.mask_key()
        self._lock = threading.Lock()  # команды, переходы состояний идущего прогона, текущая находка
        self._life = threading.Lock()  # запуск и остановка потока
        self._controls: dict[int, str] = {}  # run_id -> 'pause' | 'stop'
        self._live: dict[int, dict[str, Any]] = {}  # run_id -> текущая находка и этап
        self._slow: dict[int, _SlowState] = {}  # run_id -> замедление и перезагрузки модели
        self._unsaved_errors: dict[int, str] = {}  # прогоны, чьё состояние «ошибка» не удалось записать
        # прогоны, чью паузу из-за занятой базы не удалось записать (Э2): причина – запишется позже
        self._unsaved_pauses: dict[int, str] = {}
        # обрывы без ответа у внешнего провайдера по прогону: {run_id: {"drops", "streak", "done"}}; каскад – пауза
        # прогона после находки (DROP_STREAK_PAUSE, DROP_SHARE_PAUSE); счёт заново после «Продолжить»
        self._drops: dict[int, dict[str, int]] = {}
        self._drop_pause: dict[int, str] = {}
        self._wake = threading.Event()
        self._halt = threading.Event()
        self._thread: threading.Thread | None = None

    def current_settings(self) -> Settings:
        """Действующие настройки: сохранённые в интерфейсе (таблица settings) поверх переменных окружения."""
        return self.settings.with_stored(self.db.get_settings())

    # ---------------------------------------------------------------- жизненный цикл

    def start(self) -> None:
        """Запускает поток. Прогоны, прерванные перезапуском, ставятся на паузу. Повторный вызов при живом
        потоке ничего не делает; после shutdown() ждёт, пока прежний поток доработает находку."""
        with self._life:
            if self._thread is not None and self._thread.is_alive():
                if not self._halt.is_set():
                    return
                self._thread.join()
            self.db.recover_interrupted()
            self._halt = threading.Event()
            thread = threading.Thread(target=self._loop, args=(self._halt,), name="triage-worker", daemon=True)
            thread.start()  # не запустился – прежнее состояние, shutdown() не ждёт незапущенный поток
            self._thread = thread

    def shutdown(self, timeout: float = 5.0) -> bool:
        """Останавливает поток после текущей находки. True – поток завершился за timeout секунд
        (только тогда базу можно закрывать)."""
        with self._life:
            self._halt.set()
            self._wake.set()
            thread = self._thread
        if thread is None or thread.ident is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    # ---------------------------------------------------------------- команды

    def enqueue(self, project_id: int, model: str, scope: str, hub_ids: Iterable[str] = (),
                fresh: bool = False, origin: str = "", provider_id: int | None = None) -> int:
        """Ставит прогон в очередь; возвращает его номер. fresh – не брать готовые вердикты из кэша. Профиль –
        provider_id или профиль проекта, или профиль приложения (ADR-0102); снимок исполнителя пишется вместе с
        прогоном: окно, предел ответа, срок и режим схемы замораживаются при постановке."""
        model = str(model or "").strip()
        if scope not in SCOPES:
            raise TriageError("Неизвестный охват прогона.")
        if not model:
            raise TriageError("Не выбрана модель.")
        settings = self.current_settings()
        try:
            profile = choose_profile(self.db, settings, self.db.get_project(project_id), provider_id)
        except ProfileError as e:
            raise TriageError(str(e)) from None
        execution = execution_values(profile, model, "triage", settings.num_ctx, settings.model_json_schema)
        with self._lock:
            active = self.db.active_runs(project_id)
            if active:
                if origin == "card" and active[0].get("state") != "paused":  # разборы идут по одному, очереди нет – сказать, что делать
                    raise TriageError(f"Сейчас идёт другой разбор (прогон №{active[0]['id']}). Разборы проекта идут по одному: "
                                      "дождитесь его конца и нажмите «Разобрать» снова. Ход прогона – на странице проекта.")
                raise TriageError(f"У проекта есть незавершённый прогон №{active[0]['id']}: продолжите или "
                                  "остановите его.")
            try:  # состав очереди и паспорт – одним чтением в транзакции создания прогона (бэклог 104)
                run_id = self.db.create_run(project_id, model, scope, PROMPT_VERSION, list(hub_ids), fresh=fresh,
                                            origin=origin, execution=execution, queue_scope=scope)
            except EmptyQueue:
                raise TriageError("Нет находок SAST для выбранного охвата.") from None
            except ProfileChanged as e:
                raise TriageError(f"{e} Выберите для проекта действующий профиль.") from None
        self._wake.set()
        return run_id

    def continuation_reason(self, run: dict) -> str:
        """Почему прогон нельзя продолжить им самим ("" – можно): у него нет снимка исполнителя (начат до 0.9.12) или
        профиль снимка выключен. Тогда «Продолжить» – новый прогон на действующем профиле проекта (П22)."""
        execution = self.db.get_execution(run.get("execution_id"))
        if execution is None:
            return "Прогон начат до 0.9.12: адрес исполнителя у него не записан."
        profile = self.db.get_provider(execution["provider_id"]) if execution.get("provider_id") else None
        return snapshot_mismatch(profile, execution)

    def continue_as_new(self, run_id: int, hub_ids: Iterable[str] | None = None, origin: str | None = None,
                        fresh: bool | None = None, execution_id: int | None = None) -> int:
        """Новый прогон вместо прежнего (ADR-0102 п. 4–5, П22): «Продолжить» у прогона без снимка или с выключенным
        профилем, «Повторить ошибочные». Новый прогон – с parent_run_id и собственным снимком на действующем профиле
        проекта (или с перенесённым снимком execution_id); прежний, если он в очереди или на паузе, останавливается в
        той же транзакции с отметкой, каким прогоном продолжен. Все проверки – до записи: отказ прежний прогон не
        трогает. hub_ids – находки (по умолчанию – неразобранные)."""
        with self._lock:
            run = self.db.get_run(run_id)
            if run is None:
                raise TriageError("Прогон не найден.")
            if run["state"] == "running":
                raise TriageError("Прогон ещё идёт: сначала поставьте его на паузу.")
            self.db.settle_sending_items(run_id)  # К11: находки с меткой без результата новым прогоном не берутся
            ids = list(hub_ids) if hub_ids is not None else self.db.pending_hub_ids(run_id)
            if not ids:
                raise TriageError("Продолжать нечего: все находки прогона уже разобраны.")
            execution = None
            if execution_id is None:
                settings = self.current_settings()
                try:
                    profile = choose_profile(self.db, settings, self.db.get_project(run["project_id"]))
                except ProfileError as e:
                    raise TriageError(str(e)) from None
                execution = execution_values(profile, run["model"], "triage", settings.num_ctx,
                                             settings.model_json_schema)
            others = [r for r in self.db.active_runs(run["project_id"]) if r["id"] != run_id]
            if others:
                raise TriageError(f"У проекта есть незавершённый прогон №{others[0]['id']}: продолжите или "
                                  "остановите его.")
            try:
                new_id = self.db.create_run(run["project_id"], run["model"], "selected", PROMPT_VERSION, ids,
                                            fresh=bool(run["fresh"]) if fresh is None else fresh,
                                            origin=run.get("origin") or "" if origin is None else origin,
                                            execution=execution, execution_id=execution_id, parent_run_id=run_id)
            except ProfileChanged as e:  # профиль выключили или сменили адрес только что: прежний прогон не тронут
                raise TriageError(f"{e} Запустите новый прогон на действующем профиле проекта.") from None
            except RuntimeError:
                raise TriageError("Прогон успел измениться: обновите страницу.") from None
        self._wake.set()
        return new_id

    def retry_errors(self, run_id: int, hub_ids: Iterable[str]) -> int:
        """«Повторить ошибочные» (ADR-0102 п. 5): снимок прежнего прогона переносится, если его профиль включён и адрес
        профиля не менялся; профиль выключен или адрес изменился – отказ с причиной (прежний прогон не трогается);
        прогон без снимка (до 0.9.12) – новый прогон на действующем профиле проекта с собственным снимком."""
        run = self.db.get_run(run_id)
        if run is None:
            raise TriageError("Прогон не найден.")
        execution = self.db.get_execution(run.get("execution_id"))
        if execution is None:
            return self.continue_as_new(run_id, hub_ids, origin="retry", fresh=True)
        profile = self.db.get_provider(execution["provider_id"]) if execution.get("provider_id") else None
        reason = snapshot_mismatch(profile, execution)
        if reason:
            raise TriageError(f"{reason} Запустите новый прогон ошибочных находок на действующем профиле проекта.")
        return self.continue_as_new(run_id, hub_ids, origin="retry", fresh=True, execution_id=int(execution["id"]))

    def pause(self, run_id: int) -> bool:
        """Пауза: прогон в очереди – сразу, идущий – после текущей находки. Принятый стоп важнее."""
        with self._lock:
            run = self.db.get_run(run_id)
            if run is None:
                return False
            if run["state"] == "queued" and self.db.set_run_state(run_id, "paused", last_error="",
                                                                  only_from=("queued",)):
                return True
            run = self.db.get_run(run_id)  # поток мог успеть взять прогон в работу
            if (run is not None and run["state"] == "running" and self._controls.get(run_id) != "stop"
                    and run.get("control") != "stop"):
                try:
                    accepted = self.db.set_run_control(run_id, "pause")
                except CommitUnknown:
                    self._controls[run_id] = "pause"  # запись могла подтвердиться, а команду оператор дал
                    raise
                if not accepted:
                    return False
                self._controls[run_id] = "pause"
                return True
            return False

    def resume(self, run_id: int) -> bool:
        """Продолжить: прогон на паузе возвращается в очередь; у идущего снимается принятая пауза."""
        with self._lock:
            run = self.db.get_run(run_id)
            if run is None:
                return False
            # пауза, у которой не записался итог: обработчик уже вышел, а в базе прогон ещё идёт – он тоже возвращается в очередь
            stopping = self._controls.get(run_id) == "stop" or run.get("control") == "stop"  # принятый «Стоп» важнее
            if run["state"] == "paused" or (run["state"] == "running" and run_id in self._unsaved_pauses and not stopping):
                # К11: находки с меткой отправки без результата – «результат неизвестен», снова не отправляются
                self.db.settle_sending_items(run_id)
                if run["state"] == "paused":  # пауза уже в базе; записать её заново после этого «Продолжить» нельзя и при обрыве
                    self._unsaved_pauses.pop(run_id, None)
                ok = self.db.set_run_state(run_id, "queued", last_error="", only_from=(run["state"],))
                if ok:
                    # отложенная пауза не должна отменить это «Продолжить»
                    self._unsaved_pauses.pop(run_id, None)
                    self._controls.pop(run_id, None)
                    self._wake.set()
                return ok
            if run["state"] == "running" and self._controls.get(run_id) == "pause":
                self.db.set_run_control(run_id, "")
                del self._controls[run_id]
                return True
            return False

    def stop(self, run_id: int) -> bool:
        """Стоп: прогон в очереди или на паузе – сразу, идущий – после текущей находки. Принятая команда идущего
        прогона сначала записывается в базу: если приложение перезапустится раньше, чем закончится текущая
        находка, прогон при запуске будет остановлен, а не поставлен на паузу."""
        with self._lock:
            run = self.db.get_run(run_id)
            if run is None:
                return False
            if run["state"] in ("queued", "paused") and self.db.set_run_state(
                    run_id, "stopped", only_from=("queued", "paused")):
                return True
            run = self.db.get_run(run_id)
            if run is not None and run["state"] == "running":
                try:
                    accepted = self.db.set_run_control(run_id, "stop")
                except CommitUnknown:
                    self._controls[run_id] = "stop"  # запись могла подтвердиться, а команду оператор дал: прогон остановится
                    raise
                if accepted:
                    self._controls[run_id] = "stop"
                    return True
            return False

    def _apply_control(self, run_id: int) -> bool:
        """Между находками: выполнить принятую команду. True – прогон остановлен или поставлен на паузу."""
        with self._lock:
            control = self._controls.get(run_id)
            if control is None:
                return False
            self.db.set_run_state(run_id, "stopped" if control == "stop" else "paused", only_from=("running",))
            self._controls.pop(run_id, None)  # после записи: занятая база при повторе не потеряет команду
            if control == "stop":
                self._slow.pop(run_id, None)
            return True

    def _finish(self, run_id: int, state: str, last_error: str | None = None) -> None:
        """Перевести идущий прогон в state. Если принят стоп, вместо паузы прогон останавливается."""
        with self._lock:
            control = self._controls.get(run_id)
            if control == "stop" and state == "paused":
                state = "stopped"
            self.db.set_run_state(run_id, state, last_error=last_error, only_from=("running",))
            self._controls.pop(run_id, None)  # после записи: занятая база при повторе не потеряет принятый стоп
            if state in FINAL_RUN_STATES:
                self._slow.pop(run_id, None)

    def _set_live(self, run_id: int, **values: Any) -> None:
        with self._lock:
            if 'since' in values:
                values['since_monotonic'] = time.monotonic() if values['since'] is not None else None
            if values.get('phase') and values.get('phase') != self._live.get(run_id,{}).get('phase'):
                values['phase_since'] = time.time()
            self._live.setdefault(run_id, {}).update(values)

    # ---------------------------------------------------------------- состояние для страницы прогона

    def run_status(self, run_id: int) -> dict | None:
        """Состояние прогона: счётчики, скорость, оценка оставшегося времени, текущая находка, лента."""
        run = self.db.get_run(run_id)
        if run is None:
            return None
        with self._lock:
            live = dict(self._live.get(run_id) or {})
            control = self._controls.get(run_id)
        active = run["state"] in ACTIVE_RUN_STATES
        pending, calls = self.db.pending_model_groups(run_id) if active else (0, 0)
        # среднее время ответа модели – без загрузки модели в память (её время – только у первой находки)
        avg_call = run["model_seconds"] / run["model_calls"] if run["model_calls"] else None
        from app.journal import eta_average
        estimate = eta_average(self.db, run_id)
        eta = round(calls * estimate) if run['state'] == 'running' and estimate is not None else None
        tps_avg = run["output_tokens"] / run["eval_seconds"] if run["eval_seconds"] > 0 else None
        # удалённый API: видеокарта и память этого компьютера к прогону не относятся, скорость генерации сервер не
        # сообщает – скорость ответа считается по времени модели (с ожиданием сервера)
        execution = self.db.get_execution(run.get("execution_id")) if run.get("execution_id") else None
        remote = str((execution or {}).get("kind") or "ollama") in REMOTE_KINDS
        if remote and tps_avg is None and run["model_seconds"] > 0 and run["output_tokens"]:
            tps_avg = run["output_tokens"] / run["model_seconds"]
        # длительность – время работы над находками: паузы и простой после перезапуска не входят
        elapsed = None
        if run["started_at"]:
            working = self.db.run_work_seconds(run_id)
            if run["state"] == "running" and live.get("since"):
                working += max(0.0, time.monotonic() - live.get('since_monotonic', time.monotonic()))
            elapsed = round(working)
        current = None
        if run["state"] == "running" and live.get("hub_id") and live.get("since"):
            current = {"hub_id": live.get("hub_id"), "finding_id": live.get("finding_id"),
                       "phase": live.get("phase", ""), "seconds": round(max(0, time.monotonic() - live.get('since_monotonic', time.monotonic()))),
                       **{k:live.get(k) for k in ('phase_since','request_started_at','last_model_event_at','attempt')}}
        total = int(run["total"] or 0)
        new_verdicts = run["done"] - run["cached"] - run["skipped"] - run["failed"]
        feed = self.db.recent_items(run_id, FEED_SIZE)
        from app import journal
        slow = journal.slow_model_state(self.db, run_id)
        return {
            "run": {key: run[key] for key in ("id", "project_id", "state", "scope", "model", "prompt_version",
                                              "fresh", "total", "done", "failed", "cached", "skipped",
                                              "model_calls", "last_error", "created_at", "started_at",
                                              "finished_at", "partial_stats")},
            "new_verdicts": max(0, new_verdicts),
            "progress": round(100.0 * run["done"] / total, 1) if total else 100.0,
            "pending": pending,
            "eta_s": eta,
            "avg_call_s": round(avg_call, 1) if avg_call is not None else None,
            "elapsed_s": elapsed,
            # у удалённого API последней скорости генерации нет – на её месте средняя скорость ответа
            "tps_last": (round(tps_avg, 1) if remote and tps_avg else
                         round(run["last_tps"], 1) if run["last_tps"] else None),
            "tps_avg": round(tps_avg, 1) if tps_avg else None,
            "remote_executor": remote,
            "remote_where": {"external": "у внешнего провайдера (интернет)", "lan": "на сервере в сети организации"}.get(
                str((execution or {}).get("trust") or ""), "на сервере провайдера") if remote else "",
            "control": control,
            "current": current,
            "feed": feed,
            "last_result_at": feed[0]['finished_at'] if feed else None,
            "slow_model": ({key: slow.get(key) for key in ("tps", "baseline", "reloads", "text", "warning")}
                           if slow.get("text") else None),
            "journal_warning": model_traffic.failure_text(run_id),
        }

    # ---------------------------------------------------------------- поток

    def _loop(self, halt: threading.Event) -> None:
        """Диспетчер очереди. Не завершается от ошибок: сбой базы – подождать и попробовать снова."""
        while not halt.is_set():
            try:
                self._save_pending_errors()
                run = self.db.next_queued_run()
            except Exception as e:
                log_failure(log, "очередь прогонов недоступна", e)
                halt.wait(WORKER_POLL_S)
                continue
            if run is None:
                self._wake.wait(WORKER_POLL_S)
                self._wake.clear()
                continue
            run_id = int(run["id"])
            try:
                with model_traffic.context(run_id=run_id):  # сбой журнала при любом обращении прогона – в его учёт
                    self._process_run(run_id, halt)
            except BUSY_ERRORS as e:  # база занята, недоступна или исход записи неизвестен: данные целы, это не ошибка прогона
                log_failure(log, "прогон %s на паузе: база занята или исход записи неизвестен", e, run_id)
                self._pause_after_db_failure(run_id, DB_UNKNOWN_PAUSE if isinstance(e, CommitUnknown) else DB_RUN_PAUSE)
            except Exception as e:  # прогон не должен оставаться «идёт» после сбоя
                eid = log_failure(log, "прогон %s прерван внутренней ошибкой", e, run_id)
                self._mark_error(run_id, f"Внутренняя ошибка {type(e).__name__} (ошибка {eid}). Подробности – "
                                         "в журнале контейнера.")
            finally:
                with self._lock:
                    # отложенной паузе нужен принятый «Стоп»: он мог остаться только в памяти
                    if run_id not in self._unsaved_pauses or self._controls.get(run_id) != "stop":
                        self._controls.pop(run_id, None)
                    self._live.pop(run_id, None)

    def _pause_after_db_failure(self, run_id: int, note: str) -> None:
        """Пауза прогона после сбоя записи вне обработки находки. Оставшийся в очереди тоже: иначе поток брал бы его снова и снова,
        а следующие прогоны ждали бы. Завершённый не меняется; принятый «Стоп» (в памяти или в базе) важнее паузы. Сбой этой записи
        не останавливает поток очереди: она повторится, когда база освободится (_save_pending_errors)."""
        failure = None
        with self._lock:  # и запись, и её откладывание под одним замком: «Продолжить» не вклинится между ними
            try:
                run = self.db.get_run(run_id) or {}
                stop = self._controls.get(run_id) == "stop" or run.get("control") == "stop"
                self.db.set_run_state(run_id, "stopped" if stop else "paused", last_error=note, only_from=("running", "queued"))
                self._controls.pop(run_id, None)
                if (self.db.get_run(run_id) or {}).get("state") in FINAL_RUN_STATES:
                    self._slow.pop(run_id, None)
            except Exception as e:
                failure = e
                self._unsaved_pauses[run_id] = note
        if failure is not None:
            log_failure(log, "пауза прогона %s не записана, повторю позже", failure, run_id)

    def _mark_error(self, run_id: int, text: str) -> None:
        try:
            self.db.set_run_state(run_id, "error", last_error=text, only_from=("running", "queued"))
            with self._lock:
                self._slow.pop(run_id, None)
        except Exception as e:
            log_failure(log, "состояние прогона %s не записано, повторю позже", e, run_id)
            with self._lock:
                self._unsaved_errors[run_id] = text

    def _save_pending_errors(self) -> None:
        with self._lock:
            pauses = dict(self._unsaved_pauses)
        for run_id, text in pauses.items():
            with self._lock:  # как _finish: принятый «Стоп» (в памяти или в базе) важнее паузы, снимается после записи
                if run_id not in self._unsaved_pauses:  # пока шёл обход, оператор нажал «Продолжить»
                    continue
                run = self.db.get_run(run_id) or {}
                stop = self._controls.get(run_id) == "stop" or run.get("control") == "stop"
                self.db.set_run_state(run_id, "stopped" if stop else "paused", last_error=text, only_from=("running", "queued"))
                self._unsaved_pauses.pop(run_id, None)
                self._controls.pop(run_id, None)
                if (self.db.get_run(run_id) or {}).get("state") in FINAL_RUN_STATES:
                    self._slow.pop(run_id, None)
        with self._lock:
            pending = dict(self._unsaved_errors)
        for run_id, text in pending.items():
            self.db.set_run_state(run_id, "error", last_error=text, only_from=("running", "queued"))
            with self._lock:
                self._unsaved_errors.pop(run_id, None)
                self._slow.pop(run_id, None)

    def _process_run(self, run_id: int, halt: threading.Event) -> None:
        if not self.db.set_run_state(run_id, "running", last_error="", only_from=("queued",)):
            return  # прогон успели поставить на паузу или остановить
        run = self.db.get_run(run_id)
        project = self.db.get_project(run["project_id"]) if run is not None else None
        if run is None or project is None:
            self._finish(run_id, "error", "Проект прогона не найден.")
            return
        if run["prompt_version"] != PROMPT_VERSION:
            self._finish(run_id, "error", f"Прогон начат с промптом {run['prompt_version']}, а приложение уже "
                                          f"работает с {PROMPT_VERSION}: запустите новый прогон.")
            return
        settings = self.current_settings()  # папки клонов; адрес, модель и параметры – из снимка исполнителя
        execution = self.db.get_execution(run.get("execution_id"))
        if execution is None:  # прогон до 0.9.12 (остался в очереди после обновления): исполнителя не подменяем
            self._finish(run_id, "paused", LEGACY_RUN_NOTE)
            return
        guard = send_guard(self.db, execution, project_id=run["project_id"])
        try:
            guard()
        except SendNotAllowed as e:
            self._finish(run_id, "paused", pause_text(e))
            return
        try:  # клон могли обновить (git pull) после прошлой сверки: срезы по прежнему коду не берутся
            changed = sync_revisions(self.db, settings, project)["changed"]
            if changed:  # имена кодовых баз в журнал не пишутся: журнал пересылают при сбоях
                log.info("прогон %s: сменилась ревизия клонов у %d кодовых баз", run_id, len(changed))
        except Exception as e:
            log_failure(log, "ревизии клонов не сверены (прогон %s)", e, run_id)
        client = client_for(self._client_factory, execution, guard, db=self.db,
                            project_id=run["project_id"])
        options, _, think_rule = snapshot_options(execution)
        gate = gate_for(execution)  # группа права на генерацию – из снимка прогона (ADR-0104 п. 6), не пересчитывается
        try:
            client.check_url()
        except LlmError as e:  # адрес не из разрешённых: продолжать бессмысленно, пока адрес не исправлен
            self._refresh_contexts(run, halt)
            refused = self._refused(guard)  # профиль выключили – пауза, а не ошибка адреса
            self._finish(run_id, "paused" if refused else "error", refused or str(e))
            return
        # счёт обрывов без ответа – заново на каждый запуск и после «Продолжить» (каскад – пауза, _count_drop)
        self._drops.pop(run_id, None)
        self._drop_pause.pop(run_id, None)
        # удалённые API – точное имя модели, Ollama – без регистра и «:latest» (ADR-0106 п. 7)
        name_of = same_model(str(execution.get("kind") or "ollama"))
        remote = str(execution.get("kind") or "ollama") in REMOTE_KINDS
        try:
            model_list = client.list_models()
            names = {name_of(m.get("name", "")) for m in model_list}
        except LlmError as e:
            self._refresh_contexts(run, halt)
            # отказ допуска (адрес не подтверждён, ключ задан для другого адреса) – со своей причиной и подсказкой
            self._finish(run_id, "paused", self._refused(guard) or (
                pause_text(e) if isinstance(e, SendNotAllowed) else f"{e} {pause_note(execution)}"))
            return
        if name_of(run["model"]) not in names:
            self._refresh_contexts(run, halt)
            refused = self._refused(guard)  # модель пропала, а профиль за это время выключили: причина – профиль
            if refused:
                self._finish(run_id, "paused", refused)
                return
            self._finish(run_id, "error", (
                f"Модели «{run['model']}» нет в списке моделей сервера профиля: проверьте имя модели (оно "
                "сравнивается точно, с учётом регистра) в профиле или в параметрах проекта." if remote else
                f"Модели «{run['model']}» нет в Ollama. Загрузите её командой: ollama pull {run['model']}"))
            return
        # Паспорт окружения сохраняется при каждом продолжении, без зависимости от браузера.
        from app import __version__
        from app.journal import environment
        from app.metrics import gpu_stats
        from app.telemetry import host_snapshot
        selected_model = next((m for m in model_list if name_of(m.get('name', '')) == name_of(run['model'])), {})
        # видеокарта, память и процессор этого компьютера – только когда модель на нём (профиль local, ADR-0102 п. 9)
        local_host = host_metrics_of(execution)
        host = host_snapshot(settings.data_dir / 'telemetry' / 'host.json') if local_host else {'status': 'remote'}
        try:
            gpu = gpu_stats() if local_host else None
        except Exception:
            gpu = None  # Необязательная метрика не останавливает разбор находок.
        hardware = ({'name': gpu.get('name'), 'memory_total_mb': gpu.get('memory_total_mb'),
                     'gpus': [{'name': g.get('name'), 'memory_total_mb': g.get('memory_total_mb')} for g in gpu.get('gpus', [])]} if gpu else None)
        environment(self.db, run_id, {
            'app_version': __version__, 'prompt_version': run['prompt_version'],
            'model': {key: selected_model.get(key) for key in ('name', 'digest', 'size', 'params', 'quant', 'family', 'context_length')},
            # параметры и уровень рассуждения – из снимка исполнителя (ADR-0102), а не из текущих настроек
            'execution_id': execution['id'], 'provider_id': execution.get('provider_id'),
            'options': {**DEFAULT_OPTIONS, **options},
            # по сведениям сервера (семейство и возможности модели); у рассуждающей – предел по остатку окна
            'think': applied_think(think_rule, run['model'], {'details': {'family': selected_model.get('family') or ''},
                                                              'capabilities': selected_model.get('capabilities')}),
            'think_limit': thinking_limit(execution, applied_think(
                think_rule, run['model'], {'details': {'family': selected_model.get('family') or ''},
                                           'capabilities': selected_model.get('capabilities')}))[0],
            'gpu': hardware, 'host_memory_total': (host.get('memory') or {}).get('total_bytes') if host.get('status') == 'fresh' else None,
            'host_status': host.get('status'),
            'code_revisions': self.db.revisions(project['id']),
        })
        slow_state = self._slow_state(run, execution)  # ориентир: ответы прогона и прошлых прогонов того же исполнителя

        def waiting_cancelled() -> bool:  # ожидание права на генерацию прерывают остановка, «Пауза» и «Стоп»
            with self._lock:
                return halt.is_set() or run_id in self._controls

        while True:
            if self._apply_control(run_id):
                return
            if halt.is_set():
                self._finish(run_id, "paused", "Приложение остановлено, прогон на паузе.")
                return
            item = self.db.next_pending_item(run_id)
            if item is None:
                self._finish(run_id, "done")
                return
            # право на генерацию – на всю находку (ADR-0099): вопрос к модели в это время получает отказ, а начатый
            # вопрос находка дожидается
            if not gate.acquire("triage", waiting_cancelled):
                if self._apply_control(run_id):
                    return
                if halt.is_set():
                    self._finish(run_id, "paused", "Приложение остановлено, прогон на паузе.")
                    return
                continue  # команду успели отменить («Продолжить» после «Пауза») – ждать права снова
            refused, busy_note = "", DB_BUSY_PAUSE
            try:
                problem = self._process_item(run, client, item, settings, execution)
            except BUSY_ERRORS as e:
                if isinstance(e, CommitUnknown):
                    busy_note = DB_UNKNOWN_PAUSE
                    log_failure(log, "результат находки неизвестен: связь с базой оборвалась (прогон %s)", e, run_id)
                else:
                    log_failure(log, "результат находки не записан: база занята (прогон %s)", e, run_id)
                busy = True
            except SendNotAllowed as e:  # профиль выключили во время прогона: запрос не ушёл, находка в очереди
                busy, problem, refused = False, "", pause_text(e)
            else:
                busy = False
            finally:
                gate.release()
            if refused:
                self._set_live(run_id, since=None)
                self._finish(run_id, "paused", refused)
                return
            if busy:  # незавершённую находку «Продолжить» возьмёт снова, завершённую при потерянном ответе – нет
                self._set_live(run_id, since=None)
                self._pause_after_db_failure(run_id, busy_note)
                return
            self._set_live(run_id, since=None)  # время находки уже учтено в длительности прогона
            if problem:  # сервер не отвечает (или 402 у провайдера): находка остаётся в очереди, стоп важнее паузы
                self._finish(run_id, "paused", f"{problem} {pause_note(execution)}")
                return
            drop_note = self._drop_pause.pop(run_id, "")
            if drop_note:  # каскад обрывов у провайдера: находка записана, дальше – пауза, а не новые запросы
                self._drops.pop(run_id, None)
                self._finish(run_id, "paused", drop_note)
                return
            if self._apply_control(run_id):
                return
            if slow_state.reload_pending and not halt.is_set():
                # Выгрузка – между находками: запрос к модели уже закончен, следующий загрузит её заново; выгрузка –
                # тоже обращение к модели и не должна прийтись на ответ на вопрос
                if gate.acquire("triage", waiting_cancelled):
                    try:
                        self._reload_slow_model(run, client, slow_state, halt)
                    finally:
                        gate.release()
            if self._apply_control(run_id):
                return

    def _count_drop(self, run: Mapping[str, Any], dropped: bool) -> None:
        """Учёт обрывов без ответа у внешнего провайдера: находка с обрывом (даже если повтор ответил) продолжает
        серию, находка с ответом её прерывает. Серия DROP_STREAK_PAUSE подряд или больше DROP_SHARE_PAUSE прогона
        (но не меньше DROP_STREAK_PAUSE обрывов) – прогон встанет на паузу после этой находки (повтор не должен
        становиться бесконечным)."""
        run_id = int(run["id"])
        counts = self._drops.setdefault(run_id, {"drops": 0, "streak": 0, "done": 0})
        counts["done"] += 1
        if not dropped:
            counts["streak"] = 0
            return
        counts["drops"] += 1
        counts["streak"] += 1
        share = counts["drops"] > DROP_SHARE_PAUSE * max(1, int(run.get("total") or 0))
        if counts["streak"] >= DROP_STREAK_PAUSE or (counts["drops"] >= DROP_STREAK_PAUSE and share):
            self._drop_pause[run_id] = DROP_PAUSE_NOTE.format(drops=counts["drops"], done=counts["done"],
                                                              streak=counts["streak"])

    @staticmethod
    def _model_entry(client: OllamaClient, model: str) -> dict[str, Any]:
        """Запись /api/tags о модели, которая сейчас лежит на сервере под этим именем: digest весов (ADR-0084) и
        семейство (уровень рассуждения, ADR-0102); сведения недоступны – {}."""
        try:
            return dict(client.model_info(model))
        except LlmError:
            return {}

    @staticmethod
    def _model_digest(client: OllamaClient, model: str, run: dict) -> str:
        """Digest весов модели, которые сейчас лежат в Ollama под этим именем (ADR-0084); сведения недоступны –
        пусто: ключ кэша тогда без digest, отправка всё равно проверит модель перед запросом."""
        try:
            return str(client.model_info(model).get("digest") or "")
        except LlmError:
            return ""

    def _process_item(self, run: dict, client: OllamaClient, item: dict, settings: Settings | None = None,
                      execution: Mapping[str, Any] | None = None) -> str:
        """Одна находка прогона. Возвращает текст ошибки, если Ollama перестала отвечать, иначе "".
        settings – действующие настройки прогона (папки клонов); execution – снимок исполнителя (ADR-0102): параметры
        генерации, правило уровня рассуждения и режим схемы ответа. SendNotAllowed (профиль выключен перед
        отправкой) поднимается выше: прогон встаёт на паузу."""
        settings = settings or self.settings
        if execution is None:
            execution = self.db.get_execution(run.get("execution_id"))
        if execution is None:
            raise SendNotAllowed("У прогона нет снимка исполнителя: запрос к модели не отправлен.")
        run_id, item_id, hub_id = int(run["id"]), int(item["id"]), str(item["hub_id"])
        project_id = int(run["project_id"])
        started = time.monotonic()
        # Находка, папка проекта и папка клона – одним снимком на каждую находку: их могли поменять во время
        # прогона. Результат привязывается, только если снимок к моменту сохранения не устарел (save_case).
        source = self.db.case_input(project_id, hub_id)
        if source is None or source.get("missing"):
            self.db.finish_item(run_id, item_id, "skipped", error="Находки нет в текущей выгрузке.")
            return ""
        f = Finding.from_dict(source["data"])
        self._set_live(run_id, hub_id=hub_id, finding_id=source["finding_id"], phase="context", since=time.time(),
                       request_started_at=None,last_model_event_at=None,attempt=None)
        model = str(run["model"])
        options, _, think_rule = snapshot_options(execution)
        schema_mode = str(execution.get("schema_mode") or settings.model_json_schema)
        try:
            repo_dir, why = repo_dir_for(settings, {"repos_dir": source["repos_dir"]}, source_codebases(source, f), f)
            max_chars = CONTEXT_CHARS
            # Клона нет (или в нём нет файла находки), а срез с кодом сохранён – модель разбирает его (ADR-0072):
            # срез из одной строки выгрузки не должен затереть код, который уже в базе
            stored = self.db.get_case(project_id, hub_id)
            snapshot = snapshot_code(settings, source, stored)
            if snapshot is not None:
                ctx = snapshot[0]
                max_chars = int((stored or {}).get("context", {}).get("max_chars") or CONTEXT_CHARS)
            else:
                ctx = build_context(repo_dir, f, max_chars=max_chars, mask_key=self._mask_key, no_repo_note=why)
        except BUSY_ERRORS:
            raise
        except Exception as e:
            eid = log_failure(log, "контекст находки не собран (прогон %s)", e, run_id)
            self.db.finish_item(run_id, item_id, "error", error=failure_text("Не удалось собрать контекст", e, eid))
            return ""
        if snapshot is None and degrades(stored, ctx):
            # Полноценный срез в базе не заменяется строкой выгрузки (ADR-0072): ни срезом, ни кэшем, ни ответом
            self._keep_slice(settings, source, stored, project_id, hub_id)
            self.db.finish_item(run_id, item_id, "skipped", error=CLONE_GONE_NOTE)
            return ""

        def store(chash: str, verdict_id: int | None, from_saved: bool = False, **measures: Any) -> bool | None:
            """Срез и привязка к вердикту; сбой записи – ошибка этой находки, а не прогона (None). max_chars –
            размер среза: карточка соберёт текущий код так же и сравнит с тем, что видела модель."""
            try:
                return retry_busy(lambda: self.db.save_case(project_id, hub_id, chash,
                                                            {**case_context(f, ctx), "max_chars": max_chars},
                                                            verdict_id, source, no_downgrade=True,
                                                            from_snapshot=snapshot is not None or from_saved))
            except BUSY_ERRORS:
                raise
            except Exception as e:
                eid = log_failure(log, "срез находки не сохранён (прогон %s)", e, run_id)
                self.db.finish_item(run_id, item_id, "error", case_hash=chash,
                                    error=failure_text("Не удалось сохранить срез", e, eid), **measures)
                return None

        for attempt in range(FIT_ATTEMPTS + 1):
            chash = case_hash(f, ctx)
            if not ctx.lines:
                linked = store(chash, None)
                if linked is not None:
                    self.db.finish_item(run_id, item_id, "skipped", case_hash=chash,
                                        error=f"Нет кода для разбора: {ctx.note or ctx.status}." if linked
                                        else CHANGED_NOTE)
                return ""
            current = (stored or {}).get("verdict") or {}
            if (not run["fresh"] and stored and stored.get("verdict_id") and stored.get("case_hash") == chash
                    and current.get("prompt_version") == PROMPT_VERSION):
                # У находки уже есть вердикт по этому же коду (в том числе «второе мнение» другой модели): обычный
                # прогон его не заменяет ответом из кэша – иначе решение по нему потеряло бы «Проверено». Решение
                # принято по другому коду (код вернулся к срезу модели, бэклог 114) – отметка снимается; только когда
                # срез построен по клону: подставленный сохранённый срез (клона нет) не доказывает смену кода (ADR-0072)
                if snapshot is None:
                    retry_busy(lambda h=chash, n=max_chars: self.db.reopen_for_decision_code(project_id, hub_id, h, n,
                                                                                             source))
                self.db.finish_item(run_id, item_id, "cached", case_hash=chash, verdict_id=stored["verdict_id"],
                                    seconds=time.monotonic() - started)
                return ""
            try:
                # mask_key: строка срабатывания из выгрузки попадает в промпт только маскированной
                messages = self._masked(build_sast_messages(f, ctx, mask_key=self._mask_key))
            except Exception as e:
                eid = log_failure(log, "промпт не собран (прогон %s)", e, run_id)
                # срез всё равно сохраняется: если код изменился, прежний вердикт к нему уже не относится
                if store(chash, None) is not None:
                    self.db.finish_item(run_id, item_id, "error", case_hash=chash,
                                        error=failure_text("Не удалось собрать промпт", e, eid))
                return ""
            # Кэш по запросу целиком (ADR-0027, ADR-0084): сообщения, параметры генерации, режим схемы и digest
            # весов модели, который сейчас лежит в Ollama под этим именем. Ответ на другой запрос или от других
            # весов не подставляется; в прогоне «заново» – только ответ на этот же запрос, полученный в нём же.
            # удалённый API отпечатка весов и сведений о рассуждении не отдаёт: запись модели не запрашивается – иначе
            # перед каждой находкой уходил лишний GET /models провайдеру; кэш по запросу у
            # внешнего провайдера и так не читается (нет digest), рассуждение gpt-oss определяется по имени
            remote = str((execution or {}).get("kind") or "ollama") in REMOTE_KINDS
            entry = {} if remote else self._model_entry(client, model)
            digest = str(entry.get("digest") or "")
            # уровень рассуждения – по модели, которая сейчас лежит на сервере под этим именем (ADR-0102): одно и то же
            # значение уходит в ключ кэша и в тело запроса
            think = applied_think(think_rule, model, entry or None)
            # на каждую отправку – то же значение (по нему предел, срок и ключ); изменилось – отказ без запроса
            think_per_send = planned_think(think_rule, model, think)
            # рассуждающий запрос (think true) – свой срок и предел ответа: остаток окна после промпта, не больше
            # предела рассуждения (срез подбирается под обычный предел – код у модели рассуждение не отнимает)
            think_limit, call_timeout = thinking_limit(execution, think)
            sent_options = fit_thinking(options, think_limit, messages) if think_limit else options
            rkey = request_key(model, messages, sent_options, think, PROMPT_VERSION, model_digest=digest,
                               json_schema=schema_mode, provider=provider_key(execution))
            # веса не удалось определить – кэш по запросу не читается и не пополняется: неизвестные веса не
            # считаются совпавшими; у внешнего провайдера отпечатка весов нет никогда – кэша по ключу нет (П4),
            # каждый разбор – новый запрос
            external = str(execution.get("trust") or "") == "external"
            if not digest or external:
                cached = None
            elif run["fresh"]:
                cached = self.db.verdict_by_request_in_run(run_id, rkey)
            else:
                cached = self.db.find_verdict_by_request(rkey)
            if cached is not None:
                seconds = time.monotonic() - started
                linked = store(chash, cached["id"], seconds=seconds)
                if linked is not None:
                    self.db.finish_item(run_id, item_id, "cached" if linked else "skipped", case_hash=chash,
                                        verdict_id=cached["id"] if linked else None,
                                        error="" if linked else CHANGED_NOTE, seconds=seconds)
                return ""
            # окно и предел ответа – того сервера, куда уйдёт запрос (у удалённого API – из профиля за вычетом схемы
            # ответа, которую клиент добавит к сообщениям; KIMI-01)
            fit = fit_options(execution, options, json_overhead(client, VERDICT_FIELDS, VERDICT_REQUIRED,
                                                                VERDICT_ENUMS, VERDICT_TYPES))
            size = prompt_size(execution)  # оценка длины – та же, что у клиента перед отправкой
            if attempt == FIT_ATTEMPTS or prompt_fits(messages, fit, size):
                break
            # Плотный код (знаки вне ASCII и кириллицы) не помещается в окно контекста: срез сокращается на нужную
            # долю с запасом, иначе Ollama обрезала бы начало промпта вместе с системным сообщением. Совсем
            # маленький срез не нужен: такой промпт chat_json отклонит с понятной ошибкой.
            excess = (size or prompt_tokens)(messages) - (prompt_budget(fit) or 0)
            code = "\n".join(ctx.lines)
            keep = max(0.0, 1.0 - excess / max(1, estimate_tokens(code))) * 0.9
            smaller = int((len(code) + 10 * len(ctx.lines)) * keep)
            if snapshot is not None:
                break  # срез из базы без клона не пересобрать: если не помещается, ответит проверка длины промпта
            if smaller < MIN_CONTEXT_CHARS:
                if max_chars <= MIN_CONTEXT_CHARS:
                    break  # max_chars остаётся размером того среза, который уйдёт модели
                smaller = MIN_CONTEXT_CHARS  # меньше не сокращаем, но и наименьший срез пробуем
            max_chars = smaller
            try:
                ctx = build_context(repo_dir, f, max_chars=max_chars, mask_key=self._mask_key, no_repo_note=why)
            except Exception as e:
                eid = log_failure(log, "контекст находки не собран (прогон %s)", e, run_id)
                self.db.finish_item(run_id, item_id, "error",
                                    error=failure_text("Не удалось собрать контекст", e, eid))
                return ""
            if degrades(stored, ctx):  # файл пропал, пока срез сокращался
                self._keep_slice(settings, source, stored, project_id, hub_id)
                self.db.finish_item(run_id, item_id, "skipped", error=CLONE_GONE_NOTE)
                return ""
        # Новый срез – до обращения к модели: если код изменился, прежний вердикт к нему уже не относится
        # (save_case отвязывает его и снимает отметку «проверено»), даже если модель ответит ошибкой.
        linked = store(chash, None)
        if linked is None:
            return ""
        if not linked:
            self.db.finish_item(run_id, item_id, "skipped", case_hash=chash, error=CHANGED_NOTE)
            return ""
        self._set_live(run_id, phase="model")
        last_progress = [0.0]
        def progress(event):
            now=time.monotonic()
            if event['event']=='fragment':
                if now-last_progress[0]>=1:
                    self._set_live(run_id,phase='generating',last_model_event_at=time.time())
                    last_progress[0]=now
            elif event['event']=='request_started':
                last_progress[0]=0
                self._set_live(run_id,phase='waiting',request_started_at=time.time(),last_model_event_at=None,attempt=event['attempt'])
            elif event['event']=='response_done':self._set_live(run_id,phase='validating',last_model_event_at=time.time())
        if external:
            # К11: метка отправки – до сетевого вызова; перезапуск с меткой – «результат неизвестен», повтора нет
            self.db.mark_item_sending(run_id, item_id)
        try:
            # validate – проверка ответа по существу (пустой fix у истинной, комментарий для Hub без текста):
            # замечания ведут к повтору, как ответ не по формату. Контекст журнала обмена с моделью: обращения
            # внутри вызова (в том числе /api/tags перед отправкой кода) помечаются прогоном и находкой.
            with model_traffic.context(purpose="triage", run_id=run_id, hub_id=hub_id, project_id=project_id):
                client.timeout = call_timeout  # срок одного обращения: у рассуждающего запроса – свой
                drop_error: LlmError | None = None
                while True:
                    try:
                        obj, stats = client.chat_json(model, messages, VERDICT_FIELDS, VERDICT_REQUIRED, VERDICT_ENUMS,
                                                      options=sent_options, think=think_per_send, types=VERDICT_TYPES,
                                                      validate=check_verdict_answer, progress=progress,
                                                      json_schema=schema_mode)
                        break
                    except (SendNotAllowed, PromptOverflowError) as e:
                        if drop_error is not None:
                            # первый запрос оборвался (исход неизвестен), а повтор не ушёл: профиль выключен, отметка
                            # снята, окно – находка остаётся «результат неизвестен», а не возвращается в очередь,
                            # иначе «Продолжить» отправил бы её снова (ревью Codex, круг 18, блокирующее)
                            raise _after_drop(drop_error, e) from e
                        raise
                    except LlmError as e:
                        # обрыв без ответа у внешнего провайдера с отметкой профиля «Повторять после обрыва» – один
                        # повтор на находку (ADR-0107); второй обрыв – «результат
                        # неизвестен»; метка отправки стоит до конца: перезапуск между попытками – тоже «неизвестен»
                        if (drop_error is None and external and outcome_unknown(e) and not getattr(e, "reason", None)
                                and drop_retry_allowed(execution)):
                            drop_error = e
                            log.info("обрыв без ответа – автоматический повтор (прогон %s, находка %s)", run_id, hub_id)
                            continue
                        if drop_error is not None:
                            if not model_answered(e) and not outcome_unknown(e):
                                # повтор без ответа модели (402, ошибка сервера, сбой до отправки, кончились срок или
                                # предел отправок – запрос не ушёл) – исход первого запроса по-прежнему неизвестен
                                raise _after_drop(drop_error, e) from e
                            e.drop_retries = 1  # type: ignore[attr-defined]
                            e.stats = _merged_stats(drop_error.stats, e.stats)
                        raise
                if drop_error is not None:
                    # расход оборванной попытки – вместе с ответом повтора (ревью Codex, круг 18)
                    stats = _merged_stats(drop_error.stats, stats)
                    stats.drop_retries = 1
                if external:
                    self._count_drop(run, drop_error is not None)
        except SendNotAllowed:
            # профиль выключен или отметка проекта снята перед отправкой (в том числе перед повтором – исход прежней
            # попытки известен): запрос не ушёл – метка снимается, находка остаётся в очереди, прогон – на паузу
            if external:
                self.db.mark_item_sending(run_id, item_id, sending=False)
            raise
        except PromptOverflowError as e:
            # Оценка длины промпта – эвристика с запасом (llm.estimate_tokens, llm.PROMPT_SAFETY_SHARE). Если сама
            # Ollama насчитала в промпте любой из попыток больше, чем помещается в окно вместе с ответом, начало
            # промпта могло быть обрезано вместе с системным сообщением: такому ответу не доверяем (chat_json).
            measures = self._measures(e.stats, time.monotonic() - started)
            # у удалённого API это отказ его клиента до отправки по окну профиля (запрос не ушёл, не оплачен): совет
            # про MODEL_NUM_CTX Ollama здесь ложный – текст клиента и совет про профиль
            remote_kind = str((execution or {}).get("kind") or "ollama") in REMOTE_KINDS
            text = f"{e} {REMOTE_WINDOW_NOTE}" if remote_kind and not getattr(e, "sent", False) else PROMPT_DOUBT_NOTE
            self.db.finish_item(run_id, item_id, "error", case_hash=chash, error=text, **measures)
            return ""
        except LlmError as e:
            partial = _stats_partial(e)
            if external and outcome_unknown(e):
                # К11: байты ушли, ответа нет (или он от посредника) – «результат неизвестен»: ошибка этой находки,
                # больше не отправляется (автоповтор после обрыва, если включён в профиле, уже был); метка снимается
                # вместе с записью результата
                measures = self._measures(e.stats, time.monotonic() - started)
                retry_error = str(getattr(e, "retry_error", "") or "")
                again = (f" Автоматический повтор после обрыва не получил ответа модели: {retry_error}" if retry_error
                         else " Автоматический повтор после обрыва тоже остался без ответа."
                         if getattr(e, "drop_retries", 0) else "")
                self.db.finish_item(run_id, item_id, "error", case_hash=chash,
                                    error=f"{UNKNOWN_RESULT_NOTE} {e}{again}", stats_partial=partial, **measures)
                self._count_drop(run, True)
                # повтор после обрыва получил 402: следующие находки тоже не примут – пауза по оплате, как без обрыва
                return PAYMENT_NOTE if getattr(e, "retry_status", None) == 402 else ""
            if external and getattr(e, "reason", None):
                # ответ получен: серия обрывов прервана, если обрыва не было; обрыв, после которого повтор получил
                # известный отказ, – тоже обрыв (ревью Codex, круг 18)
                self._count_drop(run, bool(getattr(e, "drop_retries", 0)))
            if getattr(e, "reason", None):
                # известный окончательный исход (ответ получен и разобран, ADR-0106): находка – ошибка сразу, с
                # расходом ответа; служебный опрос сервера не нужен – его сбой не оставит находку в очереди и не
                # отправит её заново после «Продолжить» (ревью круг 15, находка 1); метка отправки снимается записью
                measures = self._measures(e.stats, time.monotonic() - started)
                self.db.finish_item(run_id, item_id, "error", case_hash=chash,
                                    error=str(e) + (PARTIAL_NOTE if partial else ""), stats_partial=partial, **measures)
                return ""
            if external and getattr(e, "status", None) == 402:
                # нужна оплата: запрос провайдер не принял – метка снимается, находка остаётся в очереди, прогон –
                # на паузу с причиной
                self.db.mark_item_sending(run_id, item_id, sending=False)
                return PAYMENT_NOTE
            if not self._server_alive(client):
                if external:  # ответ сервера был (или запрос не ушёл) – исход известен, метка снимается
                    self.db.mark_item_sending(run_id, item_id, sending=False)
                return str(e)
            # Модель могла сгенерировать ответ не по формату: её токены и время входят в среднюю скорость
            # прогона; после сбоя связи замеры прерванной попытки неизвестны – находка помечается
            measures = self._measures(e.stats, time.monotonic() - started)
            self.db.finish_item(run_id, item_id, "error", case_hash=chash,
                                error=str(e) + (PARTIAL_NOTE if partial else ""), stats_partial=partial, **measures)
            return ""
        eta_sample = self._observe_speed(run, stats)
        self._set_live(run_id, phase='saving')
        seconds = time.monotonic() - started
        measures = self._measures(stats, seconds)
        try:
            # срез, который видела модель (в том же представлении, что в промпте): номера строк-доказательств вне
            # него отбрасываются, при сверке differs уверенность ограничена (ADR-0080)
            verdict = parse_verdict(obj, export_fragment_view(f, ctx))
        except Exception as e:  # неожиданный сбой разбора ответа – ошибка этой находки, прогон идёт дальше
            eid = log_failure(log, "ответ модели не разобран (прогон %s)", e, run_id)
            self.db.finish_item(run_id, item_id, "error", case_hash=chash,
                                error=failure_text("Ответ модели не разобран", e, eid), **measures)
            return ""
        # последняя проверка перед сохранением – после всей нормализации вердикта (сервер с ключом мог вернуть его)
        if model_traffic.shows_secret([verdict.to_dict(), stats.to_dict()], getattr(client, "secrets", ())):
            self.db.finish_item(run_id, item_id, "error", case_hash=chash, error=model_traffic.KEY_IN_ANSWER,
                                **measures)
            return ""
        try:
            # веса под этим именем сменились, пока модель отвечала, – ответ не кладётся под ключ прежних весов;
            # ответ на повтор (замечание о формате, другой seed) – ответ на другой запрос, под ключ первого не кладётся;
            # сервер отверг схему ответа – запрос ушёл без неё, под ключ со схемой тоже не кладётся
            dropped = getattr(client, "schema_dropped", None)
            saved_key = rkey if (digest and stats.attempts == 1 and not (callable(dropped) and dropped())
                                 and self._model_digest(client, model, run) == digest) else ""
            reserved = retry_busy(self.db.reserve_verdict_id)
            verdict_id = retry_busy(lambda: self.db.save_verdict(chash, model, PROMPT_VERSION, verdict.to_dict(),
                                                                 stats.to_dict(), request_key=saved_key,
                                                                 execution_id=int(execution["id"]),
                                                                 verdict_id=reserved))
        except BUSY_ERRORS:
            raise  # занятая база – пауза прогона, находка остаётся в очереди (Э2)
        except Exception as e:  # сбой записи – ошибка этой находки, а не всего прогона
            eid = log_failure(log, "вердикт не сохранён (прогон %s)", e, run_id)
            self.db.finish_item(run_id, item_id, "error", case_hash=chash,
                                error=failure_text("Не удалось сохранить вердикт", e, eid), **measures)
            return ""
        # Пока модель отвечала, код в клоне могли поменять (правки в рабочей копии, git pull): ответ сохранён в кэше
        # для того кода, который она видела, но к находке не привязывается – иначе он выглядел бы действующим.
        # клон удалили, пока модель отвечала: поздняя сверка берёт сохранённый срез – и сохранение знает об этом,
        # подставленный срез сменой кода не считается (ADR-0072, ревью Codex ветки долга, круг 4)
        late_saved = {"used": False}

        def late_snapshot():
            got = snapshot_code(settings, source, self.db.get_case(project_id, hub_id))
            late_saved["used"] = got is not None
            return got

        if snapshot is None and self._code_changed(f, repo_dir, max_chars, chash, late_snapshot):
            self.db.finish_item(run_id, item_id, "skipped", case_hash=chash, error=CODE_CHANGED_NOTE, **measures)
            return ""
        linked = store(chash, verdict_id, from_saved=late_saved["used"], **measures)
        if linked is None:
            return ""
        if linked:
            # после обрыва замеры неполные: что модель успела сгенерировать в оборванной попытке, неизвестно; время
            # находки с повтором – не образец для оценки оставшегося
            retry_busy(lambda: self.db.finish_item(run_id, item_id, "done", case_hash=chash, verdict_id=verdict_id,
                                                   eta_sample=eta_sample and not stats.drop_retries,
                                                   stats_partial=bool(stats.drop_retries), **measures))
        else:
            retry_busy(lambda: self.db.finish_item(run_id, item_id, "skipped", case_hash=chash, error=CHANGED_NOTE,
                                                   **measures))
        return ""

    # ---------------------------------------------------------------- медленный режим модели

    @staticmethod
    def _refused(guard: Callable[[], None]) -> str:
        """Текст паузы, если допуск профиля снимка уже не действует ("" – действует): сбой перед первой отправкой
        сначала сверяется с допуском (ADR-0102), чтобы выключенный профиль давал паузу, а не ошибку."""
        try:
            guard()
        except SendNotAllowed as e:
            return pause_text(e)
        return ""

    def _slow_state(self, run: dict, execution: Mapping[str, Any] | None = None) -> _SlowState:
        """Состояние замедления прогона: ответы текущего прогона из базы, медиана прошлых прогонов той же конфигурации
        исполнителя (протокол, адрес, модель – ADR-0102, П24) и записанные в журнал перезагрузки. Читается один раз
        за прогон; продолжение после паузы берёт готовое. Выгружать модель можно, только если снимок это разрешает."""
        run_id = int(run["id"])
        state = self._slow.get(run_id)
        if state is not None:
            return state
        state = _SlowState()
        if execution is None:
            execution = self.db.get_execution(run.get("execution_id"))
        state.unload_allowed = unload_allowed_of(execution)
        executor = (str(execution["kind"]), str(execution["base_url"])) if execution else None
        try:
            state.samples = self.db.run_tps_samples(run_id, SLOW_BASELINE_WINDOW)
            history = self.db.model_tps_samples(str(run["model"]), exclude_run_id=run_id, limit=SLOW_HISTORY_WINDOW,
                                                executor=executor)
            state.history_median = _median(history) if len(history) >= SLOW_BASELINE_MIN else None
            state.history_typical = _median(history)
            state.history_fast = any(value > SLOW_TPS_KNOWN_FAST for value in history)
            from app import journal
            saved = journal.slow_model_state(self.db, run_id)
            state.reloads = int(saved.get("reloads") or 0)
            state.text = str(saved.get("text") or "")
            state.warning = bool(saved.get("warning"))
        except Exception as e:
            log_failure(log, "состояние медленного режима не прочитано (прогон %s)", e, run_id)
        self._slow[run_id] = state
        return state

    def _observe_speed(self, run: dict, stats: Any) -> bool:
        """Учесть скорость законченного ответа. True – ответ годится для оценки оставшегося времени, False –
        медленный ответ (до перезагрузки) или первый ответ после загрузки модели. При медленном режиме
        помечает перезагрузку (её выполнит _reload_slow_model между находками) или записывает предупреждение.
        """
        tps = float(getattr(stats, "eval_tps", 0) or 0)
        if tps <= 0:
            return True
        state = self._slow_state(run)
        previous = state.samples[-SLOW_BASELINE_WINDOW:]
        reference = _median(previous) if len(previous) >= SLOW_BASELINE_MIN else state.history_median
        baseline = reference if reference is not None else (state.history_typical or tps)
        first_after_reload = state.after_reload
        state.after_reload = False
        if first_after_reload:  # загрузка модели после перезагрузки: ответ не показатель режима
            state.streak = 0
            return False
        if reference is not None and reference > 0:
            slow = tps < reference * SLOW_TPS_SHARE
        elif state.history_fast:
            # Ориентира ещё нет: у моделей, которые раньше давали больше SLOW_TPS_KNOWN_FAST, два ответа
            # подряд ниже абсолютного порога уже говорят о медленном режиме.
            slow = tps < SLOW_TPS_ABSOLUTE
        else:
            slow = False
        if not slow:
            # Ориентир – медиана успешных ответов обычной скорости: медленные ответы её не сдвигают вниз,
            # иначе после первой же перезагрузки стало бы «нормально» медленно.
            state.samples.append(tps)
            state.samples = state.samples[-SLOW_BASELINE_WINDOW:]
            state.streak = 0
            return True
        state.streak += 1
        if state.streak < SLOW_STREAK:
            return False  # медленный, но серия ещё не набрана: в оценку времени всё равно не берём
        state.streak = 0
        if state.reloads < SLOW_MAX_RELOADS and state.unload_allowed:
            state.reload_pending = True
            state.pending_tps = tps
            state.pending_baseline = baseline
        elif not state.warning:
            state.warning = True
            state.text = slow_model_status_text(tps, baseline, reloaded=False)
            if not state.unload_allowed:  # общий сервер: выгружать модель профиль не разрешает (ADR-0102 п. 9)
                state.text += " Выгрузка модели на этом сервере не разрешена профилем."
            self._record_slow_event(run, "warning", tps, baseline, state)
            log.info("прогон %s: медленный режим модели не исправлен двумя перезагрузками (%s ток/с при обычных %s)",
                     int(run["id"]), _tps_number(tps), _tps_number(baseline))
        return False

    def _reload_slow_model(self, run: dict, client: OllamaClient, state: _SlowState,
                           halt: threading.Event) -> None:
        """Выгрузить модель (keep_alive 0) и дождаться, что /api/ps её больше не показывает. Следующий запрос
        загрузит модель заново. Сбой выгрузки не останавливает прогон: предупреждение остаётся оператору."""
        run_id, project_id, model = int(run["id"]), int(run["project_id"]), str(run["model"])

        def interrupted() -> bool:
            with self._lock:
                return halt.is_set() or run_id in self._controls

        if not state.reload_pending or state.reloads >= SLOW_MAX_RELOADS or interrupted():
            return
        state.reload_pending = False
        tps, baseline = state.pending_tps, state.pending_baseline
        state.reloads += 1  # ошибка и прерванное ожидание тоже расходуют попытку
        try:
            with model_traffic.context(purpose="reload", run_id=run_id, project_id=project_id):
                client.unload_model(model)
                self._wait_unloaded(client, model, interrupted)
        except LlmError as e:
            state.warning = True
            state.text = f"Модель работала медленно – перезагрузить модель не удалось: {e}"
            self._record_slow_event(run, "warning", tps, baseline, state)
            log_failure(log, "модель не выгружена для перезагрузки (прогон %s)", e, run_id)
            return
        state.after_reload = True
        state.streak = 0
        state.warning = False
        state.text = slow_model_status_text(tps, baseline, reloaded=True)
        self._record_slow_event(run, "reload", tps, baseline, state)
        log.info("прогон %s: медленный режим модели (%s ток/с при обычных %s), модель выгружена",
                 run_id, _tps_number(tps), _tps_number(baseline))

    def _record_slow_event(self, run: dict, action: str, tps: float, baseline: float, state: _SlowState) -> None:
        """Событие медленного режима – в журнал прогона (страница «Журнал»). Сбой записи не мешает разбору."""
        try:
            from app import journal
            journal.slow_model_event(self.db, int(run["id"]), action=action, tps=tps, baseline=baseline,
                                     text=state.text, reloads=state.reloads)
        except Exception as e:
            log_failure(log, "событие медленного режима не записано (прогон %s)", e, int(run["id"]))

    @staticmethod
    def _wait_unloaded(client: OllamaClient, model: str, interrupted: Callable[[], bool]) -> None:
        """Подтвердить выгрузку через /api/ps. Ошибка, истёкший срок и команда управления – не успех.
        Команды проверяются между опросами и сразу после ответа сервера."""
        wanted = norm_model_name(model)
        deadline = time.monotonic() + SLOW_RELOAD_WAIT_S
        while True:
            if interrupted():
                raise LlmError("ожидание выгрузки прервано командой управления.")
            if time.monotonic() >= deadline:
                raise LlmError(f"Ollama не подтвердила выгрузку за {SLOW_RELOAD_WAIT_S:g} с.")
            loaded = {norm_model_name(str(entry.get("name") or "")) for entry in client.ps()}
            if interrupted():
                raise LlmError("ожидание выгрузки прервано командой управления.")
            if time.monotonic() >= deadline:
                raise LlmError(f"Ollama не подтвердила выгрузку за {SLOW_RELOAD_WAIT_S:g} с.")
            if wanted not in loaded:
                return
            time.sleep(min(SLOW_RELOAD_POLL_S, max(0.0, deadline - time.monotonic())))

    @staticmethod
    def _measures(stats: Any, seconds: float) -> dict[str, Any]:
        """Замеры ответа модели для finish_item; stats – LlmStats или None (сбой до первого ответа)."""
        measures: dict[str, Any] = {"seconds": seconds, "model_call": True}
        if stats is None:
            return measures
        measures.update(eval_tps=stats.eval_tps or None, output_tokens=stats.output_tokens,
                        model_seconds=max(0.0, seconds - stats.load_s),
                        eval_seconds=stats.output_tokens / stats.eval_tps if stats.eval_tps > 0 else 0.0)
        return measures

    def _code_changed(self, f: Finding, repo_dir: Path | None, max_chars: int, chash: str,
                      snapshot: Any = None) -> bool:
        """Код находки сейчас другой, чем в срезе с отпечатком chash. Не удалось прочитать – считается изменившимся:
        ответ про код, которого не видно, привязывать нельзя. snapshot() – срез из базы, если клон удалили, пока
        модель отвечала (snapshot_code): тогда сравнивается он, а не строка выгрузки (ADR-0072)."""
        try:
            late = snapshot() if snapshot is not None else None
            if late is not None:
                return late[1] != chash
            return case_hash(f, build_context(repo_dir, f, max_chars=max_chars, mask_key=self._mask_key)) != chash
        except BUSY_ERRORS:
            raise  # занятая база – пауза прогона, а не «код изменился» (Э2)
        except Exception as e:
            log_failure(log, "срез находки не перечитан после ответа модели", e)
            return True

    def _refresh_contexts(self, run: dict, halt: threading.Event) -> None:
        """Модель недоступна (Ollama не отвечает, модели нет, адрес не из разрешённых), а срезы находок прогона
        всё равно сверяются с текущим кодом: если код изменился (правки без смены ревизии, папка без .git),
        прежний вердикт отвязывается и отметка «проверено» снимается (save_case) – решение по прежнему коду
        не остаётся «проверенным» из-за того, что модель не ответила. Очередь прогона не меняется."""
        run_id, project_id = int(run["id"]), int(run["project_id"])
        for hub_id in self.db.pending_hub_ids(run_id):
            if halt.is_set():
                return
            try:
                stored = self.db.get_case(project_id, hub_id)
                source = self.db.case_input(project_id, hub_id)
                if stored is None or source is None:
                    continue  # среза нет – отвязывать нечего
                max_chars = int(stored["context"].get("max_chars") or CONTEXT_CHARS)
                f, ctx, chash, saved = current_code_origin(self.settings, source, self._mask_key, max_chars,
                                                           case=stored)
                if chash == stored["case_hash"]:
                    # срез тот же, а решение принято по другому коду (бэклог 114) – отметка снимается; если клона нет
                    # и текущий код – сам сохранённый срез, сверять нечего (ADR-0072). Признак – у того же чтения:
                    # файл мог вернуться в клон после него (ревью Codex ветки долга, круг 5)
                    if not saved:
                        self.db.reopen_for_decision_code(project_id, hub_id, chash, max_chars, source)
                    continue
                if degrades(stored, ctx):  # полноценный срез не ухудшается
                    self._keep_slice(self.settings, source, stored, project_id, hub_id)
                    continue
                self.db.save_case(project_id, hub_id, chash, {**case_context(f, ctx), "max_chars": max_chars},
                                  None, source, no_downgrade=True)
            except Exception as e:
                log_failure(log, "срез находки не сверен (прогон %s)", e, run_id)

    def _keep_slice(self, settings: Settings, source: dict, stored: dict | None, project_id: int, hub_id: str) -> None:
        """Новый срез хуже сохранённого и не записывается (degrades). Если файл находки по-прежнему в клоне (его
        укоротили, путь стал неоднозначным), код под решением уже другой: отметка «проверено» снимается, срез
        остаётся. Если файл пропал (клон удаляют), код тот же – отметка остаётся."""
        if snapshot_code(settings, source, stored) is None:
            self.db.reopen_for_code_change(project_id, hub_id, source)

    def _masked(self, messages: list[dict]) -> list[dict]:
        """Последняя сетка перед отправкой: маскирование всего текста сообщений с данными находки (путь файла,
        правило, заметки). Повторное маскирование уже замаскированного текста его не меняет.

        env_style=False – как у среза кода в build_context: строка кода «КЛЮЧ=значение» не скрывается целиком,
        и модель видит тот же код, что человек в карточке. Поля находки prompts.py уже маскирует как текст."""
        return [{**m, "content": mask_text(str(m.get("content") or ""), self._mask_key, env_style=False)[0]}
                if m.get("role") == "user" else m for m in messages]

    @staticmethod
    def _server_alive(client: OllamaClient) -> bool:
        try:
            client.version()
        except LlmError:
            return False
        return True

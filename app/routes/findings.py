"""Раздел «Находки»: список с фильтрами и готовыми отборами, карточка находки, решение человека, текст для Hub,
отметки «скопировано», «Проверено» и «Внесено в Hub», вопрос к модели («Спросить модель») и повторный разбор
находки («Пересмотреть вердикт»).

Шаблоны – templates/findings/: list.html (список), card.html (карточка). Поведение карточки в браузере –
static/app.js; без скрипта каждое действие работает обычной формой с переходом обратно на карточку.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from app import __version__, ask, defect, defect_drafts, hub_defects, hub_onboarding, hub_state, mask_display, worklists
from app.config import VERDICTS
from app.context import (build_context, display_context, export_fragment_scope, export_fragment_shift,
                         export_fragment_view, shift_code_lines, window_code_lines)
from app.db import (DECISIONS, NO_EXPECT, Database, StaleReview, hub_verdict, loads, source_signature, source_version,
                    text_hash)
from app.masking import PLACEHOLDER_RE, is_credential_finding, mask_line, mask_text
from app.models import UNCONFIRMED_EXPORT_CHECKS, CodeContext, Finding, Verdict
from app.hub_import import group_key2 as group_key  # ключ группы второй редакции (ADR-0095)
from app.routes import hub_defect_routes, hub_status_routes
from app.prompts import (DIFFERS_CAP_VERSIONS, DIFFERS_CONFIDENCE_MAX, PROMPT_VERSION, SHORT_EXPLANATION_VERSIONS, hub_text, hub_text_v1, hub_text_v2, invisible_lines,
                         steering_fields, steering_lines)
from app.feeds import FeedStore
from app.executors import executor_label, same_model
from app.routes.common import (COUNT, MAX_NAME, CommentNeedsCheck, client_of, comment_check_text,  # noqa: F401
                               comment_confirm_valid, copy_missing_message, db_of, default_model, entered_check_text,
                               form_int, mask_key_of, models_of, project_or_404, query, redirect, register_messages,
                               profile_for, render, runner_of, settings_of, web_of)
from app.routes.feeds import store_of
from app.triage import (CONTEXT_CHARS, MIN_CONTEXT_CHARS, TriageError, case_hash, current_code, repo_dir_for,
                        snapshot_code, source_codebases)
from app.view import DECISION_LABELS, KIND_LABELS, VERDICT_LABELS, fmt_ts, missing_line_refs, review_json

router = APIRouter()

PAGE_SIZE = 200
# Второе мнение («Пересмотреть вердикт»): проверенные модели из README – раньше прочих по списку
SECOND_OPINION_MODELS = ("gpt-oss:20b", "mistral-small3.2:24b", "qwen2.5-coder:14b")
MAX_COMMENT = 20000  # знаков в комментарии для Hub

# Почему решение не сохранено (StaleReview.reason) – текст для человека
STALE_MESSAGES = {
    "source": "Находка или папка с её кодом изменились, пока карточка была открыта (новая выгрузка или другой "
              "клон). Решение не сохранено: проверьте карточку ещё раз.",
    "verdict": "Вердикт модели изменился, пока карточка была открыта (новый прогон). Решение не сохранено: "
               "проверьте карточку ещё раз.",
    "revision": "Решение по этой находке уже изменили в другой вкладке или окне. Ваше решение не сохранено, чтобы "
                "не затереть более новое: сверьте карточку и сохраните ещё раз.",
    "code": "Код находки в клоне изменился, пока карточка была открыта (правки в рабочей копии или git pull). "
            "Решение не сохранено: посмотрите код ещё раз.",
    "stale_verdict": "Код изменился после разбора – согласиться с прежним ответом нельзя: "
                     "разберите находку заново или выберите «Не согласен»",
    "number": "Номер дефекта изменили в другой вкладке, пока карточка была открыта: номер не перезаписан. "
              "Обновите карточку и проверьте номер.",
}
# Срез кода разбора не совпадает с текущим (изменился код в клоне или построение среза в новой версии): вердикт
# модели – про прежний срез. Это предупреждение, а не запрет: решение человека по текущему коду сохраняется
# с отметкой «Проверено» (ADR-0145; ADR-0147). Текст – для прежних ссылок ?ok=code_changed
CODE_CHANGED_REVIEW = ("Решение сохранено. Срез кода, который разбирала модель, не совпадает с текущим: её вердикт "
                       "относится к прежнему срезу. Чтобы модель посмотрела текущий код, нажмите «Разобрать заново».")
ENTERED_STALE = ("Решение по находке изменили в другой вкладке или окне: отметка «Внесено в Hub» не поставлена. "
                 "Обновите карточку и отметьте ещё раз.")
ENTERED_NO_DECISION = ("Сначала сохраните решение по находке: отметка «Внесено в Hub» – о тексте этого "
                       "решения.")
RISK_NEEDS_REASON = ("«Риск принят» сохраняется только с обоснованием: напишите в комментарии для Hub, почему риск "
                     "принимается и при каком условии решение пересматривается (например, срок или событие).")
NEED_VERDICT = "Выберите итоговый вердикт"
# Текст для Hub – решение человека: предложенный моделью вердикт без выбранного решения не выдаётся (R092-03)
NEED_DECISION = ("Выберите решение: «Ложное срабатывание», «Подтверждаю дефект» или «Отложить». Ответ модели ещё не "
                 "принят – без решения текст для Hub не выдаётся.")
# SAST с 0.9.6 (ADR-0089): два исхода – ложное срабатывание (короткий комментарий) и подтверждённый дефект (полный
# текст); «Отложить» – вернуться позже. «Неясно» и «Риск принят» для SAST не выбираются
SAST_OUTCOMES = ("false_positive", "true_positive")
SAST_TWO_OUTCOMES = ("Для находки SAST два решения: «Ложное срабатывание» – короткий комментарий в Hub, или "
                     "«Подтверждаю дефект» – дефект в Hub. «Отложить» – вернуться к находке позже.")
SAST_NEED_REASON = {"false_positive": "Напишите комментарий для Hub: одной-двумя фразами, почему срабатывание ложное.",
                    "true_positive": "Напишите обоснование дефекта: откуда приходят данные, что за ошибка и чем она "
                                     "опасна."}
SAST_ENTER_ONLY = ("Отметка «Внесено в Hub» – только для решений «Ложное срабатывание» и «Подтверждаю дефект»: "
                   "отложенная находка в Hub не переносится.")
ENTERED_TEXT_MOVED = ("Текст для Hub изменился после того, как вы его скопировали (например, название команды или "
                      "решение): скопируйте текст заново, вставьте его в Hub и отметьте ещё раз.")
ENTERED_RELOAD = "Обновите карточку: отметка «Внесено в Hub» сверяет текст, который вы видите, а страница открыта раньше."
ENTERED_NEEDS_REASON = ("Отметка «Внесено в Hub» не поставлена: у решения нет обоснования. Допишите его, сохраните "
                        "решение и перенесите текст в Hub.")
DEFECT_NEEDS_REASON = ("Дефект не выдан: нет обоснования. Напишите, откуда приходят данные, что за ошибка и чем она "
                       "опасна, и сохраните решение.")
# рекомендация дефекта – пункты оператора словами (ADR-0092): код модели и общий пункт в текст не подставляются
# отказ сервера не знает, что показала карточка, поэтому о кнопке не говорит; подсказка у поля – по факту (need_fix_text)
SAST_NEED_FIX = "Напишите рекомендацию: что исправить и как, по пункту в строке. Без рекомендации дефект не выдаётся."



def _catalog_project(db, project_id: int) -> bool:
    """Проект из каталога учебных примеров: у его находок о лицензиях – учебная политика (examples/catalog)."""
    from app.routes.examples import is_catalog_project
    return is_catalog_project(db, project_id)


def editor_target(settings, repo_dir, ctx, from_db: bool) -> dict | None:
    """{"path": путь файла на компьютере, "url": vscode://file/<путь>:<строка>} – когда срез взят из файла клона;
    в Docker-установке путь – от REPOS_ROOT_HOST. Файла нет, срез из базы или клона нет – None."""
    from urllib.parse import quote

    if ctx is None or from_db or ctx.status != "ok" or not ctx.file or repo_dir is None:
        return None
    try:
        rel = Path(repo_dir).resolve().relative_to(Path(settings.repos_root).resolve()).as_posix()
    except (ValueError, OSError):
        return None
    base = (settings.repos_root_host or str(Path(settings.repos_root).resolve())).replace("\\", "/").rstrip("/")
    path = "/".join(x for x in (base, "" if rel == "." else rel, ctx.file.strip("/")) if x)
    line = ctx.target_line or ctx.start_line or 1
    shown = path.replace("/", "\\") if len(path) > 1 and path[1] == ":" else path
    return {"path": shown, "url": f"vscode://file/{quote(path, safe='/:')}:{int(line)}"}

def steering_of(f: Finding, stored: dict, ctx: CodeContext) -> tuple[list[int], list[str]]:
    """Строки и поля, похожие на указания для модели: сохранённые вместе со срезом при прогоне (с невидимыми знаками –
    и у срезов, сохранённых до этой проверки) или посчитанные по срезу прежней версии."""
    if "steering_lines" in stored:
        lines = [int(n) for n in stored.get("steering_lines") or [] if str(n).isdigit()]
        fields = [str(x) for x in stored.get("steering_fields") or []]
        return sorted(set(lines) | set(invisible_lines(ctx))), fields
    return steering_lines(ctx), steering_fields(f, ctx)


def model_suggestion(f: Finding, case: dict | None) -> dict:
    """Обоснование и пункты рекомендации модели для «Дефекта из выбранных» – по правилам кнопок карточки (ADR-0092):
    только вердикт «Подтверждаю дефект» и без текста, похожего на указания для модели, в коде; поле само не
    заполняется – только кнопкой оператора."""
    row = (case or {}).get("verdict")
    stored = (case or {}).get("context")
    if not row or not stored:
        return {}
    verdict = Verdict.from_dict(row["data"])
    if verdict.verdict != "true_positive":
        return {}
    lines, fields = steering_of(f, stored, export_fragment_view(f, CodeContext.from_dict(stored)))
    if lines or fields:
        return {}
    points, dropped = defect.recommendation_points(verdict.fix, clean=True)  # заготовка из ответа модели
    comment = verdict.hub_comment.strip()  # текст о ложном срабатывании к дефекту не предлагается (план dev9, п. 1)
    return {"comment": comment if model_comment_verdict(comment, verdict.verdict) == "true_positive" else "",
            "points": "\n".join(points), "code_dropped": dropped}


def need_fix_text(model_fix: str, model_points: list[str], history_points: bool = False) -> str:
    """Подсказка у поля рекомендации – по тому, что есть в карточке (У2): кнопка «Взять пункты» есть только при
    пунктах словами в рекомендации модели; у рекомендации из одного кода и при её отсутствии кнопки нет; пункты
    прежнего разбора берутся в истории разборов (history_points, ADR-0097)."""
    if model_points:
        return ("Напишите рекомендацию: что исправить и как, по пункту в строке. Пункты модели можно взять за основу "
                "кнопкой «Взять пункты из рекомендации модели» под полем – пример кода в пункты не переносится.")
    if history_points:
        return ("Напишите рекомендацию словами: что исправить и как, по пункту в строке. У текущего разбора пунктов "
                "словами нет, у прежнего – есть: возьмите их кнопкой «Взять пункты из этого разбора» в истории "
                "разборов (шаг 2).")
    if model_fix.strip():
        return ("Напишите рекомендацию словами: что исправить и как, по пункту в строке. У модели в рекомендации "
                "только пример кода – в пункты дефекта он не переносится.")
    return ("Напишите рекомендацию словами: что исправить и как, по пункту в строке. Пунктов рекомендации модели "
            "нет.")
DEFECT_NEEDS_TEAM = ("Дефект не выдан: не указано название команды для первой фразы дефекта. Укажите его на "
                     "странице «Настройки» (раздел «Текст дефекта»).")
DEFECT_NEEDS_FIX = ("Дефект не выдан: нет рекомендации. Напишите, что исправить и как (по пункту в строке), и сохраните "
                    "решение.")
ENTERED_NEEDS_FIX = ("Отметка «Внесено в Hub» не поставлена: у дефекта нет рекомендации. Допишите её, сохраните решение "
                     "и перенесите текст в Hub.")
DEFECT_OTHER_REVISION = ("Решение по находке изменили в другой вкладке или окне: обновите карточку, сверьте решение и "
                         "скопируйте текст дефекта заново.")
SAST_COPY_DEFECT = ("Комментарий для Hub копируется только при решении «Ложное срабатывание». Для подтверждённого "
                    "дефекта сохраните решение и скопируйте заголовок и текст дефекта; отложенная находка в Hub не "
                    "переносится.")
MAX_FIX = 20000  # знаков в рекомендации дефекта SAST
FIX_TOO_LONG = (f"Рекомендация длиннее {MAX_FIX} знаков и не сохранена: сократите её – текст в поле остался "
                "как есть.")

# Отбор списка находок, внутри которого карточка ведёт к следующей находке (параметры адреса)
SELECTION_KEYS = ("kind", "verdict", "decision", "cb", "urgent", "steering", "reviewed", "copied", "entered",
                  "missing", "run_error", "dropped", "group", "hub_status", "hubsync", "hub_live",
                  "hub_model_diff", "no_code")
MAX_HUB_STATUSES = 20  # значений «Статус Hub» в одном отборе

# отбор по состоянию относительно Hub (dev15, бэклог 88): то же состояние, что в строках списка и в синхронизации
HUB_SYNC_FILTERS = {"unsent": "не отправлено в Hub", "differs": "есть отличия от Hub"}

# Готовые отборы над фильтрами списка находок: (подпись, параметры)
PRESETS = (("Непроверенные", {"kind": "SAST", "reviewed": "no"}), ("Срочные", {"urgent": "1"}),
           ("Неясно", {"verdict": "uncertain"}), ("Hub и модель разошлись", {"hub_model_diff": "1"}),
           ("Живые в Hub", {"hub_live": "1"}), ("Отложенные", {"decision": "later"}),
           ("Не внесены в Hub", {"reviewed": "yes", "entered": "no"}), ("С указаниями для модели", {"steering": "1"}))

# Фильтры списка находок чипами: группы с одним выбранным значением – (параметр, подпись, ((значение, подпись), …)),
# "" – без фильтра; флажки – (параметр, значение, подпись)
FILTER_GROUPS = (
    ("kind", "Вид", (("", "все"), *KIND_LABELS.items())),
    ("verdict", "Вердикт модели", (("", "любой"), *VERDICT_LABELS.items(), ("none", "нет вердикта"))),
    ("decision", "Моё решение", (("", "любое"), *DECISION_LABELS.items(), ("none", "нет решения"))),
    ("reviewed", "Проверено", (("", "все"), ("no", "нет"), ("yes", "да"))),
    ("entered", "Внесено в Hub", (("", "все"), ("no", "нет"), ("yes", "да"))),
    ("missing", "В выгрузке", (("", "все"), ("no", "есть"), ("yes", "нет в новой выгрузке"))),
    ("hubsync", "Синхронизация с Hub", (("", "все"), *HUB_SYNC_FILTERS.items())),
)
# «Срочные» и «С указаниями для модели» – среди готовых отборов, здесь их не повторяем
FILTER_FLAGS = (("copied", "no", "проверены, но не скопированы в Hub"),
                ("run_error", "1", "с ошибкой в последнем прогоне"),
                ("dropped", "1", "выбыли из дефекта"),
                ("no_code", "1", "без кода в клоне"))

# Уверенность модели словами: (нижняя граница, слово)
CONFIDENCE_WORDS = ((80, "высокая"), (50, "средняя"), (0, "низкая"))

register_messages({
    "saved": "Решение сохранено.",
    "all_reviewed": "Непроверенных находок SAST больше нет.",
    "no_other": "Решение сохранено. Других непроверенных находок SAST нет – осталась только эта.",
    "selection_done": "Решение сохранено. В этой выборке больше нечего проверять.",
    "selection_end": "Решение сохранено. Это была последняя находка выборки.",
    "code_changed": CODE_CHANGED_REVIEW,
    "reviewed": "Находка отмечена как проверенная.",
    "unreviewed": "Отметка «Проверено» снята.",
    "entered": "Отмечено: внесено в Hub.",
    "unentered": "Отметка «Внесено в Hub» снята.",
    "reanalyze": "Находка поставлена на повторный разбор: карточка обновится, когда модель ответит.",
    "asked": "Модель ответила – ответ ниже, в разделе «Вопросы к модели».",
    "ask_failed": "Модель не ответила – причина ниже, в разделе «Вопросы к модели».",  # плашка ошибки (НТ12)
}, errors=("ask_failed",))


class ReviewRejected(ValueError):
    """Решение не сохраняется по существу (например, «Риск принят» без обоснования). Текст – для человека; форма
    возвращается с тем, что он ввёл."""


# ============================================================================ отбор

def multi_values(q, key: str) -> tuple[str, ...]:
    """Повторяющийся параметр адреса (`hub_status=A&hub_status=B`, бэклог 99): упорядоченный кортеж без пустых и
    повторов, не больше MAX_HUB_STATUSES значений по MAX_NAME знаков."""
    raw = q.getlist(key) if hasattr(q, "getlist") else [q.get(key, "")]
    values = tuple(dict.fromkeys(v for v in (str(x)[:MAX_NAME] for x in raw) if v))
    return values[:MAX_HUB_STATUSES]


def read_selection(q) -> dict[str, Any]:
    """Отбор списка находок из параметров адреса (только допустимые значения): по нему карточка ведёт
    к следующей непроверенной находке этого же отбора."""
    selection = {
        "kind": q.get("kind", "") if q.get("kind", "") in KIND_LABELS else "",
        "verdict": q.get("verdict", "") if q.get("verdict", "") in (*VERDICTS, "none") else "",
        "decision": q.get("decision", "") if q.get("decision", "") in (*DECISIONS, "hub", "none") else "",
        "cb": q.get("cb", "")[:MAX_NAME],
        "urgent": "1" if q.get("urgent") == "1" else "",
        "steering": "1" if q.get("steering") == "1" else "",
        "reviewed": q.get("reviewed", "") if q.get("reviewed", "") in ("yes", "no") else "",
        "copied": "no" if q.get("copied") == "no" else "",
        "entered": q.get("entered", "") if q.get("entered", "") in ("yes", "no") else "",
        "missing": q.get("missing", "") if q.get("missing", "") in ("yes", "no") else "",
        "run_error": "1" if q.get("run_error") == "1" else "",
        "dropped": "1" if q.get("dropped") == "1" else "",
        "hub_status": multi_values(q, "hub_status"),
        "hub_live": "1" if q.get("hub_live") == "1" else "",
        "hub_model_diff": "1" if q.get("hub_model_diff") == "1" else "",
        "no_code": "1" if q.get("no_code") == "1" else "",
        "hubsync": q.get("hubsync", "") if q.get("hubsync", "") in HUB_SYNC_FILTERS else "",
        # группа SAST находки с этим id (точный ключ группы, ADR-0095): «Вся группа в списке» из карточки
        # переданный, но негодный (0, не число) – "0": отбор пуст, а не весь проект
        "group": "" if "group" not in q else (group if ((group := str(q.get("group", ""))).isascii()
                                                        and group.isdigit() and len(group) <= 12) else "0"),
    }
    # Сортировка и группа относятся к той же очереди, что предметные фильтры.
    for key in ("sort", "group_by", "family"):
        if q.get(key):
            selection[key] = str(q[key])[:120]
    back = q.get("back", "")[:2000]
    try:
        back_parts = urlsplit(back)
    except ValueError:
        back_parts = urlsplit("")
    if back.startswith("/projects/") and back_parts.path.endswith("/findings") and not back_parts.netloc:
        selection["back"] = back
        for key, values in parse_qs(back_parts.query).items():
            if key in ("sort", "group_by", "family") and key not in selection:
                selection[key] = values[-1][:120]
    return {k: v for k, v in selection.items() if v}


def queue_neighbor(db, project_id, anchor, selection, direction="next", *, wrap=True, descriptors=None, hub_ids=None):
    """Обход той же отсортированной группы, что видна в таблице, через границы страниц. descriptors – уже прочитанные
    дескрипторы отбора selection (страница списка читает их для таблицы): второй раз база не читается, из них
    берутся те же строки, что дал бы запрос с kind=SAST и missing=no по умолчанию (PERF-03: на 50 000 находок второе
    чтение стоило 0,5 с из 1,4 с страницы)."""
    filters = selection_filters(selection)
    defaults = {}
    if not filters.get("kind"):
        filters["kind"] = defaults["kind"] = "SAST"
    if not filters.get("missing"):
        filters["missing"] = defaults["missing"] = "no"
    if descriptors is None:
        rows = db.finding_descriptors(project_id, filters)
    else:
        rows = [r for r in descriptors
                if ("kind" not in defaults or r["kind"] == "SAST")
                and ("missing" not in defaults or r["missing"] == 0)]  # ровно как f.missing = 0 в SQL
    if hub_ids is not None:  # отбор «Синхронизация с Hub» (dev15): тот же набор, что в списке
        rows = [r for r in rows if r["hub_id"] in hub_ids]
    # После сохранения текущая строка могла выйти из фильтра «непроверенные»; позиция обхода остаётся её.
    if anchor and not any(r["id"] == anchor["id"] for r in rows):
        rows.append(anchor)
        rows.sort(key=lambda r: (r["pos"], r["id"]))
    rows = worklists.sort_findings(rows, selection.get("sort", ""))
    family = selection.get("family", "")
    if family:
        rows = [r for r in rows if worklists.family(r, "findings")[0] == family]
    if not rows:
        return None
    index = next((i for i, r in enumerate(rows) if anchor and r["id"] == anchor["id"]), -1)
    candidates = rows[index + 1:] + (rows[:index] if wrap and index >= 0 else [])
    if direction == "prev":
        candidates = list(reversed(rows[:index])) + (list(reversed(rows[index + 1:])) if wrap else [])
    return next((r["id"] for r in candidates if (not anchor or r["id"] != anchor["id"])
                 and (walks_all(selection) or not r["reviewed"])), None)


def walks_all(selection: dict[str, str]) -> bool:
    """Выборка проверенных находок («не скопированы в Hub», «проверено: да», «внесены в Hub»): карточка ведёт
    по всем находкам выборки, а не только по непроверенным."""
    return (selection.get("copied") == "no" or selection.get("reviewed") == "yes"
            or selection.get("entered") == "yes" or selection.get("dropped") == "1")


def selection_filters(selection: dict[str, str]) -> dict[str, Any]:
    """Отбор из адреса -> фильтры Database.list_findings / neighbor_unreviewed («~» – находки без кодовой базы)."""
    cb = selection.get("cb", "")
    return {"kind": selection.get("kind", ""), "verdict": selection.get("verdict", ""),
            "decision": selection.get("decision", ""), "codebase": None if not cb else ("" if cb == "~" else cb),
            "urgent": bool(selection.get("urgent")), "steering": bool(selection.get("steering")),
            "reviewed": selection.get("reviewed", ""), "copied": selection.get("copied", ""),
            "entered": selection.get("entered", ""), "missing": selection.get("missing", ""),
            "run_error": bool(selection.get("run_error")), "dropped": bool(selection.get("dropped")),
            "group": int(selection["group"]) if selection.get("group") else None,
            "hub_status": tuple(selection.get("hub_status") or ()), "hub_live": bool(selection.get("hub_live")),
            "hub_model_diff": bool(selection.get("hub_model_diff")), "no_code": bool(selection.get("no_code"))}


def selection_labels(selection: dict[str, str]) -> list[str]:
    """Отбор словами – для строки «В выборке: …» в карточке."""
    labels = []
    if selection.get("urgent"):
        labels.append("срочные")
    if selection.get("cb"):
        labels.append("без кодовой базы" if selection["cb"] == "~" else selection["cb"])
    if selection.get("kind"):
        labels.append(KIND_LABELS.get(selection["kind"], selection["kind"]))
    verdict = selection.get("verdict", "")
    if verdict:
        labels.append("модель: " + ("нет вердикта" if verdict == "none" else VERDICT_LABELS.get(verdict, verdict)))
    decision = selection.get("decision", "")
    if decision:
        labels.append("решение: " + ("нет" if decision == "none" else DECISION_LABELS.get(decision, decision)))
    if selection.get("hub_status"):
        statuses = selection["hub_status"]
        labels.append("статус Hub: " + (", ".join(statuses) if isinstance(statuses, (list, tuple)) else str(statuses)))
    if selection.get("hub_live"):
        labels.append("живые в Hub")
    if selection.get("hub_model_diff"):
        labels.append("Hub и модель разошлись")
    if selection.get("no_code"):
        labels.append("без кода в клоне")
    if selection.get("steering"):
        labels.append("с текстом-указанием для модели")
    if selection.get("reviewed"):
        labels.append("проверенные" if selection["reviewed"] == "yes" else "непроверенные")
    if selection.get("copied"):
        labels.append("не скопированы в Hub")
    if selection.get("dropped"):
        labels.append("выбыли из дефекта")
    if selection.get("group"):
        labels.append("одна группа SAST")
    if selection.get("entered"):
        labels.append("внесены в Hub" if selection["entered"] == "yes" else "не внесены в Hub")
    if selection.get("missing"):
        labels.append("нет в новой выгрузке" if selection["missing"] == "yes" else "есть в выгрузке")
    if selection.get("run_error"):
        labels.append("с ошибкой в последнем прогоне")
    if selection.get("hubsync"):
        labels.append(HUB_SYNC_FILTERS[selection["hubsync"]])
    return labels


def hub_sync_ids(request, project, selection, states=None):
    """hub_id находок отбора «Синхронизация с Hub» (dev15): то же состояние, что в строках списка; без отбора – None."""
    choice = selection.get("hubsync")
    if choice not in HUB_SYNC_FILTERS:
        return None
    states = states or hub_state.project_states(db_of(request), project, settings_of(request).hub_url)
    field = "unsent" if choice == "unsent" else "differs"
    return {hub_id for hub_id, st in states["by_hub_id"].items() if st[field]}


def card_url(project_id: int, finding_id: int, selection: dict[str, str], **params: Any) -> str:
    """Адрес карточки с отбором списка и параметрами (?ok=…)."""
    q = query(selection, **params)
    return f"/projects/{project_id}/findings/{finding_id}" + (f"?{q}" if q else "")


# ============================================================================ карточка

def masked_extra(f: Finding, key: bytes) -> dict[str, str]:
    """Прочие колонки выгрузки для карточки – маскированными, как код. У находки о секрете в коде каждая строка
    значения скрывается целиком (здесь правило ADR-0117 не действует): в такой колонке может оказаться копия кода
    с секретом, в том числе многострочный литерал, который по частям не распознать."""
    credential = is_credential_finding(f.rule, f.cwe)
    result = {}
    for name, value in f.extra.items():
        text = str(value)
        if credential:
            result[name] = "\n".join(mask_line(part, key)[0] if part.strip() else part for part in text.split("\n"))
        else:
            result[name] = mask_text(text, key)[0]
    return result


def card_note(ctx: CodeContext) -> str:
    """Заметка к срезу без прежнего предположения о смене коммита по несовпадению строки."""
    parts = [p for p in str(ctx.note or "").split("; ") if p.strip()]
    parts = [p for p in parts if "не совпадает со строкой из выгрузки" not in p]
    return "; ".join(parts)


# что делать оператору – по ключу общей классификации причин (view.code_reason_key, бэклог 103)
CODE_REASON_ADVICE = {
    "file_missing": "Разбор и решение – по сведениям из выгрузки Hub: правило, путь и строка кода.",
    "no_file": "Разбор и решение – по сведениям из выгрузки Hub.",
    "ambiguous": "Код не показан: уточните путь или оставьте клон до разбора.",
    "line_out_of_range": "Причина – клон, похоже, не на коммите скана.",
    "too_large": "Файл в клоне есть, но больше 2 МБ.",
    "binary": "Файл в клоне есть, но двоичный.",
    "unreadable": "Файл в клоне есть, но не читается.",
    "empty": "Файл в клоне есть, но пуст.",
}


def code_reason(ctx: CodeContext) -> str:
    """Почему карточка показывает сведения выгрузки вместо кода из файла клона (ADR-0073): причина – общей
    классификацией списка и сводок (view.code_reason, бэклог 103), с тем, что делать; без клона и прежние срезы – пояснение
    среза (например, «клон отвязан»). Тексты для модели (ctx.note) не меняются."""
    from app.view import code_reason as reason_label, code_reason_key
    if ctx.status == "ok":
        return ""
    key = code_reason_key(ctx.status, ctx.reason, ctx.file)
    if key not in CODE_REASON_ADVICE:
        return ctx.note
    label = reason_label(ctx.status, ctx.reason, ctx.file, len(ctx.lines or []))
    return f"{label[:1].upper()}{label[1:]}. {CODE_REASON_ADVICE[key]}"


def confidence_label(value: Any) -> str:
    """Уверенность словами: высокая (от 80), средняя (от 50), низкая."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = 0
    return next(word for bound, word in CONFIDENCE_WORDS if number >= bound)


def model_comment_verdict(text: str, verdict: str) -> str:
    """Исход, к которому на деле написан текст модели: начало «Ложное срабатывание» важнее вердикта ответа: при вердикте
    «истинная» такой текст подставлялся в обоснование дефекта и спорил с решением (план dev9, часть 2, п. 1)."""
    return "false_positive" if str(text or "").lstrip().casefold().startswith("ложное срабатывание") else str(verdict or "")


def target_line_hidden(f: Finding, ctx: CodeContext | None) -> bool:
    """Находка о секрете, у которой в срезе модели строка срабатывания – только метка: кроме меток и знаков препинания в ней ничего нет
    (срез до ADR-0117, содержимое многострочного литерала). Модель такую строку не видела, вердикт ненадёжен. Только показ."""
    if ctx is None or not is_credential_finding(f.rule, f.cwe):
        return False
    text = next((line for _, line, target in ctx.rows() if target), "")
    return bool(PLACEHOLDER_RE.search(text)) and not re.search(r"\w", PLACEHOLDER_RE.sub("", text))


def comment_origin(db: Database, case: dict | None, review: dict | None, comment: str, *,
                   project_id: int | None = None, hub_id: str = "", known: list[dict] | None = None) -> str:
    """Вердикт, к которому модель написала этот комментарий, если человек его не правил: текущий ответ модели
    по находке, ответ, по которому человек принимал прежнее решение (review.verdict_id), и – по project_id и hub_id –
    все прежние ответы по находке (db.finding_verdicts): после повторного разбора и обычного сохранения ссылка на
    прежний ответ из решения уходит, а его комментарий остаётся. "" – комментарий написан или поправлен человеком
    (или пуст)."""
    text = str(comment or "").strip()
    if not text:
        return ""
    candidates = []
    if case and case.get("verdict"):
        candidates.append(case["verdict"])
    old_id = (review or {}).get("verdict_id")
    if old_id and (not case or old_id != case.get("verdict_id")):
        old = db.get_verdict(int(old_id))
        if old is not None:
            candidates.append(old)
    if known is not None:  # ответы по находке уже выбраны этим же запросом (карточка: две сверки – одна выборка)
        candidates += known
    elif project_id is not None and hub_id:
        candidates += db.finding_verdicts(project_id, hub_id)
    for v in candidates:
        if text == str((v.get("data") or {}).get("hub_comment") or "").strip():
            return model_comment_verdict(text, v.get("verdict"))
    return ""


def saved_hub_text(f: Finding, review: dict | None, status_map: dict) -> str:
    """Текст для Hub по сохранённому решению – тот, что человек вносит в Hub (по нему считается отпечаток отметки
    «Внесено в Hub»). Решения нет – ""."""
    if not review:
        return ""
    return hub_text(f, hub_verdict(review["decision"], review["final_verdict"]), review["final_comment"], status_map)


def entered_text_changed(review: dict | None, text: str) -> bool:
    """Отметка «Внесено в Hub» стоит, а текст для Hub с тех пор другой (например, сменились статусы Hub
    в настройках). Отметки без отпечатка (поставлены до этапа 3) – entered_unconfirmed."""
    expected = (review.get("entered_decision_hash") if review.get("entered_origin") == "defect"
                else review.get("entered_text_hash")) if review else ""
    return bool(review and review.get("entered_hub") and expected and text_hash(text) != expected)


# составляющие текста SAST для Hub (О8): (ключ, что называет карточка, если изменилось). Статусы Hub в текст SAST
# не входят (prompts.hub_text): их смена причиной не называется
ENTERED_PARTS = (("comment", "текст решения"), ("fix", "рекомендация"), ("team", "название команды в настройках"))


def entered_parts(settings, review: dict | None) -> str:
    """Из чего собран текст SAST для Hub сейчас (О8) – только то, что в него входит: у подтверждённого дефекта тело –
    обоснование, рекомендация и название команды (sast_entered_text), у ложного срабатывания – комментарий; плюс
    версия приложения (формат текста). Запоминается при отметке «Внесено в Hub»."""
    review = review or {}
    parts = {"comment": text_hash(review.get("final_comment") or ""), "app": __version__}
    if defect.sast_ready(hub_verdict(review.get("decision") or "", review.get("final_verdict") or "")):
        parts.update(fix=text_hash(review.get("final_fix") or ""), team=text_hash(settings.team_name or ""))
    return json.dumps(parts, sort_keys=True)


def entered_by_bulk(review: dict | None) -> bool:
    """Отметка «Внесено в Hub» поставлена массовой отправкой из списка (ADR-0119): в частях отметки – признак bulk, а
    отпечаток – общего комментария, не текста решения."""
    try:
        was = json.loads((review or {}).get("entered_parts") or "")
    except ValueError:
        return False
    return isinstance(was, dict) and bool(was.get("bulk"))


def entered_change_reasons(settings, review: dict | None) -> list[str] | None:
    """Что изменилось в тексте для Hub после отметки «Внесено в Hub» (О8). None – отметка поставлена до 0.9.9 и
    составляющих не помнит; [] – составляющие те же (текст изменился иначе). Если изменилась только версия
    приложения – причина в формате текста."""
    try:
        was = json.loads((review or {}).get("entered_parts") or "")
    except ValueError:
        return None
    if not isinstance(was, dict):
        return None
    now = json.loads(entered_parts(settings, review))
    reasons = [label for key, label in ENTERED_PARTS if key in was and was[key] != now.get(key)]
    if not reasons and was.get("app") and was["app"] != now["app"]:
        fix = str((review or {}).get("final_fix") or "")
        comment = str((review or {}).get("final_comment") or "")
        if (app_before(was["app"], "0.9.11")
                and defect.sast_reason(comment, legacy=True) != defect.reason_text(comment, clean=True)):
            # с 0.9.11 первая буква обоснования – заглавная (ADR-0101): текст изменился из-за этого
            reasons.append(f"первая буква обоснования теперь заглавная (версия {now['app']}, отметка поставлена в "
                           f"{was['app']})")
        if app_before(was["app"], "0.10.0.dev21") and defect.as_written_changed(comment, fix if "fix" in now else ""):
            # с 0.10.0.dev21 текст оператора уходит как написан: без среза вводного слова,
            # тегов, схем, невидимых знаков, замены тире и схлопывания пустых строк
            reasons.append(f"текст оператора теперь уходит в Hub как написан, без правок приложения (версия "
                           f"{now['app']}, отметка поставлена в {was['app']})")
        if "fix" in now and app_before(was["app"], "0.9.11") and defect.marker_rule_changed(fix):
            # с 0.9.11 маркер «N)» снимается и без пробела: «2)мера» больше не пункт «2) 2)мера»
            reasons.append(f"маркер пункта «N)» без пробела больше не остаётся в тексте пункта (версия {now['app']}, "
                           f"отметка поставлена в {was['app']})")
        if "fix" in now and app_before(was["app"], "0.9.10") and defect.recommendation_points(fix)[1]:
            # с 0.9.10 пример кода в рекомендацию дефекта не переносится (ADR-0098): текст изменился из-за этого
            reasons.append(f"пример кода в рекомендации больше не переносится в Hub (версия {now['app']}, отметка "
                           f"поставлена в {was['app']})")
        if not reasons:
            reasons.append(f"формат текста в версии приложения {now['app']} (отметка поставлена в {was['app']})")
    return reasons


def app_before(version: str, release: str) -> bool:
    """Версия приложения version раньше выпуска release (по числам версии; без чисел – раньше)."""
    def key(value: str) -> tuple[int, ...]:
        return tuple(int(x) for x in re.findall(r"\d+", str(value or "")))
    return key(version) < key(release)


def entered_format_updated(review: dict | None, text: str, legacy) -> bool:
    """Отметка «Внесено в Hub» поставлена по тексту прежнего формата (до 0.9.0 или 0.9.0–0.9.5), решение с тех пор
    прежнее: текст для Hub изменился только из-за нового формата. Карточка показывает спокойную пометку вместо «текст
    изменился» и предлагает подтвердить отметку заново, если человек обновит комментарий в Hub. legacy – текст
    прежнего формата или список таких текстов."""
    texts = [legacy] if isinstance(legacy, str) else list(legacy or [])
    # отпечаток, с которым сверяется отметка: у отметки от дефекта – текста решения (entered_decision_hash), как в
    # entered_text_changed; у остальных – текста, внесённого в Hub
    expected = {review.get("entered_text_hash") or ""} if review else set()
    if review and review.get("entered_origin") == "defect":
        expected.add(review.get("entered_decision_hash") or "")
    expected.discard("")
    return bool(entered_text_changed(review, text) and review
                and any(t and text_hash(t) in expected for t in texts))


def saved_hub_text_v1(f: Finding, review: dict | None, status_map: dict) -> str:
    """Текст для Hub прежнего формата по сохранённому решению – для распознавания отметок до 0.9.0."""
    if not review:
        return ""
    return hub_text_v1(f, hub_verdict(review["decision"], review["final_verdict"]), review["final_comment"],
                       status_map)


def saved_hub_text_v2(f: Finding, review: dict | None, status_map: dict) -> str:
    """Текст для Hub формата 0.9.0–0.9.5 по сохранённому решению – для распознавания отметок до 0.9.6."""
    if not review:
        return ""
    return hub_text_v2(f, hub_verdict(review["decision"], review["final_verdict"]), review["final_comment"],
                       status_map)


def saved_legacy_texts(f: Finding, review: dict | None, status_map: dict, team: str = "") -> list[str]:
    """Тексты прежних форматов по сохранённому решению: до 0.9.0, 0.9.0–0.9.5, 0.9.6–0.9.10 (обоснование без
    поднятой первой буквы, ADR-0101) и 0.9.11–0.10.0.dev20 (прежняя чистка и срез вводного слова); team – название
    команды для тела дефекта."""
    return [saved_hub_text_v1(f, review, status_map), saved_hub_text_v2(f, review, status_map),
            saved_hub_text_v3(f, review, team), saved_hub_text_v4(f, review, team)]


def saved_hub_text_v4(f: Finding, review: dict | None, team: str = "") -> str:
    """Текст для Hub формата 0.9.11–0.10.0.dev20 по сохранённому решению: вводное «Подтверждено:» и подобное снято,
    теги, схемы, невидимые знаки и лишние пустые строки убраны, длинное тире заменено. Совпал с текущим – "" (тот же
    текст, не прежний формат). Только SAST: у DAST и SCA-license прежний текст до 0.10.0.dev21 – hub_text_v1
    (saved_hub_text_v1)."""
    if not review or not review.get("decision") or f.kind != "SAST":
        return ""
    comment = str(review.get("final_comment") or "")
    outcome = hub_verdict(review["decision"], review["final_verdict"])
    if not defect.sast_ready(outcome):
        old = defect.sast_comment_v4(f, outcome, comment)
        return old if old != defect.sast_comment(f, outcome, comment) else ""
    fix = str(review.get("final_fix") or "")
    if not defect.has_recommendation(fix) or not defect.fix_items(fix, clean=True):
        return ""  # по прежним правилам рекомендации словами не было – дефекта по ним тоже
    old = defect.sast_body(f, outcome, comment, fix, team, legacy_0911=True)
    return old if old != defect.sast_body(f, outcome, comment, fix, team) else ""


def saved_hub_text_v3(f: Finding, review: dict | None, team: str = "") -> str:
    """Текст для Hub формата 0.9.6–0.9.10 по сохранённому решению: первая буква обоснования как у оператора, маркер
    «N)» только с пробелом – собирается прежними правилами, а не заменой в очищенном тексте (ревью шага 10). Совпал с
    текущим – "" (это не прежний формат, а тот же текст)."""
    if not review or not review.get("decision"):
        return ""
    comment = str(review.get("final_comment") or "")
    outcome = hub_verdict(review["decision"], review["final_verdict"])
    if not defect.sast_ready(outcome):
        old = defect.sast_comment_v3(f, outcome, comment)
        return old if old != defect.sast_comment(f, outcome, comment) else ""
    fix = str(review.get("final_fix") or "")
    if not defect.has_recommendation(fix):
        return ""
    old = defect.sast_body(f, outcome, comment, fix, team, legacy_0910=True)
    return old if old != defect.sast_body(f, outcome, comment, fix, team) else ""


def entered_unconfirmed(review: dict | None) -> bool:
    """Отметка «Внесено в Hub» поставлена до этапа 3 и отпечатка текста не имеет: после обновления (например,
    статусы Hub стали русскими) неизвестно, тот ли текст лежит в Hub. Карточка просит подтвердить отметку заново."""
    # отметка, принятая синхронизацией, подтверждена чтением Hub: её текст – принятый из Hub
    return bool(review and review.get("entered_hub") and not review.get("entered_text_hash")
                and review.get("entered_origin") != "hub_sync")


def line_warnings(comment: str, fix: str, shown: set[int] | None) -> list[str]:
    """Ссылки «строка N» в обосновании (комментарий человека) и рекомендациях (поле модели «Как исправить») на строки,
    которых нет в показанном коде: такой довод не подтверждён. shown=None – показанного кода нет, и не подтверждена
    ни одна ссылка."""
    known = shown if shown is not None else set()
    result = []
    for label, text in (("Обоснование", defect.reason_text(comment)), ("Рекомендации модели", fix)):
        missing = missing_line_refs(text, known)
        if missing:
            numbers = ", ".join(str(n) for n in missing[:10]) + (" и другие" if len(missing) > 10 else "")
            where = "в показанном коде" if shown else "– показанного кода нет"
            verb = "ссылается" if label == "Обоснование" else "ссылаются"
            result.append(f"{label} {verb} на строки, которых нет {where}: {numbers}. Сверьте с кодом.")
    return result


def shown_lines(request: Request, project_id: int, f: Finding, case: dict | None) -> set[int] | None:
    """Номера строк кода, которые видит человек в карточке: срез, разобранный моделью, а без вердикта – срез
    из клона сейчас. Кода нет – None."""
    if case and case.get("verdict") and case.get("context"):
        ctx = CodeContext.from_dict(case["context"])
    else:
        source = db_of(request).case_input(project_id, f.hub_id)
        if source is None:
            return None
        snapshot = snapshot_code(settings_of(request), source, case)
        if snapshot is not None:
            ctx = snapshot[0]
        else:
            repo_dir, _ = repo_dir_for(settings_of(request), {"repos_dir": source["repos_dir"]},
                                       source_codebases(source, f), f)
            ctx = build_context(repo_dir, f, max_chars=CONTEXT_CHARS, mask_key=mask_key_of(request))
    lines = {n for n, _, _ in ctx.rows() if n}
    return lines or None


def defect_shown_lines(request: Request, project_id: int, f: Finding, case: dict | None, own: set[int] | None = None,
                       also: Iterable[str] = ()) -> set[int] | None:
    """Строки кода, на которые может ссылаться текст дефекта: срезы всех его находок (план dev7, раздел 11). Текст у дефекта
    общий, обоснование может ссылаться на строку другой находки – сверка только со своим срезом давала ложное предупреждение
    на каждую находку. Дефект – все физические строки семьи: при последовательной привязке их несколько. Находка не в дефекте
    – только её срез. own – свой срез, если уже получен; also – ещё находки того же дефекта (цели подготовки)."""
    db = db_of(request)
    lines = set(own if own is not None else shown_lines(request, project_id, f, case) or ())
    bound = db.hub_defect_bound(project_id, f.hub_id)
    family = db.on_connection(lambda c: defect_drafts.family_in(c, bound)) if bound else []
    others = {str(t.get("hub_id") or "") for member in family for t in loads(member.get("targets_json"), [])} | set(also)
    for hub_id in sorted(others - {"", f.hub_id}):
        row = db.get_finding_by_hub_id(project_id, hub_id)
        if row is not None and row["kind"] == "SAST":
            lines |= shown_lines(request, project_id, Finding.from_dict(row["data"]), db.get_case(project_id, hub_id)) or set()
    return lines or None


DEFECT_RACE = "Дефект не выдан: пока готовился текст, данные изменились."

SAST_OUTCOME_LABELS = {"true_positive": "истинная", "false_positive": "ложная", "uncertain": "неясно",
                       "risk_accepted": "риск принят"}


RUN_ORIGIN_LABELS = {"project": "прогон проекта", "card": "пересмотр из карточки", "retry": "повтор ошибок",
                     "": "вид запуска не записан"}
ATTEMPT_LABELS = {"error": "ошибка разбора", "skipped": "пропуск", "pending": "в очереди"}


def history_view(history: dict, current_id: int | None, decided_id: int | None, case_hash: str, own_outcome: str,
                 steering: bool) -> dict:
    """История разборов моделью для карточки (ADR-0097): строки ответов с метками и пунктами рекомендации словами,
    «модели расходятся» – только среди ответов по тем же входным данным и той же версии промпта; попытки без ответа –
    сводкой. Пункты под влиянием указаний в коде не предлагаются (как кнопка у текущего разбора)."""
    rows = []
    for a in history.get("answers") or []:
        data = a.get("data") or {}
        comparable = a.get("case_hash") == case_hash and a.get("prompt_version") == PROMPT_VERSION
        points = [] if steering else defect.recommendation_points(str(data.get("fix") or ""), clean=True)[0]
        uses = a.get("uses") or []
        rows.append({
            "id": a["id"], "model": a.get("model") or "", "verdict": a.get("verdict") or "",
            "confidence": a.get("confidence"), "created_at": a.get("created_at") or "", "stats": a.get("stats") or {},
            "summary": str(data.get("summary") or ""), "why": [str(x) for x in data.get("why") or []][:6],
            "fix": str(data.get("fix") or ""), "points": points,
            "current": a["id"] == current_id, "decided": a["id"] == decided_id,
            "disagrees": own_outcome in SAST_OUTCOMES and a.get("verdict") in SAST_OUTCOMES
                         and a.get("verdict") != own_outcome,
            "note": "" if comparable else ("по другим входным данным" if a.get("case_hash") != case_hash
                                           else "другая версия промпта"),
            "comparable": comparable,
            "runs": [{"run_id": u["run_id"], "origin": RUN_ORIGIN_LABELS.get(u.get("origin") or "",
                                                                             RUN_ORIGIN_LABELS[""])}
                     for u in uses if u.get("state") == "done"],
            "cached": sum(1 for u in uses if u.get("state") == "cached")})
    verdicts = {r["verdict"] for r in rows if r["comparable"] and r["verdict"]}
    attempts = history.get("attempts") or []
    card = [r for r in rows if any(run["origin"] == RUN_ORIGIN_LABELS["card"] for run in r["runs"])]
    return {"rows": rows, "count": len(rows), "disagree": len(verdicts) > 1, "tally": verdict_tally(rows),
            "attempts": [{**x, "label": ATTEMPT_LABELS.get(x["state"], x["state"]),
                          "origin": RUN_ORIGIN_LABELS.get(x.get("origin") or "", RUN_ORIGIN_LABELS[""])}
                         for x in attempts][-5:],
            "attempts_total": len(attempts),
            "show": len(rows) > 1 or bool(attempts) or any(not r["current"] for r in rows),
            "reanalyzed": len(card), "last_card": card[0] if card else None,
            "earlier_points": any(r["points"] for r in rows if not r["current"])}


def verdict_tally(rows: list[dict]) -> dict:
    """Сводка разборов моделью для шага 5: сколько разборов с каждым вердиктом и их
    уверенность – по всем ответам истории, как в списке шага 2; последний – самый поздний по времени ответа; «модели
    расходятся» – только среди ответов по тем же входным данным и той же версии промпта (comparable, как
    model_history.disagree, ADR-0097). Подсказка, решает человек."""
    groups: dict[str, list] = {}
    for r in rows:
        if r["verdict"]:
            groups.setdefault(r["verdict"], []).append(r["confidence"])
    order = ("true_positive", "false_positive", "uncertain")
    parts = [{"verdict": v, "count": len(groups[v]),
              "confidences": [c for c in groups[v] if c is not None]}
             for v in sorted(groups, key=lambda v: (order.index(v) if v in order else len(order), v))]
    latest = max(rows, key=lambda r: r["created_at"]) if rows else None
    split = len({r["verdict"] for r in rows if r.get("comparable", True) and r["verdict"]}) > 1
    return {"parts": parts, "latest": latest, "split": split}


def sast_decision_state(review: dict | None, source: dict | None = None, case: dict | None = None,
                        code_now: str = "") -> tuple[str, str]:
    """Состояние решения человека по находке SAST для выдачи в Hub и его итог (hub_verdict).

    "none" – решения нет: принятое решение – непустое допустимое поле decision, а подставленный моделью вердикт
    или один комментарий его не заменяют; "later" – отложено; "missing" – находки нет в текущей выгрузке;
    "changed" – решение принято по другой версии находки (после решения сменились правило, файл, строка, код из
    выгрузки, папка клона или его последняя увиденная ревизия – то, что входит в отпечаток решения finding_sig);
    (новый ответ модели при той же находке и том же коде решение не ослабляет, ADR-0097); "code_changed" – код в клоне уже не тот, который видел
    человек при сохранении решения (его собственные code_hash и code_chars; решение без отпечатка кода тоже не
    доказано); "not_ready" – итог, для которого дефект не готовится (неясно, «Риск принят»); "ok" – итог «истинная»
    или «ложная» по действующему решению.

    source – снимок находки и источника её кода (case_input): по нему решение сверяется с текущей версией находки;
    без source сверка версии и кода не делается. case – сохранённая привязка находки к вердикту модели. code_now –
    отпечаток кода, который в клоне сейчас, при том же размере среза code_chars, что у решения."""
    if not review or review.get("decision") not in DECISIONS or not review.get("decision"):
        return "none", ""
    if review["decision"] == "later":
        return "later", ""
    outcome = hub_verdict(review["decision"], review["final_verdict"])
    if source is not None:
        if source.get("missing"):
            return "missing", outcome
        if review.get("finding_sig") != source_signature(source):
            return "changed", outcome
    # новый ответ модели при той же находке и том же коде решение не ослабляет (ADR-0097): «verdict_changed» больше не
    # выставляется – находку и код решения сверяют finding_sig и code_hash
    if source is not None and (not review.get("code_hash") or review["code_hash"] != code_now):
        return "code_changed", outcome
    return ("ok" if defect.sast_ready(outcome) else "not_ready"), outcome


def sast_choice(decision: str, final_verdict: str, model_verdict: dict | None, stale_verdict: bool,
                old: dict | None = None, current_verdict_id: int | None = None) -> tuple[str, str]:
    """Два исхода SAST (ADR-0089): «Ложное срабатывание» и «Подтверждаю дефект» приходят как значения false_positive
    и true_positive поля decision; в базе они хранятся прежней парой: «Согласен», если вердикт модели тот же и относится
    к текущему коду, иначе «Не согласен» с итоговым вердиктом. Сохранённое «Не согласен» с тем же исходом по тому же
    ответу модели остаётся «Не согласен»: совпадение итога с моделью не означает согласия с её рекомендацией
    (ADR-0088), и пересохранение не должно подменить общий пункт рекомендацией модели. Пришёл новый ответ модели
    (его показывает карточка) – вид решения определяется заново. Остальные значения – как пришли."""
    if decision in SAST_OUTCOMES:
        if (old and old.get("decision") == "disagree"
                and hub_verdict(old["decision"], old.get("final_verdict") or "") == decision
                and old.get("verdict_id") == current_verdict_id):
            return "disagree", decision
        same = bool(model_verdict) and model_verdict.get("verdict") == decision and not stale_verdict
        return ("agree" if same else "disagree"), decision
    return decision, final_verdict


def sast_outcome(decision: str, final_verdict: str) -> str:
    """Выбранный в карточке исход SAST: false_positive, true_positive, later или "" (решения нет). Прежние итоги
    («неясно», «Риск принят») – как есть: карточка просит выбрать решение заново."""
    if not decision or decision == "later":
        return decision or ""
    if decision in SAST_OUTCOMES:  # черновик после отказа: значение кнопки карточки, ещё не переведённое в пару
        return decision
    return hub_verdict(decision, final_verdict)


def sast_state_text(state: str, outcome: str) -> str:
    """Почему дефект не готовится – одной строкой (для списков и журнала)."""
    return {"none": "решения нет", "later": "отложено", "missing": "нет в текущей выгрузке",
            "changed": "решение принято по прежней версии находки",
            "verdict_changed": "вердикт модели, по которому принято решение, уже не текущий",
            "code_changed": "код в клоне изменился после решения",
            "not_ready": ("ложное срабатывание – дефект не создаётся" if outcome == "false_positive"
                          else f"прежнее решение «{SAST_OUTCOME_LABELS.get(outcome, outcome)}»")}.get(state, state)


SAST_STATE_HINTS = {
    "missing": "Находки нет в текущей выгрузке: дефект по ней не готовится.",
    "changed": "Решение принято по прежней версии находки: после него сменились правило, файл, строка, код из "
               "выгрузки или папка клона. Сверьте решение и сохраните ещё раз – тогда дефект станет доступен.",
    "verdict_changed": "Вердикт модели, по которому принято решение, уже не текущий (находку разобрали заново или "
                       "новый разбор ещё идёт). Сверьте решение с текущим вердиктом и сохраните ещё раз – тогда "
                       "дефект станет доступен.",
    "code_changed": "Код в клоне не тот, который вы видели при решении: текст дефекта ссылался бы на прежние "
                    "строки. Сверьте решение с текущим кодом и сохраните ещё раз – тогда дефект станет доступен.",
}
SAST_BLOCKED_STATES = tuple(SAST_STATE_HINTS)
# решение записано без отпечатка кода (прежняя версия приложения): «код не тот» было бы неправдой (НТ17)
SAST_CODE_UNKNOWN = ("При решении отпечаток кода не сохранён (решение записано прежней версией приложения): какой код "
                     "вы видели, неизвестно. Сверьте решение с текущим кодом и сохраните ещё раз – тогда дефект станет "
                     "доступен.")


def sast_state_hint(state: str, review: dict | None, default: str = "") -> str:
    """Почему дефект не выдаётся – для панели дефекта и отказа выдачи (SAST_STATE_HINTS); у решения без отпечатка
    кода – SAST_CODE_UNKNOWN."""
    if state == "code_changed" and review and not review.get("code_hash"):
        return SAST_CODE_UNKNOWN
    return SAST_STATE_HINTS.get(state, default)
# Состояния, при которых сохранённый текст для Hub – исторический: решение относится к другому состоянию находки
SAST_HISTORIC_STATES = ("missing", "changed", "verdict_changed", "code_changed")


class DefectBlocked(ReviewRejected):
    """Дефект не готовится: решение по находке не действует (ответ 409, в том числе в разметке страницы)."""


class DefectReload(DefectBlocked):
    """Дефект не готовится, и открытая карточка устарела: находка, её код, вердикт или само решение изменились после
    открытия – скрипт предлагает обновить карточку (reload)."""


def sast_assess(request: Request, project_id: int, review: dict | None, case: dict | None,
                source: dict | None) -> dict:
    """Состояние решения SAST по одному снимку источника: {state, outcome, use_verdict}. Код читается из клона здесь
    же, при размере среза самого решения; use_verdict – рекомендации модели ("Как исправить") применимы к тексту
    дефекта: вердикт привязан к самому решению (человек его видел) и относится к коду, который в клоне сейчас."""
    if source is None:
        return {"state": "missing", "outcome": "", "use_verdict": False}
    settings, mask_key = settings_of(request), mask_key_of(request)
    hashes: dict[int, str] = {}

    chars = int((review or {}).get("code_chars") or 0)

    def code_at(size: int) -> str:
        if size not in hashes:
            hashes[size] = current_code(settings, source, mask_key, size, case=case)[2]
        return hashes[size]

    # Клона нет – код сейчас это срез из базы (ADR-0072, current_code): решение действует, если принято по нему же
    code_now = code_at(chars) if chars and (review or {}).get("code_hash") else ""
    state, outcome = sast_decision_state(review, source, case, code_now)
    use_verdict = False
    if state == "ok" and case and case.get("verdict_id") and review.get("verdict_id") == case["verdict_id"]:
        case_chars = int((case.get("context") or {}).get("max_chars") or CONTEXT_CHARS)
        use_verdict = code_at(case_chars) == case.get("case_hash")
    return {"state": state, "outcome": outcome, "use_verdict": use_verdict}


def capec_names(store: FeedStore, catalog: dict) -> dict[str, str]:
    """Названия шаблонов атак CAPEC, связанных с классами CWE каталога catalog: общий снимок каталога CAPEC без
    копирования (как на странице CAPEC); каталог не загружен – {}."""
    wanted = {p for info in catalog.values() for p in (info.get("attack_patterns") or [])}
    if not wanted:
        return {}
    with store.snapshot():
        records = (store.capec_data(shared=True) or {}).get("records") or {}
        return {p: str((records.get(p) or {}).get("name") or "") for p in wanted if records.get(p)}


def sast_defect(db: Database, settings, store: FeedStore, project_id: int, f: Finding, review: dict | None,
                verdict: Verdict | None, number: int | None = None, shown: set[int] | None = None,
                state: str = "", source: dict | None = None) -> dict:
    """Дефект для Hub по сохранённому решению SAST: {ready, number, stored, title, body, team, hint, subject,
    warnings, note, state}. ready – решение действует (state "ok"): «Подтверждаю дефект» с обоснованием, решение
    принято по текущей версии находки и текущему коду; ложное срабатывание закрывается комментарием (ADR-0089). Текст –
    исход, обоснование и своя рекомендация оператора (ADR-0092): «Как исправить» модели и вид решения («Согласен»
    или «Не согласен») в него не входят; verdict остался от прежних вызовов. Справки по CWE в тексте нет.
    warnings – ссылки на строки в обосновании и рекомендациях, которых нет в показанном коде shown: такой текст
    копируется только после подтверждения человека."""
    # состояние решения: без него (вызов из старого кода или теста) – только вид решения и итог
    state = state or (("ok" if sast_defect_ready(review) else "none") if review else "none")
    key = defect.defect_key_sast(f.hub_id)
    stored = db.defect_number(project_id, key)
    saved_number = stored  # номер в базе как есть: форма сверяет с ним выдачу (number_shown, Б9)
    # та же строка, категория и тот же код в другой кодовой базе уже получили номер – это тот же дефект (ADR-0092)
    mine_cmp = own_code_cmp(db, project_id, f.hub_id)
    all_rows = db.group_rows(project_id, group_key(f), f.hub_id)
    rows, foreign = number_rows(all_rows, mine_cmp, stored, db.defect_assigned_at(project_id, key), f.hub_id)
    foreign_own = stored if stored is not None and stored in foreign else None
    if foreign_own is not None:  # прежний номер находки теперь принадлежит находкам с другим кодом (ADR-0092 п. 8)
        stored = None
    merge = db.group_merge(project_id, group_key(f))  # группа слилась при обновлении схемы (ADR-0095 п. 4)
    if merge:
        plan = merged_number_plan(merged_members(all_rows, mine_cmp, f.hub_id, stored, foreign), f.hub_id,
                                  merge["numbers"], None)
        plan = (plan[0], plan[1], " ".join(x for x in (MERGE_NOTICE.format(date=fmt_ts(merge["merged_at"])),
                                                         plan[2]) if x))
    else:
        plan = group_number_plan(rows, None, stored)
    sibling = plan[0]
    number = number or sibling or db.next_defect_number(project_id)
    outcome_now = hub_verdict(review["decision"], review["final_verdict"]) if review and review.get("decision") else ""
    result = {"ready": state == "ok", "number": number, "stored": stored is not None, "title": "",
              "body": "", "needs_team": not settings.team_name, "subject": "находки", "warnings": [], "note": "",
              "state": state, "sibling_number": sibling if sibling is not None and sibling != stored else None,
              "saved_number": saved_number, "merge_split": bool(merge and plan[2] and "могли быть два дефекта" in plan[2]),
              "group_note": " ".join(x for x in (plan[2], FOREIGN_NUMBER.format(n=foreign_own)
                                                if foreign_own is not None else "") if x),
              "hint": sast_state_hint(state, review,
                      "Ложное срабатывание закрывается коротким комментарием в Hub, дефект не создаётся."
                      if outcome_now == "false_positive" else
                      "Дефект – только для решения «Подтверждаю дефект»: обоснование и рекомендация – ваши, "
                      "рекомендацию модели можно взять за основу.")}
    # ложное срабатывание с номером, оставшимся от прежней выдачи текста, и без дефекта в приложении – номер можно снять:
    # дефект не создаётся, а номер занимает чужой заголовок Hub (db.release_defect_number)
    result["can_release"] = (saved_number is not None and outcome_now == "false_positive"
                             and db.hub_defect_bound(project_id, f.hub_id) is None)
    if result["ready"] and not defect.reason_text(review.get("final_comment") or ""):
        # прежнее решение без обоснования: в Hub ушло бы «Обоснование: Нет информации» (ADR-0089)
        result["ready"] = False
        result["state"] = "no_reason"
        result["hint"] = DEFECT_NEEDS_REASON
    if result["ready"] and not str(settings.team_name or "").strip():
        # стандартная фраза команды – с названием (ADR-0092 п. 11)
        result["ready"] = False
        result["state"] = "no_team"
        result["hint"] = DEFECT_NEEDS_TEAM
    if result["ready"] and not defect.has_recommendation(str(review.get("final_fix") or "")):
        # решение без своей рекомендации (в том числе прежнее «Согласен»): кода модели и общего пункта в Hub нет
        result["ready"] = False
        result["state"] = "no_fix"
        result["hint"] = DEFECT_NEEDS_FIX
    if result["ready"]:
        outcome = hub_verdict(review["decision"], review["final_verdict"])
        fix = str(review.get("final_fix") or "")  # рекомендация – только своими словами оператора (ADR-0092)
        result["title"] = defect.sast_title(number, f)
        result["body"] = defect.sast_body(f, outcome, review["final_comment"], fix, settings.team_name)
        result["warnings"] = line_warnings(review["final_comment"], fix, shown)
    return result


def defect_view(view: dict, review: dict | None, origin: str) -> dict:
    """Дефект для карточки: comment_check – обоснование сохранённого решения написано моделью к другому вердикту и не
    проверено: полный текст в карточке не показывается (выдаётся по отметке «Текст проверен», R092-02);
    review_revision – редакция решения, к которой относится отметка."""
    target = hub_verdict(review["decision"], review["final_verdict"]) if review and review.get("decision") else ""
    view["comment_check"] = bool(view.get("ready") and origin and origin != target)
    view["comment_others"] = []
    view["review_revision"] = int((review or {}).get("revision") or 0)
    return view


def defect_form_problems(db: Database, settings, project_id: int, view: dict) -> dict:
    """Панель «Дефект для Hub» (ручной путь): текст не по требованиям команды – предупреждение с перечнем
    (form_problems), без запрета копирования (ADR-0123 п. 5). Не warnings: те требуют «Предупреждения проверены»."""
    view["form_problems"] = (hub_defect_routes.sast_text_problems(db, settings, project_id, view["body"])
                             if view.get("ready") and view.get("body") else [])
    return view


DEFECT_CONFIRM = "Есть спорные места – проверьте и отметьте «Предупреждения проверены», затем скопируйте ещё раз."


class DefectNeedsConfirm(ValueError):
    """Текст дефекта со спорными местами: копируется только после явного подтверждения человека (confirm=1)."""

    def __init__(self, warnings: list[str]) -> None:
        self.warnings = list(warnings)
        super().__init__(DEFECT_CONFIRM + " " + " ".join(self.warnings))


def defect_error_response(e: ValueError, rejected: type) -> JSONResponse:
    """Ответ JSON на отказ выдать дефект: спорные места – 409 с reason=confirm и списком; решение не готово – 409;
    неверный номер – 400."""
    if isinstance(e, DefectNeedsConfirm):
        return JSONResponse({"ok": False, "detail": str(e), "reason": "confirm", "warnings": e.warnings},
                            status_code=409)
    if isinstance(e, DefectReload):  # карточка устарела: её нужно обновить
        return JSONResponse({"ok": False, "detail": str(e), "reload": True}, status_code=409)
    return JSONResponse({"ok": False, "detail": str(e)}, status_code=409 if isinstance(e, rejected) else 400)


def row_effective(row: dict) -> tuple:
    """Итоговый текст решения находки группы (строка group_rows/group_siblings): обоснование и своя рекомендация
    (ADR-0092 – «Как исправить» модели в текст не подставляется)."""
    outcome = hub_verdict(row["decision"], row["final_verdict"])
    return defect.sast_effective(outcome, row.get("final_comment") or "", row.get("final_fix") or "")


def group_conflict_rows(rows: list[dict], mine: tuple) -> str:
    """Находки той же строки и категории (ADR-0089) – в Hub один дефект или одно решение: итоговое решение и итоговый
    текст (обоснование, у дефекта – и пункты рекомендации, после нормализации) должны совпадать. Сравниваются находки
    текущей выгрузки с действующим решением. mine – defect.sast_effective этой находки. Пояснение для отказа или ""."""
    differ, other = [], []
    for row in rows:
        if row.get("missing") or row.get("decision") not in ("agree", "disagree"):
            continue
        theirs = row_effective(row)
        if theirs[0] != mine[0]:
            other.append(row["hub_id"])
        elif theirs != mine:
            differ.append(row["hub_id"])
    if not (differ or other):
        return ""
    parts = []
    if other:
        parts.append(f"другое решение – у {', '.join(other[:5])}{' и других' if len(other) > 5 else ''}")
    if differ:
        parts.append(f"другой текст – у {', '.join(differ[:5])}{' и других' if len(differ) > 5 else ''}")
    return ("Та же строка и та же категория – в Hub один дефект или одно решение, решение и текст должны совпадать: "
            + "; ".join(parts) + ". Возьмите решение и текст соседней находки (кнопка в карточке) или поправьте её.")


def same_code(rows: list[dict], mine_cmp: str) -> list[dict]:
    """Подгруппа одинакового кода (ADR-0092, п. 3): соседи с тем же отпечатком сравнения code_cmp; находки без
    достоверного отпечатка (пусто) – своя подгруппа «код не сравнивался»."""
    return [r for r in rows if str(r.get("code_cmp") or "") == (mine_cmp or "")]


def own_code_cmp(db: Database, project_id: int, hub_id: str) -> str:
    """Отпечаток сравнения кода самой находки (cases.code_cmp) или "" – среза нет или сравнение недостоверно."""
    return str((db.get_case(project_id, hub_id) or {}).get("code_cmp") or "")


def sibling_states(request: Request, db: Database, project_id: int, rows: list[dict]) -> dict[str, tuple]:
    """Состояние решений соседей той же оценкой, что у своей карточки (ADR-0092, п. 5; sast_assess: версия находки,
    текущий код, при «Согласен» – привязанный вердикт): {hub_id: (state, редакция решения, code_cmp)}. Считается до
    транзакции записи (читает клоны); в транзакции сверяется, что редакции и отпечатки соседей те же."""
    out: dict[str, tuple] = {}
    for r in rows:
        if r.get("missing") or r.get("decision") not in ("agree", "disagree"):
            continue
        hub_id = r["hub_id"]
        review, case = db.get_review(project_id, hub_id), db.get_case(project_id, hub_id)
        source = db.case_input(project_id, hub_id)
        assessed = sast_assess(request, project_id, review, case, source)
        # действующее – по текущей версии находки, коду и вердикту, с исходом SAST и с обоснованием (ADR-0092 п. 5)
        if assessed["state"] in ("ok", "not_ready") and assessed["outcome"] in SAST_OUTCOMES:
            state = "ok" if defect.reason_text((review or {}).get("final_comment") or "") else "no_reason"
        else:
            state = assessed["state"]
        # отпечаток – из тех же прочитанных данных, по которым считалась оценка
        seen = {**r, "revision": (review or {}).get("revision") or 0, "code_cmp": (case or {}).get("code_cmp") or "",
                "case_hash": (case or {}).get("case_hash") or "", "case_verdict_id": (case or {}).get("verdict_id"),
                "review_verdict_id": (review or {}).get("verdict_id"),
                "finding_sig": (review or {}).get("finding_sig") or ""}
        out[hub_id] = (state, *state_print(seen, source_sig(source)))
    return out


def source_sig(source: dict | None) -> str:
    """Текущая версия находки и источника её кода (source_signature) или ""."""
    return source_signature(source) if source else ""


def state_print(row: dict, current_source: str = "") -> tuple:
    """Что определяет оценку соседа: редакция решения, отпечатки кода и среза, привязка вердикта, версия находки, по
    которой принято решение, и текущая версия находки и источника её кода."""
    return (int(row.get("revision") or 0), str(row.get("code_cmp") or ""), str(row.get("case_hash") or ""),
            row.get("case_verdict_id"), row.get("review_verdict_id"), str(row.get("finding_sig") or ""),
            current_source)


GROUP_MOVED = ("Находка с той же строкой и категорией изменилась, пока вы работали с карточкой (решение, код или ответ "
               "модели): обновите карточку и повторите.")


def current_rows(rows: list[dict], states: dict[str, tuple],
                 source_of: Callable[[str], str] | None = None) -> list[dict]:
    """Решения подгруппы, с которыми сверяется своё (ADR-0092, п. 5): все решения «ложное срабатывание» и «дефект»,
    кроме тех, что оценка states признала недействующими (другая версия находки, другой код, другой вердикт) и что с
    оценки не менялись. Соседку, решение которой появилось или изменилось после оценки (её не оценивали в этом
    снимке), проверка в транзакции сравнивает – как раньше: устаревшим её назвать нельзя. Соседка, которую оценили, а
    с тех пор у неё сменились решение, код, срез, привязка вердикта или версия находки, – отказ GROUP_MOVED."""
    keep = []
    for r in rows:
        if r.get("missing") or r.get("decision") not in ("agree", "disagree"):
            continue
        st = states.get(r["hub_id"])
        if st is None:  # решение появилось после оценки: сравнивается, устаревшим его назвать нельзя
            keep.append(r)
            continue
        now = state_print(r, source_of(r["hub_id"]) if source_of else st[-1])
        if tuple(st[1:]) != now:  # оценённое состояние изменилось – оценка недействительна
            raise ReviewRejected(GROUP_MOVED)
        if st[0] == "ok":
            keep.append(r)
    return keep


def number_rows(rows: list[dict], mine_cmp: str, own: int | None,
                own_at: str = "", own_hub: str = "") -> tuple[list[dict], set[int]]:
    """Строки для плана номера подгруппы (ADR-0092, пп. 7–8) и номера, которые принадлежат другим подгруппам. Номер
    принадлежит подгруппе, где его держит больше находок (с этой находкой, если own – её номер); при равенстве –
    подгруппе находки, получившей его раньше всех. Номера других подгрупп в план не входят."""
    holders: dict[int, dict[str, list]] = {}  # номер -> подгруппа -> [держателей, раньше всех, наименьший номер Hub]
    for r in rows:
        if r.get("defect_number") is not None:
            entry = holders.setdefault(int(r["defect_number"]), {}).setdefault(str(r.get("code_cmp") or ""),
                                                                               [0, "~", "~"])
            entry[0] += 1
            entry[1] = min(entry[1], str(r.get("defect_at") or "~"))
            entry[2] = min(entry[2], str(r.get("hub_id") or "~"))
    if own is not None:
        entry = holders.setdefault(int(own), {}).setdefault(mine_cmp or "", [0, "~", "~"])
        entry[0] += 1
        entry[1] = min(entry[1], own_at or "~")
        entry[2] = min(entry[2], own_hub or "~")
    foreign = set()
    for number, by_cmp in holders.items():
        # одинаково из любой карточки: больше держателей, затем раньше получен, затем наименьший номер находки Hub
        owner = min(by_cmp, key=lambda k: (-by_cmp[k][0], by_cmp[k][1], by_cmp[k][2], k))
        if owner != (mine_cmp or ""):
            foreign.add(number)
    mine = [r for r in same_code(rows, mine_cmp)
            if r.get("defect_number") is None or int(r["defect_number"]) not in foreign]
    return mine, foreign


FOREIGN_NUMBER = ("Номер ID{n} принадлежит находкам той же строки и категории с другим кодом: в Hub это другой "
                  "дефект. Выдайте дефект с новым номером.")


def group_conflict(db: Database, project_id: int, f: Finding, outcome: str, comment: str, fix: str) -> str:
    """group_conflict_rows по текущему состоянию группы; fix – рекомендация, которая уйдёт в текст этой находки."""
    mine = defect.sast_effective(outcome, comment, fix)
    return group_conflict_rows(db.group_rows(project_id, group_key(f), f.hub_id), mine)


def sibling_take_fix(row: dict) -> str:
    """Рекомендация для «Взять решение и текст»: своя рекомендация соседки (ADR-0092); у ложного срабатывания
    рекомендации нет."""
    if hub_verdict(row.get("decision") or "", row.get("final_verdict") or "") != "true_positive":
        return ""
    return row.get("final_fix") or ""


def group_take_all(siblings: list[dict], total: int) -> dict | None:
    """«Взять решение и текст у всех» (ADR-0090): показана вся группа (total – число других находок группы), у каждой
    действующее решение «ложное срабатывание» или «дефект» с обоснованием, и итоговые тексты совпадают так же, как их
    сравнивает выдача дефекта (row_effective). Иначе None."""
    if len(siblings) < 2 or len(siblings) != total:
        return None
    for s in siblings:
        if (s.get("decision") not in ("agree", "disagree") or not (s.get("final_comment") or "").strip()
                or hub_verdict(s["decision"], s.get("final_verdict") or "") not in SAST_OUTCOMES):
            return None
    if len({row_effective(s) for s in siblings}) != 1:
        return None
    first = siblings[0]
    return {"outcome": hub_verdict(first["decision"], first.get("final_verdict") or ""),
            "comment": first.get("final_comment") or "", "fix": sibling_take_fix(first)}


def group_number_plan(rows: list[dict], requested: int | None,
                      own: int | None = None) -> tuple[int | None, str, str]:
    """Номер дефекта группы (ADR-0089): (номер, отказ, пометка). rows – остальные находки группы, в том числе
    пропавшие из выгрузки; own – номер, уже сохранённый у этой находки. Пока номера нет ни у одной другой находки
    группы, номер этой находки свободен. Иначе номер группы один: самый частый по всей группе вместе с этой находкой
    (при равенстве – меньший), и выдача допускает только его – так разные номера сходятся к одному. Если в группе
    разные номера, пометка называет, где выдать дефект заново."""
    counts: dict[int, int] = {}
    owners: dict[int, list[str]] = {}
    for row in rows:
        if row.get("defect_number") is not None:
            n = int(row["defect_number"])
            counts[n] = counts.get(n, 0) + 1
            owners.setdefault(n, []).append(row["hub_id"])
    if not counts:
        return (requested if requested is not None else own), "", ""
    if own is not None:
        counts[own] = counts.get(own, 0) + 1
        owners.setdefault(own, []).append("эта находка")
    canonical = max(counts, key=lambda n: (counts[n], -n))
    note = ""
    if len(counts) > 1:
        note = ("У находок той же строки и категории разные номера дефекта: "
                + "; ".join(f"ID{n} – {', '.join(owners[n][:5])}" for n in sorted(counts))
                + f". В Hub это один дефект: выдайте его заново с номером ID{canonical} там, где номер другой.")
    if requested is None or requested == canonical:
        return canonical, "", note
    return None, (f"У находок той же строки и категории номер дефекта ID{canonical}: в Hub это один дефект. "
                  f"Укажите ID{canonical}."), note


MERGE_NOTICE = ("Группа объединена при обновлении приложения {date}: раньше это были разные группы. Номера дефектов "
                "не сводились.")


def merged_number_plan(members: list[dict], own_hub_id: str, history: list[int],
                       requested: int | None) -> tuple[int | None, str, str]:
    """Номер дефекта подгруппы группы, слившейся при обновлении схемы (ADR-0095 п. 4): (номер, отказ, предупреждение).

    members – все участники подгруппы вместе с текущей находкой (own_hub_id) ровно один раз: {hub_id, number}; номер,
    принадлежащий другой подгруппе, сюда уже не передан. history – номера группы на момент слияния. Если подгруппа
    держит два исторических номера и больше – номера не сводятся: допустимы только они, предлагается собственный
    номер находки, иначе самый частый (при равенстве – меньший). Иначе – обычное правило по тому же полному составу:
    номеров нет – номер свободен; есть – допустим только самый частый (при равенстве – меньший)."""
    counts: dict[int, int] = {}
    owners: dict[int, list[str]] = {}
    own = None
    for m in members:
        if m.get("number") is None:
            continue
        n = int(m["number"])
        counts[n] = counts.get(n, 0) + 1
        owners.setdefault(n, []).append("эта находка" if m.get("hub_id") == own_hub_id else str(m.get("hub_id")))
        if m.get("hub_id") == own_hub_id:
            own = n
    kept = sorted(set(counts) & {int(x) for x in history})
    if len(kept) >= 2:
        proposed = own if own in kept else max(kept, key=lambda n: (counts[n], -n))
        warning = ("В Hub могли быть два дефекта – " + "; ".join(f"ID{n} ({', '.join(owners[n])})" for n in kept)
                   + ". Оставьте номер, под которым находка уже заведена в Hub.")
        if requested is None or requested in kept:
            return (proposed if requested is None else requested), "", warning
        return None, ("В этой группе после обновления приложения номера " + ", ".join(f"ID{n}" for n in kept)
                      + ": выберите один из них."), warning
    if not counts:
        return requested, "", ""
    canonical = max(counts, key=lambda n: (counts[n], -n))
    if requested is None or requested == canonical:
        return canonical, "", ""
    return None, (f"У находок той же строки и категории номер дефекта ID{canonical}: в Hub это один дефект. "
                  f"Укажите ID{canonical}."), ""


def merged_members(rows: list[dict], mine_cmp: str, own_hub_id: str, own: int | None,
                   foreign: set[int]) -> list[dict]:
    """Участники подгруппы для merged_number_plan: соседи с тем же кодом и текущая находка; номер другой подгруппы –
    без номера (ADR-0095 п. 4)."""
    members = [{"hub_id": r["hub_id"], "number": None if r.get("defect_number") is None
                or int(r["defect_number"]) in foreign else int(r["defect_number"])}
               for r in same_code(rows, mine_cmp)]
    members.append({"hub_id": own_hub_id, "number": None if own is None or own in foreign else own})
    return members


def sast_entered_text(db: Database, settings, project_id: int, f: Finding, review: dict | None) -> str:
    """Текст, который подтверждает отметка «Внесено в Hub» по находке SAST: у подтверждённого дефекта – тело дефекта
    (команда, обоснование, рекомендация: смена любой части – уже другой текст в Hub), у остальных – текст для Hub по
    сохранённому решению (saved_hub_text)."""
    if not review or not review.get("decision"):
        return ""
    outcome = hub_verdict(review["decision"], review["final_verdict"])
    if f.kind != "SAST" or not defect.sast_ready(outcome):
        return saved_hub_text(f, review, settings.hub_status_map)
    fix = str(review.get("final_fix") or "")
    if not defect.has_recommendation(fix):  # без своей рекомендации текста дефекта нет (ADR-0092)
        return ""
    return defect.sast_body(f, outcome, review["final_comment"], fix, settings.team_name)


def sast_defect_ready(review: dict | None) -> bool:
    """По сохранённому решению SAST можно готовить дефект: решение есть, итог – «истинная» (ADR-0089)."""
    return bool(review and review.get("decision") in DECISIONS and review.get("decision")
                and defect.sast_ready(hub_verdict(review["decision"], review["final_verdict"])))


def defect_ready(review: dict | None) -> bool:
    """По сохранённому решению можно готовить дефект: решение есть, итог – «истинная» или «ложная»."""
    return bool(review and review.get("decision") in DECISIONS and review.get("decision")
                and defect.ready(hub_verdict(review["decision"], review["final_verdict"])))


def pending_run_for(db: Database, project_id: int, hub_id: str) -> dict | None:
    """Незавершённый прогон, в очереди которого эта находка ещё ждёт разбора: {id, state, model} или None."""
    for run in db.active_runs(project_id):
        if hub_id in db.pending_hub_ids(run["id"]):
            return {"id": run["id"], "state": run["state"], "model": run["model"]}
    return None


def question_view(q: dict, verdict_id: Any) -> dict:
    """Вопрос к модели для карточки и для ответа JSON: текст ответа – как есть (оформляет шаблон или скрипт)."""
    stats = q.get("stats") or {}
    data = q.get("answer_data") or {}
    return {"id": q["id"], "question": q.get("question") or "", "answer": q.get("answer") or "",
            "state": q.get("state") or "", "error": q.get("error") or "", "model": q.get("model") or "",
            "created_at": q.get("created_at") or "", "answered_at": q.get("answered_at") or "",
            "verdict_changes": str(data.get("verdict_changes") or ""),
            "tps": stats.get("eval_tps") or None, "seconds": stats.get("total_s") or None,
            "tokens": stats.get("output_tokens") or None, "attempts": stats.get("attempts") or None,
            "old": verdict_id is None or q.get("verdict_id") != verdict_id}


def finding_view(request: Request, project: dict, row: dict, selection: dict[str, str],
                 draft: dict | None = None, ask_draft: str = "") -> dict:
    db = db_of(request)
    settings = settings_of(request)
    pid = project["id"]
    mask_key = mask_key_of(request)
    # Находка и папка с её кодом – одним снимком (их могут поменять параллельно): из него строятся и срез,
    # и версия формы, поэтому решение по показанному коду не сохранится, если источник с тех пор сменился.
    source = db.case_input(pid, row["hub_id"]) or {
        "data": row["data"], "repos_dir": project.get("repos_dir") or "", "folder": ""}
    f = Finding.from_dict(source["data"])
    case = db.get_case(pid, f.hub_id)
    verdict_row = case["verdict"] if case else None
    ctx: CodeContext | None = None
    current_ctx: CodeContext | None = None  # срез текущего клона, когда он сверяется со срезом разбора
    model_ctx: CodeContext | None = None
    stored: dict = {}
    code_changed = False
    # Отпечаток кода, который сейчас в клоне (code_hash, с размером среза code_chars): уходит с формой решения,
    # и решение не сохранится, если к моменту сохранения код снова изменился
    code_hash, code_chars = "", 0
    repo_dir, why = repo_dir_for(settings, {"repos_dir": source["repos_dir"]}, source_codebases(source, f), f)
    # Клона (или файла в нём) нет, а срез сохранён в базе – код находки берётся из базы и не сверяется (ADR-0072)
    snapshot = snapshot_code(settings, source, case) if f.kind == "SAST" else None
    if case and verdict_row:
        stored = case["context"]
        ctx = model_ctx = CodeContext.from_dict(stored)  # ровно то, что видела модель
        # Код в клоне мог измениться после разбора (правки в рабочей копии без смены ревизии): тогда вердикт
        # относится к прежнему коду – карточка предупреждает, а «Проверено» не ставится, пока код не разобран заново
        code_chars = int(stored.get("max_chars") or CONTEXT_CHARS)
        if snapshot is not None:
            code_hash = snapshot[1]
        else:
            current_ctx = build_context(repo_dir, f, max_chars=code_chars, mask_key=mask_key, no_repo_note=why)
            code_hash = case_hash(f, current_ctx)
        code_changed = code_hash != case["case_hash"]
    elif f.kind == "SAST" and snapshot is not None:
        stored = case["context"]
        ctx = snapshot[0]
        code_chars = int(stored.get("max_chars") or CONTEXT_CHARS)
        code_hash = snapshot[1]
    elif f.kind == "SAST":
        code_chars = CONTEXT_CHARS
        ctx = build_context(repo_dir, f, max_chars=code_chars, mask_key=mask_key, no_repo_note=why)
        code_hash = case_hash(f, ctx)
    # Текст, похожий на указания для модели: сохранён вместе со срезом при прогоне; карточка без вердикта
    # (или срез прежней версии) – считается здесь же
    steer_lines: list[int] = []
    steer_fields: list[str] = []
    if ctx is not None:
        ctx = export_fragment_view(f, ctx)  # только представление: отпечатки выше посчитаны по исходному срезу
        steer_lines, steer_fields = steering_of(f, stored, ctx)
    steering = bool(steer_lines or steer_fields)
    verdict = Verdict.from_dict(verdict_row["data"]) if verdict_row else None
    evidence = set(verdict.evidence_lines) if verdict else set()
    # строка, где нашёлся фрагмент из выгрузки (рядом, в комментарии или частично), – своя подсветка; при совпадении
    # на строке срабатывания подсвечена она сама
    # окно показа до 400 строк из клона (ADR-0087): только если оно совпадает с окном модели; отпечатки, сверка и
    # ответ модели – по окну модели
    wide = (display_context(repo_dir, f, ctx, mask_key=mask_key, no_repo_note=why)
            if f.kind == "SAST" and snapshot is None and ctx is not None and not code_changed else None)
    display = wide.ctx if wide is not None else None
    # фрагмент найден дальше ±5 в показанном коде – только для показа: модель разбирала окно вокруг строки сканера
    export_shift_at = None
    if wide is not None:
        export_shift_at = export_fragment_shift(f, display, wide.code)
    elif ctx is not None and ctx.export_line_check == "differs" and not code_changed:
        # код после разбора не менялся. Клон есть – исполняемый код строк по разбору текущего файла с начала; срез
        # из базы без клона – по разбору самого среза, без строк со скрытыми значениями (ограничение ADR-0087)
        code_lines = shift_code_lines(repo_dir, ctx) if snapshot is None else window_code_lines(ctx)
        export_shift_at = export_fragment_shift(f, ctx, code_lines)
    export_at = (ctx.export_line_at if ctx and ctx.export_line_check in ("near", "commented", "partial")
                 else export_shift_at)
    seen = {n for n, _, _ in (ctx.rows() if ctx else []) if n}  # строки, которые видела модель
    # указания и невидимые знаки в строках, которых модель не видела: только подсветка и пояснение – на подстановку
    # её комментария (steering) они не влияют
    steer_outside = sorted(set(steering_lines(display)) - seen) if display is not None else []
    invis_outside = sorted(set(invisible_lines(display)) - seen) if display is not None else []
    code_rows = [{"n": n, "text": text, "target": target, "evidence": bool(n) and n in evidence,
                  "export": bool(n) and n == export_at,
                  "steering": bool(n) and (n in steer_lines or n in steer_outside),
                  "outside": display is not None and n not in seen}
                 for n, text, target in ((display or ctx).rows() if ctx else [])]
    # ссылки на строки в ответе модели и комментарии – по окну модели: строк вне его модель не видела
    shown = set(seen)
    # Под влиянием указаний в коде модель могла написать что угодно: её комментарий не подставляется
    model_comment = verdict.hub_comment if verdict and not steering else ""
    model_comment_for = model_comment_verdict(model_comment, verdict.verdict) if model_comment else ""
    review = db.get_review(pid, f.hub_id)
    assessment = sast_assess(request, pid, review, case, source) if f.kind == "SAST" else \
        {"state": "ok" if defect_ready(review) else "none", "outcome": "", "use_verdict": False}
    reviewed_checked = bool(review and review["reviewed"])
    # рекомендация модели – только основа для кнопки «Взять пункты из рекомендации модели» (ADR-0092): поле само не
    # заполняется, переносятся пункты словами без кода; под влиянием указаний в коде – нет
    model_fix = verdict.fix if verdict and not steering else ""
    # заготовка из ответа модели – с прежней чисткой (ADR-0101: правила заготовок); утверждённые оператором пункты
    # уходят в Hub как написаны
    model_points, model_code_dropped = defect.recommendation_points(model_fix, clean=True)
    if draft is not None:  # решение не сохранилось (страница устарела): форма – с тем, что ввёл человек
        decision, final_verdict, comment = draft["decision"], draft["final_verdict"], draft["comment"]
        final_fix = str(draft.get("fix") or "")
        reviewed_checked = bool(draft["reviewed"])
    elif review is not None:
        decision, final_verdict, comment = review["decision"], review["final_verdict"], review["final_comment"]
        final_fix = str(review.get("final_fix") or "")
        # у SAST исход выбирает человек (ADR-0089, ADR-0097): форма показывает сохранённый итог, новый ответ модели
        # его не меняет; у SCA «Согласен» – это текущий вывод
        if decision == "agree" and verdict and f.kind != "SAST":
            final_verdict = verdict.verdict
    else:
        decision, final_verdict = "", verdict.verdict if verdict else ""
        # в заготовку – только текст, который подходит к вердикту модели; к другому исходу его подставит выбор этого исхода (app.js)
        comment = model_comment if verdict and model_comment_for == verdict.verdict else ""
        final_fix = ""
    preview = hub_text(f, hub_verdict(decision, final_verdict), comment, settings.hub_status_map)
    if draft is None and review and review.get("decision"):  # ровно тот текст, что подтверждает отметка «внесено»
        preview = saved_hub_text(f, review, settings.hub_status_map)
    # Комментарий модели к другому вердикту (смена итогового вердикта, отложено, новый разбор): поле подсвечено,
    # копирование для Hub требует правки или явного подтверждения. «Согласен» – это вердикт модели, даже если
    # в сохранённом решении стоит прежний
    known_verdicts = db.finding_verdicts(pid, f.hub_id)  # Э6: одна выборка на обе сверки комментария
    comment_for = comment_origin(db, case, review, comment, known=known_verdicts)
    # Два признака «комментарий модели к другому вердикту». Для формы – по тому, что уйдёт при сохранении как есть
    # («Согласен» у SCA – это текущий вердикт, у SAST – сохранённый исход). Для предпросмотра и отметки «внесено» – по
    # сохранённому решению: именно его текст подтверждает отметка; у черновика и формы без решения они совпадают
    effective = verdict.verdict if decision == "agree" and verdict and f.kind != "SAST" else final_verdict
    comment_stale = bool(comment_for) and comment_for != hub_verdict(decision, effective)
    if draft is None and review and review.get("decision"):
        saved_stale = bool(comment_for) and comment_for != hub_verdict(review["decision"], review["final_verdict"])
    else:
        saved_stale = comment_stale
    # Предпросмотр – только текст, который можно нести в Hub (ADR-0088): без решения или с обоснованием модели к другому
    # вердикту вместо текста – пояснение (сам текст даёт только копирование после решения или отметки «Текст проверен»)
    preview_note = ""
    if draft is not None:
        preview_note = "Решение не сохранено: текст появится после сохранения."
        preview = ""
    elif not decision:
        preview_note = "Текст появится после выбора и сохранения решения: без решения ответ модели в Hub не уходит."
        preview = ""
    elif saved_stale:
        preview_note = ("Текст не показан: обоснование написано моделью к другому вердикту. Поправьте комментарий и "
                        "сохраните решение или отметьте «Текст проверен» и скопируйте текст.")
        preview = ""
    # Решение принято по прежнему ответу модели (новый разбор после решения): решение остаётся в силе (ADR-0097),
    # карточка говорит, что разбор новый и совпадает ли он с решением человека
    current_verdict_id = case["verdict_id"] if case and case.get("verdict_id") else None
    verdict_changed = bool(review and review.get("verdict_id") and current_verdict_id
                           and review["verdict_id"] != current_verdict_id)
    own_outcome = sast_outcome(review["decision"], review["final_verdict"]) if review and review.get("decision") else ""
    verdict_disagrees = bool(f.kind == "SAST" and verdict and own_outcome in SAST_OUTCOMES
                             and verdict.verdict in SAST_OUTCOMES and verdict.verdict != own_outcome)
    model_history = history_view(db.finding_model_history(pid, f.hub_id), current_verdict_id,
                                 (review or {}).get("verdict_id"), str((case or {}).get("case_hash") or ""),
                                 own_outcome, steering) if f.kind == "SAST" else None
    for h in (model_history or {}).get("rows", []):  # чей это ответ: профиль исполнителя (ADR-0102)
        h["executor"] = executor_label(db, db.verdict_execution(h["id"]))
    filters = selection_filters(selection)
    total, reviewed = db.count_unreviewed(pid, filters)
    sel_query = urlencode(selection, doseq=True)
    saved_row = None
    saved = request.query_params.get("saved", "")
    if COUNT.fullmatch(saved) and int(saved) != row["id"]:
        saved_row = db.get_finding(pid, int(saved))
    sast = f.kind == "SAST"
    # модели – того профиля, которым пойдёт запрос (ADR-0102): вопрос – профилем разбора (иначе профилем проекта),
    # разбор и пересмотр – новым прогоном на профиле проекта
    verdict_execution = db.verdict_execution(case.get("verdict_id")) if case else None
    # профиль вопроса – по тому же правилу, что и его обработка (ask.answer_execution): ответ сборки образа ВМ и ответ
    # до 0.9.12 – профилем проекта
    asked_execution = ask.answer_execution(db, case.get("verdict_id")) if case else None
    verdict_profile = db.get_provider(asked_execution["provider_id"]) if asked_execution else None
    project_profile = profile_for(request, project)
    run_info = models_of(request, profile=project_profile) if sast else {"models": [], "error": ""}
    run_models = run_info["models"]
    models = (models_of(request, profile=verdict_profile)["models"]
              if verdict_profile and sast else run_models)
    verdict_model = verdict_row["model"] if verdict_row else ""
    # сервер не отдаёт список моделей (Messages API, 404/405/501) – в списке только имя из профиля: модель прежнего
    # разбора добавляется с пометкой, иначе после смены имени в профиле её не выбрать (ревью Codex, круг 17)
    if verdict_model and models and all(m.get("source") == "profile" for m in models) \
            and verdict_model not in [m["name"] for m in models]:
        models = [*models, {"name": verdict_model, "source": "verdict"}]
    names = [m["name"] for m in models]
    run_names = [m["name"] for m in run_models]
    ask_model = verdict_model if verdict_model in names else default_model(
        settings, models, project, verdict_profile if verdict_profile else project_profile)
    analyze_model = default_model(settings, run_models, project, project_profile)
    # «Пересмотреть вердикт»: та же модель на том же коде ответит так же – по умолчанию предлагается другая:
    # модель проекта, из настроек, затем проверенные модели из README и лишь потом остальные по списку
    # имя модели: у удалённых API – как есть, у Ollama – без регистра и «:latest» (ADR-0106 п. 7)
    name_of = same_model(str((project_profile or {}).get("kind") or "ollama"))
    second = next((n for n in (project.get("model") or "", settings.default_model, *SECOND_OPINION_MODELS,
                               *run_names)
                   if n in run_names and name_of(n) != name_of(verdict_model)), "")
    reanalyze_model = second or (verdict_model if verdict_model in run_names else analyze_model)
    questions = [question_view(q, current_verdict_id) for q in db.list_questions(pid, f.hub_id)] if sast else []
    # та же строка и категория в других местах (ADR-0089): соседки с текстом для «Взять решение и текст»
    # подгруппа одинакового кода (ADR-0092): одно решение, один текст, общий номер; соседи с другим кодом –
    # отдельным списком, на выдачу не влияют
    all_siblings = db.group_siblings(pid, group_key(f), f.hub_id, limit=1_000_000) if sast else []
    mine_cmp = str((case or {}).get("code_cmp") or "") if sast else ""
    states = sibling_states(request, db, pid, all_siblings) if sast else {}
    shown_siblings = [{**s, "take_fix": sibling_take_fix(s), "state": (states.get(s["hub_id"]) or ("none",))[0]}
                      for s in all_siblings if not s.get("missing")]
    siblings = [s for s in shown_siblings if str(s.get("code_cmp") or "") == mine_cmp][:50]
    group_other = [s for s in shown_siblings if str(s.get("code_cmp") or "") != mine_cmp][:50]
    group_total = len([s for s in shown_siblings if str(s.get("code_cmp") or "") == mine_cmp])
    group_other_total = len(shown_siblings) - group_total
    near, near_total = db.near_category(pid, f.to_dict(), mine_cmp) if sast else ([], 0)
    # Подставляется только действующее решение оператора; номер и группа не переносятся.
    for neighbor in near:
        review_fields = db.get_review(pid, neighbor["hub_id"]) or {}
        for key in ("decision", "final_verdict", "final_comment", "final_fix"):
            neighbor[key] = review_fields.get(key) or ""
    near_states = sibling_states(request, db, pid, near) if sast else {}
    for neighbor in near:
        neighbor["state"] = (near_states.get(neighbor["hub_id"]) or ("none",))[0]
        neighbor["take_fix"] = sibling_take_fix(neighbor)
    defect_lines = defect_shown_lines(request, pid, f, case, own=shown) if sast else shown
    return {
        "project": project, "row": row, "f": f, "ctx": ctx, "code_rows": code_rows, "shown_lines": shown,
        "verdict": verdict, "verdict_meta": verdict_row, "review": review, "decision": decision,
        "final_verdict": final_verdict, "comment": comment, "model_comment": model_comment,
        "model_comment_for": model_comment_for, "target_hidden": target_line_hidden(f, ctx),
        "reviewed_checked": reviewed_checked, "is_draft": draft is not None,
        "hub_preview": preview, "hub_preview_note": preview_note, "saved_stale": saved_stale, "steer_lines": steer_lines, "steer_fields": steer_fields,
        "invis_lines": invisible_lines(ctx) if ctx is not None else [],
        "ctx_note": card_note(ctx) if ctx else "", "code_changed": code_changed,
        "code_reason": code_reason(ctx) if ctx else "",
        # код из файла – из базы приложения вместо клона (ADR-0072): клона или файла в нём нет, срез сохранён
        "code_from_db": snapshot is not None and snapshot[0].status == "ok",
        "no_clone": bool(verdict and ctx is not None and ctx.status != "ok"),
        # строка из выгрузки – так же, как в промпте (у находки о секрете в коде скрыта целиком); при снятом флажке
        # проекта «маскировать при показе» – исходная (dev14, ADR-0141: модели – всегда с маской)
        "export_line": mask_display.export_line(f, mask_key, project),
        # состояние относительно Hub (dev15, бэклог 88): та же функция, что у синхронизации; считается одна находка
        "hub_state": hub_state.project_states(db, project, settings.hub_url,
                                              keys=[hub_state.issue_key(row)])["by_hub_id"].get(f.hub_id),
        # разбор устарел: текущий срез клона (с масками) вторым блоком и строки, которые отличаются (бэклог 112)
        "current_code": mask_display.current_slice(model_ctx, current_ctx) if code_changed else None,
        "mask_shown": mask_display.masked(project),
        "plain_ctx": mask_display.plain_context(project, repo_dir, f, why),
        # путь к файлу на этом компьютере и ссылка «Открыть в VS Code» – только у файла, найденного в клоне (ADR-0156)
        "editor": editor_target(settings, repo_dir, current_ctx if current_ctx is not None else ctx,
                                snapshot is not None and snapshot[0].status == "ok"),
        # при снятом флажке метки в текстах модели – значениями из текущего файла клона и выгрузки (бэклог 111)
        "label_values": (label_values := mask_display.label_values(
            project, repo_dir, f, mask_key, why, also=[lambda: masked_extra(f, mask_key)])),
        "labels_note": mask_display.labels_note(project, verdict, label_values),
        # ADR-0080: уверенность при differs ограничена с sast-v6 – у прежних вердиктов ограничения нет. ADR-0082: при
        # commented/partial – только если ограничение действительно применено к этому вердикту (вердикт, полученный
        # до уточнённой сверки, его не получал)
        "confidence_capped": capped_confidence(verdict, verdict_row, ctx),
        "export_scope": (export_fragment_scope(str(f.snippet or ""), ctx.text_at(ctx.export_line_at))
                         if ctx is not None and ctx.export_line_check in ("match", "near") and ctx.export_line_at
                         else ""),
        "export_shift_at": export_shift_at,
        "display_wide": display is not None, "steer_outside": steer_outside, "invis_outside": invis_outside,
        "confidence_max": DIFFERS_CONFIDENCE_MAX,
        "confidence_raw": (verdict_row.get("raw") or {}).get("confidence") if verdict_row else None,
        "extra": masked_extra(f, mask_key) if mask_display.masked(project) else {k: str(v) for k, v in f.extra.items()},
        "prev_id": queue_neighbor(db, pid, row, selection, "prev", hub_ids=(hub_ids := hub_sync_ids(request, project, selection))),
        "next_id": queue_neighbor(db, pid, row, selection, hub_ids=hub_ids),
        "walk_all": walks_all(selection),
        "progress": {"total": total, "reviewed": reviewed},
        "selection": selection, "sel_query": sel_query, "selection_labels": selection_labels(selection),
        "saved_row": saved_row,
        "need_texts": {"reason": RISK_NEEDS_REASON, "verdict": NEED_VERDICT,
                       "reason_fp": SAST_NEED_REASON["false_positive"], "reason_tp": SAST_NEED_REASON["true_positive"],
                       "fix": need_fix_text(model_fix, model_points,
                                            bool(model_history and model_history["earlier_points"]))},
        "status_map": settings.hub_status_map,
        # «Отправить в Hub» (ADR-0115): доступна ли отправка статуса, последняя операция, быстрые сроки
        # отпечаток – только у карточки, показавшей сохранённое решение: у черновика (ответ 409 на устаревшую форму)
        # в форме введённое, а не сохранённое – отпечатка нет, отправка откажет
        "hub_status_now": (status_now := hub_status_routes.status_now(db, project, settings, f)),
        "entered_scope_note": hub_status_routes.entered_scope_note(review, status_now),
        "hub_send": (hub_status_routes.card_context(
            request, project, f.hub_id, saved_hub_text(f, review, settings.hub_status_map) if draft is None else "",
            note=hub_status_routes.DRAFT_NOTE if draft is not None else "") if f.kind == "SAST" else None),
        # «Создать дефект в Hub» (ADR-0120): состояние дефекта из карточки по этой находке и предпросмотр
        # с 0.9.23 (ADR-0121) – и привязка находки к дефекту, пометка «решение изменено после создания дефекта» (по
        # отпечатку текста сохранённого решения, как у отметки «Внесено в Hub»), «Привязать к дефекту»
        "hub_defect": hub_defect_routes.card_context(
            request, project, f.hub_id,
            current_hash=text_hash(sast_entered_text(db, settings, pid, f, review)) if review and review.get("decision")
            else "") if sast else None,
        # версия находки и папки с её кодом из того же снимка, по которому построен срез
        "finding_version": source_version(source),
        "shown_verdict_id": current_verdict_id or "",
        # редакция решения, которую видел человек: решение из устаревшей вкладки не затрёт более новое
        "review_revision": int(review["revision"]) if review else 0,
        "code_hash": code_hash, "code_chars": code_chars,
        # объяснение для человека: версия ответа модели, уверенность словами
        "is_v3": bool(verdict and (verdict.why or verdict.what_code_does or verdict.check_by_eye or verdict.terms)),
        "confidence_words": confidence_label(verdict.confidence) if verdict else "",
        "comment_for": comment_for, "comment_stale": comment_stale, "verdict_changed": verdict_changed,
        "verdict_disagrees": verdict_disagrees, "model_history": model_history,
        "verdict_executor": executor_label(db, verdict_execution) if verdict_row else "",
        "decision_in_force": assessment["state"] in ("ok", "not_ready", "later"),
        # ссылки «строка N» в комментарии для Hub на строки, которых нет в показанном коде (выдуманный довод)
        "comment_missing_lines": missing_line_refs(comment, defect_lines) if sast else [],
        # вопросы к модели и повторный разбор
        "questions": questions, "models": models, "ask_model": ask_model, "ask_draft": ask_draft,
        "reanalyze_model": reanalyze_model, "run_models": run_models, "analyze_model": analyze_model,
        "run_models_error": run_info.get("error") or "",
        "code_profile_remote": str((project_profile or {}).get("kind") or "ollama") != "ollama",
        # внешний провайдер: разбор, пересмотр и вопрос – платные запросы (ADR-0104); профиль вопроса – профиль ответа
        "code_profile_external": str((project_profile or {}).get("trust") or "") == "external",
        "code_profile_name": str((project_profile or {}).get("name") or ""),
        "catalog_example": f.kind == "SCA-license" and _catalog_project(db, project["id"]),
        "ask_profile_external": str(((verdict_profile or project_profile) or {}).get("trust") or "") == "external",
        "ask_profile_name": str(((verdict_profile or project_profile) or {}).get("name") or ""),
        **ask_busy_flags(db, settings_of(request), pid, (case or {}).get("verdict_id") if sast else None),
        "pending_run": pending_run_for(db, pid, f.hub_id) if sast else None,
        "prompt_version": PROMPT_VERSION, "short_explanation_versions": SHORT_EXPLANATION_VERSIONS,
        "entered": bool(review and review.get("entered_hub")),
        # что изменилось в тексте после отметки (О8): None – отметка до 0.9.9, состав неизвестен
        "entered_reasons": entered_change_reasons(settings, review) if sast else None,
        # отметка общим комментарием из списка (ADR-0119): текст в Hub другой по замыслу, это не «текст изменился»
        "entered_bulk": bool(review and review.get("entered_hub")) and entered_by_bulk(review),
        "entered_changed": (entered_text_changed(review, sast_entered_text(db, settings, pid, f, review))
                            and not entered_by_bulk(review)
                            and not entered_format_updated(review, sast_entered_text(db, settings, pid, f, review),
                                                           saved_legacy_texts(f, review, settings.hub_status_map, settings.team_name))),
        "entered_format_updated": entered_format_updated(review, sast_entered_text(db, settings, pid, f, review),
                                                         saved_legacy_texts(f, review, settings.hub_status_map, settings.team_name)),
        "group_total": group_total, "group_other_total": group_other_total,
        # прежние редакции текста решения (О5): что было в комментарии и рекомендации до последней правки
        "text_history": (history := db.review_text_history(pid, f.hub_id) if sast else ([], 0))[0],
        "text_history_total": history[1],
        # вся группа (с этой находкой и находками с другим кодом) – в списке находок отбором по ключу группы
        "group_list_url": f"/projects/{pid}/findings?group={row['id']}&missing=no",
        "group_size": len(shown_siblings) + (0 if row.get("missing") else 1),  # как в списке по ссылке (missing=no)
        # подсказка «Рядом та же категория» (ADR-0095 п. 6): сведения, а не группа – решение и номер не меняет
        "near": near,
        "near_total": near_total,
        # два исхода SAST (ADR-0089): выбранный исход, рекомендация дефекта, та же строка и категория в других местах
        "sast_outcome": sast_outcome(decision, final_verdict) if sast else "",
        "legacy_outcome": (sast and decision not in ("", "later")
                           and sast_outcome(decision, final_verdict) not in SAST_OUTCOMES),
        "final_fix": final_fix, "model_fix": model_fix, "model_points": "\n".join(model_points),
        "model_code_dropped": model_code_dropped,
        "siblings": siblings, "group_other": group_other, "group_compared": bool(mine_cmp),
        # группа слилась при обновлении схемы 20 (ADR-0095 п. 4): уведомление – в карточке всегда
        "group_merge_notice": (MERGE_NOTICE.format(date=fmt_ts(group_merge["merged_at"]))
                               if sast and (group_merge := db.group_merge(pid, group_key(f))) else ""),
        "group_take_all": group_take_all([s for s in siblings if s["state"] == "ok"], group_total) if sast else None,
        "entered_hash": (text_hash(sast_entered_text(db, settings, pid, f, review))
                         if sast and review and review.get("decision") else ""),
        "entered_unconfirmed": entered_unconfirmed(review),
        # класс уязвимости из каталога CWE (страница «Справочники») и дефект для Hub
        "cwe_info": store_of(request).cwe_info(f.cwe) if sast else {},
        "defect": defect_form_problems(db, settings, pid, defect_view(
            sast_defect(db, settings, store_of(request), pid, f, review,
                        verdict if assessment["use_verdict"] else None, shown=defect_lines or None,
                        state=assessment["state"], source=source),
            review, comment_for if draft is None else comment_origin(
                db, case, review, (review or {}).get("final_comment") or "", known=known_verdicts)))
        if sast else None,
        # сохранённый текст для Hub относится к другому состоянию находки: показывается как исторический
        "hub_historic": bool(assessment["state"] in SAST_HISTORIC_STATES and review and review.get("decision")),
        "has_decision": bool(review and review.get("decision")),
        # числа на вкладках проекта
        "counts": db.count_findings(pid), "review_stats": db.review_stats(pid),
    }


_form_int = form_int


def check_code(request: Request, project_id: int, f: Finding, case: dict | None, shown_hash: str,
               shown_chars: int | None) -> dict:
    """Сверка кода находки с тем, что видел человек, перед сохранением решения.

    Код в клоне читается заново (так же, как его строит прогон) и сравнивается с отпечатком shown_hash со страницы:
    другой – код изменился, пока карточка была открыта (StaleReview, reason="code"). Отпечаток считается при том же
    размере среза, что на странице (shown_chars), иначе – как у среза модели. stale_verdict – код уже не тот,
    что разбирала модель (её вердикт – про прежний код): «Согласен» не сохраняется, два исхода SAST сохраняются
    «Не согласен», отметку «Проверено» это не снимает (ADR-0147).
    Возвращает {"hash", "chars", "stale_verdict"}; у находки без кода (не SAST) hash – None."""
    if f.kind != "SAST":
        return {"hash": None, "chars": 0, "stale_verdict": False}
    source = db_of(request).case_input(project_id, f.hub_id)
    if source is None:
        raise StaleReview("находки нет", "source")
    settings, mask_key = settings_of(request), mask_key_of(request)
    case_chars = int((case or {}).get("context", {}).get("max_chars") or CONTEXT_CHARS)
    chars = shown_chars if shown_chars is not None and MIN_CONTEXT_CHARS <= shown_chars <= CONTEXT_CHARS \
        else case_chars
    _, _, current = current_code(settings, source, mask_key, chars, case=case)
    if shown_hash and current != shown_hash:
        raise StaleReview("код изменился", "code")
    stale_verdict = False
    if case and case.get("verdict_id"):
        at_case = current if chars == case_chars else current_code(settings, source, mask_key, case_chars,
                                                                   case=case)[2]
        stale_verdict = at_case != case["case_hash"]
    return {"hash": current, "chars": chars, "stale_verdict": stale_verdict}


def check_shown(db: Database, project_id: int, f: Finding, case: dict | None, shown_version: str,
                shown_verdict: int | None, shown_revision: int | None) -> None:
    """Что видел человек – находка, вердикт модели и редакция решения – не устарело (иначе StaleReview).
    Страница без редакции (открытая до обновления приложения) проверяется по версии находки и вердикту."""
    if db.review_version(project_id, f.hub_id) != shown_version:
        raise StaleReview("страница устарела", "source")
    current_verdict = case["verdict_id"] if case and case.get("verdict_id") else None
    if current_verdict != shown_verdict:
        raise StaleReview("страница устарела", "verdict")
    old = db.get_review(project_id, f.hub_id)
    if shown_revision is not None and (int(old["revision"]) if old else 0) != shown_revision:
        raise StaleReview("страница устарела", "revision")


def card_response(request: Request, project_id: int, finding_id: int, error: str = "",
                  status_code: int = 200, draft: dict | None = None, ask_draft: str = "",
                  reveal_revision: int | None = None, defect_extra: dict | None = None,
                  defect_bound: str = "") -> HTMLResponse:
    project = project_or_404(request, project_id)
    row = db_of(request).get_finding(project_id, finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Находка не найдена: возможно, её нет в новой выгрузке.")
    view = finding_view(request, project, row, read_selection(request.query_params), draft, ask_draft)
    # текст выдан по отметке «Текст проверен» (форма без скрипта): раскрывается, только если решение в карточке – та же
    # редакция, по которой текст выдан (между выдачей и чтением карточки его могли сохранить заново в другой вкладке)
    defect_now = view.get("defect")
    if reveal_revision is not None and defect_now and defect_now.get("review_revision") == reveal_revision:
        defect_now["comment_check"] = False
    if defect_extra and defect_now:  # отказ выдачи без скрипта: предупреждения и введённый номер – в форме дефекта
        defect_now.update(defect_extra)
    from app.routes.capec import related_context, cwe_values
    view['capec_context'] = related_context(request, cwe_values(row['data'].get('cwe',[])), project_id)
    # отказ «находка в дефекте, созданном в Hub» без скрипта (ADR-0121 п. 2): флажок подтверждения в форме решения открыт
    return render(request, "findings/card.html", {**view, "error": error, "defect_bound_open": defect_bound, "back_url": worklists.return_url(request, f"/projects/{project_id}/findings")}, status_code)


def finding_or_404(request: Request, project_id: int, finding_id: int) -> dict:
    project_or_404(request, project_id)
    row = db_of(request).get_finding(project_id, finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Находка не найдена.")
    return row


def wants_json(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "")


def progress_of(db: Database, project_id: int, selection: dict[str, str]) -> dict:
    total, done = db.count_unreviewed(project_id, selection_filters(selection))
    return {"total": total, "reviewed": done}


def capped_confidence(verdict: Verdict | None, verdict_row: dict | None, ctx: CodeContext | None) -> bool:
    """Показать «уверенность ограничена»: вердикт версии с потолком уверенности (sast-v6 и после, ADR-0080) и сверка,
    не подтверждающая фрагмент. По версии сохранённого ответа, а не по текущему промпту приложения (ревью dev20)."""
    if not (verdict and verdict_row and ctx is not None
            and verdict_row.get("prompt_version") in DIFFERS_CAP_VERSIONS):
        return False
    if ctx.export_line_check == "differs":
        return True
    if ctx.export_line_check in UNCONFIRMED_EXPORT_CHECKS:
        try:
            raw = float((verdict_row.get("raw") or {}).get("confidence"))
        except (TypeError, ValueError):
            return False
        return raw > verdict.confidence
    return False

# ============================================================================ адреса: список и карточка



def ask_busy_flags(db, settings, project_id: int, verdict_id) -> dict:
    """Подсказки занятости модели в карточке – по группе права исполнителя вопроса (ADR-0104 п. 6)."""
    executor = ask.card_executor(db, settings, project_id, verdict_id)
    return {"ask_busy": ask.busy(executor), "ask_run_busy": ask.run_busy(executor)}

@router.get("/projects/{project_id}/findings", response_class=HTMLResponse)
def findings_page(request: Request, project_id: int, error: str = ""):
    project = project_or_404(request, project_id)
    q = request.query_params
    selection = read_selection(q)
    filters = {k: selection.get(k, "") for k in SELECTION_KEYS}
    filters["hub_status"] = tuple(selection.get("hub_status") or ())
    try:
        page = max(1, int(q.get("page", "1")))
    except ValueError:
        page = 1
    db = db_of(request)
    sel = selection_filters(selection)
    presentation = worklists.options(q, ("severity_asc", "severity_desc"))
    filters.update(presentation)
    descriptors = db.finding_descriptors(project_id, sel)
    # состояние относительно Hub (dev15, бэклог 88): значок в строке и отбор – одним расчётом на страницу
    hub_states = hub_state.project_states(db, project, settings_of(request).hub_url)
    hub_ids = hub_sync_ids(request, project, selection, hub_states)
    if hub_ids is not None:
        descriptors = [d for d in descriptors if d["hub_id"] in hub_ids]
    from app import defect_links
    defect_by_hub = defect_links.by_hub_id(db, project_id)  # дефекты приложения – строкам и группам
    defect_links.attach(descriptors, defect_by_hub)
    for row in descriptors:  # столбцы обзора групп (план dev7, раздел 3)
        row["buckets"] = {worklists.finding_bucket(row.get("decision"), row.get("final_verdict"),
                                                   defect_links.in_defect(row.get("defects") or [])): 1}
        row["entered"] = int(bool(row.get("entered_hub")))
    w = worklists.table(worklists.sort_findings(descriptors, presentation["sort"]), filters,
                        path=f"/projects/{project_id}/findings", default_size=PAGE_SIZE, kind="findings",
                        sorts={"": "Как в отчёте", "severity_desc": "Критичность ↓", "severity_asc": "Критичность ↑"})
    ids = tuple(r["id"] for r in w["rows"])
    shown, _ = db.list_findings(project_id, ids=ids, limit=w["size"])
    order = {fid: n for n, fid in enumerate(ids)}
    rows = sorted(shown, key=lambda row: order[row["id"]])
    defect_links.attach(rows, defect_by_hub)
    # разборы моделью по текущему срезу: сколько ответов и расходятся ли модели (ADR-0097) – одной выборкой
    answer_counts = db.model_answer_counts(project_id, [r["hub_id"] for r in rows if r.get("kind") == "SAST"],
                                           PROMPT_VERSION)
    total, page, pages = w["total"], w["page"], w["pages"]
    if worklists.integer(q.get("page"), 1) > pages:
        clean = {k: v for k, v in {**selection, **presentation}.items() if v and k != "page"}
        return redirect(f"/projects/{project_id}/findings?{query(clean, page=pages)}")
    list_profile = profile_for(request, project)
    models = models_of(request, profile=list_profile)
    card_query = "?" + query({**selection, **presentation, "back": w["url"](page=page)})
    active_preset = next((label for label, params in PRESETS
                          if selection == params), "")
    base = f"/projects/{project_id}/findings"

    def link(**changes: str) -> str:
        """Адрес списка с текущими фильтрами и заменой части из них (страница – первая)."""
        q = query(filters, page="", **changes)
        return f"{base}?{q}" if q else base

    filter_groups = [{"key": key, "label": label,
                      "chips": [{"label": text, "href": link(**{key: value}), "active": filters[key] == value}
                                for value, text in options]}
                     for key, label, options in FILTER_GROUPS]
    # Тот же действующий статус, что в карточке: подтверждение, принятая сверка, выгрузка.
    statuses = db.finding_statuses(project_id)
    chosen = filters["hub_status"]
    if statuses or chosen:
        # чипы переключают значение по одному: выбранное снимается, новое добавляется (бэклог 99)
        def toggled(value: str) -> tuple[str, ...]:
            return tuple(s for s in chosen if s != value) if value in chosen else (*chosen, value)
        filter_groups.insert(1, {"key": "hub_status", "label": "Статус Hub", "chips": [
            {"label": "любой", "href": link(hub_status=()), "active": not chosen},
            *({"label": s, "href": link(hub_status=toggled(s)), "active": s in chosen}
              for s in dict.fromkeys((*statuses, *chosen)))]})
    filter_flags = [{"label": text, "href": link(**{key: "" if filters[key] else value}), "active": bool(filters[key])}
                    for key, value, text in FILTER_FLAGS]
    stats = db.review_stats(project_id)
    # отбор «одна группа»: находка, по ключу которой отобран список, – для строки над таблицей
    group_anchor = db.get_finding(project_id, int(selection["group"])) if selection.get("group") else None
    # непроверенных SAST нет, а в SCA есть: путь «продолжить разбор» ведёт дальше, на SCA
    sca_left = max(0, int(stats.get("sca") or 0) - int(stats.get("sca_reviewed") or 0))
    sca_unreviewed = (db.neighbor_unreviewed(project_id, -1, "next", kinds=("SCA",)) if sca_left else None)
    return render(request, "findings/list.html", {
        "error": error, "group_anchor": group_anchor, "group_lost": bool(selection.get("group")) and not group_anchor,
        "group_clear": link(group=""),
        "sca_unreviewed": sca_unreviewed, "sca_left": sca_left,
        "project": project, "rows": rows, "total": total, "page": page, "pages": pages, "filters": filters, "worklist": w,
        "answer_counts": answer_counts,
        "codebases": [c for c in db.codebase_counts(project_id)], "models": models["models"],
        "default_model": default_model(settings_of(request), models["models"], project, list_profile),
        "models_error": models.get("error") or "", "list_profile_name": str(list_profile.get("name") or ""),
        "list_profile_remote": str(list_profile.get("kind") or "ollama") != "ollama",
        "prev_url": f"?{query(filters, page=page - 1)}" if page > 1 else "",
        "next_url": f"?{query(filters, page=page + 1)}" if page < pages else "",
        "active_runs": db.active_runs(project_id), "review_stats": stats,
        "counts": db.count_findings(project_id),  # числа на вкладках проекта
        "hub_step": hub_onboarding.state(db, project, settings_of(request).hub_url, light=True),
        "hub_states": hub_states["by_hub_id"], "hub_summary": hub_states["summary"],
        "card_query": card_query, "queue_query": card_query, "presets": [(label, query(presentation, **params, page=""), label == active_preset)
                                              for label, params in PRESETS],
        "first_unreviewed": queue_neighbor(db, project_id, None, {**selection, **presentation},
                                           descriptors=descriptors),
        "walk_all": walks_all(selection), "selection_labels": selection_labels(selection),
        "has_filters": bool(selection), "filter_groups": filter_groups, "filter_flags": filter_flags,
        # подробные фильтры свёрнуты; открыты, когда что-то выбрано, – так видно, что действует
        "filters_open": bool(selection), "active_filters": sum(1 for v in filters.values() if v),
        # для формы кодовой базы: прочие фильтры – скрытыми полями
        "other_filters": [(k, item) for k, v in filters.items() if v and k not in ("cb", "page")
                          for item in (v if isinstance(v, (list, tuple)) else (v,))],
    })


@router.get("/projects/{project_id}/findings/by-id")
def finding_by_hub_id(request: Request, project_id: int, hub_id: str = ""):
    project_or_404(request, project_id)
    row = db_of(request).get_finding_by_hub_id(project_id, hub_id.strip())
    if row is None:
        return findings_page(request, project_id, "Находка с таким ID не найдена.")
    section = "sca/findings" if row["kind"] == "SCA" else "findings"
    return redirect(f"/projects/{project_id}/{section}/{row['id']}")


@router.get("/projects/{project_id}/findings/{finding_id}", response_class=HTMLResponse)
def finding_page(request: Request, project_id: int, finding_id: int):
    row = db_of(request).get_finding(project_id, finding_id)
    if row is not None and row["kind"] == "SCA":  # у находки SCA своя карточка – в разделе SCA
        return redirect(f"/projects/{project_id}/sca/findings/{finding_id}")
    return card_response(request, project_id, finding_id)


@router.get("/projects/{project_id}/findings/{finding_id}/state")
def finding_state(request: Request, project_id: int, finding_id: int):
    """Состояние карточки для скрипта: вердикт модели, ожидание в очереди прогона, отметки решения, занята ли
    модель вопросом. Открытая карточка опрашивает его, пока находка ждёт разбора (data-poll): done и reload –
    разбор закончен, карточку пора обновить."""
    row = finding_or_404(request, project_id, finding_id)
    db = db_of(request)
    case = db.get_case(project_id, row["hub_id"])
    pending = pending_run_for(db, project_id, row["hub_id"])
    return {"verdict_id": case["verdict_id"] if case and case.get("verdict_id") else None,
            "pending_run": pending, "review": review_json(db.get_review(project_id, row["hub_id"])),
            **ask_busy_flags(db, settings_of(request), project_id, case.get("verdict_id") if case else None),
            "done": pending is None, "reload": pending is None}


# ============================================================================ адреса: решение и отметки

@router.post("/projects/{project_id}/findings/{finding_id}/review")
async def save_review(request: Request, project_id: int, finding_id: int):
    form = await request.form()
    decision = str(form.get("decision") or "")
    final_verdict = str(form.get("final_verdict") or "")
    comment = str(form.get("comment") or "").replace("\r\n", "\n")[:MAX_COMMENT]
    # рекомендация подтверждённого дефекта SAST (поле есть только в карточке SAST; нет поля – не менять)
    fix_field = form.get("fix")
    final_fix = str(fix_field).replace("\r\n", "\n") if fix_field is not None else None
    fix_too_long = final_fix is not None and len(final_fix) > MAX_FIX  # не обрезать молча – отказ с причиной
    reviewed = str(form.get("reviewed") or "") == "1"
    action = str(form.get("action") or "save")
    shown_version = str(form.get("finding_version") or "")
    shown_verdict = str(form.get("verdict_id") or "").strip()
    # редакция решения и отпечаток кода, которые видел человек; страница без этих полей (открытая до обновления
    # приложения) проверяется только по версии находки и вердикту
    shown_revision = _form_int(form.get("review_revision"))
    shown_code = str(form.get("code_hash") or "").strip()[:64]
    shown_chars = _form_int(form.get("code_chars"))
    json_answer = action == "copy" or wants_json(request)
    defect_confirmed = str(form.get("defect_confirm") or "") == "1"  # «дефект в Hub останется прежним» (ADR-0121)
    selection = read_selection(request.query_params)  # отбор списка, внутри которого идёт обход
    sel_query = urlencode(selection, doseq=True)

    def apply():
        nonlocal decision, final_verdict, final_fix
        project_or_404(request, project_id)
        if fix_too_long:
            raise ReviewRejected(FIX_TOO_LONG)
        db = db_of(request)
        settings = settings_of(request)
        row = db.get_finding(project_id, finding_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Находка не найдена.")
        if (decision not in ("", *DECISIONS, *SAST_OUTCOMES) or final_verdict not in ("", *VERDICTS)
                or (shown_verdict and not shown_verdict.isdigit())):
            raise HTTPException(status_code=400, detail="Неверное решение или вердикт.")
        f = Finding.from_dict(row["data"])
        if decision in SAST_OUTCOMES and f.kind != "SAST":
            raise HTTPException(status_code=400, detail="Неверное решение или вердикт.")
        case = db.get_case(project_id, f.hub_id)
        model_verdict = case["verdict"] if case else None
        expected_verdict = int(shown_verdict) if shown_verdict else None
        # раньше проверок решения: сначала – что видел человек (находка, вердикт, решение, код)
        check_shown(db, project_id, f, case, shown_version, expected_verdict, shown_revision)
        old = db.get_review(project_id, f.hub_id)
        code = check_code(request, project_id, f, case, shown_code, shown_chars)
        if f.kind == "SAST":
            # два исхода SAST (ADR-0089): кнопка карточки -> прежняя пара «согласен/не согласен» и итоговый вердикт
            outcome_key = decision if decision in SAST_OUTCOMES else ""
            decision, final_verdict = sast_choice(decision, final_verdict, model_verdict, code["stale_verdict"], old,
                                                  case["verdict_id"] if case and case.get("verdict_id") else None)
            if decision == "risk_accepted":
                raise ReviewRejected(SAST_TWO_OUTCOMES)
            # рекомендация – только у подтверждённого дефекта; у остальных исходов она не сохраняется
            if outcome_key and outcome_key != "true_positive":
                final_fix = ""
        else:
            final_fix = None
        chosen = final_verdict
        group_check = None
        if action == "copy" and not decision:
            raise ReviewRejected(NEED_DECISION)
        if decision == "disagree" and not final_verdict:
            raise ReviewRejected(NEED_VERDICT)
        if decision == "agree":
            if model_verdict is None:
                raise HTTPException(status_code=400, detail="«Согласен» можно выбрать, только когда есть вердикт "
                                                            "модели.")
            if code["stale_verdict"]:
                raise StaleReview("код изменился после разбора", "stale_verdict")
            chosen = model_verdict["verdict"]
        if decision == "risk_accepted" and not comment.strip():
            raise ReviewRejected(RISK_NEEDS_REASON)
        if f.kind == "SAST" and decision in ("agree", "disagree"):
            outcome = hub_verdict(decision, chosen)
            if outcome not in SAST_OUTCOMES:
                raise ReviewRejected(SAST_TWO_OUTCOMES)
            # обоснование обязательно: одно вводное «Ложное срабатывание:» его не заменяет (ADR-0089 п. 6); в Hub
            # комментарий уходит как написан (ADR-0149), вводное слово снимается только для этой проверки
            if not defect.reason_text(comment):
                raise ReviewRejected(SAST_NEED_REASON[outcome])
            # подтверждённый дефект – с рекомендацией оператора (ADR-0092); поля нет (страница до обновления) –
            # проверяется сохранённая
            if outcome == "true_positive" and not defect.has_recommendation(
                    final_fix if final_fix is not None else str((old or {}).get("final_fix") or "")):
                raise ReviewRejected(SAST_NEED_FIX)
        # короткий текст копируется только для ложного срабатывания: у дефекта в Hub уходит полный текст, отложенная
        # находка в Hub не переносится
        if f.kind == "SAST" and action == "copy":
            if hub_verdict(decision, chosen) != "false_positive":
                raise ReviewRejected(SAST_COPY_DEFECT)
            mine = defect.sast_effective("false_positive", comment, "")
            mine_cmp = str((case or {}).get("code_cmp") or "")  # срез, по которому проверен код выше
            near = same_code(db.group_rows(project_id, group_key(f), f.hub_id), mine_cmp)
            states = sibling_states(request, db, project_id, near)

            def source_now(hub_id: str) -> str:  # текущая версия соседки – тем же соединением, в транзакции
                return source_sig(db.case_input(project_id, hub_id))
            conflict = group_conflict_rows(current_rows(near, states, source_now), mine)
            if conflict:
                raise ReviewRejected(conflict)

            own_case = (case or {}).get("case_hash")

            def copy_group_check(rows: list[dict]) -> None:
                now = db.get_case(project_id, f.hub_id) or {}  # то же соединение, внутри транзакции записи
                if now.get("case_hash") != own_case or str(now.get("code_cmp") or "") != mine_cmp:
                    raise ReviewRejected(GROUP_MOVED)
                found = group_conflict_rows(current_rows(same_code(rows, mine_cmp), states, source_now), mine)
                if found:
                    raise ReviewRejected(found)
            group_check = copy_group_check
        # Текст для Hub с комментарием модели к другому вердикту не копируется молча: нужна правка или «Текст
        # проверен» (п. 10 проверки этапа 1)
        # человек подтвердил, что комментарий модели к другому вердикту подходит и так: «Текст проверен» действует только
        # с редакцией решения, которую он видел (BUG-01) – без неё короткий текст не выдаётся, сохранение – да
        if action == "copy":
            origin = comment_origin(db, case, old, comment, project_id=project_id, hub_id=f.hub_id)
            target = hub_verdict(decision, chosen)
            if origin and origin != target and not comment_confirm_valid(form, old):
                raise CommentNeedsCheck(comment_check_text(origin, target))
        comment_confirmed = comment_confirm_valid(form, old, strict=False)
        if action == "copy":
            current = db.case_input(project_id, f.hub_id)
            if current is None or current.get("missing"):
                raise ReviewRejected(copy_missing_message(old))
        if f.kind == "SAST":
            # находка в дефекте, созданном в Hub (ADR-0121 п. 2): смена решения – только с подтверждением; привязка и
            # прежнее решение читаются в транзакции записи (проверка группы вызывается внутри неё)
            group_check = hub_defects.save_check(db, project_id, f.hub_id, decision, chosen, comment, final_fix,
                                                 defect_confirmed, group_check)
        expect = {"version": shown_version, "verdict_id": expected_verdict, "revision": shown_revision}
        # «Отложить» – вернуться позже: находка остаётся непроверенной. Вердикт модели про прежний срез кода
        # отметку не снимает (ADR-0147): решение – оператора, карточка предупреждает. check_code выше доказывает только,
        # что код не менялся, пока карточка была открыта; review.code_hash – отпечаток текущего кода
        mark = reviewed and decision != "later"
        try:
            review = db.save_review(project_id, f.hub_id, decision=decision, final_verdict=chosen,
                                    final_comment=comment, reviewed=mark, verdict_id=expect["verdict_id"],
                                    expect=expect, code_hash=code["hash"], code_chars=code["chars"],
                                    require_present=action == "copy", final_fix=final_fix,
                                    group_key=group_key(f), group_check=group_check, recheck=action != "copy")
        except StaleReview as e:
            if e.reason == "missing":  # находка исчезла из выгрузки между проверкой и записью: текст не копируется
                raise ReviewRejected(copy_missing_message(old)) from e
            raise
        text = hub_text(f, hub_verdict(decision, chosen), comment, settings.hub_status_map)
        # Сохранить черновик можно всегда, а текст в ответе – только по решению с обоснованием человека (ADR-0088):
        # без решения или с комментарием модели к другому вердикту без «Текст проверен» текст не выдаётся
        origin = comment_origin(db, case, old, comment, project_id=project_id, hub_id=f.hub_id)
        text_ok = bool(decision) and not (origin and origin != hub_verdict(decision, chosen) and not comment_confirmed)
        filters = selection_filters(selection)
        # обход всех находок выборки («не скопированы», «проверенные») – без возврата к началу: сохранение
        # без копирования выборку не меняет, и «Дальше» по кругу водило бы по тем же находкам
        walk = walks_all(selection)
        next_id = queue_neighbor(db, project_id, row, selection, wrap=not walk,
                                 hub_ids=hub_sync_ids(request, project_or_404(request, project_id), selection))
        total, done = db.count_unreviewed(project_id, filters)
        notice = ""  # предупреждение о прежнем срезе – в карточке (шаг 3), сохранение его не повторяет
        # готовность дефекта – по тому же правилу, что в карточке и при выдаче текста, а не по виду решения
        ready = sast_assess(request, project_id, review, db.get_case(project_id, f.hub_id),
                            db.case_input(project_id, f.hub_id))["state"] == "ok" if f.kind == "SAST" \
            else defect_ready(review)
        # отпечаток текста для «Отправить в Hub» – того же текста, что выдан в ответе, и только если он совпадает с
        # текстом сохранённого решения, который соберёт отправка
        send_hash = (text_hash(text) if text_ok and review and text
                     and text == saved_hub_text(f, review, settings.hub_status_map) else "")
        # режим панели «Отправить в Hub» после сохранения (dev29): статус уже в Hub – «Обновить комментарий в Hub»
        replace = (hub_status_routes.replace_answer(request, project_id, f.hub_id, review, text) if send_hash
                   else {"active": False, "note": "", "check": ""})
        return (review, text if text_ok else "", next_id, {"total": total, "reviewed": done}, notice, ready, text_ok,
                send_hash, replace)

    try:
        review, text, next_id, progress, notice, ready, text_ok, send_hash, replace = await run_in_threadpool(apply)
    except CommentNeedsCheck as e:
        return JSONResponse({"ok": False, "detail": str(e), "reason": "comment"}, status_code=409)
    except hub_defects.DefectBound as e:  # находка в дефекте, созданном в Hub: нужно подтверждение (ADR-0121 п. 2)
        if json_answer:
            return JSONResponse({"ok": False, "detail": str(e), "reason": "defect"}, status_code=409)
        # без скрипта – карточка с текстом отказа, черновиком и открытым флажком подтверждения
        draft = {"decision": decision, "final_verdict": final_verdict if final_verdict in VERDICTS else "",
                 "comment": comment, "reviewed": reviewed, "fix": final_fix or ""}
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409, draft,
                                       defect_bound=str(e))
    except ReviewRejected as e:
        if json_answer:
            return JSONResponse({"ok": False, "detail": str(e), "reason": "rejected"}, status_code=400)
        draft = {"decision": decision, "final_verdict": final_verdict if final_verdict in VERDICTS else "",
                 "comment": comment, "reviewed": reviewed, "fix": final_fix or ""}
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 400, draft)
    except StaleReview as e:
        message = STALE_MESSAGES.get(e.reason, STALE_MESSAGES["source"])
        if json_answer:
            return JSONResponse({"ok": False, "detail": message, "reason": e.reason}, status_code=409)
        # введённое человеком не теряется: черновик подставляется в форму для повторной сверки, но не пишется
        draft = {"decision": decision if decision in (*DECISIONS, *SAST_OUTCOMES) else "",
                 "final_verdict": final_verdict if final_verdict in VERDICTS else "", "comment": comment,
                 "reviewed": False, "fix": final_fix or ""}
        return await run_in_threadpool(card_response, request, project_id, finding_id,
                                       message + " Ваш вариант решения подставлен в форму – сверьте его с "
                                       "находкой и сохраните ещё раз. Отметка «Проверено» снята: после сверки "
                                       "установите её заново.", 409, draft)
    if json_answer:
        return JSONResponse({"ok": True, "hub_text": text, "copy_allowed": text_ok,
                             # отпечаток выданного текста: отметка «Внесено в Hub» сверит его с текущим
                             "entered_hash": text_hash(text) if text_ok and text else "",
                             "hub_send_hash": send_hash,  # «Отправить в Hub» сверит отпечаток показанного текста
                             "hub_replace": replace,  # режим панели «Отправить в Hub» (dev29)
                             "final_verdict": review.get("final_verdict", ""),
                             "defect_ready": ready,
                             "reviewed": bool(review.get("reviewed")), "revision": review.get("revision"),
                             "reviewed_at": review.get("reviewed_at"), "progress": progress, "notice": notice,
                             "entered": bool(review.get("entered_hub")), "entered_at": review.get("entered_hub_at"),
                             "copied_at": review.get("copied_at")})
    sel = f"&{sel_query}" if sel_query else ""
    if action == "next":
        if next_id is not None:  # на следующей карточке – строка «Сохранено: … · вернуться»
            return redirect(f"/projects/{project_id}/findings/{next_id}?saved={finding_id}{sel}")
        if walks_all(selection):  # последняя находка выборки – обратно к ней же
            return redirect(f"/projects/{project_id}/findings?{sel_query}&ok=selection_end")
        if not review.get("reviewed"):
            return redirect(f"/projects/{project_id}/findings/{finding_id}?ok=no_other{sel}")
        if selection:  # выборка пройдена – обратно к ней же, а не ко всему списку
            return redirect(f"/projects/{project_id}/findings?{sel_query}&ok=selection_done")
        return redirect(f"/projects/{project_id}/findings?ok=all_reviewed")
    # после сохранения – к следующему шагу маршрута (У1): перенос в Hub, у отложенной – «Дальше»; не к началу карточки
    step = "#step-7" if decision == "later" else ("#step-6" if ready else "#decision")
    return redirect(f"/projects/{project_id}/findings/{finding_id}?ok=saved{sel}{step}")


@router.post("/projects/{project_id}/findings/{finding_id}/copied")
async def mark_copied(request: Request, project_id: int, finding_id: int):
    """Браузер подтвердил, что текст для Hub попал в буфер обмена (revision – редакция скопированного решения)."""
    form = await request.form()
    raw = str(form.get("revision") or "").strip()
    if not raw.isdigit() or int(raw) < 1:
        raise HTTPException(status_code=400, detail="Не указана редакция решения.")

    def apply():
        row = finding_or_404(request, project_id, finding_id)
        return db_of(request).mark_copied(project_id, row["hub_id"], int(raw))

    copied_at = await run_in_threadpool(apply)
    if copied_at is None:
        raise HTTPException(status_code=409, detail="Решение не сохранено или изменилось после копирования: "
                                                    "скопируйте текст ещё раз.")
    return {"ok": True, "copied_at": copied_at}


@router.post("/projects/{project_id}/findings/{finding_id}/reviewed")
async def mark_reviewed(request: Request, project_id: int, finding_id: int):
    """Отметка «Проверено» отдельно от решения (клавиша v): решение и комментарий не меняются, редакция решения
    растёт – ответ сообщает новую. Проверки – как при сохранении решения: что видел человек и код в клоне."""
    form = await request.form()
    reviewed = str(form.get("reviewed") or "") == "1"
    shown_version = str(form.get("finding_version") or "")
    shown_verdict = str(form.get("verdict_id") or "").strip()
    shown_revision = _form_int(form.get("review_revision"))
    shown_code = str(form.get("code_hash") or "").strip()[:64]
    shown_chars = _form_int(form.get("code_chars"))
    selection = read_selection(request.query_params)

    def apply():
        row = finding_or_404(request, project_id, finding_id)
        db = db_of(request)
        if shown_verdict and not shown_verdict.isdigit():
            raise HTTPException(status_code=400, detail="Неверный вердикт.")
        f = Finding.from_dict(row["data"])
        case = db.get_case(project_id, f.hub_id)
        expected_verdict = int(shown_verdict) if shown_verdict else None
        check_shown(db, project_id, f, case, shown_version, expected_verdict, shown_revision)
        code = check_code(request, project_id, f, case, shown_code, shown_chars)
        expect = {"version": shown_version, "verdict_id": expected_verdict, "revision": shown_revision}
        # Отметка снимок решения не меняет. Если решение есть, код сверяется с отпечатком самого решения (при его
        # размере среза); если решения нет, отметка запоминает код, который видел человек
        own = db.get_review(project_id, f.hub_id)
        if own and own.get("decision"):
            current = db.case_input(project_id, f.hub_id)
            same = (current_code(settings_of(request), current, mask_key_of(request), int(own["code_chars"]),
                                 case=case)[2]
                    if current is not None and own.get("code_chars") else "")
            review = db.set_reviewed(project_id, f.hub_id, reviewed, expect=expect, code_hash=same)
        else:
            review = db.set_reviewed(project_id, f.hub_id, reviewed, expect=expect, code_hash=code["hash"],
                                     code_chars=code["chars"])
        return review, progress_of(db, project_id, selection)

    try:
        review, progress = await run_in_threadpool(apply)
    except StaleReview as e:
        message = STALE_MESSAGES.get(e.reason, STALE_MESSAGES["source"])
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": message, "reason": e.reason}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, message, 409)
    except ValueError as e:  # отложенная находка
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e)}, status_code=400)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 400)
    if wants_json(request):
        marks = review_json(review)
        return {"ok": True, **marks, "progress": progress, "checked": {"reviewed-box": marks["reviewed"]},
                "show" if marks["reviewed"] else "hide": ["reviewed-badge"],
                "text": {"progress-label": f"Проверено {progress['reviewed']} из {progress['total']} · осталось "
                                           f"{max(0, progress['total'] - progress['reviewed'])}"}}
    return redirect(card_url(project_id, finding_id, selection, ok="reviewed" if reviewed else "unreviewed"))


@router.post("/projects/{project_id}/findings/{finding_id}/entered")
async def mark_entered(request: Request, project_id: int, finding_id: int):
    """Отметка «Внесено в Hub» (клавиша h): человек сам вставил статус и комментарий в Hub. Редакция решения
    не меняется: отметка подтверждает текст редакции review_revision; если решение с тех пор сохранили заново
    (другая вкладка), отметка не ставится."""
    form = await request.form()
    entered = str(form.get("entered") or "1") == "1"
    revision = _form_int(form.get("review_revision"))
    selection = read_selection(request.query_params)
    defect_confirmed = str(form.get("defect_confirm") or "") == "1"  # снять отметку у находки в дефекте (ADR-0121)

    def apply():
        row = finding_or_404(request, project_id, finding_id)
        db = db_of(request)
        review = db.get_review(project_id, row["hub_id"])
        if entered and not (review and review.get("decision")):
            raise ValueError(ENTERED_NO_DECISION)
        if entered and revision is None:  # страница до обновления приложения: без редакции отметка не ставится
            return None
        f = Finding.from_dict(row["data"])
        if (entered and f.kind == "SAST"
                and sast_outcome(review["decision"], review["final_verdict"]) not in SAST_OUTCOMES):
            raise ValueError(SAST_ENTER_ONLY)
        if entered and f.kind == "SAST" and not defect.reason_text(review.get("final_comment") or ""):
            raise ValueError(ENTERED_NEEDS_REASON)  # прежнее решение без обоснования: в Hub такого текста нет
        if (entered and f.kind == "SAST" and sast_outcome(review["decision"], review["final_verdict"]) == "true_positive"
                and not defect.has_recommendation(str(review.get("final_fix") or ""))):
            raise ValueError(ENTERED_NEEDS_FIX)  # дефект без рекомендации оператора не готовится (ADR-0092)
        if entered:  # отметка – о тексте с обоснованием человека, не модели к другому вердикту (ADR-0088)
            origin = comment_origin(db, db.get_case(project_id, f.hub_id), review, review.get("final_comment") or "",
                                    project_id=project_id, hub_id=f.hub_id)
            target = hub_verdict(review["decision"], review["final_verdict"])
            if origin and origin != target and not comment_confirm_valid(form, review):
                raise CommentNeedsCheck(entered_check_text(origin, target))
        settings = settings_of(request)  # один снимок: отпечаток текста и его составляющие – по одним настройкам
        text = sast_entered_text(db, settings, project_id, f, review)
        # отпечаток текста, который человек скопировал или видел в карточке: если текст с тех пор другой (например,
        # сменилось название команды), отметка подтвердила бы то, чего в Hub нет
        shown_hash = str(form.get("text_hash") or "").strip()
        if entered and f.kind == "SAST" and not shown_hash:  # страница до 0.9.6: что показано – неизвестно
            raise ValueError(ENTERED_RELOAD)
        if entered and shown_hash and shown_hash != text_hash(text):
            raise ValueError(ENTERED_TEXT_MOVED)
        parts = entered_parts(settings, review) if entered and f.kind == "SAST" else ""
        # снять отметку у находки в дефекте, созданном в Hub, – только с подтверждением; Hub не трогается (ADR-0121 п. 4)
        check = None if entered or defect_confirmed else hub_defects.unenter_check(project_id, row["hub_id"])
        return db.mark_entered(project_id, row["hub_id"], entered, revision=revision, entered_hash=text_hash(text),
                               entered_parts=parts, check=check)

    try:
        review = await run_in_threadpool(apply)
    except CommentNeedsCheck as e:
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e), "reason": "comment"}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409)
    except hub_defects.DefectBound as e:  # находка в дефекте, созданном в Hub (ADR-0121 п. 4)
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e), "reason": "defect"}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409)
    except ValueError as e:
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e)}, status_code=400)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 400)
    if review is None:
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": ENTERED_STALE, "reason": "revision"}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, ENTERED_STALE, 409)
    if wants_json(request):
        marks = review_json(review)
        # Редакция решения не меняется и в ответ не входит: иначе скрипт записал бы её в форму решения, и форма
        # из устаревшей вкладки перестала бы считаться устаревшей
        marks.pop("revision")
        shown, hidden = ["entered-badge", "entered-note"], ["mark-entered", "entered-changed", "entered-unconfirmed",
                                                            "entered-format-updated", "entered-bulk"]
        return {"ok": True, **marks,
                "message": "Отмечено: внесено в Hub." if entered else "Отметка «Внесено в Hub» снята.",
                "times": {"entered-at": {"prefix": "Внесено в Hub " if entered else "",
                                           "datetime": marks['entered_at'] if entered else "", "suffix": "."}},
                "show": shown if entered else ["mark-entered"],
                # пометка «общим комментарием из списка» относится к снятой или заменённой отметке
                "hide": hidden if entered else shown + ["entered-bulk"]}
    return redirect(card_url(project_id, finding_id, selection, ok="entered" if entered else "unentered"))


DEFECT_NOT_READY = ("Дефект готовится только по сохранённому решению с итогом «истинная» или «ложная»: сохраните "
                    "решение и попробуйте ещё раз.")
SAST_DEFECT_NOT_READY = ("Дефект готовится только по сохранённому решению «Подтверждаю дефект»: сохраните решение и "
                         "попробуйте ещё раз. Для ложного срабатывания в Hub уходит короткий комментарий.")
DEFECT_BAD_NUMBER = "Номер дефекта – целое число от 1 до 999999 (число после «ID» в Hub)."
NUMBER_CHANGED = ("Номер дефекта изменили в другой вкладке, пока карточка была открыта: номер не перезаписан. "
                  "Обновите карточку и проверьте номер.")


def expected_number(form) -> object:
    """Номер, который был сохранён при открытии карточки (поле number_shown): None – номера не было; без поля или с
    неверным значением – NO_EXPECT (не сверяется в транзакции)."""
    shown = form.get("number_shown")
    if shown is None:
        return NO_EXPECT
    text = str(shown).strip()
    if not text:
        return None
    return int(text) if text.isdigit() else NO_EXPECT


def foreign_number_check(allowed: set[str], confirmed: bool):
    """Проверка чужих держателей номера в транзакции записи (Б9, К3): номер у ключей вне allowed без подтверждения –
    DefectNeedsConfirm (запись откатывается)."""
    def check(keys: list[str]) -> None:
        warning = duplicate_number_warning([k for k in keys if k not in allowed])
        if warning and not confirmed:
            raise DefectNeedsConfirm(warning)
    return check


def confirm_extra(form, e: DefectNeedsConfirm) -> dict:
    """Форма дефекта после отказа «нужно подтверждение» без скрипта (К5): предупреждения (флажок открыт) и номер,
    который ввёл человек."""
    extra = {"warnings": list(e.warnings)}
    raw = str(form.get("number") or "").strip()
    if raw:  # введённый номер – только в поле ввода; сохранённый (number_shown) остаётся прежним (К5)
        extra["entered_number"] = raw
    return extra


def number_shown_changed(form, stored: int | None) -> bool:
    """Форма прислала номер, который был сохранён при открытии карточки (number_shown; пусто – номера не было), а
    сейчас сохранён другой: выдача из устаревшей вкладки номер не перезаписывает (Б9). Без поля – не проверяется."""
    shown = form.get("number_shown")
    return shown is not None and str(shown).strip() != ("" if stored is None else str(stored))


def duplicate_number_warning(keys: list[str]) -> list[str]:
    """Предупреждение до записи: этот номер уже у других находок или пакетов проекта (не той же группы)."""
    return [f"Номер уже дан ещё {len(keys)} {'находке или пакету' if len(keys) == 1 else 'находкам или пакетам'} "
            "проекта: если в Hub это другой дефект, укажите другой номер."] if keys else []

register_messages({"defect_saved": "Номер дефекта сохранён: заголовок и текст – в разделе «Дефект для Hub»."})


def read_defect_number(form) -> int | None:
    """Номер дефекта из формы; пусто – None (возьмётся сохранённый или следующий); неверный – ValueError."""
    raw = str(form.get("number") or "").strip().removeprefix("ID").removeprefix("id").strip()
    if not raw:
        return None
    number = _form_int(raw)
    if number is None or not 1 <= number <= 999_999:
        raise ValueError(DEFECT_BAD_NUMBER)
    return number


GROUP_NUMBER_NOTE = ("Тот же номер – у находок с той же строкой и категорией: в Hub это один дефект, создайте его "
                     "сразу из всех этих находок.")


def defect_duplicates_note(keys: list[str]) -> str:
    if not keys:
        return ""
    return (f"Этот номер уже дан ещё {len(keys)} "
            f"{'находке' if len(keys) == 1 else 'находкам'} проекта – проверьте, что в Hub это один дефект.")


@router.post("/projects/{project_id}/findings/{finding_id}/defect")
async def copy_defect(request: Request, project_id: int, finding_id: int):
    """Заголовок и текст дефекта для Hub (JSON: number, title, body, note): номер из формы запоминается за находкой.
    Без скрипта – переход обратно на карточку, где текст виден в разделе «Дефект для Hub»."""
    form = await request.form(max_fields=10, max_files=0)
    selection = read_selection(request.query_params)
    confirmed = str(form.get("confirm") or "") == "1"
    stale_confirmed = []  # комментарий модели к другому вердикту выдан по отметке «Текст проверен»

    def apply():
        project_or_404(request, project_id)
        row = finding_or_404(request, project_id, finding_id)
        db = db_of(request)
        number = read_defect_number(form)
        shown_revision = _form_int(form.get("review_revision"))
        # Один снимок: находка, источник её кода, решение и привязка к вердикту читаются здесь же, текст строится
        # из этой находки, а перед записью номера снимок проверяется заново в короткой транзакции (CWE-367)
        source = db.case_input(project_id, row["hub_id"])
        if source is None:
            raise DefectBlocked(SAST_STATE_HINTS["missing"])
        f = Finding.from_dict(source["data"])
        if f.kind != "SAST":
            raise ValueError("Дефект SCA готовится в карточке SCA.")
        review = db.get_review(project_id, f.hub_id)
        case = db.get_case(project_id, f.hub_id)
        # актуальность решения проверяется при каждой выдаче текста, а не только при открытии карточки:
        # пропавшая находка, новая выгрузка, новый разбор и правка кода в клоне закрывают выдачу (409)
        assessment = sast_assess(request, project_id, review, case, source)
        # находка, её код или вердикт изменились: точная причина и обновление карточки
        if assessment["state"] in SAST_HISTORIC_STATES:
            raise DefectReload(sast_state_hint(assessment["state"], review))
        # карточка показывает другую редакцию решения (его сохранили в другой вкладке): текст выдаётся только к той,
        # которую человек видит, иначе «скопировано» и «Внесено в Hub» разошлись бы с формой. Проверяется до
        # остальных отказов: другая вкладка могла сменить и само решение (на «Отложить» или ложное срабатывание)
        if shown_revision is not None and shown_revision != int((review or {}).get("revision") or 0):
            raise DefectReload(DEFECT_OTHER_REVISION)
        if assessment["state"] != "ok":
            raise DefectBlocked(sast_state_hint(assessment["state"], review, SAST_DEFECT_NOT_READY))
        if not defect.reason_text(review.get("final_comment") or ""):
            raise DefectBlocked(DEFECT_NEEDS_REASON)
        if not defect.has_recommendation(str(review.get("final_fix") or "")):
            raise DefectBlocked(DEFECT_NEEDS_FIX)
        if not str(settings_of(request).team_name or "").strip():
            raise DefectBlocked(DEFECT_NEEDS_TEAM)
        # комментарий модели к другому вердикту не выдаётся молча ни коротким, ни полным текстом (R092-02)
        origin = comment_origin(db, case, review, review.get("final_comment") or "", project_id=project_id,
                                hub_id=f.hub_id)
        target = hub_verdict(review["decision"], review["final_verdict"])
        if origin and origin != target:
            # отметка «Текст проверен» – к той редакции решения, которую человек видел (не к изменённой в другой вкладке)
            if not comment_confirm_valid(form, review):
                raise CommentNeedsCheck(comment_check_text(origin, target))
            stale_confirmed.append(int(review["revision"]))
        # та же строка и категория – один дефект: тот же номер, то же решение и тот же текст (ADR-0089)
        key = group_key(f)
        verdict = Verdict.from_dict(case["verdict"]["data"]) if assessment["use_verdict"] else None
        mine = defect.sast_effective("true_positive", review.get("final_comment") or "",
                                     str(review.get("final_fix") or ""))

        own_number = db.defect_number(project_id, defect.defect_key_sast(f.hub_id))
        if number_shown_changed(form, own_number):
            raise DefectReload(NUMBER_CHANGED)
        own_at = db.defect_assigned_at(project_id, defect.defect_key_sast(f.hub_id))
        mine_cmp = own_code_cmp(db, project_id, f.hub_id)
        own_case = (case or {}).get("case_hash")
        states = sibling_states(request, db, project_id, same_code(db.group_rows(project_id, key, f.hub_id), mine_cmp))

        merge = db.group_merge(project_id, key)  # не меняется после шага 20: читать вне транзакции можно

        def defect_group_check(rows: list[dict], issued: int | None, own: int | None, at: str | None = None) -> None:
            now = db.get_case(project_id, f.hub_id) or {}  # собственный срез – тот же, что при оценке (ADR-0092 п. 6)
            if now.get("case_hash") != own_case or str(now.get("code_cmp") or "") != mine_cmp:
                raise DefectReload(GROUP_MOVED)
            try:
                near = current_rows(same_code(rows, mine_cmp), states,
                                    lambda hub_id: source_sig(db.case_input(project_id, hub_id)))
            except ReviewRejected as e:
                raise DefectReload(str(e)) from e
            conflict = group_conflict_rows(near, mine)
            if conflict:
                raise DefectBlocked(conflict)
            plan_rows, foreign = number_rows(rows, mine_cmp, own, own_at if at is None else at, f.hub_id)
            if issued is not None and issued in foreign:
                raise ValueError(FOREIGN_NUMBER.format(n=issued))
            if merge:  # группа слилась при обновлении схемы: номера не сводятся (ADR-0095 п. 4)
                error = merged_number_plan(merged_members(rows, mine_cmp, f.hub_id, own, foreign), f.hub_id,
                                           merge["numbers"], issued)[1]
            else:
                error = group_number_plan(plan_rows, issued, own if own not in foreign else None)[1]
            if error:
                raise ValueError(error)
        defect_group_check(db.group_rows(project_id, key, f.hub_id), number, own_number)
        view = sast_defect(db, settings_of(request), store_of(request), project_id, f, review, verdict, number,
                           shown=defect_shown_lines(request, project_id, f, case), state="ok", source=source)
        # тот же номер у находок с той же строкой и категорией – ожидаемо: в Hub это один дефект (ADR-0089)
        group = {defect.defect_key_sast(r["hub_id"])
                 for r in same_code(db.group_rows(project_id, key, f.hub_id), mine_cmp)} | {
            defect.defect_key_sast(f.hub_id)}
        # ссылки на строки, которых нет в показанном коде, и чужой номер проверяются перед каждой выдачей текста
        warnings = view["warnings"] + duplicate_number_warning(
            [k for k in db.defect_keys_with_number(project_id, view["number"]) if k not in group])
        if warnings and not confirmed:
            raise DefectNeedsConfirm(warnings)
        duplicates = db.set_defect_number_checked(
            project_id, defect.defect_key_sast(f.hub_id), view["number"], f.hub_id, source_sig=source_signature(source),
            revision=int(review["revision"]), case_verdict_id=case["verdict_id"] if case else None,
            export=defect.export_label(source.get("import_filename", ""), source.get("import_at", "")),
            group_key=key, group_check=lambda rows, own, at=None: defect_group_check(rows, view["number"], own, at),
            expect_number=expected_number(form), foreign_check=foreign_number_check(group, confirmed))
        note = defect_duplicates_note([k for k in duplicates if k not in group])
        if any(k in group for k in duplicates):
            note = (note + " " if note else "") + GROUP_NUMBER_NOTE
        if view.get("group_note"):
            note = (note + " " if note else "") + view["group_note"]
        # редакция и отпечаток выданного текста: «скопировано» и «Внесено в Hub» относятся к ним
        # entered_current – отметка «Внесено в Hub» поставлена именно по этому тексту (иначе её нужно подтвердить)
        body_hash = text_hash(view["body"])
        entered_hash = review.get("entered_decision_hash") if review.get("entered_origin") == "defect" else review.get("entered_text_hash")
        return {**view, "stored": True, "note": note, "revision": int(review["revision"]),
                "entered": bool(review.get("entered_hub")), "entered_hash": body_hash,
                "entered_current": bool(review.get("entered_hub")) and entered_hash == body_hash}

    try:
        view = await run_in_threadpool(apply)
    except CommentNeedsCheck as e:
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e), "reason": "comment"}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409)
    except StaleReview as e:  # снимок изменился между проверкой и записью номера
        message = DEFECT_RACE + " " + STALE_MESSAGES.get(e.reason, STALE_MESSAGES["source"])
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": message, "reason": e.reason, "reload": True}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, message, 409)
    except (ValueError, ReviewRejected) as e:
        if wants_json(request):
            return defect_error_response(e, ReviewRejected)
        if isinstance(e, DefectNeedsConfirm):  # без скрипта (К5): флажок подтверждения открыт, введённый номер сохранён
            return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409, None, "",
                                           None, confirm_extra(form, e))
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e),
                                       409 if isinstance(e, DefectBlocked) else 400)
    if wants_json(request):
        return {"ok": True, "number": view["number"], "title": view["title"], "body": view["body"],
                "note": view["note"], "revision": view.get("revision"), "entered": view.get("entered", False),
                "entered_hash": view.get("entered_hash", ""), "entered_current": view.get("entered_current", False)}
    if stale_confirmed:  # без скрипта: карточка показывает выданный по отметке текст (после перехода он снова скрыт)
        return await run_in_threadpool(card_response, request, project_id, finding_id, "", 200, None, "",
                                       stale_confirmed[0])
    return redirect(card_url(project_id, finding_id, selection, ok="defect_saved") + "#defect-panel")


register_messages({"defect_number_released": "Номер дефекта снят: находка – ложное срабатывание, дефект не создаётся.",
                   "defect_number_released_others": "Номер дефекта снят у этой находки, но он остаётся у других находок проекта (например, у соседа по группе с решением «Подтверждаю дефект»): дефект с этим номером в заголовке Hub по-прежнему считает его занятым."})
RELEASE_NOT_FALSE = "Номер снимается только у находки с решением «Ложное срабатывание»: обновите карточку."


register_messages({"defect_dropped_cleared": "Пометка «выбыла из дефекта» снята: находка остаётся без дефекта."})


@router.post("/projects/{project_id}/findings/{finding_id}/defect-dropped/clear")
async def clear_defect_dropped(request: Request, project_id: int, finding_id: int):
    """«Оставить как есть» у находки, выбывшей из дефекта: оператор решил, что дефект ей не
    нужен. Решение и отметки не меняются; пометка снимается, только если она та же, что показана в карточке."""
    form = await request.form(max_fields=4, max_files=0)
    selection = read_selection(request.query_params)

    def apply():
        row = finding_or_404(request, project_id, finding_id)
        if not db_of(request).clear_defect_dropped(project_id, str(row["hub_id"]), str(form.get("dropped_shown") or "")):
            raise ValueError("Пометка изменилась или уже снята: обновите карточку.")
        return row

    try:
        row = await run_in_threadpool(apply)
    except ValueError as e:
        current = db_of(request).get_finding(project_id, finding_id)
        if current is not None and current["kind"] == "SCA":  # отказ – карточкой своего раздела
            from app.routes import sca as sca_routes
            return await run_in_threadpool(sca_routes.card_response, request, project_id, finding_id, str(e), 409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409)
    section = "sca/findings" if row["kind"] == "SCA" else "findings"
    q = query(selection, ok="defect_dropped_cleared")
    return redirect(f"/projects/{project_id}/{section}/{finding_id}?{q}")


@router.post("/projects/{project_id}/findings/{finding_id}/defect-number/release")
async def release_defect_number(request: Request, project_id: int, finding_id: int):
    """«Снять номер» у ложного срабатывания (ADR-0125 «Уточнения»): номер, показанный в карточке (number_shown),
    удаляется одной транзакцией, если решение всё ещё «Ложное срабатывание» и находка не входит в дефект приложения
    (Database.release_defect_number). Номер, оставшийся от прежней выдачи текста, перестаёт занимать номер из
    заголовка Hub у настоящего дефекта."""
    form = await request.form(max_fields=4, max_files=0)
    selection = read_selection(request.query_params)

    def apply():
        project_or_404(request, project_id)
        row = finding_or_404(request, project_id, finding_id)
        number = _form_int(form.get("number_shown"))
        if number is None:
            raise ValueError("Номера у находки нет: обновите карточку.")
        hub_id = str(row["hub_id"])

        def still_false(c) -> None:
            review = c.execute("SELECT decision, final_verdict FROM reviews WHERE project_id = ? AND hub_id = ?",
                               (project_id, hub_id)).fetchone()
            if review is None or not review["decision"] or hub_verdict(
                    review["decision"], review["final_verdict"]) != "false_positive":
                raise ValueError(RELEASE_NOT_FALSE)

        return db_of(request).release_defect_number(project_id, defect.defect_key_sast(hub_id), hub_id, number,
                                                    check=still_false)

    try:
        others = await run_in_threadpool(apply)
    except ValueError as e:
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e)}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409)
    if wants_json(request):
        return {"ok": True, "others": others}
    done = "defect_number_released_others" if others else "defect_number_released"
    return redirect(card_url(project_id, finding_id, selection, ok=done) + "#step-6")


# ============================================================================ адреса: модель

@router.post("/projects/{project_id}/findings/{finding_id}/ask")
async def ask_model(request: Request, project_id: int, finding_id: int):
    """«Спросить модель»: вопрос по находке и ответ локальной модели (app/ask.py). Ответ ждёт модели – до
    нескольких минут на медленной модели; вопрос и ответ сохраняются, даже если человек ушёл со страницы."""
    form = await request.form()
    question = str(form.get("question") or "")[:ask.MAX_QUESTION * 2]
    model = str(form.get("model") or "").strip()[:MAX_NAME]
    selection = read_selection(request.query_params)

    def apply():
        row = finding_or_404(request, project_id, finding_id)
        # фабрика клиента: адрес и срок – из снимка исполнителя вопроса (ADR-0102), а не из текущих настроек
        return ask.ask_question(db_of(request), settings_of(request), web_of(request).make_client,
                                mask_key_of(request), project_id, row["hub_id"], question, model)

    try:
        answered = await run_in_threadpool(apply)
    except ask.AskError as e:
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e)}, status_code=e.status)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), e.status, None,
                                       ask.clean_question(question))
    # ответ (или ошибка модели) сохранён у находки: карточка открывается заново на этом вопросе
    ok = "asked" if answered.get("state") == "done" else "ask_failed"
    url = card_url(project_id, finding_id, selection, ok=ok, asked=answered.get("id", "")) + \
        f"#q{answered.get('id', '')}"
    if wants_json(request):
        case = db_of(request).get_case(project_id, answered.get("hub_id", ""))
        verdict_id = case["verdict_id"] if case else None
        return {"ok": True, "answered": answered.get("state") == "done", "redirect": url,
                "question": question_view(answered, verdict_id)}
    return redirect(url)


@router.get("/projects/{project_id}/findings/{finding_id}/questions/{question_id}")
def question_state(request: Request, project_id: int, finding_id: int, question_id: int):
    """Вопрос к модели по находке (JSON): открытая карточка ждёт так ответа, заданного из другой вкладки."""
    row = finding_or_404(request, project_id, finding_id)
    db = db_of(request)
    q = db.get_question(question_id)
    if q is None or q["project_id"] != project_id or q["hub_id"] != row["hub_id"]:
        raise HTTPException(status_code=404, detail="Вопрос не найден.")
    case = db.get_case(project_id, row["hub_id"])
    done = q["state"] != "pending"
    return {"question": question_view(q, case["verdict_id"] if case else None), "done": done, "reload": done}


@router.post("/projects/{project_id}/findings/{finding_id}/reanalyze")
async def reanalyze(request: Request, project_id: int, finding_id: int):
    """«Пересмотреть вердикт»: повторный разбор этой находки моделью (можно другой) отдельным прогоном. Готовый
    вердикт из кэша не берётся (fresh): та же модель на том же коде ответит так же, а другая – по-своему."""
    form = await request.form()
    model = str(form.get("model") or "").strip()[:MAX_NAME]
    fresh = str(form.get("fresh") or "1") == "1"
    selection = read_selection(request.query_params)

    def apply():
        row = finding_or_404(request, project_id, finding_id)
        if row["kind"] != "SAST":
            raise TriageError("Моделью разбираются только находки SAST.")
        if row.get("missing"):
            raise TriageError("Находки нет в текущей выгрузке: разбирать нечего.")
        if any(ord(ch) < 32 for ch in model):
            raise TriageError("Не выбрана модель.")
        return runner_of(request).enqueue(project_id, model, "selected", [row["hub_id"]], fresh=fresh, origin="card")

    try:
        run_id = await run_in_threadpool(apply)
    except TriageError as e:
        if wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e)}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409)
    if wants_json(request):
        return {"ok": True, "run_id": run_id, "run_url": f"/runs/{run_id}"}
    return redirect(card_url(project_id, finding_id, selection, ok="reanalyze"))

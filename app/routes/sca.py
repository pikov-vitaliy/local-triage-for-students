"""Раздел «SCA»: библиотеки проекта (группа «компонент + версия»), пакет для внешних агентов, загрузка ответов
агентов и соответствия AST → CVE, карточка SCA-находки с текстом для Hub и отметками «Проверено» и «Внесено в Hub».

Шаблоны – templates/sca/: index.html (библиотеки), card.html (карточка находки). Логика без запросов и базы –
app/sca.py.

В пакет для внешних агентов попадают только названия библиотек, версии и идентификаторы уязвимостей (и версия
исправления из отчёта Hub): кода, путей, кодовых баз и номеров находок в нём нет. Ответы агентов – недоверенные данные:
на страницах они выводятся только через автоэкранирование шаблонов, ссылки – только проверенные http и https.

Карточка устроена так же, как у SAST (docs/DESIGN.md, «Карточка находки»): те же элементы формы решения, ответ
JSON на action=copy, «Внесено в Hub» – кнопка #mark-entered в своей форме form[data-ajax]. Поэтому её обслуживает
тот же браузерный код: решение, «Проверено», «Скопировать короткий текст для Hub», «Внесено в Hub», переходы по клавишам.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import sca_text
from app import worklists, cvss, defect, hub_defects, hub_state, mask_display, sca
from app import package_transition
from app.config import VERDICTS
from app.db import (NEW_SET, DECISIONS, KAPO_STATES, KAPO_STATES_BY_OUTCOME, Database, ScaSnapshot, StaleReview, hub_verdict,
                    now_iso, review_signature, text_hash)
from app.logsafe import log_failure
from app.masking import mask_text
from app.models import Finding, ScaAnswer
from app.sca_contract import input_ref
from app.feeds import FeedStore, cwe_key
from app.routes.common import (COUNT, CommentNeedsCheck, comment_check_text, comment_confirm_valid,
                               copy_missing_message, db_of, entered_check_text, mask_key_of, project_or_404, query,
                               redirect, register_messages, render, settings_of)
from app.routes import hub_defect_routes, hub_status_routes
from app.routes.feeds import store_of
from app.view import review_json  # noqa: F401 – общий с карточкой SAST

log = logging.getLogger("local_triage.web")

router = APIRouter()

SCA_KINDS = ("SCA",)
MAX_COMMENT = 20000  # знаков в комментарии для Hub
MAX_DRAFT = 200_000  # сколько вставленного текста вернуть в форму, если его не удалось прочитать
LIST_LIMIT = 100_000
MARKS_LIMIT = 10_000_000

# Почему решение не сохранено – текст для человека
STALE_MESSAGES = {
    "source": "Находка изменилась, пока карточка была открыта (новая выгрузка). Решение не сохранено: проверьте "
              "карточку ещё раз.",
    "answer": "Пришёл новый ответ внешнего агента, пока карточка была открыта. Решение не сохранено: посмотрите "
              "ответ и сохраните ещё раз.",
    "revision": "Решение по этой находке уже изменили в другой вкладке или окне. Ваше решение не сохранено, чтобы "
                "не затереть более новое: сверьте карточку и сохраните ещё раз.",
    "verdict": "Данные находки изменились, пока карточка была открыта. Решение не сохранено: проверьте карточку "
               "ещё раз.",
    "deleted": "Проект или находка исчезли, пока запрос выполнялся: обновите страницу.",
    "number": "Номер дефекта изменили в другой вкладке, пока карточка была открыта: номер не перезаписан. Обновите "
              "карточку и проверьте номер.",
    "package": "Пока карточка была открыта, изменились находки этой версии компонента, их решения или набор дефекта. "
               "Решение не сохранено ни для одной находки: сверьте карточку и сохраните ещё раз.",
}
PACKAGE_MOVED_CONFIRM = ("Пока форма была открыта, данные пакета изменились: текст сохранён, а отметки «Версию проверил "
                         "сам», «Остаточный риск проверил» и «Текст проверен» не поставлены – проверьте новый текст и "
                         "отметьте заново.")
CHECK_CHANGED_CONFIRM = ("Проверка целевой версии изменилась после открытия карточки (другая версия, её проверка или "
                         "остаточные уязвимости): текст сохранён, отметки «Версию проверил сам» и «Остаточный риск "
                         "проверил» не поставлены – посмотрите новую проверку и отметьте заново.")
APPLICABILITY_STALE = ("Пока карточка была открыта, изменились данные пакета, исследование компонента или решение о "
                       "применимости: решение не сохранено. Сверьте карточку и сохраните ещё раз.")
MAX_APPLICABILITY_REASON = 2000
PACKAGE_MISMATCH = ("«Согласен с агентом» не применяется к находкам {ids}: вывод агента по ним другой или его нет. "
                    "Снимите их галочки или примите своё решение. Ничего не сохранено.")
ENTERED_STALE = ("Решение по находке изменили в другой вкладке или окне: отметка «Статус и комментарий внесены в Hub» не поставлена. "
                 "Обновите карточку и отметьте ещё раз.")
ENTERED_NO_DECISION = ("Сначала сохраните решение по находке или нажмите «Скопировать короткий текст для Hub»: отметка "
                       "«Статус и комментарий внесены в Hub» – о тексте этого решения.")
NO_PUBLIC_IDS = ("У уязвимостей набора нет публичного идентификатора (CVE, GHSA, БДУ ФСТЭК России): внутренние "
                 "номера в текст для Hub не входят, дефект по шаблону не готовится. Найдите публичный идентификатор "
                 "в исследовании компонента или примите другое решение (например, «без дефекта» с обоснованием).")
FP_NEEDS_REASON = ("«Ложное срабатывание» сохраняется только с обоснованием: напишите в комментарии для Hub одной-двумя "
                   "фразами, почему уязвимость к продукту не относится.")
SCA_NO_SHORT = ("У «Обновить» короткого текста для Hub нет: статус находок в Hub не меняется, дефект создаётся из "
                "отмеченных находок (раздел «Дефект для Hub»). У «Отложить» текста тоже нет.")
ENTERED_NO_DEFECT = ("Дефект набора ещё не готов: отметка «Дефект создан в Hub» ставится, когда текст дефекта собран и "
                     "скопирован.")
ENTERED_NO_TEXT = ("Для этого решения текста для Hub нет («Отложить», «неясно» или пустое обоснование): отметка "
                   "не ставится.")
ENTERED_DEFECT_CHANGED = ("Текст дефекта изменился с тех пор, как карточка была открыта: отметка не поставлена. "
                          "Обновите карточку, скопируйте текст ещё раз и отметьте снова.")
RISK_NEEDS_REASON = ("«Риск принят» сохраняется только с обоснованием: напишите в комментарии для Hub, почему риск "
                     "принимается и при каком условии решение пересматривается (например, срок или событие).")


class ReviewRejected(ValueError):
    """Решение не сохраняется по существу («Риск принят» без обоснования); форма возвращается с введённым."""


def answer_signature(answer: dict | None) -> str:
    """Отпечаток ответа агента (models.ScaAnswer.signature) по строке базы; ответа нет – ""."""
    if not answer:
        return ""
    if answer.get("origin") == "research":  # ответ исследования компонента меняется вместе с его ревизией (ADR-0108)
        return "research:" + str(answer.get("research_sig") or "")
    return ScaAnswer.from_dict({k: answer.get(k) for k in ("component", "version", "recommended_version",
                                                            "conclusion", "explanation", "ids", "links",
                                                            "vulnerabilities")}).signature()


def answer_covers(f: Finding, answer: dict | None) -> bool:
    """Ответ агента охватывает уязвимости находки: все её идентификаторы есть в наборе, по которому агент отвечал.
    Охват не записан (ответ загружен до этапа 3) – он неизвестен, и ответ не применяется ни к одной уязвимости
    автоматически: человек загружает новый ответ или решает сам. У находки без идентификаторов сверять нечего."""
    if not answer:
        return False
    ids = sca.finding_ids(f)
    if not ids:
        # ответ исследования – о конкретных уязвимостях: находке без идентификаторов он не отвечает (ADR-0108, ревью
        # Codex, круг 20)
        return not answer.get("per_vuln")
    scope = {str(x).casefold() for x in answer.get("vulnerabilities") or []}
    if not scope:
        return False
    return all(i.casefold() in scope for i in ids)


def answer_usable(f: Finding, answer: dict | None) -> bool:
    """Ответ применим к находке: охватывает её уязвимости (answer_covers), либо это ответ исследования, а вне
    охвата – только внутренние номера AST и вывод по компоненту «обновить» или «неясно»: он и берётся за такую
    уязвимость (ADR-0154, sca.component_fills)."""
    return answer_covers(f, answer) or bool(sca.component_fills(sca.finding_ids(f), answer))


def scope_unknown(answer: dict | None) -> bool:
    """Охват ответа не записан: ответ загружен до этапа 3, по каким уязвимостям агент отвечал – неизвестно."""
    return bool(answer) and not (answer or {}).get("vulnerabilities")


def answer_current(f: Finding, review: dict | None, answer: dict | None) -> bool:
    """Решение «Согласен с агентом» принято по текущему ответу, и этот ответ применим к находке (answer_usable)."""
    return bool(review and answer and answer_usable(f, answer)
                and review.get("answer_sig") == answer_signature(answer))


def answer_verdict(f: Finding, answer: dict | None) -> str:
    """Вердикт, которому соответствует вывод агента; ответ не охватывает уязвимости находки (новая CVE после
    повторной выгрузки) или вывода нет – "": «Согласен с агентом» тогда недоступно."""
    if not answer_usable(f, answer):
        return ""
    # у ответа исследования вывод – по уязвимостям находки, а не по всей библиотеке (ADR-0108); за уязвимость
    # только с внутренним номером AST – вывод по компоненту (ADR-0154)
    return sca.CONCLUSION_VERDICT.get(sca.answer_for(f, answer).get("conclusion") or "", "")

register_messages({
    "sca_saved": "Решение сохранено.",
    "sca_all_reviewed": "Решение сохранено. Непроверенных находок SCA больше нет.",
    "sca_no_other": "Решение сохранено. Других непроверенных находок SCA нет – осталась только эта (она не проверена).",
    "sca_entered": "Отмечено: статус и комментарий внесены в Hub.",
    "sca_entered_off": "Отметка «Статус и комментарий внесены в Hub» снята.",
    "sca_defect_entered": "Отмечено: дефект создан в Hub.",
    "sca_defect_entered_off": "Отметка «Дефект создан в Hub» снята.",
    "sca_reviewed": "Отметка «Проверено» изменена.",
    "sca_text_saved": "Текст дефекта сохранён.",
    "sca_set_saved": "Место находки в наборах дефекта сохранено.",
    "sca_applicability_saved": "Решение о применимости уязвимости сохранено.",
    "sca_exclusion_saved": "Состав текста дефекта изменён.",
})


# ============================================================================ общее

def _form_int(value: Any) -> int | None:
    """Целое из поля формы (только цифры ASCII); нет поля или не число – None."""
    text = str(value or "").strip()
    return int(text) if text.isascii() and text.isdigit() and len(text) <= 9 else None


def _wants_json(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "")




def _sca_row(db: Database, project_id: int, finding_id: int) -> dict:
    """Находка SCA проекта; другой вид или нет такой – 404."""
    row = db.get_finding(project_id, finding_id)
    if row is None or row["kind"] not in SCA_KINDS:
        raise HTTPException(status_code=404, detail="Находка SCA не найдена: возможно, её нет в новой выгрузке.")
    return row


def research_ref_of(key: tuple[str, str, str]) -> str:
    """Ключ строки исследования для пакета (экосистема, имя, версия) – как у задания исследования (sca.package_key)."""
    return input_ref(*sca.package_key({"ecosystem": key[0], "component": key[1], "version": key[2]}))


def with_research(answers: list[dict], research: dict | None, key: tuple[str, str, str]) -> list[dict]:
    """Ответы агента по пакету и за ними ответ исследования компонента (ADR-0108): прежний ответ, если он есть,
    остаётся главным – решения «Согласен с агентом» по нему не становятся «по прежнему ответу»; без прежних ответов
    главным становится исследование."""
    found = sca.research_answer(research, key)
    return [*answers, found] if found else list(answers)


def _research_conflict(answer: dict | None, research_row: dict | None, ref: str) -> str:
    """Расхождение совета агента с принятым исследованием компонента (sca.research_conflict)."""
    if not answer or not research_row or answer.get("conclusion") != "not_applicable":
        return ""
    from app import sca_research as research
    view = research.row_view({"input_ref": ref}, research_row, None, "")
    return sca.research_conflict(answer, view.get("status", ""), view.get("status_label", ""), view.get("applicable", 0))


def _research_revision(db: Database, project_id: int, f: Finding) -> str:
    """Ревизия исследования версии компонента: какую видел оператор, принимая совет агента. Исследования нет – «0»."""
    row = db.research_row(project_id, research_ref_of((f.package_ecosystem, f.package_name, f.version)))
    return str(int(row["revision"])) if row else "0"


def _finding_conflict(db: Database, project_id: int, f: Finding, latest: dict | None) -> str:
    ref = research_ref_of((f.package_ecosystem, f.package_name, f.version))
    return _research_conflict(sca.answer_for(f, latest) if latest else None, db.research_row(project_id, ref), ref)


def unconfirmed_conflict(db: Database, project_id: int, f: Finding, review: dict | None) -> str:
    """Согласие с советом «не применимо», а исследование с применимыми уязвимостями принято после последней проверки оператора: совет
    никто не подтверждал, в Hub такое решение не уходит (план dev7, разделы 2 и 4). Подтверждённое сохранением согласие – не расхождение."""
    if not review or review.get("decision") != "agree":
        return ""
    answers = _agent_answers(db, project_id, f)
    conflict = _finding_conflict(db, project_id, f, answers[0] if answers else None)
    if not conflict:
        return ""
    row = db.research_row(project_id, research_ref_of((f.package_ecosystem, f.package_name, f.version)))
    return "" if str(review.get("reviewed_at") or "") >= str((row or {}).get("imported_at") or "") else conflict


def _agent_answers(db: Database | ScaSnapshot, project_id: int, f: Finding) -> list[dict]:
    """Ответы агента по пакету находки, от главного к прочим (with_research)."""
    key = (f.package_ecosystem, f.package_name, f.version)
    if isinstance(db, ScaSnapshot):  # ответ исследования уже в снимке (Database._sca_package_state)
        return db.sca_answers(project_id, key[1], key[2], key[0])  # та же эффективная тройка (ревью Kimi, шаг 3)
    return with_research(db.sca_answers(project_id, key[1], key[2], key[0]),
                         db.research_row(project_id, research_ref_of(key)), key)


def _latest_answer(db: Database, project_id: int, f: Finding) -> dict | None:
    """Главный ответ агента по пакету находки – с той же экосистемой, именем и версией (из любого источника, в том
    числе исследование компонента, ADR-0108)."""
    answers = _agent_answers(db, project_id, f)
    return answers[0] if answers else None


def _links(urls: Any) -> list[dict]:
    """Ссылки ответа для страницы: только проверенные http и https, с подписью «сайт/путь». Ссылка не на
    первоисточник из задания помечается и подписывается полным именем сайта: в текст для Hub она не попадает."""
    result = []
    for url in urls or []:
        link = sca.norm_link(url)
        if link:
            primary = sca.is_primary_source(link)
            result.append({"url": link, "label": sca.link_label(link), "primary": primary,
                           "host": urlsplit(link).hostname or ""})
    return result


def _ordered_cwe(store: FeedStore, ids: list) -> dict[str, dict]:
    """Сведения о классах CWE в порядке ids (сначала CWE находки, затем остальных находок библиотеки),
    без повторов; справочник отдаёт их по возрастанию номера."""
    info = store.cwe_info(ids)
    order = list(dict.fromkeys(k for k in (cwe_key(c) for c in ids) if k in info))
    return {k: info[k] for k in order}


def _answer_view(answer: dict, hub_safe: list[str]) -> dict:
    return {**answer, "label": sca.CONCLUSION_LABELS.get(answer.get("conclusion") or "", "вывод не указан"),
            "verdict": sca.CONCLUSION_VERDICT.get(answer.get("conclusion") or "", ""),
            "link_items": _links(answer.get("links")),
            "notes": sca.answer_notes(answer.get("version") or "", answer, hub_safe)}


def _checks(vuln_id: str, aliases: list[str]) -> list[tuple[str, str]]:
    """Где проверить уязвимость в открытых базах – по самому идентификатору и по найденным соответствиям:
    [(подпись, адрес)]; подпись дополняется идентификатором, если адресов от разных идентификаторов несколько."""
    result: list[tuple[str, str]] = []
    for name in [vuln_id, *aliases]:
        for label, url in sca.check_links(name):
            if url not in (u for _, u in result):
                result.append((label if name == vuln_id else f"{label} {name}", url))
    return result


def _finding_marks(db: Database, project_id: int) -> dict[str, dict]:
    """Отметки по находкам SCA текущей выгрузки: {ID находки: {reviewed, entered, decision, final_verdict, outcome}};
    outcome – итог решения (hub_verdict) или «» без решения."""
    # все находки выгрузки, а не первые LIST_LIMIT: столбцы обзора групп считают каждую (MAX_ROWS – предел выгрузки на лист)
    rows, _ = db.list_findings(project_id, kind="SCA", missing="no", limit=MARKS_LIMIT)
    return {r["hub_id"]: {"reviewed": bool(r["reviewed"]), "entered": bool(r["entered_hub"]),
                          "decision": r.get("decision") or "", "final_verdict": r.get("final_verdict") or "",
                          "outcome": hub_verdict(r.get("decision") or "", r.get("final_verdict") or "")
                          if (r.get("decision") or r.get("final_verdict")) else ""}
            for r in rows}


async def _form_text(form, text_field: str, file_field: str, limit: int) -> tuple[str, str]:
    """Текст из формы: выбранный файл важнее вставленного текста. Возвращает (текст, имя файла или "")."""
    upload = form.get(file_field)
    if isinstance(upload, UploadFile) and upload.filename:
        raw = await upload.read(limit + 1)
        if len(raw) > limit:
            raise sca.ScaInputError(f"Файл больше {limit // (1024 * 1024)} МБ.")
        return sca.decode_text(raw), sca.one_line(upload.filename.replace("\\", "/").rsplit("/", 1)[-1], 200)
    text = str(form.get(text_field) or "")
    # предел вставленного текста – тот же, что у файла, при любом способе отправки формы: у формы без файлов
    # (application/x-www-form-urlencoded) предел части max_part_size не действует
    if len(text.encode("utf-8", "replace")) > limit:
        raise sca.ScaInputError(f"Вставленный текст больше {limit // (1024 * 1024)} МБ – загрузите его файлом или "
                                "частями.")
    return text, ""


def _too_big_plain_form(request: Request, limit: int) -> bool:
    """Форма без файлов (urlencoded) заведомо больше предела – отказ до разбора тела."""
    if "application/x-www-form-urlencoded" not in request.headers.get("content-type", ""):
        return False
    length = request.headers.get("content-length", "")
    return length.isdigit() and int(length) > limit * 3 + 64 * 1024  # кодирование %XX утраивает размер


# ============================================================================ страница SCA

def _url_number(value: float | None) -> str:
    """Граница отбора для адреса страницы: 7.0 -> «7», 7.5 -> «7.5»."""
    return "" if value is None else f"{value:g}"


def _cvss_selection(views: list[dict], selection: dict, show: str, page: str) -> dict:
    """Отбор по оценке CVSS для страницы SCA: чем отбираем, какие адреса у чипов, чем заполнены поля формы и
    что показано в панели. Свои границы имеют приоритет над готовым диапазоном: форма отправляет их вместо
    диапазона, а чип диапазона снимает границы, поэтому включены одновременно они не будут."""
    version = selection["version"]
    bounds = selection["min"] is not None or selection["max"] is not None
    item = cvss.bounds_item(selection["min"], selection["max"]) or selection["item"]
    table_params = worklists.options(selection.get("table_params", {}), (*cvss.SORTS, "name_asc", "name_desc"))
    clean = {**{k: v for k, v in table_params.items() if k in ("group_by", "family", "page_size")},
             "show": show, "cvss": selection["preset"], "cvss_min": _url_number(selection["min"]),
             "cvss_max": _url_number(selection["max"]), "cvss_version": version, "sort": table_params["sort"]}

    def link(**changes: str) -> str:
        """Адрес страницы с текущим отбором и заменой части параметров – остальные не теряются."""
        q = query(clean, **changes)
        return f"{page}?{q}#components" if q else f"{page}#components"

    def hidden(skip: tuple[str, ...] = ()) -> list[tuple[str, str]]:
        """Прочие параметры отбора для формы: те, что форма сама не отправляет."""
        return [(key, value) for key, value in clean.items() if value and key not in skip]

    ready = sca.filter_views(views, show)  # после готового отбора: числа диапазонов считаются по нему
    sample = cvss.select(ready, version, None)  # при выбранной версии – только пакеты с её оценками
    picked = cvss.select(views, version, item)  # после отбора по оценке: числа готовых отборов считаются по нему
    shown = cvss.sort_views(cvss.select(ready, version, item), version, selection["sort"])
    filters = [{"key": key, "label": label, "count": len(sca.filter_views(picked, key)), "active": key == show,
                "href": link(show=key)} for key, label in sca.FILTERS]
    chips = [{"label": "Все", "href": link(cvss="", cvss_min="", cvss_max=""), "active": not selection["preset"]
              and not bounds, "count": len(sample)}]
    for band in cvss.presets(version):
        chips.append({"label": band["label"], "href": link(cvss=band["key"], cvss_min="", cvss_max=""),
                      "active": selection["preset"] == band["key"] and not bounds,
                      "count": len(cvss.select(ready, version, band))})
    chips.append({"label": "Свой диапазон", "href": link(cvss="", cvss_min="", cvss_max=""), "active": bounds,
                  "count": len(cvss.select(ready, version, item)) if bounds else None})
    scale = ", ".join(f"{band['label'].lower()} {band['title']}" for band in cvss.bands(version))
    scale_name = "CVSS 2.0" if version == "2.0" else "CVSS 3.x и 4.0"  # какая шкала стоит за чипами
    score_note = (f"В строке – наибольший балл среди находок библиотеки{': ' + cvss.version_title(version) if version else ''}. "
                  "Без выбора версии берётся максимум всех импортированных баллов.")
    return {
        "shown": shown,
        "filters": filters,
        "context": {
            "cvss_chips": chips, "cvss_versions": sca.cvss_versions(views), "cvss_version": version,
            "cvss_scale": f"Диапазоны шкалы – {scale_name}: {scale}.",
            "cvss_score_note": score_note,
            "cvss_version_title": cvss.version_title(version),
            "cvss_min_raw": cvss.field_number(selection["raw"]["cvss_min"]),
            "cvss_max_raw": cvss.field_number(selection["raw"]["cvss_max"]),
            "cvss_range_hidden": hidden(("cvss", "cvss_min", "cvss_max")),
            "cvss_version_hidden": hidden(("cvss_version",)),
            "sort_chips": [{"label": label, "href": link(sort=key), "active": table_params["sort"] == key}
                           for key, label in cvss.SORT_LABELS.items()],
            "sort": selection["sort"],
            "sort_href": link(sort="cvss_asc" if selection["sort"] == "cvss_desc" else "cvss_desc"),
            "sort_note": "Сортировка числовая, пакеты без оценки – в конце; без выбора порядок отчёта: срочные, "
                         "затем по убыванию балла.",
            "cvss_errors": selection["errors"], "cvss_active": selection["active"],
            "cvss_chosen": sum(1 for key in ("cvss", "cvss_min", "cvss_max", "cvss_version") if clean[key]),
            "cvss_filters_open": selection["active"] or bool(selection["errors"]),
            "cvss_count": f"Отобрано {len(shown)} из {len(ready) if item and item.get('key') == 'no_score' else len(sample)}",
            "cvss_reset": link(cvss="", cvss_min="", cvss_max="", cvss_version="", sort=""),
        },
    }


def sca_context(request: Request, project: dict) -> dict:
    db = db_of(request)
    pid = project["id"]
    page = f"/projects/{pid}/sca"
    show = request.query_params.get("show", "")
    show = show if show in sca.FILTER_KEYS else ""
    selection = cvss.parse(request.query_params)  # неверное значение отбрасывается, а не отбирает молча
    selection["table_params"] = request.query_params
    components = db.sca_components(pid)
    all_answers = db.sca_answers(pid)  # от новых к старым: первый по библиотеке – последний ответ
    latest: dict[tuple[str, str, str], dict] = {}
    for answer in all_answers:
        latest.setdefault((answer["ecosystem"], answer["component"], answer["version"]), answer)
    # библиотека без прежних ответов – ответом служит исследование компонента (ADR-0108, with_research)
    researched = db.research(pid)
    for c in components:
        key = (sca.group_ecosystem(c), c["component"], c["version"])
        if key not in latest:
            found = sca.research_answer(researched.get(research_ref_of(key)), key)
            if found:
                latest[key] = found
    ids = {i for c in components for i in (*c["cve"], *c["vuln_ids"])}
    ast_map = db.ast_map(ids) if ids else {}
    views = sca.cvss_views(sca.component_views(components, latest, ast_map), selection["version"])
    marks = _finding_marks(db, pid)
    # состояние относительно Hub (dev15, бэклог 88): та же функция, что у синхронизации, – одним расчётом на страницу
    hub_states = hub_state.project_states(db, project, settings_of(request).hub_url)["by_hub_id"]
    from app import defect_links
    defect_map = defect_links.by_hub_id(db, pid, kind="SCA")
    defect_links.attach(views, defect_map)  # дефекты версии
    confirmed = defect_links.confirmed_hub_ids(db, pid, kind="SCA")
    package_marks = db.package_marks(pid)  # пометки идентичности пакета (план dev17, п. 4.6)
    for v in views:
        v["identity_marks"] = sorted({t for hid in v["hub_ids"] for t in package_marks.get(str(hid), [])})
        v["decided"] = v["findings"] > 0 and v["reviewed"] >= v["findings"]  # «С решением» в обзоре групп
        v["finding_items"] = [{"id": fid, "hub_id": hid, **marks.get(hid, {"reviewed": False, "entered": False}),
                               "hub": hub_states.get(str(hid))}
                              for fid, hid in zip(v["finding_ids"], v["hub_ids"], strict=False)]
        # отправка – по состояниям, как на обзоре проекта: неподтверждённое и ждущее исполнителя не называются «не
        # отправлено» (ревью кода dev15, круг 10)
        delivery = [((it["hub"] or {}).get("delivery") or {}).get("state") for it in v["finding_items"]]
        v["hub_delivery"] = [{"state": s, "label": label, "count": delivery.count(s)}
                             for s, label in hub_state.COUNT_LABELS.items() if delivery.count(s)]
        v["hub_differs"] = sum(1 for it in v["finding_items"] if (it["hub"] or {}).get("differs"))
        # столбцы обзора групп (план dev7, раздел 3): каждая находка версии ровно в одном; без отметки в выгрузке – «Без решения»
        v["buckets"] = dict.fromkeys((b[0] for b in worklists.BUCKETS), 0)
        for it in v["finding_items"]:
            v["buckets"][worklists.finding_bucket(it.get("decision"), it.get("final_verdict"),
                                                  defect_links.in_defect(defect_map.get(str(it["hub_id"]), [])))] += 1
        v["buckets"]["undecided"] += max(0, int(v["findings"]) - len(v["finding_items"]))
        unreviewed = [it for it in v["finding_items"] if not it["reviewed"]]
        v["open_id"] = (unreviewed or v["finding_items"])[0]["id"] if v["finding_items"] else None
        # закрытие версии считается по каждой находке (ревью dev27): находка закрыта статусом, если внесена в Hub со
        # статусом «Ложное срабатывание» или «Риск принят»; закрыта дефектом, если входит в подтверждённый (done) дефект.
        # «Закрыто без дефекта» – все находки закрыты статусом (такая версия не должна выглядеть
        # как забытая «без дефекта»); «все находки закрыты» – у каждой находки есть дефект или закрывающий статус
        by_status = {it["hub_id"] for it in v["finding_items"]
                     if it.get("entered") and it.get("outcome") in ("false_positive", "risk_accepted")}
        by_done_defect = {str(h) for h in v["hub_ids"] if str(h) in confirmed}
        v["closed_without_defect"] = bool(v["finding_items"]) and all(it["hub_id"] in by_status for it in v["finding_items"])
        v["all_findings_closed"] = bool(v["finding_items"]) and all(
            it["hub_id"] in by_status or it["hub_id"] in by_done_defect for it in v["finding_items"])
        if v["answer"]:
            ref = research_ref_of((sca.group_ecosystem(v), v["component"], v["version"]))
            conflict = _research_conflict(v["answer"], researched.get(ref), ref)
            if conflict:
                v["notes"] = [*v["notes"], {"tone": "warn", "text": "расходится: " + conflict}]
            v["advice_conflict"] = conflict
            v["answer_view"] = _answer_view(v["answer"], v["fixed_versions"])
            v["answer_view"]["notes"] = v["notes"]  # с замечанием об уязвимостях вне охвата ответа
    stats = db.review_stats(pid)
    counts = db.count_findings(pid)
    confirmed = sca.confirmed_keys(components, db.sca_confirmed(pid))
    rows, excluded = sca.package_report(components, settings_of(request).sca_internal_prefixes, confirmed)
    _, unconfirmed = sca.package_report(components, settings_of(request).sca_internal_prefixes, ())
    # сомнительные имена: ждут подтверждения (в пакет не идут) и уже подтверждённые (идут, можно отозвать)
    doubtful = [{**x, "confirmed": x["key"] in confirmed} for x in unconfirmed if x.get("doubtful")]
    # источники и время – у ответов по библиотекам текущей выгрузки
    shown_keys = {(v["ecosystem"], v["component"], v["version"]) for v in views}
    current = [a for key, a in latest.items() if key in shown_keys]
    sources = sorted({a["source"] for a in current}, key=str.casefold)
    score = _cvss_selection(views, selection, show, page)
    presentation = worklists.options(request.query_params, (*cvss.SORTS, "name_asc", "name_desc"))
    scored = score["shown"]
    if presentation["sort"].startswith("name_"):
        scored = sorted(scored, key=lambda r: (r["component"].casefold(), r["ecosystem"], r["version"]),
                        reverse=presentation["sort"] == "name_desc")
    params = {"show": show, "cvss": selection["preset"], "cvss_min": _url_number(selection["min"]),
              "cvss_max": _url_number(selection["max"]), "cvss_version": selection["version"], **presentation}
    w = worklists.table(scored, params, path=page, kind="sca", sorts={"": "Как в отчёте",
                         "name_asc": "Имя ↑", "name_desc": "Имя ↓", **{k:v for k,v in cvss.SORT_LABELS.items() if k}})
    known_ast = [i for i in ids if i.upper().startswith("AST-")]  # внутренние номера анализатора
    context = {
        "project": project, "imp": db.latest_import(pid), "views": views,
        "identity_pending": package_transition.pending_count(db, project, settings_of(request).hub_url),
        "worklist": w, "research_family_url": f"/projects/{pid}/components?" + query({"q": (w["active"] or {}).get("name", ""), "ecosystem": (w["active"] or {}).get("scope", ""), "group_by": "family"}), "shown": w["rows"], "show": show, "filters": score["filters"], "stats": stats,
        "counts": counts, "license_count": max(0, int(counts.get("sca") or 0) - int(stats.get("sca") or 0)),
        "urgent_count": sum(1 for v in views if v["urgent"]),
        "answered": sum(1 for v in views if v["answer"]), "sources": sources,
        "last_answer_at": max((a["updated_at"] for a in current), default=""),
        "task": sca.task_text(rows), "package_count": len(rows), "package_rows": rows,
        "package_excluded": [x for x in excluded if not x.get("doubtful")], "package_doubtful": doubtful,
        "doubtful_waiting": sum(1 for x in doubtful if not x["confirmed"]),
        "first_unreviewed": db.neighbor_unreviewed(pid, -1, "next", kinds=SCA_KINDS),
        "map_known": sum(1 for i in known_ast if ast_map.get(i)), "map_ast": len(known_ast),
        "conclusion_labels": sca.CONCLUSION_LABELS, "conclusion_verdict": sca.CONCLUSION_VERDICT,
        "answers_draft": "", "map_draft": "", "answers_report": None, "map_report": None,
        **score["context"],
    }
    ok = request.query_params.get("ok", "")
    n = request.query_params.get("n", "")
    if ok in ("sca_answers", "sca_map", "sca_doubtful") and COUNT.fullmatch(n):
        count = int(n)
        if ok == "sca_doubtful":
            context["ok_message"] = (f"Список сомнительных имён сохранён: агенту уйдут подтверждённые – {count}.")
        elif ok == "sca_answers":
            context["ok_message"] = (f"Ответы сохранены: {count} "
                                     f"{sca.plural(count, 'библиотека', 'библиотеки', 'библиотек')}.")
        else:
            context["ok_message"] = f"Соответствие AST → CVE загружено: новых пар – {count}."
    return context


def sca_response(request: Request, project_id: int, extra: dict | None = None, status_code: int = 200):
    project = project_or_404(request, project_id)
    context = sca_context(request, project)
    context.update(extra or {})
    return render(request, "sca/index.html", context, status_code)


@router.get("/projects/{project_id}/sca", response_class=HTMLResponse)
def sca_page(request: Request, project_id: int):
    return sca_response(request, project_id)


# ============================================================================ пакет для внешних агентов

def _package_rows(request: Request, project_id: int) -> list[dict]:
    """Строки пакета: без исключённых и без сомнительных имён, которые человек не подтвердил."""
    project_or_404(request, project_id)
    db = db_of(request)
    return sca.package_rows(db.sca_components(project_id), settings_of(request).sca_internal_prefixes,
                            db.sca_confirmed(project_id))


@router.post("/projects/{project_id}/sca/package/confirm")
async def confirm_doubtful(request: Request, project_id: int):
    """Подтверждение сомнительных имён библиотек для пакета: отмеченные (item) уходят агенту, остальные – нет.
    Сервер принимает только имена из текущего списка сомнительных: другое значение формы не добавит в пакет
    ни внутренний компонент, ни путь."""
    form = await request.form(max_fields=2000, max_files=0)
    chosen = {str(v) for v in form.getlist("item")}

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        _, excluded = sca.package_report(db.sca_components(project_id), settings_of(request).sca_internal_prefixes, ())
        allowed = {x["key"] for x in excluded if x.get("doubtful")}
        visible = set([x['key'] for x in excluded if x.get('doubtful')][:200])
        prior = db.sca_confirmed(project_id)
        # Старые ключи превращаются в scoped-ключи только при однозначной экосистеме.
        for old in tuple(prior):
            matches = [x['key'] for x in excluded if x.get('doubtful') and f"{x['component']}@{x['version']}" == old]
            if len(matches) == 1:
                prior.add(matches[0]); prior.discard(old)
        from app.sca_research_net import composition_change
        with composition_change():  # состав задания меняется не между проверкой и отправкой исследования
            db.set_sca_confirmed(project_id, (prior - visible) | (chosen & visible & allowed))
        return len(chosen & allowed)

    n = await run_in_threadpool(apply)
    return redirect(f"/projects/{project_id}/sca?ok=sca_doubtful&n={n}#package-doubtful")


def _attachment(content: bytes | str, media_type: str, filename: str) -> Response:
    body = content.encode("utf-8") if isinstance(content, str) else content
    return Response(body, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/projects/{project_id}/sca/package.zip")
def download_package(request: Request, project_id: int):
    """Старый исходящий формат снят: новое задание создаётся по снимку компонентов."""
    return _retired_package(request, project_id)


@router.get("/projects/{project_id}/sca/components.csv")
def download_csv(request: Request, project_id: int):
    return _retired_package(request, project_id)


@router.get("/projects/{project_id}/sca/components.json")
def download_json(request: Request, project_id: int):
    return _retired_package(request, project_id)


def _retired_package(request: Request, project_id: int) -> Response:
    """Не выдавать старое задание с внутренними номерами даже по сохранённой ссылке."""
    project_or_404(request, project_id)
    return Response(
        "Старый формат задания больше не выдаётся. Создайте задание исследования компонентов: "
        f"/projects/{project_id}/components\n",
        status_code=410, media_type="text/plain",
    )


# ============================================================================ ответы агентов и соответствие AST → CVE

def _answers_report_view(report: sca.AnswersReport, saved: int) -> dict:
    return {"source": report.source, "saved": saved, "unknown": report.unknown, "warnings": report.warnings,
            "without_answer": report.without_answer, "ambiguous": report.ambiguous}


@router.post("/projects/{project_id}/sca/answers")
async def upload_answers(request: Request, project_id: int):
    await run_in_threadpool(project_or_404, request, project_id)
    try:
        if _too_big_plain_form(request, sca.MAX_ANSWER_BYTES):
            raise StarletteHTTPException(status_code=413)
        form = await request.form(max_files=1, max_fields=10, max_part_size=sca.MAX_ANSWER_BYTES)
    except StarletteHTTPException:
        return await run_in_threadpool(sca_response, request, project_id, {
            "error": f"Ответ не прочитан: вставленный текст больше {sca.MAX_ANSWER_BYTES // (1024 * 1024)} МБ – "
                     "загрузите его файлом или частями."}, 400)
    text = ""
    try:
        text, _ = await _form_text(form, "answers", "file", sca.MAX_ANSWER_BYTES)
        source = str(form.get("source") or "")

        def apply():
            db = db_of(request)
            report = sca.parse_answers(text, db.sca_components(project_id), source,
                                       history=db.sca_components(project_id, include_missing=True))
            result = (db.save_sca_answers(project_id, report.source, report.answers) if report.answers
                      else {"saved": 0, "kept": [], "reopened": 0})
            for label in result["kept"]:
                report.warnings.append(f"{label}: ответ неполный (нет вывода, пояснения или версии) – прежний полный "
                                       "ответ этого источника оставлен.")
            if result["reopened"]:
                report.warnings.append(f"Ответ агента изменился: у {result['reopened']} "
                                       f"{sca.plural(result['reopened'], 'находки', 'находок', 'находок')} с решением "
                                       "«Согласен с агентом» снята отметка «Проверено» – сверьте их с новым ответом.")
            return report, result["saved"], len(result["kept"])

        report, saved, kept = await run_in_threadpool(apply)
    except sca.ScaInputError as e:
        return await run_in_threadpool(sca_response, request, project_id, {
            "error": str(e), "answers_draft": text[:MAX_DRAFT], "open_answers": True}, 400)
    except Exception as e:
        eid = log_failure(log, "ответ агента не прочитан", e)
        return await run_in_threadpool(sca_response, request, project_id, {
            "error": f"Ответ не прочитан: внутренняя ошибка (номер в журнале {eid}).", "open_answers": True}, 500)
    finally:
        await form.close()
    if report.unknown or report.warnings or not saved:
        extra = {"answers_report": _answers_report_view(report, saved)}
        if not saved and not kept:
            extra["error"] = "Ни одного ответа не сохранено: в ответе нет библиотек этого проекта."
        return await run_in_threadpool(sca_response, request, project_id, extra, 200 if saved or kept else 400)
    return redirect(f"/projects/{project_id}/sca?ok=sca_answers&n={saved}#components")


@router.post("/projects/{project_id}/sca/ast-map")
async def upload_ast_map(request: Request, project_id: int):
    await run_in_threadpool(project_or_404, request, project_id)
    try:
        if _too_big_plain_form(request, sca.MAX_MAP_BYTES):
            raise StarletteHTTPException(status_code=413)
        form = await request.form(max_files=1, max_fields=10, max_part_size=sca.MAX_MAP_BYTES)
    except StarletteHTTPException:
        return await run_in_threadpool(sca_response, request, project_id, {
            "error": "Соответствие не прочитано: вставленный текст слишком большой – загрузите его файлом.",
            "open_map": True}, 400)
    text = ""
    try:
        text, filename = await _form_text(form, "mapping", "file", sca.MAX_MAP_BYTES)
        report = await run_in_threadpool(sca.parse_ast_map, text)
        added = await run_in_threadpool(db_of(request).save_ast_map, report.pairs, filename or "вставка")
    except sca.ScaInputError as e:
        return await run_in_threadpool(sca_response, request, project_id, {
            "error": str(e), "map_draft": text[:MAX_DRAFT], "open_map": True}, 400)
    except Exception as e:
        eid = log_failure(log, "соответствие AST → CVE не прочитано", e)
        return await run_in_threadpool(sca_response, request, project_id, {
            "error": f"Соответствие не прочитано: внутренняя ошибка (номер в журнале {eid}).", "open_map": True}, 500)
    finally:
        await form.close()
    if report.skipped:
        return await run_in_threadpool(sca_response, request, project_id, {
            "map_report": {"pairs": len(report.pairs), "added": added, "skipped": len(report.skipped),
                           "lines": report.skipped[:10]}, "open_map": True})
    return redirect(f"/projects/{project_id}/sca?ok=sca_map&n={added}#ast-map")


# ============================================================================ карточка SCA-находки

def saved_hub_text(db: Database, settings, project_id: int, f: Finding, review: dict | None) -> str:
    """Текст для Hub по сохранённому решению SCA – тот, что человек вносит в Hub; решения нет – ""."""
    if not review:
        return ""
    ids = sca.finding_ids(f)
    latest = _latest_answer(db, project_id, f)
    aliases = sca.aliases_for(ids, db.ast_map(ids) if ids else {}, latest)
    return sca.hub_text(f, hub_verdict(review["decision"], review["final_verdict"]), review["final_comment"],
                        settings.hub_status_map, aliases, kapo_state=review.get("kapo_state") or "")


def saved_hub_text_v4(db: Database, settings, project_id: int, f: Finding, review: dict | None) -> str:
    """Текст для Hub формата 0.9.11–0.10.0.dev20 по сохранённому решению (вводное слово снято, прежняя чистка) – для
    распознавания отметок до 0.10.0.dev21 (текст оператора уходит как написан)."""
    if not review:
        return ""
    ids = sca.finding_ids(f)
    latest = _latest_answer(db, project_id, f)
    aliases = sca.aliases_for(ids, db.ast_map(ids) if ids else {}, latest)
    return sca.hub_text_v4(f, hub_verdict(review["decision"], review["final_verdict"]), review["final_comment"],
                           settings.hub_status_map, aliases)


def saved_hub_text_v3(review: dict | None, f: Finding) -> str:
    """Текст для Hub формата 0.9.8–0.9.10 по сохранённому решению (только обоснование) – для распознавания отметок
    до 0.9.11 (ADR-0101)."""
    if not review:
        return ""
    return sca.hub_text_v3(f, hub_verdict(review["decision"], review["final_verdict"]), review["final_comment"])


def saved_hub_text_v2(db: Database, settings, project_id: int, f: Finding, review: dict | None) -> str:
    """Текст для Hub формата 0.9.0–0.9.7 по сохранённому решению – для распознавания отметок до 0.9.8."""
    if not review:
        return ""
    ids = sca.finding_ids(f)
    latest = _latest_answer(db, project_id, f)
    aliases = sca.aliases_for(ids, db.ast_map(ids) if ids else {}, latest)
    return sca.hub_text_v2(f, hub_verdict(review["decision"], review["final_verdict"]), review["final_comment"],
                           settings.hub_status_map, aliases, kapo_state=review.get("kapo_state") or "")


def saved_hub_text_v1(db: Database, settings, project_id: int, f: Finding, review: dict | None) -> str:
    """Текст для Hub прежнего формата (до 0.9.0) по сохранённому решению – для распознавания прежних отметок."""
    if not review:
        return ""
    ids = sca.finding_ids(f)
    latest = _latest_answer(db, project_id, f)
    aliases = sca.aliases_for(ids, db.ast_map(ids) if ids else {}, latest)
    return sca.hub_text_v1(f, hub_verdict(review["decision"], review["final_verdict"]), review["final_comment"],
                           settings.hub_status_map, aliases)


KAPO_NEEDS_CHOICE = ("Для «Риск принят» уточните по ГОСТ Р КАПО: уязвимость неактуальна для продукта или "
                     "нейтрализована принятыми мерами.")
NEED_VERDICT = "Выберите вывод"


def normalized_kapo(outcome: str, value: str) -> str:
    """Уточнение решения SCA по ГОСТ Р КАПО для итога outcome (hub_verdict): «Подтверждено» – анализ не завершён
    (по умолчанию) или актуальна; «Риск принят» – неактуальна или нейтрализована (выбор обязателен:
    ReviewRejected); «Ложное срабатывание» – ложноположительное (п. 6.12); остальное – пусто."""
    allowed = KAPO_STATES_BY_OUTCOME.get(outcome, ())
    value = str(value or "")
    if not allowed:
        return ""
    if value in allowed:
        return value
    if outcome == "risk_accepted":
        raise ReviewRejected(KAPO_NEEDS_CHOICE)
    if value:
        raise HTTPException(status_code=400, detail="Уточнение по ГОСТ Р КАПО не подходит к выбранному выводу.")
    return allowed[0]


def known_cves(f: Finding, aliases: dict) -> list[str]:
    """CVE находки: из выгрузки и найденные соответствия (AST → CVE по выгрузке поставщика или ответу агента)."""
    result: list[str] = []
    for vuln_id in sca.finding_ids(f):
        for x in [vuln_id, *((aliases.get(vuln_id) or {}).get("aliases") or [])]:
            if x.upper().startswith("CVE-") and x.upper() not in result:
                result.append(x.upper())
    return result


OUTCOME_LABELS = {"true_positive": "обновить", "false_positive": "не применимо", "uncertain": "неясно",
                  "risk_accepted": "риск принят"}


def decision_state(f: Finding, review: dict | None, latest: dict | None,
                   row: dict | None = None) -> tuple[str, str]:
    """Состояние решения человека по находке SCA для дефекта и его итог (hub_verdict):
    "ok" – итог «обновить» или «не применимо» по действующему решению; "none" – решения нет; "later" – отложено;
    "missing" – находки нет в текущей выгрузке; "changed" – решение принято по другой версии находки (после
    решения сменились CVE, путь зависимости или другие поля SCA_KEYS, или версия решения неизвестна);
    "stale" – «Согласен с агентом» принято по прежнему ответу, или ответ не охватывает уязвимости находки (новая
    CVE, охват неизвестен); "not_ready" – итог, для которого дефект не готовится (неясно, «Риск принят»).
    row – строка находки из базы (data, missing): по ней решение сверяется с текущей версией находки; без row
    сверка не делается."""
    if not review or not (review.get("decision") or review.get("final_verdict")):
        return "none", ""
    if review.get("decision") == "later":
        return "later", ""
    outcome = hub_verdict(review["decision"], review["final_verdict"])
    if row is not None:
        if row.get("missing"):
            return "missing", outcome
        if review.get("finding_sig") != review_signature(row.get("data") or {}):
            return "changed", outcome
    if review.get("decision") == "agree" and not answer_current(f, review, latest):
        return "stale", outcome
    return ("ok" if defect.ready(outcome) else "not_ready"), outcome


def state_text(state: str, outcome: str) -> str:
    return {"none": "решения нет", "later": "отложено",
            "missing": "нет в текущей выгрузке",
            "changed": "решение принято по прежней версии находки (сменились уязвимости или путь зависимости)",
            "stale": "«Согласен с агентом» – по прежнему ответу агента или ответ не про эту уязвимость",
            "not_ready": f"итог «{OUTCOME_LABELS.get(outcome, outcome)}»"}.get(state, state)


def defect_ready(review: dict | None, f: Finding | None = None, latest: dict | None = None,
                 row: dict | None = None) -> bool:
    """Дефект по сохранённому решению: итог «обновить» или «не применимо», и решение действует – принято по текущей
    версии находки (row), находка есть в выгрузке, «Согласен с агентом» принято по текущему ответу, который
    охватывает уязвимости находки (f и latest – находка и последний ответ агента по её библиотеке)."""
    if f is None:
        return bool(review and (review.get("decision") or review.get("final_verdict"))
                    and review.get("decision") != "later"
                    and defect.ready(hub_verdict(review["decision"], review["final_verdict"])))
    return decision_state(f, review, latest, row)[0] == "ok"


def title_warnings(component: str, version: str, ecosystem: str = "") -> list[str]:
    """Предупреждения к заголовку дефекта SCA: имя или версия библиотеки не похожи на координаты пакета (в поле
    выгрузки мог оказаться путь или фрагмент кода) или на имя пакета своей экосистемы (ecosystem – колонка Type
    выгрузки) – такой заголовок уходит в Hub только после подтверждения."""
    name, ver = sca.one_line(component, sca.MAX_COMPONENT), sca.one_line(version, sca.MAX_VERSION)
    reason = sca.package_exclusion(name, ver) or sca.package_doubt(name, ver, [ecosystem] if ecosystem else [])
    return [f"Заголовок дефекта: {reason} – «{sca.one_line(component, 120)}». Проверьте, что в Hub уйдёт имя "
            "библиотеки, а не путь или внутреннее название."] if reason else []


KAPO_CONFLICT_HINT = ("По этой библиотеке и версии у действующих решений разные уточнения по ГОСТ Р КАПО: {groups}. "
                      "Заключение дефекта одно на библиотеку и версию, поэтому он не готовится, пока уточнения не "
                      "совпадут: сверьте решения по этим находкам.")
CONFLICT_HINT = ("По этой библиотеке и версии есть действующие решения с разными итогами: {groups}. Один дефект "
                 "на библиотеку не может означать разные наборы находок, поэтому общий дефект не готовится, пока "
                 "итоги не совпадут: сверьте решения по этим находкам.")


def set_key(f: Finding, set_no: int) -> str:
    """Ключ номера дефекта набора (ADR-0091 п. 7): набор по умолчанию – прежний ключ пакета, отдельный – с номером."""
    # эффективная тройка (план dev17, п. 4.3): без сведений Hub – Type и компонент выгрузки, как раньше
    base = defect.defect_key_sca(f.package_name, f.version, f.package_ecosystem)
    return base if not set_no else f"{base}#{int(set_no)}"


def _sig(*parts: Any) -> str:
    return text_hash("\x1f".join(str(x) for x in parts))


SCA_FP_HINT = ("«Ложное срабатывание» и «Риск принят» закрываются коротким комментарием в Hub, дефект не создаётся "
               "(ADR-0091).")
SCA_NO_DEFECT_HINT = "Находка помечена «без дефекта»: {reason}"


def sca_defect(db: Database | ScaSnapshot, store: FeedStore, project_id: int, f: Finding, review: dict | None,
               number: int | None = None, today: str = "", override: dict | None = None) -> dict:
    """Дефект SCA по набору находки и шаблону команды (ADR-0091): {ready, number, stored, title, body, hint, subject,
    note, warnings, excluded, state, ...данные карточки}.

    Готов, когда решение по находке действует (decision_state), его исход – «Обновить», находка не помечена
    «без дефекта», у набора есть целевая версия (не затронутая по исследованию; непроверенная – с отметкой «Версию
    проверил сам») и Объяснение не пусто. Замечания к оформлению Объяснения (нет строки по уязвимости, текст не на
    русском) – предупреждения в cautions, готовности они не мешают (ADR-0152).
    В набор входят находки пакета из текущей выгрузки с действующим решением «Обновить» и тем же местом в наборах;
    остальные перечислены в note и excluded и выдаче не мешают."""
    snap = db if isinstance(db, ScaSnapshot) else db.sca_snapshot(project_id, f.hub_id)
    today = today or now_iso()[:10]
    placed = snap.placed if snap.row is not None else {}
    place = placed.get(f.hub_id)
    set_no = 0 if place is None or place.get("set_no") is None else int(place["set_no"])
    key = set_key(f, set_no)
    stored = snap.defect_number(project_id, key)
    number = number or stored or snap.next_defect_number(project_id)
    latest = snap.latest_answer
    own_row = snap.row
    state, outcome = decision_state(f, review, latest, own_row)
    result = {"ready": state == "ok", "number": number, "stored": stored is not None, "title": "",
              "body": "", "needs_team": False, "subject": "библиотеки и версии", "note": "", "warnings": [],
              "excluded": [], "state": state, "set_no": set_no, "sets": snap.sets if snap.row is not None else {},
              # пакет и ревизия идентичности, которые видит оператор, – для формы выбора набора (план dev17, п. 4.3)
              "input_ref": snap.input_ref, "shown_pkg_rev": int((own_row or {}).get("pkg_rev") or 0),
              "comment_stale": [], "vulns": [], "explanation": "", "explanation_draft": "", "target": "",
              "target_basis": "", "check": None, "ast": [], "text_revision": 0, "problems": [], "cautions": [], "sources": [],
              "residual": [], "residual_outside": [], "recommendation_note": "", "residual_confirm_sig": "",
              "residual_shown_sig": "", "residual_unsourced": [], "applicability": [], "research_revision": 0,
              "version_sig": "", "excluded_vulns": [], "set_revision": 0,
              "hint": "Один дефект на набор находок версии компонента: в Hub создайте его из отмеченных находок набора."}
    if state == "missing":
        result["hint"] = "Находки нет в текущей выгрузке: дефект по ней не готовится."
    elif state == "changed":
        result["hint"] = ("Решение принято по прежней версии находки: после него в выгрузке сменились уязвимости, "
                          "путь зависимости или другие сведения. Сверьте решение и сохраните ещё раз – тогда дефект "
                          "станет доступен.")
    elif state == "stale" and not (review or {}).get("answer_sig"):
        result["hint"] = ("Решение «Согласен с агентом» принято до обновления приложения, и неизвестно, по какому "
                          "ответу агента и каким соответствиям AST → CVE: сверьте решение с текущим ответом "
                          "и сохраните ещё раз – тогда дефект станет доступен.")
    elif state == "stale" and scope_unknown(latest):
        result["hint"] = ("Охват ответа агента неизвестен (ответ загружен до обновления приложения): загрузите новый "
                          "ответ или примите своё решение – тогда дефект станет доступен.")
    elif state == "stale":
        result["hint"] = ("Решение «Согласен с агентом» принято по прежнему ответу агента: сверьте решение с новым "
                          "ответом и сохраните ещё раз – тогда дефект станет доступен.")
    elif state == "none":
        result["hint"] = "сначала сохраните решение «Обновить» по находке набора: дефект готовится по нему."
    elif state == "later":
        result["hint"] = "решение отложено: дефект готовится после решения «Обновить»."
    elif state == "not_ready":
        result["hint"] = "итог решения не «Обновить» (неясно или риск принят): дефект по нему не готовится."
    if result["ready"] and outcome != "true_positive":
        result.update(ready=False, state="short_only", hint=SCA_FP_HINT)
    if result["ready"] and place is not None and place.get("set_no") is None:
        result.update(ready=False, state="no_defect", hint=SCA_NO_DEFECT_HINT.format(
            reason=place.get("no_defect_reason") or "обоснование не указано"))
    if not result["ready"]:
        return result
    # участники набора: находки пакета из текущей выгрузки с действующим «Обновить» и тем же местом
    # с пропавшими из выгрузки: их место в наборах учитывается в области набора (Г10), в набор они не входят
    group = next((c for c in snap.sca_components(project_id, include_missing=True)
                  if (c["ecosystem"], c["component"], c["version"])
                  == (f.package_ecosystem, f.package_name, f.version)), None)
    members, others, excluded, accepted = {}, {}, [], []
    mapping_all: dict[str, list[str]] = {}
    for fid in (group or {}).get("finding_ids") or []:
        found = snap.get_finding(project_id, fid)
        if found is None:
            continue
        item = Finding.from_dict(found["data"])
        item_review = review if item.hub_id == f.hub_id else snap.get_review(project_id, item.hub_id)
        ids = sca.finding_ids(item)
        agreed = latest if (item_review or {}).get("decision") == "agree" else None
        aliases = sca.aliases_for(ids, snap.ast_map(ids) if ids else {}, agreed)
        for vuln_id, info in aliases.items():  # соответствия – по всем находкам пакета, и по историческим (Г10)
            mapping_all.setdefault(vuln_id, [])
            mapping_all[vuln_id] += [x for x in (info.get("aliases") or []) if x not in mapping_all[vuln_id]]
        if found.get("missing"):
            # историческая находка (ADR-0091 п. 6): в этот набор не входит; её уязвимости, если она не участник этого
            # набора, – «другие» и через исследование не возвращаются (Г10)
            gone_place = placed.get(item.hub_id)
            gone_set = 0 if gone_place is None else gone_place.get("set_no")
            if gone_set != set_no:
                others[item.hub_id] = ids
            continue
        item_state, item_outcome = decision_state(item, item_review, latest, found)
        item_place = placed.get(item.hub_id)
        item_set = None if item_place is not None and item_place.get("set_no") is None else (
            0 if item_place is None else int(item_place["set_no"]))
        if item_state == "ok" and item_outcome == "true_positive" and item_set == set_no:
            members[item.hub_id] = ids
            accepted.append((item, item_review))
            continue
        # уязвимости всех находок Hub, которые не участники этого набора (другой исход, другой набор, «без дефекта»,
        # решения нет или оно не действует), – «другие»: связь уязвимости с находкой Hub – факт выгрузки, а не решения;
        # в этот набор они входят только через свои находки, а не через исследование (ADR-0091 п. 9, Г10)
        others[item.hub_id] = ids
        reason = (state_text(item_state, item_outcome) if item_state != "ok"
                  else OUTCOME_LABELS.get(item_outcome, item_outcome) if item_outcome != "true_positive"
                  else "без дефекта" if item_set is None else f"отдельный набор {item_set}")
        excluded.append({"hub_id": item.hub_id, "reason": reason})
    if f.hub_id not in members:
        result.update(ready=False, state="missing", hint="Находки нет в текущей выгрузке: дефект по ней не готовится.")
        return result
    result["excluded"] = excluded
    if excluded:
        shown = "; ".join(f"{x['hub_id']} – {x['reason']}" for x in excluded[:10])
        more = f" и ещё {len(excluded) - 10}" if len(excluded) > 10 else ""
        result["note"] = f"В этот дефект не входят находки версии ({len(excluded)}): {shown}{more}."
    research = snap.research
    payload = (research or {}).get("payload") or None
    research_date = str((research or {}).get("observed_at") or (research or {}).get("imported_at") or "")[:10]
    sets = snap.sets
    # одна карта классов уязвимостей пакета – для области набора, проверки цели, пояснения о версии Hub и решений о
    # применимости (ADR-0091 п. 8, ADR-0094): находки Hub, соответствия, исследование и все проверки версий
    rep = sca_text.union_classes(sca_text.class_groups([*members.values(), *others.values()], mapping_all, payload))
    research_revision = int((research or {}).get("revision") or 0)
    decided = sca_text.applicability(snap.applicability, rep, research_revision)
    effective = {root: info["decision"] for root, info in decided.items() if info["decision"]}
    not_applicable = [root for root, decision in effective.items() if decision == "not_product"]
    vulns = sca_text.set_vulns(members, others, mapping_all, (payload or {}).get("public_findings") or [],
                               excluded=(sets.get(set_no) or {}).get("excluded") or [], default_set=set_no == 0,
                               rep=rep, applicability=effective)
    record = override if override is not None else (snap.package_text(set_no) or {})
    result["text_revision"] = int(record.get("revision") or 0)
    # исключённые оператором из текста набора – с обоснованием, вернуть можно в карточке (ADR-0091 п. 9)
    result["set_revision"] = int((sets.get(set_no) or {}).get("revision") or 0)
    result["excluded_vulns"] = [
        {"id": str(x.get("id") or ""), "ids": [str(i) for i in x.get("ids") or [x.get("id")]],
         "reason": str(x.get("reason") or "")} if isinstance(x, dict) else {"id": str(x), "ids": [str(x)], "reason": ""}
        for x in (sets.get(set_no) or {}).get("excluded") or []]
    cves = sorted({i for v in vulns for i in v.ids if sca_text.kind_of(i) == "cve"})
    bdu = store.bdu_by_cve(cves) if cves else {}
    # прежний ответ агента (формат 1) – основание цели и источник заготовки для всего набора (ADR-0091 п. 14.4), а не
    # открытой карточки: хотя бы один участник набора согласен с текущим ответом, и ответ охватывает уязвимости всех
    # участников – тогда он одинаково действует из любой карточки набора; иначе ни из одной
    agreed = any((r or {}).get("decision") == "agree" and answer_current(item, r, latest) for item, r in accepted)
    # ответ исследования компонента (ADR-0108) – не прежний ответ: дефект и так строится по исследованию (payload)
    legacy = (latest if agreed and latest and latest.get("origin") != "research"
              and all(answer_covers(item, latest) for item, _ in accepted) else None)
    draft = sca_text.explanation_draft(vulns, bdu, str((legacy or {}).get("explanation") or ""))
    # Объяснение – без внутренних номеров AST до проверок и подписей: проверяется и подтверждается тот же текст, что
    # уходит в Hub (ADR-0101)
    # отступ первой строки Объяснения остаётся как написан (ADR-0149 п. 5), пустые строки по краям не входят
    from app.defect import edges
    explanation = sca_text.strip_ids_keep_indent(edges(str(record.get("explanation") or "")) or draft)
    # то же Объяснение по прежним правилам (края срезаны целиком) – для прежнего тела и прежних подписей
    explanation_v4 = sca_text.strip_internal_ids(str(record.get("explanation") or "").strip() or draft)
    manual = str(record.get("target_version") or "") if record.get("target_basis") == "manual" else ""
    # «Исправленной версии нет» (ADR-0101): явный выбор оператора – раньше решения компонента и советов исследования;
    # цели нет, проверки цели и пояснения о версии Hub нет, проверяется, что исправления нет у уязвимостей «Описания»
    no_fix = record.get("target_basis") == "no_fix"
    nofix = None
    if no_fix:
        target = sca_text.Target(basis="no_fix")
        check = None
        nofix = sca_text.no_fix_check(f.package_ecosystem, f.version, payload, research_date, vulns, rep,
                                      not_applicable)
    else:
        target = sca_text.resolve_target(manual, snap.component_decision, payload, legacy, today)
        check = (sca_text.check_version(f.package_ecosystem, f.version, target.version, payload,
                                        research_date, rep=rep, not_applicable=not_applicable)
                 if target.version else None)
    hub_fix = sca.first_version(f.fixed_version)  # справка в карточке: версия Hub этой находки
    # пояснение «почему не версия Hub» – одно на набор: все версии Hub всех находок набора (ADR-0094 Р2.7)
    hub_versions = list(dict.fromkeys(v for item, _ in accepted for v in sca.all_versions(item.fixed_version)))
    note, note_refs = ("", []) if no_fix else sca_text.hub_explanation(
        f.package_ecosystem, hub_versions, target.version, payload, rep, not_applicable)
    sources = sca_text.research_sources(vulns, payload, target.version)
    if legacy:
        sources += [u for u in (sca.norm_link(x) for x in legacy.get("links") or []) if u and sca.is_primary_source(u)]
    sources = [u for u in dict.fromkeys(sources) if sca_text.human_url(u)]  # только страницы для человека (Г7)
    title = defect.sca_title(number, f.package_display_name, f.version)
    # остаточные уязвимости цели (ADR-0094 Р1): строка в «Рекомендациях» и их доказательства в «Источниках»
    residual = list(nofix.items) if nofix is not None else (list(check.residual) if check else [])
    residual_lines = ([sca_text.no_fix_line(item, payload) for item in residual] if no_fix
                      else [sca_text.residual_line(item, target.version, payload) for item in residual])
    # доказательства автоматических утверждений «Рекомендаций» – по тем же правилам, что и у «Описания» (п. 19)
    sources += sca_text.evidence_urls([ref for item in residual for ref in item.get("refs") or []], payload)
    sources += sca_text.evidence_urls(note_refs, payload)
    sources = list(dict.fromkeys(sources))
    # без подходящего доказательства – для «исправления нет» считается именно доказательство этого утверждения
    residual_unsourced = [r["id"] for r in residual if not sca_text.evidence_urls(
        r.get("proof_refs") if r.get("status") == "no_fix_published" else r.get("refs") or [], payload)]
    # добавление оператора – как написано (ADR-0149 п. 5: отступ первой строки остаётся); note_raw – как сохранено,
    # для прежних форматов: их сборщики срезают края сами, как до 0.10.0.dev21 (ревью Codex круга 5)
    note_raw = str(record.get("recommendation_note") or "")
    recommendation_note = defect.edges(note_raw)
    public = any(v.public for v in vulns)  # без публичных идентификаторов «Описание» пусто (ADR-0101)
    measures = sca_text.strip_internal_ids(recommendation_note).strip()
    body = sca_text.body(f.package_display_name, vulns, explanation, "" if no_fix else (target.version or "…"), sources, note,
                         residual_lines, recommendation_note) if (target.version or no_fix) and public else ""
    text_sig = _sig(title, body)
    # тот же набор по правилам до 0.10.0.dev21 (края Объяснения и добавления срезаны, пустые строки добавления не
    # входили): подписи оператора и отметки, поставленные по нему, остаются в силе – изменился только формат.
    # Подписи прежних правил признаются и при том же теле: подпись Объяснения по прежним правилам
    # могла быть другой (хвостовые пробелы, ревью Codex круга 5); пояснение о смене формата – только если тело другое
    # имя пакета – то же короткое имя, что у нынешнего тела: до 0.10.0.dev21 dev17 уже называл пакет им (слияние
    # main в dev17, ревью Codex круга 1)
    body_v4 = sca_text.body(f.package_display_name, vulns, explanation_v4, "" if no_fix else (target.version or "…"), sources,
                            note, residual_lines, note_raw, legacy_note=True) if body else ""
    legacy_text_sig_v4 = _sig(title, body_v4) if body_v4 and body_v4 != body else ""
    # подпись того же набора в формате 0.9.8–0.9.10: отметка «Дефект создан в Hub» по ней – текст изменился из-за
    # формата 0.9.11 (без AST, «Описание» по группам), карточка называет причину (ADR-0101)
    old_ast = record.get("ast") or {}
    legacy_body = sca_text.body_v0910(
        f.package_display_name, vulns, str(record.get("explanation") or "").strip() or draft, target.version, sources, note,
        [v.main for v in vulns if not v.public and old_ast.get(v.main) != "hide"], residual_lines,
        note_raw) if target.version and not no_fix else ""
    legacy_text_sig = _sig(title, legacy_body) if legacy_body else ""
    # в режиме no_fix подпись – о причинах, найденных исправлениях и ревизии исследования: отметки, поставленные по
    # прежнему исследованию, к новому не относятся
    version_sig = (_sig("no_fix", json.dumps((nofix.problems + nofix.fixed) if nofix else [], ensure_ascii=False),
                        research_revision)
                   if no_fix
                   else _sig(target.version, (check.state if check else ""), (check.detail if check else "")))
    body_sig = _sig(body)
    version_confirm = _sig(version_sig, body_sig)  # «Версию проверил сам» и «Текст проверен» – о тексте целиком
    text_confirm = _sig(_sig(explanation), body_sig)
    # «Остаточный риск проверил» – о теле, списке остаточных уязвимостей с их статусами и ревизии исследования;
    # residual_shown – то, что показано оператору (цель, список, ревизия): отметка ставится, только если сервер
    # насчитал то же самое (ревью 82103ee)
    residual_shown = _sig("no_fix" if no_fix else target.version,
                          json.dumps([[r.get("id"), r.get("status"), r.get("scope", ""), r.get("date", "")]
                                      for r in residual], ensure_ascii=False), research_revision)
    residual_confirm = _sig(body_sig, residual_shown)
    # подписи по телу прежних правил (body_v4): отметка, поставленная до 0.10.0.dev21, действует
    body_sig_v4 = _sig(body_v4) if body_v4 else ""
    version_ok = {version_confirm} | ({_sig(version_sig, body_sig_v4)} if body_sig_v4 else set())
    text_ok = {text_confirm} | ({_sig(_sig(explanation_v4), body_sig_v4)} if body_sig_v4 else set())
    residual_ok = {residual_confirm} | ({_sig(body_sig_v4, residual_shown)} if body_sig_v4 else set())
    problems = []
    cautions = []  # показываются рядом с «Перед выдачей дефекта», но утверждению текста не мешают
    if not public:
        problems.append(NO_PUBLIC_IDS)
    if target.problem:
        problems.append(target.problem)
    if check and check.state == "not_newer":  # запрет: отметка его не снимает (ADR-0094 Р1.3)
        problems.append(f"Целевая версия {target.version} не новее текущей {f.version}: обновлять нечего. Укажите "
                        "другую версию или примите решение по компоненту.")
    if no_fix:
        problems += nofix.problems  # нет исследования, нет сведений об уязвимости, статус не установлен – запрет
        # исправление, найденное исследованием, – предупреждение без отдельной отметки (ADR-0145,
        # ADR-0153, бэклог 126): оно бывает выпущено под другими координатами (продолжение
        # закрытого проекта, новая группа Maven) – под текущими обновлять некуда, замену оператор описывает в
        # «Добавлении к «Рекомендациям»»
        cautions += [f"{p} Дефект с «Исправленной версии нет» можно утвердить и так. Если под текущими координатами "
                     "обновить можно – укажите целевую версию; если исправление вышло под другими координатами – "
                     "опишите замену в «Добавлении к «Рекомендациям»»." for p in nofix.fixed]
        if not measures:
            problems.append("«Исправленной версии нет»: меры обязательны – опишите их в «Добавлении к «Рекомендациям»» "
                            "(например, замена компонента, отключение уязвимой функции, ограничение входных данных).")
    if residual and record.get("residual_checked_sig") not in residual_ok:
        problems.append(("Исправленной версии нет для " if no_fix else "Обновление не закрывает ")
                        + ", ".join(r["id"] for r in residual)
                        + ": исправления нет или оно не установлено. Проверьте и отметьте «Остаточный риск проверил».")
    if check and check.state == "affected":
        # предупреждение, не запрет (оператор выбрал своё решение и должен иметь возможность создать
        # дефект): версия в тексте остаётся той, что указал оператор; альтернативы названы рядом
        cautions.append(f"Целевая версия {target.version} затронута: {', '.join(check.affected)} – по исследованию компонента "
                        "она сама уязвима. Дефект можно утвердить и с ней (решение оператора); иначе укажите другую версию или, "
                        "если уязвимость к продукту не применима, примите решение в разделе «Применимость уязвимостей».")
    elif check and check.state == "unverified" and record.get("version_checked_sig") not in version_ok:
        problems.append(f"Целевая версия {target.version} не проверена ({check.detail}): проверьте её и отметьте "
                        "«Версию проверил сам».")
    if not str(record.get("explanation") or "").strip() and draft:  # заготовка – не решение оператора (ADR-0088)
        problems.append("Объяснение подставлено из исследования компонента, БДУ ФСТЭК России или ответа агента: "
                        "проверьте его, поправьте при необходимости и утвердите текст дефекта.")
    elif not str(explanation or "").strip() and public:
        # пусто и то, что останется после удаления внутренних номеров AST: в Hub уходит именно этот текст
        # (ревью dev26: одно «AST-…» в поле – не объяснение)
        problems.append("Объяснение пустое: напишите, что это за уязвимости и при каких условиях они срабатывают, "
                        "и утвердите текст дефекта. Внутренние номера AST в текст для Hub не входят.")
    # замечания к оформлению Объяснения – предупреждения: оператор решает сам, каким текст уйдёт в Hub (ADR-0145 – проверки предупреждают, ADR-0152)
    missing = sca_text.explanation_problems(explanation, vulns)
    if missing and str(record.get("explanation") or "").strip() and str(explanation or "").strip():
        # о строках пустого текста и неутверждённой заготовки не говорим – там свой запрет выше
        cautions.append("В Объяснении нет отдельной строки или она слишком короткая для: " + ", ".join(missing)
                        + ". Дефект можно утвердить и так. Чтобы объяснение по каждой уязвимости было видно "
                        "получателю дефекта, начните строку с её идентификатора и опишите уязвимость хотя бы одной фразой, "
                        f"например: «{missing[0]}: что это и при каких условиях срабатывает».")
    foreign = sca_text.non_russian_lines(explanation, vulns)  # по каждой строке уязвимости (Г12)
    free = sca_text.free_text(explanation, vulns)  # свободный текст: у набора только с AST – всё Объяснение
    # каждая содержательная строка отдельно: длинный русский абзац не прячет английскую строку
    free_foreign = any(sca_text._LETTER.search(line) and sca_text.cyrillic_share(line) < 1 / 3
                       for line in free.split("\n"))
    if (foreign or free_foreign) and record.get("text_checked_sig") not in text_ok:
        where = ", ".join(foreign + (["текст без идентификатора"] if free_foreign else []))
        cautions.append(f"Объяснение не на русском ({where}). Дефект можно утвердить и так; переведите текст или "
                        "отметьте «Текст проверен» – предупреждение уйдёт.")
    # строки «Описания» этого снимка – ожидания проверки текста перед Hub (ADR-0123 п. 4.2): то же представление, что
    # у тела, sca_text.description_lines
    hub_lines, research_lines = sca_text.description_lines(vulns)
    result.update(vulns=[{"main": v.main, "ids": v.ids, "public": v.public, "members": v.hub_members,
                          "research": bool(v.research)} for v in vulns],
                  description={"hub": hub_lines, "research": research_lines},
                  explanation=explanation, explanation_draft=draft, target=target.version, no_fix=no_fix,
                  legacy_text_sig=legacy_text_sig, legacy_text_sig_v4=legacy_text_sig_v4,
                  target_basis=sca_text.BASIS_LABELS.get(target.basis, ""),
                  check={"state": check.state, "detail": check.detail, "affected": check.affected} if check else None,
                  sources=sources, problems=problems, cautions=cautions, text_sig=text_sig, version_sig=version_sig,
                  explanation_sig=_sig(explanation), version_confirm_sig=version_confirm,
                  residual=residual, residual_confirm_sig=residual_confirm, residual_shown_sig=residual_shown,
                  residual_unsourced=residual_unsourced, research_revision=research_revision,
                  applicability=applicability_view(rep, decided, payload, members, vulns,
                                                   {row["vuln_key"]: row for row in snap.applicability}),
                  residual_outside=[r["id"] for r in residual
                                    if not any(set(r.get("ids") or [r["id"]]) & set(v.ids) for v in vulns)],
                  recommendation_note=recommendation_note,
                  text_confirm_sig=text_confirm, input_ref=snap.input_ref, hub_fix=hub_fix, research_date=research_date,
                  members=list(members), manual_target=manual,
                  # условия перехода и остаточные риски из совета исследования – в карточку (Г9); в текст их переносит
                  # оператор (поле – ADR-0094, схема 19)
                  advice_notes=str(((payload or {}).get("package_advice") or {}).get("compatibility_notes") or ""),
                  remaining_risks=[str(x) for x in ((payload or {}).get("package_advice") or {}).get("remaining_risks")
                                   or [] if str(x).strip()])
    build_type = str((own_row or {}).get("data", {}).get("build_type") or "")
    if (f.package or {}).get("source") == "hub":  # сведения Hub о библиотеке применены – их экосистема (п. 4.3)
        build_type = f.package_ecosystem
    result["warnings"] = title_warnings(f.package_name, f.version, build_type)  # эффективное имя (п. 4.3)
    if problems:
        result.update(ready=False, state="text", hint=" ".join(problems))
        return result
    result["title"] = title
    result["body"] = body
    return result


def applicability_view(rep: dict, decided: dict, payload: dict | None, members: dict,
                       vulns: list[sca_text.Vuln], stored: dict | None = None) -> list[dict]:
    """Уязвимости исследования пакета для раздела «Применимость уязвимостей» (ADR-0094 Р3): класс, вывод агента,
    где встречается (текущая версия, проверки версий), пометка «оспорена» и позиции источников (Р3.1), решение
    оператора – действующее или нет и почему, связь с находками набора (членство важнее решения). stored – все
    строки решений по ключу, в том числе снятые: редакция формы – редакция строки с основным идентификатором."""
    records = sca_text.research_records(payload)
    order: list[str] = []
    for r in records:
        root = sca_text.class_root(rep, r.get("id"))
        if root not in order:
            order.append(root)
    member_roots = {sca_text.class_root(rep, i) for ids in members.values() for i in ids}
    set_roots = {sca_text.class_root(rep, v.ids[0]) for v in vulns if v.ids}
    applies_labels = {"yes": "применима", "no": "не применима", "unknown": "неясно"}
    out = []
    for root in order:
        ids = sca_text.class_ids(rep, root)
        main = sca_text.Vuln(ids=ids).main
        public = [r for r in (payload or {}).get("public_findings") or []
                  if isinstance(r, dict) and sca_text.class_root(rep, r.get("id")) == root]
        where = ["текущая версия"] if public else []
        for c in (payload or {}).get("version_checks") or []:
            if isinstance(c, dict) and any(sca_text.class_root(rep, x.get("id")) == root for x in c.get("findings") or []
                                           if isinstance(x, dict)):
                where.append(f"{'цель' if c.get('role') == 'target' else 'версия Hub'} {c.get('version')}")
        disputed = next((r["disputed"] for r in public if isinstance(r.get("disputed"), dict)), None)
        info = decided.get(root) or {}
        rows = info.get("rows") or []
        own = next((row for row in rows if row.get("vuln_key") == main), None)
        out.append({
            "key": main, "ids": ids, "where": where,
            "applies": ", ".join(applies_labels.get(a, a) for a in dict.fromkeys(str(r.get("applies") or "")
                                                                                for r in public) if a),
            "disputed": {"by": "производитель" if disputed.get("by") == "vendor" else "другой источник",
                         "note": str(disputed.get("note") or "")} if disputed else None,
            "positions": [{"source": str(p.get("source") or ""),
                           "affects": applies_labels.get(str(p.get("affects") or ""), str(p.get("affects") or ""))}
                          for r in public for p in r.get("source_positions") or [] if isinstance(p, dict)],
            "decision": info.get("decision", ""), "stale": info.get("stale", ""),
            "rows": [{"key": row.get("vuln_key"), "decision": row.get("decision"),
                      "label": sca_text.APPLICABILITY_LABELS.get(str(row.get("decision") or ""), ""),
                      "reason": row.get("reason") or ""} for row in rows],
            "revision": int(((stored or {}).get(main) or own or {}).get("revision") or 0),
            "reason": (own or (rows[0] if rows else {})).get("reason") or "",
            "selected": (own or (rows[0] if rows else {})).get("decision") or "",
            "linked": root in member_roots, "in_set": root in set_roots})
    return out


def _comment_target(snap: ScaSnapshot, f: Finding, agent_version: str = "") -> sca_text.Target:
    """Целевая версия заготовок комментария – по тем же данным и правилу, что у текста дефекта набора (resolve_target): ручная цель,
    решение по компоненту, совет исследования, затем совет агента agent_version. «Исправленной версии нет» – цели нет."""
    place = snap.placed.get(f.hub_id) if snap.row is not None else None
    no_set = place is not None and place.get("set_no") is None  # «без дефекта»: настройки набора к находке не относятся
    record = {} if no_set else (snap.package_text(0 if place is None else int(place["set_no"])) or {})
    if record.get("target_basis") == "no_fix":
        return sca_text.Target(basis="no_fix")
    manual = str(record.get("target_version") or "") if record.get("target_basis") == "manual" else ""
    return sca_text.resolve_target(manual, snap.component_decision, (snap.research or {}).get("payload") or None,
                                   {"recommended_version": agent_version} if agent_version else None, now_iso()[:10])


DEFECT_BLOCKED_STATES = ("conflict", "changed", "missing", "short_only", "no_defect")  # плашка «Дефект для Hub не готовится» карточки
TARGET_NOTE_BASIS = {"research": "исследование", "component": "решение по компоненту", "manual": "указана оператором"}


def _target_note(agent_version: str, target: sca_text.Target, decision: str = "", defect_target: str = "", defect_state: str = "ok") -> str:
    """Одна строка рядом с выводом, если совет агента расходится с версией, которая уйдёт в дефект; иначе "". Без исследования и ручной
    цели дефект берёт совет только при согласии в наборе и ответе по всем его находкам (sca_defect): сравнивается с целью самого дефекта,
    defect_target. До решения по находке и при раннем выходе расчёта (defect_state: «без дефекта», устаревшее решение) сравнивать не с чем:
    причину называет сам блок дефекта."""
    if (target.basis == "legacy" and target.version and decision in ("agree", "disagree") and defect_state in ("ok", "text")
            and defect_target != target.version):
        return (f"Совет агента – {target.version}: в дефект версия сейчас не уйдёт. Нужны «Согласен» в наборе и ответ агента по всем его находкам, "
                "иначе укажите версию сами")
    word = TARGET_NOTE_BASIS.get(target.basis, "")
    if not word or not agent_version or not target.version or agent_version == target.version:
        return ""
    return f"Совет агента – {agent_version}, {word} – {target.version}: в дефект уйдёт {target.version}"


def _update_comment(snap: ScaSnapshot, project_id: int, f: Finding) -> str:
    """Заготовка комментария к выводу «обновить»: цель и состав – по тем же данным, что текст дефекта набора (ручная цель, решение по
    компоненту, исключения из набора, решения о применимости). «Исправленной версии нет» – заготовки нет."""
    research = snap.research
    payload = (research or {}).get("payload") or None
    if not payload:
        return ""
    place = snap.placed.get(f.hub_id) if snap.row is not None else None
    no_set = place is not None and place.get("set_no") is None  # «без дефекта»: настройки набора к находке не относятся
    set_no = 0 if place is None or no_set else int(place["set_no"])
    target = _comment_target(snap, f)
    if target.basis == "no_fix":
        return ""
    members, others, mapping = {f.hub_id: sca.finding_ids(f)}, {}, {}  # те же соответствия и деление на наборы, что у текста дефекта
    group = next((c for c in snap.sca_components(project_id, include_missing=True)
                  if (c["ecosystem"], c["component"], c["version"]) == (f.package_ecosystem, f.package_name, f.version)), None)
    for finding_id in (group or {}).get("finding_ids") or []:
        found = snap.get_finding(project_id, finding_id)
        if found is None:
            continue
        item = Finding.from_dict(found["data"])
        ids = sca.finding_ids(item)
        agreed = snap.latest_answer if (snap.get_review(project_id, item.hub_id) or {}).get("decision") == "agree" else None
        for vuln_id, info in sca.aliases_for(ids, snap.ast_map(ids) if ids else {}, agreed).items():
            known = mapping.setdefault(vuln_id, [])
            known += [x for x in (info.get("aliases") or []) if x not in known]
        item_place = snap.placed.get(item.hub_id)
        item_none = item_place is not None and item_place.get("set_no") is None
        item_set = 0 if item_place is None or item_none else int(item_place["set_no"])
        same_set = (item_none, item_set) == (no_set, set_no)
        if item.hub_id == f.hub_id or (found.get("missing") and same_set):  # пропавшая из выгрузки находка своего набора в него не входит
            continue
        (members if same_set else others)[item.hub_id] = ids
    excluded = [] if no_set else ((snap.sets.get(set_no) or {}).get("excluded") or [])
    return sca_text.update_comment(f.package_display_name, target.version, payload, members, others, snap.applicability,
                                   int((research or {}).get("revision") or 0), excluded, mapping, default_set=not no_set and set_no == 0)


def sca_defect_view(view: dict, f: Finding, review: dict | None) -> dict:
    """Дефект для карточки SCA: comment_check – у этой находки обоснование – текст агента к другому выводу, не проверено;
    comment_others – такие же находки группы (их комментарий правится в их карточках). Пока что-то из этого есть, полный
    текст в карточке не показывается (R092-02)."""
    stale = view.get("comment_stale") or []
    view["comment_check"] = bool(view.get("ready") and f.hub_id in stale)
    view["comment_others"] = [x for x in stale if x != f.hub_id] if view.get("ready") else []
    view["review_revision"] = int((review or {}).get("revision") or 0)
    return view


def comment_origin(db: Database, project_id: int, finding: Finding, comment: str) -> str:
    """Вывод, к которому относится неизменённая заготовка комментария: текст агента (с текущим соответствием
    AST → CVE и без него – соответствие могли загрузить после решения) или прежняя заготовка (до 0.9.11) «Обновить …
    (безопасная версия по данным Hub)», которая строилась без ответа агента и означает «обновить» (истинная); с 0.9.11
    такой заготовки нет (ADR-0100), но сохранённые тексты узнаются по началу. "" – текст человека."""
    text = str(comment or '').strip()
    if not text:
        return ''
    ids = sca.finding_ids(finding)
    mapping = db.ast_map(ids) if ids else {}
    for answer in _agent_answers(db, project_id, finding):
        if not answer_usable(finding, answer):
            continue
        for aliases in (sca.aliases_for(ids, mapping, answer), sca.aliases_for(ids, {}, answer)):
            if text == sca.suggested_comment(finding, answer, aliases).strip():
                return answer_verdict(finding, answer)
    # Заготовки (агента и прежние по данным Hub) узнаются по началу текста: перечень уязвимостей в них меняется с загрузкой
    # соответствий AST → CVE, а начало – нет. Свой текст с таким же началом под другим выводом один раз попросит
    # «Текст проверен» – осознанно: лучше лишняя отметка, чем текст агента в Hub под противоположным выводом
    for prefix, conclusion in (("Обновить ", "true_positive"), ("Не применимо: ", "false_positive"),
                               ("Требуется проверка: ", "uncertain")):
        if text.startswith(prefix):
            return conclusion
    return ''


def component_research_view(project_id: int, snap) -> dict:
    """Исследование версии компонента для карточки находки SCA: состояние, когда ответ агента принят, решение
    компонента и адрес его карточки; researched=False – ответа агента нет."""
    from app import sca_research as research
    found = snap.research
    decision = snap.component_decision
    view = research.row_view({"input_ref": snap.research_ref}, found, decision, "") if found or decision else None
    # карточка компонента есть, когда есть исследование или решение; иначе – поиск версии в списке компонентов
    name = sca.package_key({"ecosystem": "", "component": (snap.package or ("", "", ""))[1]})[1]  # как в списке
    url = (f"/projects/{project_id}/components/{snap.research_ref}" if snap.research_ref and (found or decision)
           else f"/projects/{project_id}/components?" + urlencode({"q": name}) if name else "")
    return {"url": url, "list_link": not (found or decision),
            "researched": bool(found), "status_label": (view or {}).get("status_label", ""),
            "fresh_at": (view or {}).get("fresh_at", ""), "applicable": (view or {}).get("applicable", 0),
            "decision_label": ((view or {}).get("decision") or {}).get("action_label", ""),
            "decision_stale": bool((view or {}).get("decision_stale"))}


def card_view(request: Request, project: dict, row: dict, draft: dict | None = None) -> dict:
    db = db_of(request)
    settings = settings_of(request)
    pid = project["id"]
    f = Finding.from_dict(row["data"])
    answers = _agent_answers(db, pid, f)
    latest = answers[0] if answers else None
    ids = sca.finding_ids(f)
    ast_map = db.ast_map(ids) if ids else {}
    aliases = sca.aliases_for(ids, ast_map, latest)
    covers = answer_covers(f, latest)
    # вне охвата только внутренние номера AST и вывод по компоненту «обновить» или «неясно»: ответ применим, вывод
    # за них – по компоненту (ADR-0154)
    by_component = sca.component_fills(ids, latest)
    usable = covers or bool(by_component)
    snap = db.sca_snapshot(pid, f.hub_id)  # дефект, форма набора и отпечаток пакета – из одного снимка (К4)
    # заготовка называет ту же целевую версию, что уйдёт в дефект; совет агента – только если других оснований нет (план dev9, п. 4)
    agent_version = str((sca.answer_for(f, latest) or {}).get("recommended_version") or "") if latest and usable else ""
    comment_target = _comment_target(snap, f, agent_version)
    # ответ не про уязвимости этой находки (новая CVE после повторной выгрузки) – заготовка по нему не строится
    suggestion = sca.suggested_comment(f, latest if usable else None, aliases, comment_target.version)
    agent_verdict = answer_verdict(f, latest)
    # «Своё решение» убирает текст, написанный под вывод агента; без ответа агента заготовки нет (ADR-0100)
    model_comment = suggestion if agent_verdict else ""
    review = db.get_review(pid, f.hub_id)
    empty_review = review is None or not (review["decision"] or review["final_verdict"] or review["final_comment"])
    reviewed_checked = bool(review and review["reviewed"])
    advice_conflict = _finding_conflict(db, pid, f, latest)
    kapo_state = ""
    # у нового решения с выводом «обновить» уточнение по ГОСТ Р КАПО по умолчанию – «актуальна»;
    # сохранённые решения и незаписанный черновик показываются как есть (у прежних «по выводу» – анализ не завершён)
    kapo_default = ""
    if draft is not None:  # решение не сохранилось (страница устарела): форма – с тем, что ввёл человек
        stored_decision, final_verdict, comment = draft["decision"], draft["final_verdict"], draft["comment"]
        reviewed_checked = bool(draft["reviewed"])
        kapo_state = draft.get("kapo_state", "") if draft.get("kapo_state", "") in KAPO_STATES else ""
    elif not empty_review:
        stored_decision, final_verdict, comment = review["decision"], review["final_verdict"], review["final_comment"]
        kapo_state = review.get("kapo_state") or ""
    elif advice_conflict:  # совет расходится с исследованием: «ложное срабатывание» и его текст сами не подставляются
        stored_decision, final_verdict, comment = "", "", ""
        kapo_default = "actual"
    else:
        stored_decision, final_verdict, comment = "", agent_verdict, suggestion
        kapo_default = "actual"
        if agent_verdict == "true_positive":
            kapo_state = "actual"
    # Старые записи со своим выводом и пустым решением показываются как «Своё решение».
    decision = stored_decision or ("disagree" if draft is None and not empty_review and final_verdict else "")
    comment_for = comment_origin(db, pid, f, comment)
    # для формы – по тому, что в форме; для предпросмотра и отметки – по сохранённому решению (его подтверждает отметка)
    comment_stale = bool(comment_for) and comment_for != hub_verdict(decision, final_verdict)
    if draft is None and not empty_review:
        saved_stale = bool(comment_for) and comment_for != hub_verdict(review["decision"] or "",
                                                                     review["final_verdict"] or "")
    else:
        saved_stale = comment_stale
    # текст для Hub по сохранённому решению – одним чтением: его показывает предпросмотр, его отпечаток едет с формой
    # «Отправить в Hub» (два чтения могли бы разойтись, если между ними пришло соответствие номеров или ответ агента)
    saved_text = saved_hub_text(db, settings, pid, f, review) if draft is None and not empty_review else ""
    # Предпросмотр – только текст, который можно нести в Hub (ADR-0088), иначе – пояснение
    preview_note = ""
    if draft is not None:
        preview_note = "Решение не сохранено: текст появится после сохранения."
    elif not decision:
        preview_note = "Текст появится после выбора и сохранения решения: без решения ответ агента в Hub не уходит."
    elif hub_verdict(decision, final_verdict) not in sca.SHORT_OUTCOMES:
        preview_note = ("У «Обновить» короткого текста нет: статус находок в Hub не меняется, дефект создаётся из "
                        "отмеченных находок." if hub_verdict(decision, final_verdict) == "true_positive"
                        else "У «Отложить» и «неясно» короткого текста нет.")
    elif saved_stale:
        preview_note = ("Текст не показан: обоснование – текст агента к другому выводу. Поправьте комментарий и "
                        "сохраните решение или отметьте «Текст проверен» и скопируйте текст.")
    hub_safe = [f.fixed_version] if f.fixed_version else []
    mask_key = mask_key_of(request)
    group = next((c for c in db.sca_components(pid, include_missing=True)
                  if (c["ecosystem"], c["component"], c["version"])
                  == (f.package_ecosystem, f.package_name, f.version)), None)
    defect_view = sca_defect_view(sca_defect(snap, store_of(request), pid, f, snap.review), f, review)
    # панель «Дефект для Hub» (ручной путь): текст не по требованиям команды – предупреждение, без запрета (ADR-0123 п. 5)
    defect_view["form_problems"] = (hub_defect_routes.sca_text_problems(
        db, pid, defect_view["body"], hub_defect_routes.sca_expect(defect_view, f.package_display_name))
        if defect_view.get("ready") and defect_view.get("body") else [])
    # отпечаток текста, по которому сверяется отметка «Внесено в Hub»: у «Обновить» – текст набора дефекта (ADR-0091
    # п. 22), у остальных – короткий текст; прежние форматы – только для узнавания отметок до 0.9.8
    entered_hash = str((review["entered_decision_hash"] if review.get("entered_origin") == "defect"
                        else review["entered_text_hash"]) or "") if review and review["entered_hub"] else ""
    tp_saved = bool(review) and hub_verdict(review["decision"] or "", review["final_verdict"] or "") == "true_positive"
    entered_now = (str(defect_view.get("text_sig") or "") if defect_view.get("ready") else "-") if tp_saved else (
        text_hash(saved_hub_text(db, settings, pid, f, review)) if review else "")
    legacy_hashes = {text_hash(saved_hub_text_v1(db, settings, pid, f, review)),
                     text_hash(saved_hub_text_v2(db, settings, pid, f, review)),
                     text_hash(saved_hub_text_v3(review, f)),
                     text_hash(saved_hub_text_v4(db, settings, pid, f, review))} if review else set()
    legacy_hashes.discard(text_hash(""))  # у «Обновить» и «Отложить» прежних коротких текстов нет
    chosen_rows = set(draft.get("apply_to") or []) if draft is not None and "apply_to" in draft else None
    package_rows = []
    for m in snap.current_members:
        other = snap.get_review(pid, m["hub_id"])
        package_rows.append({"hub_id": m["hub_id"], "id": m["id"], "own": m["hub_id"] == f.hub_id,
                             "revision": int((other or {}).get("revision") or 0),
                             "version": db.review_version(pid, m["hub_id"]),
                             "checked": chosen_rows is None or m["hub_id"] in chosen_rows,
                             "state": _package_row_state(other)})
    siblings = []
    if group:
        for fid, hid in zip(group["finding_ids"], group["hub_ids"], strict=False):
            if hid == f.hub_id:
                continue
            other = db.get_review(pid, hid)
            siblings.append({"id": fid, "hub_id": hid, "reviewed": bool(other and other["reviewed"]),
                             "entered": bool(other and other["entered_hub"])})
    stats = db.review_stats(pid)
    saved_row = None
    saved = request.query_params.get("saved", "")
    if COUNT.fullmatch(saved) and int(saved) != row["id"]:
        saved_row = db.get_finding(pid, int(saved))
    return {
        "project": project, "row": row, "f": f, "review": review, "decision": decision,
        "final_verdict": final_verdict, "comment": comment, "reviewed_checked": reviewed_checked,
        "comment_for": comment_for,
        "comment_stale": comment_stale,
        "is_draft": draft is not None, "reviewed": bool(review and review["reviewed"]),
        # итог разбора под заголовком – только по сохранённому решению, не по черновику и не по подстановке из ответа
        # агента (ревью dev28)
        "summary_decision": summary_decision(None if empty_review else review),
        "entered": bool(review and review["entered_hub"]),
        # отметка полного дефекта по тексту правил до 0.10.0.dev21 (добавление без пустых строк) – «формат обновился»,
        # а не «текст изменился» (ADR-0149 п. 6, ревью Codex)
        "entered_changed": bool(entered_hash and entered_hash != entered_now and entered_hash not in legacy_hashes
                                and not (tp_saved and entered_hash == defect_view.get("legacy_text_sig_v4"))),
        # отметка поставлена по тексту прежнего формата, решение прежнее: «формат обновился», а не «текст изменился»
        "entered_format_updated": bool(entered_hash and entered_hash != entered_now and entered_hash in legacy_hashes),
        # отметка «Дефект создан в Hub» по тексту формата 0.9.8–0.9.10: текст изменился из-за формата 0.9.11 (ADR-0101)
        "entered_defect_format": bool(tp_saved and entered_hash and entered_hash != entered_now
                                      and entered_hash == defect_view.get("legacy_text_sig")),
        # отметка по тексту правил до 0.10.0.dev21: добавление оператора уходило без пустых строк
        "entered_defect_format_v4": bool(tp_saved and entered_hash and entered_hash != entered_now
                                         and entered_hash == defect_view.get("legacy_text_sig_v4")),
        # «Дефект создан в Hub» – только если отметка поставлена по текущему тексту набора (К10, ADR-0091 п. 7)
        # отметка по подтверждённому составу (0.9.26.dev23: Push текста как есть при неготовой заготовке, «Проверить в
        # Hub») отпечатка решения не имеет – сверять нечего, дефект в Hub подтверждён чтением: «Дефект создан в Hub»
        "entered_defect_current": bool(tp_saved and ((entered_hash and entered_hash == entered_now) or (
            review and review["entered_hub"] and review.get("entered_origin") == "defect" and not entered_hash))),
        "short_outcome": hub_verdict(review["decision"] or "", review["final_verdict"] or "") in sca.SHORT_OUTCOMES
                         if review and (review["decision"] or review["final_verdict"]) else None,
        # отметка до этапа 3, без отпечатка текста: подтвердить заново
        "entered_unconfirmed": bool(review and review["entered_hub"] and not review["entered_text_hash"]
                                    and review.get("entered_origin") != "hub_sync"),
        "hub_preview": "" if preview_note else (
            saved_text if draft is None and not empty_review
            else sca.hub_text(f, hub_verdict(stored_decision, final_verdict), comment, settings.hub_status_map, aliases,
                              kapo_state=kapo_state)),
        "hub_preview_note": preview_note, "saved_stale": saved_stale,
        # Р8: длина приставки «<id> в <компонент> <версия>: » короткого текста – для предупреждения о длине в поле
        "comment_prefix_len": max(0, len(sca.hub_text(f, "false_positive", "x", settings.hub_status_map, aliases)) - 1),
        # комментарий, начинающийся с публичного номера находки, приставки не получает – скрипт это учитывает
        "comment_prefix_ids": sca.public_ids_text(sca.finding_ids(f), aliases),
        "kapo_state": kapo_state, "kapo_labels": defect.KAPO_LABELS, "kapo_default": kapo_default,
        # ответ исследования – вывод, пояснение и источники по уязвимостям этой находки (ADR-0108)
        "latest": _answer_view(sca.answer_for(f, latest), hub_safe) if latest else None,
        "other_answers": [_answer_view(sca.answer_for(f, a), hub_safe) for a in answers[1:]],
        "agent_verdict": agent_verdict, "model_comment": model_comment, "advice_conflict": advice_conflict,
        "update_comment": _update_comment(snap, pid, f),
        "target_note": _target_note(agent_version, comment_target, decision, str(defect_view.get("target") or ""), str(defect_view.get("state") or "")),
        "research_shown": _research_revision(db, pid, f),
        # ответ агента не охватывает уязвимости находки; решение «Согласен» принято по другому ответу
        "answer_stale": bool(latest) and not usable and not scope_unknown(latest),
        # охват ответа неизвестен (загружен до этапа 3): ответ не применяется, нужен новый или своё решение
        "scope_unknown": bool(latest) and not covers and scope_unknown(latest),
        "missing_vulns": [i for i in ids if latest and i.casefold() not in
                          {str(x).casefold() for x in latest.get("vulnerabilities") or []}] if latest and not covers
                         else [],
        # ответ исследования не называет уязвимость, у которой только внутренний номер Hub: исследование идёт по
        # публичным данным, повтор этого не изменит – «Согласен с агентом» записывает вывод по компоненту, карточка
        # об этом предупреждает (ADR-0154)
        "answer_by_component": by_component,
        # вне охвата только внутренние номера, но вывод по компоненту «не применимо»: он за неопознанную уязвимость
        # не берётся, карточка ведёт к своему решению
        "missing_internal": bool(latest) and not by_component and bool(sca.internal_gap(ids, latest))
        and str(latest.get("conclusion") or "") == "not_applicable",
        # у находки есть и опознанные уязвимости: вывод сложен из выводов по ним и по компоненту
        "answer_by_component_mixed": bool(by_component) and len(by_component) < len(ids),
        "answer_changed": bool(review and review["decision"] == "agree" and latest and review["answer_sig"]
                               and review["answer_sig"] != answer_signature(latest)),
        # «Согласен с агентом» принято до этапа 3: неизвестно, по какому ответу – подтвердить заново
        "agree_unconfirmed": bool(review and review["decision"] == "agree" and not review["answer_sig"]),
        # записи БДУ ФСТЭК России по CVE находки (страница «Справочники») и дефект для Hub
        "bdu": store_of(request).bdu_by_cve(known_cves(f, aliases)),
        # классы CWE всей библиотеки, а не только этой находки: сначала CWE находки, затем остальные
        "cwe_info": _ordered_cwe(store_of(request), list(f.cwe) + list((group or {}).get("cwe", []))),
        "cwe_own": {cwe_key(c) for c in f.cwe},
        "defect": defect_view,
        # ADR-0096 п. 10: исследование своей версии компонента – основа решения, ссылка на его карточку
        "component_research": component_research_view(pid, snap),
        "ids": [{"id": i, **aliases[i], "checks": _checks(i, aliases[i]["aliases"])} for i in ids],
        "hub_safe": sca.first_version(f.fixed_version), "siblings": siblings,
        # состояние относительно Hub (dev15, бэклог 88): та же функция, что у синхронизации; считается одна находка
        "hub_state": hub_state.project_states(db, project, settings.hub_url,
                                              keys=[hub_state.issue_key(row)])["by_hub_id"].get(f.hub_id),
        "package_rows": package_rows, "package_fp": snap.fingerprint,
        "extra": ({k: mask_text(str(v), mask_key)[0] for k, v in f.extra.items()} if mask_display.masked(project)
                  else {k: str(v) for k, v in f.extra.items()}),  # показ по флажку проекта (dev14, ADR-0141)
        "prev_id": db.neighbor_unreviewed(pid, row["pos"], "prev", kinds=SCA_KINDS,
                                          hub_ids=(hub_ids := back_hub_ids(request, project)),
                                          filters=(back_sel := back_filters(request, project)),
                                          only_unreviewed=not back_walks_all(back_sel)),
        "next_id": db.neighbor_unreviewed(pid, row["pos"], "next", kinds=SCA_KINDS, hub_ids=hub_ids,
                                          filters=back_sel, only_unreviewed=not back_walks_all(back_sel)),
        "progress": {"total": int(stats.get("sca") or 0), "reviewed": int(stats.get("sca_reviewed") or 0)},
        "saved_row": saved_row, "status_map": settings.hub_status_map,
        # «Отправить в Hub» (ADR-0115): отпечаток – той же строки, что предпросмотр (одно чтение); у черновика – нет
        "hub_status_now": (status_now := hub_status_routes.status_now(db, project, settings_of(request), f)),
        "entered_scope_note": hub_status_routes.entered_scope_note(review, status_now),
        "hub_send": {**hub_status_routes.card_context(request, project, f.hub_id, saved_text,
                                                      note=hub_status_routes.DRAFT_NOTE if draft is not None else ""),
                     "research_conflict": unconfirmed_conflict(db, pid, f, review)},
        # «Создать дефект в Hub» (ADR-0120): дефект набора запросом через исполнителя
        "hub_defect": hub_defect_routes.card_context(request, project, f.hub_id),
        "need_texts": {"reason": RISK_NEEDS_REASON, "verdict": NEED_VERDICT, "kapo": KAPO_NEEDS_CHOICE},
        "finding_version": db.review_version(pid, f.hub_id),
        "answer_id": str(latest["id"]) if latest else "",
        "review_revision": int(review["revision"]) if review else 0,
        "verdict_labels": [(v, sca.DECISION_LABELS[sca.VERDICT_CONCLUSION[v]]) for v in VERDICTS],
        "conclusion_labels": sca.CONCLUSION_LABELS,
        # числа на вкладках проекта
        "counts": db.count_findings(pid), "stats": stats,
    }


def summary_decision(review: dict | None) -> str:
    """Решение в строке «итог разбора» под заголовком карточки – только по сохранённой записи (ревью dev28)."""
    if not review or not (review.get("decision") or review.get("final_verdict")):
        return "не принято"
    if review.get("decision") == "later":
        return "отложено"
    return OUTCOME_LABELS.get(hub_verdict(review.get("decision") or "", review.get("final_verdict") or ""), "неясно")


def back_hub_ids(request, project: dict):
    """Отбор «Синхронизация с Hub» списка находок, из которого открыта карточка SCA (параметр hubsync адреса возврата,
    dev15): соседи карточки и переход после сохранения – внутри него (ревью кода dev15, круг 1). Без отбора – None."""
    from urllib.parse import parse_qs
    back = worklists.return_url(request, back_fallback(request, project["id"]))
    choice = (parse_qs(urlsplit(back).query).get("hubsync") or [""])[-1]
    if choice not in ("unsent", "differs"):
        return None
    states = hub_state.project_states(db_of(request), project, settings_of(request).hub_url)
    field = "unsent" if choice == "unsent" else "differs"
    return {hub_id for hub_id, st in states["by_hub_id"].items() if st[field]}


def back_filters(request, project: dict) -> dict | None:
    """Отбор списка находок, из которого открыта карточка SCA (адрес возврата – `/projects/<id>/findings?…`): соседи
    карточки и переход после сохранения – внутри него (ревью Codex dev18: многозначный статус Hub и новые флаги). Вид
    находки задаёт сама карточка (SCA); без отбора или из другой страницы – None."""
    from starlette.datastructures import QueryParams

    from app.routes.findings import read_selection, selection_filters
    back = worklists.return_url(request, back_fallback(request, project["id"]))
    parts = urlsplit(back)
    if parts.netloc or not parts.path.startswith("/projects/") or not parts.path.endswith("/findings"):
        return None
    selection = {k: v for k, v in read_selection(QueryParams(parts.query)).items() if k not in ("back", "kind")}
    if not selection:
        return None
    filters = selection_filters(selection)
    filters["kind"] = ""
    return filters


def back_walks_all(filters: dict | None) -> bool:
    """Отбор списка – по проверенным («проверено: да», «внесены», «не скопированы», «выбыли»): обход идёт по всем
    находкам отбора, как walks_all списка находок; иначе – по непроверенным."""
    if not filters:
        return False
    return (filters.get("copied") == "no" or filters.get("reviewed") == "yes" or filters.get("entered") == "yes"
            or bool(filters.get("dropped")))


def back_fallback(request, project_id) -> str:
    """Куда карточка SCA может вернуться: список SCA (по умолчанию), список находок или карточка компонента, из «Где
    используется» которой она открыта, – по строгому образцу пути; иное значение back не принимается."""
    back_path = request.query_params.get("back", "").split("?")[0]
    if back_path == f"/projects/{project_id}/findings":
        return back_path
    if re.fullmatch(rf"/projects/{project_id}/components/[a-z0-9]{{1,24}}:[0-9a-f]{{16}}", back_path):
        return back_path
    return f"/projects/{project_id}/sca"


def redirect_with_back(request, url):
    """Прежняя карточка SCA после сохранения помнит тот же рабочий список (или карточку компонента)."""
    if "back" not in request.query_params:
        return redirect(url)
    pid = request.path_params["project_id"]
    back = worklists.return_url(request, back_fallback(request, pid))
    target = urlsplit(url)
    params = list(parse_qsl(target.query))
    if target.path in (f"/projects/{pid}/sca", f"/projects/{pid}/findings"):
        queue = urlsplit(back)
        return redirect(urlunsplit(("", "", queue.path, urlencode([*parse_qsl(queue.query), *params]), queue.fragment)))
    return redirect(urlunsplit(("", "", target.path, urlencode([*params, ("back", back)]), target.fragment)))


def _package_row_state(review: dict | None) -> str:
    """Подпись решения находки в списке пакетного решения."""
    if not review or not (review.get("decision") or review.get("final_verdict")):
        return "решения нет"
    if review.get("decision") == "later":
        return "отложено"
    label = OUTCOME_LABELS.get(hub_verdict(review["decision"], review["final_verdict"]), "")
    return f"{label}{', проверено' if review.get('reviewed') else ''}"


def card_response(request: Request, project_id: int, finding_id: int, error: str = "", status_code: int = 200,
                  draft: dict | None = None, reveal_revision: int | None = None,
                  defect_extra: dict | None = None) -> HTMLResponse:
    project = project_or_404(request, project_id)
    db = db_of(request)
    hub_id = _sca_row(db, project_id, finding_id)["hub_id"]
    # Карточка – из согласованного состояния пакета (К4): строится между двумя одинаковыми отпечатками пакета
    # (данные и решения находок, ответ агента, соответствия, исследование, наборы, тексты, номера). Импорт или
    # другая вкладка между чтениями – карточка собирается заново; не успокоилось за три попытки – отпечаток формы
    # пустой, пакетное сохранение откажет и попросит обновить карточку
    for _ in range(3):
        before = db.sca_defect_fingerprint(project_id, hub_id)
        row = _sca_row(db, project_id, finding_id)
        view = card_view(request, project, row, draft)
        if before == view["package_fp"] == db.sca_defect_fingerprint(project_id, hub_id):
            break
    else:
        view["package_fp"] = ""
        # и отправка в Hub: карточка собрана из несогласованных чтений – отпечатка текста нет, отправка откажет
        view["hub_send"].update(text_hash="", note=hub_status_routes.UNSETTLED_NOTE)
        error = error or "Данные этой версии компонента меняются (идёт загрузка): обновите карточку через минуту."
    from app.routes.capec import related_context, cwe_values
    capec_context = related_context(request, cwe_values(row['data'].get('cwe',[])), project_id)
    fallback = back_fallback(request, project_id)
    # текст выдан по отметке «Текст проверен» (форма без скрипта): раскрывается только та же редакция решения
    defect_now = view.get("defect")
    if reveal_revision is not None and defect_now and defect_now.get("review_revision") == reveal_revision:
        defect_now["comment_check"] = False
    if defect_extra and defect_now:  # отказ выдачи без скрипта: предупреждения и введённый номер – в форме дефекта
        defect_now.update(defect_extra)
    return render(request, "sca/card.html", {**view, "error": error, "capec_context": capec_context,
                  # back_url уходит дальше в формы и заготовку как есть; якорь таблицы – только у видимой ссылки
                  "back_url": worklists.return_url(request, fallback)}, status_code)


@router.get("/projects/{project_id}/sca/findings/{finding_id}", response_class=HTMLResponse)
def finding_page(request: Request, project_id: int, finding_id: int):
    return card_response(request, project_id, finding_id)


def _normalized_decision(decision: str, final_verdict: str, agent_verdict: str) -> tuple[str, str]:
    """«Согласен» – вывод агента; «Своё решение» всегда хранится как disagree."""
    if not decision:
        raise ReviewRejected("Выберите решение в нижней панели: «Согласен с агентом», «Своё решение», «Отложить» или «Риск принят».")
    if decision == "disagree" and not final_verdict:
        raise ReviewRejected(NEED_VERDICT)
    if decision == "agree":
        if not agent_verdict:
            raise HTTPException(status_code=400, detail="«Согласен с агентом» можно выбрать, только когда есть ответ "
                                                        "агента с выводом.")
        if final_verdict and final_verdict != agent_verdict:
            raise HTTPException(status_code=400, detail="«Согласен с агентом» означает вывод агента. Чтобы выбрать "
                                                        "другой вывод, отметьте «Своё решение».")
        return decision, agent_verdict
    return decision, final_verdict


def _save_package(db: Database, project_id: int, f: Finding, latest: dict | None, others: list[str], *,
                  decision: str, final_verdict: str, kept: str, chosen: str, comment: str, reviewed: bool,
                  expect: dict, kapo: str, require_present: bool, package_fp: str,
                  apply_revs: dict[str, int | None], apply_vers: dict[str, str] | None = None) -> dict:
    """Пакетное решение (ADR-0091 п. 4): решение находки f и отмеченных находок others её версии компонента – одной
    транзакцией. В транзакции сверяются редакция каждой находки и отпечаток пакета, который видел человек: не совпало
    – не записывается ничего (StaleReview "package" с перечнем изменившихся находок). «Согласен с агентом» – только
    к находкам с тем же выводом агента (ReviewRejected). Возвращает решение по f."""
    snap = db.sca_snapshot(project_id, f.hub_id)
    current = {m["hub_id"]: m for m in snap.current_members}
    revisions = {**apply_revs, f.hub_id: expect.get("revision")}
    versions = {**(apply_vers or {}), f.hub_id: expect.get("version")}

    def changed_message() -> str:
        now = db.sca_snapshot(project_id, f.hub_id)
        alive = {m["hub_id"] for m in now.current_members}
        shown = set(revisions) | set(versions)
        names = sorted(h for h in shown | alive if h not in alive or h not in shown or (
            revisions.get(h) is not None
            and int((now.get_review(project_id, h) or {}).get("revision") or 0) != int(revisions[h])) or (
            versions.get(h) is not None and db.review_version(project_id, h) != versions[h]))
        return STALE_MESSAGES["package"] + (f" Изменились находки: {', '.join(names)}." if names else
                                            " Изменились исследование компонента, текст или набор дефекта.")

    if not package_fp or snap.fingerprint != package_fp or any(h not in current for h in others):
        raise StaleReview(changed_message(), "package")
    outcome = hub_verdict(kept, chosen)
    items = [{"hub_id": f.hub_id, "decision": kept, "final_verdict": chosen, "final_comment": comment,
              "reviewed": reviewed, "verdict_id": None, "expect": expect, "answer_sig": answer_signature(latest),
              "require_present": require_present, "kapo_state": kapo, "recheck": not require_present}]
    odd = []
    for hub_id in others:
        item = Finding.from_dict(current[hub_id]["data"])
        try:
            item_kept, item_chosen = _normalized_decision(decision, final_verdict, answer_verdict(item, latest))
        except HTTPException:
            odd.append(hub_id)
            continue
        if hub_verdict(item_kept, item_chosen) != outcome:
            odd.append(hub_id)
            continue
        items.append({"hub_id": hub_id, "decision": item_kept, "final_verdict": item_chosen, "final_comment": comment,
                      "reviewed": reviewed, "verdict_id": None,
                      "expect": {"version": db.review_version(project_id, hub_id), "verdict_id": None,
                                 "revision": revisions.get(hub_id), "answer_id": expect["answer_id"]},
                      "answer_sig": answer_signature(latest), "require_present": True, "kapo_state": kapo,
                      "recheck": not require_present})
    if odd:
        raise ReviewRejected(PACKAGE_MISMATCH.format(ids=", ".join(odd)))

    def check(c) -> None:
        if db._sca_defect_fingerprint(c, project_id, f.hub_id) != package_fp:
            raise StaleReview("пакет изменился", "package")

    after_fp: dict[str, str] = {}

    def remember(c) -> None:  # отпечаток пакета сразу после своей записи – той же транзакцией (К6)
        after_fp["fp"] = db._sca_defect_fingerprint(c, project_id, f.hub_id)

    try:
        saved = db.save_reviews(project_id, items, check=check, after=remember)
        return {**saved[0], "_package_after": after_fp.get("fp", "")}
    except StaleReview as e:
        if e.reason in ("package", "revision", "source", "missing"):
            raise StaleReview(changed_message(), "package") from e
        raise


@router.post("/projects/{project_id}/sca/findings/{finding_id}/review")
async def save_review(request: Request, project_id: int, finding_id: int):
    form = await request.form()
    decision = str(form.get("decision") or "")
    final_verdict = str(form.get("final_verdict") or "")
    comment = str(form.get("comment") or "").replace("\r\n", "\n")[:MAX_COMMENT]
    reviewed = str(form.get("reviewed") or "") == "1"
    action = str(form.get("action") or "save")
    kapo_form = str(form.get("kapo_state") or "")
    shown_version = str(form.get("finding_version") or "")
    # редакция решения и ответ агента, которые видел человек; страница без этих полей проверяется по версии находки
    shown_revision = _form_int(form.get("review_revision"))
    shown_answer = None if form.get("answer_id") is None else str(form.get("answer_id")).strip()
    # пакетное решение (ADR-0091 п. 4): отмеченные находки версии, отпечаток пакета и редакции, которые видел человек
    package_mode = str(form.get("apply_package") or "") == "1"
    apply_to = list(dict.fromkeys(str(x) for x in form.getlist("apply_to"))) if package_mode else []
    package_fp = str(form.get("package_fp") or "")
    apply_revs = {str(k)[len("apply_rev_"):]: _form_int(v) for k, v in form.multi_items()
                  if str(k).startswith("apply_rev_")}
    apply_vers = {str(k)[len("apply_ver_"):]: str(v) for k, v in form.multi_items() if str(k).startswith("apply_ver_")}
    wants_json = action == "copy" or _wants_json(request)

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        settings = settings_of(request)
        row = _sca_row(db, project_id, finding_id)
        if decision not in ("", *DECISIONS) or final_verdict not in ("", *VERDICTS):
            raise HTTPException(status_code=400, detail="Неверное решение или вывод.")
        f = Finding.from_dict(row["data"])
        # раньше проверок решения: что видел человек (находка, ответ агента, решение)
        if db.review_version(project_id, f.hub_id) != shown_version:
            raise StaleReview("страница устарела", "source")
        latest = _latest_answer(db, project_id, f)
        if shown_answer is not None and shown_answer != (str(latest["id"]) if latest else ""):
            raise StaleReview("страница устарела", "answer")
        old = db.get_review(project_id, f.hub_id)
        if shown_revision is not None and (int(old["revision"]) if old else 0) != shown_revision:
            raise StaleReview("страница устарела", "revision")
        agent_verdict = answer_verdict(f, latest)
        kept, chosen = _normalized_decision(decision, final_verdict, agent_verdict)
        # совет принимается по исследованию, которое видел оператор: пришло новое – страница устарела, подтверждение к нему не относится
        if kept == "agree" and form.get("research_shown") is not None and str(form.get("research_shown")) != _research_revision(db, project_id, f):
            raise StaleReview("страница устарела", "answer")
        if kept == "agree" and str(form.get("confirm_conflict") or "") != "1":
            conflict = _finding_conflict(db, project_id, f, latest)
            if conflict:
                raise ReviewRejected(f"Совет агента «не применимо» расходится с исследованием ({conflict}). Сверьте исследование; "
                                     "чтобы всё же принять совет, отметьте подтверждение рядом с решением.")
        # обоснование обязательно: вводное «Ложное срабатывание:» и подобное (К8) и внутренние номера AST (ADR-0101) его
        # не заменяют; в Hub комментарий уходит как написан, без AST (ADR-0149), вводное слово снимается только здесь
        if kept == "risk_accepted" and not sca.short_reason(comment):
            raise ReviewRejected(RISK_NEEDS_REASON)
        if hub_verdict(kept, chosen) == "false_positive" and not sca.short_reason(comment):
            raise ReviewRejected(FP_NEEDS_REASON)
        if action == "copy" and hub_verdict(kept, chosen) not in sca.SHORT_OUTCOMES:
            raise ReviewRejected(SCA_NO_SHORT)
        origin = comment_origin(db, project_id, f, comment)
        # «Текст проверен» – только с редакцией решения, которую видел человек (BUG-01, одно правило с SAST)
        if (action == 'copy' or kept == 'risk_accepted') and origin and origin != hub_verdict(kept, chosen):
            if not comment_confirm_valid(form, old):
                raise CommentNeedsCheck(comment_check_text(origin, hub_verdict(kept, chosen)))
        comment_confirmed = comment_confirm_valid(form, old, strict=False)
        # текст в ответе на обычное сохранение – только по решению с обоснованием человека (ADR-0088)
        text_ok = bool(kept) and not (origin and origin != hub_verdict(kept, chosen) and not comment_confirmed)
        # уточнение по ГОСТ Р КАПО – после нормализации решения: допустимые пары итога и уточнения
        kapo = normalized_kapo(hub_verdict(kept, chosen), kapo_form)
        # ответ агента проверяется и в самой транзакции записи (ожидаемый номер – тот, что видел человек; у страницы
        # без этого поля – тот, что прочитан выше): ответ, загруженный между проверкой и записью, решение не пропустит
        expect = {"version": shown_version, "verdict_id": None, "revision": shown_revision,
                  "answer_id": shown_answer if shown_answer is not None else (str(latest["id"]) if latest else "")}
        # «Отложить» – вернуться позже: находка остаётся непроверенной. Решение помнит, по какому ответу агента
        # оно принято: новый ответ с другим выводом вернёт «Согласен с агентом» на проверку
        others = [h for h in apply_to if h != f.hub_id]
        try:
            if package_mode:
                review = _save_package(db, project_id, f, latest, others, decision=decision,
                                       final_verdict=final_verdict, kept=kept, chosen=chosen, comment=comment,
                                       reviewed=reviewed and decision != "later", expect=expect, kapo=kapo,
                                       require_present=action == "copy", package_fp=package_fp,
                                       apply_revs=apply_revs, apply_vers=apply_vers)
            else:
                review = db.save_review(project_id, f.hub_id, decision=kept, final_verdict=chosen,
                                        final_comment=comment, reviewed=reviewed and decision != "later",
                                        verdict_id=None, expect=expect, answer_sig=answer_signature(latest),
                                        require_present=action == "copy", kapo_state=kapo, recheck=action != "copy")
        except StaleReview as e:
            if e.reason == "missing":  # находка исчезла из выгрузки между проверкой и записью: текст не копируется
                raise ReviewRejected(copy_missing_message(old)) from e
            raise
        # Ответ описывает одно состояние базы, прочитанное после записи одним снимком (db.sca_snapshot): находка, решение,
        # ответ агента, состав группы, соответствия AST → CVE, номера дефектов и счётчики. Замок держится только на чтение
        # этих данных; текст, готовность дефекта и справочники считаются вне замка на данных снимка. Если после записи
        # находка изменилась или пропала из выгрузки, а решение или ответ агента сменились, ответ строится по ним, а не по
        # данным, прочитанным до записи; разрешение копировать (copy_allowed) – по тому же состоянию.
        saved_revision = int(review["revision"])
        review_package_after = review.pop("_package_after", "") if isinstance(review, dict) else ""
        snap = db.sca_snapshot(project_id, f.hub_id)
        if snap.row is None or snap.review is None:
            raise StaleReview("Проект или находка исчезли, пока решение сохранялось.", "deleted")
        f_now = Finding.from_dict(snap.row["data"])
        review = snap.review
        # после записи решение сохранили ещё раз (другая вкладка): текст по чужой редакции не выдаётся (R092-02)
        foreign = int(review["revision"]) != saved_revision
        # пакетные поля формы обновляются, только если снимок – ровно состояние после своей записи: иначе другая
        # вкладка успела изменить пакет, и форма должна это показать, а не принять молча (К6)
        package_after = str(review_package_after or "")
        package_fresh = bool(package_after) and snap.fingerprint == package_after
        latest_now = snap.latest_answer
        ids = sca.finding_ids(f_now)
        aliases = sca.aliases_for(ids, snap.ast_map(ids) if ids else {}, latest_now)
        text = sca.hub_text(f_now, hub_verdict(review["decision"], review["final_verdict"]), review["final_comment"],
                            settings.hub_status_map, aliases, kapo_state=review.get("kapo_state") or "")
        defect_now = sca_defect(snap, store_of(request), project_id, f_now, review)  # с проверкой итогов группы
        ready = defect_now["ready"]
        moved = (str(latest_now["id"]) if latest_now else "") != str(expect["answer_id"])
        notices = []
        if moved:
            notices.append("Пока решение сохранялось, пришёл новый ответ агента: отметка «Проверено» снята. Обновите "
                           "карточку, посмотрите новый ответ и сохраните решение ещё раз.")
        if foreign:
            notices.append("Пока решение сохранялось, его изменили в другой вкладке: текст для Hub не скопирован. "
                           "Обновите карточку и проверьте решение.")
        # «сохранено и для находок …» – не предупреждение: браузер дописывает его к подтверждению по полю applied
        if package_mode and not package_fresh:
            notices.append("Пока решение сохранялось, другие находки этой версии или набор дефекта изменились: "
                           "обновите карточку, прежде чем сохранять дальше.")
        if snap.row["missing"]:
            notices.append("Пока решение сохранялось, находка пропала из выгрузки: текст для Hub не копируется.")
        elif snap.row["data"] != row["data"]:
            notices.append("Пока решение сохранялось, данные находки изменились (новая выгрузка): текст для Hub собран "
                           "по новым данным – сверьте решение.")
        return {"review": review, "text": text if text_ok and not foreign else "", "next_id": snap.next_id,
                "ready": ready,
                # режим панели «Отправить в Hub» после сохранения (dev29)
                "replace": hub_status_routes.replace_answer(request, project_id, f_now.hub_id, review,
                                                            text if text_ok and not foreign else ""),
                "notice": " ".join(notices),
                "progress": {"total": int(snap.stats.get("sca") or 0), "reviewed": int(snap.stats.get("sca_reviewed") or 0)},
                "copy_allowed": not snap.row["missing"] and not foreign and text_ok, "answer_moved": moved,
                "defect_state": str(defect_now.get("state") or ""),
                # номер ответа, по которому принято решение (его видел человек): форма его не меняет, пока человек не
                # увидел новый ответ, – иначе следующее «Проверено» стало бы согласием с ответом, которого он не видел
                "answer_id": str(expect["answer_id"]),
                "current_answer_id": str(latest_now["id"]) if latest_now else "", "applied": others,
                # поля пакетного решения после своей записи (К6): иначе следующее сохранение из той же карточки
                # сочло бы пакет изменившимся
                "package_stale": bool(package_mode and not package_fresh),
                "package": None if not package_fresh else {"fp": snap.fingerprint,
                            "revisions": {m["hub_id"]: int((snap.get_review(project_id, m["hub_id"]) or {})
                                                           .get("revision") or 0) for m in snap.current_members},
                            "versions": {m["hub_id"]: db.review_version(project_id, m["hub_id"])
                                         for m in snap.current_members}}}

    try:
        done = await run_in_threadpool(apply)
        review, text, next_id, ready = done["review"], done["text"], done["next_id"], done["ready"]
    except CommentNeedsCheck as e:
        if wants_json:
            return JSONResponse({'ok': False, 'detail': str(e), 'reason': 'comment'}, status_code=409)
        draft = {'decision': decision, 'final_verdict': final_verdict, 'comment': comment, 'reviewed': reviewed,
                 'kapo_state': kapo_form, **({"apply_to": apply_to} if package_mode else {})}
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409, draft)
    except ReviewRejected as e:
        if wants_json:
            return JSONResponse({"ok": False, "detail": str(e), "reason": "rejected"}, status_code=400)
        draft = {"decision": decision if decision in DECISIONS else "",
                 "final_verdict": final_verdict if final_verdict in VERDICTS else "", "comment": comment,
                 "reviewed": reviewed, "kapo_state": kapo_form, **({"apply_to": apply_to} if package_mode else {})}
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 400, draft)
    except StaleReview as e:
        message = str(e) if e.reason == "package" else STALE_MESSAGES.get(e.reason, STALE_MESSAGES["source"])
        if wants_json:
            return JSONResponse({"ok": False, "detail": message, "reason": e.reason}, status_code=409)
        # введённое человеком не теряется: черновик подставляется в форму, но не пишется
        draft = {"decision": decision if decision in DECISIONS else "",
                 "final_verdict": final_verdict if final_verdict in VERDICTS else "", "comment": comment,
                 "reviewed": False, "kapo_state": kapo_form, **({"apply_to": apply_to} if package_mode else {})}
        return await run_in_threadpool(card_response, request, project_id, finding_id,
                                       message + " Ваш вариант решения подставлен в форму – сверьте его и сохраните "
                                       "ещё раз. Отметка «Проверено» снята: после сверки установите её заново.",
                                       409, draft)
    if wants_json:
        return JSONResponse({"ok": True, "hub_text": text, "copy_allowed": done["copy_allowed"],
                             "hub_send_hash": text_hash(text) if text else "",  # отпечаток для «Отправить в Hub»
                             "hub_replace": done["replace"],  # режим панели «Отправить в Hub» (dev29)
                             "final_verdict": review.get("final_verdict", ""),
                             "summary_decision": summary_decision(review),  # строка «итог разбора» (ревью dev28)
                             "defect_ready": ready, "progress": done["progress"], "notice": done["notice"],
                             "applied": done.get("applied") or [],
                             "answer_id": done["answer_id"], "answer_moved": done["answer_moved"],
                             "current_answer_id": done["current_answer_id"], "package": done["package"],
                             "package_stale": done["package_stale"],
                             **review_json(review)})
    if action == "next":
        # отбор списка, из которого открыта карточка (dev15 – «Синхронизация с Hub», dev18 – предметный отбор): следующая
        # ищется внутри него заново, независимо от общего next_id (ревью Codex dev18, круг 3)
        project = project_or_404(request, project_id)
        hub_ids, back_sel = back_hub_ids(request, project), back_filters(request, project)
        if hub_ids is not None or back_sel is not None:
            next_id = db_of(request).neighbor_unreviewed(project_id, _sca_row(db_of(request), project_id, finding_id)["pos"],
                                                         "next", kinds=("SCA",), hub_ids=hub_ids, filters=back_sel,
                                                         only_unreviewed=not back_walks_all(back_sel))
    if action == "next":
        if next_id is not None:  # на следующей карточке – строка «Сохранено: … · вернуться»
            return redirect_with_back(request, f"/projects/{project_id}/sca/findings/{next_id}?saved={finding_id}")
        if not review.get("reviewed"):  # отложена или без «Проверено»: сама она ещё не проверена
            return redirect_with_back(request, f"/projects/{project_id}/sca/findings/{finding_id}?ok=sca_no_other#decision")
        return redirect_with_back(request, f"/projects/{project_id}/sca?ok=sca_all_reviewed#components")
    # следующий шаг оператора – ниже на странице, чтобы не бросать его то вверх, то вниз:
    # текст готов – к блоку «Создать дефект в Hub», «Обновить» – к дефекту по шаблону, иначе – к «Отправить в Hub»
    outcome = hub_verdict(review.get("decision") or "", review.get("final_verdict") or "")
    anchor = "#decision"  # следующего шага на странице нет (отложено, неясно): карточка остаётся на решении, а не в начале
    if review.get("decision") != "later" and outcome == "true_positive":
        anchor = "#hub-defect-section" if ready else {"ok": "#sca-set", "text": "#sca-set"}.get(
            done["defect_state"], "#defect-blocked" if done["defect_state"] in DEFECT_BLOCKED_STATES else "#decision")
    elif review.get("decision") != "later" and outcome in sca.SHORT_OUTCOMES:
        anchor = "#hub-send"
    return redirect_with_back(request, f"/projects/{project_id}/sca/findings/{finding_id}?ok=sca_saved{anchor}")


@router.post("/projects/{project_id}/sca/findings/{finding_id}/defect")
async def copy_defect(request: Request, project_id: int, finding_id: int):
    """Заголовок и текст дефекта SCA для Hub (JSON: number, title, body, note): номер из формы запоминается за
    библиотекой и версией. Без скрипта – переход обратно на карточку с текстом в разделе «Дефект для Hub»."""
    from app.routes.findings import (DEFECT_NOT_READY, NUMBER_CHANGED, DefectNeedsConfirm, DefectReload,
                                     defect_duplicates_note, defect_error_response, duplicate_number_warning,
                                     confirm_extra, expected_number, number_shown_changed, read_defect_number)

    form = await request.form(max_fields=10, max_files=0)
    confirmed = str(form.get("confirm") or "") == "1"
    stale_confirmed = []  # комментарий агента к другому выводу выдан по отметке «Текст проверен»

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        hub_id = _sca_row(db, project_id, finding_id)["hub_id"]
        number = read_defect_number(form)
        # Всё, из чего строится текст (находка и пакет, решения участников группы, ответ агента, соответствия AST → CVE,
        # номера дефектов), и отпечаток этих данных читаются одним снимком (db.sca_snapshot): текст строится из того же, что
        # покрыто отпечатком, вне замка, а номер записывается, только если отпечаток в момент записи тот же (CWE-367).
        # Цикл A → B → A между чтениями невозможен: чтения в одном захвате замка, записи в них не вклиниваются
        snap = db.sca_snapshot(project_id, hub_id)
        if snap.row is None:
            raise StaleReview("Проект или находка исчезли.", "deleted")
        f = Finding.from_dict(snap.row["data"])
        view = sca_defect(snap, store_of(request), project_id, f, snap.review, number)
        if number_shown_changed(form, snap.defect_number(project_id, set_key(f, view["set_no"]))):
            raise DefectReload(NUMBER_CHANGED)
        if not view["ready"]:
            raise ReviewRejected(view["hint"] if view.get("state") in ("stale", "conflict", "missing", "changed", "text",
                                                                       "short_only", "no_defect")
                                 else DEFECT_NOT_READY)
        stale = view.get("comment_stale") or []
        others = [x for x in stale if x != f.hub_id]
        if others:  # подтвердить чужую карточку отсюда нельзя: комментарий правится в ней самой
            raise CommentNeedsCheck(
                "В дефект входят находки, где комментарий – текст агента к другому выводу: " + ", ".join(others[:10])
                + (f" и ещё {len(others) - 10}" if len(others) > 10 else "")
                + ". Откройте их карточки, поправьте комментарий и сохраните – затем скопируйте ещё раз.")
        if f.hub_id in stale:
            own = snap.review or {}
            # отметка «Текст проверен» – к той редакции решения, которую человек видел
            if not comment_confirm_valid(form, own):
                target = hub_verdict(own.get("decision") or "", own.get("final_verdict") or "")
                raise CommentNeedsCheck(comment_check_text(
                    comment_origin(snap, project_id, f, own.get("final_comment") or ""), target))
            stale_confirmed.append(int(own.get("revision") or 0))
        own_key = set_key(f, view["set_no"])
        package = own_key[:own_key.rindex("#")] if own_key.endswith(f"]#{view['set_no']}") else own_key
        # другие наборы того же пакета с этим номером – отказ в транзакции записи; прочие – предупреждение
        foreign = [k for k in db.defect_keys_with_number(project_id, view["number"])
                   if k != own_key and k != package and not k.startswith(package + "#")]
        warnings = view["warnings"] + duplicate_number_warning(foreign)
        if warnings and not confirmed:
            raise DefectNeedsConfirm(warnings)
        def foreign_check(keys: list[str]) -> None:  # в транзакции записи (К3): чужой номер – только с подтверждением
            outside = [k for k in keys if k != own_key and k != package and not k.startswith(package + "#")]
            warning = duplicate_number_warning(outside)
            if warning and not confirmed:
                raise DefectNeedsConfirm(warning)

        duplicates = db.set_sca_defect_number_checked(project_id, set_key(f, view["set_no"]), view["number"],
                                                      f.hub_id, snap.fingerprint, expect_number=expected_number(form),
                                                      foreign_check=foreign_check)
        note = " ".join(x for x in (view["note"], defect_duplicates_note(duplicates)) if x)
        return {**view, "note": note}

    try:
        view = await run_in_threadpool(apply)
    except CommentNeedsCheck as e:
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e), "reason": "comment"}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409)
    except StaleReview as e:  # пока готовился текст, изменились группа, решения, ответ агента или соответствия
        message = "Дефект не выдан: пока готовился текст, данные изменились. " + STALE_MESSAGES.get(
            e.reason, STALE_MESSAGES["source"])
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": message, "reason": e.reason}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, message, 409)
    except ValueError as e:
        if _wants_json(request):
            return defect_error_response(e, ReviewRejected)
        if isinstance(e, DefectNeedsConfirm):  # без скрипта (К5): флажок подтверждения открыт, номер сохранён
            return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409, None, None,
                                           confirm_extra(form, e))
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 400)
    if _wants_json(request):
        return {"ok": True, "number": view["number"], "title": view["title"], "body": view["body"],
                "note": view["note"], "text_sig": view.get("text_sig", "")}
    if stale_confirmed:  # без скрипта: карточка показывает выданный по отметке текст
        return await run_in_threadpool(card_response, request, project_id, finding_id, "", 200, None,
                                       stale_confirmed[0])
    return redirect_with_back(request, f"/projects/{project_id}/sca/findings/{finding_id}?ok=defect_saved#defect-panel")


MAX_EXPLANATION = 20000


@router.post("/projects/{project_id}/sca/findings/{finding_id}/exclude")
async def save_exclusion(request: Request, project_id: int, finding_id: int):
    """Исключение уязвимости из текста набора с обоснованием или возврат (ADR-0091 п. 9): action – exclude или
    include. Состав уязвимости – по снимку пакета на сервере; запись – одной транзакцией со сверкой отпечатка,
    который видел человек, и редакции набора; не совпало – 409, ничего не записано."""
    form = await request.form()
    vuln = str(form.get("vuln_key") or "").strip()
    action = str(form.get("action") or "")
    reason = str(form.get("reason") or "").replace("\r\n", "\n").strip()
    shown_set = _form_int(form.get("set_no")) or 0
    set_revision = _form_int(form.get("set_rev")) or 0
    shown_fp = str(form.get("shown_fp") or "")

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        if action not in ("exclude", "include"):
            raise ReviewRejected("Неизвестное действие с текстом дефекта.")
        if action == "exclude" and not reason:
            raise ReviewRejected("Исключение из текста сохраняется только с обоснованием: напишите, почему.")
        if len(reason) > MAX_APPLICABILITY_REASON:
            raise ReviewRejected(f"Обоснование длиннее {MAX_APPLICABILITY_REASON} знаков: сократите его.")
        hub_id = _sca_row(db, project_id, finding_id)["hub_id"]
        snap = db.sca_snapshot(project_id, hub_id)
        if snap.row is None:
            raise StaleReview("Проект или находка исчезли.", "deleted")
        f = Finding.from_dict(snap.row["data"])
        view = sca_defect(snap, store_of(request), project_id, f, snap.review)
        if int(view.get("set_no") or 0) != shown_set:
            raise StaleReview("Находку перенесли в другой набор дефекта.", "set")
        pool = view.get("vulns") if action == "exclude" else view.get("excluded_vulns")
        item = next((v for v in pool or [] if (v.get("main") or v.get("id")) == vuln), None)
        if item is None:
            raise StaleReview("Уязвимости уже нет в этом списке.", "package")
        db.save_sca_exclusion(project_id, hub_id, shown_set, vuln, item["ids"], reason, action == "exclude",
                              expect_set_revision=set_revision, expect_fp=shown_fp)

    try:
        await run_in_threadpool(apply)
    except StaleReview as e:
        message = STALE_MESSAGES["deleted"] if e.reason == "deleted" else (
            "Пока карточка была открыта, изменились данные пакета или набор дефекта: состав текста не изменён. "
            "Сверьте карточку и повторите.")
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": message, "reason": e.reason, "reload": True}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, message, 409)
    except (ReviewRejected, ValueError) as e:
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e)}, status_code=400)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 400)
    if _wants_json(request):
        return {"ok": True}
    return redirect_with_back(request, f"/projects/{project_id}/sca/findings/{finding_id}"
                                       "?ok=sca_exclusion_saved#sca-set-vulns")


@router.post("/projects/{project_id}/sca/findings/{finding_id}/applicability")
async def save_applicability(request: Request, project_id: int, finding_id: int):
    """Решение оператора о применимости класса уязвимости (ADR-0094 Р3): «применима», «не затрагивает текущую
    версию», «не применима к продукту» – с обоснованием; пустое решение снимает прежнее. Состав класса вычисляется
    сервером по снимку пакета, запись – одной транзакцией со сверкой отпечатка, который видел человек, ревизии
    исследования и редакции решения (Р4.5); не совпало – 409, ничего не записано."""
    form = await request.form()
    vuln = str(form.get("vuln_key") or "").strip()
    decision = str(form.get("decision") or "").strip()
    reason = str(form.get("reason") or "").replace("\r\n", "\n").strip()
    revision = _form_int(form.get("revision")) or 0
    research_revision = _form_int(form.get("research_revision")) or 0
    shown_fp = str(form.get("shown_fp") or "")

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        if decision and decision not in sca_text.APPLICABILITY_LABELS:
            raise ReviewRejected("Неизвестное решение о применимости.")
        if decision and not reason:
            raise ReviewRejected("Решение о применимости сохраняется только с обоснованием: напишите, почему.")
        if len(reason) > MAX_APPLICABILITY_REASON:
            raise ReviewRejected(f"Обоснование длиннее {MAX_APPLICABILITY_REASON} знаков: сократите его.")
        hub_id = _sca_row(db, project_id, finding_id)["hub_id"]
        snap = db.sca_snapshot(project_id, hub_id)
        if snap.row is None:
            raise StaleReview("Проект или находка исчезли.", "deleted")
        f = Finding.from_dict(snap.row["data"])
        view = sca_defect(snap, store_of(request), project_id, f, snap.review)
        item = next((x for x in view.get("applicability") or [] if x["key"] == vuln), None)
        if item is None:
            raise StaleReview("Уязвимости нет среди уязвимостей исследования пакета.", "package")
        db.save_sca_applicability(project_id, hub_id, item["key"], item["ids"], decision, reason,
                                  expect_revision=revision, expect_research_revision=research_revision,
                                  expect_fp=shown_fp)

    try:
        await run_in_threadpool(apply)
    except StaleReview as e:
        message = STALE_MESSAGES["deleted"] if e.reason == "deleted" else APPLICABILITY_STALE
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": message, "reason": e.reason, "reload": True}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, message, 409)
    except (ReviewRejected, ValueError) as e:
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e)}, status_code=400)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 400)
    if _wants_json(request):
        return {"ok": True}
    return redirect_with_back(request, f"/projects/{project_id}/sca/findings/{finding_id}"
                                       "?ok=sca_applicability_saved#sca-applicability")


@router.post("/projects/{project_id}/sca/findings/{finding_id}/package-text")
async def save_package_text(request: Request, project_id: int, finding_id: int):
    """Текст набора дефекта SCA (ADR-0091 п. 13): Объяснение, целевая версия вручную, выбор по AST без соответствия,
    отметки «Версию проверил сам» и «Текст проверен». Одна запись на набор; text_revision – редакция, которую видел
    человек (другая – 409, введённое не теряется). Отметки сохраняются подписью того, что проверено, и теряют силу,
    когда версия, её проверка или Объяснение меняются."""
    form = await request.form()
    revision = _form_int(form.get("text_revision")) or 0
    explanation = str(form.get("explanation") or "").replace("\r\n", "\n")
    manual = str(form.get("target_version") or "").strip()[:100]
    version_checked = str(form.get("version_checked") or "") == "1"
    text_checked = str(form.get("text_checked") or "") == "1"
    residual_checked = str(form.get("residual_checked") or "") == "1"
    # как написано (ADR-0149 п. 5): отступ первой строки остаётся, пустые строки по краям и хвостовые пробелы – нет
    recommendation_note = defect.edges(str(form.get("recommendation_note") or ""))
    shown_set = _form_int(form.get("set_no"))  # набор и пакет, текст которых видел человек
    shown_ref = None if form.get("input_ref") is None else str(form.get("input_ref"))
    shown_fp = None if form.get("shown_fp") is None else str(form.get("shown_fp"))  # снимок пакета при открытии формы
    # проверка версии и остаточные уязвимости, которые видел человек: отметка ставится только к ним (ревью 82103ee)
    shown_version = str(form.get("version_shown") or "")
    shown_residual = str(form.get("residual_shown") or "")
    # черновик формы при отказе (К11); unsaved_explanation показывается и там, где формы набора нет («без дефекта»)
    no_fix = str(form.get("no_fix") or "") == "1"  # «Исправленной версии нет – меры вместо обновления» (ADR-0101)
    text_draft = {"explanation": explanation, "manual_target": manual, "unsaved_explanation": explanation,
                  "recommendation_note": recommendation_note, "no_fix": no_fix}

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        if len(explanation) > MAX_EXPLANATION:
            raise ReviewRejected(f"Объяснение длиннее {MAX_EXPLANATION} знаков: сократите его.")
        hub_id = _sca_row(db, project_id, finding_id)["hub_id"]
        snap = db.sca_snapshot(project_id, hub_id)
        if snap.row is None:
            raise StaleReview("Проект или находка исчезли.", "deleted")
        f = Finding.from_dict(snap.row["data"])
        ast: dict = {}  # выбор «не указывать AST» больше не нужен: AST в текст не входит никогда (ADR-0101)
        if len(recommendation_note) > MAX_EXPLANATION:
            raise ReviewRejected(f"Добавление к рекомендациям длиннее {MAX_EXPLANATION} знаков: сократите его.")
        if no_fix and manual:
            raise ReviewRejected("Укажите целевую версию или отметьте «Исправленной версии нет» – одно из двух.")
        basis = "no_fix" if no_fix else ("manual" if manual else "")
        assert basis in sca_text.TARGET_BASES
        draft = {"explanation": explanation, "target_version": manual, "target_basis": basis,
                 "ast": ast, "recommendation_note": recommendation_note}
        view = sca_defect(snap, store_of(request), project_id, f, snap.review, override=draft)
        set_no = int(view.get("set_no") or 0)
        if shown_ref is not None and (shown_ref != snap.input_ref or (shown_set or 0) != set_no):
            raise StaleReview("Находку перенесли в другой набор дефекта.", "text")
        # пакет изменился после открытия формы (исследование, решение компонента, состав, номер) или отпечатка нет:
        # отметки относились к прежнему тексту – не применяются, текст сохраняется (К4). Проверка цели или остаточные
        # уязвимости, насчитанные для присланной цели, – не те, что видел человек: их отметки тоже не ставятся
        moved = shown_fp is None or shown_fp != snap.fingerprint
        confirm_version = version_checked and not moved and shown_version == view.get("version_sig")
        confirm_residual = residual_checked and not moved and shown_residual == view.get("residual_shown_sig")
        confirm_text = text_checked and not moved
        dropped = ((version_checked and not confirm_version) or (residual_checked and not confirm_residual)
                   or (text_checked and not confirm_text))
        saved = db.save_sca_package_text(
            project_id, snap.input_ref, set_no, expect_revision=revision, explanation=explanation, ast=ast,
            target_version=manual, target_basis=basis,
            version_checked_sig=view.get("version_confirm_sig", "") if confirm_version else "",
            text_checked_sig=view.get("text_confirm_sig", "") if confirm_text else "", text_sig="", member=hub_id,
            residual_checked_sig=view.get("residual_confirm_sig", "") if confirm_residual else "",
            recommendation_note=recommendation_note, expect_fp=snap.fingerprint)
        fresh = db.sca_snapshot(project_id, hub_id)
        result = sca_defect(fresh, store_of(request), project_id, f, fresh.review)
        if dropped:
            result["hint"] = ((PACKAGE_MOVED_CONFIRM if moved else CHECK_CHANGED_CONFIRM) + " "
                              + result.get("hint", "")).strip()
        return {"text_revision": int(saved.get("revision") or 0), "ready": result["ready"], "hint": result["hint"],
                "problems": result.get("problems") or [], "cautions": result.get("cautions") or [],
                "title": result["title"], "body": result["body"],
                "explanation": result.get("explanation") or "", "explanation_draft": result.get("explanation_draft") or "",
                "confirm_dropped": bool(dropped)}

    try:
        done = await run_in_threadpool(apply)
    except StaleReview as e:
        message = ("Текст дефекта изменили в другой вкладке: обновите карточку. Ваш текст не сохранён – скопируйте "
                   "его, если он нужен." if e.reason == "text" else
                   "Пока текст сохранялся, изменились данные пакета: текст не сохранён – обновите карточку и сохраните "
                   "его ещё раз." if e.reason == "package" else STALE_MESSAGES.get(e.reason, STALE_MESSAGES["source"]))
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": message, "reason": e.reason, "reload": True}, status_code=409)
        # без скрипта (К11): введённое Объяснение и версия возвращаются в форму, но не записываются; отметки –
        # заново, после сверки с текущим текстом
        html_message = ("Текст дефекта изменили в другой вкладке. Ваш текст не сохранён, он подставлен в форму: сверьте "
                        "его с текущим и сохраните ещё раз." if e.reason == "text" else message)
        return await run_in_threadpool(card_response, request, project_id, finding_id, html_message, 409, None, None,
                                       text_draft)
    except ReviewRejected as e:
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e)}, status_code=400)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 400, None, None,
                                       text_draft)
    if _wants_json(request):
        return {"ok": True, **done}
    if done["confirm_dropped"]:  # без скрипта: причина, почему отметки не поставлены, – на карточке
        return await run_in_threadpool(card_response, request, project_id, finding_id, PACKAGE_MOVED_CONFIRM, 409)
    # текст утверждён – следующий шаг «Создать дефект в Hub»; остались условия – к их перечню
    anchor = "#hub-defect-section" if done["ready"] else ("#sca-set-problems" if done["problems"] else "#sca-set")
    return redirect_with_back(request, f"/projects/{project_id}/sca/findings/{finding_id}?ok=sca_text_saved{anchor}")


@router.post("/projects/{project_id}/sca/findings/{finding_id}/set")
async def move_to_set(request: Request, project_id: int, finding_id: int):
    """Место находки в наборах дефекта (ADR-0091 пп. 5–6): set_no – номер набора (0 – по умолчанию, «new» – новый
    набор) или «none» – «без дефекта» с обоснованием reason. set_rev_<n> – редакции наборов, которые видел человек."""
    form = await request.form()
    target = str(form.get("set_no") or "0").strip()
    reason = str(form.get("reason") or "").strip()[:2000]
    # показанный пакет и ревизия идентичности находки (план dev17, п. 4.3): форма до обновления их не передаёт
    shown_ref = None if form.get("shown_ref") is None else str(form.get("shown_ref"))
    shown_pkg_rev = _form_int(form.get("shown_pkg_rev"))
    expect = {}
    for name, value in form.items():
        if str(name).startswith("set_rev_") and str(name)[8:].isdigit():
            parsed = _form_int(value)
            expect[int(str(name)[8:])] = parsed if parsed is not None else 0

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        hub_id = _sca_row(db, project_id, finding_id)["hub_id"]
        snap = db.sca_snapshot(project_id, hub_id)
        if snap.row is None:
            raise StaleReview("Проект или находка исчезли.", "deleted")
        if target == "none":
            number = None
        elif target == "new":
            number = NEW_SET
        elif target.isdigit():
            number = int(target)
        else:
            raise ReviewRejected("Неверный набор.")
        try:
            return db.move_sca_member(project_id, snap.input_ref, hub_id, number, reason, expect,
                                      expect_input_ref=shown_ref, expect_pkg_rev=shown_pkg_rev)
        except ValueError as e:
            raise ReviewRejected(str(e)) from e

    try:
        sets = await run_in_threadpool(apply)
    except StaleReview as e:
        detail = str(e) or STALE_MESSAGES.get(e.reason, STALE_MESSAGES["source"])
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": detail, "reason": e.reason, "reload": True}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, detail, 409)
    except ReviewRejected as e:
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": str(e)}, status_code=400)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 400)
    if _wants_json(request):
        return {"ok": True, "sets": {str(k): v["revision"] for k, v in sets.items()}}
    return redirect_with_back(request, f"/projects/{project_id}/sca/findings/{finding_id}?ok=sca_set_saved#defect-panel")


@router.post("/projects/{project_id}/sca/findings/{finding_id}/copied")
async def mark_copied(request: Request, project_id: int, finding_id: int):
    """Браузер подтвердил, что текст для Hub попал в буфер обмена (revision – редакция скопированного решения)."""
    form = await request.form()
    revision = _form_int(form.get("revision"))
    if not revision:
        raise HTTPException(status_code=400, detail="Не указана редакция решения.")

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        return db.mark_copied(project_id, _sca_row(db, project_id, finding_id)["hub_id"], revision)

    copied_at = await run_in_threadpool(apply)
    if copied_at is None:
        raise HTTPException(status_code=409, detail="Решение не сохранено или изменилось после копирования: "
                                                    "скопируйте текст ещё раз.")
    return {"ok": True, "copied_at": copied_at}


@router.post("/projects/{project_id}/sca/findings/{finding_id}/entered")
async def mark_entered(request: Request, project_id: int, finding_id: int):
    """Отметка «Внесено в Hub» (entered=1, клавиша h): человек сам вставил текст сохранённого решения в Hub; снять –
    entered=0. Редакция решения не меняется. review_revision (необязательно) – редакция, текст которой внесён: если
    решение с тех пор сохранили заново (другая вкладка), отметка не ставится."""
    form = await request.form()
    entered = str(form.get("entered") or "1") != "0"
    revision = _form_int(form.get("review_revision"))
    wants_json = _wants_json(request)
    defect_confirmed = str(form.get("defect_confirm") or "") == "1"  # снять отметку у находки в дефекте (ADR-0121)

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        row = _sca_row(db, project_id, finding_id)
        review = db.get_review(project_id, row["hub_id"])
        if entered and not (review and (review["decision"] or review["final_verdict"])):
            raise ValueError(ENTERED_NO_DECISION)
        if entered and revision is None:  # страница до обновления приложения: без редакции отметка не ставится
            return None
        f = Finding.from_dict(row["data"])
        if entered:  # отметка – о тексте с обоснованием человека, не агента к другому выводу (ADR-0088)
            origin = comment_origin(db, project_id, f, review.get("final_comment") or "")
            target = hub_verdict(review["decision"] or "", review["final_verdict"] or "")
            if origin and origin != target and not comment_confirm_valid(form, review):
                raise CommentNeedsCheck(entered_check_text(origin, target))
        outcome = hub_verdict(review["decision"] or "", review["final_verdict"] or "") if review else ""
        if entered and outcome == "true_positive":
            # текст дефекта проверяется по снимку пакета, и тот же снимок сверяется в транзакции отметки (К2):
            # текст набора, исследование, номер или состав, изменившиеся между проверкой и записью, отметку не ставят
            snap = db.sca_snapshot(project_id, row["hub_id"])
            view = sca_defect(snap, store_of(request), project_id, f, snap.review)
            if not view["ready"]:
                raise ValueError(ENTERED_NO_DEFECT)
            if str(form.get("defect_sig") or "") != view["text_sig"]:
                raise ValueError(ENTERED_DEFECT_CHANGED)

            def same_snapshot(c) -> None:
                if db._sca_defect_fingerprint(c, project_id, row["hub_id"]) != snap.fingerprint:
                    raise ValueError(ENTERED_DEFECT_CHANGED)

            return db.mark_entered(project_id, row["hub_id"], entered, revision=revision, entered_hash=view["text_sig"],
                                   check=same_snapshot)
        text = saved_hub_text(db, settings_of(request), project_id, f, review)
        if entered and not text.strip():  # «Отложить», «неясно», пустое обоснование: текста для Hub нет (К9)
            raise ValueError(ENTERED_NO_TEXT)
        # снять отметку у находки в дефекте, созданном в Hub, – только с подтверждением; Hub не трогается (ADR-0121 п. 4)
        check = None if entered or defect_confirmed else hub_defects.unenter_check(project_id, row["hub_id"])
        return db.mark_entered(project_id, row["hub_id"], entered, revision=revision, entered_hash=text_hash(text),
                               check=check)

    try:
        review = await run_in_threadpool(apply)
    except CommentNeedsCheck as e:
        if wants_json:
            return JSONResponse({"ok": False, "detail": str(e), "reason": "comment"}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409)
    except hub_defects.DefectBound as e:  # находка в дефекте, созданном в Hub (ADR-0121 п. 4)
        if wants_json:
            return JSONResponse({"ok": False, "detail": str(e), "reason": "defect"}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 409)
    except ValueError as e:
        if wants_json:
            return JSONResponse({"ok": False, "detail": str(e)}, status_code=400)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 400)
    if review is None:
        if wants_json:
            return JSONResponse({"ok": False, "detail": ENTERED_STALE, "reason": "revision"}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, ENTERED_STALE, 409)
    tp = hub_verdict(review.get("decision") or "", review.get("final_verdict") or "") == "true_positive"
    show_mark = ["mark-entered"]
    if wants_json and tp and not entered:
        # отметка снята: кнопка возвращается, только если дефект набора готов к выдаче (как в карточке)
        def defect_ready() -> bool:
            db = db_of(request)
            snap = db.sca_snapshot(project_id, _sca_row(db, project_id, finding_id)["hub_id"])
            return bool(snap.row is not None and sca_defect(snap, store_of(request), project_id,
                                                           Finding.from_dict(snap.row["data"]), snap.review).get("ready"))
        if not await run_in_threadpool(defect_ready):
            show_mark = []
    if wants_json:
        marks = review_json(review)
        # Редакция решения не меняется и в ответ не входит: иначе скрипт записал бы её в форму решения, и форма
        # из устаревшей вкладки перестала бы считаться устаревшей (как у SAST)
        marks.pop("revision")
        shown, hidden = ["entered-badge", "entered-note"], ["mark-entered", "entered-changed", "entered-unconfirmed", "entered-format-updated",
                                                            "entered-defect-format-updated"]
        done = "Дефект создан в Hub" if tp else "Статус и комментарий внесены в Hub"
        return {"ok": True, **marks, "text": {"entered-note-text": f"{done}."},
                "message": f"Отмечено: {done[0].lower()}{done[1:]}." if entered else f"Отметка «{done}» снята.",
                "times": {"entered-at": {"prefix": f"{done} " if entered else "",
                                           "datetime": marks['entered_at'] if entered else "", "suffix": "."}},
                "show": shown if entered else show_mark,
                # снятие отметки: пометки о прежнем формате тоже больше не к месту (ревью Codex круга 4)
                "hide": hidden if entered else shown + ([] if show_mark else ["mark-entered"])
                + ["entered-defect-format-updated", "entered-format-updated"]}
    ok = ("sca_defect_entered" if tp else "sca_entered") + ("" if entered else "_off")
    return redirect_with_back(request, f"/projects/{project_id}/sca/findings/{finding_id}?ok={ok}")


@router.post("/projects/{project_id}/sca/findings/{finding_id}/reviewed")
async def mark_reviewed(request: Request, project_id: int, finding_id: int):
    """Отметка «Проверено» отдельно от решения (reviewed=1 или 0, клавиша v): решение и комментарий не меняются,
    редакция решения растёт – ответ сообщает новую. finding_version и review_revision – что видел человек: если
    находку или решение с тех пор изменили, отметка не меняется (409)."""
    form = await request.form()
    reviewed = str(form.get("reviewed") or "") == "1"
    shown_version = str(form.get("finding_version") or "")
    shown_revision = _form_int(form.get("review_revision"))
    wants_json = _wants_json(request)

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        row = _sca_row(db, project_id, finding_id)
        expect = {"version": shown_version, "verdict_id": None, "revision": shown_revision} if shown_version else None
        review = db.set_reviewed(project_id, row["hub_id"], reviewed, expect=expect)
        stats = db.review_stats(project_id)
        return review, {"total": int(stats.get("sca") or 0), "reviewed": int(stats.get("sca_reviewed") or 0)}

    try:
        review, progress = await run_in_threadpool(apply)
    except StaleReview as e:
        message = STALE_MESSAGES.get(e.reason, STALE_MESSAGES["source"])
        if wants_json:
            return JSONResponse({"ok": False, "detail": message, "reason": e.reason}, status_code=409)
        return await run_in_threadpool(card_response, request, project_id, finding_id, message, 409)
    except ValueError as e:  # отложенную находку проверенной не отметить
        if wants_json:
            return JSONResponse({"ok": False, "detail": str(e), "reason": "later"}, status_code=400)
        return await run_in_threadpool(card_response, request, project_id, finding_id, str(e), 400)
    if wants_json:
        marks = review_json(review)
        left = max(0, progress["total"] - progress["reviewed"])
        return {"ok": True, **marks, "progress": progress, "checked": {"reviewed-box": marks["reviewed"]},
                "show" if marks["reviewed"] else "hide": ["reviewed-badge"],
                "text": {"progress-label": f"Проверено {progress['reviewed']} из {progress['total']} · "
                                           f"осталось {left}"}}
    return redirect_with_back(request, f"/projects/{project_id}/sca/findings/{finding_id}?ok=sca_reviewed")


# ------------------------------------------------------------------ решение компонента → находки версии (ADR-0153)

COMPONENT_APPLY_ACTIONS = ("update",)  # действия решения компонента, которые записываются находкам
COMPONENT_APPLY_KAPO = "actual"  # уточнение нового решения «обновить» – «актуальна» (ADR-0145, как в карточке находки)


class ComponentApplyRefused(Exception):
    """Решение компонента находкам не записано; args[0] – код причины для страницы компонента."""


def _apply_state(db: Database, project_id: int, input_ref: str, usages: list[dict] | None = None,
                 research: tuple[str, int] | None = None) -> tuple[list[dict], str]:
    """Что запись решения компонента читает о находках версии: получатели и отпечаток этого состояния.
    Получатели – все находки версии из текущей выгрузки, как их показывает карточка компонента (db.sca_usages), с
    редакцией решения, версией находки и ответом агента. Отпечаток – состав, эти три значения у каждой находки и
    ревизия исследования компонента: его карточка кладёт в форму, а запись пересчитывает под блокировкой записи;
    изменилось что-либо из показанного оператору – не записывается ничего. Карточка передаёт usages и research –
    тот состав и то исследование, которые сама показывает; запись читает их из базы."""
    recipients = []
    for usage in (db.sca_usages(project_id, input_ref) if usages is None else usages):
        hub_id = str(usage["hub_id"])
        row = db.get_finding_by_hub_id(project_id, hub_id)
        if row is None:
            continue
        review = db.get_review(project_id, hub_id)
        latest = _latest_answer(db, project_id, Finding.from_dict(row["data"]))
        recipients.append({"id": usage["id"], "hub_id": hub_id, "review": review,
                           "revision": int(review["revision"]) if review else 0,
                           "version": db.review_version(project_id, hub_id),
                           "answer_id": str(latest["id"]) if latest else "", "answer_sig": answer_signature(latest)})
    if research is None:
        research_row = db.research_row(project_id, input_ref) or {}
        research = (str(research_row.get("answer_sig") or ""), int(research_row.get("revision") or 0))
    shown = {"findings": sorted([r["hub_id"], r["revision"], r["version"], r["answer_id"], r["answer_sig"]]
                                for r in recipients),
             "research": [str(research[0] or ""), int(research[1] or 0)]}
    return recipients, _sig("component-apply", json.dumps(shown, ensure_ascii=False, sort_keys=True))


def component_apply_view(db: Database, project_id: int, input_ref: str, decision: dict | None,
                         usages: list[dict], research: tuple[str, int]) -> dict:
    """Карточка компонента: можно ли записать решение компонента находкам версии, что при этом изменится и что
    карточка показала (token, decision_revision – поля формы). decision, usages и research – те самые решение,
    находки версии и исследование, которые карточка показывает оператору: форма строится из них, отдельного
    чтения нет (ревью dev27: показанное и переданное в форму не расходятся)."""
    action = str((decision or {}).get("action") or "")
    current = bool(decision) and str(decision.get("state") or "current") == "current"
    recipients, token = _apply_state(db, project_id, input_ref, usages, research)
    decided = sum(1 for r in recipients if r["review"] and r["review"].get("decision") not in ("", "later", None))
    if not recipients:
        why = "В текущей выгрузке находок этой версии нет: записывать решение некому."
    elif not current:
        why = "Сначала сохраните решение по компоненту – оно запишется находкам этой версии."
    elif action not in COMPONENT_APPLY_ACTIONS:
        why = ("Находкам записывается только решение «обновить». Для другого решения откройте находку и сохраните "
               "решение в её карточке.")
    else:
        why = ""
    return {"can": not why, "why": why, "count": len(recipients), "decided": decided,
            "first_id": recipients[0]["id"] if recipients else None, "token": token if recipients else "",
            "decision_revision": int(decision["revision"]) if current else 0,
            # «Сохранить и применить» в форме решения: находки есть; действие проверит запись
            "offer": bool(recipients)}


def apply_component_decision(db: Database, project_id: int, input_ref: str, *, decision_revision: int,
                             token: str) -> int:
    """Решение компонента «обновить» – находкам его версии (решение принимается в карточке
    компонента и само подставляется в находки и дефект): вывод «обновить», обоснование компонента как комментарий и
    отметка «Проверено» – всем находкам, которые показывает карточка, одной транзакцией (db.save_reviews).

    Записывается редакция решения decision_revision – та, что видел или только что сохранил оператор; token –
    отпечаток показанного состояния находок (_apply_state). Не совпало с базой – ComponentApplyRefused
    ("apply_changed"), не записано ничего. Внутри транзакции, когда другие записи приложения ждут, редакция решения
    и отпечаток пересчитываются заново: состав версии, решения находок, ответы агента и исследование должны быть
    теми же, что на странице. Каждая находка должна присутствовать в выгрузке. Уточнение по ГОСТ Р КАПО – своё у
    каждой находки: прежнее, если оно допустимо для «обновить», иначе «актуальна». Текст дефекта запись не меняет:
    целевая версия берётся из решения компонента, если в наборе не задана своя и не выбран режим «Исправленной
    версии нет» (sca_text.resolve_target). Возвращает число находок."""
    def current_decision() -> dict:
        decision = db.decision(project_id, input_ref)
        if not decision or str(decision.get("state") or "current") != "current":
            raise ComponentApplyRefused("apply_no_decision")
        if int(decision["revision"]) != int(decision_revision):
            raise ComponentApplyRefused("apply_changed")
        if str(decision.get("action") or "") not in COMPONENT_APPLY_ACTIONS:
            raise ComponentApplyRefused("apply_action")
        return decision

    decision = current_decision()
    recipients, now = _apply_state(db, project_id, input_ref)
    if not recipients:
        raise ComponentApplyRefused("apply_no_findings")
    if not token or now != token:
        raise ComponentApplyRefused("apply_changed")
    comment = str(decision.get("rationale") or "").strip()[:MAX_COMMENT]
    allowed = KAPO_STATES_BY_OUTCOME.get("true_positive", ())
    items = []
    for r in recipients:
        old_kapo = str((r["review"] or {}).get("kapo_state") or "")
        items.append({"hub_id": r["hub_id"], "decision": "disagree", "final_verdict": "true_positive",
                      "final_comment": comment, "reviewed": True, "verdict_id": None,
                      "expect": {"version": r["version"], "verdict_id": None, "revision": r["revision"],
                                 "answer_id": r["answer_id"]},
                      "answer_sig": r["answer_sig"], "require_present": True,
                      "kapo_state": old_kapo if old_kapo in allowed else COMPONENT_APPLY_KAPO, "recheck": True})

    def check(c) -> None:  # под блокировкой записи: то же решение и то же состояние находок, что на странице
        try:
            again = current_decision()
        except ComponentApplyRefused as e:
            raise StaleReview("решение компонента изменилось", "package") from e
        if str(again.get("rationale") or "") != str(decision.get("rationale") or ""):
            raise StaleReview("решение компонента изменилось", "package")
        if _apply_state(db, project_id, input_ref)[1] != token:
            raise StaleReview("находки версии изменились", "package")

    try:
        db.save_reviews(project_id, items, check=check)
    except StaleReview as e:
        raise ComponentApplyRefused("apply_changed") from e
    except (ReviewRejected, HTTPException) as e:  # отказ проверки решения; прочее – ошибка программы, идёт выше
        # без текста отказа: в нём могут быть номера находок и их данные (REVIEW.md)
        log.info("решение компонента проекта %d находкам не записано: отказ проверки %s", project_id,
                 type(e).__name__)
        raise ComponentApplyRefused("apply_rejected") from e
    return len(items)


@router.post("/projects/{project_id}/components/{input_ref}/apply-findings")
async def apply_component_decision_route(request: Request, project_id: int, input_ref: str):
    """Кнопка карточки компонента «Применить решение к находкам этой версии». Форма несёт только то, что карточка
    показала: редакцию решения компонента и отпечаток находок; записывается решение из базы."""
    from urllib.parse import quote
    form = await request.form(max_fields=6, max_files=0)
    shown_revision = _form_int(form.get("decision_revision")) or 0
    token = str(form.get("token") or "")

    def work() -> int:
        project_or_404(request, project_id)
        return apply_component_decision(db_of(request), project_id, input_ref, decision_revision=shown_revision,
                                        token=token)

    card = f"/projects/{project_id}/components/{quote(input_ref)}"
    # «К списку» после применения ведёт в тот же отфильтрованный список – как у «Сохранить и применить»
    back = (worklists.return_url(request, f"/projects/{project_id}/components")
            if "back" in request.query_params else "")
    try:
        count = await run_in_threadpool(work)
    except ComponentApplyRefused as e:
        return redirect(f"{card}?" + query({"err": e.args[0], "back": back}) + "#component-apply")
    return redirect(f"{card}?" + query({"ok": "applied", "n": str(count), "back": back}) + "#component-apply")

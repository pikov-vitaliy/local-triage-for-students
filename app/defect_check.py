"""Проверка формы текста дефекта перед Hub по требованиям команды (ADR-0123).

Программа проверяет форму текста команды – тело дефекта, которое приложение ставит в начало описания дефекта в Hub
(без блока Hub): каркас, запрещённые служебные блоки, внутренние номера, служебные адреса. Смысл обоснования, точность
объяснений и выбор версии проверяет оператор (ADR-0123 п. 1); данные набора SCA (целевая версия, объяснения,
подтверждения) уже проверяет sca_defect – здесь они не повторяются.

Функции чистые: номера находок Hub проекта и ожидания по набору SCA передаёт вызывающий. Нарушение – строка по-русски
с номером требования команды (S – SAST, A – SCA) в начале. Проверяется нормализованная копия (п. 2), сам текст не
меняется.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from app import defect, defect_where, i18n, sca_text

# Требования команды, которые проверяет программа (ADR-0123 пп. 3–4; S3, S11 и смысл объяснений – у оператора)
REQUIREMENTS = i18n.Labels({
    "S1": "дефект SAST – только каркас команды: стандартная фраза, «Обоснование:», «Рекомендация:» с пунктами «1)», «2)»",
    "S2": "первая строка – стандартная фраза с названием команды из «Настроек»",
    "S4": "рекомендация – меры по пунктам «1)», «2)»",
    "S5": "без внутренних номеров находок Hub",
    "S6": "без требований ГОСТ к конвейеру: тест, условие закрытия, срок",
    "S8": "без перечня номеров находок: находки группируются в Hub",
    "A1": "дефект SCA – разделы «Описание», «Объяснение», «Рекомендации», «Источники» по порядку, ничего сверх",
    "A3": "«Описание» – публичные идентификаторы уязвимостей набора со ссылкой; без внутренних номеров AST",
    "A4": "«Объяснение» не пусто",
    "A7": "одна рекомендация «Обновление <компонент> до версии <версия>»",
    "A8": "«Источники» – только адреса страниц для человека",
})

# п. 3.5 (S6): требования к конвейеру – в любом месте обоснования и пунктов, без учёта регистра
PIPELINE_PHRASES = ("добавить тест", "написать тест", "тест, подтверждающий исправление", "дефект закрывается",
                    "проверить срабатывания того же правила", "срок устранения", "рабочих дней после разметки",
                    "гост р 71207", "гост р 56939",
                    # те же признаки по-английски: рекомендация могла быть написана на английском интерфейсе (ADR-0158)
                    "add a test", "write a test", "test that confirms the fix", "test confirming the fix",
                    "defect is closed", "check findings of the same rule", "remediation deadline", "fix deadline",
                    "business days after triage", "gost r 71207", "gost r 56939")
_ASCII = re.compile(r"[a-z]")


def _has_phrase(low: str, phrase: str) -> bool:
    """Признак S6 в строке: русский – подстрокой, как раньше; английский – целым словом (test-and-set – не тест)."""
    if not _ASCII.match(phrase):
        return phrase in low
    text = re.sub(r"[\u2010\u2011\u2012\u2013]", "-", low)  # неразрывный и другие дефисы – как обычный
    # целое слово: «test-and-set» – не тест; «56939-2024» – тот же стандарт с годом
    return re.search(r"(?<![\w-])" + re.escape(phrase) + r"(?!\w)(?!-[^\W\d_])", text) is not None


# п. 3.6: служебные строки прежнего формата SAST (начало строки после снятия маркера списка); «Срок –» – заголовок
# срока (S6), «Срок жизни буфера…» – не нарушение
SAST_LEGACY_STARTS = (("Итог:", "S1"), ("Область:", "S1"), ("Что это значит:", "S1"),
                      ("Требуется от разработчика", "S1"), ("Справочно (", "S1"),
                      ("Если вы считаете срабатывание ложным", "S1"), ("Срок –", "S6"), ("Срок -", "S6"))
# п. 4.6: служебные строки прежнего формата SCA (начало строки)
SCA_LEGACY_STARTS = ("Заключение AppSec", "Критичность:", "Область:", "Что не установлено", "Требуется от разработчика",
                     "Обоснование неактуальности", "Нормативная опора", "Справочно (", "В колонке «Серьёзность»",
                     "Сводка по уязвимостям", "Детальная информация по уязвимостям")

# заголовки шаблона команды – из общей таблицы генератора и разбора (defect_where.HEADS, ADR-0158): проверка узнаёт
# русское и английское написание при любом языке интерфейса; в текстах нарушений – на языке интерфейса
REASON_HEAD = defect_where.HEADS["reason"][0]
RECOMMENDATION_HEAD = defect_where.HEADS["recommendation"][0]
SECTIONS = ("Описание", "Объяснение", "Рекомендации", "Источники")  # канонические имена разделов SCA (ключи parts)
SECTION_KEYS = {"Описание": "description", "Объяснение": "explanation", "Рекомендации": "recommendations",
                "Источники": "sources"}
REFUSAL = i18n.N_("Текст не по требованиям команды: ")
MAX_LISTED = 3  # нарушений в тексте отказа; остальные – числом (длинный перечень занимал полэкрана)

_SPACES = re.compile(r"\s+")
_MARKER = re.compile(r"^(?:\d{1,3}\)\s*|\d{1,3}\.\s+|-\s+)")  # маркер списка «N)», «N.», «-»
_ITEM = re.compile(r"^(\d{1,3})\)\s*(.*)$")
# п. 3.7: явные ссылки на находку Hub – реквизит «ID: <число>», «ID <число>», «№ <число>»; перечень из трёх и более
# чисел через запятую. Число – целым идентификатором: за ним не буква, цифра, «_» или дефис («ID: 12345abc» – не
# ссылка); перечень не продолжает слово, число с точкой или запятой и идентификатор с дефисом («item12345, …»,
# «CWE-79, 80, 81» – не перечень номеров); дробное число – не номер: «ID: 12345.6», «…, 12347.5» (точка конца
# предложения после номера допустима)
_REF = re.compile(r"(?<![\w-])(?:ID\s*:\s*|ID\s+|№\s*)(\d+)(?![\w-]|[.,]\d)", re.I)
# перечень берётся максимальным справа: «12344, 12345, 12346, 12347.5» – не три номера и дробь, а перечень с дробью
# (не номера); цена в _REF: «ID: 12345,12346» без пробела читается как десятичная запятая и ссылкой не считается
_LIST = re.compile(r"(?<![\w.,-])\d+(?:\s*,\s*\d+){2,}(?![\w-]|[.,]\d|\s*,\s*\d)")
_URL = re.compile(r"^https?://\S+$", re.I)


# ---------------------------------------------------------------------------- нормализация и общее


def norm_line(line: str) -> str:
    """Строка после нормализации (п. 2): пробелы по краям сняты, подряд идущие – один."""
    return _SPACES.sub(" ", str(line or "")).strip()


def normalize(text: str) -> list[str]:
    """Строки нормализованной копии текста (п. 2): переводы строк \\r\\n – \\n, пробелы по краям строк сняты, подряд
    идущие – один; пустые строки остаются пустыми (разделители)."""
    return [norm_line(line) for line in str(text or "").replace("\r\n", "\n").split("\n")]


def _num(value: str) -> str:
    text = str(value or "").strip()
    return str(int(text)) if text.isdigit() else text


def number_candidates(text: str) -> set[str]:
    """Числа, которые п. 3.7 сверяет с номерами находок Hub проекта: из реквизитов «ID: N», «ID N», «№ N» и из
    перечней через запятую. Вызывающий по ним читает номера находок проекта (Database.hub_ids_among)."""
    out: set[str] = set()
    for line in normalize(text):
        out |= {m.group(1) for m in _REF.finditer(line)}
        for m in _LIST.finditer(line):
            out |= set(re.findall(r"\d+", m.group(0)))
    return out | {_num(x) for x in out}


def _quote(line: str, limit: int = 90) -> str:
    text = str(line or "")
    return i18n._("«{text}»", text=text if len(text) <= limit else text[: limit - 1] + "…")


def _head(key: str) -> str:
    """Заголовок шаблона в тексте нарушения – на языке интерфейса."""
    return defect_where.head(key)


def _problem(code: str, detail: str) -> str:
    return f"{code}: {detail}"


def _unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _hub_refs(lines: Iterable[str], finding_ids: Iterable[str], ref_code: str, list_code: str) -> list[str]:
    """п. 3.7 (и 4.6 для SCA): реквизит «ID: N» / «ID N» / «№ N» с номером находки Hub проекта; перечень из трёх и
    более чисел через запятую, каждое – номер находки проекта. Отдельное число в тексте – не нарушение."""
    ids = {_num(x) for x in finding_ids}
    if not ids:
        return []
    out = []
    for line in lines:
        for m in _REF.finditer(line):
            if _num(m.group(1)) in ids:
                out.append(_problem(ref_code, i18n._("внутренний номер находки Hub {ref} – {line}",
                                                     ref=_quote(m.group(0).strip()), line=_quote(line))))
        for m in _LIST.finditer(line):
            numbers = re.findall(r"\d+", m.group(0))
            if all(_num(n) in ids for n in numbers):
                out.append(_problem(list_code, i18n._("перечень номеров находок Hub {numbers} – {line}",
                                                      numbers=_quote(m.group(0)), line=_quote(line))))
    return out


def refusal(problems: list[str], at_create: bool = False) -> str:
    """Текст отказа «Подготовить дефект» и «Создать» (ADR-0123 п. 5). at_create – отказ «Создать»: у находки открыт
    предпросмотр, новую заготовку не запросить, пока его не отменили, а текст мог разойтись с названием команды."""
    shown = "; ".join(problems[:MAX_LISTED])
    more = i18n._("; и ещё {n}", n=len(problems) - MAX_LISTED) if len(problems) > MAX_LISTED else ""
    if at_create:
        return (i18n._(REFUSAL) + shown + more + i18n._(". Нажмите «Отменить предпросмотр», поправьте решение (или "
                                                        "название команды) и запросите заготовку заново."))
    return (i18n._(REFUSAL) + shown + more + i18n._(". Поправьте решение в карточке (обоснование, рекомендацию или "
                                                    "текст набора), сохраните его и запросите заготовку заново."))


# ---------------------------------------------------------------------------- SAST (п. 3)


def _phrases(team_phrase: str | Iterable[str]) -> tuple[str, list[str]]:
    """(фраза для текста нарушения, все допустимые написания): team_phrase – фраза на языке интерфейса или набор фраз
    (defect.sast_phrases); к каждой добавляется она же на другом языке (defect.phrase_variants) – текст, собранный до
    переключения языка интерфейса, проходит S2 (ADR-0158)."""
    given = [team_phrase] if isinstance(team_phrase, str) else [str(p) for p in team_phrase]
    allowed = [norm_line(v) for p in given for v in defect.phrase_variants(p)]
    return norm_line(given[0] if given else ""), list(dict.fromkeys(allowed))


def sast_problems(text: str, *, team_phrase: str | Iterable[str], finding_ids: Iterable[str] = ()) -> list[str]:
    """Нарушения требований команды в тексте дефекта SAST (ADR-0123 п. 3): первая непустая строка – team_phrase
    (стандартная фраза из настройки названия команды, defect.sast_phrase, на любом из двух языков), затем ровно одна
    «Обоснование:» с непустым текстом (на той же строке или следующими строками), ровно одна «Рекомендация:» и под ней
    пункты «1)», «2)», … по порядку – и ничего больше. Заголовки узнаются по-русски и по-английски (defect_where.HEADS)
    при любом языке интерфейса. В обосновании и пунктах – без требований к конвейеру, служебных строк прежнего формата и
    ссылок на находки Hub проекта (finding_ids – номера находок проекта, хотя бы те, что упомянуты в тексте). [] – текст
    по требованиям."""
    # раздел «Где исправлять» – сведения для разработчиков, не часть шаблона команды (план dev7, раздел 11)
    lines = [line for line in normalize(defect_where.split(text)[0]) if line]
    if not lines:
        return [_problem("S1", i18n._("текст дефекта пуст"))]
    out: list[str] = []
    phrase, allowed = _phrases(team_phrase)
    reason_head, rec_head = _head("reason"), _head("recommendation")
    body = lines[1:]
    if lines[0] not in allowed:  # п. 3.1
        out.append(_problem("S2", i18n._("первая строка – не стандартная фраза команды {phrase}: {line}",
                                         phrase=_quote(phrase, 160), line=_quote(lines[0]))))
        if defect_where.head_prefix(lines[0], "reason"):  # фразы нет вовсе: первая строка – уже «Обоснование:»
            body = lines
    # язык каркаса – язык самого текста: есть русские заголовки – только они (как до dev38), иначе английские
    lang = "ru" if any(defect_where.head_prefix_in(line, "reason", "ru") or defect_where.is_head_in(line, "recommendation", "ru")
                       for line in body) else "en"
    reason_at = [i for i, line in enumerate(body) if defect_where.head_prefix_in(line, "reason", lang)]
    rec_at = [i for i, line in enumerate(body) if defect_where.is_head_in(line, "recommendation", lang)]
    for head, found in ((reason_head, reason_at), (rec_head, rec_at)):  # пп. 3.2, 3.3
        if not found:
            out.append(_problem("S1", i18n._("строка {head} должна быть ровно одна, а её нет", head=_quote(head))))
        elif len(found) != 1:
            out.append(_problem("S1", i18n._("строка {head} должна быть ровно одна, а их {n}", head=_quote(head),
                                             n=len(found))))
    if len(reason_at) == 1 and len(rec_at) == 1:
        r, k = reason_at[0], rec_at[0]
        out += [_problem("S1", i18n._("строка сверх шаблона команды до «Обоснование:» – {line}", line=_quote(line)))
                for line in body[:r]]
        if k < r:
            out.append(_problem("S1", i18n._("«Рекомендация:» стоит раньше «Обоснование:»")))
        else:
            reason = [body[r][len(defect_where.head_prefix_in(body[r], "reason", lang)):].strip(), *body[r + 1:k]]
            if not any(reason):
                out.append(_problem("S1", i18n._("обоснование пустое")))
            items = body[k + 1:]
            if not items:
                out.append(_problem("S4", i18n._("под «Рекомендация:» нет ни одного пункта «1) …»")))
            number = 1
            for line in items:
                m = _ITEM.match(line)
                if m is None or not m.group(2).strip():
                    out.append(_problem("S1", i18n._("после «Рекомендация:» – строка не пункт «N) …»: {line}",
                                                     line=_quote(line))))
                    continue
                if int(m.group(1)) != number:
                    out.append(_problem("S1", i18n._("пункты рекомендации не по порядку: {line} вместо «{number})»",
                                                     line=_quote(line), number=number)))
                number += 1
    for line in body:
        low = line.casefold()
        out += [_problem("S6", i18n._("требование ГОСТ к конвейеру («{phrase}») – {line}", phrase=p,
                                      line=_quote(line))) for p in PIPELINE_PHRASES if _has_phrase(low, p)]  # п. 3.5
        bare = _MARKER.sub("", line, count=1).casefold()
        out += [_problem(code, i18n._("служебная строка прежнего формата – {line}", line=_quote(line)))
                for start, code in SAST_LEGACY_STARTS if bare.startswith(start.casefold())]  # п. 3.6
    out += _hub_refs(body, finding_ids, "S5", "S8")  # п. 3.7
    return _unique(out)


# ---------------------------------------------------------------------------- SCA (п. 4)


def _is_also_affected(line: str) -> bool:
    """Разделитель «Также затрагивают эту версию:» на любом из двух языков (ADR-0158)."""
    return defect_where.is_head(line, "also_affected") or line == sca_text.ALSO_AFFECTED


def _description(lines: list[str], hub: list[str], research: list[str]) -> list[str]:
    """п. 4.2 (A3): каждая ожидаемая строка «<идентификатор> (<ссылка>)» – ровно один раз, посторонних нет; разделитель
    «Также затрагивают эту версию:» – между уязвимостями находок Hub и применимыми по исследованию, только если есть
    и те и другие (так его ставит генератор, sca_text.body)."""
    hub, research = [norm_line(x) for x in hub], [norm_line(x) for x in research]
    expected = _unique([*hub, *research])
    sep = _head("also_affected")
    out: list[str] = []
    seps = [i for i, line in enumerate(lines) if _is_also_affected(line)]
    if hub and research and len(seps) != 1:
        out.append(_problem("A3", i18n._("строка {sep} нужна ровно одна – между уязвимостями находок Hub и применимыми "
                                         "по исследованию", sep=_quote(sep))))
    elif not (hub and research) and seps:
        out.append(_problem("A3", i18n._("строка {sep} – только между уязвимостями находок Hub и применимыми по "
                                         "исследованию", sep=_quote(sep))
                            + ("" if hub else i18n._(": уязвимостей находок Hub в наборе нет"))))
    for line in expected:
        count = lines.count(line)
        if count == 0:
            out.append(_problem("A3", i18n._("в «Описании» нет строки {line}", line=_quote(line))))
        elif count > 1:
            out.append(_problem("A3", i18n._("строка {line} в «Описании» повторяется", line=_quote(line))))
    out += [_problem("A3", i18n._("посторонняя строка в «Описании» – {line}", line=_quote(line))) for line in lines
            if not _is_also_affected(line) and line not in expected]
    if hub and research and len(seps) == 1:
        at = seps[0]
        for i, line in enumerate(lines):
            if line in hub and line not in research and i > at:
                out.append(_problem("A3", i18n._("уязвимость находок Hub {line} стоит после {sep}", line=_quote(line),
                                                 sep=_quote(sep))))
            elif line in research and line not in hub and i < at:
                out.append(_problem("A3", i18n._("уязвимость по исследованию {line} стоит до {sep}", line=_quote(line),
                                                 sep=_quote(sep))))
    return out


def _update_templates() -> list[str]:
    """Шаблоны строки обновления на обоих языках (defect_where.UPDATE_LINE и перевод каталога): первым – на языке
    интерфейса (для текста нарушения)."""
    ru, en = defect_where.UPDATE_LINE
    shown = ru if i18n.current() == "ru" else (i18n.translate(ru, "en") if i18n.translate(ru, "en") != ru else en)
    return list(dict.fromkeys((shown, *defect_where.variants(defect_where.UPDATE_LINE))))


def _update_line(template: str, component: str, target: str) -> str:
    return norm_line(template.replace("{component}", component).replace("{target}", target))


def _recommendations(lines: list[str], component: str, target: str, no_fix: bool) -> list[str]:
    """п. 4.4 (A7): обновление – ровно одна строка «Обновление <компонент> до версии <версия>» последней, перед ней –
    пояснение версии Hub, остаточный риск и добавление оператора; «Исправленной версии нет» (ADR-0101) – строки
    обновления нет, есть меры. Строка обновления – только полная форма «Обновление <компонент набора> до версии
    <версия>» (одно слово версии): строки про другие компоненты и строки оператора, которые продолжают фразу («… до
    версии 2.0 потребует миграции API»), – добавление оператора и меры. Цена: «… до версии 3.0 или новее» в режиме без
    исправления строкой обновления не считается. Строка узнаётся по-русски и по-английски («Update <компонент> to
    version <версия>», ADR-0158); ожидаемая строка – на языке, которым написана найденная строка обновления."""
    templates = _update_templates()
    fulls = []
    for template in templates:
        head = norm_line(template.split("{target}")[0].replace("{component}", component))
        fulls.append((template, re.compile(re.escape(head) + r" \S+")))
    updates = [line for line in lines if any(full.fullmatch(line) for _t, full in fulls)]
    if no_fix:
        out = [_problem("A7", i18n._("в режиме «Исправленной версии нет» строки обновления нет – {line}",
                                     line=_quote(line))) for line in updates]
        if not lines:
            out.append(_problem("A7", i18n._("в режиме «Исправленной версии нет» в «Рекомендациях» нет мер")))
        return out
    expected = _update_line(templates[0], component, target)
    if not updates:
        return [_problem("A7", i18n._("в «Рекомендациях» нет строки {line}", line=_quote(expected, 160)))]
    if len(updates) > 1:
        return [_problem("A7", i18n._("строк обновления {n} – нужна одна {line}", n=len(updates),
                                      line=_quote(expected, 160)))]
    written = next(t for t, full in fulls if full.fullmatch(updates[0]))  # язык найденной строки
    expected = _update_line(written, component, target)
    if updates[0] != expected:
        return [_problem("A7", i18n._("строка обновления {line} не совпадает с набором: нужна {expected}",
                                      line=_quote(updates[0]), expected=_quote(expected, 160)))]
    if lines[-1] != updates[0]:
        return [_problem("A7", i18n._("после строки обновления – другие строки: строка обновления последняя в "
                                      "«Рекомендациях»"))]
    return []


def _sources(lines: list[str]) -> list[str]:
    """п. 4.5 (A8): только адреса страниц для человека (sca_text.human_url) без внутреннего номера (has_internal_id)."""
    out = []
    for line in lines:
        if not _URL.match(line):
            out.append(_problem("A8", i18n._("в «Источниках» – не адрес: {line}", line=_quote(line))))
        elif not sca_text.human_url(line):
            out.append(_problem("A8", i18n._("служебный адрес (запрос к API или файл метаданных реестра) – {line}",
                                             line=_quote(line))))
        elif sca_text.has_internal_id(line):
            out.append(_problem("A8", i18n._("адрес с внутренним номером уязвимости (AST) – {line}", line=_quote(line))))
    return out


# нарушение «внутренний номер уязвимости (AST)» вне «Источников» (п. 4.6): по нему справочная проверка занесённого
# дефекта отбирает нарушения (hub_defect_routes); узнаётся на обоих языках
INTERNAL_ID_PROBLEM = i18n.N_("внутренний номер уязвимости (AST) – {line}")


def is_internal_id_problem(problem: str) -> bool:
    """Нарушение – внутренний номер уязвимости (AST) в тексте, на любом из двух языков (ADR-0158)."""
    detail = str(problem or "").split(": ", 1)[-1]  # без кода требования «A3: »
    marks = {t.split("{line}")[0].rstrip(" -–") for t in
             (INTERNAL_ID_PROBLEM, i18n.translate(INTERNAL_ID_PROBLEM, "en"), "internal vulnerability ID (AST) - {line}")}
    return any(m and detail.startswith(m) for m in marks)


def sca_problems(text: str, *, expected_hub: Iterable[str], expected_research: Iterable[str], component: str,
                 target: str, no_fix: bool, finding_ids: Iterable[str] = ()) -> list[str]:
    """Нарушения требований команды в тексте дефекта SCA (ADR-0123 п. 4): разделы «Описание», «Объяснение»,
    «Рекомендации», «Источники» – каждый один раз, по порядку, до «Описания» ничего; «Описание» сверяется со строками
    набора (expected_hub – уязвимости находок Hub, expected_research – применимые по исследованию; то же представление,
    что у генератора, sca_text.description_lines, из того же снимка набора); «Объяснение» не пусто; «Рекомендации» –
    строка обновления компонента до целевой версии (component, target) или, при no_fix, меры без неё; «Источники» –
    только адреса для человека. Во всём тексте – без номеров AST, ссылок на находки Hub проекта (finding_ids) и
    служебных строк прежнего формата. Данные набора (целевая версия, объяснения, подтверждения) проверяет sca_defect.
    Заголовки разделов узнаются по-русски и по-английски (defect_where.HEADS) при любом языке интерфейса.
    [] – текст по требованиям."""
    lines = [line for line in normalize(defect_where.split(text)[0]) if line]  # раздел «Где исправлять» – не часть шаблона
    out: list[str] = []
    # язык каркаса – язык самого текста (по русским заголовкам разделов), как у SAST
    lang = "ru" if any(defect_where.is_head_in(line, SECTION_KEYS[name], "ru") for line in lines for name in SECTIONS) \
        else "en"
    at = {name: [i for i, line in enumerate(lines) if defect_where.is_head_in(line, SECTION_KEYS[name], lang)]
          for name in SECTIONS}
    for name in SECTIONS:  # п. 4.1
        shown = _head(SECTION_KEYS[name])
        if not at[name]:
            out.append(_problem("A1", i18n._("нет раздела «{name}»", name=shown)))
        elif len(at[name]) > 1:
            out.append(_problem("A1", i18n._("раздел «{name}» повторяется ({n} раза)", name=shown, n=len(at[name]))))
    first = at["Описание"][0] if at["Описание"] else len(lines)
    out += [_problem("A1", i18n._("строка до «Описания» – {line}", line=_quote(line))) for line in lines[:first]]
    parts: dict[str, list[str]] | None = None
    if all(len(at[name]) == 1 for name in SECTIONS):
        starts = [at[name][0] for name in SECTIONS]
        if starts != sorted(starts):
            out.append(_problem("A1", i18n._("разделы не по порядку: нужно «Описание», «Объяснение», «Рекомендации», "
                                             "«Источники»")))
        else:
            ends = [*starts[1:], len(lines)]
            parts = {name: lines[s + 1:e] for name, s, e in zip(SECTIONS, starts, ends, strict=True)}
    if parts is not None:
        out += _description(parts["Описание"], list(expected_hub), list(expected_research))
        if not parts["Объяснение"]:  # п. 4.3
            out.append(_problem("A4", i18n._("раздел «Объяснение» пуст")))
        out += _recommendations(parts["Рекомендации"], component, target, no_fix)
        out += _sources(parts["Источники"])
    sources = set(parts["Источники"]) if parts is not None else set()
    for line in lines:  # п. 4.6
        if sca_text.has_internal_id(line) and line not in sources:  # адрес в «Источниках» назван выше (A8)
            out.append(_problem("A3", i18n._(INTERNAL_ID_PROBLEM, line=_quote(line))))
        out += [_problem("A1", i18n._("служебная строка прежнего формата – {line}", line=_quote(line)))
                for start in SCA_LEGACY_STARTS if line.casefold().startswith(start.casefold())]
    out += _hub_refs(lines, finding_ids, "A1", "A1")
    return _unique(out)

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

from app import defect_where, sca_text

# Требования команды, которые проверяет программа (ADR-0123 пп. 3–4; S3, S11 и смысл объяснений – у оператора)
REQUIREMENTS = {
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
}

# п. 3.5 (S6): требования к конвейеру – в любом месте обоснования и пунктов, без учёта регистра
PIPELINE_PHRASES = ("добавить тест", "написать тест", "тест, подтверждающий исправление", "дефект закрывается",
                    "проверить срабатывания того же правила", "срок устранения", "рабочих дней после разметки",
                    "гост р 71207", "гост р 56939")
# п. 3.6: служебные строки прежнего формата SAST (начало строки после снятия маркера списка); «Срок –» – заголовок
# срока (S6), «Срок жизни буфера…» – не нарушение
SAST_LEGACY_STARTS = (("Итог:", "S1"), ("Область:", "S1"), ("Что это значит:", "S1"),
                      ("Требуется от разработчика", "S1"), ("Справочно (", "S1"),
                      ("Если вы считаете срабатывание ложным", "S1"), ("Срок –", "S6"), ("Срок -", "S6"))
# п. 4.6: служебные строки прежнего формата SCA (начало строки)
SCA_LEGACY_STARTS = ("Заключение AppSec", "Критичность:", "Область:", "Что не установлено", "Требуется от разработчика",
                     "Обоснование неактуальности", "Нормативная опора", "Справочно (", "В колонке «Серьёзность»",
                     "Сводка по уязвимостям", "Детальная информация по уязвимостям")

REASON_HEAD = "Обоснование:"
RECOMMENDATION_HEAD = "Рекомендация:"
SECTIONS = ("Описание", "Объяснение", "Рекомендации", "Источники")
REFUSAL = "Текст не по требованиям команды: "
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
    return "«" + (text if len(text) <= limit else text[: limit - 1] + "…") + "»"


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
                out.append(_problem(ref_code, f"внутренний номер находки Hub {_quote(m.group(0).strip())} – {_quote(line)}"))
        for m in _LIST.finditer(line):
            numbers = re.findall(r"\d+", m.group(0))
            if all(_num(n) in ids for n in numbers):
                out.append(_problem(list_code, f"перечень номеров находок Hub {_quote(m.group(0))} – {_quote(line)}"))
    return out


def refusal(problems: list[str], at_create: bool = False) -> str:
    """Текст отказа «Подготовить дефект» и «Создать» (ADR-0123 п. 5). at_create – отказ «Создать»: у находки открыт
    предпросмотр, новую заготовку не запросить, пока его не отменили, а текст мог разойтись с названием команды."""
    shown = "; ".join(problems[:MAX_LISTED])
    more = f"; и ещё {len(problems) - MAX_LISTED}" if len(problems) > MAX_LISTED else ""
    if at_create:
        return (REFUSAL + shown + more + ". Нажмите «Отменить предпросмотр», поправьте решение (или название команды) и "
                "запросите заготовку заново.")
    return (REFUSAL + shown + more + ". Поправьте решение в карточке (обоснование, рекомендацию или текст набора), "
            "сохраните его и запросите заготовку заново.")


# ---------------------------------------------------------------------------- SAST (п. 3)


def sast_problems(text: str, *, team_phrase: str, finding_ids: Iterable[str] = ()) -> list[str]:
    """Нарушения требований команды в тексте дефекта SAST (ADR-0123 п. 3): первая непустая строка – team_phrase
    (стандартная фраза из настройки названия команды, defect.sast_phrase), затем ровно одна «Обоснование:» с непустым
    текстом (на той же строке или следующими строками), ровно одна «Рекомендация:» и под ней пункты «1)», «2)», … по
    порядку – и ничего больше. В обосновании и пунктах – без требований к конвейеру, служебных строк прежнего формата и
    ссылок на находки Hub проекта (finding_ids – номера находок проекта, хотя бы те, что упомянуты в тексте). [] – текст
    по требованиям."""
    # раздел «Где исправлять» – сведения для разработчиков, не часть шаблона команды (план dev7, раздел 11)
    lines = [line for line in normalize(defect_where.split(text)[0]) if line]
    if not lines:
        return [_problem("S1", "текст дефекта пуст")]
    out: list[str] = []
    phrase = norm_line(team_phrase)
    body = lines[1:]
    if lines[0] != phrase:  # п. 3.1
        out.append(_problem("S2", f"первая строка – не стандартная фраза команды {_quote(phrase, 160)}: "
                                  f"{_quote(lines[0])}"))
        if lines[0].startswith(REASON_HEAD):  # фразы нет вовсе: первая строка – уже «Обоснование:»
            body = lines
    reason_at = [i for i, line in enumerate(body) if line.startswith(REASON_HEAD)]
    rec_at = [i for i, line in enumerate(body) if line == RECOMMENDATION_HEAD]
    for head, found in ((REASON_HEAD, reason_at), (RECOMMENDATION_HEAD, rec_at)):  # пп. 3.2, 3.3
        if len(found) != 1:
            out.append(_problem("S1", f"строка {_quote(head)} должна быть ровно одна, а "
                                      + ("её нет" if not found else f"их {len(found)}")))
    if len(reason_at) == 1 and len(rec_at) == 1:
        r, k = reason_at[0], rec_at[0]
        out += [_problem("S1", f"строка сверх шаблона команды до «Обоснование:» – {_quote(line)}") for line in body[:r]]
        if k < r:
            out.append(_problem("S1", "«Рекомендация:» стоит раньше «Обоснование:»"))
        else:
            reason = [body[r][len(REASON_HEAD):].strip(), *body[r + 1:k]]
            if not any(reason):
                out.append(_problem("S1", "обоснование пустое"))
            items = body[k + 1:]
            if not items:
                out.append(_problem("S4", "под «Рекомендация:» нет ни одного пункта «1) …»"))
            number = 1
            for line in items:
                m = _ITEM.match(line)
                if m is None or not m.group(2).strip():
                    out.append(_problem("S1", f"после «Рекомендация:» – строка не пункт «N) …»: {_quote(line)}"))
                    continue
                if int(m.group(1)) != number:
                    out.append(_problem("S1", f"пункты рекомендации не по порядку: {_quote(line)} вместо «{number})»"))
                number += 1
    for line in body:
        low = line.casefold()
        out += [_problem("S6", f"требование ГОСТ к конвейеру («{p}») – {_quote(line)}") for p in PIPELINE_PHRASES
                if p in low]  # п. 3.5
        bare = _MARKER.sub("", line, count=1).casefold()
        out += [_problem(code, f"служебная строка прежнего формата – {_quote(line)}") for start, code in
                SAST_LEGACY_STARTS if bare.startswith(start.casefold())]  # п. 3.6
    out += _hub_refs(body, finding_ids, "S5", "S8")  # п. 3.7
    return _unique(out)


# ---------------------------------------------------------------------------- SCA (п. 4)


def _description(lines: list[str], hub: list[str], research: list[str]) -> list[str]:
    """п. 4.2 (A3): каждая ожидаемая строка «<идентификатор> (<ссылка>)» – ровно один раз, посторонних нет; разделитель
    «Также затрагивают эту версию:» – между уязвимостями находок Hub и применимыми по исследованию, только если есть
    и те и другие (так его ставит генератор, sca_text.body)."""
    hub, research = [norm_line(x) for x in hub], [norm_line(x) for x in research]
    expected = _unique([*hub, *research])
    sep = sca_text.ALSO_AFFECTED
    out: list[str] = []
    seps = [i for i, line in enumerate(lines) if line == sep]
    if hub and research and len(seps) != 1:
        out.append(_problem("A3", f"строка {_quote(sep)} нужна ровно одна – между уязвимостями находок Hub и "
                                  "применимыми по исследованию"))
    elif not (hub and research) and seps:
        out.append(_problem("A3", f"строка {_quote(sep)} – только между уязвимостями находок Hub и применимыми по "
                                  "исследованию" + ("" if hub else ": уязвимостей находок Hub в наборе нет")))
    for line in expected:
        count = lines.count(line)
        if count == 0:
            out.append(_problem("A3", f"в «Описании» нет строки {_quote(line)}"))
        elif count > 1:
            out.append(_problem("A3", f"строка {_quote(line)} в «Описании» повторяется"))
    out += [_problem("A3", f"посторонняя строка в «Описании» – {_quote(line)}") for line in lines
            if line != sep and line not in expected]
    if hub and research and len(seps) == 1:
        at = seps[0]
        for i, line in enumerate(lines):
            if line in hub and line not in research and i > at:
                out.append(_problem("A3", f"уязвимость находок Hub {_quote(line)} стоит после {_quote(sep)}"))
            elif line in research and line not in hub and i < at:
                out.append(_problem("A3", f"уязвимость по исследованию {_quote(line)} стоит до {_quote(sep)}"))
    return out


def _recommendations(lines: list[str], component: str, target: str, no_fix: bool) -> list[str]:
    """п. 4.4 (A7): обновление – ровно одна строка «Обновление <компонент> до версии <версия>» последней, перед ней –
    пояснение версии Hub, остаточный риск и добавление оператора; «Исправленной версии нет» (ADR-0101) – строки
    обновления нет, есть меры. Строка обновления – только полная форма «Обновление <компонент набора> до версии
    <версия>» (одно слово версии): строки про другие компоненты и строки оператора, которые продолжают фразу («… до
    версии 2.0 потребует миграции API»), – добавление оператора и меры. Цена: «… до версии 3.0 или новее» в режиме без
    исправления строкой обновления не считается."""
    head = norm_line(f"Обновление {component} до версии")
    full = re.compile(re.escape(head) + r" \S+")
    updates = [line for line in lines if full.fullmatch(line)]
    if no_fix:
        out = [_problem("A7", f"в режиме «Исправленной версии нет» строки обновления нет – {_quote(line)}")
               for line in updates]
        if not lines:
            out.append(_problem("A7", "в режиме «Исправленной версии нет» в «Рекомендациях» нет мер"))
        return out
    expected = norm_line(f"Обновление {component} до версии {target}")
    if not updates:
        return [_problem("A7", f"в «Рекомендациях» нет строки {_quote(expected, 160)}")]
    if len(updates) > 1:
        return [_problem("A7", f"строк обновления {len(updates)} – нужна одна {_quote(expected, 160)}")]
    if updates[0] != expected:
        return [_problem("A7", f"строка обновления {_quote(updates[0])} не совпадает с набором: нужна "
                               f"{_quote(expected, 160)}")]
    if lines[-1] != updates[0]:
        return [_problem("A7", "после строки обновления – другие строки: строка обновления последняя в «Рекомендациях»")]
    return []


def _sources(lines: list[str]) -> list[str]:
    """п. 4.5 (A8): только адреса страниц для человека (sca_text.human_url) без внутреннего номера (has_internal_id)."""
    out = []
    for line in lines:
        if not _URL.match(line):
            out.append(_problem("A8", f"в «Источниках» – не адрес: {_quote(line)}"))
        elif not sca_text.human_url(line):
            out.append(_problem("A8", f"служебный адрес (запрос к API или файл метаданных реестра) – {_quote(line)}"))
        elif sca_text.has_internal_id(line):
            out.append(_problem("A8", f"адрес с внутренним номером уязвимости (AST) – {_quote(line)}"))
    return out


def sca_problems(text: str, *, expected_hub: Iterable[str], expected_research: Iterable[str], component: str,
                 target: str, no_fix: bool, finding_ids: Iterable[str] = ()) -> list[str]:
    """Нарушения требований команды в тексте дефекта SCA (ADR-0123 п. 4): разделы «Описание», «Объяснение»,
    «Рекомендации», «Источники» – каждый один раз, по порядку, до «Описания» ничего; «Описание» сверяется со строками
    набора (expected_hub – уязвимости находок Hub, expected_research – применимые по исследованию; то же представление,
    что у генератора, sca_text.description_lines, из того же снимка набора); «Объяснение» не пусто; «Рекомендации» –
    строка обновления компонента до целевой версии (component, target) или, при no_fix, меры без неё; «Источники» –
    только адреса для человека. Во всём тексте – без номеров AST, ссылок на находки Hub проекта (finding_ids) и
    служебных строк прежнего формата. Данные набора (целевая версия, объяснения, подтверждения) проверяет sca_defect.
    [] – текст по требованиям."""
    lines = [line for line in normalize(defect_where.split(text)[0]) if line]  # раздел «Где исправлять» – не часть шаблона
    out: list[str] = []
    at = {name: [i for i, line in enumerate(lines) if line == name] for name in SECTIONS}
    for name in SECTIONS:  # п. 4.1
        if not at[name]:
            out.append(_problem("A1", f"нет раздела «{name}»"))
        elif len(at[name]) > 1:
            out.append(_problem("A1", f"раздел «{name}» повторяется ({len(at[name])} раза)"))
    first = at["Описание"][0] if at["Описание"] else len(lines)
    out += [_problem("A1", f"строка до «Описания» – {_quote(line)}") for line in lines[:first]]
    parts: dict[str, list[str]] | None = None
    if all(len(at[name]) == 1 for name in SECTIONS):
        starts = [at[name][0] for name in SECTIONS]
        if starts != sorted(starts):
            out.append(_problem("A1", "разделы не по порядку: нужно «Описание», «Объяснение», «Рекомендации», "
                                      "«Источники»"))
        else:
            ends = [*starts[1:], len(lines)]
            parts = {name: lines[s + 1:e] for name, s, e in zip(SECTIONS, starts, ends, strict=True)}
    if parts is not None:
        out += _description(parts["Описание"], list(expected_hub), list(expected_research))
        if not parts["Объяснение"]:  # п. 4.3
            out.append(_problem("A4", "раздел «Объяснение» пуст"))
        out += _recommendations(parts["Рекомендации"], component, target, no_fix)
        out += _sources(parts["Источники"])
    sources = set(parts["Источники"]) if parts is not None else set()
    for line in lines:  # п. 4.6
        if sca_text.has_internal_id(line) and line not in sources:  # адрес в «Источниках» назван выше (A8)
            out.append(_problem("A3", f"внутренний номер уязвимости (AST) – {_quote(line)}"))
        out += [_problem("A1", f"служебная строка прежнего формата – {_quote(line)}") for start in SCA_LEGACY_STARTS
                if line.casefold().startswith(start.casefold())]
    out += _hub_refs(lines, finding_ids, "A1", "A1")
    return _unique(out)

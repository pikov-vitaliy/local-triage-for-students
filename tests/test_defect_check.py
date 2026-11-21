"""Требования команды к тексту дефекта – проверка формы перед Hub (ADR-0123): грамматика текста SAST и SCA, каждое
нарушение внутри иначе правильного каркаса и соседние допустимые случаи, выход текущих генераторов, нормализованные
эталоны команды, тексты прежнего формата 0.9.0–0.9.5; маршруты: «Подготовить дефект» и «Создать» с нарушающим текстом
– отказ без записи в очередь, «Привязать к дефекту» не проверяется, панель «Дефект для Hub» – предупреждение без
запрета. Все данные, номера, адреса и компоненты выдуманы."""

from __future__ import annotations

import json
import re

import pytest

from app import defect, defect_check, sca_text
from app.db import Database
from app.defect_check import sast_problems, sca_problems
from test_defect import save_sast
from test_hub_defect_guard import link_fields
from test_hub_defects import BLANK, FIX, REASON, SERVICE, blank, create, hub_job, hub_settings, pair_project
from test_hub_defects import sast_ready, shown, to_preview
from test_hub_status_routes import AS_JSON
from test_sca import sca_text_ready, shown_fields
from test_sca_package_decision import UPD, post_package
from test_sca_text import RESEARCH
from test_web import ORIGIN, prepared, web  # noqa: F401

TEAM = "Платформа"
PHRASE = defect.sast_phrase(TEAM)
COMPONENT = "org.example.thirdparty:example-json-kit"
CVE1, CVE2 = "CVE-2099-10001", "CVE-2099-10002"
LINE1, LINE2 = f"{CVE1} (https://nvd.nist.gov/vuln/detail/{CVE1})", f"{CVE2} (https://nvd.nist.gov/vuln/detail/{CVE2})"


def codes(problems: list[str]) -> set[str]:
    return {p.split(":", 1)[0] for p in problems}


# ============================================================================ SAST: каркас


def sast(reason: str = "Значение owner из параметра запроса подставляется в SQL-запрос склейкой строк, что "
                       "позволяет изменить запрос.",
         items: tuple[str, ...] = ("Параметризовать запрос.", "Имя таблицы выбирать из белого списка."),
         phrase: str = PHRASE, head: str = "Обоснование:", before: str = "") -> str:
    """Текст SAST в каркасе команды (ADR-0089) с подменяемыми частями."""
    lines = [phrase, ""] + ([before, ""] if before else []) + [head, reason, "", "Рекомендация:"]
    lines += [f"{n}) {item}" for n, item in enumerate(items, 1)]
    return "\n".join(lines)


def check_sast(text: str, ids=()) -> list[str]:
    return sast_problems(text, team_phrase=PHRASE, finding_ids=ids)


def test_sast_frame_is_clean():
    assert check_sast(sast()) == []
    assert check_sast(sast(head="Обоснование: значение приходит из запроса.", reason="")) == [], \
        "текст обоснования на строке «Обоснование:»"
    assert check_sast(sast(reason="Первая строка обоснования.\nВторая строка обоснования.")) == []


def test_sast_team_template_normalized():
    """Нормализованный эталон команды (ADR-0089, выдуманные данные): лишние пробелы, \\r\\n и пустые строки – не
    нарушения (п. 2)."""
    template = ("  После тщательного   анализа уязвимости команда Платформа приняла решение присвоить данной уязвимости "
                "категорию True Positive.  \r\n\r\n\r\nОбоснование:\r\n  Параметр sort из запроса попадает в ORDER BY "
                "без проверки, поэтому нарушитель меняет текст запроса.\r\n\r\nРекомендация:\r\n1)  Имя столбца "
                "выбирать из перечня разрешённых значений.\r\n2) Использовать параметризованный запрос.\r\n")
    assert check_sast(template) == []
    assert defect_check.normalize("  a   b \r\nc") == ["a b", "c"]


@pytest.mark.parametrize("comment, fix", [
    (REASON, FIX),
    ("строка 26 формирует запрос из owner без проверки.", "1. Параметризовать запрос.\n2) Белый список.\n- Тест не нужен"),
    ("Значение из заголовка Host\nпопадает в ссылку письма.", "Проверять Host по списку.\n```java\nx = y;\n```\nЭкранировать."),
    ("Буфер 1048576 байт выделяется по длине из запроса. Срок жизни буфера не ограничен.",
     "Ограничить длину.\n    code();\nОсвобождать буфер."),
])
def test_sast_generator_output_is_clean(comment, fix):
    body = defect.sast_body(None, "true_positive", comment, fix, TEAM)
    assert check_sast(body, ids={"510001", "1048576"}) == [], body


def test_sast_phrase_and_structure_violations():
    other = defect.sast_phrase("Другая команда")
    assert codes(check_sast(sast(phrase=other))) == {"S2"}
    missing = "\n".join(sast().split("\n")[2:])  # без стандартной фразы
    assert "S2" in codes(check_sast(missing)) and not [p for p in check_sast(missing) if "ровно одна" in p]
    assert codes(check_sast(sast(before="Итог: подтверждено."))) == {"S1"}, "строка до «Обоснования» – сверх шаблона"
    assert codes(check_sast(sast(before="Пояснение для разработчика."))) == {"S1"}
    twice = sast().replace("Рекомендация:", "Обоснование: ещё одно\n\nРекомендация:")
    assert any("«Обоснование:» должна быть ровно одна" in p for p in check_sast(twice))
    assert any("«Рекомендация:» должна быть ровно одна" in p for p in check_sast(sast().replace("Рекомендация:", "")))
    assert any("обоснование пустое" in p for p in check_sast(sast(reason="")))
    assert codes(check_sast(sast(items=()))) == {"S4"}
    shuffled = sast().replace("2) Имя", "3) Имя")
    assert any("не по порядку" in p for p in check_sast(shuffled))
    tail = sast() + "\nСвязаться с командой AppSec."
    assert any("строка не пункт" in p for p in check_sast(tail)), "после пунктов других строк нет"
    reversed_ = "\n".join([PHRASE, "Рекомендация:", "1) Параметризовать запрос.", "Обоснование:", "Текст обоснования."])
    assert any("раньше" in p for p in check_sast(reversed_))
    assert check_sast("") == ["S1: текст дефекта пуст"]


# ============================================================================ SAST: конвейер, служебные строки, номера


def test_sast_pipeline_requirement_in_a_point():
    found = check_sast(sast(items=("Параметризовать запрос.", "Добавить тест на значение со спецсимволами.")))
    assert codes(found) == {"S6"} and "добавить тест" in found[0]
    inline = check_sast(sast(items=("Параметризовать запрос. Добавить тест, подтверждающий исправление.",)))
    assert codes(inline) == {"S6"} and len(inline) == 2  # «добавить тест» и «тест, подтверждающий исправление»


def test_sast_pipeline_requirement_inside_multiline_reason():
    reason = ("Значение owner приходит из запроса.\nДефект закрывается по ссылке на исправление.\nЗапрос "
              "выполняется без параметров.")
    assert codes(check_sast(sast(reason=reason))) == {"S6"}


@pytest.mark.parametrize("phrase", ["Написать тест на граничное значение", "Проверить срабатывания того же правила",
                                    "срок устранения – по плану", "10 рабочих дней после разметки",
                                    "по ГОСТ Р 71207-2024", "по ГОСТ Р 56939-2024"])
def test_sast_every_pipeline_phrase(phrase):
    assert codes(check_sast(sast(items=("Параметризовать запрос.", f"{phrase}.")))) == {"S6"}


def test_sast_deadline_heading_and_buffer_lifetime():
    assert check_sast(sast(reason="Срок жизни буфера не ограничен, данные из запроса остаются в памяти.")) == []
    assert codes(check_sast(sast(reason="Значение приходит из запроса.\nСрок – 10 дней."))) == {"S6"}
    assert codes(check_sast(sast(items=("Параметризовать запрос.", "Срок - по регламенту.")))) == {"S6"}


@pytest.mark.parametrize("line, code", [
    ("Итог: подтверждена ошибка.", "S1"), ("Область: кодовая база demo-core.", "S1"),
    ("Что это значит: ошибку можно использовать.", "S1"), ("Требуется от разработчика: исправить код.", "S1"),
    ("Справочно (класс слабости): CWE-89.", "S1"), ("Если вы считаете срабатывание ложным, покажите место.", "S1"),
])
def test_sast_legacy_lines(line, code):
    in_reason = check_sast(sast(reason="Значение приходит из запроса.\n" + line))
    assert code in codes(in_reason) and any("прежнего формата" in p for p in in_reason)
    in_point = check_sast(sast(items=("Параметризовать запрос.", line)))  # после снятия маркера «2)»
    assert any("прежнего формата" in p for p in in_point)


def test_sast_internal_finding_numbers():
    assert codes(check_sast(sast(reason="Как в находке ID: 12345, значение не проверяется."), ids={"12345"})) == {"S5"}
    assert codes(check_sast(sast(reason="См. ID 12345."), ids={"12345"})) == {"S5"}
    assert codes(check_sast(sast(reason="См. находку № 12345."), ids={"12345"})) == {"S5"}
    assert check_sast(sast(reason="Как в ID: 12345, значение не проверяется."), ids={"777"}) == [], \
        "число не номер находки проекта"
    assert check_sast(sast(reason="Буфер 1048576 байт выделяется по длине из запроса."), ids={"1048576"}) == [], \
        "отдельное число – не нарушение при любой длине"
    listed = sast(items=("Проверить места 510001, 510002, 510003 и исправить.",))
    assert codes(check_sast(listed, ids={"510001", "510002", "510003"})) == {"S8"}
    assert check_sast(listed, ids={"510001", "510002"}) == [], "не каждое число – номер находки"
    assert check_sast(sast(items=("Порты 8080, 8443 закрыть.",)), ids={"8080", "8443"}) == [], "перечень из двух"
    assert defect_check.number_candidates("ID: 0012, № 7; 1, 2, 3") >= {"0012", "12", "7", "1", "2", "3"}


# границы идентификатора (п. 3.7): номер – целым числом, перечень – не продолжение слова и не идентификатор с дефисом
BOUNDARY_CASES = [
    ("ID: 12345", {"12345"}, True),
    ("ID 12345.", {"12345"}, True),
    ("№12345,", {"12345"}, True),
    ("(12345, 12346, 12347)", {"12345", "12346", "12347"}, True),
    ("ID: 12345abc", {"12345"}, False),
    ("item12345, 12346, 12347", {"12345", "12346", "12347"}, False),
    ("CWE-79, 80, 81", {"79", "80", "81"}, False),
    ("ID: 12345.6", {"12345"}, False),
    ("12345, 12346, 12347.5", {"12345", "12346", "12347"}, False),
    ("12344, 12345, 12346.5, 12347", {"12344", "12345", "12346", "12347"}, False),
    ("12345, 12346, 12347.", {"12345", "12346", "12347"}, True),
    ("12344, 12345, 12346, 12347.5", {"12344", "12345", "12346", "12347"}, False),
]


@pytest.mark.parametrize("ref, ids, caught", BOUNDARY_CASES)
def test_sast_finding_number_boundaries(ref, ids, caught):
    assert bool(defect_check.number_candidates(ref) & ids) == caught, ref
    found = check_sast(sast(reason=f"Значение из запроса не проверяется, как в {ref} – та же ошибка."), ids=ids)
    assert (codes(found) & {"S5", "S8"} != set()) == caught, (ref, found)
    if not caught:
        assert found == [], (ref, found)


def test_sast_legacy_0905_text_is_refused_by_every_class():
    """Синтетический текст прежнего формата (каркас 0.9.0–0.9.5, выдуманные данные)."""
    legacy = "\n".join([
        PHRASE, "",
        "Итог: ReportRepository.find (src/main/java/demo/ReportRepository.java:57) – значение из запроса подставляется "
        "в SQL-запрос. Подтверждена ошибка в программе класса CWE-89.",
        "Область: кодовая база demo-core, выгрузка Hub от 01.10.2026.", "",
        "Обоснование: значение приходит из параметра запроса без проверки.", "",
        "Что это значит: если ошибку можно использовать для реализации угроз, это уязвимость (ГОСТ Р 56939-2024, п. 3.20).",
        "", "Требуется от разработчика:",
        "1. Заменить склейку строк параметризованным запросом.",
        "2. Проверить срабатывания того же правила в этой кодовой базе: 610201, 610202, 610203.",
        "3. Добавить тест: значение со спецсимволами не меняет текст запроса.",
        "Дефект закрывается по ссылке на исправляющее изменение и результату теста.",
        "Срок – не позже 10 рабочих дней после разметки (ГОСТ Р 71207-2024, п. 5.9).", "",
        "Если вы считаете срабатывание ложным, покажите место в коде, где значение ограничено.", "",
        "Справочно (класс слабости; применимость к продукту отдельно не оценивалась):", "CWE-89 – SQL Injection."])
    found = check_sast(legacy, ids={"610201", "610202", "610203"})
    assert codes(found) == {"S1", "S6", "S8"}, found  # «Рекомендация:» нет – каркас S1, пункты не разбираются
    for start in ("Итог:", "Область:", "Что это значит:", "Требуется от разработчика", "Если вы считаете",
                  "Справочно ("):
        assert any("прежнего формата" in p and start in p for p in found), start
    short = ("Подтверждена ошибка в программе класса CWE-89: SQL Injection в src/Report.java:57.\nОбоснование: значение "
             "из запроса.\nТребуется от разработчика: исправить код, добавить тест. Срок – 10 рабочих дней после разметки.")
    assert {"S1", "S2", "S6"} <= codes(check_sast(short))


# ============================================================================ SCA: каркас


def sca(description=(LINE1, sca_text.ALSO_AFFECTED, LINE2), explanation=(f"{CVE1}: Подстановка имени класса ведёт к выполнению кода.",
                                                 f"{CVE2}: Отказ в обслуживании при разборе вложенных структур."),
        recommendations=(f"Обновление {COMPONENT} до версии 1.2.7",),
        sources=(f"https://nvd.nist.gov/vuln/detail/{CVE1}", "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"),
        order=("Описание", "Объяснение", "Рекомендации", "Источники"), before: str = "") -> str:
    parts = {"Описание": list(description), "Объяснение": list(explanation), "Рекомендации": list(recommendations),
             "Источники": list(sources)}
    lines = [before] if before else []
    for name in order:
        lines += [name, *parts[name], ""]
    return "\n".join(lines)


def check_sca(text: str, hub=(LINE1,), research=(LINE2,), target="1.2.7", no_fix=False, ids=()) -> list[str]:
    return sca_problems(text, expected_hub=list(hub), expected_research=list(research), component=COMPONENT,
                        target=target, no_fix=no_fix, finding_ids=ids)


def test_sca_frame_is_clean():
    text = sca(description=(LINE1, sca_text.ALSO_AFFECTED, LINE2))
    assert check_sca(text) == []
    assert check_sca(sca(description=(LINE1, LINE2)), hub=(LINE1, LINE2), research=()) == [], \
        "обе уязвимости находок Hub"


def test_sca_team_template_normalized():
    """Нормализованный эталон команды (ADR-0091, выдуманные данные): пробелы и \\r\\n – не нарушения."""
    template = ("Описание\r\n  CVE-2099-10001   (https://nvd.nist.gov/vuln/detail/CVE-2099-10001)\r\nCVE-2099-10002 "
                "(https://nvd.nist.gov/vuln/detail/CVE-2099-10002)\r\n\r\nОбъяснение\r\nCVE-2099-10001: Подстановка "
                "имени класса в параметры подключения ведёт к выполнению кода.\r\nCVE-2099-10002: Отказ в "
                "обслуживании при разборе вложенных структур.\r\n\r\nРекомендации\r\nТакже версия 1.2.5, указанная в "
                "Hub, затронута CVE-2099-10002 (средняя), поэтому указана версия 1.2.7.\r\nОбновление "
                "org.example.thirdparty:example-json-kit  до версии 1.2.7\r\n\r\nИсточники\r\n"
                "https://nvd.nist.gov/vuln/detail/CVE-2099-10001\r\nhttps://github.com/advisories/GHSA-aaaa-bbbb-cccc\r\n")
    assert check_sca(template, hub=(LINE1, LINE2), research=()) == []


def generated(no_fix: bool = False, hub_note: str = "", residual: tuple = (), note: str = "", members=None):
    vulns = sca_text.set_vulns(members=members or {"200250": [CVE1]}, others={}, aliases={},
                               research=RESEARCH["public_findings"])
    explanation = (f"{CVE1}: Подстановка имени класса в параметры подключения ведёт к выполнению кода.\n"
                   f"{CVE2}: Отказ в обслуживании при разборе вложенных структур.")
    sources = sca_text.research_sources(vulns, RESEARCH, "1.2.7")
    body = sca_text.body(COMPONENT, vulns, explanation, "" if no_fix else "1.2.7", sources, hub_note, residual, note)
    hub, research = sca_text.description_lines(vulns)
    return body, hub, research


@pytest.mark.parametrize("kwargs", [
    {}, {"hub_note": "Версия 1.2.5, указанная в Hub, затронута CVE-2099-10002 (средняя); по исследованным диапазонам "
                     "версия 1.2.7 не затронута."},
    {"residual": ("Исправление не установлено в исследованном охвате на 2026-10-20: CVE-2099-10003 (высокая) – "
                  "обновление до 1.2.7 её не закрывает.",)},
    {"note": "Перед обновлением проверить совместимость конфигурации."},
    {"no_fix": True, "residual": ("Исправления нет ни в одной опубликованной версии на 2026-10-20: CVE-2099-10001 "
                                  "(критическая).",), "note": "Отключить разбор вложенных структур."},
    {"members": {"200250": [CVE1], "200251": [CVE2]}},
])
def test_sca_generator_output_is_clean(kwargs):
    no_fix = bool(kwargs.get("no_fix"))
    body, hub, research = generated(**kwargs)
    assert check_sca(body, hub=hub, research=research, target="" if no_fix else "1.2.7", no_fix=no_fix,
                     ids={"200250", "200251"}) == [], body


def test_sca_sections():
    assert codes(check_sca(sca(order=("Описание", "Объяснение", "Рекомендации", "Источники", "Объяснение")))) == {"A1"}
    assert any("не по порядку" in p for p in check_sca(sca(order=("Объяснение", "Описание", "Рекомендации",
                                                                   "Источники"))))
    assert any("нет раздела «Источники»" in p for p in check_sca(sca(order=("Описание", "Объяснение", "Рекомендации"))))
    assert any("до «Описания»" in p for p in check_sca(sca(before="Заголовок дефекта")))
    assert codes(check_sca(sca(explanation=()))) == {"A4"}


def test_sca_description():
    ok = (LINE1, sca_text.ALSO_AFFECTED, LINE2)
    assert check_sca(sca(description=ok)) == []
    one = check_sca(sca(description=(LINE1,)))
    assert codes(one) == {"A3"} and any(f"нет строки «{LINE2}»" in p for p in one), "одна из двух ожидаемых"
    extra = check_sca(sca(description=(*ok, "CVE-2099-19999 (https://nvd.nist.gov/vuln/detail/CVE-2099-19999)")))
    assert any("посторонняя строка" in p for p in extra), "лишняя строка"
    again = check_sca(sca(description=(*ok, LINE2)))
    assert any("повторяется" in p for p in again), "повтор"
    bare = check_sca(sca(description=(LINE1, sca_text.ALSO_AFFECTED, CVE2)))
    assert any(f"посторонняя строка в «Описании» – «{CVE2}»" in p for p in bare) and any(
        f"нет строки «{LINE2}»" in p for p in bare), "строка без ссылки"
    assert check_sca(sca(description=())) and check_sca(sca(description=()), hub=(), research=()) == [], \
        "ожидаемый список пуст – «Описание» может быть пустым"


def test_sca_also_affected_separator():
    assert check_sca(sca(description=(LINE1, sca_text.ALSO_AFFECTED, LINE2))) == [], "с уязвимостями Hub"
    without_hub = check_sca(sca(description=(sca_text.ALSO_AFFECTED, LINE2)), hub=(), research=(LINE2,))
    assert codes(without_hub) == {"A3"} and any("только между" in p for p in without_hub), "без уязвимостей Hub"
    assert check_sca(sca(description=(LINE2,)), hub=(), research=(LINE2,)) == []
    swapped = check_sca(sca(description=(LINE2, sca_text.ALSO_AFFECTED, LINE1)))
    assert any("стоит после" in p for p in swapped) and any("стоит до" in p for p in swapped)
    assert any("ровно одна" in p for p in check_sca(sca(description=(LINE1, LINE2)))), \
        "есть и те и другие – разделитель между ними"


def test_sca_recommendations():
    update = f"Обновление {COMPONENT} до версии 1.2.7"
    for line in ("Сводка по уязвимостям:", "ID: 73001 – находка Hub."):
        found = check_sca(sca(description=(LINE1, sca_text.ALSO_AFFECTED, LINE2), recommendations=(line, update)),
                          ids={"73001"})
        assert codes(found) == {"A1"}, (line, found)
    residual = ("Исправление не установлено в исследованном охвате на 2026-10-20: CVE-2099-10003 (высокая) – "
                "обновление до 1.2.7 её не закрывает.")
    full = (LINE1, sca_text.ALSO_AFFECTED, LINE2)
    assert check_sca(sca(description=full, recommendations=(residual, update))) == [], "остаточный риск перед строкой"
    assert any("нет строки" in p for p in check_sca(sca(description=full, recommendations=(residual,))))
    assert any("строк обновления 2" in p for p in check_sca(sca(description=full, recommendations=(update, update))))
    assert any("не совпадает с набором" in p for p in check_sca(
        sca(description=full, recommendations=(f"Обновление {COMPONENT} до версии 1.2.8",))))
    assert any("последняя" in p for p in check_sca(sca(description=full, recommendations=(update, residual))))
    # «Исправленной версии нет» (ADR-0101): строки обновления нет, есть меры
    measures = ("Исправления нет ни в одной опубликованной версии на 2026-10-20: CVE-2099-10001 (критическая).",
                "Отключить разбор вложенных структур.")
    assert check_sca(sca(description=full, recommendations=measures), target="", no_fix=True) == []
    assert any("строки обновления нет" in p for p in check_sca(
        sca(description=full, recommendations=(*measures, update)), target="", no_fix=True))
    assert any("нет мер" in p for p in check_sca(sca(description=full, recommendations=()), target="", no_fix=True))


def test_sca_update_line_is_only_about_the_set_component():
    """Строка обновления набора – только «Обновление <компонент набора> до версии» (п. 4.4): строки про другие
    компоненты – добавление оператора и меры, а не вторая строка обновления."""
    full = (LINE1, sca_text.ALSO_AFFECTED, LINE2)
    update = f"Обновление {COMPONENT} до версии 1.2.7"
    other = "Обновление org.example.thirdparty:example-xml-kit до версии 3.1.0 – вместе с основным компонентом."
    # режим обновления: ровно одна строка компонента набора, равная ожидаемой, последняя
    assert check_sca(sca(description=full, recommendations=(other, update))) == [], "строка про другой компонент"
    assert any("последняя" in p for p in check_sca(sca(description=full, recommendations=(update, other))))
    assert any("нет строки" in p for p in check_sca(sca(description=full, recommendations=(other,))))
    near = f"Обновление {COMPONENT}-extra до версии 2.0.0"  # другой компонент с тем же началом имени
    assert check_sca(sca(description=full, recommendations=(near, update))) == []
    # «Исправленной версии нет»: нарушение – только строка обновления компонента набора
    measures = ("Исправления нет ни в одной опубликованной версии на 2026-10-20: CVE-2099-10001 (критическая).",
                "Отключить разбор вложенных структур.")
    assert check_sca(sca(description=full, recommendations=(*measures, other)), target="", no_fix=True) == []
    found = check_sca(sca(description=full, recommendations=(*measures, other, f"Обновление {COMPONENT} до версии 1.2.7")),
                      target="", no_fix=True)
    assert len(found) == 1 and "строки обновления нет" in found[0] and COMPONENT in found[0], found


def test_sca_sources():
    full = (LINE1, sca_text.ALSO_AFFECTED, LINE2)
    tracker = "https://bugs.example.org/show_bug.cgi?id=1234&ctype=html"
    assert check_sca(sca(description=full, sources=(f"https://nvd.nist.gov/vuln/detail/{CVE1}", tracker))) == [], \
        "страница трекера с параметрами – допустимо"
    for url in ("https://api.example.org/advisories/1", "https://repo.example.org/kit/1.2.7/kit-1.2.7.pom",
                "https://repo.example.org/kit/maven-metadata.xml", "https://example.org/api/v1/vulns"):
        assert codes(check_sca(sca(description=full, sources=(url,)))) == {"A8"}, url
    assert any("не адрес" in p for p in check_sca(sca(description=full, sources=("NVD, раздел уязвимости",))))
    ast_url = check_sca(sca(description=full, sources=("https://vendor.example.org/vuln/AST-2026-000150",)))
    assert codes(ast_url) == {"A8"} and len(ast_url) == 1


@pytest.mark.parametrize("start", defect_check.SCA_LEGACY_STARTS)
def test_sca_legacy_lines_anywhere(start):
    text = sca(description=(LINE1, sca_text.ALSO_AFFECTED, LINE2),
               recommendations=(f"{start} – прежний блок.", f"Обновление {COMPONENT} до версии 1.2.7"))
    assert codes(check_sca(text)) == {"A1"}, start


def test_sca_internal_numbers():
    full = (LINE1, sca_text.ALSO_AFFECTED, LINE2)
    with_ast = check_sca(sca(description=full, explanation=(
        f"{CVE1}: Подстановка имени класса ведёт к выполнению кода (это AST-2026-000150).",
        f"{CVE2}: Отказ в обслуживании.")))
    assert codes(with_ast) == {"A3"} and "AST" in with_ast[0]
    listed = sca(description=full, recommendations=("Находки 73001, 73002, 73003 – один набор.",
                                                    f"Обновление {COMPONENT} до версии 1.2.7"))
    assert codes(check_sca(listed, ids={"73001", "73002", "73003"})) == {"A1"}
    assert check_sca(listed, ids={"73001"}) == []


@pytest.mark.parametrize("ref, ids, caught", BOUNDARY_CASES)
def test_sca_finding_number_boundaries(ref, ids, caught):
    text = sca(description=(LINE1, sca_text.ALSO_AFFECTED, LINE2),
               recommendations=(f"См. {ref} – тот же набор.", f"Обновление {COMPONENT} до версии 1.2.7"))
    found = check_sca(text, ids=ids)
    assert (any("находок Hub" in p or "находки Hub" in p for p in found)) == caught, (ref, found)
    assert found == [] if not caught else codes(found) == {"A1"}, (ref, found)


def test_sca_legacy_0905_text_is_refused_by_every_class():
    """Синтетический текст прежнего формата SCA (каркас 0.9.0–0.9.5, выдуманные данные)."""
    legacy = "\n".join([
        "Заключение AppSec: статус уязвимости – анализ не завершён. По выгрузке обнаружен компонент example-parser "
        "1.4.2 с известной уязвимостью CVE-2099-10001.",
        "Критичность: не определена – оценка по регламенту не выполнена.",
        "Область: продукт demo-web, выгрузка Hub от 01.10.2026.",
        "Что не установлено: вызывается ли уязвимая функция.",
        "Требуется от разработчика – выбрать одно: 1) обновить компонент; 2) представить обоснование.",
        "Обоснование неактуальности должно показать, где подключён компонент.",
        "Нормативная опора: правила анализа (ГОСТ Р КАПО, пп. 6.14, 7.11).",
        "Справочно (класс уязвимости): CWE-94.",
        "В колонке «Серьёзность» сводки Hub указан уровень политики Hub.",
        "Сводка по уязвимостям:", "73001   : example-parser : 1.4.2   High   CVE-2099-10001",
        "Детальная информация по уязвимостям:", "ID: 73001", "Описание", LINE1, "AST-2026-000150",
        "Рекомендации", "Обновить до версии 1.4.3 или новее."])
    found = check_sca(legacy, hub=(LINE1,), research=(), target="1.4.3", ids={"73001"})
    assert codes(found) == {"A1", "A3"}, found  # разделов «Объяснение» и «Источники» нет – A1
    assert any("нет раздела «Объяснение»" in p for p in found)
    for start in defect_check.SCA_LEGACY_STARTS:
        assert any("прежнего формата" in p and start in p for p in found), start
    assert any("внутренний номер находки Hub" in p for p in found)
    assert any("AST" in p for p in found)


def test_refusal_lists_problems():
    problems = [f"S6: нарушение {n}" for n in range(10)]
    text = defect_check.refusal(problems)
    assert text.startswith("Текст не по требованиям команды: S6: нарушение 0; ") and "и ещё 7" in text
    assert text.endswith("Поправьте решение в карточке (обоснование, рекомендацию или текст набора), сохраните его и "
                         "запросите заготовку заново.")
    assert set(defect_check.REQUIREMENTS) >= {"S1", "S2", "S4", "S5", "S6", "S8", "A1", "A3", "A4", "A7", "A8"}
    # «Создать»: у находки открыт предпросмотр – сначала его отменить; текст мог разойтись с названием команды
    at_create = defect_check.refusal(["S2: первая строка"], at_create=True)
    assert at_create == ("Текст не по требованиям команды: S2: первая строка. Нажмите «Отменить предпросмотр», "
                         "поправьте решение (или название команды) и запросите заготовку заново.")


# ============================================================================ маршруты


def defect_ops(db) -> list[dict]:
    return [o for o in db.hub_ops_list() if o["purpose"].startswith("defect_")]


def test_prepare_refuses_violating_sast_text_and_panel_only_warns(web):
    pid, _ = sast_ready(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON,
                       "Параметризовать запрос.\nДобавить тест, подтверждающий исправление.")
    card = web.client.get(url).text
    assert 'id="defect-form-problems"' in card and "Текст не по требованиям команды" in card and "S6" in card
    assert 'id="defect-confirm-row" hidden' in card, "предупреждение – не «спорные места», копирование без отметки"
    copied = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "", "part": "body"})
    assert copied.status_code == 200 and "Добавить тест" in copied.json()["body"], "ручной путь не запрещён"
    r = blank(web, url)
    assert r.status_code == 400 and r.json()["detail"].startswith("Текст не по требованиям команды: S6"), r.text
    assert db.hub_defects(pid) == [] and db.hub_ops_list() == []
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON + " Как в ID: 510002.", FIX)
    r = blank(web, url)
    assert r.status_code == 400 and "S5" in r.json()["detail"], "номер находки проекта"
    assert db.hub_defects(pid) == [] and db.hub_ops_list() == []
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    assert 'id="defect-form-problems"' not in web.client.get(url).text
    assert blank(web, url).status_code == 200, "текст по требованиям – заготовка ставится"


def test_prepare_repeats_the_check_in_the_transaction(web, monkeypatch):
    """Проверка до записи не увидела номер находки (подмена чтения вне транзакции) – её повтор в транзакции постановки
    отказывает, ничего не записано."""
    pid, _ = sast_ready(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON + " Как в ID: 510002.", FIX)
    monkeypatch.setattr(Database, "hub_ids_among", lambda self, project_id, ids: set())
    r = blank(web, url)
    assert r.status_code == 400 and "S5" in r.json()["detail"], r.text
    assert db.hub_defects(pid) == [] and db.hub_ops_list() == []


def test_create_refuses_violating_saved_command_text(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    good = row["command_text"]
    db.hub_defect_update(row["id"], command_text=good + "\n2) Срок – 10 рабочих дней после разметки.")
    r = create(web, pid, row["id"])
    assert r.status_code == 400 and r.json()["detail"].startswith("Текст не по требованиям команды: S6"), r.text
    assert r.json()["detail"].endswith("Нажмите «Отменить предпросмотр», поправьте решение (или название команды) и "
                                       "запросите заготовку заново."), "у «Создать» – свой хвост отказа"
    assert db.hub_defect(row["id"])["state"] == "preview" and not [o for o in db.hub_ops_list()
                                                                   if o["purpose"] == "defect_create"]
    # стандартная фраза – из текущей настройки названия команды: сменили после предпросмотра – отказ
    db.hub_defect_update(row["id"], command_text=good)
    db.set_settings({"team_name": "Другая команда"})
    r = create(web, pid, row["id"])
    assert r.status_code == 400 and "S2" in r.json()["detail"], r.text
    db.set_settings({"team_name": "Платформа"})
    assert create(web, pid, row["id"]).status_code == 200
    assert sorted(o["purpose"] for o in defect_ops(db)) == ["defect_blank", "defect_create"]


def sca_ready(web, note: str = "") -> tuple[int, str]:
    """Набор SCA с готовым текстом (как test_sca.sca_text_ready); note – добавление оператора к «Рекомендациям»."""
    pid = prepared(web)
    db = web.app.state.db
    hub_settings(web, pid)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    url = f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}"
    if not note:
        sca_text_ready(web, url)
        return pid, url
    found = re.search(r'name="text_revision" value="(\d+)"', web.client.get(url).text)
    first = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        "text_revision": found.group(1) if found else "0", "target_version": "9.9.9"})
    assert first.status_code == 200, first.text
    ids = [line.split(":", 1)[0].strip() for line in first.json()["explanation_draft"].split("\n") if ":" in line]
    explanation = "\n".join(f"{i}: Уязвимость компонента позволяет нарушителю нарушить работу продукта при обработке "
                            "входных данных." for i in ids)
    second = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **shown_fields(web.client.get(url).text), "text_revision": str(first.json()["text_revision"]),
        "target_version": "9.9.9", "version_checked": "1", "explanation": explanation, "recommendation_note": note})
    assert second.status_code == 200, second.text
    return pid, url


def test_prepare_refuses_violating_sca_text(web):
    pid, url = sca_ready(web, note="Сводка по уязвимостям: см. находку ID: 73002.")
    db = web.app.state.db
    card = web.client.get(url).text
    assert 'id="defect-form-problems"' in card and "Сводка по уязвимостям" in card
    r = blank(web, url)
    assert r.status_code == 400 and r.json()["detail"].startswith("Текст не по требованиям команды: A1"), r.text
    assert db.hub_defects(pid) == [] and db.hub_ops_list() == []


def test_sca_create_checks_the_saved_text_against_the_same_snapshot(web, monkeypatch):
    """Форма сохранённого текста проверяется по ожиданиям снимка набора. Чтобы до проверки формы не сработала сверка
    тела с набором (круг 2, D2 – «набор изменился»), тело снимка подменено на сохранённый текст строки."""
    from app.routes import sca as sca_card
    pid, url = sca_ready(web)
    db = web.app.state.db
    assert 'id="defect-form-problems"' not in web.client.get(url).text
    assert blank(web, url).status_code == 200
    hub_job(web, match_blank=True)
    hub_job(web, body=SERVICE)
    row = db.hub_defects(pid)[0]
    assert row["state"] == "preview"
    real = sca_card.sca_defect

    def body_as_saved(*args, **kwargs):
        view = real(*args, **kwargs)
        return {**view, "body": db.hub_defect(row["id"])["command_text"]}

    monkeypatch.setattr(sca_card, "sca_defect", body_as_saved)
    good = row["command_text"]
    lines = good.split("\n")
    first_vuln = lines[1]
    assert first_vuln.startswith("CVE-") or first_vuln.startswith("GHSA-") or first_vuln.startswith("BDU:"), good
    db.hub_defect_update(row["id"], command_text="\n".join([lines[0], *lines[2:]]))  # без уязвимости набора
    r = create(web, pid, row["id"])
    assert r.status_code == 400 and "A3" in r.json()["detail"] and first_vuln in r.json()["detail"], r.text
    update = next(line for line in lines if line.startswith("Обновление "))
    db.hub_defect_update(row["id"], command_text=good.replace(update, "ID: 73002\n" + update))
    r = create(web, pid, row["id"])
    assert r.status_code == 400 and "A1" in r.json()["detail"], r.text
    assert not [o for o in db.hub_ops_list() if o["purpose"] == "defect_create"]
    db.hub_defect_update(row["id"], command_text=good)
    assert create(web, pid, row["id"]).status_code == 200


def test_link_to_defect_is_not_checked(web, monkeypatch):
    """«Привязать к дефекту» текст не отправляет: проверка требований к нему не применяется – старый дефект не теряет
    путь добавления находки (ADR-0123 п. 5)."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    assert db.hub_defect(row["id"])["state"] == "done"
    sibling = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510005')['id']}"
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    # требования ужесточились после создания дефекта: тот же текст теперь не проходит проверку
    monkeypatch.setattr(defect_check, "sast_problems", lambda text, **kw: ["S6: нарушение после создания дефекта"])
    card = web.client.get(sibling).text
    assert 'id="hub-defect-link-button"' in card and 'id="defect-form-problems"' in card
    fields = link_fields(card)
    # заготовка по тому же тексту – отказ требованиями (подмена действует), «Привязать» – без проверки
    refused = web.client.post(f"{sibling}/hub-defect", headers=AS_JSON, data={
        "review_revision": fields["review_revision"], "text_hash": fields["text_hash"]})
    assert refused.status_code == 400 and refused.json()["detail"].startswith("Текст не по требованиям команды")
    assert len(defect_ops(db)) == 3, "заготовка, создание, чтение – новых операций нет"
    r = web.client.post(f"{sibling}/hub-defect-link", headers=AS_JSON, data=fields)
    assert r.status_code == 200, r.text
    link = hub_job(web, body={})
    assert link["purpose"] == "defect_link" and link["path"] == "/defects/555/link"
    targets = json.loads(db.hub_defect(r.json()["defect_id"])["targets_json"])
    assert [t["hub_id"] for t in targets] == ["510005"]


def create_ops(db) -> list[dict]:
    return [o for o in db.hub_ops_list() if o["purpose"] == "defect_create"]


def test_create_repeats_the_check_in_the_transaction(web, monkeypatch):
    """«Создать»: проверка до транзакции не увидела номер находки (подмена чтения вне транзакции) – её повтор в
    транзакции hub_defect_advance отказывает: строка в предпросмотре, POST /defects не поставлен."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    good = row["command_text"]
    with_ref = good.replace("\n\nРекомендация:", "\nКак в находке ID: 510002.\n\nРекомендация:")
    assert with_ref != good
    db.hub_defect_update(row["id"], command_text=with_ref)
    monkeypatch.setattr(Database, "hub_ids_among", lambda self, project_id, ids: set())
    r = create(web, pid, row["id"])
    assert r.status_code == 400 and "S5" in r.json()["detail"] and "Отменить предпросмотр" in r.json()["detail"], r.text
    assert db.hub_defect(row["id"])["state"] == "preview" and create_ops(db) == []


@pytest.mark.parametrize("step", ["blank", "create"])
def test_team_name_is_reread_in_the_transaction(web, monkeypatch, step):
    """Название команды сменили в «Настройках» между проверкой до транзакции и постановкой (hub_defect_start у
    заготовки, hub_defect_advance у «Создать»): стандартная фраза текста – уже не фраза команды, транзакция читает
    название на своём соединении – отказ S2, ничего не поставлено."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url) if step == "create" else None
    method = "hub_defect_advance" if row else "hub_defect_start"
    original = getattr(db, method)

    def renamed_first(*args, **kwargs):
        db.set_settings({"team_name": "Другая команда"})  # другая вкладка сохранила «Настройки»
        return original(*args, **kwargs)

    monkeypatch.setattr(db, method, renamed_first)
    r = create(web, pid, row["id"]) if row else blank(web, url)
    assert r.status_code == 400 and r.json()["detail"].startswith("Текст не по требованиям команды: S2"), r.text
    if row:
        assert db.hub_defect(row["id"])["state"] == "preview" and create_ops(db) == []
    else:
        assert db.hub_defects(pid) == [] and db.hub_ops_list() == []


def test_refusals_without_script_are_error_pages(web):
    """Без скрипта отказ требованиями – страница ошибки 400 с тем же текстом: у «Подготовить дефект» и у «Создать»;
    ничего не поставлено."""
    pid, _ = sast_ready(web)
    db = web.app.state.db
    as_page = {**ORIGIN, "Accept": "text/html,application/xhtml+xml"}  # как у браузера без скрипта
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON,
                       "Параметризовать запрос.\nДобавить тест, подтверждающий исправление.")
    r = web.client.post(f"{url}/hub-defect", data=shown(web, url), headers=as_page, follow_redirects=False)
    assert r.status_code == 400 and "text/html" in r.headers["content-type"], r.text[:300]
    assert "Текст не по требованиям команды: S6" in r.text and "Поправьте решение в карточке" in r.text
    assert db.hub_defects(pid) == [] and db.hub_ops_list() == []
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row = to_preview(web, pid, url)
    db.hub_defect_update(row["id"], command_text=row["command_text"] + "\n2) Срок – 10 рабочих дней после разметки.")
    r = web.client.post(f"/projects/{pid}/hub/defects/{row['id']}/create", data={}, headers=as_page,
                        follow_redirects=False)
    assert r.status_code == 400 and "text/html" in r.headers["content-type"], r.text[:300]
    assert "Текст не по требованиям команды: S6" in r.text and "Отменить предпросмотр" in r.text
    assert db.hub_defect(row["id"])["state"] == "preview" and create_ops(db) == []


def test_panel_does_not_quote_a_hidden_body(web):
    """Полный текст скрыт (обоснование – текст модели к другому вердикту): перечня нарушений нет – он цитировал бы
    строки скрытого текста; своё обоснование с тем же нарушением – перечень виден."""
    from test_audit_lta001b import HUB_ID
    from test_r092_hub_text import bind_verdict
    pid = prepared(web)
    comment = "Ложное срабатывание: входные данные ограничены допустимым набором."
    bind_verdict(web, pid, "false_positive", comment, "Не требуется.")
    violating = "Параметризовать запрос.\nДобавить тест, подтверждающий исправление."
    url, _ = save_sast(web, pid, HUB_ID, "disagree", "true_positive", comment, fix=violating)
    card = web.client.get(url).text
    assert 'id="defect-body-hidden"' in card and 'id="defect-form-problems"' not in card
    save_sast(web, pid, HUB_ID, "disagree", "true_positive", "Значение приходит из параметра запроса без проверки.",
              fix=violating)
    card = web.client.get(url).text
    assert 'id="defect-body-hidden"' not in card and 'id="defect-form-problems"' in card and "S6" in card


def test_sca_create_refuses_when_the_set_is_no_longer_ready_by_date(web, monkeypatch):
    """Цель набора – из решения по компоненту со сроком пересмотра (ADR-0091 п. 14). После предпросмотра срок истёк
    (подмена «сегодня»): отпечаток набора тот же (дата в него не входит), а набор уже не готов и цели нет – «Создать»
    отказывает «Набор SCA изменился…» до проверки формы (не нарушением строки обновления), POST не поставлен."""
    from app.routes import hub_defect_routes
    from app.routes import sca as sca_card
    pid, url = sca_ready(web)
    db = web.app.state.db
    research_ref = db.sca_snapshot(pid, "73001")._state["research_ref"]
    with db._tx() as c:  # цель – не ручная, а из решения по компоненту (пересмотр 01.11.2026)
        c.execute("UPDATE sca_package_texts SET target_basis = '' WHERE project_id = ?", (pid,))
        c.execute("INSERT INTO sca2_decisions(project_id, input_ref, revision, action, rationale, target_version,"
                  " review_at, state, decided_at) VALUES (?, ?, 1, 'update', 'Обновить до проверенной версии.',"
                  " '9.9.9', '2026-11-01', 'current', '2026-10-27T10:00:00+00:00')", (pid, research_ref))
    monkeypatch.setattr(sca_card, "now_iso", lambda: "2026-10-28T10:00:00+00:00")
    card = web.client.get(url).text
    assert 'id="defect-form-problems"' not in card
    assert blank(web, url).status_code == 200
    hub_job(web, body={**BLANK, "linkedIssues": []})
    hub_job(web, body=SERVICE)
    row = db.hub_defects(pid)[0]
    assert row["state"] == "preview" and "до версии 9.9.9" in row["command_text"]
    monkeypatch.setattr(sca_card, "now_iso", lambda: "2026-11-02T10:00:00+00:00")  # срок пересмотра истёк
    assert db.sca_snapshot(pid, "73001").fingerprint == row["source_fingerprint"]
    r = create(web, pid, row["id"])
    assert r.status_code == 400 and r.json()["detail"] == hub_defect_routes.SCA_CHANGED, r.text
    assert db.hub_defect(row["id"])["state"] == "preview" and create_ops(db) == []


def test_sca_update_line_with_a_continuation_is_an_operator_addition():
    """Круг 2 (D4): строка оператора «Обновление <компонент набора> до версии 2.0 потребует миграции API.» – добавление
    оператора, не вторая строка обновления: в режиме обновления и в режиме «Исправленной версии нет» нарушений нет."""
    note = f"Обновление {COMPONENT} до версии 2.0 потребует миграции API."
    upd = sca(recommendations=(note, f"Обновление {COMPONENT} до версии 1.2.7"))
    assert check_sca(upd) == [], check_sca(upd)
    nofix = sca(recommendations=(note, "Ограничить приём входных данных на шлюзе."))
    assert check_sca(nofix, target="", no_fix=True) == []


def test_sca_create_refuses_when_the_body_by_snapshot_differs(web, monkeypatch):
    """Круг 2 (D2): после предпросмотра цель набора сменилась (например, истёк срок пересмотра решения по компоненту и
    цель взята из исследования), набор готов, отпечаток тот же – тело по снимку отличается от сохранённого текста:
    «Создать» отказывает «Набор SCA изменился…», а не нарушением строки обновления; POST не поставлен."""
    from app.routes import hub_defect_routes
    from app.routes import sca as sca_card
    pid, url = sca_ready(web)
    db = web.app.state.db
    assert blank(web, url).status_code == 200
    hub_job(web, body={**BLANK, "linkedIssues": []})
    hub_job(web, body=SERVICE)
    row = db.hub_defects(pid)[0]
    assert row["state"] == "preview"
    real = sca_card.sca_defect

    def other_target(*args, **kwargs):
        view = real(*args, **kwargs)
        return {**view, "body": str(view.get("body") or "") + "\nЦель по исследованию: другая версия."}

    monkeypatch.setattr(sca_card, "sca_defect", other_target)
    r = create(web, pid, row["id"])
    assert r.status_code == 400 and r.json()["detail"] == hub_defect_routes.SCA_CHANGED, r.text
    assert db.hub_defect(row["id"])["state"] == "preview" and create_ops(db) == []

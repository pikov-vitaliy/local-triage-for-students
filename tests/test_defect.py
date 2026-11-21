"""Текст дефекта для Hub: заголовок и тело SAST и SCA в принятом формате (docs/hub-format.md), номер дефекта
по счётчику проекта, кнопки в карточках."""

from __future__ import annotations

import re

import pytest
import time
from pathlib import Path

from app import defect
from app.models import Finding
from feed_fixtures import bdu_zip, cwe_zip
from test_sca import AS_JSON, answer, answers_json, form_fields, post_answers, sca_card, shown_fields
from test_web import ORIGIN, hidden_fields, prepared, start_run, wait_run, web  # noqa: F401

CATALOG = {"CWE-89": {"id": "CWE-89", "name": "Improper Neutralization of Special Elements used in an SQL Command",
                      "name_ru": "Внедрение SQL-кода", "description": "The product constructs an SQL command."}}


def sast(**fields) -> Finding:
    base = {"hub_id": "510001", "kind": "SAST", "rule": "Внедрение SQL-кода", "cwe": ["CWE-89"],
            "file": "src/InvoiceDao.java", "line": 58}
    return Finding.from_dict({**base, **fields})


# ============================================================================ SAST

def test_sast_title_and_true_positive_body():
    """Формат 0.9.6 (ADR-0089): стандартная фраза, «Обоснование:», «Рекомендация:» по пунктам «1)» – и ничего больше."""
    assert defect.sast_title(38, sast(rule="Изменение произвольных файлов")) == (
        "ID38 - Изменение произвольных файлов (SAST)")
    fix = ("Используйте `PreparedStatement` вместо склейки строк.\n```java\nps.setString(1, owner);\n```\n"
           "Проверьте другие запросы DAO.")
    body = defect.sast_body(sast(), "true_positive", "Подтверждено: owner из запроса попадает в SQL (строка 58).",
                            fix, "Платформа")
    assert body == (
        "После тщательного анализа уязвимости команда Платформа приняла решение присвоить данной уязвимости "
        "категорию True Positive.\n\n"
        "Обоснование:\n"
        "Подтверждено: owner из запроса попадает в SQL (строка 58).\n\n"  # как написал оператор (ADR-0149)
        "Рекомендация:\n"
        "1) Используйте `PreparedStatement` вместо склейки строк.\n"
        "2) Проверьте другие запросы DAO.")  # пример кода в Hub не идёт – только меры словами (ADR-0098)
    for absent in ("Итог:", "Область:", "ГОСТ", "Требуется от разработчика", "Добавить тест", "Справочно", "Срок"):
        assert absent not in body, absent


def test_sast_body_only_for_true_positive_and_only_with_operator_recommendation():
    with pytest.raises(ValueError):
        defect.sast_body(sast(), "false_positive", "Значение приводится к числу.", "", "Платформа")
    # без своей рекомендации текста нет (ADR-0092): общий пункт и код модели не подставляются
    for empty in ("", "   ", "- ", "```java\nint x;\n```", "    query.bind(1, x);"):
        with pytest.raises(ValueError):
            defect.sast_body(sast(), "true_positive", "x", empty, "Платформа")
    body = defect.sast_body(sast(), "true_positive", "x", "Параметризовать запрос.", "")
    assert body.startswith("После тщательного анализа уязвимости команда приняла решение присвоить данной уязвимости")
    assert body.endswith("Рекомендация:\n1) Параметризовать запрос.")


def test_recommendation_points_take_words_not_code():
    points, dropped = defect.recommendation_points(
        "1. Использовать PreparedStatement.\n2) Белый список для имени колонки.\n```java\nps.setString(1, x);\n```\n"
        "~~~\nraw();\n~~~\n    indented();\n- Для имени функции – перечисление.")
    assert points == ["Использовать PreparedStatement.", "Белый список для имени колонки.",
                      "Для имени функции – перечисление."]
    assert dropped
    assert defect.recommendation_points("```java\nint x;") == ([], True), "незакрытая ограда – код до конца"
    # ограда закрывается только теми же знаками не короче открывающей
    assert defect.recommendation_points("```\na();\n~~~\nquery();\n```")[0] == []
    assert defect.recommendation_points("````\na();\n```\nquery();\n````\nСлово.")[0] == ["Слово."]
    assert not defect.has_recommendation("```\nx\n~~~\nquery();")
    assert defect.recommendation_points("Обновить драйвер.") == (["Обновить драйвер."], False)
    assert not defect.has_recommendation("1)\n2) ;")


def test_sast_comment_is_operator_reason_only():
    text = defect.sast_comment(sast(), "false_positive", "  Ложное срабатывание: имя таблицы " + chr(0x2014)
                               + " из заранее заданной строки.  ")
    # как написал оператор (ADR-0149): вводное слово, длинное тире и отступ остаются, срезаны только хвостовые пробелы
    assert text == "  Ложное срабатывание: имя таблицы " + chr(0x2014) + " из заранее заданной строки."
    assert defect.sast_comment(sast(), "false_positive", "имя таблицы задано.") == "Имя таблицы задано."  # ADR-0101
    assert defect.sast_comment(sast(), "false_positive", "Ложное срабатывание:") == ""  # обоснования нет


def test_recommendations_split_lists_and_paragraphs():
    assert defect.recommendations("1. Первое\n2. Второе\n\nТретье\nпродолжение") == [
        "Первое", "Второе", "Третье продолжение"]
    assert defect.recommendations("- пункт <b>жирный</b>\n* второй") == ["пункт жирный", "второй"]
    assert defect.recommendations("") == []


# ============================================================================ SCA

def sca_row(hub_id: str, vuln: str, fixed: str = "", cvss: float | None = 9.8, cwe=("CWE-94",)) -> Finding:
    return Finding.from_dict({"hub_id": hub_id, "kind": "SCA", "component": "lodash", "version": "4.17.21",
                              "policy_severity": "Critical", "vuln_ids": [vuln] if vuln.startswith("AST") else [],
                              "cve": [vuln] if vuln.startswith("CVE") else [], "fixed_version": fixed, "cvss": cvss,
                              "cwe": list(cwe)})


def test_sca_title_and_hub_format_sample_match_the_generator():
    """Заголовок дефекта SCA и образец в docs/hub-format.md – строка в строку то, что собирает sca_text.body
    (прежний сборщик сводки и блоков удалён в 0.9.13 – хвост DEAD-01б)."""
    assert defect.sca_title(1, "lodash", "4.17.21") == "ID1 - lodash | Component version: 4.17.21 (SCA)"
    # docs/hub-format.md описывает формат 0.9.8 (ADR-0091, ADR-0094): образец – строка в строку то, что собирает
    # sca_text.body для смешанного эталона; прежний формат (сводка и блоки) в документе больше не показывается
    from app import sca_text
    sample = (Path(__file__).resolve().parent.parent / "docs" / "hub-format.md").read_text(encoding="utf-8")
    assert "Сводка по уязвимостям:\nID      Компонент" not in sample
    etalon = sca_text.body(
        "org.example:example-parser",
        [sca_text.Vuln(ids=["CVE-2099-1001"], hub_members=["1"]), sca_text.Vuln(ids=["GHSA-nnnn-oooo-ffff"])],
        "CVE-2099-1001: Уязвимость разбора позволяет выполнить код при подстановке параметров запроса.\n"
        "GHSA-nnnn-oooo-ffff: Разбор файла сертификата без ограничения размера ведёт к отказу в обслуживании.",
        "1.5.0", ["https://github.com/example/driver/security/advisories/GHSA-nnnn-oooo-ffff"],
        residual_lines=["Исправления нет ни в одной опубликованной версии на 2026-10-20 (github.com): "
                        "GHSA-nnnn-oooo-ffff (низкая) – обновление до 1.5.0 её не закрывает."],
        recommendation_note="Перед обновлением проверить совместимость с Java 17.")
    block = sample.split("исправления нет; вторая найдена исследованием, а не Hub):\n\n```\n",
                         1)[1].split("```", 1)[0]
    assert block.strip() == etalon.strip(), "образец SCA в hub-format.md разошёлся с генератором"


# ============================================================================ в карточках

def save_sast(web, pid: int, hub_id: str, decision: str, verdict: str, comment: str,
              fix: str = "Параметризовать запрос.", **extra) -> tuple[str, dict]:
    """Решение SAST формой карточки. fix – рекомендация оператора: у подтверждённого дефекта она обязательна
    (ADR-0092), у остальных исходов сервер её не сохраняет. extra – другие поля формы (например, defect_confirm="1" –
    смена решения находки в дефекте, созданном в Hub, ADR-0121)."""
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, hub_id)["id"]
    url = f"/projects/{pid}/findings/{fid}"
    card = web.client.get(url).text
    r = web.client.post(f"{url}/review", headers={**ORIGIN, "Accept": "application/json"}, data={
        **hidden_fields(card), "review_revision": re.search(r'name="review_revision" value="(\d+)"', card).group(1),
        "decision": decision, "final_verdict": verdict, "comment": comment, "fix": fix, "reviewed": "1",
        "action": "save", **extra})
    assert r.status_code == 200, r.text
    return url, r.json()


def test_sast_card_defect_panel_and_numbers(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    url = f"/projects/{pid}/findings/{fid}"
    card = web.client.get(url).text
    assert 'id="defect-panel" aria-labelledby="defect-title" hidden' in card
    r = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": ""})
    assert r.status_code == 409 and "Подтверждаю дефект" in r.json()["detail"]
    url, saved = save_sast(web, pid, "510001", "true_positive", "", "Подтверждено: owner из запроса.")
    assert saved["defect_ready"] is True
    card = web.client.get(url).text
    assert 'id="defect-panel" aria-labelledby="defect-title">' in card and 'id="defect-number" value="1"' in card
    answer_json = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "", "part": "title"}).json()
    assert answer_json["title"] == "ID1 - Внедрение SQL-кода (SAST)" and answer_json["number"] == 1
    assert answer_json["body"].startswith("После тщательного анализа уязвимости команда Платформа приняла решение "
                                          "присвоить данной уязвимости категорию True Positive.\n\nОбоснование:\n"
                                          "Подтверждено: owner из запроса.\n\nРекомендация:\n1) ")  # ADR-0149
    # ложное срабатывание – без дефекта
    url_fp, fp = save_sast(web, pid, "510003", "false_positive", "", "Вывод экранируется.")
    assert fp["defect_ready"] is False
    # следующая находка получает следующий номер; тот же номер – с предупреждением
    url2, _ = save_sast(web, pid, "510002", "true_positive", "", "Вывод не экранируется.")
    assert 'id="defect-number" value="2"' in web.client.get(url2).text
    # чужой номер – предупреждение до записи (Б9): номер не сохраняется без подтверждения
    warned = web.client.post(f"{url2}/defect", headers=AS_JSON, data={"number": "ID1"})
    assert warned.status_code == 409 and warned.json()["reason"] == "confirm", warned.text
    assert "Номер уже дан ещё 1" in warned.json()["detail"]
    assert db.defect_number(pid, "sast:510002") is None
    dup = web.client.post(f"{url2}/defect", headers=AS_JSON, data={"number": "ID1", "confirm": "1"}).json()
    assert dup["title"].startswith("ID1 - ") and "уже дан ещё 1 находке" in dup["note"]
    assert web.client.post(f"{url2}/defect", headers=AS_JSON, data={"number": "0"}).status_code == 400
    # без скрипта – номер сохраняется, карточка показывает текст
    r = web.client.post(f"{url}/defect", headers=ORIGIN, data={"number": "7"}, follow_redirects=False)
    assert r.status_code == 303 and "ok=defect_saved" in r.headers["location"]
    card = web.client.get(url).text
    assert "ID7 - Внедрение SQL-кода (SAST)" in card and "Номер сохранён для этой находки" in card
    # «Отложить» – дефекта нет
    _, later = save_sast(web, pid, "510001", "later", "", "Позже.")
    assert later["defect_ready"] is False
    assert 'id="defect-panel" aria-labelledby="defect-title" hidden' in web.client.get(url).text


def test_sast_card_shows_cwe_class_from_catalog(web, tmp_path: Path):
    pid = prepared(web)
    web.app.state.feeds.load("cwe", cwe_zip(tmp_path / "c.zip"), "c.zip")
    fid = web.app.state.db.get_finding_by_hub_id(pid, "510001")["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert 'id="cwe-info"' in card and "Improper Neutralization" in card


def package_text(web, url: str, **fields) -> dict:
    """Текст набора дефекта SCA (ADR-0091): Объяснение, версия вручную, отметки «Версию проверил сам»/«Текст проверен»."""
    card = web.client.get(url).text
    revision = re.search(r'name="text_revision" value="(\d+)"', card)
    data = {"text_revision": revision.group(1) if revision else "0", **shown_fields(card), **fields}
    r = web.client.post(f"{url}/package-text", headers=AS_JSON, data=data)
    assert r.status_code == 200, r.text
    return r.json()


def test_sca_card_defect_with_bdu(web, tmp_path: Path):
    """Дефект SCA по шаблону команды (ADR-0091): Описание – CVE со ссылкой NVD, Объяснение – по-русски из БДУ,
    Рекомендации – версия из ответа агента после отметки «Версию проверил сам» (исследования нет), Источники; без
    заключения по ГОСТ, сводки Hub и блоков по находкам."""
    pid = prepared(web)
    web.app.state.feeds.load("bdu", bdu_zip(tmp_path / "v.zip"), "v.zip")
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    assert 'id="bdu-records"' in card and "BDU:2099-00001" in card
    url = f"/projects/{pid}/sca/findings/{fid}"
    saved = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "agree", "final_verdict": "true_positive", "reviewed": "1",
        "comment": "Обновить до 1.4.9.", "action": "save"}).json()
    assert saved["defect_ready"] is False, "версия из ответа агента без исследования не проверена"
    refused = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "3"})
    assert refused.status_code == 409 and "не проверена" in refused.json()["detail"], refused.text
    first = package_text(web, url, version_checked="1")
    assert first["ready"] is False and "утвердите" in first["hint"], "подставленное Объяснение оператор утверждает сам (dev26)"
    done = package_text(web, url, explanation=first["explanation_draft"], version_checked="1")
    assert done["ready"] is True, done
    got = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "3"}).json()
    assert got["title"] == "ID3 - example-parser | Component version: 1.4.2 (SCA)"
    body = got["body"]
    assert body.startswith("Описание\nCVE-2099-10002 (https://nvd.nist.gov/vuln/detail/CVE-2099-10002)\n")
    assert "\nОбъяснение\nCVE-2099-10002: Уязвимость функции разбора" in body
    assert "\nРекомендации\nОбновление example-parser до версии 1.4.9\n" in body
    assert "\nИсточники\nhttps://nvd.nist.gov/vuln/detail/CVE-2099-10002" in body
    for banned in ("Заключение", "ГОСТ", "Сводка", "73001", "безопасн", "или новее", "javascript"):
        assert banned not in body, banned
    # по 73002 решения ещё нет – в дефект она не входит, и это сказано явно
    assert "73002 – решения нет" in got["note"]
    other_fid, other = sca_card(web, pid, "73002")
    other_url = f"/projects/{pid}/sca/findings/{other_fid}"
    web.client.post(f"{other_url}/review", headers=AS_JSON, data={
        **form_fields(other), "decision": "agree", "final_verdict": "true_positive", "reviewed": "1",
        "comment": "Обновить до 1.4.9.", "action": "save"})
    # состав набора изменился: в Описании и Объяснении теперь и CVE-2099-10001 у 73002 – её строка из БДУ
    view = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "3"})
    # строка новой CVE в Объяснении – предупреждение, не запрет (ADR-0152); выдачу держит отметка версии: текст набора
    # изменился, и «Версию проверил сам» относится к прежнему
    assert view.status_code == 409 and "не проверена" in view.json()["detail"], view.text
    assert "CVE-2099-10001" not in view.json()["detail"]
    draft = package_text(web, url, explanation="", version_checked="1")["explanation_draft"]
    assert package_text(web, url, explanation=draft, version_checked="1")["ready"] is True
    view = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "3"})
    assert view.status_code == 200, view.text
    body = view.json()["body"]
    assert "CVE-2099-10001 (https://nvd.nist.gov/vuln/detail/CVE-2099-10001)" in body and view.json()["note"] == ""
    # номер набора – общий для его находок
    _, other = sca_card(web, pid, "73002")
    assert 'id="defect-number" value="3"' in other


def test_defect_number_counter(web):
    pid = prepared(web)
    db = web.app.state.db
    assert db.next_defect_number(pid) == 1 and db.defect_number(pid, "sast:1") is None
    assert db.set_defect_number(pid, "sast:1", 5) == []
    assert db.next_defect_number(pid) == 6 and db.set_defect_number(pid, "sca:a@1", 5) == ["sast:1"]
    time.sleep(0)


def test_sca_card_shows_every_cwe_of_the_library(web, tmp_path: Path):
    """Карточка SCA показывает классы CWE всех находок библиотеки (а не только этой) с описанием; кавычки,
    экранированные в выгрузке БДУ (\\"…\\"), выводятся обычными."""
    from feed_fixtures import BDU_XML
    pid = prepared(web)
    escaped = BDU_XML.replace("Неправильное ограничение ссылок на внешние сущности XML",
                              'Ограничение ссылок (атаки типа \\"внешние сущности XML\\")')
    web.app.state.feeds.load("bdu", bdu_zip(tmp_path / "v.zip", escaped), "v.zip")
    web.app.state.feeds.load("cwe", cwe_zip(tmp_path / "c.zip"), "c.zip")
    _, card = sca_card(web, pid, "73001")             # у 73001 – CWE-1333 и 400, у соседней 73002 – CWE-611
    info = card[card.index('id="cwe-info"'):card.index("</dl>", card.index('id="cwe-info"'))]
    assert "CWE-1333" in info and "CWE-611" in info
    assert "Классы уязвимостей библиотеки" in card and "эта находка" in info
    assert "The product uses a regular expression" in info                    # описание из каталога CWE
    assert "(атаки типа &#34;внешние сущности XML&#34;)" in info or '(атаки типа "внешние сущности XML")' in info
    assert "\&#34;" not in info and '\\"' not in info
    _, other = sca_card(web, pid, "73002")            # своя CWE-611 – первой, затем CWE соседней находки
    block = other[other.index('id="cwe-info"'):]
    assert block.index("CWE-611") < block.index("CWE-1333")


def test_sast_risk_accepted_and_uncertain_rejected(web):
    """У SAST два исхода (ADR-0089): «Риск принят» и итог «неясно» не сохраняются, прежнее решение – просьба выбрать
    заново."""
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    url = f"/projects/{pid}/findings/{fid}"
    card = web.client.get(url).text
    for decision, verdict in (("risk_accepted", ""), ("disagree", "uncertain")):
        r = web.client.post(f"{url}/review", headers={**ORIGIN, "Accept": "application/json"}, data={
            **hidden_fields(card), "review_revision": re.search(r'name="review_revision" value="(\d+)"', card).group(1),
            "decision": decision, "final_verdict": verdict, "comment": "x", "action": "save"})
        assert r.status_code == 400 and "два решения" in r.json()["detail"], r.text
    db.save_review(pid, "510001", decision="risk_accepted", final_verdict="", final_comment="до релиза",
                   reviewed=False)
    card = web.client.get(url).text
    assert 'id="legacy-outcome"' in card and "Выберите решение заново" in card
    assert 'value="false_positive" form="review-form">' in card and 'value="true_positive" form="review-form">' in card


def test_sast_comment_required_and_copy_only_for_false_positive(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    url = f"/projects/{pid}/findings/{fid}"
    card = web.client.get(url).text
    base = {**hidden_fields(card), "review_revision": re.search(r'name="review_revision" value="(\d+)"', card).group(1)}
    headers = {**ORIGIN, "Accept": "application/json"}
    r = web.client.post(f"{url}/review", headers=headers, data={**base, "decision": "false_positive", "comment": " ",
                                                                 "action": "save"})
    assert r.status_code == 400 and "почему срабатывание ложное" in r.json()["detail"]
    r = web.client.post(f"{url}/review", headers=headers, data={**base, "decision": "true_positive", "comment": "x",
                                                                 "fix": "Параметризовать запрос.", "action": "copy"})
    assert r.status_code == 400 and "только при решении «Ложное срабатывание»" in r.json()["detail"]
    r = web.client.post(f"{url}/review", headers=headers, data={
        **base, "decision": "false_positive", "action": "copy",
        "comment": "Имя таблицы берётся из заранее заданной строки, поэтому SQL-инъекция исключена."})
    assert r.status_code == 200 and r.json()["hub_text"] == ("Имя таблицы берётся из заранее заданной строки, поэтому "
                                                             "SQL-инъекция исключена.")
    assert r.json()["defect_ready"] is False


def test_sast_own_recommendation_goes_to_defect(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    url = f"/projects/{pid}/findings/{fid}"
    card = web.client.get(url).text
    r = web.client.post(f"{url}/review", headers={**ORIGIN, "Accept": "application/json"}, data={
        **hidden_fields(card), "review_revision": re.search(r'name="review_revision" value="(\d+)"', card).group(1),
        "decision": "true_positive", "comment": "owner из запроса склеивается в SQL.", "action": "save",
        "fix": "Использовать PreparedStatement.\nДля имени таблицы – белый список."})
    assert r.status_code == 200, r.text
    assert db.get_review(pid, "510001")["final_fix"].startswith("Использовать PreparedStatement.")
    body = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": ""}).json()["body"]
    assert body.endswith("Рекомендация:\n1) Использовать PreparedStatement.\n2) Для имени таблицы – белый список.")


def test_sca_group_with_different_kapo_states_does_not_block_the_defect(web):
    """Уточнение по ГОСТ Р КАПО – внутреннее поле решения (ADR-0091 п. 3): разные уточнения у находок набора выдачу не
    блокируют и в текст не попадают."""
    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    for hub_id, kapo in (("73001", "actual"), ("73002", "not_finished")):
        fid, card = sca_card(web, pid, hub_id)
        r = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=AS_JSON, data={
            **form_fields(card), "decision": "disagree", "final_verdict": "true_positive", "reviewed": "1",
            "comment": "Обновить до 1.4.9.", "kapo_state": kapo, "action": "save"})
        assert r.status_code == 200, r.text
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    package_text(web, url, target_version="1.4.9")
    done = package_text(web, url, explanation="CVE-2099-10002: Уязвимость функции разбора документа позволяет "
                        "прочитать файлы сервера.\nCVE-2099-10001: Уязвимость разбора вложенных сущностей вызывает "
                        "отказ в обслуживании.", target_version="1.4.9", version_checked="1")
    assert done["ready"], done
    got = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "3"})
    assert got.status_code == 200, got.text
    assert "ГОСТ" not in got.json()["body"] and "КАПО" not in got.json()["body"]


def test_sca_defect_fingerprint_follows_export_label(tmp_path):
    from app.db import Database, StaleReview
    from app.triage import order_findings
    db = Database(tmp_path / "t.db")
    pid = db.create_project("p")
    rows = [Finding.from_dict({"hub_id": "1", "kind": "SCA", "component": "lodash", "version": "4.17.20",
                               "cve": ["CVE-2021-23337"]})]
    db.save_import(pid, "AppSec.Hub_issue_report_15_10_2026.xlsx", "xlsx", [], {}, [], order_findings(rows))
    db.save_review(pid, "1", decision="disagree", final_verdict="true_positive", final_comment="x", reviewed=False,
                   kapo_state="not_finished")
    key = defect.defect_key_sca("lodash", "4.17.20")
    snap = db.sca_snapshot(pid, "1")
    # повторная загрузка с той же подписью выгрузки выдачу не отклоняет
    db.save_import(pid, "AppSec.Hub_issue_report_15_10_2026_21-00.xlsx", "xlsx", [], {}, [], order_findings(rows))
    assert db.set_sca_defect_number_checked(pid, key, 1, "1", snap.fingerprint) == []
    snap = db.sca_snapshot(pid, "1")
    db.save_import(pid, "AppSec.Hub_issue_report_19_10_2026.xlsx", "xlsx", [], {}, [], order_findings(rows))
    with pytest.raises(StaleReview):
        db.set_sca_defect_number_checked(pid, key, 2, "1", snap.fingerprint)
    db.close()



def test_bar_full_text_button_submits_defect_form_without_script(web):
    """Нижняя кнопка полного текста – кнопка отправки формы дефекта: без скрипта она тоже работает."""
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    url, _ = save_sast(web, pid, "510001", "true_positive", "", "Подтверждено: owner из запроса.")
    card = web.client.get(url).text
    assert re.search(r'<button type="submit" form="defect-form" name="part" value="body" class="btn btn-primary" '
                     r'id="copy-defect-bar"', card)
    r = web.client.post(f"{url}/defect", headers=ORIGIN, data={"number": "", "part": "body"}, follow_redirects=False)
    assert r.status_code == 303

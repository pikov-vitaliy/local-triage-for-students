"""Шаги 9–10 выпуска 0.9.11 (ADR-0101): первая буква обоснования SAST – заглавная (Р9);
отметки по прежнему тексту – «формат обновился»; предупреждение о длине комментария для Hub (Р8) – разметка. Данные
выдуманы."""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from app import defect
from app.db import text_hash
from app.routes import findings as routes
from test_defect import save_sast, sast
from test_sca import sca_card
from test_web import prepared, web  # noqa: F401


@pytest.mark.parametrize("comment, expected, legacy", [
    ("строка 26 формирует запрос из ввода.", "Строка 26 формирует запрос из ввода.", "Строка 26 формирует запрос из ввода."),
    # с 0.10.0.dev21 вводное слово остаётся (ADR-0149); прежний формат 0.9.11–0.10.0.dev20 его снимал
    ("Подтверждено: имя пользователя вставляется в HTML.", "Подтверждено: имя пользователя вставляется в HTML.",
     "Имя пользователя вставляется в HTML."),
    ("подтверждено: имя вставляется в HTML.", "Подтверждено: имя вставляется в HTML.", "Имя вставляется в HTML."),
    ("ёлочки в имени файла не экранируются.", "Ёлочки в имени файла не экранируются.", "Ёлочки в имени файла не экранируются."),
    ("owner из запроса попадает в SQL.", "owner из запроса попадает в SQL.", "owner из запроса попадает в SQL."),
    ("Ложное срабатывание:", "", ""),
    ("", "", ""),
])
def test_sast_reason_capitalizes_only_a_cyrillic_first_letter(comment, expected, legacy):
    assert defect.sast_reason(comment) == expected
    assert defect.sast_reason(comment, legacy=True) == legacy


def test_body_comment_and_group_text_use_the_same_reason():
    f = sast()
    body = defect.sast_body(f, "true_positive", "метод findByStatus уязвим к SQL-инъекции.", "1) Параметризовать.",
                            "Платформа")
    assert "Обоснование:\nМетод findByStatus уязвим к SQL-инъекции.\n" in body
    assert defect.sast_comment(f, "false_positive", "запрос параметризован.") == "Запрос параметризован."
    assert defect.sast_effective("false_positive", "запрос параметризован.", "")[1] == "Запрос параметризован."
    assert defect.sast_comment_v3(f, "false_positive", "запрос параметризован.") == "запрос параметризован."


def test_entered_before_0911_names_the_capital_letter_reason(monkeypatch):
    settings = SimpleNamespace(team_name="Платформа", hub_status_map={})
    tp = {"decision": "disagree", "final_verdict": "true_positive", "final_comment": "строка 26 формирует запрос.",
          "final_fix": "1) Параметризовать запрос."}
    monkeypatch.setattr(routes, "__version__", "0.9.10")
    tp["entered_parts"] = routes.entered_parts(settings, tp)
    monkeypatch.setattr(routes, "__version__", "0.9.11")
    reasons = routes.entered_change_reasons(settings, tp)
    assert len(reasons) == 1 and "первая буква обоснования теперь заглавная" in reasons[0], reasons
    latin = {**tp, "final_comment": "owner из запроса попадает в SQL."}
    monkeypatch.setattr(routes, "__version__", "0.9.10")
    latin["entered_parts"] = routes.entered_parts(settings, latin)
    monkeypatch.setattr(routes, "__version__", "0.9.11")
    assert "формат текста" in routes.entered_change_reasons(settings, latin)[0]


def test_reasons_combine_capital_letter_and_marker(monkeypatch):
    """Отметка 0.9.10: строчная буква и «2)мера» – обе причины названы, пример кода – нет."""
    settings = SimpleNamespace(team_name="Платформа", hub_status_map={})
    tp = {"decision": "disagree", "final_verdict": "true_positive", "final_comment": "строка 26 формирует запрос.",
          "final_fix": "1) Параметризовать запрос.\n2)Проверить другие запросы.\n```\nx();\n```"}
    monkeypatch.setattr(routes, "__version__", "0.9.10")
    tp["entered_parts"] = routes.entered_parts(settings, tp)
    monkeypatch.setattr(routes, "__version__", "0.9.11")
    reasons = routes.entered_change_reasons(settings, tp)
    assert len(reasons) == 2, reasons
    assert "первая буква" in reasons[0] and "маркер пункта" in reasons[1]


def test_card_shows_format_updated_for_marks_on_the_old_text(web):  # noqa: F811
    """Отметка «Внесено в Hub» по тексту 0.9.6–0.9.10 (строчная буква): «формат обновился», а не «текст изменился»."""
    pid = prepared(web)
    db = web.app.state.db
    save_sast(web, pid, "510001", "disagree", "false_positive", "имя таблицы берётся из заранее заданной строки.")
    review = db.get_review(pid, "510001")
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    url = f"/projects/{pid}/findings/{fid}"
    old_text = "имя таблицы берётся из заранее заданной строки."  # буквально прежний формат, не из кода
    db.mark_entered(pid, "510001", True, review["revision"], text_hash(old_text))
    page = web.client.get(url).text
    assert 'id="entered-format-updated"' in page and 'id="entered-changed"' not in page
    db.mark_entered(pid, "510001", True, review["revision"], text_hash("Имя таблицы берётся из заранее заданной строки."))
    page = web.client.get(url).text
    assert 'id="entered-format-updated"' not in page and 'id="entered-changed"' not in page


def test_old_defect_body_with_dash_and_marker_is_recognized_as_format_update(web):  # noqa: F811
    """Отметка по телу дефекта 0.9.10: строчная буква, длинное тире (в тексте для Hub – короткое) и «2)мера» без
    пробела – «формат обновился», хеш – по буквальному прежнему тексту."""
    pid = prepared(web)
    db = web.app.state.db
    save_sast(web, pid, "510001", "disagree", "true_positive", "строка " + chr(0x2014) + " источник ошибки.",
              fix="1) Параметризовать запрос.\n2)Проверить другие запросы.")
    review = db.get_review(pid, "510001")
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    old_body = ("После тщательного анализа уязвимости команда Тестовая команда приняла решение присвоить данной "
                "уязвимости категорию True Positive.\n\nОбоснование:\nстрока – источник ошибки.\n\nРекомендация:\n"
                "1) Параметризовать запрос.\n2) 2)Проверить другие запросы.")
    db.mark_entered(pid, "510001", True, review["revision"], text_hash(old_body))
    page = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert 'id="entered-format-updated"' in page and 'id="entered-changed"' not in page


def test_sca_comment_field_carries_the_warning_threshold_and_prefix_length(web):  # noqa: F811
    pid = prepared(web)
    _, card = sca_card(web, pid, "73002")  # CVE-2099-10001 в example-parser 1.4.2
    field = re.search(r'<textarea[^>]*name="comment"[^>]*>', card).group(0)
    assert 'data-warn-at="250"' in field
    prefix = "CVE-2099-10001 в example-parser 1.4.2: "
    assert f'data-prefix-len="{len(prefix)}"' in field and 'data-prefix-ids="CVE-2099-10001"' in field, field

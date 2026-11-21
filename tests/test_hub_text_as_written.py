"""Тексты в Hub как написал оператор (0.10.0.dev21): приложение не вырезает теги и схемы, не
меняет тире, не срезает вводное «Подтверждено:», не схлопывает пустые строки. Остаются прежние правила:
заглавная первая буква обоснования SAST (ADR-0101 п. 7), в рекомендации – меры словами (ADR-0098), без номеров AST
и с приставкой короткого комментария SCA (ADR-0101 пп. 1–2). Прежние отметки узнаются по замороженным правилам.
Данные выдуманы."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app import defect, hub_defects, hub_status, sca, sca_text
from app.db import text_hash
from app.models import Finding
from app.routes import findings as routes
from test_defect import save_sast, sast
from test_web import prepared, web  # noqa: F401

DASH = chr(0x2014)
ZWSP = chr(0x200B)
TRICKY = [
    "Шаблон List<Object> из запроса не проверяется.",
    "Если a<b && c>d, ветка пропускает проверку.",
    "Значение <img src=x onerror=alert(1)> попадает в ответ.",
    "Строка javascript:void(0) и data: из параметра идут в ссылку.",
    f"Источник {DASH} параметр owner.",
    f"Невидимый{ZWSP}знак остаётся.",
]


@pytest.mark.parametrize("text", TRICKY)
def test_sast_comment_keeps_operator_words(text):
    assert defect.sast_comment(sast(), "false_positive", text) == text
    assert defect.sast_effective("false_positive", text, "")[1] == text


def test_sast_comment_keeps_the_verdict_word_blank_lines_and_capital_rule():
    text = "Подтверждено: имя таблицы задано в коде.\n\n\n\nВторой абзац."
    assert defect.sast_comment(sast(), "false_positive", text) == text
    assert defect.sast_comment(sast(), "false_positive", "ложное срабатывание: запрос параметризован.") == (
        "Ложное срабатывание: запрос параметризован.")  # заглавная буква – ADR-0101 п. 7
    # отступ первой строки – как написан, пустые строки по краям и хвостовые пробелы не уходят (ревью Kimi круга 3)
    assert defect.sast_comment(sast(), "false_positive", "\r\n  owner задан в коде.  \r\n") == "  owner задан в коде."
    assert defect.sast_comment(sast(), "false_positive", "\tстрока 26 задана.") == "\tСтрока 26 задана."
    # только вводное слово – обоснованием не считается (ADR-0089 п. 6): текста для Hub нет, как и раньше
    assert defect.reason_text("Ложное срабатывание:") == ""
    assert defect.sast_comment(sast(), "false_positive", "Ложное срабатывание:") == ""


def test_prior_format_is_frozen_for_recognition():
    text = f"Подтверждено: строка {DASH} <b>источник</b>.\n\n\n\nВторой абзац."
    assert defect.sast_comment_v4(sast(), "false_positive", text) == "Строка – источник.\n\nВторой абзац."
    assert defect.sast_comment_v3(sast(), "false_positive", "строка <b>источник</b>.") == "строка источник."
    assert defect.sast_reason(text, legacy=True) == f"Строка {DASH} источник.\n\n\n\nВторой абзац."


def test_sast_body_keeps_reason_and_operator_points_but_measures_only():
    fix = ("1) Используйте List<String> вместо сырого типа.\n2)Проверьте a<b && c>d.\n```java\nps.setString(1, x);\n"
           f"```\n- Замените {DASH} на параметр.")
    comment = "Подтверждено: owner из запроса <b>попадает</b> в SQL."
    body = defect.sast_body(sast(), "true_positive", comment, fix, "Платформа")
    assert f"Обоснование:\n{comment}\n\nРекомендация:\n" in body
    assert body.endswith("1) Используйте List<String> вместо сырого типа.\n2) Проверьте a<b && c>d.\n"
                         f"3) Замените {DASH} на параметр.")  # код и маркеры – по ADR-0098, слова – как написаны
    old = defect.sast_body(sast(), "true_positive", comment, fix, "Платформа", legacy_0911=True)
    assert "Обоснование:\nowner из запроса попадает в SQL.\n" in old  # прежний: вводное снято, теги вырезаны
    assert "2) Проверьте ad.\n3) Замените – на параметр." in old


def test_model_draft_points_keep_the_prior_cleaning():
    """Заготовка из ответа модели (кнопка «Взять пункты») – по прежним правилам: это не текст оператора."""
    assert defect.recommendation_points("1) Экранируйте <b>вывод</b>.", clean=True)[0] == ["Экранируйте вывод."]
    assert defect.recommendation_points("1) Экранируйте <b>вывод</b>.")[0] == ["Экранируйте <b>вывод</b>."]


def test_status_reason_is_a_plain_json_string_without_html_escaping():
    text = "Если a<b && c>d – \"кавычки\" и <img src=x> остаются."
    request = hub_status.status_request([{"issue_id": "1", "issue_type": "SAST"}], "False Positive",
                                        hub_status.clean_reason(text), "2026-12-01T00:00:00Z")
    assert request["body"]["reason"] == text
    assert json.loads(json.dumps(request["body"]))["reason"] == text
    assert "&lt;" not in json.dumps(request["body"], ensure_ascii=False)


def test_defect_description_html_escapes_the_operator_text():
    body = defect.sast_body(sast(), "true_positive", "Шаблон <img src=x onerror=alert(1)> и a<b && c>d.",
                            "Экранируйте вывод <b>.", "Платформа")
    html = hub_defects.command_html(body)
    assert "<img" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "a&lt;b &amp;&amp; c&gt;d" in html and "Экранируйте вывод &lt;b&gt;." in html
    assert html.count("<p>") == 3  # фраза команды, «Обоснование», «Рекомендация» – абзацами
    # прочитанное описание Hub совпадает с отправленным текстом (сверка подтверждения)
    assert hub_defects.description_matches(hub_defects.description_html(body, ""), body)


def test_sast_title_from_export_keeps_the_prior_cleaning():
    assert defect.sast_title(5, sast(rule=f"Правило {DASH} <b>SQL</b>")) == "ID5 - Правило – SQL (SAST)"


def test_entered_mark_on_prior_text_is_format_update_with_named_reason(monkeypatch):
    settings = SimpleNamespace(team_name="Платформа", hub_status_map={})
    fp = {"decision": "disagree", "final_verdict": "false_positive",
          "final_comment": "Ложное срабатывание: имя таблицы задано в коде."}
    monkeypatch.setattr(routes, "__version__", "0.10.0.dev20")
    fp["entered_parts"] = routes.entered_parts(settings, fp)
    monkeypatch.setattr(routes, "__version__", "0.10.0.dev21")
    reasons = routes.entered_change_reasons(settings, fp)
    assert len(reasons) == 1 and "как написан" in reasons[0], reasons
    plain = {**fp, "final_comment": "Имя таблицы задано в коде."}
    monkeypatch.setattr(routes, "__version__", "0.10.0.dev20")
    plain["entered_parts"] = routes.entered_parts(settings, plain)
    monkeypatch.setattr(routes, "__version__", "0.10.0.dev21")
    assert "формат текста" in routes.entered_change_reasons(settings, plain)[0]


def test_card_recognizes_marks_on_the_prior_format(web):  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    comment = "Ложное срабатывание: имя таблицы <b>задано</b> в коде."
    save_sast(web, pid, "510001", "disagree", "false_positive", comment)
    review = db.get_review(pid, "510001")
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    url = f"/projects/{pid}/findings/{fid}"
    db.mark_entered(pid, "510001", True, review["revision"], text_hash("Имя таблицы задано в коде."))
    page = web.client.get(url).text
    assert 'id="entered-format-updated"' in page and 'id="entered-changed"' not in page
    db.mark_entered(pid, "510001", True, review["revision"], text_hash(comment))  # текущий текст – как написан
    page = web.client.get(url).text
    assert 'id="entered-format-updated"' not in page and 'id="entered-changed"' not in page


def test_rules_page_lists_changed_decisions_and_writes_nothing(web):  # noqa: F811
    """Страница масштаба – только чтение: ни решения, ни операции Hub, ни проект не меняются."""
    pid = prepared(web)
    db = web.app.state.db
    save_sast(web, pid, "510001", "disagree", "false_positive", "Ложное срабатывание: имя таблицы задано в коде.")
    review = db.get_review(pid, "510001")
    db.mark_entered(pid, "510001", True, review["revision"], text_hash("Имя таблицы задано в коде."))

    def snapshot():
        return [db._all("SELECT * FROM reviews WHERE project_id = ? ORDER BY hub_id", (pid,)),
                db._all("SELECT * FROM hub_ops ORDER BY id"), db._all("SELECT * FROM hub_defects ORDER BY id"),
                db._all("SELECT * FROM projects ORDER BY id")]

    before = snapshot()
    page = web.client.get(f"/projects/{pid}/hub-text-rules")
    assert page.status_code == 200, page.text
    assert "510001" in page.text and "по прежнему тексту" in page.text
    assert snapshot() == before


def test_defect_origin_mark_is_recognized_by_the_decision_hash():
    review = {"entered_hub": 1, "entered_origin": "defect", "entered_text_hash": text_hash("тело дефекта в Hub"),
              "entered_decision_hash": text_hash("прежний текст")}
    assert routes.entered_format_updated(review, "новый текст", ["прежний текст"])
    assert not routes.entered_format_updated(review, "новый текст", ["другой"])


def test_dast_comment_keeps_operator_words_and_prior_format_is_frozen():
    from app.prompts import hub_text, hub_text_v1
    f = Finding.from_dict({"hub_id": "9", "kind": "DAST", "rule": "XSS"})
    text = f"Проверено {DASH} <b>ок</b>\n\n\n\nВторой абзац."
    current = hub_text(f, "false_positive", text, {})
    assert current.endswith("Комментарий: " + text) and current.startswith("Статус: ")
    old = hub_text_v1(f, "false_positive", text, {})
    assert DASH not in old and "\n\n\n" not in old  # прежний формат – для узнавания отметок


def sca_finding(**fields) -> Finding:
    base = {"hub_id": "73002", "kind": "SCA", "component": "example-parser", "version": "1.4.2",
            "cve": ["CVE-2099-10001"]}
    return Finding.from_dict({**base, **fields})


def test_sca_short_text_keeps_operator_words():
    f = sca_finding()
    text = f"Ложное срабатывание: класс <Parser> не вызывается {DASH} a<b && c>d."
    assert sca.hub_text(f, "false_positive", text) == f"CVE-2099-10001 в example-parser 1.4.2: {text}"
    assert sca.hub_text(f, "false_positive", "CVE-2099-10001: <b>не</b> применимо.") == (
        "CVE-2099-10001: <b>не</b> применимо.")  # начинается с номера – без приставки (ADR-0101 п. 2)
    assert sca.hub_text(f, "false_positive", "Код AST-2099-1 не вызывается.") == (
        "CVE-2099-10001 в example-parser 1.4.2: Код не вызывается.")  # номера AST убираются (ADR-0101 пп. 1–2)
    assert sca.short_reason("Ложное срабатывание:") == ""  # одно вводное слово обоснованием не считается
    assert sca.hub_text(f, "true_positive", text) == ""


def test_sca_prior_short_format_is_frozen():
    f = sca_finding()
    text = f"Ложное срабатывание: класс <b>Parser</b> не вызывается {DASH} совсем."
    assert sca.hub_text_v4(f, "false_positive", text) == (
        "CVE-2099-10001 в example-parser 1.4.2: класс Parser не вызывается – совсем.")
    assert sca.hub_text_v3(f, "false_positive", text) == "класс Parser не вызывается – совсем."


def test_sca_head_from_export_keeps_the_prior_cleaning():
    f = sca_finding(component=f"parser{DASH}core")
    assert sca.hub_text(f, "false_positive", f"Не вызывается {DASH} совсем.") == (
        f"CVE-2099-10001 в parser–core 1.4.2: Не вызывается {DASH} совсем.")


def test_command_html_keeps_blank_lines_and_indentation():
    """Ревью Codex, круг 1: содержимое не теряется до отправки – лишние пустые строки и отступы доходят до HTML."""
    assert hub_defects.command_html("А\nБ\n\nВ") == "<p>А<br>Б</p><p>В</p>"  # обычный текст – как раньше
    assert hub_defects.command_html("\n\nА\n\n\n\nБ\n\n") == "<p>А</p><p><br></p><p><br></p><p>Б</p>"
    assert hub_defects.command_html("Шаги:\n  отступ\n\tтаб <b>") == (
        "<p>Шаги:<br>&nbsp;&nbsp;отступ<br>&nbsp;&nbsp;&nbsp;&nbsp;таб &lt;b&gt;</p>")
    body = "Обоснование:\n  А\n\n\n\nБ"
    assert hub_defects.description_matches(hub_defects.description_html(body, ""), body)


def test_presence_checks_keep_the_prior_criterion():
    """Ревью Codex и Kimi, круг 1: пустой тег, невидимый знак и одно вводное слово обоснованием и пунктом не считаются,
    как до 0.10.0.dev21; уходящий текст – как написан."""
    for empty in ("<b></b>", f"Ложное срабатывание:{ZWSP}", ZWSP, "Ложное срабатывание:"):
        assert defect.reason_text(empty) == "", empty
        assert defect.sast_comment(sast(), "false_positive", empty) == "", empty
        assert sca.short_reason(empty) == "" and sca.hub_text(sca_finding(), "false_positive", empty) == "", empty
    assert not defect.has_recommendation("<b></b>") and not defect.has_recommendation(ZWSP)
    assert defect.has_recommendation("Экранируйте <b>вывод</b>.")


def test_capital_letter_after_invisible_mark():
    assert defect.sast_reason(f"{ZWSP}строка 26 формирует запрос.") == f"{ZWSP}Строка 26 формирует запрос."
    assert defect.sast_reason("<b>строка</b> 26.") == "<b>строка</b> 26."  # тег – видимый текст, буква не первая


def test_group_send_takes_only_exactly_the_same_text(web):  # noqa: F811
    """Ревью Codex, круг 1: группа уходит одним комментарием, отметка соседа – по его тексту; соседом идёт только точно
    тот же текст (пустые строки оператора – часть текста)."""
    from test_hub_status_routes import REASON, decide, project as hub_project, run_worker, sast as hub_sast, send
    pid = hub_project(web, [hub_sast("101"), hub_sast("102"), hub_sast("103")])
    decide(web, pid, "101", comment=REASON + "\n\nВторой абзац.")
    decide(web, pid, "102", comment=REASON + "\n\n\n\nВторой абзац.")  # те же слова, другие пустые строки
    decide(web, pid, "103", comment=REASON + "\n\nВторой абзац.")
    assert send(web, pid, "101").status_code == 200
    job = run_worker(web)
    assert job["body"]["issues"] == [{"issueId": 101, "issueType": "SAST"}, {"issueId": 103, "issueType": "SAST"}]
    assert job["body"]["reason"] == REASON + "\n\nВторой абзац."
    db = web.app.state.db
    assert db.get_review(pid, "103")["entered_hub"] == 1 and db.get_review(pid, "102")["entered_hub"] == 0


def test_scale_page_survives_no_defect_placement_and_counts_real_members(web, monkeypatch):  # noqa: F811
    """Ревью Codex и Kimi, круг 1: находка «без дефекта» (set_no NULL) не роняет страницу; участники набора – по
    правилу сборщика дефекта (в выгрузке, действующее «Обновить», этот набор)."""
    from app import hub_text_scale
    from app.ecosystem import finding_ecosystem
    from app.routes import sca as sca_routes
    from app.sca_contract import input_ref
    from test_hub_status_routes import project as hub_project, sca as hub_sca
    pid = hub_project(web, [hub_sca("71"), hub_sca("72"), hub_sca("73")])
    db = web.app.state.db
    data = db.get_finding_by_hub_id(pid, "71")["data"]
    ref = input_ref(finding_ecosystem(data), str(data.get("component") or ""), str(data.get("version") or ""))
    db.move_sca_member(pid, ref, "73", None, "Компонент не входит в поставку.",
                       {0: db.sca_sets(pid, ref).get(0, {}).get("revision", 0)})
    db.save_sca_package_text(pid, ref, 0, expect_revision=0, explanation="", ast={}, target_version="2.0.0",
                             target_basis="manual", version_checked_sig="", text_checked_sig="", text_sig="",
                             recommendation_note="Первая мера.\n\nВторая мера.")
    notes = db.sca_text_notes(pid)
    assert notes and notes[0]["placed"]["73"] is None
    states = {"71": ("ok", "true_positive"), "72": ("ok", "false_positive"), "73": ("ok", "true_positive")}
    monkeypatch.setattr(sca_routes, "decision_state", lambda f, review, latest, row=None: states[f.hub_id])
    report = hub_text_scale.report(db, web.app.state.settings, pid, web.app.state.feeds)
    assert [m["hub_id"] for m in report["sets"][0]["members"]] == ["71"]
    assert web.client.get(f"/projects/{pid}/hub-text-rules").status_code == 200


def test_push_names_layout_only_difference():
    """Ревью круга 2: правка только пустых строк и отступов в Hub не уходит (сравнение по строкам разметки), но Push
    называет причину, а не молчит."""
    hub = hub_defects.command_html("Обоснование:\nА\n\nБ")
    assert hub_defects.layout_only_change("Обоснование:\nА\n\n\n\nБ", hub), "добавлены пустые строки"
    assert hub_defects.layout_only_change("Обоснование:\n  А\n\nБ", hub), "добавлен отступ"
    assert not hub_defects.layout_only_change("Обоснование:\nА\n\nБ", hub), "тот же текст без оформления"
    assert not hub_defects.layout_only_change("Обоснование:\nА\n\nВ", hub), "другие слова – обычная правка"
    assert not hub_defects.layout_only_change("Обоснование:\nА\n\n\n\nБ", ""), "описания Hub нет"
    # убрано оформление, которое было в Hub (ревью круга 3): отступ и пустой абзац видны по разметке Hub
    indented = "<p>Обоснование:<br>&nbsp;&nbsp;А</p><p>Б</p>"
    assert hub_defects.layout_only_change("Обоснование:\nА\n\nБ", indented)
    gap = "<p>Обоснование:<br>А</p><p><br></p><p>Б</p>"
    assert hub_defects.layout_only_change("Обоснование:\nА\n\nБ", gap)


def test_set_marks_by_body_signature():
    from app.hub_text_scale import _mark_by_sig
    assert _mark_by_sig({"entered_hub": 1, "entered_origin": "defect", "entered_decision_hash": "old"}, "new", "old")[
        "basis"] == "по прежнему тексту"
    assert _mark_by_sig({"entered_hub": 1, "entered_origin": "manual", "entered_text_hash": "new"}, "new", "old")[
        "basis"] == "по нынешнему тексту"
    assert _mark_by_sig({"entered_hub": 0}, "new", "old") == {"entered": False, "origin": "", "basis": ""}


def test_sca_note_keeps_blank_lines_and_prior_body_drops_them():
    note = "Первый абзац мер.\n\nВторой абзац AST-2099-1.\nAST-2099-2\n\n\nТретий."
    assert sca_text.note_lines(note) == ["Первый абзац мер.", "", "Второй абзац.", "", "", "Третий."]
    assert sca_text.note_lines(note, legacy=True) == ["Первый абзац мер.", "Второй абзац.", "Третий."]
    assert sca_text.note_lines("") == [] and sca_text.note_lines("  \n ") == []


# ------------------------------------------------------------------ ревью круга 5 (Codex r5a/r5b, Kimi r4)

def _sca_set(web, monkeypatch, explanation: str, note: str = "", text_checked_sig: str = ""):
    """Набор дефекта SCA из одной находки с решением «Обновить» и целевой версией вручную; проверка версии –
    «verified», чтобы набор был готов и тело показывалось. (pid, ref, view)."""
    from app.ecosystem import finding_ecosystem
    from app.routes import sca as sca_routes
    from app.sca_contract import input_ref
    from test_hub_status_routes import project as hub_project, sca as hub_sca
    monkeypatch.setattr(sca_text, "check_version", lambda *a, **k: sca_text.VersionCheck("verified", ""))
    pid = hub_project(web, [hub_sca("81")])
    db = web.app.state.db
    data = db.get_finding_by_hub_id(pid, "81")["data"]
    ref = input_ref(finding_ecosystem(data), str(data.get("component") or ""), str(data.get("version") or ""))
    monkeypatch.setattr(sca_routes, "decision_state", lambda f, review, latest, row=None: ("ok", "true_positive"))
    db.save_sca_package_text(pid, ref, 0, expect_revision=0, explanation=explanation, ast={}, target_version="2.0.0",
                             target_basis="manual", version_checked_sig="", text_checked_sig=text_checked_sig,
                             text_sig="", recommendation_note=note)
    f = Finding.from_dict(db.get_finding_by_hub_id(pid, "81")["data"])
    return pid, ref, sca_routes.sca_defect(db, web.app.state.feeds, pid, f, db.get_review(pid, "81"))


def test_prior_text_check_stays_valid_when_the_body_is_the_same(web, monkeypatch):  # noqa: F811
    """Н1: хвостовые пробелы внутри Объяснения входили в прежнюю подпись Объяснения, но не в тело. Тела совпадают –
    отметка «Текст проверен» прежних правил действует, пояснения о смене формата нет."""
    from app.routes import sca as sca_routes
    explanation = "CVE-2099-0001: the parser reads untrusted archive entries.  \nExtra explanation."
    _, _, view = _sca_set(web, monkeypatch, explanation)
    assert [c for c in view["cautions"] if "не на русском" in c], "без отметки – предупреждение (ADR-0152)"
    assert not [p for p in view["problems"] if "не на русском" in p]
    _, _, ready = _sca_set(web, monkeypatch, explanation, text_checked_sig=view["text_confirm_sig"])
    assert ready["ready"] and ready["body"], ready["problems"]
    prior = sca_routes._sig(sca_routes._sig(sca_text.strip_internal_ids(explanation.strip())),
                            sca_routes._sig(ready["body"]))
    assert prior != ready["text_confirm_sig"], "прежняя подпись другая – иначе тест ничего не проверяет"
    _, _, again = _sca_set(web, monkeypatch, explanation, text_checked_sig=prior)
    assert again["ready"] and not again["problems"], again["problems"]
    assert not [c for c in again["cautions"] if "не на русском" in c], "отметка прежних правил действует"
    assert again["legacy_text_sig_v4"] == ""


def test_sca_explanation_and_note_keep_first_line_indent(web, monkeypatch):  # noqa: F811
    """Н2, Н4: отступ первой строки Объяснения и добавления к «Рекомендациям» остаётся в теле дефекта; набор, у
    которого изменился только отступ, отчёт масштаба показывает."""
    from app import hub_text_scale
    pid, ref, view = _sca_set(web, monkeypatch, "  CVE-2099-0001: разбор архива читает записи без проверки.",
                              note="  Ограничить доступ.")
    assert view["ready"], view["problems"]
    assert "\nОбъяснение\n  CVE-2099-0001: разбор архива читает записи без проверки.\n" in view["body"]
    assert "\n  Ограничить доступ.\n" in view["body"]
    assert view["legacy_text_sig_v4"], "по прежним правилам отступы срезались – тело другое"
    report = hub_text_scale.report(web.app.state.db, web.app.state.settings, pid, web.app.state.feeds)
    assert [m["hub_id"] for m in report["sets"][0]["members"]] == ["81"]


def test_sca_set_without_changes_is_not_in_the_scale_report(web, monkeypatch):  # noqa: F811
    from app import hub_text_scale
    pid, ref, view = _sca_set(web, monkeypatch, "CVE-2099-0001: разбор архива читает записи без проверки.",
                              note="Ограничить доступ.")
    assert view["ready"] and view["legacy_text_sig_v4"] == "", view["problems"]
    assert hub_text_scale.report(web.app.state.db, web.app.state.settings, pid, web.app.state.feeds)["sets"] == []


def test_prior_note_rules_are_exactly_the_old_ones():
    note = "  Первая мера.  \n\n  Вторая мера.\n"
    assert sca_text.note_lines(note, legacy=True) == ["Первая мера.", "  Вторая мера."]
    assert sca_text.note_lines(note) == ["  Первая мера.", "", "  Вторая мера."]


def test_sca_reason_presence_keeps_the_prior_criterion():
    """Н3: «<data:b>» обоснованием не считается, как до 0.10.0.dev21."""
    assert sca.short_reason("<data:b>") == ""
    assert sca.short_reason("  Компонент не используется.") == "Компонент не используется."


def test_sca_short_text_recognizes_own_id_after_indent():
    """К4: свой номер в начале обоснования после отступа – без приставки; отступ остаётся."""
    f = Finding(hub_id="1", kind="SCA", cve=["CVE-2099-10001"], component="example-parser", version="1.4.2")
    assert sca.hub_text(f, "false_positive", "  CVE-2099-10001: не применимо.") == "  CVE-2099-10001: не применимо."
    assert sca.hub_text(f, "false_positive", "Не применимо.") == "CVE-2099-10001 в example-parser 1.4.2: Не применимо."


def test_sast_recommendation_keeps_line_indent_before_the_number():
    """К2: отступ строки рекомендации в 1–3 пробела остаётся – в пункте и перед номером в тексте дефекта; четыре
    пробела – код, как раньше; прежние правила – без отступа."""
    fix = "Экранируйте вывод.\n  - Используйте параметры.\n    ps.setString(1, v);"
    assert defect.fix_items(fix) == ["Экранируйте вывод.", "  Используйте параметры."]
    assert defect.fix_items(fix, clean=True) == ["Экранируйте вывод.", "Используйте параметры."]
    body = defect.sast_body(SimpleNamespace(hub_id="1", rule="Внедрение SQL", file="a.java", line=1, codebase="c",
                                            cwe=["CWE-89"]), "true_positive", "Значение попадает в SQL.", fix,
                            "Платформа")
    assert body.endswith("Рекомендация:\n1) Экранируйте вывод.\n  2) Используйте параметры.")
    assert "&nbsp;&nbsp;2) Используйте" in hub_defects.command_html(body)
    assert defect.as_written_changed("Значение попадает в SQL.", fix), "прежние правила срезали отступ"


def test_push_names_removed_plain_space_indent():
    """Н5: в описании Hub отступ обычными пробелами после <br> – правка, которая его убирает, тоже называется;
    перевод строки между тегами отступом не считается."""
    assert hub_defects.layout_only_change("Обоснование:\nА\n\nБ", "<p>Обоснование:<br>  А</p><p>Б</p>")
    assert not hub_defects.layout_only_change("Обоснование:\nА\n\nБ", "<p>Обоснование:<br>\nА</p><p>Б</p>")


# ------------------------------------------------------------------ ревью круга 6 (Codex r6a/r6b)

def test_empty_tag_line_is_not_a_point_next_to_a_real_one():
    """A1: пустой тег пунктом не считается и рядом с содержательной строкой; слова пункта – как написаны."""
    fix = "<b></b>\n<i>Параметризовать</i> запрос."
    assert defect.fix_items(fix) == ["<i>Параметризовать</i> запрос."]
    assert defect.fix_items(fix, clean=True) == ["Параметризовать запрос."]
    body = defect.sast_body(SimpleNamespace(hub_id="1", rule="Внедрение SQL", file="a.java", line=1, codebase="c",
                                            cwe=["CWE-89"]), "true_positive", "Значение попадает в SQL.", fix,
                            "Платформа")
    assert body.endswith("Рекомендация:\n1) <i>Параметризовать</i> запрос.")


def test_push_names_removed_indent_inside_nested_markup():
    """B2: отступ во вложенной разметке Hub (<p><strong>&nbsp;…) тоже узнаётся – разбором до нормализации."""
    hub = "<p><strong>&nbsp;&nbsp;Причина.</strong></p><p>Б</p>"
    assert hub_defects.layout_only_change("Причина.\n\nБ", hub)
    assert not hub_defects.layout_only_change("Причина.\n\nБ", "<p><strong>Причина.</strong></p><p>Б</p>")


def test_scale_page_names_both_reasons_for_sets(web, monkeypatch):  # noqa: F811
    """A3/B5: набор, у которого изменился только отступ Объяснения, страница объясняет верно."""
    pid, ref, view = _sca_set(web, monkeypatch, "  CVE-2099-0001: разбор архива читает записи без проверки.")
    page = web.client.get(f"/projects/{pid}/hub-text-rules").text
    assert 'id="hub-text-rules-sets"' in page and "отступ в начале Объяснения" in page


def test_delivered_text_is_compared_letter_by_letter(web):  # noqa: F811
    """B1: выполненная запись статуса с тем же текстом без лишних пустых строк – не «тот же текст»: комментарий в
    новом формате можно отправить заменой."""
    from app.routes import hub_status_routes
    from test_hub_status_replace_dev29 import entered_once
    from test_hub_status_routes import project as hub_project, sast as hub_sast
    pid = hub_project(web, [hub_sast("101")])
    entered_once(web, pid, "101", comment="Причина решения подробно.\n\nПодробности решения.")
    db = web.app.state.db
    settings, project = web.app.state.settings, db.get_project(pid)
    hub_url = db.get_settings().get("hub_url") or settings.hub_url
    sent = db._all("SELECT request_json, targets_json FROM hub_ops WHERE project_id = ? AND purpose = 'status'"
                   " AND state = 'done'", (pid,))
    body = json.loads(sent[0]["request_json"])["body"]
    revision = int(json.loads(sent[0]["targets_json"])[0]["revision"])
    reason = body["reason"]

    def delivered(text: str) -> bool:
        return db.on_connection(lambda c: hub_status_routes.text_delivered_in(
            c, pid, "101", body["status"], text, revision, hub_url, project["hub_app_id"]))

    assert delivered(reason), "тот же текст – внесён"
    assert not delivered(reason.replace("\n\n", "\n\n\n")), "лишняя пустая строка – другой текст"


def test_internal_id_removal_keeps_the_line_indent(web, monkeypatch):  # noqa: F811
    """Ревью Kimi круга 5: удаление внутреннего номера AST не срезает отступ строки – в Объяснении, «Добавлении» и
    коротком комментарии SCA; прежние правила срезают, поэтому набор попадает в отчёт масштаба."""
    from app import hub_text_scale
    assert sca_text.strip_ids_keep_indent("  CVE-2099-0001 (это AST-2099-1): текст.") == "  CVE-2099-0001: текст."
    assert sca_text.strip_ids_keep_indent("  AST-2099-1") == ""
    assert sca_text.note_lines("  Мера AST-2099-1 первая.") == ["  Мера первая."]
    pid, ref, view = _sca_set(web, monkeypatch, "  CVE-2099-0001 (это AST-2099-1): разбор архива читает записи без "
                                               "проверки.")
    assert view["ready"], view["problems"]
    assert "\nОбъяснение\n  CVE-2099-0001: разбор архива читает записи без проверки.\n" in view["body"]
    assert view["legacy_text_sig_v4"], "прежние правила срезали отступ"
    report = hub_text_scale.report(web.app.state.db, web.app.state.settings, pid, web.app.state.feeds)
    assert [m["hub_id"] for m in report["sets"][0]["members"]] == ["81"]
    f = Finding(hub_id="1", kind="SCA", cve=["CVE-2099-10001"], component="example-parser", version="1.4.2")
    assert sca.hub_text(f, "false_positive", "  Не применимо, AST-2099-1 не вызывается.") == (
        "CVE-2099-10001 в example-parser 1.4.2:   Не применимо, не вызывается.")


# ------------------------------------------------------------------ ревью круга 7 (Codex r7a/r7b)

def test_pulled_comment_differing_only_in_spaces_is_not_current(web):  # noqa: F811
    """Отметка принятого Pull без отпечатка: текущий – только тот же текст буква в букву (края – по ADR-0149);
    отличие в пробелах и пустых строках – можно заменить."""
    from app.routes import hub_status_routes
    from test_hub_status_replace_dev29 import accept_hub_state
    from test_hub_status_routes import decide as hub_decide, project as hub_project, sast as hub_sast
    pid = hub_project(web, [hub_sast("101")])
    hub_decide(web, pid, "101", comment="Причина решения подробно.\n\n\nПодробности решения.")
    accept_hub_state(web, pid, "101", {"detail": {"status": "False Positive"},
                                       "manual": {"reason": "Причина решения подробно.\n\nПодробности решения.",
                                                  "expiredAt": "2027-01-26T00:00:00Z"}})
    db = web.app.state.db
    # действующие настройки, как у приложения: сохранённые в базе поверх окружения (адрес Hub – в базе)
    settings, project = web.app.state.web.base.with_stored(db.get_settings()), db.get_project(pid)
    raw = hub_status_routes.accepted_hub_reason(db, project, settings, "101", raw=True)
    assert raw == "Причина решения подробно.\n\nПодробности решения."
    assert hub_status_routes.accepted_hub_reason(db, project, settings, "101") != raw, "обычный вид – нормализован"
    with db._tx() as c:  # отметка принятого Pull: происхождение hub_sync, без отпечатка (как в test_hub_status_replace_dev29)
        op = c.execute("INSERT INTO hub_ops(project_id, purpose, op_key, lock_keys, targets_json, request_json, hub_url,"
                       " app_id, text_hash, text_norm, state, created_at, updated_at) VALUES (?, 'read', 'k-pull', '[]',"
                       " '[]', '{}', 'https://hub.example.org', 7, '', '', 'done', '2026-11-02T10:00:00+00:00',"
                       " '2026-11-02T10:00:00+00:00') RETURNING id", (pid,)).fetchone()[0]
        c.execute("UPDATE reviews SET entered_hub=1, entered_origin='hub_sync', entered_text_hash='', entered_op_id=?,"
                  " entered_hub_at='2026-11-02T10:00:00+00:00' WHERE project_id=? AND hub_id=?", (op, pid, "101"))
    from test_hub_status_replace_dev29 import card
    html = card(web, pid, "101")
    assert ">Обновить комментарий в Hub</button>" in html, "текст отличается пустой строкой – замена доступна"


def test_indent_inside_nested_markup_at_the_end_and_after_markup_newline():
    assert hub_defects.layout_only_change("Причина.", "<strong>&nbsp;&nbsp;Причина.</strong>")
    assert hub_defects.layout_only_change("Причина.", "<p>\n<strong>&nbsp;&nbsp;Причина.</strong></p>")
    assert not hub_defects.layout_only_change("Причина.", "<p>\n  <strong>Причина.</strong></p>"), \
        "пробелы разметки после перевода строки – не отступ"


def test_indent_after_list_marker_in_hub_markup():
    """Ревью Kimi круга 6: отступ после маркера пункта списка во вложенной разметке Hub тоже узнаётся."""
    assert hub_defects.layout_only_change("1) Причина.", "<ol><li><strong>&nbsp;&nbsp;Причина.</strong></li></ol>")
    assert not hub_defects.layout_only_change("1) Причина.", "<ol><li><strong>Причина.</strong></li></ol>")


def test_no_layout_warning_when_hub_has_exactly_the_app_description():
    """Ревью Kimi круга 6: дефект создан приложением с отступами и пустыми строками, Hub хранит ровно собранное
    описание, правки нет – LAYOUT_KEPT не нужен; Hub переписал разметку, а слова те же – нужен."""
    text = "Обоснование:\n  А\n\n\n\nБ"
    built = hub_defects.command_html(text)
    assert not hub_defects.layout_warning(text, built, built, built)
    reformatted = "<p>Обоснование:<br>&nbsp;&nbsp;А</p><p>Б</p>"
    assert hub_defects.layout_warning(text, built, reformatted, reformatted)
    assert not hub_defects.layout_warning(text, built, built, reformatted), "описание Hub не оставлено – отправка"

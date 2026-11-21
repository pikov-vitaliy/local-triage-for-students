"""Рекомендация дефекта SAST – только меры словами (ADR-0098): пример кода в
ограде, с отступом и строки без букв в текст для Hub не идут; у внесённого в Hub дефекта с примером кода причина
«Текст изменился» называет это правило. Данные выдуманы."""

from __future__ import annotations

from types import SimpleNamespace

from app import defect
from app.routes import findings as routes

FIX = ("1) Передавать значение параметром.\n```java\nps.setString(1, owner);\n```\n"
       "    String sql = \"SELECT\" + COLUMNS;\n}\n2) Проверить другие запросы.")


def test_code_is_not_a_point_of_the_defect():
    assert defect.fix_items(FIX) == ["Передавать значение параметром.", "Проверить другие запросы."]
    assert defect.fix_items("```\nquery(x);\n```") == []
    assert not defect.has_recommendation("```\nquery(x);\n```")


# маркер пункта (шаг 3 плана 0.9.11): одна таблица для сервера и предпросмотра в браузере (tests/e2e/test_save_stays_in_place.py)
MARKERS = ("2)первая мера\n10)вторая мера\n3) третья мера\n1)\n1.5 раза больше\n-x включает режим\n"
           "*args передаются\n- пункт\n1)2)вложенный маркер\n1.1)подпункт\n\u0662)арабская цифра")
MARKER_POINTS = ["первая мера", "вторая мера", "третья мера", "1.5 раза больше", "-x включает режим",
                 "*args передаются", "пункт", "2)вложенный маркер", "1.1)подпункт", "\u0662)арабская цифра"]


def test_list_marker_without_space_is_removed_once():
    assert defect.fix_items(MARKERS) == MARKER_POINTS
    assert defect.fix_items("ssdf\n2)sdfsdf\n3)sdfsdf") == ["ssdf", "sdfsdf", "sdfsdf"]
    assert not defect.has_recommendation("1)\n2)")
    body = defect.sast_body(SimpleNamespace(hub_id="1", rule="Внедрение SQL", file="a.java", line=1, codebase="c",
                                            cwe=["CWE-89"]), "true_positive", "Значение попадает в SQL.",
                            "1)Параметризовать запрос.\n2)Проверить другие запросы.", "Платформа")
    assert body.endswith("Рекомендация:\n1) Параметризовать запрос.\n2) Проверить другие запросы.")


def test_body_has_no_code():
    body = defect.sast_body(SimpleNamespace(hub_id="1", rule="Внедрение SQL", file="a.java", line=1, codebase="c",
                                            cwe=["CWE-89"]), "true_positive",
                            "Подтверждено: значение из запроса попадает в SQL.", FIX, "Платформа")
    assert body.endswith("Рекомендация:\n1) Передавать значение параметром.\n2) Проверить другие запросы.")
    assert "ps.setString" not in body and "COLUMNS" not in body


def test_entered_defect_with_code_names_the_new_rule(monkeypatch):
    settings = SimpleNamespace(team_name="Платформа", hub_status_map={})
    tp = {"decision": "disagree", "final_verdict": "true_positive", "final_comment": "А", "final_fix": FIX}
    monkeypatch.setattr(routes, "__version__", "0.9.9")  # отметка до 0.9.10: код тогда переносился
    tp["entered_parts"] = routes.entered_parts(settings, tp)
    monkeypatch.setattr(routes, "__version__", "9.9.9")
    reasons = routes.entered_change_reasons(settings, tp)
    assert len(reasons) == 1 and "пример кода в рекомендации больше не переносится" in reasons[0]
    # маркер «N)» без пробела (0.9.11): своя причина; пример кода, уже исключённый в 0.9.10, причиной не называется
    marker = {**tp, "final_fix": "2)Передавать значение параметром.\n```\nx();\n```"}
    monkeypatch.setattr(routes, "__version__", "0.9.10")
    marker["entered_parts"] = routes.entered_parts(settings, marker)
    monkeypatch.setattr(routes, "__version__", "0.9.11")
    marked = routes.entered_change_reasons(settings, marker)
    assert len(marked) == 1 and "маркер пункта «N)» без пробела" in marked[0], marked
    words = {**tp, "final_fix": "1) Передавать значение параметром."}
    monkeypatch.setattr(routes, "__version__", "0.9.9")
    words["entered_parts"] = routes.entered_parts(settings, words)
    monkeypatch.setattr(routes, "__version__", "9.9.9")
    assert "формат текста" in routes.entered_change_reasons(settings, words)[0]

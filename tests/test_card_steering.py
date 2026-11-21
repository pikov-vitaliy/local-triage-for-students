"""Текст модели для «Дефекта из выбранных» – по правилам кнопок карточки (ADR-0092). Данные выдуманы."""

from app.models import Finding
from app.routes.findings import model_suggestion

F = Finding(hub_id="101", kind="SAST", rule="Внедрение SQL", cwe=["CWE-89"], codebase="demo", file="demo.py", line=2,
            snippet="query = 'SELECT ' + value", severity="high")
CONTEXT = {"status": "ok", "file": "demo.py", "language": "python", "start_line": 1, "end_line": 3, "target_line": 2,
           "lines": ["value = input()", "query = 'SELECT ' + value", "run(query)"], "steering_lines": [],
           "steering_fields": []}


def case(verdict="true_positive", fix="1. Передавать значение параметром.", **context):
    return {"context": {**CONTEXT, **context},
            "verdict": {"data": {"verdict": verdict, "confidence": 90, "hub_comment": " Значение идёт в SQL. ",
                                 "fix": fix}}}


def test_model_suggestion_takes_comment_and_points_of_true_positive():
    assert model_suggestion(F, case()) == {"comment": "Значение идёт в SQL.", "points": "Передавать значение параметром.",
                                           "code_dropped": False}
    fenced = model_suggestion(F, case(fix="Параметр запроса.\n```python\nrun(query, [value])\n```"))
    assert fenced["points"] == "Параметр запроса." and fenced["code_dropped"] is True


def test_model_suggestion_refuses_other_verdicts_steering_and_missing_case():
    assert model_suggestion(F, case(verdict="false_positive")) == {}
    assert model_suggestion(F, case(verdict="uncertain")) == {}
    assert model_suggestion(F, case(steering_lines=[2])) == {}
    assert model_suggestion(F, case(steering_fields=["snippet"])) == {}
    assert model_suggestion(F, None) == {}
    assert model_suggestion(F, {"context": CONTEXT, "verdict": None}) == {}

"""ADR-0147: срез, который разбирала модель, не совпадает с текущим кодом – «Решение для выбранных» и «Дефект из
выбранных» не исключают находку, а предупреждают; исход сохраняется «Не согласен» со своим вердиктом, а не «Согласен»
с ответом модели о прежнем срезе. Данные выдуманы, сети нет."""

from __future__ import annotations

import pytest

from app.routes import findings as card
from test_db import verdict
from test_decision_selected import apply as decide_apply, preview as decide_preview
from test_defect_selected import prepare, preview as defect_preview, setup
from test_web import web  # noqa: F401

NOTE = "срез, который разбирала модель, не совпадает с текущим кодом"


def with_model_verdict(web, pid: int, hub_id: str, value: str) -> None:
    db = web.app.state.db
    vid = db.save_verdict(f"stale-{hub_id}", "demo", "sast-v6", verdict(value), {})
    db.save_case(pid, hub_id, f"stale-{hub_id}", {"status": "ok", "file": "a.py", "lines": ["x"]}, vid)


@pytest.fixture
def stale(monkeypatch):
    real = card.check_code

    def marked(*args, **kwargs):
        return {**real(*args, **kwargs), "stale_verdict": True}
    monkeypatch.setattr(card, "check_code", marked)


def test_decision_selected_includes_stale_slice_and_saves_disagree(web, stale):  # noqa: F811
    pid = setup(web)
    with_model_verdict(web, pid, "101", "false_positive")
    page = decide_preview(web, pid)
    assert page.status_code == 200 and NOTE in page.text
    assert 'id="decide-apply"' in page.text
    r = decide_apply(web, pid, page.text)
    assert r.status_code == 303, r.text
    review = web.app.state.db.get_review(pid, "101")
    assert (review["decision"], review["final_verdict"], review["reviewed"]) == ("disagree", "false_positive", 1)


def test_defect_selected_includes_stale_slice_and_saves_disagree(web, stale):  # noqa: F811
    pid = setup(web)
    with_model_verdict(web, pid, "101", "true_positive")
    page = defect_preview(web, pid)
    assert NOTE in page.text and "код изменился после разбора" not in page.text
    r = prepare(web, pid)
    assert r.status_code == 303, r.text
    review = web.app.state.db.get_review(pid, "101")
    assert (review["decision"], review["final_verdict"], review["reviewed"]) == ("disagree", "true_positive", 1)


def test_fresh_slice_has_no_warning(web):  # noqa: F811
    pid = setup(web)
    assert NOTE not in decide_preview(web, pid).text and NOTE not in defect_preview(web, pid).text

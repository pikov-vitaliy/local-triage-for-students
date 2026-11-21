"""Новый срез под проверенной находкой (ADR-0011, ADR-0147): если он совпадает с кодом, по
которому человек отметил решение, «Проверено» остаётся; если код изменился после решения – снимается, как раньше;
у решения без отпечатка кода – прежнее правило. Данные выдуманы."""

from __future__ import annotations

from test_hub_status_routes import project, sast
from test_web import web  # noqa: F401

CTX = {"status": "ok", "lines": ["x"], "max_chars": 12000}


def _reviewed(db, pid, hub_id):
    return db.get_review(pid, hub_id)["reviewed"]


def test_same_code_as_operator_saw_keeps_reviewed(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("1")])
    db.save_case(pid, "1", "slice-old-builder", CTX, None)
    db.save_review(pid, "1", decision="disagree", final_verdict="false_positive", final_comment="Ложное: пустая строка.",
                   reviewed=True, code_hash="slice-current", code_chars=12000)
    db.save_case(pid, "1", "slice-current", CTX, None)  # новый прогон пересобрал срез – тот самый код
    assert _reviewed(db, pid, "1"), "решение по этому коду – отметка остаётся"
    db.save_case(pid, "1", "slice-after-edit", CTX, None)  # код в клоне изменился после решения
    assert not _reviewed(db, pid, "1"), "код другой – отметка снимается, как раньше"


def test_old_decision_without_code_hash_keeps_old_rule(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("2")])
    db.save_case(pid, "2", "slice-a", CTX, None)
    db.save_review(pid, "2", decision="disagree", final_verdict="false_positive", final_comment="Ложное.", reviewed=True)
    db.save_case(pid, "2", "slice-b", CTX, None)
    assert not _reviewed(db, pid, "2")


def test_unknown_slice_size_keeps_old_rule(web):  # noqa: F811
    """Размер среза решения не записан (0), у нового среза его тоже нет: сравнивать нечего – прежнее правило."""
    db = web.app.state.db
    pid = project(web, [sast("4")])
    no_size = {"status": "ok", "lines": ["x"]}
    db.save_case(pid, "4", "slice-a", no_size, None)
    db.save_review(pid, "4", decision="disagree", final_verdict="false_positive", final_comment="Ложное.", reviewed=True,
                   code_hash="slice-b", code_chars=0)
    db.save_case(pid, "4", "slice-b", no_size, None)
    assert not _reviewed(db, pid, "4")


def test_different_slice_size_keeps_old_rule(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("3")])
    db.save_case(pid, "3", "slice-a", CTX, None)
    db.save_review(pid, "3", decision="disagree", final_verdict="false_positive", final_comment="Ложное.", reviewed=True,
                   code_hash="slice-b", code_chars=4000)  # отпечаток при другом размере среза не сравним
    db.save_case(pid, "3", "slice-b", CTX, None)
    assert not _reviewed(db, pid, "3")

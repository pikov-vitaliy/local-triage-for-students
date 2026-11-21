"""Пакет 5: полнота срезов перед отвязкой и повторная проверка решения после конфликта."""

import re

import pytest

from app.models import CodeContext, Finding
from app.triage import case_hash, sync_revisions
from fake_ollama import verdict_answer
from test_code_snapshots import MODEL, analysed, card_url, clone, form_of, wait_run, web  # noqa: F401
from test_sca import answers_text, form_fields, post_answers, sca_card
from test_web import ORIGIN, prepared


@pytest.mark.parametrize("reason", ["no_repo", "unreadable", "ambiguous", "too_large", "binary",
                                   "line_out_of_range", "", "missing", "empty", "ok"])
def test_removed_clone_detaches_only_with_complete_snapshots(web, reason):
    pid = prepared(web)
    db = web.app.state.db
    second = Finding.from_dict(db.case_input(pid, "510002")["data"])
    second_file = clone(web) / second.file
    second_file.parent.mkdir(parents=True, exist_ok=True)
    second_file.write_text("// учебный код\n" * 100, encoding="utf-8")
    assert web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN).status_code == 200
    finding = Finding.from_dict(db.case_input(pid, "510001")["data"])
    ctx = CodeContext.from_dict(db.get_case(pid, finding.hub_id)["context"])
    if reason != "ok":
        ctx.status, ctx.reason, ctx.lines = "export_line_only", reason, [finding.snippet]
        assert db.save_case(pid, finding.hub_id, case_hash(finding, ctx), ctx.to_dict(), None)
    incomplete = reason not in ("ok", "missing", "empty")
    assert db.snapshot_counts(pid)["billing-core"]["incomplete"] == int(incomplete)
    path = clone(web)
    parked = path.with_name("parked")
    path.rename(parked)
    sync_revisions(db, web.settings, db.get_project(pid))
    run = web.app.state.runner.enqueue(pid, MODEL, "all", [], fresh=True)
    assert wait_run(web, run)["state"] == "done"
    assert ("billing-core" in db.detached_codebases(pid)) is not incomplete
    assert db.snapshot_counts(pid)["billing-core"]["incomplete"] == int(incomplete)
    page = web.client.get(f"/projects/{pid}").text
    if incomplete:
        assert 'id="snapshots-ready"' not in page and "Клоны не удаляйте" in page
        assert any(row["hub_id"] == finding.hub_id for row in db.incomplete_snapshots(pid))
    else:
        assert 'id="snapshots-ready"' in page
    if reason == "no_repo":
        assert db.get_case(pid, finding.hub_id)["verdict_id"] is not None
        parked.rename(path)
        assert web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN).status_code == 200
        restored = db.get_case(pid, finding.hub_id)
        assert restored["context"]["status"] == "ok" and restored["verdict_id"] is None
        assert not db.incomplete_snapshots(pid)


@pytest.mark.parametrize("kind", ["sast", "sca"])
def test_conflict_form_preserves_text_but_requires_new_reviewed_mark(web, kind):
    pid = analysed(web) if kind == "sast" else prepared(web)
    db = web.app.state.db
    if kind == "sast":
        hub_id = "510001"
        url = card_url(web, pid, hub_id)
        fields = form_of(web.client.get(url).text)
        case = db.get_case(pid, hub_id)
        new_id = db.save_verdict(case["case_hash"], MODEL, "sast-v4", verdict_answer("false_positive"), {})
        db.save_case(pid, hub_id, case["case_hash"], case["context"], new_id)
        read_fields, notice = form_of, "Вердикт модели изменился"
    else:
        hub_id = "73001"
        assert post_answers(web, pid, answers_text()).status_code == 303
        fid, html = sca_card(web, pid, hub_id)
        url = f"/projects/{pid}/sca/findings/{fid}"
        fields = form_fields(html)
        assert post_answers(web, pid, answers_text(recommended_version="1.4.10")).status_code == 303
        read_fields, notice = form_fields, "новый ответ внешнего агента"
    decision = {"fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "true_positive", "comment": "Мой проверяемый вывод"}
    response = web.client.post(url + "/review", headers=ORIGIN, data={**fields, **decision, "reviewed": "1"})
    assert response.status_code == 409 and notice in response.text
    assert 'data-draft="1"' in response.text and "Мой проверяемый вывод</textarea>" in response.text
    checkbox = re.search(r'<input[^>]*id="reviewed-box"[^>]*>', response.text).group()
    assert "checked" not in checkbox
    assert db.get_review(pid, hub_id) is None
    saved = web.client.post(url + "/review", headers=ORIGIN, data={**read_fields(response.text), **decision})
    assert saved.status_code == 200
    review = db.get_review(pid, hub_id)
    assert review["reviewed"] == 0 and review["decision"] == "disagree"
    assert review["final_comment"] == decision["comment"]

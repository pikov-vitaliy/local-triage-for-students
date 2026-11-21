"""Пакет 4: замечания ревью предбоевых исправлений, только выдуманные данные."""

import re

import pytest

from fake_ollama import verdict_answer
from test_code_snapshots import (MODEL, analysed, card_url, cases, clone, decide, form_of, wait_run,
                                 web)  # noqa: F401
from test_sca import form_fields, sca_card
from test_web import ORIGIN, prepared

AS_JSON = {**ORIGIN, "Accept": "application/json"}


def test_returned_clone_replaces_no_repo_snapshot_even_after_model_verdict(web):
    pid = prepared(web)
    db = web.app.state.db
    path = clone(web)
    parked = path.with_name("parked")
    path.rename(parked)
    run = web.app.state.runner.enqueue(pid, MODEL, "all", [], fresh=True)
    assert wait_run(web, run)["state"] == "done"
    before = db.get_case(pid, "510001")
    assert before["context"]["reason"] == "no_repo" and before["verdict_id"] is not None
    parked.rename(path)
    page = web.client.get(f"/projects/{pid}").text
    assert 'id="snapshots-ready"' not in page
    assert 'id="snapshots-incomplete"' in page and 'id="save-snapshots"' in page
    assert db.snapshot_counts(pid)["billing-core"]["incomplete"] == 3
    assert any(row["hub_id"] == "510001" for row in db.incomplete_snapshots(pid))
    assert dict(db.snapshot_candidates(pid))["510001"]
    page = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN)
    assert page.status_code == 200
    after = db.get_case(pid, "510001")
    assert after["context"]["status"] == "ok" and after["case_hash"] != before["case_hash"]
    assert after["verdict_id"] is None


@pytest.mark.parametrize("detached", [False, True])
def test_no_repo_complete_only_without_active_mapping(web, detached):
    pid = prepared(web)
    db = web.app.state.db
    if detached:
        db.set_detached(pid, ["billing-core"])
    else:
        db.set_codebase_folder(pid, "billing-core", "", manual=True)
    run = web.app.state.runner.enqueue(pid, MODEL, "selected", ["510001"], fresh=True)
    assert wait_run(web, run)["state"] == "done"
    assert db.get_case(pid, "510001")["context"]["reason"] == "no_repo"
    assert db.snapshot_counts(pid)["billing-core"]["incomplete"] == 0
    assert not db.incomplete_snapshots(pid)
    assert "510001" not in dict(db.snapshot_candidates(pid))


def test_reset_automapping_counts_loss_and_requires_confirmation(web):
    pid = prepared(web)
    db = web.app.state.db
    db.set_codebase_folder(pid, "billing-core", "Catalog_API", manual=True)
    run = web.app.state.runner.enqueue(pid, MODEL, "all", [], fresh=True)
    assert wait_run(web, run)["state"] == "done"
    decide(web, pid, "510001")
    before, mapping = cases(web, pid), db.get_codebase_map(pid)
    count = db.case_reset_counts(pid)["billing-core"]["cases"]
    page = web.client.get(f"/projects/{pid}").text
    button = re.search(r'<button[^>]*value="reset"[^>]*>', page).group()
    assert f"срезов кода: {count}; отметок «Проверено»: 1" in button
    url = f"/projects/{pid}/codebases"
    blocked = web.client.post(url, headers=ORIGIN, data={"action": "reset"}, follow_redirects=False)
    assert blocked.status_code == 409
    assert f"срезов кода: {count}; отметок «Проверено»: 1" in blocked.text
    assert cases(web, pid) == before and db.get_codebase_map(pid) == mapping
    assert db.get_review(pid, "510001")["reviewed"] == 1
    saved = web.client.post(url, headers=ORIGIN, data={"action": "reset", "confirm_reset": "1"},
                            follow_redirects=False)
    assert saved.status_code == 303
    assert db.get_codebase_map(pid)["billing-core"]["folder"] == "billing-core"
    assert db.get_case(pid, "510001") is None and db.get_case(pid, "510004") is not None
    assert db.get_review(pid, "510001")["reviewed"] == 0


@pytest.mark.parametrize("json_response", [False, True])
@pytest.mark.parametrize("verdict,status", [("", 400), ("uncertain", 200)])
def test_sca_own_decision_needs_explicit_verdict(web, json_response, verdict, status):
    pid = prepared(web)
    fid, html = sca_card(web, pid, "73002")
    response = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review",
                               headers=AS_JSON if json_response else ORIGIN, data={
                                   **form_fields(html), "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": verdict,
                                   "comment": "Мой вывод", "reviewed": "1"})
    assert response.status_code == status
    review = web.app.state.db.get_review(pid, "73002")
    if not verdict:
        assert "Выберите вывод" in response.text and review is None
        if not json_response:
            assert "Мой вывод" in response.text
    else:
        assert review["decision"] == "disagree" and review["final_verdict"] == "uncertain"


def test_agreement_with_old_verdict_token_is_rejected(web):
    pid = analysed(web)
    db = web.app.state.db
    url = card_url(web, pid, "510001")
    form = form_of(web.client.get(url).text)
    case = db.get_case(pid, "510001")
    new_id = db.save_verdict(case["case_hash"], MODEL, "sast-v4", verdict_answer("false_positive"), {})
    db.save_case(pid, "510001", case["case_hash"], case["context"], new_id)
    response = web.client.post(url + "/review", headers=AS_JSON, data={
        **form, "fix": "Параметризовать запрос.", "decision": "agree", "comment": "Старый ответ", "reviewed": "1"})
    assert response.status_code == 409 and db.get_review(pid, "510001") is None

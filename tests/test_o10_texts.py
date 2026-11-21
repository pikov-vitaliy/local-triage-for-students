"""О10 (НТ12, НТ17): «Модель не ответила» – плашкой ошибки, а не успеха; решение SAST без отпечатка кода (прежняя
версия приложения) – честная причина вместо «код в клоне не тот». Данные выдуманы."""

from __future__ import annotations

from test_web import prepared, start_run, wait_run, web  # noqa: F401


def test_ask_failed_is_an_error_flash(web):  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    page = web.client.get(f"/projects/{pid}/findings/{fid}?ok=ask_failed").text
    assert '<p class="flash flash-err" role="alert">Модель не ответила' in page
    page = web.client.get(f"/projects/{pid}/findings/{fid}?ok=saved").text
    assert '<p class="flash flash-ok" role="status">Решение сохранено.' in page


def test_decision_without_code_print_says_so(web):  # noqa: F811
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    case = db.get_case(pid, "510001")
    db.save_review(pid, "510001", decision="disagree", final_verdict="true_positive",
                   final_comment="Подтверждено: owner из запроса попадает в SQL без параметров.",
                   reviewed=False, final_fix="Параметризовать запрос.", verdict_id=case["verdict_id"])
    assert db.get_review(pid, "510001")["code_hash"] == ""
    page = web.client.get(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510001')['id']}").text
    assert "отпечаток кода не сохранён" in page
    assert "Код в клоне не тот, который вы видели" not in page


def test_defect_refusal_for_a_decision_without_code_print_names_the_real_reason(web):  # noqa: F811
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    case = db.get_case(pid, "510001")
    db.save_review(pid, "510001", decision="disagree", final_verdict="true_positive",
                   final_comment="Подтверждено: owner из запроса попадает в SQL без параметров.",
                   reviewed=False, final_fix="Параметризовать запрос.", verdict_id=case["verdict_id"])
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    from test_web import ORIGIN
    r = web.client.post(f"/projects/{pid}/findings/{fid}/defect", data={"number": "", "part": "body"},
                        headers={**ORIGIN, "Accept": "application/json"})
    assert r.status_code == 409, r.text
    assert "отпечаток кода не сохранён" in r.json()["detail"]

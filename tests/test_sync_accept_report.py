"""Предпросмотр и итог «Принять состояние Hub» (0.10.0.dev15, план п. 1.4–1.5): предпросмотр называет решения
приложения, которые Hub заменит; итог считает решения, ушедшие в историю, и остаток; шаг «Состояние Hub» пишет
«принято с ошибкой», если после принятия у принятого объекта осталось отличие."""
from app import hub_onboarding, hub_pull as pull
from app.db import dumps, loads
from test_hub_status_routes import HUB, decide, project, sast
from test_sync_golden_path import LiveHub, synced, synchronize
from test_web import web  # noqa: F401


def sync_run(db, rid):
    return db._one("SELECT * FROM hub_defect_sync_runs WHERE id=?", (rid,))


def test_preview_names_replaced_decisions_and_result_counts_saved(web):
    db = web.app.state.db
    hub = LiveHub(3)
    pid = project(web, [sast("1"), sast("2", line=5), sast("3", line=8)])
    synchronize(db, pid, hub)
    decide(web, pid, "1", comment="Основание оператора")  # Hub поставит другое основание – заменится
    decide(web, pid, "2")  # в Hub решения нет – остаётся «не отправлено», не заменяется
    hub.decision(1, status="False Positive", reason="Основание Hub")
    row = synced(db, pid, hub)
    preview = pull.preview(db, row)
    assert preview["replaced"]["count"] == 1, preview["replaced"]
    item = preview["replaced"]["items"][0]
    fid = db._one("SELECT id FROM findings WHERE project_id=? AND hub_id='1'", (pid,))["id"]
    assert item == {"key": "SAST:1", "hub_id": "1", "url": f"/projects/{pid}/findings/{fid}"}
    result = pull.apply(db, row["id"], preview["token"])
    assert result["saved"] == 1 and result["residue"] == [], result
    state = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert state["state"] == "accepted" and state["saved"] == 1, state
    page = web.client.get(f"/projects/{pid}/hub-pending")
    assert page.status_code == 200 and "SAST:1" in page.text and "сохранено до принятия состояния Hub" in page.text


def test_residue_after_accept_is_named_as_application_error(web):
    """Остаток после принятия – ошибка приложения: шаг не «принято», а «принято с ошибкой» с объектами."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    row = synchronize(db, pid, hub)
    result = loads(db._one("SELECT result_json FROM hub_defect_sync_runs WHERE id=?", (row["id"],))["result_json"], {})
    assert result["residue"] == []
    with db._tx() as c:
        c.execute("UPDATE hub_defect_sync_runs SET result_json=? WHERE id=?",
                  (dumps({**result, "residue": ["issue:SAST:2"]}), row["id"]))
    state = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert state["state"] == "accepted_error" and not state["done"] and state["residue"] == ["issue:SAST:2"], state
    assert state["label"] == hub_onboarding.LABELS["accepted_error"]


def test_operator_decision_hub_never_had_is_unsent_after_first_accept(web):
    """Решение оператора принято до первой синхронизации, в Hub решения нет: это новая запись из приложения – «ждёт отправки» и до принятия, и после него; остатком и ошибкой она не считается."""
    from test_sync_golden_path import assert_synced
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    decide(web, pid, "1")
    row = synced(db, pid, hub)
    diff = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SAST:1'",
                         (row["id"],))["diff_json"], {})
    # до первого принятия базы нет – рядом законно стоит «базовая версия неизвестна»
    assert diff["groups"] == ["pending", "unknown_base"] and diff["delivery"]["state"] == "unsent", diff
    pull.apply(db, row["id"], pull.preview(db, row)["token"])
    assert db.get_review(pid, "1")["final_verdict"] == "false_positive"  # не заменено
    assert_synced(db, row, unsent=["SAST:1"])
    assert hub_onboarding.state(db, db.get_project(pid), HUB)["state"] == "accepted"


def test_delivered_decision_removed_by_hub_stays_sent(web):
    """Решение доставлено в Hub, потом Hub его снял (вернул на проверку). Правило: Hub ответил
    «принято» – решение отправлено, процесс закончен. Без решения Hub разбор приложения не трогается:
    решение остаётся, отметка «Внесено» снимается; рядом видно отличие от Hub; после принятия это не остаток."""
    from test_hub_status_routes import send
    from test_sync_golden_path import assert_synced, drain
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    assert send(web, pid, "1").status_code == 200
    drain(db, hub)
    hub.issues[1]["status"] = "To verify"  # в Hub решение сняли
    hub.issues[1]["issueBranchBriefData"][0]["status"] = "To verify"
    hub.manual.pop(1, None)
    row = synchronize(db, pid, hub)
    review = db.get_review(pid, "1")
    assert review["final_verdict"] == "false_positive" and not review["entered_hub"], dict(review)
    assert not db._all("SELECT id FROM hub_sync_pending WHERE project_id=? AND entity_key='SAST:1'", (pid,))
    assert_synced(db, row, sent=["SAST:1"])  # «Отправлено в Hub» с отличием рядом, остатка нет
    assert hub_onboarding.state(db, db.get_project(pid), HUB)["state"] == "accepted"
    # обзор проекта и страница чтения Hub говорят то же, что списки (ревью кода dev15, круг 9)
    overview = web.client.get(f"/projects/{pid}").text
    assert "отправлено в Hub 1" in overview and "а в Hub другое" not in overview
    page = web.client.get(f"/projects/{pid}/hub-sync/{row['id']}").text
    assert 'class="hub-sync-delivery">Отправлено в Hub<' in page


def test_read_before_delivery_does_not_replace_the_decision(web):
    """Чтение сделано до доставки решения: о снятии оно не говорит. Доставка меняет принятую базу, и принять такое
    чтение нельзя – нужен новый обход (защита ADR-0127); решение оператора не тронуто, на страницах – «Отправлено в
    Hub»."""
    import pytest
    from test_hub_status_routes import send
    from test_sync_golden_path import drain
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    row = synced(db, pid, hub)  # чтение до отправки
    assert send(web, pid, "1").status_code == 200
    drain(db, hub)
    from app import hub_sync_compare as compare
    compare.recompare(db, row["id"])  # принятие требует пересчёта после локальных изменений
    diff = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SAST:1'",
                         (row["id"],))["diff_json"], {})
    assert diff["delivery"]["state"] == "sent" or diff["groups"] == ["stale"], diff
    with pytest.raises(ValueError, match="нужен новый обход"):
        pull.apply(db, row["id"], pull.preview(db, sync_run(db, row["id"]))["token"])
    assert db.get_review(pid, "1")["final_verdict"] == "false_positive"
    from app import hub_state
    assert hub_state.project_states(db, db.get_project(pid), HUB)["by_hub_id"]["1"]["delivery"]["state"] == "sent"


def test_contradiction_only_run_is_accepted_not_special(web):
    """Ветки «только противоречия Hub» больше нет: противоречие – пометка, находка принимается (план п. 1.2)."""
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    hub.decision(1, status="False Positive", reason="Основание в Hub.")
    hub.issues[1]["status"] = "Open"
    hub.issues[1]["issueBranchBriefData"][0]["status"] = "Open"
    synchronize(db, pid, hub)
    state = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert state["state"] == "accepted" and "contradictions" not in state, state
    assert "hub_only" not in hub_onboarding.LABELS and "hub_only" not in hub_onboarding.DONE

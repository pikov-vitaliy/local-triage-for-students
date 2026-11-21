"""Ревью кода 0.10.0.dev15, круг 1 (Codex xhigh 0/11/3, Kimi high 0/5/1): регрессии на каждую подтверждённую находку.
Данные выдуманные: поддельный Hub."""
import re
from types import SimpleNamespace

import pytest

from app import hub_onboarding, hub_pull as pull, hub_state, hub_sync_compare as compare
from app.db import dumps, loads
from db_support import record_queries
from test_hub_status_routes import HUB, decide, project, sast, sca, send
from test_sync_golden_path import LiveHub, assert_synced, drain, synced, synchronize
from test_sync_saved_edits import restore_saved
from test_web import ORIGIN, web  # noqa: F401


def states(db, pid, keys=None):
    return hub_state.project_states(db, db.get_project(pid), HUB, keys)


def fid(db, pid, hub_id):
    return db._one("SELECT id FROM findings WHERE project_id=? AND hub_id=?", (pid, hub_id))["id"]


def listed_entered(db, pid, hub_id) -> int:
    """Отметка «Внесено в Hub» так, как её видит список (с проверкой подтверждающей операции)."""
    rows, _ = db.list_findings(pid, ids=(fid(db, pid, hub_id),), limit=1)
    return int(rows[0]["entered_hub"])


def discard(web, pid, pending_id):
    page = web.client.get(f"/projects/{pid}/hub-pending/{pending_id}").text
    token = re.search(r'name="confirmation" value="([^"]*)"', page).group(1)
    return web.client.post(f"/projects/{pid}/hub-pending/{pending_id}", headers=ORIGIN, follow_redirects=False,
                           data={"action": "discard", "confirm": "yes", "confirmation": token})


def saved_id(db, pid, key="SAST:1"):
    return db._one("SELECT id FROM hub_sync_pending WHERE project_id=? AND entity_key=? AND state='saved'",
                   (pid, key))["id"]


def replaced_by_hub(web):
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    synchronize(db, pid, hub)
    decide(web, pid, "1", comment="Основание оператора")
    hub.decision(1, status="False Positive", reason="Основание Hub")
    synchronize(db, pid, hub)  # Hub заменил решение: правка – в истории, отметка «Внесено» – по записи Hub
    return db, pid, hub


# ---------------------------------------------------------------------------- история: Codex 1, 2, 3, 9; Kimi 1, 6


def test_discard_restored_returns_hub_decision_with_valid_mark(web):
    db, pid, _ = replaced_by_hub(web)
    assert listed_entered(db, pid, "1") == 1
    ident = saved_id(db, pid)
    restore_saved(web, pid, ident)
    assert db.get_review(pid, "1")["final_comment"] == "Основание оператора"
    assert discard(web, pid, ident).status_code in (302, 303)
    review = db.get_review(pid, "1")
    assert review["final_comment"] == "Основание Hub" and review["decision_origin"] == "hub_sync", dict(review)
    assert listed_entered(db, pid, "1") == 1  # отметка действует: со ссылкой на операцию чтения принятого наблюдения


def test_discard_after_newer_edit_keeps_operator_work(web):
    """Восстановить A → сохранить B → открыть A заново → отбросить A: B остаётся."""
    db, pid, _ = replaced_by_hub(web)
    ident = saved_id(db, pid)
    restore_saved(web, pid, ident)
    decide(web, pid, "1", comment="Основание B")
    response = discard(web, pid, ident)
    assert response.status_code in (302, 303) and "pending_kept" in response.headers["location"]
    assert db.get_review(pid, "1")["final_comment"] == "Основание B"


def test_discard_restored_draft_refused_while_push_unconfirmed(web):
    from app import defect_drafts
    from test_hub_pull import PullHub, accept, read
    db = web.app.state.db
    pid = db.create_project("Демо черновика")
    db.update_project(pid, hub_app_id=7)
    db.set_settings({"hub_url": HUB})
    hub = PullHub()
    accept(db, read((db, pid), hub))
    owner = db._one("SELECT * FROM hub_defects")
    defect_drafts.save(db, owner, str(owner["draft_revision"]), summary="Новая правка", command="Новый текст")
    hub.defects[77]["summary"] = "Заголовок другого оператора"
    accept(db, read((db, pid), hub))
    pending = db._one("SELECT * FROM hub_sync_pending WHERE state='saved'")
    target = {"project_id": pid, "hub_url": HUB, "app_id": 7}
    pull.restore(db, target, pending["id"], pull.pending_context(db, target, pending["id"])["confirmation"])
    db.hub_defect_update(owner["id"], update_json=dumps({"phase": "unknown", "note": "ответа от Hub нет"}))
    token = pull.pending_context(db, target, pending["id"])["confirmation"]
    with pytest.raises(ValueError, match="дождитесь"):
        pull.restore(db, target, pending["id"], token, discard=True)
    assert db._one("SELECT state FROM hub_sync_pending WHERE id=?", (pending["id"],))["state"] == "restored"


def test_saved_decision_without_expiry_stays_history_when_hub_has_expiry(web):
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    synchronize(db, pid, hub)
    decide(web, pid, "1", comment="Одно основание")
    hub.decision(1, status="False Positive", reason="Одно основание")  # то же основание, но в Hub есть срок
    row = synchronize(db, pid, hub)
    result = loads(db._one("SELECT result_json FROM hub_defect_sync_runs WHERE id=?", (row["id"],))["result_json"], {})
    saved = db._all("SELECT state FROM hub_sync_pending WHERE project_id=? AND entity_key='SAST:1'", (pid,))
    assert [s["state"] for s in saved] == ["saved"] and result["saved"] == 1, (saved, result)


def test_pending_list_shows_every_open_edit_by_pages(web):
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    row = synchronize(db, pid, hub)
    with db._tx() as c:
        for i in range(1100):
            c.execute("INSERT INTO hub_sync_pending(project_id,hub_url,app_id,entity_kind,entity_key,signature,"
                      "payload_json,state,created_run_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                      (pid, HUB, 7, "issue", f"SAST:{1000 + i}", f"s{i}", "{}", "saved" if i < 1000 else "delivered",
                       row["id"], "2026-11-08T10:00:00+00:00"))
    first = web.client.get(f"/projects/{pid}/hub-pending").text
    assert "Действующие (1000)" in first and 'id="hub-pending-next"' in first
    assert "Закрытые (100)" in first
    last = web.client.get(f"/projects/{pid}/hub-pending?page=5").text
    assert "SAST:1000<" in last and "Страница 5 из 5" in last


# ---------------------------------------------------------------------------- сравнение: Kimi 2, 3; Codex 7, 8, 14


def test_legacy_decision_without_origin_is_unsent_after_accept(web):
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    decide(web, pid, "1")
    with db._tx() as c:
        c.execute("UPDATE reviews SET decision_origin='' WHERE project_id=? AND hub_id='1'", (pid,))
    row = synchronize(db, pid, hub)
    assert_synced(db, row, unsent=["SAST:1"])
    assert hub_onboarding.state(db, db.get_project(pid), HUB)["state"] == "accepted"


def test_accepted_absence_keeps_unsent_decision_visible(web):
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    hub.issues.pop(1)  # в Hub находки больше нет: список без неё, по ID – 404
    row = synchronize(db, pid, hub)
    diff = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SAST:1'",
                         (row["id"],))["diff_json"], {})
    assert diff["groups"] == ["pending"] and diff["delivery"]["state"] == "unsent", diff
    assert states(db, pid)["by_hub_id"]["1"]["delivery"]["state"] == "unsent"


def test_delivery_stays_sent_when_parts_straddle_the_send():
    local = {"review": {"decision_origin": "operator"}, "status_intent": {"op_id": 101, "state": "done"}}
    sources = {"detail": {"op_id": 100}, "manual": {"op_id": 102}}
    assert compare.delivery_of("issue", "SAST:1", local, {"groups": ["local_only"]}, None, sources)["state"] == "sent"
    after = {"detail": {"op_id": 103}, "manual": {"op_id": 104}}
    # круг 8: Hub показывает доставленное решение – совпадение, сведений отправки нет; порядок по номерам не нужен
    assert compare.delivery_of("issue", "SAST:1", local, {"groups": ["matched"]}, None, after)["state"] is None


@pytest.mark.parametrize("phase, expected", [("unknown", "unconfirmed"), ("unconfirmed", "unconfirmed"),
                                             ("failed", "refused"), ("putting", "unconfirmed"), ("", "unsent")])
def test_defect_delivery_follows_push_phase(phase, expected):
    # круг 3: «выполняется» – только при операции шага в очереди; фаза без операции – «не подтверждено»
    local = {"owner": {"update_json": dumps({"phase": phase, "note": "Hub не принял: отказ"}) if phase else "{}"}}
    found = compare.delivery_of("defect", "77", local, {"groups": ["pending"], "current_pending": True}, None)
    assert found["state"] == expected, found
    if expected == "refused":
        assert found["error"] == "Hub не принял: отказ"


def test_unknown_outcome_names_the_existing_button():
    context = SimpleNamespace(last_status={"SAST:1": {"id": 5, "state": "unknown", "created_at": "2026-11-08T10:00:00+00:00",
                                                      "error": ""}})
    found = compare.causes("issue", "SAST:1", {"review": {}}, {"groups": ["pending"], "current_pending": True}, context)
    assert any("«Pull из Hub»" in c for c in found) and not any("«Сверить»" in c for c in found), found


# ---------------------------------------------------------------------------- страницы: Codex 4, 5, 6, 11, 12, 13; Kimi 4, 5


def test_coincident_does_not_hide_other_differences():
    st = hub_state._state(1, 5, "issue", "SAST:1", {"groups": ["coincident", "observed"]}, {})
    assert st["differs"] and st["badges"] == [{"text": compare.LABELS["observed"], "tone": "accent"}], st
    st = hub_state._state(1, 5, "issue", "SAST:1", {"groups": ["coincident"]}, {})
    assert not st["differs"] and st["badges"] == []


def tamper(db, rid, key, diff=None, version=None):
    with db._tx() as c:
        if diff is not None:
            c.execute("UPDATE hub_sync_items SET diff_json=? WHERE run_id=? AND entity_key=?", (dumps(diff), rid, key))
        if version is not None:
            run_json = loads(c.execute("SELECT run_json FROM hub_defect_sync_runs WHERE id=?", (rid,)).fetchone()[0], {})
            c.execute("UPDATE hub_defect_sync_runs SET run_json=? WHERE id=?",
                      (dumps({**run_json, "compare_version": version}), rid))


def test_saved_comparison_of_other_version_or_after_expiry_is_recomputed(web):
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    row = synchronize(db, pid, hub)
    forged = {"groups": ["conflict"], "fields": [], "causes": [], "delivery": {"state": None}}
    tamper(db, row["id"], "SAST:1", forged)
    assert states(db, pid)["by_hub_id"]["1"]["group"] == "conflict"  # тот же расчёт – сохранённое берётся как есть
    tamper(db, row["id"], "SAST:1", version=compare.COMPARE_VERSION - 1)
    assert states(db, pid)["by_hub_id"]["1"]["group"] == "matched"  # другой расчёт – объект считается заново
    tamper(db, row["id"], "SAST:1", {**forged, "valid_until": 1}, version=compare.COMPARE_VERSION)
    assert states(db, pid)["by_hub_id"]["1"]["group"] == "matched"  # срок записи Hub наступил – заново


def test_other_type_with_the_same_number_does_not_replace_state(web):
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    row = synchronize(db, pid, hub)
    with db._tx() as c:
        c.execute("INSERT INTO hub_sync_items(run_id,entity_kind,entity_key,hub_json,diff_json,local_signature)"
                  " VALUES (?,'issue','SCA_S:1','{}',?,'x')", (row["id"], dumps({"groups": ["new"]})))
    found = states(db, pid)
    assert found["by_hub_id"]["1"]["key"] == "SAST:1" and ("issue", "SCA_S:1") in found["items"]


def test_new_finding_after_read_has_the_same_groups_as_recompare(web):
    from app.triage import order_findings
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    row = synchronize(db, pid, hub)
    db.save_import(pid, "repeat.xlsx", "xlsx", [], {}, [], order_findings([sast("1"), sast("2", line=5), sast("3", line=8)]))
    before = states(db, pid)["by_hub_id"]["3"]
    compare.recompare(db, row["id"])
    stored = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SAST:3'",
                           (row["id"],))["diff_json"], {})
    assert before["groups"] == stored["groups"] == ["stale"], (before["groups"], stored["groups"])
    assert before["read"] == "missing"


def test_summary_counts_defects_apart_from_findings():
    states_ = {("issue", "SAST:1"): hub_state._state(1, 5, "issue", "SAST:1", {"groups": ["matched"]}, {}),
               ("defect", "77"): hub_state._state(1, 5, "defect", "77", {"groups": ["changed"]}, {})}
    run = {"id": 5, "created_at": "2026-11-08T10:00:00+00:00", "applied_at": None,
           "run_json": dumps({"inventory_complete": True, "details_complete": True})}
    summary = hub_state._summary(1, run, None, states_, False, True)
    assert summary["differs"] == 0 and summary["defects"] == {"unsent": 0, "queued": 0, "unconfirmed": 0, "refused": 0, "differs": 1}, summary
    assert not summary["all_match"]


def test_legacy_pending_rows_do_not_add_queries_per_row(web):
    from test_hub_pull_pending import legacy_pending
    db = web.app.state.db
    hub = LiveHub(12)
    pid = project(web, [sast(str(i), line=i + 1) for i in range(1, 13)])
    row = synchronize(db, pid, hub)
    run_row = db._one("SELECT * FROM hub_defect_sync_runs WHERE id=?", (row["id"],))
    context = db.on_connection(lambda c: compare.ComparisonContext(c, run_row))

    def legacy(ident):
        issue = dict(context.issue_local(f"SAST:{ident}"))
        issue.pop("review_after_base", None)
        issue["status_intent"] = {"op_id": 1, "body": {"status": "False Positive", "reason": "x", "expiredAt": "y"}}
        legacy_pending(db, row["id"], "issue", f"SAST:{ident}", issue, {"detail": {"status": "Open"}},
                       loads(issue["state"]["confirmed_json"], {}))

    def count():
        queries = []
        stop = record_queries(queries)
        states(db, pid)
        stop()
        return len(queries)
    legacy(1)
    legacy(2)
    few = count()
    for ident in range(3, 13):
        legacy(ident)
    # десять строк прежнего формата при запросе на строку добавили бы не меньше десяти запросов; небольшой допуск –
    # на запросы, зависящие от времени (кэш настроек)
    assert count() - few < 5, (few, count())


def test_card_shows_hub_notes_when_matched(web):
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    hub.decision(1, status="False Positive", reason="Основание в Hub.")
    hub.issues[1]["status"] = "Open"  # противоречие на стороне Hub
    hub.issues[1]["issueBranchBriefData"][0]["status"] = "Open"
    synchronize(db, pid, hub)
    card = web.client.get(f"/projects/{pid}/findings/{fid(db, pid, '1')}").text
    assert "Совпадает с последним чтением Hub" in card and "В Hub: подробный статус и ручная запись" in card


def test_never_read_card_says_sent_after_delivery(web):
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    decide(web, pid, "1")
    assert send(web, pid, "1").status_code == 200
    drain(db, hub)
    st = states(db, pid)["by_hub_id"]["1"]
    assert st["read"] == "never" and st["delivery"]["state"] == "sent", st
    card = web.client.get(f"/projects/{pid}/findings/{fid(db, pid, '1')}").text
    assert "Решение отправлено в Hub" in card and "в Hub не отправлялось" not in card


# ---------------------------------------------------------------------------- навигация SCA: Codex 10


def test_sca_card_navigation_stays_inside_hub_filter(web):
    db = web.app.state.db
    pid = project(web, [sca("201"), sca("202"), sca("203")])
    for ident in ("201", "203"):  # решения есть, в Hub не отправлены; у 202 решения нет
        decide(web, pid, ident, decision="disagree", verdict="false_positive")
    with db._tx() as c:
        c.execute("UPDATE reviews SET reviewed=0 WHERE project_id=?", (pid,))  # обход – по непроверенным
    back = f"/projects/{pid}/findings?hubsync=unsent"
    card = web.client.get(f"/projects/{pid}/sca/findings/{fid(db, pid, '201')}", params={"back": back}).text
    target = re.search(r'id="nav-next" href="/projects/\d+/sca/findings/(\d+)', card).group(1)
    assert int(target) == fid(db, pid, "203"), target
    plain = web.client.get(f"/projects/{pid}/sca/findings/{fid(db, pid, '201')}").text
    assert int(re.search(r'id="nav-next" href="/projects/\d+/sca/findings/(\d+)', plain).group(1)) == fid(db, pid, "202")


# ---------------------------------------------------------------------------- настоящий остаток (Codex и Kimi: тест)


def test_real_residue_after_accept_is_named(web, monkeypatch):
    """Остаток вычисляется самим принятием: при строгом наборе допустимых групп совпадение – остаток."""
    monkeypatch.setattr(pull, "AFTER_ACCEPT", ("pending",))
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    row = synchronize(db, pid, hub)
    result = loads(db._one("SELECT result_json FROM hub_defect_sync_runs WHERE id=?", (row["id"],))["result_json"], {})
    assert result["residue"] == ["issue:SAST:1"], result
    state = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert state["state"] == "accepted_error" and state["residue"] == ["issue:SAST:1"]
    synced(db, pid, hub)

def test_current_branch_status_is_the_decision_not_reference_data():
    """Статус текущей ветки – тот же статус решения: отправленное решение не выглядит «изменением прочих сведений Hub»;
    статус другой ветки – справочное сведение."""
    def detail(main, other):
        return {"detail": {"status": main, "currentBranch": "main", "issueBranchBriefData": [
            {"branch": "main", "status": main}, {"branch": "develop", "status": other}]}}
    base, sent = compare.observed_issue_values(detail("To verify", "Open")), compare.observed_issue_values(detail("False Positive", "Open"))
    assert base == sent
    assert compare.observed_issue_values(detail("To verify", "Fixed")) != base

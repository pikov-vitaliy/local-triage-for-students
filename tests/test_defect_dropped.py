"""Находка, выбывшая из дефекта, ждёт решения оператора (схема 33); «Внесено в Hub» – только по
подтверждённым связям. Данные выдуманные."""

import re

from app.db import loads
from test_defect import save_sast
from test_hub_defect_guard import created
from test_hub_defect_update import deliver, hub_body, read_job, ready, sent_body, to_put
from test_hub_defects import FIX, REASON, pair_project
from test_hub_pull import accept, read
from test_hub_review_round1 import project_hub
from test_web import ORIGIN, web  # noqa: F401


def finding_id(db, pid, hub_id):
    return db._scalar("SELECT id FROM findings WHERE project_id=? AND hub_id=?", (pid, hub_id))


def test_unlinked_in_hub_is_dropped_shown_and_kept_until_the_operator_decides(web):
    pid = pair_project(web)
    db = web.app.state.db
    urls = {ident: save_sast(web, pid, ident, "true_positive", "", REASON, FIX)[0] for ident in ("510001", "510005")}
    defect = created(web, pid, urls["510001"], links=(510001, 510005))
    body = loads(defect["confirmed_object_json"], {})
    body["linkedIssues"] = [link for link in body["linkedIssues"] if link["id"] != 510001]
    accept(db, read((db, pid), project_hub(db, pid, [body])))

    review = db.get_review(pid, "510001")
    assert review["entered_hub"] == 0
    info = review["dropped_info"]
    assert info["defect_id"] == defect["id"] and info["via"] == "sync" and info["number"] == defect["number"]
    assert db.get_review(pid, "510005")["dropped_info"] == {}, "оставшаяся в составе находка без пометки"
    history = db._all("SELECT details_json FROM hub_defect_history WHERE defect_id=? AND event='hub_sync'", (defect["id"],))
    assert loads(history[-1]["details_json"], {})["dropped"] == ["510001"]

    card = web.client.get(urls["510001"]).text
    assert 'id="defect-dropped"' in card and "Оставить как есть" in card
    assert f'/projects/{pid}/defects/{defect["id"]}' in card
    assert 'id="defect-dropped"' not in web.client.get(urls["510005"]).text
    listing = web.client.get(f"/projects/{pid}/findings?dropped=1").text
    assert f'id="finding-{finding_id(db, pid, "510001")}"' in listing
    assert f'id="finding-{finding_id(db, pid, "510005")}"' not in listing
    assert "выбыла из дефекта</span>" in listing and "выбыли из дефекта" in listing
    page = web.client.get(f"/projects/{pid}/defects/{defect['id']}").text
    assert 'id="defect-dropped-list"' in page and ">510001</a>" in page
    defects = web.client.get(f"/projects/{pid}/defects").text
    assert 'id="defects-dropped"' in defects and "?dropped=1" in defects

    # показанная пометка устарела – отказ; та же – снята, решение и отметки не меняются
    fid = finding_id(db, pid, "510001")
    stale = web.client.post(f"/projects/{pid}/findings/{fid}/defect-dropped/clear", data={"dropped_shown": "{}"}, headers=ORIGIN,
                            follow_redirects=False)
    assert stale.status_code == 409 and db.get_review(pid, "510001")["dropped_info"]
    before = db.get_review(pid, "510001")
    shown = re.search(r'name="dropped_shown" value="([^"]*)"', card).group(1).replace("&#34;", '"')
    done = web.client.post(f"/projects/{pid}/findings/{fid}/defect-dropped/clear", data={"dropped_shown": shown}, headers=ORIGIN,
                           follow_redirects=False)
    assert done.status_code == 303 and "defect_dropped_cleared" in done.headers["location"]
    after = db.get_review(pid, "510001")
    assert after["dropped_info"] == {} and after["revision"] == before["revision"]
    assert {k: v for k, v in after.items() if k not in ("defect_dropped", "dropped_info")} == {
        k: v for k, v in before.items() if k not in ("defect_dropped", "dropped_info")}
    assert 'id="defects-dropped"' not in web.client.get(f"/projects/{pid}/defects").text


def test_saved_decision_clears_the_mark(web):
    pid = pair_project(web)
    db = web.app.state.db
    urls = {ident: save_sast(web, pid, ident, "true_positive", "", REASON, FIX)[0] for ident in ("510001", "510005")}
    defect = created(web, pid, urls["510001"], links=(510001, 510005))
    body = loads(defect["confirmed_object_json"], {})
    body["linkedIssues"] = [link for link in body["linkedIssues"] if link["id"] != 510001]
    accept(db, read((db, pid), project_hub(db, pid, [body])))
    assert [d["hub_id"] for d in db.dropped_findings(pid, defect["id"])] == ["510001"]
    save_sast(web, pid, "510001", "false_positive", "", REASON, "")
    assert db.get_review(pid, "510001")["dropped_info"] == {} and db.dropped_findings(pid) == []
    # дефекта в Hub больше нет – выбывает и оставшаяся находка
    accept(db, read((db, pid), project_hub(db, pid, [])))
    assert [(d["hub_id"], d["dropped_info"]["via"]) for d in db.dropped_findings(pid)] == [("510005", "sync")]


def test_update_marks_only_confirmed_links_and_drops_the_rest(web):
    """«Push в Hub» у дефекта, из которого в Hub убрали находку без синхронизации: подтверждение не ставит ей
    «Внесено в Hub» и номер ключу, а помечает её выбывшей."""
    pid, row = ready(web)
    db = web.app.state.db
    with db._tx() as c:  # номер ID5 у ключа от прежнего подтверждения (ревью 31.10, B2)
        c.execute("INSERT INTO defects(project_id,defect_key,number,updated_at,assigned_at) VALUES (?,?,5,'x','x')",
                  (pid, "sast:510001"))
    unlinked = hub_body(links=())
    put = to_put(web, pid, row, first=unlinked, second=unlinked)
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"], links=()))
    review = db.get_review(pid, "510001")
    assert review["entered_hub"] == 0 and db.defect_number(pid, "sast:510001") is None
    assert review["dropped_info"]["via"] == "confirm" and review["dropped_info"]["defect_id"] == row["id"]
    fresh = db.hub_defect(row["id"])
    assert loads(fresh["targets_json"], []) == [] and loads(fresh["number_keys_json"], []) == []


def test_absent_defect_keeps_no_live_targets_and_late_effects_do_not_restore_marks(web):
    """Ревью 31.10 (A1, B1): после принятого отсутствия позднее последствие прежнего подтверждения не возвращает
    отметку и не стирает пометку; после «Оставить как есть» новая синхронизация не помечает снова."""
    from app import hub_defects
    pid = pair_project(web)
    db = web.app.state.db
    urls = {ident: save_sast(web, pid, ident, "true_positive", "", REASON, FIX)[0] for ident in ("510001", "510005")}
    defect = created(web, pid, urls["510001"], links=(510001, 510005))
    keys = loads(db.hub_defect(defect["id"])["number_keys_json"], [])
    assert keys and all(db.defect_number(pid, k) == defect["number"] for k in keys)
    created_row = db.hub_defect(defect["id"])  # строка, прочитанная доставкой до принятия отсутствия
    with db._tx() as c:  # последствия подтверждения не доведены (сбой) – после отсутствия их не довести
        c.execute("UPDATE hub_defects SET effects_done=0 WHERE id=?", (defect["id"],))
    accept(db, read((db, pid), project_hub(db, pid, [])))
    hub_defects._apply_effects(db, created_row, "")
    absent_row = db.hub_defect(defect["id"])
    assert loads(absent_row["targets_json"], []) == [] and loads(absent_row["number_keys_json"], []) == []
    assert absent_row["effects_done"] == 1 and all(db.defect_number(pid, k) is None for k in keys)
    hub_defects._apply_effects(db, db.hub_defect(defect["id"]), "")
    assert all(db.defect_number(pid, k) is None for k in keys), "позднее последствие не возвращает номер"
    for ident in urls:
        review = db.get_review(pid, ident)
        assert review["entered_hub"] == 0 and review["dropped_info"]["via"] == "sync"
    for ident in urls:
        assert db.clear_defect_dropped(pid, ident, db.get_review(pid, ident)["defect_dropped"])
    accept(db, read((db, pid), project_hub(db, pid, [])))
    assert db.dropped_findings(pid) == []


def test_failed_link_type_change_and_other_defect(web):
    """Ревью 31.10: неудавшаяся привязка в составе не была (A2); смена типа связи – выбытие (B3); находка в
    подтверждённом составе другого дефекта не помечается, принятая связь снимает пометку (B4)."""
    from app import hub_pull as pull
    pid = pair_project(web)
    db = web.app.state.db
    urls = {ident: save_sast(web, pid, ident, "true_positive", "", REASON, FIX)[0] for ident in ("510001", "510005")}
    defect = created(web, pid, urls["510001"], links=(510001, 510005))
    with db._tx() as c:
        c.execute("UPDATE reviews SET entered_hub=0, entered_origin='', entered_defect_id=NULL WHERE project_id=?", (pid,))
        c.execute("INSERT INTO hub_defects(project_id,kind,state,origin,hub_url,app_id,hub_defect_id,draft_owner_id,"
                  "targets_json,created_at,updated_at) SELECT project_id,kind,'failed',origin,hub_url,app_id,hub_defect_id,"
                  "id,?,created_at,updated_at FROM hub_defects WHERE id=?",
                  ('[{"hub_id": "510003", "issue_type": "SAST"}]', defect["id"]))
    body = loads(defect["confirmed_object_json"], {})
    body["linkedIssues"] = [link if link["id"] != 510001 else {**link, "type": "SCA_S"} for link in body["linkedIssues"]]
    accept(db, read((db, pid), project_hub(db, pid, [body])))
    assert [d["hub_id"] for d in db.dropped_findings(pid)] == ["510001"], "без отметки, по смене типа; 510003 – нет"
    other = {**db.hub_defect(defect["id"]), "id": defect["id"] + 1000}
    with db._tx() as c:
        assert pull.mark_dropped(c, other, {"510005"}, "sync") == []
        # 510001 в составе – только связью SCA_S (другая находка Hub): локальная находка SAST помечается
        assert pull.mark_dropped(c, other, {"510001"}, "sync") == ["510001"]
        # дефект прежнего экземпляра Hub не мешает пометке в текущем (ревью круга 7, B)
        assert pull.mark_dropped(c, {**other, "hub_url": "http://hub-2.example"}, {"510005"}, "sync") == ["510005"]
        c.execute("UPDATE reviews SET defect_dropped='' WHERE project_id=? AND hub_id='510005'", (pid,))
    body["linkedIssues"] = [{**link, "type": "SAST"} for link in body["linkedIssues"]]
    accept(db, read((db, pid), project_hub(db, pid, [body])))
    assert db.dropped_findings(pid) == [], "связь снова прочитана и принята – пометка снята"


def test_late_effect_of_an_accepted_row_and_other_type_link(web):
    """Ревью 31.10, круг 3: строка с принятым синхронизацией составом (цели без происхождения), прочитанная до
    принятия отсутствия, не возвращает номер (A); связь другого типа с тем же номером, ушедшая из дефекта, не помечает
    локальную находку (B)."""
    from app import hub_defects
    pid = pair_project(web)
    db = web.app.state.db
    urls = {ident: save_sast(web, pid, ident, "true_positive", "", REASON, FIX)[0] for ident in ("510001", "510005")}
    defect = created(web, pid, urls["510001"], links=(510001, 510005))
    body = loads(defect["confirmed_object_json"], {})
    body["linkedIssues"] = [link if link["id"] != 510005 else {**link, "type": "SCA_S"} for link in body["linkedIssues"]]
    accept(db, read((db, pid), project_hub(db, pid, [body])))
    accepted = db.hub_defect(defect["id"])
    keys = loads(accepted["number_keys_json"], [])
    assert keys and not any(t.get("entered_origin") for t in loads(accepted["targets_json"], []))
    assert [d["hub_id"] for d in db.dropped_findings(pid)] == ["510005"]
    assert db.clear_defect_dropped(pid, "510005", db.get_review(pid, "510005")["defect_dropped"])
    body["linkedIssues"] = [link for link in body["linkedIssues"] if link["id"] != 510005]
    accept(db, read((db, pid), project_hub(db, pid, [body])))
    assert db.dropped_findings(pid) == [], "ушла связь SCA_S:510005 – локальная SAST-находка в дефект не входила"
    stale = db.hub_defect(defect["id"])
    accept(db, read((db, pid), project_hub(db, pid, [])))
    assert all(db.defect_number(pid, k) is None for k in keys)
    hub_defects._apply_effects(db, stale, "")
    assert all(db.defect_number(pid, k) is None for k in keys), "прочитанная раньше строка не возвращает номер"


def test_late_effect_of_a_schema28_target_keeps_the_mark(web):
    """Ревью 31.10, круг 4: строка с целями схемы 28 (без происхождения, с отпечатком текста) и недоведёнными
    последствиями, прочитанная до принятия отсутствия, не ставит «Внесено в Hub» и не снимает пометку «выбыла»."""
    import json
    from app import hub_defects
    pid = pair_project(web)
    db = web.app.state.db
    urls = {ident: save_sast(web, pid, ident, "true_positive", "", REASON, FIX)[0] for ident in ("510001", "510005")}
    defect = created(web, pid, urls["510001"], links=(510001, 510005))
    legacy = [{k: v for k, v in t.items() if k not in ("entered_origin", "entered_defect_id", "entered_op_id",
                                                        "entered_defect_revision")}
              for t in loads(defect["targets_json"], [])]
    assert legacy and all(t.get("entered_hash") for t in legacy)
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET targets_json=?, effects_done=0 WHERE id=?", (json.dumps(legacy), defect["id"]))
        c.execute("UPDATE reviews SET entered_hub=0, entered_hub_at=NULL, entered_origin='', entered_defect_id=NULL,"
                  " entered_op_id=NULL, entered_text_hash='' WHERE project_id=?", (pid,))
    stale = db.hub_defect(defect["id"])
    accept(db, read((db, pid), project_hub(db, pid, [])))
    assert sorted(d["hub_id"] for d in db.dropped_findings(pid)) == ["510001", "510005"]
    hub_defects._apply_effects(db, stale, "")
    for ident in urls:
        review = db.get_review(pid, ident)
        assert review["entered_hub"] == 0 and review["dropped_info"]["via"] == "sync"


def test_only_the_operator_mark_or_a_read_link_clears_the_mark(web):
    """Ревью 31.10, круг 5: автоматическая отметка (статус, дефект, позднее последствие) пометку не снимает; отметка
    оператора – снимает. Цель схемы 28 сверяется с составом по паре номера и типа."""
    import json
    from app import hub_defects
    pid = pair_project(web)
    db = web.app.state.db
    urls = {ident: save_sast(web, pid, ident, "true_positive", "", REASON, FIX)[0] for ident in ("510001", "510005")}
    defect = created(web, pid, urls["510001"], links=(510001, 510005))
    legacy = [{k: v for k, v in t.items() if k not in ("entered_origin", "entered_defect_id", "entered_op_id",
                                                        "entered_defect_revision")}
              for t in loads(defect["targets_json"], [])]
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET targets_json=?, effects_done=0 WHERE id=?", (json.dumps(legacy), defect["id"]))
        c.execute("UPDATE reviews SET entered_hub=0, entered_hub_at=NULL, entered_origin='', entered_defect_id=NULL,"
                  " entered_op_id=NULL, entered_text_hash='' WHERE project_id=?", (pid,))
    stale = db.hub_defect(defect["id"])
    body = loads(defect["confirmed_object_json"], {})
    body["linkedIssues"] = [link if link["id"] != 510001 else {**link, "type": "SCA_S"} for link in body["linkedIssues"]]
    accept(db, read((db, pid), project_hub(db, pid, [body])))
    assert [d["hub_id"] for d in db.dropped_findings(pid)] == ["510001"]
    hub_defects._apply_effects(db, stale, "")  # в составе SCA_S:510001 – цель SAST:510001 не отмечается
    review = db.get_review(pid, "510001")
    assert review["entered_hub"] == 0 and review["dropped_info"]
    revision = review["revision"]
    db.mark_entered(pid, "510001", True, revision=revision, entered_hash="h", entered_origin="status")
    assert db.get_review(pid, "510001")["dropped_info"], "автоматическая отметка пометку не снимает"
    db.mark_entered(pid, "510001", True, revision=revision, entered_hash="h")
    assert db.get_review(pid, "510001")["dropped_info"] == {}, "отметка оператора снимает"


def test_import_of_another_defect_clears_the_mark_by_pair(web):
    """Ревью 31.10, круг 6: «Занести из Hub» дефекта, в котором прочитана связь находки, снимает пометку; связь другого
    типа с тем же номером – нет."""
    from app import defect_drafts
    from test_hub_defect_import import imported
    from test_hub_defects import hub_settings
    from test_web import prepared, start_run, wait_run
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    db = web.app.state.db
    mark = '{"defect_id": 1, "number": 4, "hub_defect_id": "555", "at": "2026-10-31T00:00:00Z", "via": "sync"}'
    with db._tx() as c:
        c.execute("UPDATE reviews SET defect_dropped=? WHERE project_id=? AND hub_id='510001'", (mark, pid))
        defect_drafts.clear_dropped(c, pid, [(510001, "SCA_S")])
    assert db.get_review(pid, "510001")["dropped_info"], "связь другого типа пометку не снимает"
    imported(web, pid, "777", hub_body(links=((510001, "SAST"),)))
    assert db.get_review(pid, "510001")["dropped_info"] == {}


def test_general_sync_releases_numbers_only_for_findings_in_some_set(web, monkeypatch):
    """Ревью круг 7 (номера наборов): общая синхронизация, как и одиночная, снимает номер только с ключей выбывших
    находок, которые не отнесены оператором к «без дефекта» (`in_some_set`)."""
    from app import defect_drafts

    pid = pair_project(web)
    db = web.app.state.db
    urls = {ident: save_sast(web, pid, ident, "true_positive", "", REASON, FIX)[0] for ident in ("510001", "510005")}
    defect = created(web, pid, urls["510001"], links=(510001, 510005))
    number = db.defect_number(pid, "sast:510001")
    assert number == defect["number"]
    seen = []

    def nobody(c, project_id, hub_ids):
        seen.append(list(hub_ids))
        return []  # будто выбывшая находка отнесена к «без дефекта»

    monkeypatch.setattr(defect_drafts, "in_some_set", nobody)
    # ключ выбывшей находки записан в ключах номера (обычный созданный дефект) – прежние ключи его тоже не снимают
    # (ревью dev14, A3/B1); путь «без записанных ключей» (занесённый из Hub) – ниже
    assert "sast:510001" in loads(db.hub_defect(defect["id"])["number_keys_json"], [])
    body = loads(defect["confirmed_object_json"], {})
    body["linkedIssues"] = [link for link in body["linkedIssues"] if link["id"] != 510001]
    accept(db, read((db, pid), project_hub(db, pid, [body])))
    assert ["510001"] in seen
    assert db.defect_number(pid, "sast:510001") == number, "номер «без дефекта» не снимается"


def test_general_sync_without_recorded_keys_and_absent_defect_keep_no_defect_numbers(web, monkeypatch):
    """Ревью dev14: и у дефекта без записанных ключей номера (занесённый из Hub), и при отсутствии дефекта в Hub номер с
    ключа находки «без дефекта» не снимается."""
    from app import defect_drafts
    from app.hub_pull import no_defect_keys

    pid = pair_project(web)
    db = web.app.state.db
    urls = {ident: save_sast(web, pid, ident, "true_positive", "", REASON, FIX)[0] for ident in ("510001", "510005")}
    defect = created(web, pid, urls["510001"], links=(510001, 510005))
    number = db.defect_number(pid, "sast:510001")
    monkeypatch.setattr(defect_drafts, "in_some_set", lambda c, project_id, hub_ids: [])
    with db._tx() as c:
        assert no_defect_keys(c, pid, ["510001"]) == {"sast:510001"}
        c.execute("UPDATE hub_defects SET number_keys_json='[]' WHERE project_id=?", (pid,))
    body = loads(defect["confirmed_object_json"], {})
    body["linkedIssues"] = [link for link in body["linkedIssues"] if link["id"] != 510001]
    accept(db, read((db, pid), project_hub(db, pid, [body])))
    assert db.defect_number(pid, "sast:510001") == number
    with db._tx() as c:  # ключ оставшейся в дефекте находки 510005 записан за строкой
        c.execute("UPDATE hub_defects SET number_keys_json=? WHERE project_id=?", ('["sast:510005"]', pid))
    accept(db, read((db, pid), project_hub(db, pid, [])))  # дефекта в Hub больше нет, 510005 – «без дефекта»
    assert db.defect_number(pid, "sast:510001") == number and db.defect_number(pid, "sast:510005") == number

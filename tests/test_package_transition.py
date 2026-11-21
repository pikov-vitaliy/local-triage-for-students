"""Шаг 4 плана dev17 (п. 4.4–4.5): переход сущностей при изменении эффективной идентичности пакета SCA – решения,
участники наборов, исследования, тексты, применимость, строки наборов, ключи и резервы номеров, архив; принятие
состояния Hub в три фазы, предпросмотр равен применению, отпечаток входов в токене. Пакеты и номера выдуманы."""

from __future__ import annotations

import json

import pytest

from app import hub_sync as sync, hub_sync_compare as compare, package_identity as pi, package_transition as pt
from app.db import dumps, loads, review_signature
from app.defect import defect_key_sca
from app.sca_contract import input_ref
from test_hub_pull import PullHub, accept, finish_pull, run
from test_hub_status_routes import HUB, project, sca
from test_sca_applicability import put_research
from test_web import web  # noqa: F401

OLD = ("maven", "lib", "1.2.3")
NEW = ("maven", "org.example:lib", "1.2.3")


def made(web, *specs):
    """Проект с находками SCA: (hub_id, компонент, Type)."""
    findings = []
    for hub_id, component, build_type in specs:
        f = sca(hub_id)
        f.component, f.build_type = component, build_type
        findings.append(f)
    return web.app.state.db, project(web, findings)


def transition(db, pid, changes):
    """Фазы 1–2 без Hub: колонки pkg_* как после apply_library, затем rebind_packages."""
    with db._tx() as c:
        before = pt.snapshot(c, pid)
        for hub_id, (eco, name) in changes.items():
            c.execute("UPDATE findings SET pkg_ecosystem = ?, pkg_name = ?, pkg_source = 'hub', pkg_note = '',"
                      " pkg_scope = 'h|7' WHERE project_id = ? AND hub_id = ?", (eco, name, pid, hub_id))
        return pt.rebind_packages(c, pid, None, before, pt.snapshot(c, pid))


def one(db, sql, params=()):
    return db._one(sql, params)


def task_row(db, pid, ref, ecosystem, name, version):
    with db._tx() as c:
        task_id = c.execute("SELECT task_id FROM sca2_research WHERE project_id = ? AND input_ref = ? LIMIT 1",
                            (pid, ref)).fetchone()[0]
        c.execute("INSERT INTO sca2_task_rows(task_id, input_ref, ecosystem, name, version) VALUES (?, ?, ?, ?, ?)",
                  (task_id, ref, ecosystem, name, version))


def execute(db, sql, params=()):
    with db._tx() as c:
        c.execute(sql, params)


def test_classify_refine_and_change():
    assert pt.classify(OLD, NEW) == "refine"
    assert pt.classify(("npm", "core", "17.3.12"), ("npm", "@angular/core", "17.3.12")) == "refine"
    assert pt.classify(("npm", "lib", "1.2.3"), NEW) == "change", "смена экосистемы – изменение"
    assert pt.classify(("maven", "core", "1.0"), ("maven", "org.a:other", "1.0")) == "change"
    assert pt.classify(OLD, OLD) == ""


def test_refine_moves_group_entities_and_rewrites_operator_signature(web):  # noqa: F811
    db, pid = made(web, ("73001", "lib", "maven"), ("73002", "lib", "maven"))
    s, t = input_ref(*OLD), input_ref(*NEW)
    put_research(db, pid, s, {"identity_resolution": {"state": "resolved", "coordinates": "org.example:lib"}})
    task_row(db, pid, s, "maven", "lib", "1.2.3")
    execute(db, "INSERT INTO sca_package_texts(project_id, input_ref, set_no, explanation, updated_at)"
                " VALUES (?, ?, 0, 'Текст оператора.', 'x')", (pid, s))
    execute(db, "INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, updated_at)"
                " VALUES (?, '73002', ?, 1, 'x')", (pid, s))
    execute(db, "INSERT INTO sca_defect_sets(project_id, input_ref, set_no, revision, updated_at) VALUES (?, ?, 1, 3, 'x')",
            (pid, s))
    execute(db, "INSERT INTO defects(project_id, defect_key, number, updated_at) VALUES (?, ?, 5, 'x')",
            (pid, defect_key_sca("lib", "1.2.3", "maven") + "#1"))
    db.save_review(pid, "73001", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True)
    summary = transition(db, pid, {"73001": NEW[:2], "73002": NEW[:2]})
    assert summary["refine"] == 2 and summary["change"] == 0
    assert one(db, "SELECT input_ref FROM sca2_research WHERE project_id = ?", (pid,))["input_ref"] == t
    assert one(db, "SELECT input_ref FROM sca_package_texts WHERE project_id = ?", (pid,))["input_ref"] == t
    member = one(db, "SELECT input_ref, set_no FROM sca_set_members WHERE project_id = ? AND hub_id = '73002'", (pid,))
    assert (member["input_ref"], member["set_no"]) == (t, 1)
    sets = one(db, "SELECT input_ref, revision FROM sca_defect_sets WHERE project_id = ?", (pid,))
    assert (sets["input_ref"], sets["revision"]) == (t, 3), "уточнение переносит набор без сброса ревизии"
    assert one(db, "SELECT number FROM defects WHERE project_id = ? AND defect_key = ?",
               (pid, defect_key_sca("org.example:lib", "1.2.3", "maven") + "#1"))["number"] == 5
    review = db.get_review(pid, "73001")
    data = db.get_finding_by_hub_id(pid, "73001")["data"]
    assert not review["reviewed"] and review["finding_sig"] == review_signature(data)
    assert summary["decisions"]["sig_rewritten"] == 1 and summary["decisions"]["reviewed_removed"] == 1
    rev = one(db, "SELECT identity_rev FROM projects WHERE id = ?", (pid,))["identity_rev"]
    assert rev == 1 and {r["pkg_rev"] for r in db._all("SELECT pkg_rev FROM findings WHERE project_id = ?", (pid,))} == {1}


def test_change_archives_entities_keeps_numbered_places(web):  # noqa: F811
    db, pid = made(web, ("73001", "lib", "npm"), ("73002", "lib", "npm"))
    old = ("npm", "lib", "1.2.3")
    s, t = input_ref(*old), input_ref(*NEW)
    put_research(db, pid, s, {"identity_resolution": {"state": "resolved", "coordinates": "lib"}})
    task_row(db, pid, s, "npm", "lib", "1.2.3")
    execute(db, "INSERT INTO sca_package_texts(project_id, input_ref, set_no, explanation, updated_at)"
                " VALUES (?, ?, 2, 'Текст.', 'x')", (pid, s))
    execute(db, "INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, no_defect_reason, updated_at)"
                " VALUES (?, '73001', ?, NULL, 'только сборка', 'x')", (pid, s))
    execute(db, "INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, updated_at)"
                " VALUES (?, '73002', ?, 2, 'x')", (pid, s))
    execute(db, "INSERT INTO sca_defect_sets(project_id, input_ref, set_no, revision, excluded_json, updated_at)"
                " VALUES (?, ?, 2, 4, '[\"x\"]', 'x')", (pid, s))
    db.save_review(pid, "73001", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True)
    operator_sig = db.get_review(pid, "73001")["finding_sig"]
    execute(db, "INSERT INTO reviews(project_id, hub_id, decision, final_verdict, decision_origin, finding_sig, reviewed,"
                " updated_at) VALUES (?, '73002', 'hub', 'false_positive', 'hub_sync', 'old', 1, 'x')", (pid,))
    summary = transition(db, pid, {"73001": NEW[:2], "73002": NEW[:2]})
    assert summary["change"] == 2
    assert db._all("SELECT 1 FROM sca2_research WHERE project_id = ?", (pid,)) == [], "смена экосистемы – архив"
    assert db._all("SELECT 1 FROM sca_package_texts WHERE project_id = ?", (pid,)) == []
    assert one(db, "SELECT 1 FROM sca_set_members WHERE project_id = ? AND hub_id = '73001'", (pid,)) is None, \
        "«без дефекта» относилось к прежнему пакету"
    member = one(db, "SELECT input_ref, set_no FROM sca_set_members WHERE project_id = ? AND hub_id = '73002'", (pid,))
    assert (member["input_ref"], member["set_no"]) == (t, 2)
    sets = one(db, "SELECT input_ref, revision, excluded_json FROM sca_defect_sets WHERE project_id = ?", (pid,))
    assert (sets["input_ref"], sets["revision"], sets["excluded_json"]) == (t, 1, "[]")
    tables = {r["source_table"] for r in db._all("SELECT source_table FROM sca_identity_archive WHERE project_id = ?",
                                                 (pid,))}
    assert {"sca2_research", "sca_package_texts", "sca_set_members", "sca_defect_sets"} <= tables
    assert db.get_review(pid, "73001")["finding_sig"] == operator_sig, "решение оператора по другой версии находки"
    hub_review = db.get_review(pid, "73002")
    assert hub_review["finding_sig"] == review_signature(db.get_finding_by_hub_id(pid, "73002")["data"])
    assert not hub_review["reviewed"]
    assert summary["decisions"]["other_version"] == 1


def test_partial_split_keeps_entities_with_the_remaining_group(web):  # noqa: F811
    db, pid = made(web, ("73001", "lib", "maven"), ("73002", "lib", "maven"))
    s, t = input_ref(*OLD), input_ref(*NEW)
    put_research(db, pid, s, {"identity_resolution": {"state": "resolved", "coordinates": "lib"}})
    execute(db, "INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, updated_at)"
                " VALUES (?, '73001', ?, 1, 'x')", (pid, s))
    execute(db, "INSERT INTO defects(project_id, defect_key, number, updated_at) VALUES (?, ?, 6, 'x')",
            (pid, defect_key_sca("lib", "1.2.3", "maven") + "#1"))
    summary = transition(db, pid, {"73001": NEW[:2]})
    assert [g["kind"] for g in summary["groups"]] == ["частичное расщепление"]
    assert one(db, "SELECT input_ref FROM sca2_research WHERE project_id = ?", (pid,))["input_ref"] == s
    member = one(db, "SELECT input_ref, set_no FROM sca_set_members WHERE project_id = ? AND hub_id = '73001'", (pid,))
    assert (member["input_ref"], member["set_no"]) == (t, 1)
    assert one(db, "SELECT revision FROM sca_defect_sets WHERE project_id = ? AND input_ref = ? AND set_no = 1",
               (pid, t))["revision"] == 1
    assert one(db, "SELECT number FROM defects WHERE project_id = ? AND defect_key = ?",
               (pid, defect_key_sca("lib", "1.2.3", "maven") + "#1"))["number"] == 6, "резерв остаётся у прежней группы"


def test_merge_gives_new_places_with_reason_and_keeps_target(web):  # noqa: F811
    db, pid = made(web, ("73001", "lib", "maven"), ("73002", "lib", "maven"), ("73003", "org.example:lib", "maven"))
    s, t = input_ref(*OLD), input_ref(*NEW)
    put_research(db, pid, t, {"identity_resolution": {"state": "resolved", "coordinates": "org.example:lib"}})
    put_research(db, pid, s, {"identity_resolution": {"state": "resolved", "coordinates": "org.example:lib"}})
    execute(db, "INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, updated_at)"
                " VALUES (?, '73003', ?, 1, 'x')", (pid, t))
    execute(db, "INSERT INTO sca_defect_sets(project_id, input_ref, set_no, revision, updated_at) VALUES (?, ?, 1, 2, 'x')",
            (pid, t))
    execute(db, "INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, no_defect_reason, updated_at)"
                " VALUES (?, '73001', ?, NULL, 'только сборка', 'x')", (pid, s))
    summary = transition(db, pid, {"73001": NEW[:2], "73002": NEW[:2]})
    assert [g["kind"] for g in summary["groups"]] == ["слияние"]
    places = {r["hub_id"]: r for r in db._all("SELECT * FROM sca_set_members WHERE project_id = ?", (pid,))}
    assert places["73003"]["set_no"] == 1 and not places["73003"]["pending_reason"], "своё место цели не трогается"
    assert {places["73001"]["set_no"], places["73002"]["set_no"]} == {2, 3}
    assert "без дефекта" in places["73001"]["pending_reason"] and pt.MERGE_REASON in places["73002"]["pending_reason"]
    assert [r["input_ref"] for r in db._all("SELECT input_ref FROM sca2_research WHERE project_id = ?", (pid,))] == [t], \
        "исследование пришедшей группы – в архив, своё у цели остаётся"
    assert one(db, "SELECT revision FROM sca_defect_sets WHERE project_id = ? AND input_ref = ? AND set_no = 1",
               (pid, t))["revision"] == 2


def test_pending_place_blocks_defect_update(web):  # noqa: F811
    """Место в наборах ждёт выбора после слияния: подготовка обновления дефекта с такой целью недоступна – общий
    предикат кнопки и сервера (план п. 4.5)."""
    from app import hub_defects
    db, pid = made(web, ("73001", "lib", "maven"), ("73003", "org.example:lib", "maven"))
    execute(db, "INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, updated_at)"
                " VALUES (?, '73003', ?, 1, 'x')", (pid, input_ref(*NEW)))
    transition(db, pid, {"73001": NEW[:2]})
    with db._tx() as c:
        target = [{"hub_id": "73001", "issue_type": "SCA_S"}]
        problem = hub_defects.pending_place_problem(c, {"project_id": pid, "targets_json": dumps(target)})
        assert "73001" in problem and "выбрать заново" in problem
        assert hub_defects.pending_place_problem(c, {"project_id": pid, "targets_json": dumps(
            [{"hub_id": "73003", "issue_type": "SCA_S"}])}) == ""
        assert hub_defects.pending_place_problem(c, {"project_id": pid, "targets_json": dumps(
            [{"hub_id": "73001", "issue_type": "SAST"}])}) == "", "тот же номер другого типа – не эта находка"
        row = {"id": 1, "project_id": pid, "draft_owner_id": 1, "targets_json": dumps(target),
               "conflicts_json": "[]"}
        assert hub_defects._update_idle_problem(c, row) == problem


def test_family_keys_and_number_follow_the_targets(web):  # noqa: F811
    db, pid = made(web, ("73001", "lib", "maven"))
    old_key, new_key = defect_key_sca("lib", "1.2.3", "maven"), defect_key_sca("org.example:lib", "1.2.3", "maven")
    with db._tx() as c:
        owner = c.execute("INSERT INTO hub_defects(project_id, kind, number, state, origin, targets_json,"
                          " number_keys_json, sca_set_key, created_at, updated_at) VALUES (?, 'SCA', 9, 'done', 'app', ?, ?,"
                          " ?, 'x', 'x') RETURNING id",
                          (pid, dumps([{"hub_id": "73001", "issue_type": "SCA_S"}]), dumps([old_key]), old_key)).fetchone()[0]
        c.execute("UPDATE hub_defects SET draft_owner_id = id WHERE id = ?", (owner,))
        c.execute("INSERT INTO defects(project_id, defect_key, number, updated_at) VALUES (?, ?, 9, 'x')", (pid, old_key))
    summary = transition(db, pid, {"73001": NEW[:2]})
    row = one(db, "SELECT number_keys_json, sca_set_key FROM hub_defects WHERE id = ?", (owner,))
    assert loads(row["number_keys_json"], []) == [new_key] and row["sca_set_key"] == new_key
    assert one(db, "SELECT number FROM defects WHERE project_id = ? AND defect_key = ?", (pid, new_key))["number"] == 9
    assert one(db, "SELECT 1 FROM defects WHERE project_id = ? AND defect_key = ?", (pid, old_key)) is None
    assert summary["defects"]["families"] == 1


def test_agree_without_valid_answer_loses_reviewed(web):  # noqa: F811
    db, pid = made(web, ("73001", "lib", "npm"))
    old = ("npm", "lib", "1.2.3")
    put_research(db, pid, input_ref(*old), {"identity_resolution": {"state": "resolved", "coordinates": "lib"}})
    db.save_review(pid, "73001", decision="agree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True)
    execute(db, "UPDATE reviews SET answer_sig = 'research:sig1' WHERE project_id = ? AND hub_id = '73001'", (pid,))
    summary = transition(db, pid, {"73001": NEW[:2]})
    assert summary["decisions"]["agree_stale"] == 1 and not db.get_review(pid, "73001")["reviewed"]


def test_nothing_changes_without_new_identity(web):  # noqa: F811
    db, pid = made(web, ("73001", "lib", "maven"))
    with db._tx() as c:
        snap = pt.snapshot(c, pid)
        summary = pt.rebind_packages(c, pid, None, snap, pt.snapshot(c, pid))
    assert summary["findings"] == 0
    assert one(db, "SELECT identity_rev FROM projects WHERE id = ?", (pid,))["identity_rev"] == 0


def test_fingerprint_sees_every_transition_table(web):  # noqa: F811
    db, pid = made(web, ("73001", "lib", "maven"))
    first = db.on_connection(lambda c: pt.transition_fingerprint(c, pid))
    execute(db, "INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, updated_at)"
                " VALUES (?, '73001', ?, 1, 'x')", (pid, input_ref(*OLD)))
    assert db.on_connection(lambda c: pt.transition_fingerprint(c, pid)) != first


def test_apply_library_rule_rows():
    data = {"build_type": "npm", "component": "core", "version": "17.3.12"}
    assert pt.resolved_columns(data, {"detail": {"library": {"groupId": "%40angular", "name": "core",
                                                             "version": "17.3.12"}}}, "h|7") == (
        "npm", "@angular/core", "hub", "", "h|7")
    assert pt.resolved_columns(data, {"detail": {}}, "h|7")[2] == "file"


# ============================================================================ принятие состояния Hub в три фазы


def synced(web, library, *, status="To verify", component="lib", build_type="maven"):
    """Проект с находкой SCA 201 и прочитанным Hub, где у находки есть сведения о библиотеке."""
    db, pid = made(web, ("201", component, build_type))
    rid = sync.start(db, pid, HUB, 7, previous=None, app_confirmed=True)
    finish_pull(db, PullHub(count=0, defects=False), rid)
    detail = {"id": 201, "appId": 7, "status": status, "currentBranch": "main",
              "issueBranchBriefData": [{"branch": "main", "status": status}]}
    if library is not None:
        detail["library"] = library
    with db._tx() as c:
        c.execute("UPDATE hub_sync_items SET hub_json = ?, stale_reason = '', coverage_json = '{}' WHERE run_id = ?"
                  " AND entity_key = 'SCA_S:201'",
                  (dumps({"brief": {"id": 201, "appId": 7, "type": "SCA_S"}, "detail": detail, "manual": None}), rid))
        compare.compare_in(c, sync.run_in(c, rid))
    return db, pid, rid


def test_apply_writes_identity_and_preview_equals_result(web):  # noqa: F811
    from app import hub_pull as pull
    db, pid, rid = synced(web, {"groupId": "org.example", "name": "lib", "version": "1.2.3"})
    shown = pull.preview(db, run(db, rid))
    assert shown["identity"] and shown["identity"]["findings"] == 1, shown.get("identity")
    result = pull.apply(db, rid, shown["token"])
    row = one(db, "SELECT pkg_ecosystem, pkg_name, pkg_source, pkg_scope, pkg_rev FROM findings WHERE project_id = ?"
                  " AND hub_id = '201'", (pid,))
    assert (row["pkg_ecosystem"], row["pkg_name"], row["pkg_source"]) == ("maven", "org.example:lib", "hub")
    assert row["pkg_scope"].endswith("|7") and row["pkg_rev"] == 1
    assert {k: v for k, v in result["identity"].items() if k != "pending"} == \
        {k: v for k, v in shown["identity"].items() if k != "pending"}, "предпросмотр равен применению"
    again = pull.preview(db, run(db, rid))
    assert again.get("applied")


def test_token_rejects_a_change_between_preview_and_apply(web):  # noqa: F811
    from app import hub_pull as pull
    db, pid, rid = synced(web, {"groupId": "org.example", "name": "lib", "version": "1.2.3"})
    shown = pull.preview(db, run(db, rid))
    execute(db, "INSERT INTO sca_defect_sets(project_id, input_ref, set_no, revision, updated_at) VALUES (?, ?, 1, 1, 'x')",
            (pid, input_ref(*OLD)))
    with pytest.raises(ValueError, match="Итог изменился"):
        pull.apply(db, rid, shown["token"])
    assert one(db, "SELECT pkg_source FROM findings WHERE project_id = ? AND hub_id = '201'", (pid,))["pkg_source"] == ""


def test_present_without_library_is_file_identity_without_transition(web):  # noqa: F811
    from app import hub_pull as pull
    db, pid, rid = synced(web, None)
    shown = pull.preview(db, run(db, rid))
    assert shown["identity"] is not None and shown["identity"]["findings"] == 0
    pull.apply(db, rid, shown["token"])
    row = one(db, "SELECT pkg_source, pkg_rev FROM findings WHERE project_id = ? AND hub_id = '201'", (pid,))
    assert (row["pkg_source"], row["pkg_rev"]) == ("file", 0)
    data = db.get_finding_by_hub_id(pid, "201")["data"]
    assert pi.of(data) == OLD, "без сведений о библиотеке тройка прежняя"


def test_hub_projection_signs_with_effective_identity(web):  # noqa: F811
    """accept_issue пишет подпись проекции решения Hub по текущей эффективной идентичности (план п. 4.3)."""
    db, pid, rid = synced(web, {"groupId": "org.example", "name": "lib", "version": "1.2.3"}, status="False Positive")
    with db._tx() as c:
        item = c.execute("SELECT hub_json FROM hub_sync_items WHERE run_id = ? AND entity_key = 'SCA_S:201'",
                         (rid,)).fetchone()
        hub = json.loads(item["hub_json"])
        hub["manual"] = {"id": 301, "issueId": 201, "issueType": "SCA_S", "status": "False Positive", "oldStatus":
                         "To verify", "reason": "Не используется", "conditionalCategory": None, "changedBy": "demo",
                         "createTs": 1800000000000, "expiredAt": 4070995199999}
        c.execute("UPDATE hub_sync_items SET hub_json = ? WHERE run_id = ? AND entity_key = 'SCA_S:201'",
                  (dumps(hub), rid))
        compare.compare_in(c, sync.run_in(c, rid))
    accept(db, rid)
    review = db.get_review(pid, "201")
    # безусловно (ревью Codex шага 4, F9): проекция решения Hub должна появиться, иначе проверять подпись не у чего
    assert review and review.get("decision_origin") == "hub_sync", review
    data = db.get_finding_by_hub_id(pid, "201")["data"]
    assert pi.of(data) == NEW, "тройка – по сведениям Hub о библиотеке"
    assert review["finding_sig"] == review_signature(data)


def pull_run(db, pid, library, previous=None, extra=None, status="To verify"):
    """Новый прочитанный запуск синхронизации: у находки SCA 201 сведения о библиотеке library; extra – такие же
    сведения у других находок {hub_id: library}; status – статус находки 201 в Hub."""
    rid = sync.start(db, pid, HUB, 7, previous=previous, app_confirmed=True)
    finish_pull(db, PullHub(count=0, defects=False), rid)
    with db._tx() as c:
        for hub_id, lib in {"201": library, **(extra or {})}.items():
            state = status if hub_id == "201" else "To verify"
            detail = {"id": int(hub_id), "appId": 7, "status": state, "currentBranch": "main",
                      "issueBranchBriefData": [{"branch": "main", "status": state}], "library": lib}
            c.execute("UPDATE hub_sync_items SET hub_json = ?, stale_reason = '', coverage_json = '{}' WHERE run_id = ?"
                      " AND entity_key = ?", (dumps({"brief": {"id": int(hub_id), "appId": 7, "type": "SCA_S"},
                                                       "detail": detail, "manual": None}), rid, f"SCA_S:{hub_id}"))
        compare.compare_in(c, sync.run_in(c, rid))
    return rid


def test_failure_after_transition_rolls_back_the_whole_accept(web, monkeypatch):  # noqa: F811
    """Ревью Codex шага 4 (F9): сбой после перехода (фазы 1–2 уже записали) – откатывается всё принятие; то же
    подтверждение после сбоя действует – входы не изменились."""
    from app import hub_pull as pull
    db, pid, rid = synced(web, {"groupId": "org.example", "name": "lib", "version": "1.2.3"})
    shown = pull.preview(db, run(db, rid))
    real = pt.rebind_packages

    def broken(*args, **kwargs):
        real(*args, **kwargs)
        raise RuntimeError("сбой после перехода")

    monkeypatch.setattr(pt, "rebind_packages", broken)
    with pytest.raises(RuntimeError):
        pull.apply(db, rid, shown["token"])
    row = one(db, "SELECT pkg_source, pkg_rev FROM findings WHERE project_id = ? AND hub_id = '201'", (pid,))
    assert (row["pkg_source"], row["pkg_rev"]) == ("", 0)
    assert one(db, "SELECT identity_rev FROM projects WHERE id = ?", (pid,))["identity_rev"] == 0
    assert not run(db, rid)["applied_at"]
    assert db._all("SELECT 1 FROM sca_identity_archive WHERE project_id = ?", (pid,)) == []
    monkeypatch.undo()
    assert pull.apply(db, rid, shown["token"])["identity"]["findings"] == 1


def test_merge_pending_place_survives_a_second_accept(web):  # noqa: F811
    """Ревью Codex шага 4 (F9): слияние при принятии – пришедшая находка получает новое место с причиной; повторное
    принятие того же состояния Hub причину не снимает и мест не двигает; ревизия идентичности растёт один раз."""
    from app import hub_pull as pull
    db, pid = made(web, ("201", "lib", "maven"), ("202", "org.example:lib", "maven"))
    t = input_ref(*NEW)
    execute(db, "INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, updated_at)"
                " VALUES (?, '202', ?, 1, 'x')", (pid, t))
    execute(db, "INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, updated_at)"
                " VALUES (?, '201', ?, 1, 'x')", (pid, input_ref(*OLD)))
    library = {"groupId": "org.example", "name": "lib", "version": "1.2.3"}
    rid = pull_run(db, pid, library)
    shown = pull.preview(db, run(db, rid))
    pull.apply(db, rid, shown["token"])
    places = {r["hub_id"]: r for r in db._all("SELECT * FROM sca_set_members WHERE project_id = ?", (pid,))}
    assert places["202"]["set_no"] == 1 and not places["202"]["pending_reason"], "место цели не трогается"
    assert places["201"]["input_ref"] == t and places["201"]["set_no"] != 1
    assert pt.MERGE_REASON in places["201"]["pending_reason"]
    rev = one(db, "SELECT identity_rev FROM projects WHERE id = ?", (pid,))["identity_rev"]
    current = run(db, rid)
    # в Hub у находки сменился статус, идентичность та же: принимать есть что, перехода нет
    again = pull_run(db, pid, library, previous=(current["id"], current["revision"]), status="Confirmed")
    second = pull.preview(db, run(db, again))
    assert second.get("count"), second
    assert not second.get("identity"), "тройка та же – перехода нет"
    pull.apply(db, again, second["token"])
    after = {r["hub_id"]: r for r in db._all("SELECT * FROM sca_set_members WHERE project_id = ?", (pid,))}
    assert after["201"]["set_no"] == places["201"]["set_no"]
    assert after["201"]["pending_reason"] == places["201"]["pending_reason"], "причина переживает повторное принятие"
    assert one(db, "SELECT identity_rev FROM projects WHERE id = ?", (pid,))["identity_rev"] == rev



def test_family_with_an_unmatched_target_gets_no_set_key(web):  # noqa: F811
    """D2: цели семейства нет среди находок SCA проекта – единственный набор не доказан: ключ набора пуст, причина
    названа; номер переносится по сопоставленным целям."""
    db, pid = made(web, ("73001", "lib", "maven"))
    old_key, new_key = defect_key_sca("lib", "1.2.3", "maven"), defect_key_sca("org.example:lib", "1.2.3", "maven")
    targets = [{"hub_id": "73001", "issue_type": "SCA_S"}, {"hub_id": "79999", "issue_type": "SCA_S"}]
    with db._tx() as c:
        owner = c.execute("INSERT INTO hub_defects(project_id, kind, number, state, origin, targets_json,"
                          " number_keys_json, sca_set_key, created_at, updated_at) VALUES (?, 'SCA', 9, 'done', 'app', ?, ?,"
                          " ?, 'x', 'x') RETURNING id", (pid, dumps(targets), dumps([old_key]), old_key)).fetchone()[0]
        c.execute("UPDATE hub_defects SET draft_owner_id = id WHERE id = ?", (owner,))
        c.execute("INSERT INTO defects(project_id, defect_key, number, updated_at) VALUES (?, ?, 9, 'x')", (pid, old_key))
    summary = transition(db, pid, {"73001": NEW[:2]})
    row = one(db, "SELECT number_keys_json, sca_set_key, conflicts_json FROM hub_defects WHERE id = ?", (owner,))
    assert row["sca_set_key"] == "" and "79999" in row["conflicts_json"]
    assert loads(row["number_keys_json"], []) == [new_key]
    assert str(owner) in summary["defects"]["without_set_key"], "подпись – номер строки, номера Hub нет"
    assert summary["defects"]["without_set_key_total"] == 1, "полный счёт – отдельно от усечённого списка"


def test_group_counts_include_defect_keys_and_reserves(web):  # noqa: F811
    """D6: в строке группы – архив прежнего ключа семейства и перенос резерва номера."""
    db, pid = made(web, ("73001", "lib", "maven"))
    old_key = defect_key_sca("lib", "1.2.3", "maven")
    with db._tx() as c:
        owner = c.execute("INSERT INTO hub_defects(project_id, kind, number, state, origin, targets_json,"
                          " number_keys_json, sca_set_key, created_at, updated_at) VALUES (?, 'SCA', 9, 'done', 'app', ?, ?,"
                          " ?, 'x', 'x') RETURNING id",
                          (pid, dumps([{"hub_id": "73001", "issue_type": "SCA_S"}]), dumps([old_key]), old_key)).fetchone()[0]
        c.execute("UPDATE hub_defects SET draft_owner_id = id WHERE id = ?", (owner,))
        c.execute("INSERT INTO defects(project_id, defect_key, number, updated_at) VALUES (?, ?, 9, 'x')", (pid, old_key))
        c.execute("INSERT INTO defects(project_id, defect_key, number, updated_at) VALUES (?, ?, 11, 'x')",
                  (pid, old_key + "#2"))  # резерв: номер 11 не держит ни одно семейство
    summary = transition(db, pid, {"73001": NEW[:2]})
    group = summary["groups"][0]
    assert group["archived"].get("defects") == 1, group
    assert group["moved"].get("defects") == 1 and summary["defects"]["reserves_moved"] == 1, group



def test_same_number_other_type_is_unmatched_and_rows_keys_are_recomputed(web):  # noqa: F811
    """Ревью Codex шага 4, круг 3: SAST:73001 рядом с SCA_S:73001 – несопоставленная цель (ключа набора нет);
    у строки семейства без сопоставленных целей ключи – пустой список."""
    db, pid = made(web, ("73001", "lib", "maven"))
    old_key = defect_key_sca("lib", "1.2.3", "maven")
    with db._tx() as c:
        owner = c.execute("INSERT INTO hub_defects(project_id, kind, number, state, origin, targets_json,"
                          " number_keys_json, sca_set_key, created_at, updated_at) VALUES (?, 'SCA', 9, 'done', 'app', ?, ?,"
                          " ?, 'x', 'x') RETURNING id",
                          (pid, dumps([{"hub_id": "73001", "issue_type": "SCA_S"}, {"hub_id": "73001", "issue_type": "SAST"}]),
                           dumps([old_key]), old_key)).fetchone()[0]
        c.execute("UPDATE hub_defects SET draft_owner_id = id WHERE id = ?", (owner,))
        other = c.execute("INSERT INTO hub_defects(project_id, kind, number, state, origin, targets_json,"
                          " number_keys_json, sca_set_key, draft_owner_id, created_at, updated_at) VALUES (?, 'SCA', NULL,"
                          " 'preview', 'app', ?, ?, '', ?, 'x', 'x') RETURNING id",
                          (pid, dumps([{"hub_id": "79999", "issue_type": "SCA_S"}]), dumps([old_key]), owner)).fetchone()[0]
        c.execute("INSERT INTO defects(project_id, defect_key, number, updated_at) VALUES (?, ?, 9, 'x')", (pid, old_key))
    transition(db, pid, {"73001": NEW[:2]})
    row = one(db, "SELECT sca_set_key, conflicts_json FROM hub_defects WHERE id = ?", (owner,))
    assert row["sca_set_key"] == "" and "SAST:73001" in row["conflicts_json"]
    assert loads(one(db, "SELECT number_keys_json FROM hub_defects WHERE id = ?", (other,))["number_keys_json"], []) == []


def test_assignment_change_without_new_triples_raises_identity_rev(web):  # noqa: F811
    """Ревью Codex шага 4, круг 3 (план, раздел 6): смена назначения при неизменной конечной тройке – identity_rev
    растёт, pkg_rev находок – нет."""
    db, pid = made(web, ("73001", "lib", "maven"))
    with db._tx() as c:
        c.execute("UPDATE findings SET pkg_ecosystem = 'maven', pkg_name = 'lib', pkg_source = 'hub', pkg_note = '',"
                  " pkg_scope = 'https://hub.example.org|7' WHERE project_id = ? AND hub_id = '73001'", (pid,))
    before = one(db, "SELECT identity_rev FROM projects WHERE id = ?", (pid,))["identity_rev"]
    pkg_rev = one(db, "SELECT pkg_rev FROM findings WHERE project_id = ? AND hub_id = '73001'", (pid,))["pkg_rev"]
    db.change_hub_assignment(pid, 8)
    assert one(db, "SELECT identity_rev FROM projects WHERE id = ?", (pid,))["identity_rev"] == before + 1
    assert one(db, "SELECT pkg_rev FROM findings WHERE project_id = ? AND hub_id = '73001'", (pid,))["pkg_rev"] == pkg_rev


def test_npm_scope_added_counted_in_summary_and_on_sync_page(web):  # noqa: F811
    """Ревью Kimi шага 4, круг 2: «Добавлена область npm» – находка npm, которой Hub добавил область, в сводке
    предпросмотра и в блоке «Идентичность пакетов» страницы синхронизации."""
    from app import hub_pull as pull
    db, pid, rid = synced(web, {"groupId": "%40angular", "name": "core", "version": "1.2.3"}, component="core",
                          build_type="npm")
    shown = pull.preview(db, run(db, rid))
    assert shown["identity"]["scope_added"] == 1, shown["identity"]
    assert shown["identity"]["coordinates_added"] == 0
    page = web.client.get(f"/projects/{pid}/hub-sync/{rid}").text
    assert "<dt>Добавлена область npm</dt><dd>1</dd>" in page


def test_sync_page_shows_identity_summary_before_and_after_accept(web):  # noqa: F811
    """Ревью Codex шага 4, круг 3: при принятии состояния Hub последствия перехода видны в подтверждении и в итоге."""
    from app import hub_pull as pull
    db, pid, rid = synced(web, {"groupId": "org.example", "name": "lib", "version": "1.2.3"})
    page = web.client.get(f"/projects/{pid}/hub-sync/{rid}").text
    assert 'id="hub-sync-identity-summary"' in page and "Дополнены координаты" in page
    shown = pull.preview(db, run(db, rid))
    pull.apply(db, rid, shown["token"])
    after = web.client.get(f"/projects/{pid}/hub-sync/{rid}").text
    assert 'id="hub-sync-identity-done-summary"' in after


# ============================================================================ остаток шага 4 (10.11)

def test_sca_identity_is_typed_for_every_caller(web):  # noqa: F811
    """Остаток шага 4: общий расчёт ключа набора типизирован – SAST:201 рядом с SCA_S:201 несопоставлен и в третьей
    фазе, при подготовке, подтверждении и сверке дефекта; цель без типа связи – по виду находки, как раньше."""
    from app.defect_drafts import UNMATCHED_TARGETS, sca_identity
    db, pid = made(web, ("201", "lib", "maven"))
    key = defect_key_sca("lib", "1.2.3", "maven")
    with db._tx() as c:
        assert sca_identity(c, pid, [{"hub_id": "201", "issue_type": "SCA_S"}]) == (key, [])
        assert sca_identity(c, pid, [{"hub_id": "201"}]) == (key, [])
        got, conflicts = sca_identity(c, pid, [{"hub_id": "201", "issue_type": "SCA_S"},
                                               {"hub_id": "201", "issue_type": "SAST"}])
        assert got == "" and conflicts == [UNMATCHED_TARGETS.format(ids="SAST:201")]
        assert sca_identity(c, pid, [{"hub_id": "201", "issue_type": "SCA_L"}])[0] == ""


def _hub_defect_sequence(web, local_links, hub_links, others=()):
    """Проект с находкой SCA 201 (и others – находки SCA без сведений Hub о библиотеке: их пакет не меняется), дефект
    SCA №9 (Hub 77) с локальным составом local_links и прочитанный Hub, где у находки 201 есть сведения о библиотеке, а
    у дефекта – состав hub_links; возвращает (db, pid, rid, владелец)."""
    db, pid = made(web, ("201", "lib", "maven"), *((hub_id, "other", "maven") for hub_id in others))
    old_key = defect_key_sca("lib", "1.2.3", "maven") if not others else defect_key_sca("other", "1.2.3", "maven")
    targets = [{"hub_id": str(i), "issue_id": i, "issue_type": t} for i, t in local_links]
    with db._tx() as c:
        owner = c.execute(
            "INSERT INTO hub_defects(project_id, kind, number, state, origin, hub_url, app_id, hub_defect_id,"
            " targets_json, number_keys_json, sca_set_key, summary, command_text, created_at, updated_at)"
            " VALUES (?, 'SCA', 9, 'done', 'app', ?, 7, '77', ?, ?, ?, 'ID9 - lib', 'Текст', 'x', 'x') RETURNING id",
            (pid, HUB, dumps(targets), dumps([old_key]), old_key)).fetchone()[0]
        c.execute("UPDATE hub_defects SET draft_owner_id = id WHERE id = ?", (owner,))
        c.execute("INSERT INTO defects(project_id, defect_key, number, updated_at) VALUES (?, ?, 9, 'x')", (pid, old_key))
    hub = PullHub(count=0, defects=True)
    hub.defects[77]["summary"] = "ID9 - lib"
    hub.defects[77]["linkedIssues"] = [{"id": i, "type": t, "appId": 7, "severity": 2, "lastScanTs": 1800000000000,
                                        "scanObject": {"id": 3, "url": None}} for i, t in hub_links]
    rid = sync.start(db, pid, HUB, 7, previous=None, app_confirmed=True)
    finish_pull(db, hub, rid)
    detail = {"id": 201, "appId": 7, "status": "To verify", "currentBranch": "main",
              "issueBranchBriefData": [{"branch": "main", "status": "To verify"}],
              "library": {"groupId": "org.example", "name": "lib", "version": "1.2.3"}}
    with db._tx() as c:
        c.execute("UPDATE hub_sync_items SET hub_json = ?, stale_reason = '', coverage_json = '{}' WHERE run_id = ?"
                  " AND entity_key = 'SCA_S:201'",
                  (dumps({"brief": {"id": 201, "appId": 7, "type": "SCA_S"}, "detail": detail, "manual": None}), rid))
        for hub_id in others:  # находка есть в Hub, сведений о библиотеке нет – пакет прежний
            plain = {**{k: v for k, v in detail.items() if k != "library"}, "id": int(hub_id)}
            c.execute("UPDATE hub_sync_items SET hub_json = ?, stale_reason = '', coverage_json = '{}' WHERE run_id = ?"
                      " AND entity_key = ?",
                      (dumps({"brief": {"id": int(hub_id), "appId": 7, "type": "SCA_S"}, "detail": plain,
                              "manual": None}), rid, f"SCA_S:{hub_id}"))
        compare.compare_in(c, sync.run_in(c, rid))
    return db, pid, rid, owner


def test_accept_sequence_third_phase_does_not_restore_a_key_for_other_type_link(web):  # noqa: F811
    """Остаток шага 4: Hub связал дефект с SCA_S:201 и SAST:201 (локальная 201 – SCA). Вторая фаза оставила ключ по
    прежнему составу, третья принимает состав Hub и ключа не даёт – цель SAST:201 несопоставлена; сводка «без
    единственного набора» – по итогу всей последовательности, предпросмотр равен применению."""
    from app import hub_pull as pull
    from app.defect_drafts import UNMATCHED_TARGETS
    db, pid, rid, owner = _hub_defect_sequence(web, [(201, "SCA_S")], [(201, "SCA_S"), (201, "SAST")])
    shown = pull.preview(db, run(db, rid))
    result = pull.apply(db, rid, shown["token"])
    row = one(db, "SELECT sca_set_key, conflicts_json FROM hub_defects WHERE id = ?", (owner,))
    assert row["sca_set_key"] == "", row
    assert loads(row["conflicts_json"], []) == [UNMATCHED_TARGETS.format(ids="SAST:201")]
    assert result["identity"]["defects"]["without_set_key"] == ["77"], "подпись – номер дефекта Hub"
    assert result["identity"]["defects"]["without_set_key_total"] == 1
    assert {k: v for k, v in result["identity"].items() if k != "pending"} == \
        {k: v for k, v in shown["identity"].items() if k != "pending"}, "предпросмотр равен применению"


def test_accept_sequence_summary_follows_a_key_restored_by_the_third_phase(web):  # noqa: F811
    """Остаток шага 4, обратный случай: локальный состав с несопоставленной SAST:201 – вторая фаза ключ снимает; Hub
    оставил только SCA_S:201 – третья фаза ключ набора возвращает, и сводка этот дефект «без единственного набора»
    уже не называет."""
    from app import hub_pull as pull
    db, pid, rid, owner = _hub_defect_sequence(web, [(201, "SCA_S"), (201, "SAST")], [(201, "SCA_S")])
    shown = pull.preview(db, run(db, rid))
    result = pull.apply(db, rid, shown["token"])
    row = one(db, "SELECT sca_set_key, conflicts_json FROM hub_defects WHERE id = ?", (owner,))
    assert row["sca_set_key"] == defect_key_sca("org.example:lib", "1.2.3", "maven"), row
    assert loads(row["conflicts_json"], []) == []
    assert result["identity"]["defects"]["without_set_key"] == []
    assert result["identity"]["defects"]["without_set_key_total"] == 0
    assert {k: v for k, v in result["identity"].items() if k != "pending"} == \
        {k: v for k, v in shown["identity"].items() if k != "pending"}, "предпросмотр равен применению"


def test_accept_sequence_summary_counts_a_defect_touched_only_by_the_accepted_composition(web):  # noqa: F811
    """Ревью Codex остатка шага 4, круг 1 (оба ревьюера): прежний состав дефекта (SCA_S:202) переходом не затронут, а
    принятый из Hub (SCA_S:201 и SAST:201) включает перенесённую находку 201 и несопоставленную связь – третья фаза
    снимает ключ набора, и сводка «без единственного набора» этот дефект называет; предпросмотр равен применению."""
    from app import hub_pull as pull
    from app.defect_drafts import UNMATCHED_TARGETS
    db, pid, rid, owner = _hub_defect_sequence(web, [(202, "SCA_S")], [(201, "SCA_S"), (201, "SAST")], others=("202",))
    shown = pull.preview(db, run(db, rid))
    assert shown["identity"]["findings"] == 1, shown["identity"]
    result = pull.apply(db, rid, shown["token"])
    row = one(db, "SELECT sca_set_key, conflicts_json FROM hub_defects WHERE id = ?", (owner,))
    assert row["sca_set_key"] == "" and loads(row["conflicts_json"], []) == [UNMATCHED_TARGETS.format(ids="SAST:201")]
    assert result["identity"]["defects"]["without_set_key"] == ["77"], "подпись – номер дефекта Hub"
    assert result["identity"]["defects"]["without_set_key_total"] == 1
    assert {k: v for k, v in result["identity"].items() if k != "pending"} == \
        {k: v for k, v in shown["identity"].items() if k != "pending"}, "предпросмотр равен применению"

"""7а: выбранный состав, атомарная подготовка и фактическое тело запроса. Данные выдуманы."""

from copy import deepcopy
from html import unescape
import re

import pytest

from app import defect, hub_defects
from app.db import dumps, loads
from app.routes import defect_selected
from app.triage import order_findings
from test_hub_defects import BLANK, FIX, REASON, SERVICE, hub_job, no_job, sast_ready, to_preview, create
from test_hub_status_routes import AS_JSON, project, sast
from test_web import ORIGIN, web  # noqa: F401


def setup(web, count=3):
    findings = [sast(str(101 + i), line=2 + i) for i in range(count)]
    if count > 1:
        findings[1].file = "other.py"
    pid = project(web, findings)
    web.app.state.db.set_settings({"team_name": "Платформа"})
    return pid


def url(pid):
    return f"/projects/{pid}/hub/defect-selected"


def form_of(html):
    result = {}
    for name, value in re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', html):
        value = unescape(value)
        if name == "hub_id":
            result.setdefault(name, []).append(value)
        else:
            result[name] = value
    return result


def preview(web, pid, ids=("101", "102"), **changes):
    response = web.client.post(url(pid), data={"hub_id": list(ids), "comment": REASON, "fix": FIX,
                                              "action": "preview", **changes}, headers=ORIGIN)
    assert response.status_code == 200, response.text
    return response


def prepare(web, pid, ids=("101", "102"), fields=None, **changes):
    fields = form_of(preview(web, pid, ids).text) if fields is None else fields
    return web.client.post(url(pid), data={**fields, "action": "prepare", "confirm": "1", "overwrite": "1", **changes},
                           headers=ORIGIN, follow_redirects=False)


def to_selected_preview(web, pid, ids=("101", "102"), blank_change=None):
    response = prepare(web, pid, ids)
    assert response.status_code == 303, response.text
    row_id = int(response.headers["location"].split("/")[-1])
    blank_body = deepcopy(BLANK)
    blank_body["linkedIssues"] = [{"id": int(h), "type": "SAST", "severity": 2, "createTs": 1793318400000}
                                  for h in ids]
    if blank_change:
        blank_change(blank_body)
    hub_job(web, body=blank_body, raw=True)
    hub_job(web, body=SERVICE, raw=True)
    return web.app.state.db.hub_defect(row_id)


def selected_create(web, pid, row, **changes):
    html = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    fields = form_of(html)
    return web.client.post(f"/projects/{pid}/hub/defects/{row['id']}/create",
                           data={"create_snapshot": fields.get("create_snapshot", ""), **changes}, headers=AS_JSON)


def test_selected_atomic_decision_exact_targets_and_one_post(web):
    pid = setup(web)
    db = web.app.state.db
    page = web.client.get(url(pid), params={"hub_id": ["101", "102"]})
    assert page.status_code == 200
    assert db._scalar("SELECT count(*) FROM reviews") == 0
    assert db._scalar("SELECT count(*) FROM hub_ops") == 0
    row = to_selected_preview(web, pid)
    assert db._scalar("SELECT count(*) FROM hub_defects") == 1
    assert row["draft_command_text"] == row["command_text"]
    assert row["draft_owner_id"] == row["id"]
    assert "demo.py:" not in row["command_text"] and "other.py:" not in row["command_text"]
    targets = loads(row["targets_json"], [])
    assert [t["hub_id"] for t in targets] == ["101", "102"]
    for t in targets:
        review = db.get_review(pid, t["hub_id"])
        assert review["final_verdict"] == "true_positive" and review["reviewed"]
        assert review["final_comment"] == REASON and review["final_fix"] == FIX
        assert review["revision"] == t["revision"] and t["decision_hash"]
        assert not review["entered_hub"]
    assert db.get_review(pid, "103") is None
    assert selected_create(web, pid, row).status_code == 200
    assert selected_create(web, pid, row).status_code == 409
    post = hub_job(web, body={"id": 555}, raw=True)
    assert post["method"] == "POST" and post["path"] == "/defects"
    remote = dict(deepcopy(post["body"]), id=555, createTs=1793318400000)
    hub_job(web, body=remote, raw=True)
    assert db.hub_defect(row["id"])["state"] == "done"
    assert db.get_review(pid, "101")["entered_hub"] and db.get_review(pid, "102")["entered_hub"]
    assert db.get_review(pid, "103") is None
    assert db._scalar("SELECT count(*) FROM hub_ops WHERE purpose='status'") == 0
    assert db._scalar("SELECT count(*) FROM hub_ops WHERE purpose='defect_create'") == 1
    no_job(web)


@pytest.mark.parametrize("path", ["selected", "card"])
@pytest.mark.parametrize("change", ["extra", "missing", "wrong_type", "malformed", "no_links", "duplicate"])
def test_blank_composition_refused_before_post(web, path, change):
    def corrupt(body):
        if change == "extra":
            body["linkedIssues"].append({"id": 999, "type": "SAST"})
        elif change == "missing":
            body["linkedIssues"] = []
        elif change == "wrong_type":
            body["linkedIssues"][0]["type"] = "SCA_S"
        elif change == "malformed":
            body["linkedIssues"].append({"id": True, "type": "SAST"})
        elif change == "no_links":
            body.pop("linkedIssues")
        else:
            body["linkedIssues"].append(deepcopy(body["linkedIssues"][0]))
    if path == "selected":
        pid = setup(web)
        row = to_selected_preview(web, pid, blank_change=corrupt)
        response = selected_create(web, pid, row)
    else:
        pid, card_url = sast_ready(web)
        body = deepcopy(BLANK)
        corrupt(body)
        row = to_preview(web, pid, card_url, blank_body=body)
        response = create(web, pid, row["id"])
    assert response.status_code == 400, response.text
    assert "linkedIssues" in response.text
    db = web.app.state.db
    after = db.hub_defect(row["id"])
    assert after["state"] == "preview"
    assert after["targets_json"] == row["targets_json"] and after["blank_json"] == row["blank_json"]
    assert db._scalar("SELECT count(*) FROM hub_ops WHERE purpose='defect_create'") == 0
    no_job(web)


def test_overwrite_binds_text_and_revision_and_preserves_errors(web):
    pid = setup(web)
    db = web.app.state.db
    db.save_review(pid, "102", decision="disagree", final_verdict="false_positive", final_comment="Прежний текст.", reviewed=True)
    response = preview(web, pid)
    fields = form_of(response.text)
    assert "Прежний текст." in response.text and 'id="selected-replacements"' in response.text
    refused = prepare(web, pid, fields=fields, overwrite="")
    assert refused.status_code == 409 and "Подтвердите перезапись" in refused.text and REASON in refused.text
    assert prepare(web, pid, fields=fields, comment=REASON + " Изменение.").status_code == 409
    assert db.get_review(pid, "101") is None
    assert prepare(web, pid, fields=fields).status_code == 303
    assert db._scalar("SELECT count(*) FROM review_texts") == 1


@pytest.mark.parametrize("stage", ["review", "row", "queue"])
def test_prepare_failure_rolls_back_everything(web, monkeypatch, stage):
    pid = setup(web)
    db = web.app.state.db
    for ident in ("101", "102"):
        db.save_review(pid, ident, decision="disagree", final_verdict="false_positive",
                       final_comment="Прежнее решение.", reviewed=True)
    tables = ("reviews", "review_texts", "hub_defects", "hub_defect_history", "hub_ops", "defects")
    before = {table: db._all(f"SELECT * FROM {table} ORDER BY 1, 2") for table in tables}
    fields = form_of(preview(web, pid).text)
    name = {"review": "_save_review_in", "row": "_hub_defect_row", "queue": "_hub_insert"}[stage]
    original = getattr(db, name)
    calls = []
    def fail(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(result)
        if stage != "review" or len(calls) == 2:
            raise ValueError("Синтетический сбой")
        return result
    monkeypatch.setattr(db, name, fail)
    response = prepare(web, pid, fields=fields)
    assert response.status_code == 409, response.text
    for table in tables:
        assert db._all(f"SELECT * FROM {table} ORDER BY 1, 2") == before[table], table


def test_selection_limits_and_duplicates():
    assert defect_selected.selection([]) == []
    assert defect_selected.selection(["1", "1"]) == ["1"]
    assert len(defect_selected.selection(map(str, range(50)))) == 50
    with pytest.raises(hub_defects.DefectRefused, match="51"):
        defect_selected.selection(map(str, range(51)))


@pytest.mark.parametrize("field,value,reason", [("rule", "Другая категория", "другая категория"),
                                               ("cwe", ["CWE-79"], "другой набор CWE"),
                                               ("codebase", "other", "другая кодовая база"),
                                               ("kind", "SCA", "не SAST")])
def test_exclusions_before_confirmation(web, field, value, reason):
    one, two = sast("101"), sast("102", line=3)
    setattr(two, field, value)
    pid = project(web, [one, two])
    response = preview(web, pid)
    assert reason in response.text
    assert prepare(web, pid, fields=form_of(response.text)).status_code == 303
    db = web.app.state.db
    assert db.get_review(pid, "101")["reviewed"]
    assert db.get_review(pid, "102") is None


def test_cwe_order_and_ambiguous_id(web):
    one, two, alias = sast("101"), sast("102", line=3), sast("00102", line=4)
    one.cwe, two.cwe = ["CWE-89", "CWE-20"], ["CWE-20", "CWE-089", "CWE-20"]
    pid = project(web, [one, two])
    assert "Войдут (2)" in preview(web, pid).text
    db = web.app.state.db
    db.save_import(pid, "x.xlsx", "xlsx", [], {}, [], order_findings([one, two, alias]))
    response = preview(web, pid)
    assert "неоднозначное" in response.text and "Войдут (1)" in response.text


@pytest.mark.parametrize("change", ["review", "mark", "number", "source", "presence", "destination", "base", "data", "verdict", "code"])
def test_stale_confirmation_refuses_entire_prepare(web, change, monkeypatch):
    pid = setup(web)
    db = web.app.state.db
    fields = form_of(preview(web, pid).text)
    if change in ("review", "mark"):
        db.save_review(pid, "102", decision="disagree", final_verdict="false_positive", final_comment="Другой текст.", reviewed=True)
        if change == "mark":
            fields = form_of(preview(web, pid).text)
            db.mark_entered(pid, "102", True)
    elif change == "number":
        db.set_defect_number(pid, defect.defect_key_sast("102"), 4)
    elif change == "source":
        with db._tx() as c:
            c.execute("UPDATE projects SET repos_dir='another' WHERE id=?", (pid,))
    elif change == "presence":
        with db._tx() as c:
            c.execute("UPDATE findings SET missing=1 WHERE project_id=? AND hub_id='102'", (pid,))
    elif change == "destination":
        db.update_project(pid, hub_app_id=8)
    elif change in ("data", "verdict"):
        with db._tx() as c:
            if change == "data":
                c.execute("UPDATE findings SET data_json=(data_json::jsonb || jsonb_build_object('snippet','changed'))::text WHERE hub_id='102'")
            else:
                c.execute("INSERT INTO cases(project_id,hub_id,case_hash,context_json,updated_at) VALUES (?,'102','new','{}','now')", (pid,))
    elif change == "code":
        from app.routes import findings as card
        original = card.check_code
        def changed(*a, **k):
            result = original(*a, **k)
            return {**result, "hash": "new-code-hash"} if a[2].hub_id == "102" else result
        monkeypatch.setattr(card, "check_code", changed)
    else:
        with db._tx() as c:
            c.execute("INSERT INTO hub_entity_versions(project_id,hub_url,app_id,entity_kind,entity_key,accepted_epoch)"
                      " VALUES (?,'https://hub.example.org',7,'issue','SAST:102',1)", (pid,))
    before = db._all("SELECT * FROM reviews ORDER BY hub_id")
    response = prepare(web, pid, fields=fields)
    assert response.status_code == 409 and "после показа" in response.text
    assert db._all("SELECT * FROM reviews ORDER BY hub_id") == before
    assert db._scalar("SELECT count(*) FROM hub_defects") == 0


def test_two_tabs_and_cancel_preserve_saved_decisions(web):
    pid = setup(web)
    fields = form_of(preview(web, pid).text)
    second = form_of(preview(web, pid, ("102", "103")).text)
    assert prepare(web, pid, fields=fields).status_code == 303
    assert prepare(web, pid, fields=second).status_code == 409
    assert web.app.state.db.get_review(pid, "103") is None


def test_issue_ids_boundary_before_any_write(web):
    # Предел issueIds – 2000 знаков (hub_ops.ISSUE_IDS_MAX; прежние 200 не вмещали крупный дефект).
    # Через маршрут граница недостижима: выбор ограничен MAX_SELECTED = 50 целями (50 × 12 цифр + 49 запятых = 649 знаков),
    # поэтому здесь – состав длиннее прежних 200 знаков проходит без отказа; сама граница 2000/2001 – в
    # tests/test_hub_issue_ids_limit.py (blank_request, check_request).
    ids = [str(100000000001 + i) for i in range(50)]
    assert len(",".join(ids)) == 649 > 200
    pid = project(web, [sast(h, line=i + 1) for i, h in enumerate(ids)])
    assert prepare(web, pid, ids).status_code == 303


def group_project(web):
    findings = [sast("101", 2), sast("102", 3), sast("103", 4), sast("901", 2), sast("902", 3), sast("903", 4)]
    return project(web, findings)


def occupied_group(web, pid, neighbor, state="done", origin="app"):
    db = web.app.state.db
    body = defect.sast_body(sast(neighbor), "true_positive", REASON, FIX, "Тестовая команда")
    row = db.hub_defect_insert(pid, kind="SAST", number=9, summary="ID9 - Демо (SAST)", anchor_hub_id=neighbor,
                               targets=[{"hub_id": neighbor, "issue_id": int(neighbor), "issue_type": "SAST"}],
                               number_keys=[], command_text=body if origin == "app" else "Другой текст Hub",
                               hub_url="https://hub.example.org", app_id=7)
    db.hub_defect_update(row["id"], state=state, hub_defect_id="555" if state in ("done", "mismatch") else "", origin=origin)
    return row


@pytest.mark.parametrize("state", ["done", "mismatch", "creating", "unknown", "unconfirmed", "blank", "preview"])
@pytest.mark.parametrize("neighbor", ["901", "902", "903"])
def test_group_conflicts_excluded_before_confirmation(web, state, neighbor):
    pid = group_project(web)
    occupied_group(web, pid, neighbor, state)
    response = preview(web, pid, ("101", "102", "103"))
    assert "Войдут (2)" in response.text
    excluded = response.text.split('id="selected-excluded"')[1].split("</ul>")[0]
    assert str(int(neighbor) - 800) in excluded and "в группе" in excluded.lower()


def test_create_after_anchor_excluded_uses_final_groups(web):
    pid = group_project(web)
    db = web.app.state.db
    occupied_group(web, pid, "901")
    before = db.get_review(pid, "101")
    row = to_selected_preview(web, pid, blank_change=lambda body: body.update(
        linkedIssues=[link for link in body["linkedIssues"] if link["id"] == 102]))
    assert row["anchor_hub_id"] == "101"
    assert [t["hub_id"] for t in loads(row["targets_json"], [])] == ["102"]
    response = selected_create(web, pid, row)
    assert response.status_code == 200, response.text
    post = hub_job(web, body={"id": 556}, raw=True)
    assert post["method"] == "POST" and post["path"] == "/defects"
    assert [t["id"] for t in post["body"]["linkedIssues"]] == [102]
    hub_job(web, body=dict(deepcopy(post["body"]), id=556, createTs=1793318400000), raw=True)
    assert db.hub_defect(row["id"])["state"] == "done"
    assert db.get_review(pid, "102")["entered_hub"]
    assert db.get_review(pid, "101") == before
    assert db._scalar("SELECT count(*) FROM hub_ops WHERE purpose='defect_create'") == 1
    assert db._scalar("SELECT count(*) FROM hub_ops WHERE purpose='status'") == 0
    no_job(web)


@pytest.mark.parametrize("changed_id", ["101", "102"])
def test_code_change_after_reviews_rolls_back_prepare(web, monkeypatch, changed_id):
    pid = setup(web)
    db = web.app.state.db
    db.set_repos_dir(pid, "team")
    db.set_codebase_folder(pid, "demo", "demo", manual=True)
    repo = web.tmp / "repos" / "team" / "demo"
    repo.mkdir()
    code_a = "value = input()\nquery = 'SELECT ' + value\nexecute(query)\n"
    for name in ("demo.py", "other.py"):
        (repo / name).write_text(code_a, encoding="utf-8")
    changed = repo / ("demo.py" if changed_id == "101" else "other.py")
    assert db.get_case(pid, changed_id) is None
    fields = form_of(preview(web, pid).text)
    tables = ("reviews", "review_texts", "hub_defects", "hub_defect_history", "hub_ops", "defects")
    before = {table: db._all(f"SELECT * FROM {table} ORDER BY 1, 2") for table in tables}
    original = db._save_review_in
    saved_codes = []

    def change_after_save(*args, **kwargs):
        result = original(*args, **kwargs)
        saved_codes.append(result)
        if len(saved_codes) == 2:
            changed.write_text(code_a.replace("value", "other"), encoding="utf-8")
        return result

    monkeypatch.setattr(db, "_save_review_in", change_after_save)
    response = prepare(web, pid, fields=fields)
    assert len(saved_codes) == 2
    assert response.status_code == 409 and "после показа" in response.text
    for table in tables:
        assert db._all(f"SELECT * FROM {table} ORDER BY 1, 2") == before[table], table
    no_job(web)


@pytest.mark.parametrize("moment", ["prepare", "create"])
@pytest.mark.parametrize("neighbor", ["902", "903"])
@pytest.mark.parametrize("origin", ["app", "import"])
def test_late_group_conflict_refuses_whole_operation(web, moment, neighbor, origin):
    pid = group_project(web)
    db = web.app.state.db
    if moment == "prepare":
        fields = form_of(preview(web, pid, ("101", "102", "103")).text)
    else:
        row = to_selected_preview(web, pid, ("101", "102", "103"))
    occupied_group(web, pid, neighbor, origin=origin)
    before = db._all("SELECT * FROM reviews ORDER BY 1, 2")
    if moment == "prepare":
        response = prepare(web, pid, fields=fields)
        assert response.status_code == 409
        assert db._scalar("SELECT count(*) FROM hub_defects") == 1
    else:
        response = selected_create(web, pid, row)
        assert response.status_code == 400, response.text
        fresh = db.hub_defect(row["id"])
        assert fresh["targets_json"] == row["targets_json"] and fresh["blank_json"] == row["blank_json"]
        assert fresh["state"] == "preview"
    assert db._all("SELECT * FROM reviews ORDER BY 1, 2") == before
    assert db._scalar("SELECT count(*) FROM hub_ops WHERE purpose='defect_create'") == 0


def test_selected_busy_neighbor_cannot_be_skipped_as_own_target(web):
    pid = group_project(web)
    occupied_group(web, pid, "902")
    response = preview(web, pid, ("101", "102", "902"))
    assert "Войдут (1)" in response.text
    assert prepare(web, pid, fields=form_of(response.text)).status_code == 303
    assert web.app.state.db.get_review(pid, "102") is None


@pytest.mark.parametrize("comment,fix", [("", FIX), ("Подтверждено:", FIX), (REASON, "```c\nfree(p);\n```")])
def test_invalid_text_kept_without_local_writes(web, comment, fix):
    pid = setup(web)
    response = web.client.post(url(pid), data={"hub_id": ["101", "102"], "action": "preview", "comment": comment,
                                              "fix": fix}, headers=ORIGIN)
    assert response.status_code == 400
    assert 'id="selected-prepare"' not in response.text
    assert web.app.state.db._scalar("SELECT count(*) FROM reviews") == 0


def test_comment_origin_checked_on_second_target(web, monkeypatch):
    from app.routes import findings as card
    pid = setup(web)
    original = card.comment_origin
    monkeypatch.setattr(card, "comment_origin", lambda *a, **k: "false_positive" if k.get("hub_id") == "102" else original(*a, **k))
    response = web.client.post(url(pid), data={"hub_id": ["101", "102"], "action": "preview", "comment": REASON,
                                              "fix": FIX}, headers=ORIGIN)
    assert response.status_code == 400 and "102" in response.text and "к другому исходу" in response.text
    assert web.app.state.db._scalar("SELECT count(*) FROM reviews") == 0


@pytest.mark.parametrize("moment", ["preview", "prepare", "create"])
def test_stale_verdict_never_silently_saves_unreviewed(web, monkeypatch, moment):
    from app.routes import findings as card
    pid = setup(web)
    if moment == "prepare":
        fields = form_of(preview(web, pid).text)
    elif moment == "create":
        row = to_selected_preview(web, pid)
    original = card.check_code
    def stale(*a, **k):
        code = original(*a, **k)
        return {**code, "stale_verdict": True} if a[2].hub_id == "102" else code
    monkeypatch.setattr(card, "check_code", stale)
    if moment == "preview":
        response = preview(web, pid)
        # ADR-0147: находка не исключается, а входит с предупреждением; смена после предпросмотра – отказ ниже
        assert "Войдут (2)" in response.text and "не совпадает с текущим кодом" in response.text
    elif moment == "prepare":
        assert prepare(web, pid, fields=fields).status_code == 409
        assert web.app.state.db.get_review(pid, "101") is None
    else:
        assert selected_create(web, pid, row).status_code == 400
        assert web.app.state.db.hub_defect(row["id"])["state"] == "preview"


@pytest.mark.parametrize("change", ["blank", "draft", "targets", "mark", "data", "verdict", "number"])
def test_create_rechecks_shown_snapshot(web, change):
    pid = setup(web)
    db = web.app.state.db
    row = to_selected_preview(web, pid)
    signature = hub_defects.creation_signature(row)
    with db._tx() as c:
        if change == "blank":
            blank_body = loads(row["blank_json"], {})
            blank_body["description"] += "<p>Изменённая заготовка</p>"
            c.execute("UPDATE hub_defects SET blank_json=? WHERE id=?", (dumps(blank_body), row["id"]))
        elif change == "draft":
            c.execute("UPDATE hub_defects SET draft_revision=draft_revision+1 WHERE id=?", (row["id"],))
        elif change == "targets":
            c.execute("UPDATE hub_defects SET targets_json=? WHERE id=?", (dumps(loads(row["targets_json"], [])[:1]), row["id"]))
        elif change == "mark":
            c.execute("UPDATE reviews SET entered_hub=1,entered_hub_at='2099-01-01' WHERE hub_id='102'")
        elif change == "data":
            c.execute("UPDATE findings SET data_json=(data_json::jsonb || jsonb_build_object('snippet','changed'))::text WHERE hub_id='102'")
        elif change == "verdict":
            c.execute("INSERT INTO cases(project_id,hub_id,case_hash,context_json,updated_at) VALUES (?,'102','new','{}','now')", (pid,))
        else:
            c.execute("INSERT INTO defects(project_id,defect_key,number,updated_at) VALUES (?,?,8,'now')",
                      (pid, defect.defect_key_sast("102")))
    response = web.client.post(f"/projects/{pid}/hub/defects/{row['id']}/create", data={"create_snapshot": signature}, headers=AS_JSON)
    assert response.status_code == 400, response.text
    assert db._scalar("SELECT count(*) FROM hub_ops WHERE purpose='defect_create'") == 0


@pytest.mark.parametrize("mode", ["normal", "lost", "missing"])
def test_independent_hub_api_only_create_update_pull_and_late_effects(web, mode):
    from app import defect_drafts, hub_pull
    from selected_hub_support import SelectedHub, drain
    from test_hub_pull import read, accept
    from test_hub_defects import verify
    db = web.app.state.db
    hub = SelectedHub(lost_create=mode == "lost", missing_first=mode == "missing")
    pid = project(web, [])
    accept(db, read((db, pid), hub))
    assert db._scalar("SELECT count(*) FROM findings WHERE file_import_id IS NOT NULL") == 0
    response = prepare(web, pid, ("1", "2"))
    assert response.status_code == 303, response.text
    row_id = int(response.headers["location"].rsplit("/", 1)[1])
    drain(db, hub, pid)
    row = db.hub_defect(row_id)
    assert row["state"] == "preview"
    statuses = {i: v["status"] for i, v in hub.issues.items()}
    assert selected_create(web, pid, row).status_code == 200
    drain(db, hub, pid)
    if mode == "lost":
        assert db.hub_defect(row_id)["state"] == "unknown"
        assert verify(web, pid, row_id).status_code == 200
        drain(db, hub, pid)
    row = db.hub_defect(row_id)
    assert row["state"] == "done", row["error"]
    assert len([r for r in hub.calls if r["method"] == "POST" and r["path"] == "/defects"]) == 1
    assert len([r for r in hub.calls if r["method"] == "POST" and r["path"].endswith("/link")]) == (mode == "missing")
    assert statuses == {i: v["status"] for i, v in hub.issues.items()}
    assert db.get_review(pid, "1")["entered_hub"] and db.get_review(pid, "2")["entered_hub"]
    # Одиночный черновик выбранного дефекта допускает обычный цикл обновления.
    defect_drafts.save(db, row, str(row["draft_revision"]), summary=row["draft_summary"],
                       command=row["draft_command_text"] + "\n2) Дополнение оператора.")
    response = web.client.post(f"/projects/{pid}/hub/defects/{row_id}/update", data={"back": "defect-card"}, headers=ORIGIN)
    assert response.status_code == 200, response.text
    drain(db, hub, pid)
    page = web.client.get(f"/projects/{pid}/defects/{row_id}")
    assert hub_defects.update_state(db.hub_defect(row_id))["phase"] == "preview", hub_defects.update_state(db.hub_defect(row_id)).get("refusals")
    assert "Дополнение оператора." in page.text
    fields = form_of(page.text)
    response = web.client.post(f"/projects/{pid}/hub/defects/{row_id}/update-put",
                               data={k: fields.get(k, "") for k in ("generation", "shown")}, headers=AS_JSON)
    assert response.status_code == 200, (response.text, fields, loads(db.hub_defect(row_id)["update_json"], {}))
    drain(db, hub, pid, progress=lambda: web.client.get(f"/projects/{pid}/defects/{row_id}"))
    assert len([r for r in hub.calls if r["method"] == "PUT"]) == 1
    assert "Дополнение оператора." in hub.defects[555]["description"]
    fresh = db.hub_defect(row_id)
    defect_drafts.save(db, fresh, str(fresh["draft_revision"]), summary=fresh["draft_summary"],
                       command=fresh["draft_command_text"] + "\n3) Ещё не отправлено.")
    # Неотправленный черновик сохраняется отдельно при принятии изменённых полей и состава Hub.
    hub.defects[555]["linkedIssues"] = [t for t in hub.defects[555]["linkedIssues"] if t["id"] != 2]
    hub.defects[555]["description"] = hub.defects[555]["description"].replace("Параметризовать", "Исправить")
    rid = read((db, pid), hub)
    before_ops = db._all("SELECT * FROM hub_ops ORDER BY 1, 2")
    result = accept(db, rid)
    assert not result["skipped"], result
    assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == before_ops
    assert not db.get_review(pid, "2")["entered_hub"] and db.get_review(pid, "2")["reviewed"]
    assert db.get_review(pid, "2")["final_verdict"] == "true_positive"
    assert db.get_review(pid, "1")["entered_hub"]
    assert db._one("SELECT * FROM hub_sync_pending WHERE entity_kind='defect'")
    before = db.hub_defect(row_id)
    if row["read_op_id"]:
        hub_defects._on_read(db, row, db.hub_op(row["read_op_id"]))
    hub_defects._apply_effects(db, row, "2099-01-01T00:00:00Z")
    hub_defects.sync(db, row)
    assert db.hub_defect(row_id) == before and not db.get_review(pid, "2")["entered_hub"]
    token = hub_pull.preview(db, db._one("SELECT * FROM hub_defect_sync_runs WHERE id=?", (rid,)))["token"]
    count = db._scalar("SELECT count(*) FROM hub_sync_applications")
    hub_pull.apply(db, rid, token)
    assert db._scalar("SELECT count(*) FROM hub_sync_applications") == count


@pytest.mark.parametrize("count", [0, 1, 50, 51])
def test_full_selection_boundaries(web, count):
    pid = setup(web, max(count, 1))
    ids = [str(101 + i) for i in range(count)]
    response = web.client.get(url(pid), params={"hub_id": ids})
    db = web.app.state.db
    assert db._scalar("SELECT count(*) FROM hub_ops") == 0
    assert response.status_code == (400 if count == 51 else 200)
    if count in (1, 50):
        assert prepare(web, pid, ids + ids[:1]).status_code == 303
        row = db._one("SELECT * FROM hub_defects")
        assert len(loads(row["targets_json"], [])) == count
        assert db._scalar("SELECT count(*) FROM reviews WHERE reviewed=1") == count
    else:
        assert 'id="selected-prepare"' not in response.text


@pytest.mark.parametrize("change", ["outcome", "comment", "fix"])
def test_each_content_change_requires_overwrite(web, change):
    pid = setup(web)
    old = dict(final_verdict="true_positive", final_comment=REASON, final_fix=FIX)
    old[{"outcome": "final_verdict", "comment": "final_comment", "fix": "final_fix"}[change]] = (
        "false_positive" if change == "outcome" else "Прежний текст.")
    web.app.state.db.save_review(pid, "102", decision="disagree", reviewed=True, **old)
    fields = form_of(preview(web, pid).text)
    assert prepare(web, pid, fields=fields, overwrite="").status_code == 409


def test_same_content_preserves_dates_marks_and_prefills_text(web):
    pid = setup(web)
    db = web.app.state.db
    for ident in ("101", "102"):
        db.save_review(pid, ident, decision="agree", final_verdict="true_positive", final_comment=REASON,
                       final_fix=FIX, reviewed=True)
        db.mark_entered(pid, ident, True)
    before = {ident: db.get_review(pid, ident) for ident in ("101", "102")}
    page = web.client.get(url(pid), params={"hub_id": ["101", "102"]})
    assert REASON in page.text and FIX in page.text
    assert 'id="selected-overwrite"' not in preview(web, pid).text
    assert prepare(web, pid, overwrite="").status_code == 303
    for ident, old in before.items():
        fresh = db.get_review(pid, ident)
        for key in ("entered_hub", "entered_hub_at", "reviewed_at", "decided_at"):
            assert fresh[key] == old[key], key


@pytest.mark.parametrize("kind", ["none", "common", "partial", "different", "foreign", "reserved"])
def test_number_ownership_before_prepare(web, kind):
    pid = setup(web)
    db = web.app.state.db
    if kind != "none":
        db.set_defect_number(pid, defect.defect_key_sast("101"), 4)
    if kind in ("common", "different"):
        db.set_defect_number(pid, defect.defect_key_sast("102"), 4 if kind == "common" else 5)
    elif kind == "foreign":
        db.set_defect_number(pid, defect.defect_key_sast("103"), 4)
    elif kind == "reserved":
        row = occupied_group(web, pid, "103", state="preview")
        db.hub_defect_update(row["id"], number=4)
    before = db._all("SELECT * FROM reviews ORDER BY 1, 2")
    response = prepare(web, pid)
    if kind in ("different", "foreign", "reserved"):
        assert response.status_code == 409
        assert db._all("SELECT * FROM reviews ORDER BY 1, 2") == before
        assert db._scalar("SELECT count(*) FROM hub_ops") == 0
    else:
        assert response.status_code == 303
        assert db._one("SELECT * FROM hub_defects")["number"] == (1 if kind == "none" else 4)


@pytest.mark.parametrize("state", ["queued", "taken", "unknown"])
def test_status_operation_blocks_overwrite(web, state):
    from app import hub_status
    pid = setup(web)
    db = web.app.state.db
    fields = form_of(preview(web, pid).text)
    target = {"hub_id": "102", "issue_id": 102, "issue_type": "SAST"}
    # Запрос стандартного пути статуса; состояние операции не освобождает цель.
    request = hub_status.status_request([target], "False Positive", "Тестовая причина.", "")
    op = db.hub_enqueue(purpose="status", request=request, hub_url="https://hub.example.org", app_id=7,
                        project_id=pid, targets=[target])
    with db._tx() as c:
        c.execute("UPDATE hub_ops SET state=? WHERE id=?", (state, op["id"]))
    assert "незавершённая операция статуса" in preview(web, pid).text
    assert prepare(web, pid, fields=fields).status_code == 409
    assert db._scalar("SELECT count(*) FROM reviews") == 0


def test_anchor_change_recalculates_and_invalidates_confirmation(web):
    pid = setup(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE findings SET data_json=(data_json::jsonb || jsonb_build_object('rule','Другая категория'))::text WHERE hub_id='103'")
    initial = preview(web, pid, ("101", "102", "103"))
    assert "Войдут (2)" in initial.text
    assert prepare(web, pid, fields=form_of(initial.text), anchor="103").status_code == 409
    changed = preview(web, pid, ("101", "102", "103"), anchor="103")
    assert "Войдут (1)" in changed.text
    assert prepare(web, pid, fields=form_of(changed.text)).status_code == 303
    assert db.get_review(pid, "101") is None and db.get_review(pid, "103")["reviewed"]


def test_actual_post_body_checked_after_builder(web, monkeypatch):
    pid = setup(web)
    row = to_selected_preview(web, pid)
    original = hub_defects.create_body
    def wrong(*a, **k):
        body = original(*a, **k)
        body["linkedIssues"] = body["linkedIssues"][:1]
        return body
    monkeypatch.setattr(hub_defects, "create_body", wrong)
    assert selected_create(web, pid, row).status_code == 400
    no_job(web)


@pytest.mark.parametrize("change", ["extra", "missing", "malformed", "wrong_type", "app", "text", "no_links"])
def test_selected_wrong_read_never_confirms(web, change):
    pid = setup(web)
    db = web.app.state.db
    row = to_selected_preview(web, pid)
    assert selected_create(web, pid, row).status_code == 200
    post = hub_job(web, body={"id": 555}, raw=True)
    remote = dict(deepcopy(post["body"]), id=555)
    if change == "extra":
        remote["linkedIssues"].append({"id": 999, "type": "SAST"})
    elif change == "missing":
        remote["linkedIssues"].pop()
    elif change == "malformed":
        remote["linkedIssues"][0]["id"] = True
    elif change == "wrong_type":
        remote["linkedIssues"][0]["type"] = "SCA_S"
    elif change == "app":
        remote["appId"] = 8
    elif change == "text":
        remote["description"] = "Другой текст."
    else:
        remote.pop("linkedIssues")
    hub_job(web, body=remote, raw=True)
    assert db.hub_defect(row["id"])["state"] != "done"
    assert not db.get_review(pid, "101")["entered_hub"] and not db.get_review(pid, "102")["entered_hub"]


def test_late_manual_number_and_changed_decision_not_overwritten(web):
    pid = setup(web)
    db = web.app.state.db
    row = to_selected_preview(web, pid)
    assert selected_create(web, pid, row).status_code == 200
    post = hub_job(web, body={"id": 555}, raw=True)
    db.set_defect_number(pid, defect.defect_key_sast("102"), 8)
    db.save_review(pid, "102", decision="disagree", final_verdict="false_positive", final_comment="Новый вывод.", reviewed=True)
    hub_job(web, body=dict(deepcopy(post["body"]), id=555), raw=True)
    assert db.defect_number(pid, defect.defect_key_sast("102")) == 8
    assert db.get_review(pid, "102")["final_verdict"] == "false_positive"
    assert not db.get_review(pid, "102")["entered_hub"]
    assert db.get_review(pid, "101")["entered_hub"]


@pytest.mark.parametrize("ident", ["missing", "bad-id", "0"])
def test_absent_and_invalid_identifiers_are_explained_before_confirm(web, ident):
    pid = project(web, [sast("101"), sast(ident, 3)])
    db = web.app.state.db
    if ident == "missing":
        with db._tx() as c:
            c.execute("UPDATE findings SET missing=1 WHERE project_id=? AND hub_id=?", (pid, ident))
    page = preview(web, pid, ("101", ident))
    assert "Войдут (1)" in page.text and "Исключены (1)" in page.text
    excluded = page.text.split('id="selected-excluded"')[1].split('</ul>')[0]
    assert ident in excluded and ("отсутствует" in excluded if ident == "missing" else "номер" in excluded.lower())
    assert prepare(web, pid, fields=form_of(page.text)).status_code == 303
    assert db.get_review(pid, ident) is None


def test_level_codes_only_from_hub_defects_and_not_contradictory():
    """Hub отказывает в создании без priorityId («invalid priority code null»), а заготовка кода не даёт; код – только
    из соответствия, которое дал сам Hub в прочитанных дефектах (ADR-0126: ID из rank не выводится)."""
    objects = [{"priority": {"name": "Major", "rank": 2}, "priorityId": 2,
                "severity": {"name": "Medium", "rank": 1}, "severityId": 1},
               {"priority": {"name": "Critical", "rank": 1}, "priorityId": 1,
                "severity": {"name": "Medium", "rank": 1}, "severityId": 7},  # противоречие – не берётся
               {"priority": {"name": "Blocker", "rank": 0}, "priorityId": True},  # не число
               {"priority": {"name": "Minor"}, "priorityId": 3}, None, "текст"]
    codes = hub_defects.level_codes(objects)
    assert codes == {("priority", "Major", 2): 2, ("priority", "Critical", 1): 1}
    body = {"priority": {"name": "Major", "rank": 2}, "severity": {"name": "Medium", "rank": 1}}
    used = hub_defects.fill_level_codes(body, codes, dict(body))
    assert body["priorityId"] == 2 and "severityId" not in body and used == {("priority", "Major", 2): 2}
    assert not hub_defects.level_codes_changed(used, codes)
    assert hub_defects.level_codes_changed(used, {})  # соответствие пропало или стало противоречивым
    blank = {"priority": {"name": "Major", "rank": 2}, "priorityId": 4}
    kept = dict(blank)
    assert hub_defects.fill_level_codes(kept, codes, blank) == {} and kept["priorityId"] == 4  # комбинация Hub
    other = {"priority": {"name": "Major", "rank": 3}}
    hub_defects.fill_level_codes(other, codes, dict(other))
    assert "priorityId" not in other  # другой rank – соответствия нет, кода в заготовке нет
    # смена уровня при коде в заготовке: код нового уровня из соответствия или отказ (ревью dev11 A2/B2)
    changed = {**blank, "priority": {"name": "Critical", "rank": 1}}
    hub_defects.fill_level_codes(changed, codes, blank)
    assert changed["priorityId"] == 1
    with pytest.raises(hub_defects.DefectRefused, match="priorityId"):
        hub_defects.fill_level_codes({**blank, "priority": {"name": "Minor", "rank": 3}}, codes, blank)
    # строковый справочник: прежний выбор – уровень заготовки целиком, с rank (ревью dev11 A1)
    assert hub_defects.pick_level(["Major", "Critical"], "Major", blank["priority"]) == blank["priority"]
    assert hub_defects.pick_level(["Major", "Critical"], "Critical", blank["priority"]) == {"name": "Critical"}


def test_level_diffs_compare_sent_levels_and_codes():
    sent = {"priority": {"name": "Major", "rank": 2}, "priorityId": 2, "severity": {"name": "Medium", "rank": 1}}
    assert hub_defects.level_diffs(sent, {"priority": {"name": "Major", "rank": 2, "x": 1}, "priorityId": 2,
                                          "severity": {"name": "Medium", "rank": 1}}) == []
    diffs = hub_defects.level_diffs(sent, {"priority": {"name": "Minor", "rank": 3}, "priorityId": 3,
                                           "severity": {"name": "Medium", "rank": 1}})
    assert len(diffs) == 2 and diffs[0].startswith("priority:") and diffs[1].startswith("priorityId:")
    # rank в ответе необязателен: его отсутствие – не расхождение, другой rank – расхождение (ревью dev11 B, круг 2)
    assert hub_defects.level_diffs(sent, {"priority": {"name": "Major"}, "priorityId": 2}) == []
    assert hub_defects.level_diffs(sent, {"priority": {"name": "Major", "rank": 4}, "priorityId": 2})
    assert hub_defects.level_diffs({"priority": "Major"}, {"priority": "Major"}) == []  # не словарь – как есть
    assert hub_defects.level_diffs({"priority": None}, {"priority": None}) == []


def test_selected_create_sends_level_codes_given_by_hub(web):
    pid = setup(web)
    db = web.app.state.db
    row = to_selected_preview(web, pid)
    # дефект, прочитанный из Hub, с кодами рядом с уровнями (как confirmed_object_json после «Pull из Hub»)
    known = dumps({"priority": {"name": "Major", "rank": 2}, "priorityId": 2,
                   "severity": {"name": "Medium", "rank": 2}, "severityId": 5})
    with db._tx() as c:
        c.execute("INSERT INTO hub_defects(project_id,kind,state,origin,hub_url,app_id,confirmed_object_json,created_at,"
                  "updated_at) SELECT project_id,kind,'done','hub',hub_url,app_id,?,created_at,updated_at"
                  " FROM hub_defects WHERE id=?", (known, row["id"]))
    assert selected_create(web, pid, row).status_code == 200
    post = hub_job(web, body={"id": 555}, raw=True)
    assert post["method"] == "POST" and post["body"]["priorityId"] == 2 and post["body"]["severityId"] == 5
    # подтверждающее чтение вернуло другой код – не «done» и без отметок (ревью dev11 A3/B3)
    remote = dict(deepcopy(post["body"]), id=555, createTs=1793318400000, priorityId=3)
    hub_job(web, body=remote, raw=True)
    after = db.hub_defect(row["id"])
    assert after["state"] == "unconfirmed" and "priorityId" in after["verify_json"]
    assert not db.get_review(pid, "101")["entered_hub"]


def test_selected_create_refuses_when_level_codes_change_before_queue(web, monkeypatch):
    """Соответствие стало противоречивым между сборкой тела и транзакцией постановки (ревью dev11 A4/B1)."""
    pid = setup(web)
    db = web.app.state.db
    row = to_selected_preview(web, pid)
    known = dumps({"priority": {"name": "Major", "rank": 2}, "priorityId": 2})
    with db._tx() as c:
        c.execute("INSERT INTO hub_defects(project_id,kind,state,origin,hub_url,app_id,confirmed_object_json,created_at,"
                  "updated_at) SELECT project_id,kind,'done','hub',hub_url,app_id,?,created_at,updated_at"
                  " FROM hub_defects WHERE id=?", (known, row["id"]))
    original = hub_defects.fill_level_codes

    def racing(body, codes, blank):
        used = original(body, codes, blank)
        with db._tx() as c:  # другая вкладка приняла дефект с другим кодом того же уровня
            c.execute("INSERT INTO hub_defects(project_id,kind,state,origin,hub_url,app_id,confirmed_object_json,"
                      "created_at,updated_at) SELECT project_id,kind,'done','hub',hub_url,app_id,?,created_at,updated_at"
                      " FROM hub_defects WHERE id=?",
                      (dumps({"priority": {"name": "Major", "rank": 2}, "priorityId": 3}), row["id"]))
        return used

    monkeypatch.setattr(hub_defects, "fill_level_codes", racing)
    response = selected_create(web, pid, row)
    assert response.status_code in (400, 409) and "Соответствие кодов" in response.text
    assert db._scalar("SELECT count(*) FROM hub_ops WHERE purpose='defect_create'") == 0


def test_selected_create_without_known_codes_keeps_body(web):
    pid = setup(web)
    row = to_selected_preview(web, pid)
    assert selected_create(web, pid, row).status_code == 200
    post = hub_job(web, body={"id": 555}, raw=True)
    assert "priorityId" not in post["body"] and "severityId" not in post["body"]


def test_selected_page_offers_model_text_only_by_button(web, monkeypatch):
    """Текст дефекта из выбранных можно взять у модели – кнопками, как в карточке находки."""
    from app.routes import findings as card
    pid = setup(web)
    calls = []

    def suggestion(f, case):
        calls.append(f.hub_id)
        return {"comment": "Обоснование <модели>", "points": "Пункт один\nПункт два", "code_dropped": True}

    monkeypatch.setattr(card, "model_suggestion", suggestion)
    html = web.client.get(url(pid), params={"hub_id": ["101", "102"]}).text
    assert set(calls) == {"101"}  # только опорная находка
    assert 'id="take-model-comment"' in html and 'data-text="Обоснование &lt;модели&gt;"' in html
    assert 'id="take-model-points"' in html and 'data-code-dropped="1"' in html
    assert '<textarea name="comment" id="selected-comment" rows="6"></textarea>' in html  # поле само не заполняется
    monkeypatch.setattr(card, "model_suggestion", lambda f, case: {})
    html = web.client.get(url(pid), params={"hub_id": ["101", "102"]}).text
    assert 'id="selected-model-none"' in html and "take-model" not in html


def test_failed_selected_attempt_retries_with_the_same_composition(web):
    """«Подготовить заново» у дефекта из выбранных – та же форма с тем же составом."""
    pid = setup(web)
    row = to_selected_preview(web, pid)
    assert selected_create(web, pid, row).status_code == 200
    hub_job(web, status=400, body={"errorMessage": "Invalid priority code null"}, error="Hub ответил кодом 400")
    card = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert f'href="/projects/{pid}/hub/defect-selected?hub_id=101&amp;hub_id=102" id="hub-defect-retry"' in card

def test_selected_defect_waits_for_sync_after_restore(web):
    """После восстановления копии предпросмотр из выбранных снят, новый не начать до «Синхронизировать» (ADR-0128, п. 9)."""
    pid = setup(web)
    db = web.app.state.db
    row = to_selected_preview(web, pid)
    db.settle_after_restore()
    assert db.hub_defect(row["id"])["state"] == "cancelled"
    response = prepare(web, pid)
    assert response.status_code != 303 and "Синхронизировать" in response.text
    assert db._scalar("SELECT COUNT(*) FROM hub_defects") == 1

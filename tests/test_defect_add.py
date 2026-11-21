"""«Добавить в дефект» и семья строк (ADR-0136). Данные выдуманы, сети нет."""

from __future__ import annotations

import html
import json
import re

import pytest

from app import defect, defect_drafts, hub_defects
from app.db import Database, dumps
from test_defect import save_sast
from app.routes import defect_add
from test_hub_defect_import import apply_sync, deliver, sync, tab, take
from test_hub_defect_update import act, hub_body, phase, put_click, read_job, ready, sent_body, to_done, to_preview as update_preview
from test_hub_defects import FIX, create, hello, hub_job, no_job, sast_ready, to_preview
from test_hub_status_routes import AS_JSON
from test_web import ORIGIN, web  # noqa: F401

OTHER_REASON = "В этой строке данные из запроса тоже попадают в SQL без параметров."


def url(pid: int) -> str:
    return f"/projects/{pid}/hub/add-to-defect"


def created(web) -> tuple[int, dict, str]:
    """Дефект приложения по находке 510001, подтверждённый чтением; находка другой категории 510002 с решением «Подтверждаю дефект»."""
    pid, card = sast_ready(web)
    hello(web)
    row = to_preview(web, pid, card)
    assert create(web, pid, row["id"]).status_code == 200
    job = hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "appId": 7, "summary": row["summary"], "description": job["body"]["description"], "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    fresh = web.app.state.db.hub_defect(row["id"])
    assert fresh["state"] == "done", fresh["error"]
    save_sast(web, pid, "510002", "true_positive", "", OTHER_REASON, FIX)
    return pid, fresh, job["body"]["description"]


def from_import(web, build: bool = False) -> tuple[int, dict]:
    """Дефект №777, занесённый из Hub, с находкой 510001; находка 510002 с решением «Подтверждаю дефект»."""
    pid, row = ready(web, build=build)
    hello(web)
    save_sast(web, pid, "510002", "true_positive", "", OTHER_REASON, FIX)
    return pid, row


def choose(web, pid: int, row: dict, hub_id: str = "510002"):
    return web.client.post(url(pid), data={"hub_id": hub_id, "defect": row["id"], "action": "preview"}, headers=ORIGIN)


def snapshot_of(page: str) -> str:
    return html.unescape(re.search(r'name="snapshot" value="([^"]+)"', page).group(1))


def add(web, pid: int, row: dict, page: str, hub_id: str = "510002", **extra):
    return web.client.post(url(pid), data={"hub_id": hub_id, "defect": row["id"], "action": "apply", "snapshot": snapshot_of(page), "confirm": "1", **extra},
                           headers=ORIGIN, follow_redirects=False)


def add_now(web, pid: int, row: dict, hub_id: str = "510002") -> None:
    shown = choose(web, pid, row, hub_id)
    assert shown.status_code == 200, shown.text
    r = add(web, pid, row, shown.text, hub_id)
    assert r.status_code == 303, r.text


def links(*ids: int) -> list[dict]:
    return [{"id": i, "type": "SAST"} for i in ids]


def in_hub(row: dict, description: str, *ids: int) -> dict:
    return {"id": int(row["hub_defect_id"]), "appId": row["app_id"], "summary": row["summary"], "description": description, "linkedIssues": links(*ids)}


def link_row(db, pid: int, hub_id: str = "510002") -> dict:
    return db.hub_defect_bound(pid, hub_id)


def history_events(db, owner_id: int) -> list[str]:
    return [r["event"] for r in db._all("SELECT event FROM hub_defect_history WHERE defect_id = ? ORDER BY id", (owner_id,))]


# ============================================================================ страница


def test_page_lists_defect_and_preview_sends_nothing(web):
    pid, row, _ = created(web)
    page = web.client.get(url(pid), params={"hub_id": "510002"}).text
    assert f'value="{row["id"]}"' in page and 'id="add-preview"' in page
    shown = choose(web, pid, row)
    assert shown.status_code == 200 and "POST /defects/555/link" in shown.text and OTHER_REASON in shown.text and "не меняется" in shown.text
    assert "&#34;groupId&#34;" in shown.text or '"groupId"' in shown.text, "тело запроса показано целиком"
    no_job(web)


def test_needs_confirmation(web):
    pid, row, _ = created(web)
    page = choose(web, pid, row).text
    r = web.client.post(url(pid), data={"hub_id": "510002", "defect": row["id"], "action": "apply", "snapshot": snapshot_of(page)}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 409 and "Подтвердите" in r.text
    no_job(web)


def test_finding_without_confirmed_defect_decision_is_refused(web):
    pid, _, _ = created(web)
    save_sast(web, pid, "510002", "false_positive", "", "Константа, внешнего ввода нет.")
    page = web.client.get(url(pid), params={"hub_id": "510002"}).text
    assert "Подтверждаю дефект" in page and 'id="add-preview"' not in page


def test_finding_with_model_text_for_another_verdict_is_refused(web, monkeypatch):
    pid, row, _ = created(web)
    from app.routes import findings as card
    monkeypatch.setattr(card, "comment_origin", lambda *a, **k: "false_positive")
    page = web.client.get(url(pid), params={"hub_id": "510002"}).text
    assert "к другому вердикту" in page and 'id="add-preview"' not in page


def test_finding_already_in_defect_is_refused(web):
    pid, _, _ = created(web)
    page = web.client.get(url(pid), params={"hub_id": "510001"}).text
    assert "уже входит" in page and 'id="add-preview"' not in page


def test_defect_with_second_finding_number_is_refused(web):
    pid, row, _ = created(web)
    web.app.state.db.set_defect_number(pid, defect.defect_key_sast("510002"), 99)
    r = choose(web, pid, row)
    assert r.status_code == 400 and "свой номер ID99" in r.text
    no_job(web)


def test_finding_with_the_same_number_can_be_added(web):
    pid, row, description = created(web)
    db = web.app.state.db
    db.set_defect_number(pid, defect.defect_key_sast("510002"), row["number"])
    assert choose(web, pid, row).status_code == 200, "свой ключ находки номер не занимает"
    add_now(web, pid, row)
    hub_job(web, body={})
    hub_job(web, body=in_hub(row, description, 510001, 510002))
    assert link_row(db, pid)["state"] == "done"
    assert db.defect_number(pid, defect.defect_key_sast("510002")) == row["number"]


def test_card_offers_the_page_only_for_a_saved_defect_decision(web):
    pid, _, _ = created(web)
    db = web.app.state.db
    own = web.client.get(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510002')['id']}").text
    assert 'id="hub-defect-add-link"' in own and "hub_id=510002" in own
    bound = web.client.get(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510001')['id']}").text
    assert 'id="hub-defect-add-link"' not in bound
    save_sast(web, pid, "510002", "false_positive", "", "Константа, внешнего ввода нет.")
    other = web.client.get(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510002')['id']}").text
    assert 'id="hub-defect-add-link"' not in other


# ============================================================================ отпечаток показанного


@pytest.mark.parametrize("change", [
    "review", "summary", "number", "accepted", "draft_revision", "text_generation", "members", "group_id"])
def test_each_shown_field_refuses_a_stale_page(web, change):
    pid, row, _ = created(web)
    db = web.app.state.db
    page = choose(web, pid, row).text
    if change == "review":
        save_sast(web, pid, "510002", "true_positive", "", OTHER_REASON + " Уточнено.", FIX)
    elif change == "members":
        with db._tx() as c:
            c.execute("UPDATE hub_defects SET targets_json = ? WHERE id = ?", (dumps(json.loads(row["targets_json"]) + [{"hub_id": "510003", "issue_id": 510003, "issue_type": "SAST"}]), row["id"]))
    elif change == "group_id":
        with db._tx() as c:
            c.execute("UPDATE hub_defects SET blank_json = ? WHERE id = ?", (dumps({**json.loads(row["blank_json"]), "groupId": 42}), row["id"]))
    else:
        value = {"summary": row["summary"] + " ", "number": int(row["number"]) + 50, "accepted": dumps({"id": 555, "linkedIssues": links(510001)}),
                 "draft_revision": int(row["draft_revision"]) + 1, "text_generation": int(row.get("text_generation") or 0) + 1}[change]
        field = {"accepted": "confirmed_object_json"}.get(change, change)
        with db._tx() as c:
            c.execute(f"UPDATE hub_defects SET {field} = ? WHERE id = ?", (value, row["id"]))
    r = add(web, pid, row, page)
    assert r.status_code == 409, r.text
    no_job(web)


@pytest.mark.parametrize("change", ["source", "code"])
def test_changed_source_or_code_refuses_a_stale_page(web, monkeypatch, change):
    pid, row, _ = created(web)
    page = choose(web, pid, row).text
    if change == "source":
        monkeypatch.setattr(defect_add, "source_version", lambda _: "другая версия")
    else:
        real = defect_add.defect_selected.target_snapshot

        def other_code(*args):
            snapshot = real(*args)
            return {**snapshot, "code": {**snapshot["code"], "hash": "другой код"}}

        monkeypatch.setattr(defect_add.defect_selected, "target_snapshot", other_code)
    r = add(web, pid, row, page)
    assert r.status_code == 409 and "изменились после показа" in r.text
    no_job(web)


def test_double_submit_sends_one_request(web):
    pid, row, _ = created(web)
    db = web.app.state.db
    page = choose(web, pid, row).text
    assert add(web, pid, row, page).status_code == 303
    assert add(web, pid, row, page).status_code == 409
    assert len([o for o in db.hub_ops_list(limit=1000) if o["purpose"] == "defect_link"]) == 1


def test_unsent_edit_stays_newer_than_the_link_confirmation(web):
    from test_hub_defect_guard import created as made, start_link
    from test_hub_defects import REASON, pair_project
    pid = pair_project(web)
    db = web.app.state.db
    url_one, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    parent = made(web, pid, url_one)
    saved = defect_drafts.save(db, parent, str(parent["draft_revision"]), summary=parent["summary"], command="Неотправленная правка")
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    start_link(web, pid, "510005")
    hub_job(web, body={})
    hub_job(web, body={"id": 555, "appId": parent["app_id"], "summary": parent["summary"], "description": json.loads(parent["confirmed_object_json"])["description"],
                       "linkedIssues": links(510001, 510005)})
    events = db._all("SELECT event, revision FROM hub_defect_history WHERE defect_id = ? ORDER BY id", (parent["id"],))
    confirm, edit = events[-2], events[-1]
    assert (confirm["event"], edit["event"]) == ("hub_confirm", "edit") and edit["revision"] > confirm["revision"], "синхронизация видит правку новее принятого"
    target = json.loads(link_row(db, pid, "510005")["targets_json"])[0]
    assert target["entered_defect_revision"] == confirm["revision"] == saved["draft_revision"], "отметка относится к подтверждённой редакции"


def test_change_between_check_and_transaction_refuses_and_queues_nothing(web, monkeypatch):
    pid, row, _ = created(web)
    db = web.app.state.db
    page = choose(web, pid, row).text

    def changes(*_):
        def check(c) -> None:
            c.execute("UPDATE hub_defects SET draft_revision = draft_revision + 5 WHERE id = ?", (row["id"],))
        return check

    monkeypatch.setattr(defect_add, "hub_target_check", changes)
    r = add(web, pid, row, page)
    assert r.status_code == 409 and "изменились после показа" in r.text
    assert db.hub_defect(row["id"])["draft_revision"] == row["draft_revision"], "транзакция отменена"
    assert db.hub_defect_for(pid, ["510002"]) is None
    no_job(web)


def test_old_form_after_hub_refusal_does_not_send_again(web):
    pid, row, _ = created(web)
    db = web.app.state.db
    page = choose(web, pid, row).text
    assert add(web, pid, row, page).status_code == 303
    hub_job(web, status=400, error="отказ Hub")
    r = add(web, pid, row, page)
    assert r.status_code == 409 and "изменились после показа" in r.text
    no_job(web)
    assert len([o for o in db.hub_ops_list(limit=1000) if o["purpose"] == "defect_link"]) == 1
    add_now(web, pid, row)  # новый предпросмотр – новая попытка
    assert hub_job(web, body={})["path"] == "/defects/555/link"


def test_old_form_after_cancelled_attempt_does_not_send_again(web):
    pid, row, _ = created(web)
    db = web.app.state.db
    page = choose(web, pid, row).text
    assert add(web, pid, row, page).status_code == 303
    bound = link_row(db, pid)
    with db._tx() as c:
        hub_defects.settle_restored_in(c, "2026-11-06T12:00:00Z")
    assert db.hub_defect(bound["id"])["state"] == "cancelled"
    assert add(web, pid, row, page).status_code == 409
    no_job(web)


# ============================================================================ весь путь


def test_add_to_app_defect_pull_apply_and_push(web):
    pid, row, description = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    job = hub_job(web, body={})
    assert job["method"] == "POST" and job["path"] == "/defects/555/link"
    assert job["body"]["issueIds"] == [510002] and job["body"]["issueType"] == "SAST" and job["body"]["defectId"] == 555
    read = hub_job(web, body=in_hub(row, description, 510001, 510002))
    assert read["method"] == "GET" and read["path"] == "/defects/555"
    owner = db.hub_defect(row["id"])
    assert owner["draft_command_text"] == row["draft_command_text"] and owner["command_text"] == row["command_text"], "текст дефекта не меняется"
    bound = link_row(db, pid)
    assert bound["state"] == "done" and int(bound["draft_owner_id"]) == row["id"] and bound["origin"] == "app"
    assert db.get_review(pid, "510002")["final_comment"] == OTHER_REASON, "решение находки остаётся её"
    assert db.get_review(pid, "510002")["entered_hub"] == 1
    assert db.defect_number(pid, defect.defect_key_sast("510002")) == row["number"]
    no_job(web)
    # до «Применить» правка и Push закрыты, карточка говорит, что делать
    card = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert 'id="defect-unmerged"' in card and "510002" in card
    assert db.on_connection(lambda c: defect_drafts.edit_problem(c, owner)) == hub_defects.UPDATE_FAMILY_UNMERGED
    r = act(web, pid, row["id"], "update")
    assert r.status_code == 409 and hub_defects.UPDATE_FAMILY_UNMERGED in r.json()["detail"]
    # Pull видит совпадение с принятым, но предлагает «Применить» несхлопнутой семье
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=in_hub(row, description, 510001, 510002))
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert f'id="hub-sync-unmerged-{row["id"]}"' in page and "внесёт их в состав" in page
    assert apply_sync(web, pid, row["id"]).status_code == 200, "«Применить» проходит"
    owner, bound = db.hub_defect(row["id"]), db.hub_defect(bound["id"])
    assert [t["hub_id"] for t in json.loads(owner["targets_json"])] == ["510001", "510002"]
    assert json.loads(bound["targets_json"]) == [] and json.loads(bound["number_keys_json"]) == []
    assert defect.defect_key_sast("510002") in json.loads(owner["number_keys_json"])
    assert owner["draft_command_text"] == row["draft_command_text"], "текст не меняется"
    assert db.get_review(pid, "510002")["entered_hub"] == 1, "отметка остаётся"
    assert db.on_connection(lambda c: defect_drafts.edit_problem(c, owner)) == ""
    assert db.on_connection(lambda c: hub_defects._update_idle_problem(c, owner)) == ""
    assert 'id="defect-unmerged"' not in web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    # Pull снова совпадает: предпросмотра нет
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=in_hub(owner, description, 510001, 510002))
    assert json.loads(db.hub_defect(row["id"])["sync_json"]).get("matches") is True


def test_add_to_imported_defect_keeps_owner_and_pushes_full_composition(web):
    pid, row = from_import(web)
    db = web.app.state.db
    page = web.client.get(url(pid), params={"hub_id": "510002"}).text
    assert f'value="{row["id"]}"' in page, "занесённый дефект можно выбрать"
    confirm_before = row["confirm_op_id"]
    add_now(web, pid, row)
    job = hub_job(web, body={})
    assert job["body"] == {"defectId": 777, "issueIds": [510002], "issueType": "SAST", "groupId": None}, "поле groupId отправляется явным null"
    both = hub_body(links=((510001, "SAST"), (510002, "SAST")))
    hub_job(web, body=both)
    owner, bound = db.hub_defect(row["id"]), link_row(db, pid)
    assert bound["state"] == "done" and bound["origin"] == "app", bound["error"]
    assert owner["origin"] == "import" and owner["confirm_op_id"] == confirm_before, "владелец не меняется"
    assert db.get_review(pid, "510002")["entered_hub"] == 1
    assert db.defect_number(pid, defect.defect_key_sast("510002")) == row["number"]
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=both)
    assert apply_sync(web, pid, row["id"]).status_code == 200
    owner = db.hub_defect(row["id"])
    assert {t["hub_id"] for t in json.loads(owner["targets_json"])} == {"510001", "510002"}
    # Push: состав владельца полон, номер своей семьи не занят «другим»
    owner = defect_drafts.save(db, owner, str(owner["draft_revision"]), summary=owner["draft_summary"], command="Правка после добавления находки")
    update_preview(web, pid, owner, both)
    assert phase(db, row["id"]) == "preview", hub_defects.update_state(db.hub_defect(row["id"]))
    preview = db.hub_defect(row["id"])
    assert {t["hub_id"] for t in hub_defects.update_state(preview)["new"]["targets"]} == {"510001", "510002"}
    assert put_click(web, pid, preview).status_code == 200
    read_job(web, both)
    put = take(web)
    assert put is not None and put["method"] == "PUT" and put["path"] == "/defects/777"
    assert {i["id"] for i in put["body"]["linkedIssues"]} == {510001, 510002}, "полный состав в теле"
    assert "Правка после добавления находки" in put["body"]["description"]
    assert hub_defects.split_description(put["body"]["description"])[1], "служебный блок сохранён"
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"], links=((510001, "SAST"), (510002, "SAST"))))
    final = db.hub_defect(row["id"])
    assert phase(db, row["id"]) == "done", hub_defects.update_state(final)
    assert {t["hub_id"] for t in json.loads(final["targets_json"])} == {"510001", "510002"}
    assert db.get_review(pid, "510002")["entered_hub"] == 1
    assert db.defect_number(pid, defect.defect_key_sast("510001")) == db.defect_number(pid, defect.defect_key_sast("510002")) == row["number"]


def test_add_after_push_is_allowed(web):
    pid, row = from_import(web, build=True)
    db = web.app.state.db
    done = to_done(web, pid, row)
    assert int(done["text_generation"]) >= 1
    assert f'value="{row["id"]}"' in web.client.get(url(pid), params={"hub_id": "510002"}).text
    add_now(web, pid, row)
    assert hub_job(web, body={})["path"] == "/defects/777/link"
    fresh = json.loads(db.hub_defect(row["id"])["confirmed_object_json"])
    hub_job(web, body=hub_body(links=((510001, "SAST"), (510002, "SAST")), summary=fresh["summary"], description=fresh["description"]))
    assert link_row(db, pid)["state"] == "done", link_row(db, pid)["error"]


def test_second_finding_can_be_added_before_apply(web):
    pid, row, description = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    hub_job(web, body={})
    hub_job(web, body=in_hub(row, description, 510001, 510002))
    save_sast(web, pid, "510003", "true_positive", "", OTHER_REASON, FIX)
    add_now(web, pid, row, "510003")
    job = hub_job(web, body={})
    assert job["body"]["issueIds"] == [510003]
    expected = json.loads(link_row(db, pid, "510003")["blank_json"])["expected_previous_links"]
    assert sorted(i for i, _ in expected) == [510001, 510002], "прежний состав – всё подтверждённое"
    hub_job(web, body=in_hub(row, description, 510001, 510002, 510003))
    assert link_row(db, pid, "510003")["state"] == "done"
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=in_hub(row, description, 510001, 510002, 510003))
    assert apply_sync(web, pid, row["id"]).status_code == 200
    assert [t["hub_id"] for t in json.loads(db.hub_defect(row["id"])["targets_json"])] == ["510001", "510002", "510003"]
    assert db.on_connection(lambda c: defect_drafts.family_single_in(c, db.hub_defect(row["id"])))


def test_unmerged_list_compares_number_and_type(web):
    pid, row, description = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    hub_job(web, body={})
    hub_job(web, body=in_hub(row, description, 510001, 510002))
    owner = db.hub_defect(row["id"])
    assert db.on_connection(lambda c: hub_defects.family_unmerged_in(c, owner)) == ["510002"]
    assert db.on_connection(lambda c: hub_defects.family_unmerged_in(c, owner, [(510002, "SAST")])) == ["510002"]
    assert db.on_connection(lambda c: hub_defects.family_unmerged_in(c, owner, [(510002, "SCA_S")])) == []


def test_link_removed_in_hub_before_apply_drops_the_finding(web):
    pid, row, description = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    hub_job(web, body={})
    hub_job(web, body=in_hub(row, description, 510001, 510002))
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=in_hub(row, description, 510001))
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert f'id="hub-sync-unobserved-{row["id"]}"' in page and "510002" in page
    assert f'id="hub-sync-unmerged-{row["id"]}"' not in page, "снятую в Hub находку не обещает внести"
    assert apply_sync(web, pid, row["id"]).status_code == 200
    assert [t["hub_id"] for t in json.loads(db.hub_defect(row["id"])["targets_json"])] == ["510001"]
    assert db.get_review(pid, "510002")["entered_hub"] == 0
    assert db.defect_number(pid, defect.defect_key_sast("510002")) is None


# ============================================================================ итоги привязки


def test_hub_refusal_frees_the_finding_and_shows_on_its_card(web):
    pid, row, _ = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    hub_job(web, status=400, error="отказ Hub")
    failed = db.hub_defect_for(pid, ["510002"])
    assert failed["state"] == "failed" and db.hub_defect_bound(pid, "510002") is None
    assert db.hub_defect(row["id"])["draft_revision"] == row["draft_revision"]
    card = web.client.get(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510002')['id']}").text
    assert "отказ Hub" in card and 'id="hub-defect-add-link"' in card
    assert db.on_connection(lambda c: hub_defects.family_running_problem(c, db.hub_defect(row["id"]))) == ""
    add_now(web, pid, row)  # новая попытка – новая строка со своим ключом
    assert hub_job(web, body={})["path"] == "/defects/555/link"


def test_unknown_link_without_finding_in_answer_warns_on_retry(web):
    pid, row, description = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    hub_job(web, status=504, error="нет ответа")
    assert link_row(db, pid)["state"] == "unknown"
    assert db.on_connection(lambda c: hub_defects.family_busy_in(c, db.hub_defect(row["id"])))
    assert web.client.post(f"/projects/{pid}/hub/defects/{link_row(db, pid)['id']}/verify", headers=AS_JSON, data={}).status_code == 200
    hub_job(web, body=in_hub(row, description, 510001))
    failed = db.hub_defect_for(pid, ["510002"])
    assert failed["state"] == "failed" and "привязка не состоялась" in failed["error"]
    page = web.client.get(url(pid), params={"hub_id": "510002"}).text
    assert 'id="add-retry-note"' in page and "проверьте дефект в Hub" in page


def test_incomplete_link_row_is_read_again_and_creation_row_is_not(web):
    pid, row, description = created(web)
    db = web.app.state.db
    assert not hub_defects.link_rereadable({**row, "state": "mismatch"}), "строка создания и владелец не читаются этим путём"
    add_now(web, pid, row)
    hub_job(web, body={})
    hub_job(web, body=in_hub(row, description, 510001))
    bound = link_row(db, pid)
    assert bound["state"] == "mismatch" and hub_defects.view(bound)["verify"] is True
    posts = len([o for o in db.hub_ops_list(limit=1000) if json.loads(o["request_json"])["method"] == "POST"])
    assert db.on_connection(lambda c: hub_defects.family_busy_in(c, db.hub_defect(row["id"])))
    card = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert f'id="defect-confirmation-diff-{bound["id"]}"' in card and "Привязка находки не подтверждена" in card
    assert web.client.post(f"/projects/{pid}/hub/defects/{bound['id']}/verify", headers=AS_JSON, data={}).status_code == 200
    assert db.hub_defect(bound["id"])["state"] == "created"
    hub_job(web, body=in_hub(row, description, 510001, 510002))
    assert db.hub_defect(bound["id"])["state"] == "done"
    assert db.get_review(pid, "510002")["entered_hub"] == 1
    assert len([o for o in db.hub_ops_list(limit=1000) if json.loads(o["request_json"])["method"] == "POST"]) == posts, "повторной записи нет"


def test_stale_verify_does_not_revive_a_collapsed_row(web):
    pid, row, description = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    hub_job(web, body={})
    hub_job(web, body=in_hub(row, description, 510001))
    stale = link_row(db, pid)
    assert stale["state"] == "mismatch"
    collapse_as(db, stale["id"], "mismatch")  # другая вкладка: общая синхронизация
    with pytest.raises(ValueError, match="изменилось"):
        hub_defects.restart_read(db, stale)
    fresh = db.hub_defect(stale["id"])
    assert fresh["state"] == "mismatch" and json.loads(fresh["targets_json"]) == []
    no_job(web)
    assert not db.on_connection(lambda c: hub_defects.family_busy_in(c, db.hub_defect(row["id"])))


def same(row: dict, other: dict) -> bool:
    """Строка та же; время записи не сравнивается: идемпотентный повтор последствий его обновляет."""
    return {**row, "updated_at": ""} == {**other, "updated_at": ""}


def test_redelivery_of_every_answer_changes_nothing(web):
    pid, row, description = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    bound = link_row(db, pid)
    link_op = bound["link_op_id"]
    hub_job(web, body={})
    hub_defects.after_op(db, db.hub_op(link_op))
    assert db.hub_defect(bound["id"])["state"] == "created"
    read_op = db.hub_defect(bound["id"])["read_op_id"]
    hub_defects.after_op(db, db.hub_op(link_op))
    hub_job(web, body=in_hub(row, description, 510001, 510002))
    done = db.hub_defect(bound["id"])
    assert done["state"] == "done"
    owner_before = db.hub_defect(row["id"])
    for op_id in (link_op, read_op):
        hub_defects.after_op(db, db.hub_op(op_id))
    assert same(db.hub_defect(bound["id"]), done) and same(db.hub_defect(row["id"]), owner_before)
    no_job(web)
    # после «Применить» старые ответы не возвращают цели и не трогают отметки
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=in_hub(row, description, 510001, 510002))
    assert apply_sync(web, pid, row["id"]).status_code == 200
    applied = db.hub_defect(bound["id"])
    for op_id in (link_op, read_op):
        hub_defects.after_op(db, db.hub_op(op_id))
    assert same(db.hub_defect(bound["id"]), applied) and json.loads(applied["targets_json"]) == []
    assert db.get_review(pid, "510002")["entered_hub"] == 1
    no_job(web)


def test_restored_mismatch_stays_and_is_read_again(web):
    pid, row, description = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    hub_job(web, body={})
    hub_job(web, body=in_hub(row, description, 510001))
    bound = link_row(db, pid)
    with db._tx() as c:
        hub_defects.settle_restored_in(c, "2026-11-06T12:00:00Z")
    assert db.hub_defect(bound["id"])["state"] == "mismatch"
    assert web.client.post(f"/projects/{pid}/hub/defects/{bound['id']}/verify", headers=AS_JSON, data={}).status_code == 200
    hub_job(web, body=in_hub(row, description, 510001, 510002))
    assert db.hub_defect(bound["id"])["state"] == "done"


def test_neighbour_link_of_the_old_path_collapses_and_opens_push(web):
    from test_hub_defect_guard import created as made, start_link
    from test_hub_defects import REASON, pair_project
    pid = pair_project(web)
    db = web.app.state.db
    url_one, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    parent = made(web, pid, url_one)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    linked = start_link(web, pid, "510005")
    hub_job(web, body={})
    answer = {"id": 555, "appId": parent["app_id"], "summary": parent["summary"], "description": json.loads(parent["confirmed_object_json"])["description"],
              "linkedIssues": links(510001, 510005)}
    hub_job(web, body=answer)
    assert db.hub_defect(linked)["state"] == "done"
    assert sync(web, pid, parent["id"]).status_code == 200
    hub_job(web, body=answer)
    assert apply_sync(web, pid, parent["id"]).status_code == 200
    owner = db.hub_defect(parent["id"])
    assert db.on_connection(lambda c: hub_defects._update_idle_problem(c, owner)) == ""
    assert act(web, pid, parent["id"], "update").status_code == 200


def test_owner_mismatch_verify_is_still_refused(web):
    pid, row, _ = created(web)
    web.app.state.db.hub_defect_update(row["id"], state="mismatch")
    assert web.client.post(f"/projects/{pid}/hub/defects/{row['id']}/verify", headers=AS_JSON, data={}).status_code == 400


# ============================================================================ схлопнутая строка и чужая строка


def collapse_as(db, row_id: int, state: str) -> None:
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET state = ?, targets_json = '[]', number_keys_json = '[]' WHERE id = ?", (state, row_id))


@pytest.mark.parametrize("state", ["done", "mismatch"])
def test_collapsed_row_is_history_for_edit_push_and_live_check(web, state):
    pid, row, description = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    hub_job(web, body={})
    hub_job(web, body=in_hub(row, description, 510001, 510002))
    bound = link_row(db, pid)
    collapse_as(db, bound["id"], state)
    owner = db.hub_defect(row["id"])
    assert db.on_connection(lambda c: defect_drafts.family_single_in(c, owner))
    assert not db.on_connection(lambda c: hub_defects.family_busy_in(c, owner))
    assert db.on_connection(lambda c: defect_drafts.edit_problem(c, owner)) == ""
    assert db.on_connection(lambda c: Database.hub_defect_live_in(c, owner["hub_url"], owner["app_id"], "555", exclude_id=owner["id"], owner_id=owner["id"])) is None
    assert db.on_connection(lambda c: Database.hub_defect_live_in(c, owner["hub_url"], owner["app_id"], "555", exclude_id=owner["id"]))["id"] == bound["id"]


def test_foreign_row_without_targets_still_holds_the_defect(web):
    pid, row, _ = created(web)
    db = web.app.state.db
    other = db.hub_defect_insert(pid, kind="SAST", number=70, summary="ID70 - x (SAST)", anchor_hub_id="", targets=[], number_keys=[], command_text="x",
                                 hub_url=row["hub_url"], app_id=row["app_id"])
    db.hub_defect_update(other["id"], state="done", hub_defect_id="555")
    owner = db.hub_defect(row["id"])
    assert db.on_connection(lambda c: hub_defects._update_idle_problem(c, owner)) == hub_defects.UPDATE_MANY_ROWS.format(other=other["id"])


def test_link_row_has_no_push_or_pull_and_old_forms_are_refused(web):
    pid, row, description = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    hub_job(web, body={})
    hub_job(web, body=in_hub(row, description, 510001, 510002))
    bound = link_row(db, pid)
    page = tab(web, pid)
    assert f'id="hub-update-form-{bound["id"]}"' not in page and f'id="hub-sync-form-{bound["id"]}"' not in page
    assert f'id="hub-defect-link-row-{bound["id"]}"' in page
    r = act(web, pid, bound["id"], "update")
    assert r.status_code == 409 and hub_defects.UPDATE_NOT_OWNER in r.json()["detail"]
    assert sync(web, pid, bound["id"]).status_code == 404


# ============================================================================ условия добавления


def set_row(db, row_id: int, **fields) -> None:
    with db._tx() as c:
        for field, value in fields.items():
            c.execute(f"UPDATE hub_defects SET {field} = ? WHERE id = ?", (value, row_id))


@pytest.mark.parametrize("name, fields, word", [
    ("конфликт", {"conflicts_json": dumps(["разные версии"])}, "конфликты"),
    ("заголовок", {"draft_summary": "ID1 - другой заголовок"}, "неотправленная"),
    ("текст", {"draft_command_text": "Новый текст"}, "неотправленная"),
    ("основа", {"draft_fields_basis_json": dumps({"version": 1, "known": False, "pending": [], "references": {}})}, "Pull из Hub"),
    ("без номера", {"number": None}, "нет номера"),
    ("другой номер", {"number": 88}, "изменился"),
])
def test_add_problem_reasons(web, name, fields, word):
    pid, row, _ = created(web)
    db = web.app.state.db
    set_row(db, row["id"], **fields)
    r = choose(web, pid, row)
    assert r.status_code == 400 and word in html.unescape(r.text), name
    assert 'id="add-closed"' in r.text
    no_job(web)


def test_form_of_text_alone_is_not_an_edit(web):
    pid, row, _ = created(web)
    db = web.app.state.db
    set_row(db, row["id"], draft_command_text=row["command_text"] + "\n\n", draft_revision=int(row["draft_revision"]) + 3)
    assert choose(web, pid, row).status_code == 200, "край строк и рост редакции – не правка у дефекта из приложения"
    set_row(db, row["id"], origin="import")
    assert choose(web, pid, row).status_code == 400, "у занесённого сравнение точное"


def test_field_change_is_an_edit_compared_by_value(web):
    pid, row, _ = created(web)
    db = web.app.state.db
    fields = json.loads(row["draft_fields_json"])
    set_row(db, row["id"], draft_fields_json=json.dumps(fields, ensure_ascii=False, indent=1))
    assert choose(web, pid, row).status_code == 200, "другая запись JSON – не правка"
    set_row(db, row["id"], draft_fields_json=dumps({**fields, "stage": "выдуманная стадия"}))
    r = choose(web, pid, row)
    assert r.status_code == 400 and "неотправленная" in r.text


def test_number_taken_outside_the_family_refuses(web):
    pid, row, _ = created(web)
    db = web.app.state.db
    db.set_defect_number(pid, defect.defect_key_sast("510009"), row["number"])
    r = choose(web, pid, row)
    assert r.status_code == 400 and "занят другим" in r.text


@pytest.mark.parametrize("name, fields", [
    ("Push идёт", {"update_op_id": 1}),
    ("Push не подтверждён", {"update_json": dumps({"phase": "unconfirmed"})}),
    ("предпросмотр Push", {"update_json": dumps({"phase": "preview"})}),
    ("Pull идёт", {"sync_op_id": 1}),
    ("проверка идёт", {"verify_op_id": 1}),
    ("предпросмотр Pull", {"sync_json": dumps({"read": {"summary": "x"}})}),
])
def test_running_operations_of_the_owner_close_the_defect(web, name, fields):
    pid, row, _ = created(web)
    db = web.app.state.db
    page = choose(web, pid, row).text
    set_row(db, row["id"], **fields)
    assert db.on_connection(lambda c: hub_defects.family_running_problem(c, db.hub_defect(row["id"]))), name
    assert choose(web, pid, row).status_code == 400, name
    assert add(web, pid, row, page).status_code == 409, name
    no_job(web)


def test_running_check_also_applies_to_the_neighbour_link(web):
    from test_hub_defect_guard import card_of, link_fields
    from test_hub_defects import REASON, pair_project
    pid = pair_project(web)
    db = web.app.state.db
    url_one, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    from test_hub_defect_guard import created as made
    parent = made(web, pid, url_one)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    fields = link_fields(web.client.get(card_of(web, pid, "510005")).text)
    set_row(db, parent["id"], update_json=dumps({"phase": "preview"}))
    r = web.client.post(f"{card_of(web, pid, '510005')}/hub-defect-link", headers=AS_JSON, data=fields)
    assert r.status_code == 409 and "предпросмотр" in r.json()["detail"]
    no_job(web)


def test_effects_pending_and_busy_rows_close_the_family(web):
    pid, row, description = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    bound = link_row(db, pid)
    owner = db.hub_defect(row["id"])
    assert db.on_connection(lambda c: hub_defects.family_running_problem(c, owner)) == hub_defects.FAMILY_BUSY, "linking"
    hub_job(web, body={})
    assert db.hub_defect(bound["id"])["state"] == "created"
    assert db.on_connection(lambda c: hub_defects.family_running_problem(c, owner)) == hub_defects.FAMILY_BUSY, "created"
    hub_job(web, body=in_hub(row, description, 510001, 510002))
    assert db.on_connection(lambda c: hub_defects.family_running_problem(c, owner)) == ""
    set_row(db, bound["id"], effects_done=0)
    assert db.on_connection(lambda c: hub_defects.family_running_problem(c, owner)) == hub_defects.EFFECTS_PENDING
    set_row(db, bound["id"], effects_done=1, verify_op_id=1)
    assert db.on_connection(lambda c: hub_defects.family_running_problem(c, owner)) == hub_defects.FAMILY_BUSY


# ============================================================================ группа


def test_neighbour_in_selected_family_is_fine_and_in_another_defect_refused(web):
    from test_hub_defect_guard import created as made
    from test_hub_defects import REASON, pair_project
    pid = pair_project(web)
    db = web.app.state.db
    url_one, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    parent = made(web, pid, url_one)
    hello(web)
    save_sast(web, pid, "510005", "true_positive", "", OTHER_REASON, FIX)  # сосед с другим текстом решения
    assert choose(web, pid, parent, "510005").status_code == 200, "сосед в выбранной семье не мешает, текст не сравнивается"
    other = db.hub_defect_insert(pid, kind="SAST", number=71, summary="ID71 - другой дефект (SAST)", anchor_hub_id="510002", targets=[], number_keys=[], command_text="x",
                                 hub_url=parent["hub_url"], app_id=parent["app_id"])
    db.hub_defect_update(other["id"], state="done", hub_defect_id="556")
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET confirmed_object_json = ?, draft_fields_json = '{}', draft_fields_basis_json = ? WHERE id = ?",
                  (dumps({"id": 556, "summary": "ID71 - другой дефект (SAST)", "description": "x", "linkedIssues": []}),
                   dumps({"version": 1, "known": True, "base": {}, "references": {}}), other["id"]))
    r = choose(web, pid, db.hub_defect(other["id"]), "510005")
    assert r.status_code == 400 and "510001" in r.text and "добавьте находку в него" in r.text
    no_job(web)


# ============================================================================ рядом


def test_redelivered_candidate_does_not_mark_targets_outside_the_answer(monkeypatch):
    calls = []
    monkeypatch.setattr(hub_defects, "_apply_effects", lambda db, row, closed_at: calls.append(row["id"]))

    class Db:
        def __init__(self, row):
            self.row = row

        def hub_defect(self, _):
            return self.row

    outside = {"id": 1, "state": "done", "confirm_op_id": 9, "effects_done": 1, "targets_json": dumps([{"hub_id": "510002", "issue_type": "SAST"}])}
    op = {"id": 9, "state": "done", "response_json": dumps({"body": {"id": 555, "linkedIssues": [{"id": 510001, "type": "SAST"}]}})}
    monkeypatch.setattr(hub_defects, "_body", lambda _: {"id": 555, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    hub_defects._on_candidate(Db(outside), op, {"verify_defect": 1, "candidate": "555"})
    assert calls == []
    hub_defects._on_candidate(Db({**outside, "effects_done": 0}), op, {"verify_defect": 1, "candidate": "555"})
    assert calls == [1], "недоведённые последствия доводятся"
    hub_defects._on_candidate(Db({**outside, "targets_json": dumps([{"hub_id": "510001", "issue_type": "SAST"}])}), op, {"verify_defect": 1, "candidate": "555"})
    assert calls == [1, 1], "цели в составе: повтор идемпотентен"


@pytest.mark.parametrize("description, block, expected", [
    ("<p>Текст</p><p>Блок</p>", "<p>Блок</p>", len("<p>Текст</p>")),
    ("<p>Текст <b>Блок</b></p>", "<b>Блок</b></p>", -1),
    ("<p>Текст</p>\n<p>Блок</p>", "\n<p>Блок</p>", len("<p>Текст</p>")),
    ("<p>Блок</p>", "<p>Блок</p>", 0),
])
def test_block_start_checks_the_boundary_on_exact_match(description, block, expected):
    assert hub_defects.block_start(description, block) == expected


@pytest.mark.parametrize("state", ["linking", "created", "unknown", "unconfirmed"])
def test_restored_copy_cancels_an_unfinished_link_and_frees_the_family(web, state):
    pid, row, _ = created(web)
    db = web.app.state.db
    add_now(web, pid, row)
    bound = link_row(db, pid)
    set_row(db, bound["id"], state=state)
    with db._tx() as c:
        assert hub_defects.settle_restored_in(c, "2026-11-06T12:00:00Z") >= 1
    fresh = db.hub_defect(bound["id"])
    assert fresh["state"] == "cancelled" and hub_defects.RESTORED_NOTE in fresh["error"]
    assert db.hub_ops_list(limit=1)[0]["state"] == "cancelled", "запись после восстановления не идёт"
    no_job(web)
    owner = db.hub_defect(row["id"])
    assert not db.on_connection(lambda c: hub_defects.family_busy_in(c, owner))
    assert db.on_connection(lambda c: defect_drafts.family_single_in(c, owner))

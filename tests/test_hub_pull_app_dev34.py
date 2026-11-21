"""«Pull из Hub» у дефекта, созданного приложением (0.9.26.dev34: у дефекта – Push и Pull).
Pull – у строки-владельца; состав считается по всему семейству строк (строка создания и строки привязки); «Применить»
собирает действующий состав у владельца, как принятие состояния Hub. Данные, адреса и номера выдуманы, сети нет."""

from __future__ import annotations

import json
import re

import pytest

from app import hub_defects
from test_defect import save_sast
from test_hub_defect_guard import created, link_fields
from test_hub_defect_import import apply_sync, sync, tab
from test_hub_defects import FIX, REASON, hub_job, no_job, pair_project, sast_ready
from test_hub_status_routes import AS_JSON
from test_web import web  # noqa: F401


def hub_object(row: dict, **changes) -> dict:
    """Объект дефекта, как его вернул Hub при подтверждении создания, с правками."""
    obj = json.loads(row["confirmed_object_json"])
    return {**obj, **changes}


def family(web) -> tuple[int, dict, dict]:
    """Дефект №555 (ID1) из 510001 и строка привязки 510005 к нему – семейство из двух строк."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    owner = created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    sibling = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510005')['id']}"
    r = web.client.post(f"{sibling}/hub-defect-link", headers=AS_JSON, data=link_fields(web.client.get(sibling).text))
    assert r.status_code == 200, r.text
    link_id = r.json()["defect_id"]
    hub_job(web, body={})  # привязка
    hub_job(web, body={**hub_object(db.hub_defect(owner["id"])),
                       "linkedIssues": [{"id": 510001, "type": "SAST"}, {"id": 510005, "type": "SAST"}]})
    assert db.hub_defect(link_id)["state"] == "done"
    return pid, db.hub_defect(owner["id"]), db.hub_defect(link_id)


def targets_of(row: dict) -> list[str]:
    return [str(t["hub_id"]) for t in json.loads(row["targets_json"] or "[]")]


def test_single_app_defect_pull_matches(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = created(web, pid, url)
    assert row["origin"] == "app" and hub_defects.pull_allowed(row)
    page = tab(web, pid)
    assert f'id="hub-sync-{row["id"]}"' in page and f'id="hub-import-origin-{row["id"]}"' not in page
    card = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert f'/hub/defects/{row["id"]}/sync"' in card
    assert sync(web, pid, row["id"]).status_code == 200
    job = hub_job(web, body=hub_object(row))
    assert job["method"] == "GET" and job["path"] == "/defects/555"
    tab(web, pid)
    fresh = db.hub_defect(row["id"])
    state = json.loads(fresh["sync_json"])
    assert state.get("matches") is True, state
    assert fresh["error"] == "", "пояснение цепочки создания снимается совпадением"
    assert f'id="hub-sync-matches-{row["id"]}"' in tab(web, pid)
    no_job(web)


def test_text_compared_by_lines_for_app_defect():
    row = {"origin": "app", "command_text": "Обоснование:\nтекст\n"}
    assert not hub_defects._text_changed(row, {"command_text": "Обоснование:\nтекст"})
    assert hub_defects._text_changed(row, {"command_text": "Обоснование:\nдругой текст"})
    assert hub_defects._text_changed({**row, "origin": "import"}, {"command_text": "Обоснование:\nтекст"})


def test_link_row_has_no_pull_and_family_matches(web):
    pid, owner, link = family(web)
    db = web.app.state.db
    assert not hub_defects.pull_allowed(link) and hub_defects.pull_allowed(owner)
    page = tab(web, pid)
    assert f'id="hub-sync-{owner["id"]}"' in page and f'id="hub-sync-{link["id"]}"' not in page
    r = sync(web, pid, link["id"])
    assert r.status_code >= 400, r.text
    assert sync(web, pid, owner["id"]).status_code == 200
    hub_job(web, body=hub_object(owner))
    tab(web, pid)
    state = json.loads(db.hub_defect(owner["id"])["sync_json"])
    # состав – по семейству: 510005 своя, не «занята другой строкой»; ADR-0136: несхлопнутой семье Pull предлагает «Применить»
    assert state["family_unmerged"] == ["510005"] and state["added"] == [] and state["not_added"] == [], state


def test_family_apply_removes_a_linked_member_and_collapses(web):
    pid, owner, link = family(web)
    db = web.app.state.db
    assert db.get_review(pid, "510005")["entered_hub"] == 1
    assert db.defect_number(pid, "sast:510005") == 1
    assert sync(web, pid, owner["id"]).status_code == 200
    hub_job(web, body=hub_object(owner, linkedIssues=[{"id": 510001, "type": "SAST"}]))
    tab(web, pid)
    state = json.loads(db.hub_defect(owner["id"])["sync_json"])
    assert state.get("composition_changed") and not state.get("matches"), state
    r = apply_sync(web, pid, owner["id"])
    assert r.status_code == 200, r.text
    owner_now, link_now = db.hub_defect(owner["id"]), db.hub_defect(link["id"])
    assert targets_of(owner_now) == ["510001"] and targets_of(link_now) == []
    assert json.loads(link_now["number_keys_json"]) == []
    assert db.get_review(pid, "510005")["entered_hub"] == 0
    assert db.get_review(pid, "510005")["defect_dropped"]
    assert db.defect_number(pid, "sast:510005") is None and db.defect_number(pid, "sast:510001") == 1
    assert db.hub_defect_bound(pid, "510005") is None, "находка свободна"
    # повторный Pull – совпадает
    assert sync(web, pid, owner["id"]).status_code == 200
    hub_job(web, body=hub_object(owner, linkedIssues=[{"id": 510001, "type": "SAST"}]))
    tab(web, pid)
    assert json.loads(db.hub_defect(owner["id"])["sync_json"]).get("matches") is True


def test_family_apply_keeps_both_members_at_the_owner(web):
    pid, owner, link = family(web)
    db = web.app.state.db
    new_summary = owner["summary"] + " (уточнено)"
    assert sync(web, pid, owner["id"]).status_code == 200
    hub_job(web, body=hub_object(owner, summary=new_summary))
    tab(web, pid)
    assert json.loads(db.hub_defect(owner["id"])["sync_json"]).get("summary_changed")
    r = apply_sync(web, pid, owner["id"])
    assert r.status_code == 200, r.text
    owner_now, link_now = db.hub_defect(owner["id"]), db.hub_defect(link["id"])
    assert sorted(targets_of(owner_now)) == ["510001", "510005"] and targets_of(link_now) == []
    assert owner_now["summary"] == new_summary
    # текст тот же по смыслу – текст строк остаётся текстом приложения: соседи группы находят дефект (ревью dev34, круг 2)
    assert owner_now["command_text"] == owner["command_text"] == link_now["command_text"]
    assert sorted(json.loads(owner_now["number_keys_json"])) == ["sast:510001", "sast:510005"]
    assert db.get_review(pid, "510005")["entered_hub"] == 1 and db.hub_defect_bound(pid, "510005") is not None
    assert db.defect_number(pid, "sast:510005") == 1


def test_family_change_between_preview_and_apply_is_refused(web):
    pid, owner, link = family(web)
    db = web.app.state.db
    assert sync(web, pid, owner["id"]).status_code == 200
    hub_job(web, body=hub_object(owner, linkedIssues=[{"id": 510001, "type": "SAST"}]))
    tab(web, pid)
    form = re.search(rf'<form [^>]*id="hub-sync-apply-form-{owner["id"]}".*?</form>', tab(web, pid), re.S).group(0)
    shown_value = re.search(r'name="shown" value="([^"]*)"', form).group(1)
    with db._tx() as c:  # строка привязки изменилась после предпросмотра
        c.execute("UPDATE hub_defects SET targets_json = '[]' WHERE id = ?", (link["id"],))
    r = apply_sync(web, pid, owner["id"], shown_value)
    assert r.status_code >= 400 and "обновите" in r.text.lower(), r.text
    assert targets_of(db.hub_defect(owner["id"])) == ["510001"]
    assert db.get_review(pid, "510005")["entered_hub"] == 1


def test_pending_link_blocks_pull_and_apply(web):
    """Ревью dev34, круг 1: строка привязки ещё не «создан» – Pull и «Применить» ждут её итога, цели не стираются."""
    pid, owner, link = family(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET state = 'linking' WHERE id = ?", (link["id"],))
    r = sync(web, pid, owner["id"])
    assert r.status_code >= 400 and "привязка находок" in r.text, r.text
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET state = 'done' WHERE id = ?", (link["id"],))
    assert sync(web, pid, owner["id"]).status_code == 200
    hub_job(web, body=hub_object(owner, linkedIssues=[{"id": 510001, "type": "SAST"}]))
    tab(web, pid)
    form = re.search(rf'<form [^>]*id="hub-sync-apply-form-{owner["id"]}".*?</form>', tab(web, pid), re.S).group(0)
    shown_value = re.search(r'name="shown" value="([^"]*)"', form).group(1)
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET state = 'linking' WHERE id = ?", (link["id"],))
    r = apply_sync(web, pid, owner["id"], shown_value)
    assert r.status_code >= 400 and "привязка находок" in r.text, r.text
    assert targets_of(db.hub_defect(link["id"])) == ["510005"]


def test_renumbered_family_follows_the_owner_and_matches_without_number_conflict(web):
    """Ревью dev34, круг 1: Hub перенумеровал дефект – строка привязки берёт новый номер; совпадение не называет свою
    строку привязки «занятым» номером."""
    pid, owner, link = family(web)
    db = web.app.state.db
    assert sync(web, pid, owner["id"]).status_code == 200
    hub_job(web, body=hub_object(owner))
    tab(web, pid)
    fresh = db.hub_defect(owner["id"])
    state = json.loads(fresh["sync_json"])
    assert state["family_unmerged"] == ["510005"] and state["not_added"] == [] and "уже занят" not in (fresh["error"] or "")
    renamed = owner["summary"].replace("ID1", "ID7")
    assert renamed != owner["summary"]
    assert sync(web, pid, owner["id"]).status_code == 200
    hub_job(web, body=hub_object(owner, summary=renamed))
    tab(web, pid)
    assert apply_sync(web, pid, owner["id"]).status_code == 200
    assert db.hub_defect(owner["id"])["number"] == 7 and db.hub_defect(link["id"])["number"] == 7
    assert db.defect_number(pid, "sast:510001") == db.defect_number(pid, "sast:510005") == 7



def test_number_disappearing_and_returning_keeps_the_number(web):
    """ID пропал из заголовка Hub или появился снова – номера находок приложение
    само не меняет, в предпросмотре Pull только предупреждение."""
    pid, owner, link = family(web)
    db = web.app.state.db
    no_number = owner["summary"].replace("ID1 - ", "")
    assert no_number != owner["summary"]
    assert sync(web, pid, owner["id"]).status_code == 200
    hub_job(web, body=hub_object(owner, summary=no_number))
    tab(web, pid)
    warnings = json.loads(db.hub_defect(owner["id"])["sync_json"])["warnings"]
    assert any("ID1 пропал из заголовка в Hub" in w for w in warnings), warnings
    assert apply_sync(web, pid, owner["id"]).status_code == 200
    # ADR-0138: номер остаётся за дефектом и находками, Push вернёт его в заголовок
    assert db.hub_defect(owner["id"])["number"] == 1 and db.hub_defect(link["id"])["number"] == 1
    assert db.defect_number(pid, "sast:510001") == db.defect_number(pid, "sast:510005") == 1
    assert sorted(json.loads(db.hub_defect(owner["id"])["number_keys_json"])) == ["sast:510001", "sast:510005"]
    back = owner["summary"].replace("ID1", "ID3")
    fresh = db.hub_defect(owner["id"])
    assert sync(web, pid, owner["id"]).status_code == 200
    hub_job(web, body=hub_object(fresh, summary=back))
    tab(web, pid)
    assert apply_sync(web, pid, owner["id"]).status_code == 200
    assert db.hub_defect(owner["id"])["number"] == 3 and db.hub_defect(link["id"])["number"] == 3
    assert db.defect_number(pid, "sast:510001") == db.defect_number(pid, "sast:510005") == 3, "номер в Hub другой: находки следуют за ним"


def test_local_text_edit_kept_by_pull_stays_unsent(web):
    """Ревью dev34, круг 2: правка текста в черновике, в Hub изменён заголовок – после «Применить» правка остаётся и
    последнее событие истории – правка (синхронизация видит её неотправленной)."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = created(web, pid, url)
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_command_text = ?, draft_revision = draft_revision + 1 WHERE id = ?",
                  (row["draft_command_text"] + "\nДобавлено оператором.", row["id"]))
        c.execute("INSERT INTO hub_defect_history(defect_id, row_id, revision, event, summary, command_text, details_json,"
                  " created_at) SELECT id, id, draft_revision, 'edit', draft_summary, draft_command_text, '{}', '2026-11-03'"
                  " FROM hub_defects WHERE id = ?", (row["id"],))
    row = db.hub_defect(row["id"])
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=hub_object(row, summary=row["summary"] + " (уточнено)"))
    tab(web, pid)
    assert apply_sync(web, pid, row["id"]).status_code == 200
    fresh = db.hub_defect(row["id"])
    assert fresh["draft_command_text"].endswith("Добавлено оператором.")
    last = db._one("SELECT event, revision FROM hub_defect_history WHERE defect_id = ? ORDER BY id DESC LIMIT 1",
                   (row["id"],))
    assert last["event"] == "edit" and last["revision"] == fresh["draft_revision"]


def test_local_edit_kept_when_hub_removes_a_member(web):
    """Ревью dev34, круг 3: правка текста и выбытие находки одним «Применить» – последнее событие истории всё равно
    правка с редакцией выше всех событий принятия."""
    pid, owner, link = family(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_command_text = ?, draft_revision = draft_revision + 1 WHERE id = ?",
                  (owner["draft_command_text"] + "\nДобавлено оператором.", owner["id"]))
        c.execute("INSERT INTO hub_defect_history(defect_id, row_id, revision, event, summary, command_text, details_json,"
                  " created_at) SELECT id, id, draft_revision, 'edit', draft_summary, draft_command_text, '{}', '2026-11-03'"
                  " FROM hub_defects WHERE id = ?", (owner["id"],))
    owner = db.hub_defect(owner["id"])
    assert sync(web, pid, owner["id"]).status_code == 200
    hub_job(web, body=hub_object(owner, linkedIssues=[{"id": 510001, "type": "SAST"}]))
    tab(web, pid)
    assert apply_sync(web, pid, owner["id"]).status_code == 200
    fresh = db.hub_defect(owner["id"])
    events = db._all("SELECT event, revision FROM hub_defect_history WHERE defect_id = ? ORDER BY id", (owner["id"],))
    accepted = max(e["revision"] for e in events if e["event"] in ("hub_sync", "hub_confirm", "migration", "create"))
    edited = max(e["revision"] for e in events if e["event"] == "edit")
    assert edited > accepted and edited == fresh["draft_revision"], events[-4:]


def test_hub_text_form_is_neither_an_edit_nor_a_conflict(web):
    """Ревью dev34, круги 1 и 3: текст приложения с переводом строки в конце, разбор Hub – без него. Pull с новым
    заголовком не создаёт фиктивной правки; следующий Pull с настоящей правкой текста в Hub применяется без конфликта."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = created(web, pid, url)
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET command_text = command_text || chr(10),"
                  " draft_command_text = command_text || chr(10) WHERE id = ?", (row["id"],))
    row = db.hub_defect(row["id"])
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=hub_object(row, summary=row["summary"] + " (уточнено)"))
    tab(web, pid)
    assert apply_sync(web, pid, row["id"]).status_code == 200
    fresh = db.hub_defect(row["id"])
    assert fresh["draft_command_text"] == fresh["command_text"], "без правки оператора черновик равен принятому"
    changed = "Обоснование:\nтекст изменён в Hub.\n\nРекомендация:\n1) Мера."
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=hub_object(fresh, summary=fresh["summary"], description=hub_defects.command_html(changed)))
    tab(web, pid)
    r = apply_sync(web, pid, row["id"])
    assert r.status_code == 200, r.text
    fresh = db.hub_defect(row["id"])
    assert "текст изменён в Hub" in fresh["draft_command_text"] and fresh["draft_command_text"] == fresh["command_text"]


def test_number_shift_note_only_for_appearing_or_disappearing_id():
    """Предупреждение – только когда ID пропал или появился; перенумерация и
    неизменный номер его не дают."""
    assert "ID4 пропал" in hub_defects.number_shift_note(4, None)
    assert "появился ID7" in hub_defects.number_shift_note(None, 7)
    assert hub_defects.number_shift_note(4, 7) == hub_defects.number_shift_note(4, 4) == ""
    assert hub_defects.number_shift_note(None, None) == hub_defects.number_shift_note(True, None) == ""


def test_replayed_creation_confirmation_does_not_mark_a_member_added_by_pull(web):
    """Ревью dev34, круг 6: Pull добавил находку 510005, затем исполнитель повторно доставил старое подтверждающее
    чтение создания – последствия уже доведены, новой находке отметка от операции, где её не было, не ставится."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row = created(web, pid, url)
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=hub_object(row, linkedIssues=[{"id": 510001, "type": "SAST"}, {"id": 510005, "type": "SAST"}]))
    tab(web, pid)
    assert apply_sync(web, pid, row["id"]).status_code == 200
    fresh = db.hub_defect(row["id"])
    assert sorted(targets_of(fresh)) == ["510001", "510005"]
    before = db.get_review(pid, "510005")
    before = dict(before) if before is not None else None
    op = db.hub_op(int(fresh["confirm_op_id"]))
    hub_defects._on_read(db, fresh, op)
    after = db.get_review(pid, "510005")
    assert (dict(after) if after is not None else None) == before
    assert db.hub_defect(row["id"])["targets_json"] == fresh["targets_json"]


def test_apply_waits_for_pending_confirmation_effects(web):
    """Ревью dev34, круг 6: последствия подтверждения не доведены – «Применить» отказывает, состав не меняется."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row = created(web, pid, url)
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=hub_object(row, linkedIssues=[{"id": 510001, "type": "SAST"}, {"id": 510005, "type": "SAST"}]))
    form = re.search(rf'<form [^>]*id="hub-sync-apply-form-{row["id"]}".*?</form>', tab(web, pid), re.S).group(0)
    value = re.search(r'name="shown" value="([^"]*)"', form).group(1)
    with db._tx() as c:  # маршрут сначала доводит последствия (показ строки) – здесь гонка после этого показа
        c.execute("UPDATE hub_defects SET effects_done = 0 WHERE id = ?", (row["id"],))
    shown = db.hub_defect(row["id"])
    with pytest.raises(ValueError, match="ещё не доведены"):
        hub_defects.apply_import_sync(db, shown, shown=value)
    assert db.hub_defect(row["id"])["targets_json"] == shown["targets_json"]


def test_apply_waits_for_pending_effects_of_a_link_row(web):
    """Ревью dev34, круг 7: у строки привязки подтверждение записано, отметки не доведены – «Применить» отказывает;
    показ вкладки доводит их, затем «Применить» проходит и отметка находки строки привязки сохраняется."""
    pid, owner, link = family(web)
    db = web.app.state.db
    assert sync(web, pid, owner["id"]).status_code == 200
    hub_job(web, body=hub_object(owner, summary=owner["summary"] + " (уточнено)"))
    form = re.search(rf'<form [^>]*id="hub-sync-apply-form-{owner["id"]}".*?</form>', tab(web, pid), re.S).group(0)
    value = re.search(r'name="shown" value="([^"]*)"', form).group(1)
    with db._tx() as c:  # сбой после записи итога привязки: отметки находки строки привязки не поставлены
        c.execute("UPDATE hub_defects SET effects_done = 0 WHERE id = ?", (link["id"],))
        c.execute("UPDATE reviews SET entered_hub = 0 WHERE project_id = ? AND hub_id = '510005'", (pid,))
    with pytest.raises(ValueError, match="ещё не доведены"):
        hub_defects.apply_import_sync(db, db.hub_defect(owner["id"]), shown=value)
    assert targets_of(db.hub_defect(link["id"])) == ["510005"]
    tab(web, pid)  # показ вкладки доводит последствия строки привязки
    assert db.hub_defect(link["id"])["effects_done"] == 1 and db.get_review(pid, "510005")["entered_hub"] == 1
    assert apply_sync(web, pid, owner["id"]).status_code == 200
    assert sorted(targets_of(db.hub_defect(owner["id"]))) == ["510001", "510005"]
    assert db.get_review(pid, "510005")["entered_hub"] == 1

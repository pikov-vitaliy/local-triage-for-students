"""HUB-AUD-09 (аудит 01.11.2026): «статус уже стоит в Hub» решает последняя принятая версия находки в назначении
(Hub, приложение, тип, номер) – принятие Pull и подтверждённые записи приложения по порядку версий, а не любая
прежняя выполненная операция. Данные и адреса выдуманы."""

from __future__ import annotations

import pytest

from app.db import loads
from test_hub_bulk import preview, targets_of
from test_hub_bulk import send as bulk_send
from test_hub_pull import PullHub, accept, read
from test_hub_status_routes import HUB, decide, fid, project, run_worker, sast, send, verify
from test_web import web  # noqa: F401

REASON = "Значение задано константой."


def open_hub(count: int = 2) -> PullHub:
    hub = PullHub(count, defects=False)
    for item in hub.issues.values():
        item["status"] = "To verify"
        item["issueBranchBriefData"][0]["status"] = "To verify"
    return hub


def sent_ids(web, response) -> list[int]:
    body = loads(web.app.state.db.hub_op(response.json()["op_id"])["request_json"], {})["body"]
    return [body["issueId"]] if "issueId" in body else [x["issueId"] for x in body["issues"]]


def bulk_ids(web, pid: int, *hub_ids: str) -> list[int]:
    return [int(t.split("|", 1)[0]) for t in targets_of(preview(web, pid, *hub_ids))]


@pytest.mark.parametrize("already", [True, False])
def test_fresh_pull_controls_group_members(web, already):
    """Воспроизведение из аудита: FP у №2 поставлен в Hub извне и принят Pull – №2 в группу не входит; №2 отправлена
    приложением, затем в Hub возвращена в «To verify» и это принято – №2 снова уходит."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    decide(web, pid, "2", comment=REASON)
    if already:
        hub.decision(2, reason=REASON)
    else:
        assert send(web, pid, "2").status_code == 200
        run_worker(web, status=200)
    decide(web, pid, "1", comment=REASON)
    accept(db, read((db, pid), hub))
    assert bulk_ids(web, pid, "1", "2") == ([1] if already else [1, 2])
    html = preview(web, pid, "1", "2")
    assert ("статус уже внесён в Hub" in html) == already
    response = send(web, pid, "1")
    assert response.status_code == 200, response.text
    assert sent_ids(web, response) == ([1] if already else [1, 2])


def test_post_after_pull_counts(web):
    """Обратный порядок: Pull принял «To verify» у обеих, затем №2 внесена приложением – новая запись новее Pull,
    №2 исключается из группы и списка."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    decide(web, pid, "2", comment=REASON)
    accept(db, read((db, pid), hub))
    assert bulk_ids(web, pid, "2") == [2]
    assert send(web, pid, "2").status_code == 200
    run_worker(web, status=200)
    assert db.get_review(pid, "2")["entered_hub"]
    decide(web, pid, "1", comment=REASON)
    assert bulk_ids(web, pid, "1", "2") == [1]
    response = send(web, pid, "1")
    assert response.status_code == 200, response.text
    assert sent_ids(web, response) == [1]


def test_pull_of_other_app_does_not_prove_status(web):
    """Принятие Pull другого назначения (другой номер приложения) статус в текущем назначении не доказывает
    (HUB-AUD-02 остаётся в силе)."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    hub.decision(2, reason=REASON)
    decide(web, pid, "1", comment=REASON)
    decide(web, pid, "2", comment=REASON)
    accept(db, read((db, pid), hub))
    assert bulk_ids(web, pid, "1", "2") == [1]
    db.update_project(pid, hub_app_id=8)
    assert bulk_ids(web, pid, "1", "2") == [1, 2]


def test_group_message_names_excluded_and_bulk_post_after_pull(web):
    """Ответ постановки из карточки называет пропущенную соседку; массовая отправка после Pull ставит в операцию
    только готовую находку (ревью dev16, A и B)."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    decide(web, pid, "2", comment=REASON)
    hub.decision(2, reason=REASON)
    decide(web, pid, "1", comment=REASON)
    accept(db, read((db, pid), hub))
    shown = targets_of(preview(web, pid, "1", "2"))
    assert [t.split("|", 1)[0] for t in shown] == ["1"]
    r = bulk_send(web, pid, shown)
    assert r.status_code == 303, r.text[:300]
    job = run_worker(web, status=200)
    assert job["path"] == "/issue/status/update" and job["body"]["issueId"] == 1
    assert db.get_review(pid, "1")["entered_hub"]
    # из карточки: группа уже ушла – новая постановка той же находки отказывает (статус в Hub), сообщение называет
    # соседку только в ответе постановки другой пары
    pid2 = project(web, [sast("1"), sast("2")])
    hub2 = open_hub()
    decide(web, pid2, "2", comment=REASON)
    hub2.decision(2, reason=REASON)
    decide(web, pid2, "1", comment=REASON)
    accept(db, read((db, pid2), hub2))
    response = send(web, pid2, "1")
    assert response.status_code == 200, response.text
    assert "Уже внесена в Hub и не отправляется: 2" in response.json()["message"]


def test_pull_between_bulk_preview_and_post_is_refused(web):
    """Принятие Pull между предпросмотром списка и его отправкой меняет состав – транзакция постановки отказывает."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    decide(web, pid, "1", comment=REASON)
    decide(web, pid, "2", comment=REASON)
    accept(db, read((db, pid), hub))
    shown = targets_of(preview(web, pid, "1", "2"))
    assert len(shown) == 2
    hub.decision(2, reason=REASON)
    accept(db, read((db, pid), hub))
    r = bulk_send(web, pid, shown)
    assert r.status_code == 400 and "Состав изменился" in r.text and "2 (статус уже внесён в Hub)" in r.text
    assert [o for o in db.hub_ops_list() if o["purpose"] == "status"] == []  # операции Pull – чтение


def test_done_before_effects_already_counts(web):
    """Результат записан (операция done), последствия ещё не доставлены (сбой до отметок): версия цели записана вместе
    с переходом в done – следующая группа и список уже не берут находку (ревью dev16, A1); повторная доставка ставит
    отметку и состава не меняет."""
    from app import hub_effects
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    decide(web, pid, "2", comment=REASON)
    accept(db, read((db, pid), hub))
    assert send(web, pid, "2").status_code == 200
    got = db.hub_claim("w1", HUB, 120)
    assert got
    out = db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], {"status": 200, "body_text": "{}", "error": ""})
    assert out["outcome"] == "accepted" and out["op"]["state"] == "done"
    assert not db.get_review(pid, "2")["entered_hub"]  # отметки ещё нет
    decide(web, pid, "1", comment=REASON)
    assert bulk_ids(web, pid, "1", "2") == [1]
    response = send(web, pid, "1")
    assert response.status_code == 200, response.text
    assert sent_ids(web, response) == [1]
    hub_effects.after_result(db, db.hub_op(out["op"]["id"]))  # повторная доставка
    assert db.get_review(pid, "2")["entered_hub"]
    assert bulk_ids(web, pid, "1", "2") == []  # 1 – в открытой операции, 2 – в Hub


def test_snapshot_read_before_write_is_not_accepted_over_it(web):
    """Снимок Pull прочитан до записи приложения, запись выполнена, затем снимок принимают: принятая база изменилась –
    отказ; новое чтение видит статус и принимается (ревью dev16, A1)."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    decide(web, pid, "2", comment=REASON)
    accept(db, read((db, pid), hub))  # первая принятая база: To verify
    stale = read((db, pid), hub)  # снимок до записи
    assert send(web, pid, "2").status_code == 200
    run_worker(web, status=200)
    hub.decision(2, reason=REASON)  # в Hub статус поставлен записью приложения
    from app import hub_sync, hub_sync_compare
    with db._tx() as c:  # пересчёт расхождений старого снимка его не спасает: база цели изменилась записью
        hub_sync_compare.compare_in(c, hub_sync.run_in(c, stale))
    with pytest.raises(ValueError, match="Принятая база изменилась"):
        accept(db, stale)
    decide(web, pid, "1", comment=REASON)
    assert bulk_ids(web, pid, "1", "2") == [1]
    accept(db, read((db, pid), hub))
    assert bulk_ids(web, pid, "1", "2") == [1]
    assert db.get_review(pid, "2")["entered_hub"]


def test_leading_zeros_in_local_id_use_the_hub_number(web):
    """Локальный номер «002» – в версиях и состояниях Hub это SAST:2: предикат ищет по номеру Hub (ревью dev16, A2)."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("002")])
    hub = open_hub()
    decide(web, pid, "002", comment=REASON)
    assert send(web, pid, "002").status_code == 200
    run_worker(web, status=200)
    assert db.get_review(pid, "002")["entered_hub"]
    decide(web, pid, "1", comment=REASON)
    assert bulk_ids(web, pid, "1", "002") == [1]  # запись приложения – версия SAST:2
    accept(db, read((db, pid), hub))  # в Hub вернули на проверку
    assert [h for h in targets_of(preview(web, pid, "1", "002"))] and bulk_ids(web, pid, "1", "002") == [1, 2]


def test_hub_return_to_verify_clears_automatic_mark(web):
    """Статус записало приложение, в Hub его потом сняли и это принято Pull: отметка «Внесено в Hub» снята, решение
    оператора, его редакция и «Проверено» остались; карточка и список согласны с предикатом (ревью dev16, B1)."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    decide(web, pid, "2", comment=REASON)
    assert send(web, pid, "2").status_code == 200
    run_worker(web, status=200)
    before = db.get_review(pid, "2")
    assert before["entered_hub"] and before["entered_origin"] == "status"
    card = web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '2')}").text
    assert 'id="entered-badge" hidden' not in card and "Позже статус в Hub изменили" not in card
    accept(db, read((db, pid), hub))  # To verify
    after = db.get_review(pid, "2")
    assert not after["entered_hub"] and after["entered_origin"] == "" and after["entered_op_id"] is None
    assert (after["decision"], after["final_verdict"], after["final_comment"], after["reviewed"], after["revision"]) == (
        before["decision"], before["final_verdict"], before["final_comment"], before["reviewed"], before["revision"])
    card = web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '2')}").text
    assert 'id="entered-badge" hidden' in card and "Позже статус в Hub изменили" in card
    listing = web.client.get(f"/projects/{pid}/findings?kind=SAST&entered=no").text
    assert f"/findings/{fid(web, pid, '2')}" in listing
    # отправить можно снова – группа из обеих
    decide(web, pid, "1", comment=REASON)
    assert bulk_ids(web, pid, "1", "2") == [1, 2]


def test_mark_of_other_scope_survives_pull(web):
    """Отметка операции другого назначения (другой номер приложения) – история того назначения: Pull её не снимает
    (HUB-AUD-02)."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    decide(web, pid, "2", comment=REASON)
    assert send(web, pid, "2").status_code == 200
    run_worker(web, status=200)
    op_id = db.get_review(pid, "2")["entered_op_id"]
    with db._tx() as c:
        c.execute("UPDATE hub_ops SET app_id = 8 WHERE id = ?", (op_id,))
    accept(db, read((db, pid), hub))
    after = db.get_review(pid, "2")  # entered_hub здесь – в текущем назначении (0), физическая отметка – entered_recorded
    assert after["entered_recorded"] == 1 and after["entered_op_id"] == op_id


def test_bulk_post_after_return_to_verify_sends_both(web):
    """Возврат в Hub на проверку после записи приложения: «Отправить выбранные» ставит обе находки (ревью dev16, A)."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    decide(web, pid, "2", comment=REASON)
    assert send(web, pid, "2").status_code == 200
    run_worker(web, status=200)
    decide(web, pid, "1", comment=REASON)
    accept(db, read((db, pid), hub))  # To verify у обеих
    r = bulk_send(web, pid, targets_of(preview(web, pid, "1", "2")))
    assert r.status_code == 303, r.text[:300]
    job = run_worker(web, status=200)
    assert job["path"] == "/issue/status/change" and sorted(i["issueId"] for i in job["body"]["issues"]) == [1, 2]
    assert all(db.get_review(pid, h)["entered_hub"] for h in ("1", "2"))


def test_legacy_verification_records_versions_before_marks(web, monkeypatch):
    """Операция прежней схемы (без записанных баз целей) подтверждается сверкой: версия цели записана в транзакции
    сверки – сбой до отметок не оставляет предикат на старой базе; повторная доставка ставит отметку (ревью dev16, A1)."""
    from app import hub_effects
    from app.db import dumps, loads
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    decide(web, pid, "2", comment=REASON)
    accept(db, read((db, pid), hub))  # принятая база: To verify
    op_id = send(web, pid, "2").json()["op_id"]
    got = db.hub_claim("w1", HUB, 120)
    db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], {"status": 200, "body_text": "{}", "error": ""})
    with db._tx() as c:  # как операция схемы 30: без баз целей и без версии
        request = loads(db.hub_op(op_id)["request_json"], {})
        request.pop("accepted_issue_bases", None)
        c.execute("UPDATE hub_ops SET request_json=? WHERE id=?", (dumps(request), op_id))
        c.execute("DELETE FROM hub_entity_versions WHERE entity_key='SAST:2' AND (accepted_source_json::json ->> 'origin')='status_confirmation'")
    assert hub_effects.legacy_status_needs_read(db.hub_op(op_id))
    assert verify(web, pid, op_id).status_code == 200
    read_job = db.hub_claim("w1", HUB, 120)
    body = loads(db.hub_op(op_id)["request_json"], {})["body"]
    db.hub_result(read_job["attempt"]["id"], read_job["attempt"]["lease_token"], {"status": 200, "body_text": dumps(body)})

    def boom(*args, **kwargs):
        raise RuntimeError("сбой до отметок")

    monkeypatch.setattr(hub_effects, "mark_targets", boom)
    with pytest.raises(RuntimeError):
        hub_effects.after_result(db, db.hub_op(read_job["op"]["id"]))
    monkeypatch.undo()
    assert not db.get_review(pid, "2")["entered_hub"]
    version = db._one("SELECT accepted_source_json FROM hub_entity_versions WHERE entity_key='SAST:2'")
    assert loads(version["accepted_source_json"], {}).get("op_id") == op_id
    decide(web, pid, "1", comment=REASON)
    assert bulk_ids(web, pid, "1", "2") == [1]
    hub_effects.after_result(db, db.hub_op(read_job["op"]["id"]))  # повторная доставка
    assert db.get_review(pid, "2")["entered_hub"]


def test_duplicate_delivery_keeps_the_version(web):
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    decide(web, pid, "2", comment=REASON)
    assert send(web, pid, "2").status_code == 200
    got = db.hub_claim("w1", HUB, 120)
    result = {"status": 200, "body_text": "{}", "error": ""}
    assert db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], result)["outcome"] == "accepted"
    versions = db._all("SELECT * FROM hub_entity_versions ORDER BY entity_key")
    assert [v["accepted_epoch"] for v in versions] == [1]
    assert db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], result)["outcome"] == "duplicate"
    assert db._all("SELECT * FROM hub_entity_versions ORDER BY entity_key") == versions


def test_manual_mark_survives_withdrawn_hub_decision(web):
    """Решение, принятое из Hub, в Hub сняли: решение снимается, а ручная отметка оператора с её отпечатками
    остаётся (ревью dev16, A3)."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    hub.decision(2, reason=REASON)
    accept(db, read((db, pid), hub))
    review = db.get_review(pid, "2")
    assert review["decision_origin"] == "hub_sync" and review["entered_origin"] == "hub_sync"
    db.mark_entered(pid, "2", True, revision=review["revision"], entered_hash="h", entered_parts='{"manual": 1}',
                    entered_origin="manual")
    hub2 = open_hub()  # в Hub вернули на проверку
    accept(db, read((db, pid), hub2))
    after = db.get_review(pid, "2")
    assert after["decision"] == "" and after["decision_origin"] == ""
    assert after["entered_recorded"] == 1 and after["entered_origin"] == "manual" and after["entered_parts"] == '{"manual": 1}'


def test_comparison_fields_do_not_wait_for_sending_after_withdrawal(web):
    """После снятия отметки сравнение синхронизации не называет поля «Ждёт отправки в Hub» (ревью dev16, A4/B3:
    Hub ответил «принято» – решение отправлено, позднее изменение в Hub – не «не отправлено»)."""
    from app.db import loads
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    decide(web, pid, "2", comment=REASON)
    accept(db, read((db, pid), hub))
    assert send(web, pid, "2").status_code == 200
    run_worker(web, status=200)
    accept(db, read((db, pid), hub))  # возврат в To verify принят, отметка снята
    assert not db.get_review(pid, "2")["entered_hub"]
    rid = read((db, pid), hub)
    diff = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SAST:2'", (rid,))["diff_json"], {})
    assert "pending" not in diff["groups"]
    kinds = {f["field"]: f["kind"] for f in diff["fields"]}
    assert "pending" not in kinds.values() and kinds.get("status") == "local_only", kinds
    assert diff["delivery"]["state"] == "sent", diff["delivery"]  # dev15: отметка «отправлено» рядом с отличием
    assert db._one("SELECT COUNT(*) AS n FROM hub_sync_pending WHERE project_id=? AND hub_url=?"
                   " AND state IN ('pending', 'restored')", (pid, HUB))["n"] == 0
    page = web.client.get(f"/projects/{pid}/hub-sync/{rid}").text
    assert "Ждёт отправки в Hub" not in page and "отправки не ждёт" in page
    assert 'class="hub-sync-delivery">Отправлено в Hub<' in page  # ревью кода dev15, круг 9: отправка видна и здесь


def test_no_superseded_note_when_hub_took_another_decision(web):
    """FP записало приложение, в Hub поставили «Риск принят» и это принято: отметка Pull стоит, подписи «отметка снята»
    нет (ревью dev16, B2)."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    decide(web, pid, "2", comment=REASON)
    assert send(web, pid, "2").status_code == 200
    run_worker(web, status=200)
    hub.decision(2, status="Accepted risk", reason=REASON)
    accept(db, read((db, pid), hub))
    review = db.get_review(pid, "2")
    assert review["entered_hub"] and review["entered_origin"] == "hub_sync" and review["final_verdict"] == "risk_accepted"
    card = web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '2')}").text
    assert "Позже статус в Hub изменили" not in card and 'id="entered-badge" hidden' not in card


def test_pull_mark_of_other_scope_survives_pull(web):
    """Отметка Pull (решение принято из Hub) другого приложения Hub – история того назначения: Pull в текущем
    назначении её не снимает (ревью dev16, круг 3)."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2")])
    hub = open_hub()
    hub.decision(2, reason=REASON)
    accept(db, read((db, pid), hub))
    review = db.get_review(pid, "2")
    assert review["entered_origin"] == "hub_sync" and review["entered_hub"] == 1
    with db._tx() as c:  # отметка – от чтения другого приложения Hub
        c.execute("UPDATE hub_ops SET app_id = 8 WHERE id = ?", (review["entered_op_id"],))
        c.execute("UPDATE reviews SET decision_origin = 'operator' WHERE project_id = ? AND hub_id = ?", (pid, "2"))
    accept(db, read((db, pid), open_hub()))  # в текущем назначении – To verify
    after = db.get_review(pid, "2")
    assert after["entered_recorded"] == 1 and after["entered_op_id"] == review["entered_op_id"]
    assert after["entered_origin"] == "hub_sync"


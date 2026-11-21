"""Правки, сохранённые отдельно при принятии Hub, и отправка до первого принятия – как их видит синхронизация
(0.10.0.dev14, ADR-0142; ревью кругов 1–5). Данные выдуманные."""

import json
import re

from app import hub_sync as sync
from app.db import loads
from test_hub_status_routes import HUB, ORIGIN, decide, project, sast, send
from test_sync_golden_path import LiveHub, drain, groups, synchronize, synced
from test_web import web  # noqa: F401


class FailingHub(LiveHub):
    """Hub отвечает ошибкой на смену статуса."""

    def answer(self, request):
        if request["method"] == "POST" and request["path"] == "/issue/status/update":
            return 500, json.dumps({"errorMessage": "internal"})
        return super().answer(request)


def saved_edit(web, db, hub, pid) -> int:
    """Принято A, локально B, Hub снова A (другим путём) – B сохранена отдельно; вернуть номер сохранённой правки."""
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    hub.decision(1, status="False Positive", reason="Обоснование, записанное в Hub другим путём.")
    synchronize(db, pid, hub)
    # dev15: правка, заменённая состоянием Hub при принятии, – история (`saved`), не «ждёт отправки»
    row = db._one("SELECT id FROM hub_sync_pending WHERE project_id=? AND entity_key='SAST:1' AND state='saved'",
                  (pid,))
    assert row, "правка B сохранена отдельно"
    return int(row["id"])


def restore_saved(web, pid, pending_id):
    page = web.client.get(f"/projects/{pid}/hub-pending/{pending_id}").text
    token = re.search(r'name="confirmation" value="([^"]*)"', page).group(1)
    r = web.client.post(f"/projects/{pid}/hub-pending/{pending_id}", headers=ORIGIN, follow_redirects=False,
                        data={"action": "restore", "confirm": "yes", "confirmation": token})
    assert r.status_code in (302, 303), r.text


def pending_state(db, pending_id) -> str:
    return db._one("SELECT state FROM hub_sync_pending WHERE id=?", (pending_id,))["state"]


def causes(db, row, key):
    item = db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key=?", (row["id"], key))
    return loads(item["diff_json"], {}).get("causes", [])


def test_failed_send_before_first_accept_waits_for_sending(web):
    db = web.app.state.db
    hub = FailingHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    decide(web, pid, "1")
    assert send(web, pid, "1").status_code == 200
    drain(db, hub)
    assert groups(db, synced(db, pid, hub)).get("pending") == ["SAST:1"]


def test_restored_and_sent_saved_edit_is_delivered_after_accept(web):
    """Сохранённая правка без срока восстановлена и отправлена со сроком – после принятия закрыта, «совпадает»."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    pending_id = saved_edit(web, db, hub, pid)
    restore_saved(web, pid, pending_id)
    sent = send(web, pid, "1", extra={"replace": "1", "replace_confirm": "1"})  # в Hub уже «Ложное срабатывание»
    assert sent.status_code == 200, sent.text
    drain(db, hub)
    web.client.get(sent.json()["status_url"])
    drain(db, hub)
    found = causes(db, synced(db, pid, hub), "SAST:1")
    assert any("уже отправлена" in c for c in found), found
    synchronize(db, pid, hub)
    assert pending_state(db, pending_id) == "delivered"
    assert sync.passport(synced(db, pid, hub))["matches_snapshot"]


def test_restored_unsent_saved_edit_survives_second_accept(web):
    """Восстановить, не отправить, снова принять Hub – сохранённая правка не закрывается доставленной."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    pending_id = saved_edit(web, db, hub, pid)
    restore_saved(web, pid, pending_id)
    synchronize(db, pid, hub)
    # dev15: при новом принятии решение Hub снова побеждает – правка возвращается в историю (не «доставлена»)
    assert pending_state(db, pending_id) == "saved"
    assert sync.passport(synced(db, pid, hub))["matches_snapshot"]


def test_sending_another_decision_keeps_saved_edit_unsent(web):
    """Отправлено другое решение – сохранённая правка остаётся неотправленной, причина называет её, а не текущее."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    pending_id = saved_edit(web, db, hub, pid)
    decide(web, pid, "1", comment="Совсем другое обоснование оператора: значение берётся из константы модуля.")
    sent = send(web, pid, "1", extra={"replace": "1", "replace_confirm": "1"})
    assert sent.status_code == 200, sent.text
    drain(db, hub)
    web.client.get(sent.json()["status_url"])
    drain(db, hub)
    found = causes(db, synced(db, pid, hub), "SAST:1")
    assert not any("уже отправлена" in c for c in found), found
    # dev15: правка в истории – не отличие и не причина; текущее решение доставлено
    assert not any(c.startswith("Правка решения, сохранённая отдельно") for c in found), found
    assert not any(c.startswith("Правка решения в приложении") for c in found), ("текущее решение доставлено", found)
    assert pending_state(db, pending_id) == "saved"
    assert HUB


def test_hub_change_after_delivered_saved_edit_is_explained(web):
    """Ревью Kimi dev14, круг 9: сохранённая правка доставлена, затем Hub изменил обоснование – причина изменения Hub
    не скрывается сообщением о доставке."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    pending_id = saved_edit(web, db, hub, pid)
    restore_saved(web, pid, pending_id)
    sent = send(web, pid, "1", extra={"replace": "1", "replace_confirm": "1"})
    assert sent.status_code == 200, sent.text
    drain(db, hub)
    web.client.get(sent.json()["status_url"])
    drain(db, hub)
    hub.decision(1, status="False Positive", reason="Третье обоснование, записанное в Hub после отправки.")
    found = causes(db, synced(db, pid, hub), "SAST:1")
    assert any("уже отправлена" in c for c in found), found
    assert any("Hub" in c and ("изменилось" in c or "изменил" in c) for c in found), ("изменение Hub объяснено", found)


def test_unsent_saved_edit_and_hub_change_have_no_contradicting_causes(web):
    """Ревью Kimi dev14, круг 10: текущее решение доставлено, сохранённая правка не отправлена, Hub снова изменил решение –
    причины не утверждают одновременно, что неотправленной правки нет."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    saved_edit(web, db, hub, pid)
    decide(web, pid, "1", comment="Совсем другое обоснование оператора: значение берётся из константы модуля.")
    sent = send(web, pid, "1", extra={"replace": "1", "replace_confirm": "1"})
    assert sent.status_code == 200, sent.text
    drain(db, hub)
    web.client.get(sent.json()["status_url"])
    drain(db, hub)
    hub.decision(1, status="False Positive", reason="Третье обоснование, записанное в Hub после отправки.")
    found = causes(db, synced(db, pid, hub), "SAST:1")
    # dev15: сохранённая правка – история, не причина отличия; изменение Hub объяснено без противоречий
    assert not any(c.startswith("Правка решения, сохранённая отдельно") for c in found), found
    assert any("Hub" in c for c in found), found


def test_delivered_saved_edit_is_sent_unaccepted_not_pending(web):
    """Ревью Codex dev14, круг 11: восстановленная и отправленная правка до принятия – группа «Отправлено, ждёт
    принятия», не «Ждёт отправки»; ссылка – «Открыть сохранённую правку»."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    pending_id = saved_edit(web, db, hub, pid)
    restore_saved(web, pid, pending_id)
    sent = send(web, pid, "1", extra={"replace": "1", "replace_confirm": "1"})
    assert sent.status_code == 200, sent.text
    drain(db, hub)
    web.client.get(sent.json()["status_url"])
    drain(db, hub)
    row = synced(db, pid, hub)
    found = groups(db, row)
    assert "SAST:1" in found.get("sent_unaccepted", []) and "SAST:1" not in found.get("pending", []), found
    page = web.client.get(f"/projects/{pid}/hub-sync/{row['id']}").text
    assert "Отправлено в Hub, ждёт принятия состояния Hub" in page and "Открыть неотправленную правку" not in page

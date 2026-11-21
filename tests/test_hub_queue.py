"""Очередь операций в Hub (ADR-0114, app/db.py: hub_*): постановка и правила идентичности, блокировка целей,
атомарный захват с арендой, результат с токеном аренды, поздний и повторный результат, истечение аренды, отмена,
миграция 24 → 25. Время – настоящее (now_iso), если тест не про срок; адреса выдуманы."""

from __future__ import annotations

import json
from db_support import connect_db
import threading
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app import hub_ops
from app.db import Database, now_iso

HUB = "https://hub.example.org"


@pytest.fixture
def db(tmp_path: Path):
    database = Database(tmp_path / "triage.db")
    yield database
    database.close()


def probe(db, **kw):
    return db.hub_enqueue(purpose="probe", request=hub_ops.probe_request(), hub_url=HUB, app_id=None, **kw)


def status_req(issue_id: int, reason: str = "ложное", expired: str = "2027-01-01T00:00:00Z") -> dict:
    return {"method": "POST", "path": "/issue/status/update",
            "body": {"issueId": issue_id, "issueType": "SAST", "status": "False Positive", "reason": reason,
                     "expiredAt": expired}}


def write(db, issue_id: int = 1, reason: str = "ложное", expired: str = "2027-01-01T00:00:00Z", app_id: int = 7):
    return db.hub_enqueue(purpose="status", request=status_req(issue_id, reason, expired), hub_url=HUB,
                          app_id=app_id, targets=[{"issue_type": "SAST", "issue_id": issue_id, "revision": 1}],
                          text=reason)


def past(seconds: int) -> str:
    return (datetime.fromisoformat(now_iso()) - timedelta(seconds=seconds)).isoformat(timespec="seconds")


def claim(db, worker="w1", lease=120, now=None):
    got = db.hub_claim(worker, HUB, lease, now=now)
    assert got is not None
    return got


def deliver(db, got, result):
    return db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], result)


# ============================================================================ постановка


def test_enqueue_stores_snapshot_and_queued(db):
    op = write(db)
    assert op["state"] == "queued" and op["hub_url"] == HUB and op["app_id"] == 7 and op["purpose"] == "status"
    assert json.loads(op["request_json"])["path"] == "/issue/status/update"
    assert json.loads(op["targets_json"]) == [{"issue_type": "SAST", "issue_id": 1, "revision": 1}]
    assert op["text_hash"] == hub_ops.text_hash("ложное") and op["text_norm"] == "ложное"


def test_enqueue_rejects_unknown_purpose_and_request(db):
    with pytest.raises(ValueError, match="назначение"):
        db.hub_enqueue(purpose="delete", request=hub_ops.probe_request(), hub_url=HUB, app_id=None)
    with pytest.raises(hub_ops.HubRequestRejected):
        db.hub_enqueue(purpose="read", request={"method": "DELETE", "path": "/defects/1"}, hub_url=HUB, app_id=None)
    assert db.hub_ops_list() == []


def test_open_duplicate_is_refused(db):
    op = write(db)
    with pytest.raises(ValueError, match=f"№{op['id']}"):
        write(db)


def test_target_lock_refuses_other_text_for_same_finding(db):
    write(db, reason="первый текст")
    with pytest.raises(ValueError, match="незакрытая операция"):
        write(db, reason="второй текст")
    write(db, issue_id=2, reason="второй текст")  # другая находка – можно


def test_write_key_includes_request_body(db):
    a = write(db, expired="2027-01-01T00:00:00Z")
    got = claim(db)
    deliver(db, got, {"status": 400})  # определённый отказ: замок снят
    b = write(db, expired="2027-06-01T00:00:00Z")
    assert a["op_key"] != b["op_key"]


def test_done_write_is_never_queued_again(db):
    write(db)
    deliver(db, claim(db), {"status": 200, "body_text": "{}"})
    with pytest.raises(ValueError, match="уже выполнена"):
        write(db)


@pytest.mark.parametrize("close", ["failed", "cancelled"])
def test_failed_or_cancelled_write_frees_the_key(db, close):
    first = write(db)
    if close == "failed":
        deliver(db, claim(db), {"status": 403})
    else:
        assert db.hub_cancel(first["id"])
    again = write(db)
    assert again["id"] != first["id"] and again["op_key"] == first["op_key"]
    assert db.hub_op(first["id"])["op_key"] != first["op_key"], "прежняя строка уступила ключ"


def test_probe_can_be_queued_again_after_done(db):
    probe(db)
    deliver(db, claim(db), {"status": 200, "body_text": json.dumps({"name": "u"})})
    second = probe(db)
    assert second["state"] == "queued"


def test_probe_open_refused(db):
    probe(db)
    with pytest.raises(ValueError, match="уже в очереди"):
        probe(db)


# ============================================================================ захват


def test_claim_uses_real_time_and_lease(db):
    write(db)
    got = db.hub_claim("w1", HUB, 120)  # без подставленного времени
    assert got is not None and got["op"]["state"] == "queued"
    taken = datetime.fromisoformat(got["attempt"]["taken_at"])
    until = datetime.fromisoformat(got["attempt"]["taken_until"])
    assert until - taken == timedelta(seconds=120) and taken.tzinfo is not None
    assert db.hub_op(got["op"]["id"])["state"] == "taken" and len(got["attempt"]["lease_token"]) == 32


def test_claim_only_own_hub_and_fifo(db):
    first, second = write(db, issue_id=1), write(db, issue_id=2)
    assert db.hub_claim("w1", "https://other.example.org", 120) is None
    assert claim(db)["op"]["id"] == first["id"] and claim(db)["op"]["id"] == second["id"]
    assert db.hub_claim("w1", HUB, 120) is None


def test_two_workers_one_claim(db):
    """Две копии исполнителя – два одновременных запроса к одному приложению (база одна на процесс, EXCLUSIVE):
    операцию получает ровно одна."""
    write(db)
    results, errors, barrier = [], [], threading.Barrier(4)

    def worker(name):
        try:
            barrier.wait()
            results.append(db.hub_claim(name, HUB, 120))
        except Exception as e:  # ошибка потока не должна потеряться
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and len(results) == 4 and sum(r is not None for r in results) == 1


# ============================================================================ результат


def test_wrong_token_rejected(db):
    write(db)
    got = claim(db)
    assert db.hub_result(got["attempt"]["id"], "0" * 32, {"status": 200})["outcome"] == "rejected"
    assert db.hub_result(got["attempt"]["id"], "", {"status": 200})["outcome"] == "rejected"
    assert db.hub_result(999, got["attempt"]["lease_token"], {"status": 200})["outcome"] == "rejected"
    assert db.hub_op(got["op"]["id"])["state"] == "taken"


def test_result_closes_and_repeat_is_duplicate(db):
    write(db)
    got = claim(db)
    first = deliver(db, got, {"status": 200, "body_text": "{\"id\": 5}", "headers": {"Location": "/x"}})
    assert first["outcome"] == "accepted" and first["op"]["state"] == "done" and first["op"]["closed_at"]
    again = deliver(db, got, {"status": 500})
    assert again["outcome"] == "duplicate" and again["op"]["state"] == "done"
    stored = json.loads(db.hub_op(got["op"]["id"])["attempts"][0]["result_json"])
    assert stored["status"] == 200 and stored["headers"] == {"location": "/x"}, "первый результат не перезаписан"


@pytest.mark.parametrize("result,state", [
    ({"status": 0, "error": "timeout"}, "unknown"),
    ({"status": 200, "error": "обрыв"}, "unknown"),
    ({"status": 200, "body_text": "{}", "truncated": True}, "unknown"),
    ({"status": 302}, "unknown"),
    ({"status": 503}, "unknown"),
    ({"status": 409}, "failed"),
])
def test_write_outcomes(db, result, state):
    write(db)
    out = deliver(db, claim(db), result)
    assert out["op"]["state"] == state
    assert (out["op"]["closed_at"] is None) == (state == "unknown")


def test_unknown_write_keeps_lock_and_cannot_be_cancelled(db):
    op = write(db)
    deliver(db, claim(db), {"status": 0, "error": "timeout"})
    assert not db.hub_cancel(op["id"])
    with pytest.raises(ValueError, match="уже в очереди"):
        write(db)
    with pytest.raises(ValueError, match="незакрытая операция"):
        write(db, reason="другой текст")


def test_cancel_only_queued(db):
    op = write(db)
    claim(db)
    assert not db.hub_cancel(op["id"])
    other = write(db, issue_id=2)
    assert db.hub_cancel(other["id"]) and db.hub_op(other["id"])["state"] == "cancelled"


def test_read_failure_is_failed(db):
    probe(db)
    out = deliver(db, claim(db), {"status": 0, "error": "сбой"})
    assert out["op"]["state"] == "failed" and out["op"]["closed_at"]


# ============================================================================ аренда


def test_expired_lease_write_unknown_read_failed(db):
    write(db)
    probe(db)
    w = claim(db, now=past(300))
    r = claim(db, now=past(300))
    assert db.hub_expire_leases() == 2
    assert db.hub_op(w["op"]["id"])["state"] == "unknown"
    assert db.hub_op(r["op"]["id"])["state"] == "failed" and db.hub_op(r["op"]["id"])["closed_at"]
    assert probe(db)["state"] == "queued", "повторная проверка связи после истёкшей"
    assert db.hub_expire_leases() == 0


def test_live_lease_not_expired(db):
    write(db)
    claim(db)
    assert db.hub_expire_leases() == 0


@pytest.mark.parametrize("purpose,state", [("status", "unknown"), ("probe", "failed")])
def test_late_result_closes_taken_at_once(db, purpose, state):
    write(db) if purpose == "status" else probe(db)
    got = claim(db, now=past(300))
    out = deliver(db, got, {"status": 200, "body_text": "{}"})
    assert out["outcome"] == "late" and out["op"]["state"] == state
    attempt = db.hub_op(got["op"]["id"])["attempts"][0]
    assert attempt["late"] == 1 and attempt["received_at"]


def test_late_result_after_expiry_keeps_unknown(db):
    write(db)
    got = claim(db, now=past(300))
    db.hub_expire_leases()
    out = deliver(db, got, {"status": 200, "body_text": "{}"})
    assert out["outcome"] == "late" and out["op"]["state"] == "unknown", "поздний 200 не закрывает запись сам"


# ============================================================================ миграция


def test_new_database_has_hub_tables(tmp_path: Path):
    path = tmp_path / "triage.db"
    Database(path).close()
    con = connect_db(path)
    try:
        tables = {r[0] for r in con.execute("SELECT table_name FROM information_schema.tables"
                                            " WHERE table_schema = current_schema()")}
        columns = {r[0] for r in con.execute("SELECT column_name FROM information_schema.columns"
                                             " WHERE table_name = 'projects'")}
    finally:
        con.close()
    assert {"hub_ops", "hub_attempts"} <= tables and "hub_app_id" in columns


def test_update_project_hub_app_id_set_and_clear(db):
    pid = db.create_project("p")
    assert db.update_project(pid, hub_app_id=12)
    assert db.get_project(pid)["hub_app_id"] == 12
    assert db.update_project(pid, name="q")
    assert db.get_project(pid)["hub_app_id"] == 12, "False – не менять"
    assert db.update_project(pid, hub_app_id=None)
    assert db.get_project(pid)["hub_app_id"] is None

from db_support import record_queries
"""Регрессии приёмки: только синтетические ответы и локальное применение."""

import cProfile
import copy
import json
import os
import pstats
import time
from pathlib import Path

import pytest

from app import hub_pull as pull, hub_sync as sync, hub_sync_compare as compare
from app.db import dumps, loads
from test_hub_pull import PullHub, accept, read, run, store, HUB  # noqa: F401
from test_hub_sync_analyst import defect_store
from test_hub_sync_analyst import seed_performance
from test_hub_sync_observed import local_finding
from test_web import web  # noqa: F401


@pytest.mark.parametrize("origin,reason,expiry", [
    ("operator", "Основание\n  Hub", "2098-12-31"),
    ("hub_sync", "", None), ("hub_sync", "Основание", None),
    ("", "Старое решение без базы", None),
])
def test_first_accept_does_not_promote_equal_or_unproven_decision(store, origin, reason, expiry):
    db, pid = store
    local_finding(store)
    with db._tx() as c:
        c.execute("UPDATE reviews SET decision_origin=?,entered_origin=?,final_comment=?,desired_hub_expired_at=?",
                  (origin, "hub_sync" if origin == "hub_sync" else "", reason, expiry))
    hub = PullHub(defects=False)
    hub.decision(1)
    rid = read(store, hub)
    assert accept(db, rid)["pending"] == 0
    saved = db._all("SELECT * FROM hub_sync_pending ORDER BY 1, 2")
    if origin == "hub_sync":
        assert not saved  # решение уже из Hub – работы оператора нет
    else:
        # dev15 (план п. 1.3.1, ревью Codex круг 1): заменяемое решение оператора сохраняется в историю и при первом
        # принятии без базы и без операции отправки (раньше – только с доказательством правки); не отличие
        assert [r["state"] for r in saved] == ["saved"]
        assert loads(saved[0]["payload_json"], {})["local"]["review"]["final_comment"] == reason
    assert db.get_review(pid, "1")["final_comment"] == "Основание Hub"
    before = loads(db._one("SELECT before_json FROM hub_sync_applications")["before_json"], {})
    assert before["local"]["review"]["final_comment"] == reason


@pytest.mark.parametrize("known", [False, True])
def test_import_revision_alone_is_not_operator_edit(store, known):
    db, _ = store
    owner, _ = defect_store(store)
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET origin='import',draft_revision=9,confirmed_object_json=? WHERE id=?",
                  (owner["confirmed_object_json"] if known else "", owner["id"]))
    rid = read(store, PullHub())
    assert accept(db, rid)["pending"] == 0
    assert not db._all("SELECT * FROM hub_sync_pending ORDER BY 1, 2")


@pytest.mark.parametrize("state,pending", [("failed", 1), ("done", 0), ("cancelled", 0)])
@pytest.mark.parametrize("origin", ["", "hub_sync"])
def test_unknown_base_preserves_only_explicit_unsent_status(store, state, pending, origin):
    db, pid = store
    rid, _ = seed_performance(db, pid, 1)
    with db._tx() as c:
        c.execute("UPDATE reviews SET decision_origin=?", (origin,))
        c.execute("UPDATE hub_ops SET state=? WHERE purpose='status'", (state,))
        item = c.execute("SELECT hub_json FROM hub_sync_items WHERE run_id=?", (rid,)).fetchone()
        hub = loads(item["hub_json"], {})
        hub["manual"]["reason"] = "Иное принятое основание"
        c.execute("UPDATE hub_sync_items SET hub_json=? WHERE run_id=?", (dumps(hub), rid))
        compare.compare_in(c, sync.run_in(c, rid))
    # dev15: решение Hub побеждает; неудачная отправка другого основания – в истории (`saved`), не «ждёт отправки»
    assert accept(db, rid)["pending"] == 0
    if pending:
        row = db._one("SELECT * FROM hub_sync_pending")
        assert row["state"] == "saved"
        payload = loads(row["payload_json"], {})
        # Формат dev2 не содержал состояния операции внутри сохранённого status_intent.
        payload["local"]["status_intent"].pop("state", None)
        with db._tx() as c:
            c.execute("UPDATE hub_sync_pending SET payload_json=? WHERE id=?", (dumps(payload), row["id"]))
        compare.recompare(db, rid)
        assert db._one("SELECT state FROM hub_sync_pending")["state"] == "saved"
    elif origin == "hub_sync" or state != "failed":
        assert not db._all("SELECT * FROM hub_sync_pending WHERE state<>'saved'")


def test_operator_draft_after_accept_is_preserved_but_equal_change_is_not(store):
    from app import defect_drafts
    db, _ = store
    hub = PullHub()
    accept(db, read(store, hub))
    owner = db._one("SELECT * FROM hub_defects")
    defect_drafts.save(db, owner, str(owner["draft_revision"]), summary="Новая правка", command="Новый текст")
    hub.defects[77]["summary"] = "Заголовок другого оператора"
    # dev15: черновик дефекта приводится к Hub, правка оператора – в истории (`saved`), не «ждёт отправки»
    assert accept(db, read(store, hub))["pending"] == 0
    pending = db._one("SELECT * FROM hub_sync_pending")
    assert pending["state"] == "saved" and loads(pending["payload_json"], {})["values"]["summary"] == "Новая правка"
    owner = db._one("SELECT * FROM hub_defects")
    defect_drafts.save(db, owner, str(owner["draft_revision"]), summary=owner["draft_summary"],
                       command="Принятый \n текст")
    assert accept(db, read(store, hub))["pending"] == 0
    assert db._scalar("SELECT COUNT(*) FROM hub_sync_pending") == 1


@pytest.mark.parametrize("baseline", ["hub", "operator", "operator_unchanged"])
def test_new_operator_defect_decision_after_accept_survives_conflicting_hub(store, baseline):
    db, pid = store
    hub = PullHub(defects=False)
    if baseline != "hub":
        local_finding(store)
        db.save_review(pid, "1", decision="disagree", final_verdict="true_positive",
                       final_comment="Прежний вывод оператора", final_fix="Прежнее исправление", reviewed=False)
    accept(db, read(store, hub))
    if baseline != "operator_unchanged":
        db.save_review(pid, "1", decision="disagree", final_verdict="true_positive",
                       final_comment="Новый вывод оператора", final_fix="Новое исправление", reviewed=False)
    hub.decision(1)
    rid = read(store, hub)
    # dev15: «Подтверждаю дефект» при решении Hub «Ложное срабатывание» – Hub побеждает, вывод оператора в истории
    assert accept(db, rid)["pending"] == 0
    if baseline == "operator_unchanged":
        # dev15 (план п. 1.3, ревью Codex круг 2): заменённый Hub вывод оператора сохраняется в историю и без новой
        # правки после принятия – его можно вернуть
        saved = db._all("SELECT * FROM hub_sync_pending ORDER BY 1, 2")
        assert [r["state"] for r in saved] == ["saved"]
        assert loads(saved[0]["payload_json"], {})["local"]["review"]["final_comment"] == "Прежний вывод оператора"
        return
    pending = db._one("SELECT id,payload_json FROM hub_sync_pending")
    payload = loads(pending["payload_json"], {})
    original = payload["local"]["review"]
    assert original["final_comment"] == "Новый вывод оператора"
    assert original["final_fix"] == "Новое исправление"
    # Старое ожидание: доказательство приходится восстанавливать из истории принятия.
    payload["local"].pop("review_after_base")
    payload["values"] = pull.pending_values("issue", payload["local"])
    with db._tx() as c:
        c.execute("UPDATE hub_sync_pending SET payload_json=? WHERE id=?", (dumps(payload), pending["id"]))
    compare.recompare(db, rid)
    assert db._one("SELECT state FROM hub_sync_pending")["state"] == "saved"


def legacy_pending(db, rid, kind, key, local, base, hub):
    payload = {"local": local, "base": base, "values": pull.pending_values(kind, local),
               "links": None, "hub_at_save": hub}
    with db._tx() as c:
        ident = c.execute("INSERT INTO hub_sync_pending(project_id,hub_url,app_id,entity_kind,entity_key,"
                          "signature,payload_json,created_run_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)" " RETURNING id",
                          (*pull.scope(run(db, rid)), kind, key, str(time.time_ns()), dumps(payload), rid,
                           "2026-10-30T10:00:00+00:00")).fetchone()[0]
    return ident, payload


@pytest.mark.parametrize("entry", ["page", "pending", "recompare", "apply"])
def test_legacy_false_pending_reconciled_with_history_and_real_edit_kept(web, entry):
    db = web.app.state.db
    pid = db.create_project("Демо восстановления ожиданий")
    db.update_project(pid, hub_app_id=7)
    db.set_settings({"hub_url": HUB})
    hub = PullHub()
    hub.decision(1)
    rid = read((db, pid), hub)
    result = accept(db, rid)
    row = run(db, rid)
    ctx = db.on_connection(lambda c: compare.ComparisonContext(c, row))
    issue = ctx.issue_local("SAST:1")
    accepted = loads(issue["state"]["confirmed_json"], {})
    equal, payload_equal = legacy_pending(db, rid, "issue", "SAST:1", issue, {}, accepted)
    poor = copy.deepcopy(issue)
    poor["state"] = None
    poor["review"].update(final_comment="", desired_hub_expired_at=None, decision_origin="hub_sync")
    stale, payload_stale = legacy_pending(db, rid, "issue", "SAST:1", poor, {}, accepted)
    defect = ctx.defect_local("77")
    duplicate, _ = legacy_pending(db, rid, "defect", "77", defect, {}, {"detail": hub.defects[77]})
    db.save_review(pid, "1", decision="disagree", final_verdict="false_positive",
                   final_comment="Настоящее намерение", reviewed=False)
    real = db.on_connection(lambda c: compare.ComparisonContext(c, row).issue_local("SAST:1"))
    true_id, _ = legacy_pending(db, rid, "issue", "SAST:1", real, accepted, accepted)
    operations = db._all("SELECT * FROM hub_ops ORDER BY 1, 2")
    if entry == "page":
        assert web.client.get(f"/projects/{pid}/hub-sync/{rid}").status_code == 200
    elif entry == "pending":
        response = web.client.get(f"/projects/{pid}/hub-pending/{stale}")
        assert response.status_code == 200 and "История ожидания" in response.text
    elif entry == "recompare":
        compare.recompare(db, rid)
    else:
        assert pull.apply(db, rid, result["token"])["pending"] == 1
    rows = {p["id"]: p for p in db._all("SELECT * FROM hub_sync_pending ORDER BY 1, 2")}
    assert rows[equal]["state"] == rows[duplicate]["state"] == "delivered"
    assert rows[stale]["state"] == "discarded"
    assert rows[true_id]["state"] == "pending"
    for ident, original in ((equal, payload_equal), (stale, payload_stale)):
        saved = loads(rows[ident]["payload_json"], {})
        assert {k: v for k, v in saved.items() if k != "history"} == original
        assert len(saved["history"]) == 1 and saved["history"][0]["reason"]
    assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == operations
    snapshot = db._all("SELECT * FROM hub_sync_pending ORDER BY 1, 2")
    pull.apply(db, rid, result["token"])
    assert db._all("SELECT * FROM hub_sync_pending ORDER BY 1, 2") == snapshot


def seed_volume(db, pid):
    """Сохранённый полный обход: 1800 находок и 10 дефектов наблюдаемой формы."""
    hub = PullHub(count=1800, defects=False)
    rid = read((db, pid), PullHub(count=0, defects=False))
    defect = PullHub().defects[77]
    with db._tx() as c:
        for ident, detail in hub.issues.items():
            detail = {**detail, "description": "Синтетическое описание правила. " * 1024}
            value = {"brief": {"id": ident, "appId": 7, "type": "SAST"}, "detail": detail, "manual": None}
            c.execute("INSERT INTO hub_sync_items(run_id,entity_kind,entity_key,hub_json) VALUES (?,'issue',?,?)",
                      (rid, f"SAST:{ident}", dumps(value)))
        for ident in range(101, 111):
            obj = {**copy.deepcopy(defect), "id": ident, "linkedIssues": []}
            value = {"brief": {"id": ident, "app": {"id": 7}}, "detail": obj}
            c.execute("INSERT INTO hub_sync_items(run_id,entity_kind,entity_key,hub_json) VALUES (?,'defect',?,?)",
                      (rid, str(ident), dumps(value)))
        compare.compare_in(c, sync.run_in(c, rid))
    return rid


def measure_page(web, pid, rid, label):
    queries = []
    profile = cProfile.Profile()
    stop_recording = record_queries(queries)
    # TestClient выполняет обработчик в другом потоке: профилируем внутри него.
    from app.routes import hub_sync_routes
    original = hub_sync_routes.hub_sync_compare.snapshot_current
    original_loads = compare.loads
    parses = {"large_json": 0, "parsed_bytes": 0}
    def counted_loads(raw, default):
        if isinstance(raw, str) and len(raw) > 8192:
            parses["large_json"] += 1
            parses["parsed_bytes"] += len(raw.encode("utf-8"))
        return original_loads(raw, default)
    compare.loads = hub_sync_routes.loads = counted_loads
    def profiled(*args, **kwargs):
        return profile.runcall(original, *args, **kwargs)
    hub_sync_routes.hub_sync_compare.snapshot_current = profiled
    start = time.perf_counter()
    try:
        response = web.client.get(f"/projects/{pid}/hub-sync/{rid}")
    finally:
        elapsed = time.perf_counter() - start
        hub_sync_routes.hub_sync_compare.snapshot_current = original
        compare.loads = hub_sync_routes.loads = original_loads
        stop_recording()
    result = {"label": label, "objects": 1810, "seconds": round(elapsed, 4),
              "sql": len(queries), "bytes": len(response.content), **parses}
    print(json.dumps(result))
    if directory := os.environ.get("HUB_PULL_MEASUREMENT"):
        path = Path(directory)
        with (path / "measurements.jsonl").open("a", encoding="utf-8") as out:
            out.write(json.dumps(result) + "\n")
        with (path / f"profile-{label}.txt").open("w", encoding="utf-8") as out:
            pstats.Stats(profile, stream=out).sort_stats("cumulative").print_stats(25)
        (path / f"sql-{label}.txt").write_text("\n".join(queries), encoding="utf-8")
    assert response.status_code == 200
    return result


def test_result_page_after_accepting_1810_objects(web):
    db = web.app.state.db
    pid = db.create_project("Демо объёма применения")
    db.update_project(pid, hub_app_id=7)
    rid = seed_volume(db, pid)
    measure_page(web, pid, rid, "before-apply")
    assert accept(db, rid)["count"] == 1810
    first = measure_page(web, pid, rid, "after-apply-first")
    again = measure_page(web, pid, rid, "after-apply-repeat")
    assert max(first["sql"], again["sql"]) < 120
    assert max(first["seconds"], again["seconds"]) < 3
    assert max(first["bytes"], again["bytes"]) < 200_000
    assert max(first["large_json"], again["large_json"]) <= 50


def test_operator_defect_decision_after_accept_is_not_pending_while_hub_has_no_decision(store):
    """«Подтверждаю дефект» сохранено после принятия, в Hub – Open без решения;
    статусом это решение в Hub не уходит – «Ждёт отправки» нет, решение оператора не меняется."""
    db, pid = store
    hub = PullHub(defects=False)
    local_finding(store)
    accept(db, read(store, hub))
    db.save_review(pid, "1", decision="disagree", final_verdict="true_positive",
                   final_comment="Обновить компонент", final_fix="Обновить", reviewed=True)
    rid = read(store, hub)
    assert accept(db, rid)["pending"] == 0
    assert not db._all("SELECT * FROM hub_sync_pending WHERE state='pending'")
    review = db.get_review(pid, "1")
    assert review["final_verdict"] == "true_positive" and review["final_comment"] == "Обновить компонент"


def test_pending_order_does_not_change_local_fingerprint(store):
    """Итоговая проверка 0.10.0: номера неотправленных правок одного объекта входят в отпечаток локального состояния
    списком. После UPDATE строки PostgreSQL отдаёт её в другом месте выборки без ORDER BY, и сверка сочла бы данные
    изменёнными («Локальные данные изменились после сравнения») – без единой правки."""
    from app import hub_entity_versions as versions

    db, pid = store
    hub = PullHub(defects=False)
    local_finding(store)
    rid = read(store, hub)
    accept(db, rid)
    row = run(db, rid)
    issue = db.on_connection(lambda c: compare.ComparisonContext(c, row).issue_local("SAST:1"))
    payload = dumps({"local": issue, "base": {}, "values": pull.pending_values("issue", issue), "links": None, "hub_at_save": {}})
    with db._tx() as c:  # подписи идут против номеров: чтение по уникальному индексу тоже не даёт порядка номеров
        first, second = (c.execute(
            "INSERT INTO hub_sync_pending(project_id,hub_url,app_id,entity_kind,entity_key,signature,payload_json,"
            "created_run_id,created_at) VALUES (?,?,?,?,?,?,?,?,?) RETURNING id",
            (*pull.scope(row), "issue", "SAST:1", signature, payload, rid, "2026-11-05T10:00:00+00:00")).fetchone()[0]
            for signature in ("b", "a"))
    before = db.on_connection(lambda c: compare.ComparisonContext(c, row).issue_local("SAST:1"))
    assert before["pending"] == [first, second]
    with db._tx() as c:  # значения прежние, но новая версия строки ложится после второй
        c.execute("UPDATE hub_sync_pending SET state = state WHERE id = ?", (first,))
    # dev15: принятие уже сохранило в историю решение оператора по Fixed – смотрим только две вставленные строки
    physical = [r["id"] for r in db._all("SELECT id FROM hub_sync_pending") if r["id"] in (first, second)]
    assert physical == [second, first], "строка не сменила место: тест не проверяет зависимость от порядка"
    after = db.on_connection(lambda c: compare.ComparisonContext(c, row).issue_local("SAST:1"))
    assert after["pending"] == [first, second]
    assert versions.digest(after) == versions.digest(before)


def test_historical_operator_defect_decision_is_not_closed_by_compatibility():
    """Ревью dev10: сохранённая правка «Подтверждаю дефект» – историческое решение; совместимость с Open в Hub её не
    закрывает (иначе её нельзя вернуть в редактор), а текущее решение – закрывает."""
    local = {"review": {"decision": "disagree", "final_verdict": "true_positive", "final_comment": "Б",
                        "decision_origin": "operator", "revision": 2}}
    hub = {"detail": {"status": "Open"}, "manual": None}
    base = {"detail": {"status": "False Positive"}, "manual": {"status": "False Positive", "reason": "А"}}
    assert pull.pending_change("issue", local, base, hub) == (False, None)
    assert pull.pending_change("issue", local, base, hub, historical=True)[0] is True


def _hub_status(hub, ident, status):
    hub.issues[ident]["status"] = status
    hub.issues[ident]["issueBranchBriefData"][0]["status"] = status


@pytest.mark.parametrize("hub_status,outgoing", [("Open", False), ("False Positive", True)])
def test_operator_defect_decision_in_comparison_follows_current_hub_status(store, hub_status, outgoing):
    """«Подтверждаю дефект» сохранено после принятия, затем Hub сам сменил статус
    (создание дефекта: To verify → Open) – сверка, как и «Принять», не называет решение «ждёт отправки»; Hub поставил
    «Ложное срабатывание» – решение оператора остаётся спорным."""
    db, pid = store
    hub = PullHub(defects=False)
    local_finding(store)
    _hub_status(hub, 1, "To verify")
    accept(db, read(store, hub))
    db.save_review(pid, "1", decision="disagree", final_verdict="true_positive",
                   final_comment="Обновить компонент", final_fix="Обновить", reviewed=True)
    _hub_status(hub, 1, hub_status)
    rid = read(store, hub)
    groups = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_kind='issue'",
                           (rid,))["diff_json"], {})["groups"]
    assert bool({"pending", "conflict"} & set(groups)) == outgoing, groups
    if not outgoing:
        assert accept(db, rid)["pending"] == 0
        review = db.get_review(pid, "1")
        assert review["final_verdict"] == "true_positive" and review["final_comment"] == "Обновить компонент"

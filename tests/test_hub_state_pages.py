"""Состояние относительно Hub на страницах оператора (0.10.0.dev15, бэклог 88): список находок (значок и отбор),
карточки SAST и SCA, обзор групп SCA, строка «Синхронизация с Hub» на обзоре проекта; замер скорости на 1800
находках (план п. 2.3: меньше 120 SQL-запросов и 3 секунд на страницу)."""
import json
import re
import time

from app import hub_state, hub_sync as sync, hub_sync_compare as compare
from app.db import dumps
from db_support import record_queries
from test_hub_pull import PullHub, accept, read
from test_hub_status_routes import HUB, decide, project, sast, sca, send
from test_sync_golden_path import LiveHub, drain, synced, synchronize
from test_web import web  # noqa: F401


def badges(html, hub_id):
    return re.findall(rf'<a class="badge badge-(\w+) hub-state" id="hub-state-{hub_id}(?:-\d+)?"[^>]*>([^<]*)</a>', html)


def test_list_badges_and_filters(web):
    db = web.app.state.db
    hub = LiveHub(3)
    pid = project(web, [sast("1"), sast("2", line=5), sast("3", line=8)])
    synchronize(db, pid, hub)
    decide(web, pid, "2")
    hub.issues[3]["category"] = {"category": "Новое правило", "cwes": [{"id": "CWE-20"}]}
    synced(db, pid, hub)
    page = web.client.get(f"/projects/{pid}/findings").text
    assert badges(page, "1") == []  # совпадает – без значка
    assert badges(page, "2") == [("warn", compare.DELIVERY_LABELS["unsent"])]
    assert badges(page, "3") == [("accent", compare.LABELS["observed"])]
    assert "Синхронизация с Hub" in page and "не отправлено в Hub" in page  # группа отбора
    differs = web.client.get(f"/projects/{pid}/findings?hubsync=differs").text
    assert set(re.findall(r'id="hub-state-(\d+)"', differs)) == {"2", "3"}


def test_filter_keeps_only_matching_rows(web):
    db = web.app.state.db
    hub = LiveHub(3)
    pid = project(web, [sast("1"), sast("2", line=5), sast("3", line=8)])
    synchronize(db, pid, hub)
    decide(web, pid, "2")
    synced(db, pid, hub)
    states = hub_state.project_states(db, db.get_project(pid), HUB)
    from app.routes.findings import HUB_SYNC_FILTERS
    assert set(HUB_SYNC_FILTERS) == {"unsent", "differs"}
    ids = {h for h, st in states["by_hub_id"].items() if st["unsent"]}
    assert ids == {"2"}
    page = web.client.get(f"/projects/{pid}/findings?hubsync=unsent").text
    shown = set(re.findall(r'id="hub-state-(\d+)"', page))
    assert shown == {"2"}, shown


def test_card_shows_state_note(web):
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    synchronize(db, pid, hub)
    decide(web, pid, "2")
    synced(db, pid, hub)
    fid = lambda h: db._one("SELECT id FROM findings WHERE project_id=? AND hub_id=?", (pid, h))["id"]  # noqa: E731
    card = web.client.get(f"/projects/{pid}/findings/{fid('2')}").text
    assert 'id="hub-state-note"' in card and compare.DELIVERY_LABELS["unsent"] in card
    assert 'id="hub-state-link"' in card
    matched = web.client.get(f"/projects/{pid}/findings/{fid('1')}").text
    assert "Совпадает с последним чтением Hub" in matched


def test_never_read_project_overview_and_card(web):
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2", line=5)])
    decide(web, pid, "1")
    overview = web.client.get(f"/projects/{pid}").text
    line = re.search(r'<p[^>]*id="step-hub-sync-line"[^>]*>(.*?)</p>', overview, re.S).group(1)
    assert "Hub не читался" in line and "– 1" in line, line
    fid = db._one("SELECT id FROM findings WHERE project_id=? AND hub_id='1'", (pid,))["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert 'id="hub-state-never"' in card


def test_overview_line_counts_and_all_match(web):
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    synchronize(db, pid, hub)
    synced(db, pid, hub)
    overview = web.client.get(f"/projects/{pid}").text
    line = re.search(r'<p[^>]*id="step-hub-sync-line"[^>]*>(.*?)</p>', overview, re.S).group(1)
    assert "всё совпадает с Hub" in line, line
    decide(web, pid, "1")
    overview = web.client.get(f"/projects/{pid}").text
    line = re.search(r'<p[^>]*id="step-hub-sync-line"[^>]*>(.*?)</p>', overview, re.S).group(1)
    assert "не отправлено 1" in line and "Hub не принял 0" in line and 'id="step-hub-unsent-link"' in line, line


def test_sca_card_and_groups_overview(web):
    db = web.app.state.db
    hub = PullHub(count=0, defects=False)
    pid = project(web, [sca("201")])
    previous = None
    rid = sync.start(db, pid, HUB, 7, previous=previous, app_confirmed=True)  # номер подтверждён: в Hub пусто
    from test_hub_pull import finish_pull
    finish_pull(db, hub, rid)
    with db._tx() as c:  # наблюдение находки SCA, как в полном чтении
        c.execute("UPDATE hub_sync_items SET hub_json=?,stale_reason='',coverage_json='{}' WHERE run_id=? AND entity_key=?",
                  (dumps({"brief": {"id": 201, "appId": 7, "type": "SCA_S"},
                          "detail": {"id": 201, "appId": 7, "status": "To verify", "currentBranch": "main",
                                     "issueBranchBriefData": [{"branch": "main", "status": "To verify"}]},
                          "manual": None}), rid, "SCA_S:201"))
        compare.compare_in(c, sync.run_in(c, rid))
    decide(web, pid, "201", decision="disagree", verdict="false_positive")
    st = hub_state.project_states(db, db.get_project(pid), HUB)["by_hub_id"]["201"]
    assert st["delivery"]["state"] == "unsent", st
    overview = web.client.get(f"/projects/{pid}/sca").text
    assert "не отправлено в Hub 1" in overview
    fid = db._one("SELECT id FROM findings WHERE project_id=? AND hub_id='201'", (pid,))["id"]
    card = web.client.get(f"/projects/{pid}/sca/findings/{fid}").text
    assert 'id="hub-state-note"' in card


# ============================================================================ скорость (план п. 2.3)


def seed_large(web, n=1800):
    """1800 находок с полным чтением, история операций (100 отправок), сохранённые редакции (50 решений оператора,
    заменённых решением Hub при принятии), 300 неотправленных решений."""
    db = web.app.state.db
    pid = project(web, [])
    rid = read((db, pid), PullHub(count=0, defects=False))
    from app.triage import order_findings
    db.save_import(pid, "big.xlsx", "xlsx", [], {}, [], order_findings([sast(str(i), line=i % 300 + 1)
                                                                       for i in range(1, n + 1)]))
    live = LiveHub(n)
    for ident in range(1, 51):  # в Hub – «Ложное срабатывание» со своим основанием
        live.decision(ident, status="False Positive", reason="Основание Hub")
    with db._tx() as c:
        c.execute("DELETE FROM hub_sync_items WHERE run_id=?", (rid,))
        for ident, detail in live.issues.items():
            detail = {**detail, "description": "Синтетическое описание правила. " * 256}
            value = {"brief": {"id": ident, "appId": 7, "type": "SAST"}, "detail": detail,
                     "manual": live.manual.get(ident)}
            c.execute("INSERT INTO hub_sync_items(run_id,entity_kind,entity_key,hub_json) VALUES (?,'issue',?,?)",
                      (rid, f"SAST:{ident}", dumps(value)))
        compare.compare_in(c, sync.run_in(c, rid))
    for ident in range(1, 51):
        decide(web, pid, str(ident), comment="Своё основание оператора")
    compare.recompare(db, rid)  # принятие требует пересчёта после локальных правок
    accept(db, rid)
    for ident in range(51, 351):
        decide(web, pid, str(ident))
    for ident in range(51, 151):
        assert send(web, pid, str(ident)).status_code == 200
    drain(db, live)
    return db, pid, rid


def measure(web, url):
    queries = []
    stop = record_queries(queries)
    start = time.perf_counter()
    try:
        response = web.client.get(url)
    finally:
        elapsed = time.perf_counter() - start
        stop()
    assert response.status_code == 200, (url, response.status_code)
    result = {"url": url, "seconds": round(elapsed, 3), "sql": len(queries)}
    print(json.dumps(result, ensure_ascii=False))
    return result


def test_pages_with_hub_state_on_1800_findings(web):
    db, pid, rid = seed_large(web)
    assert db._scalar("SELECT COUNT(*) FROM hub_sync_pending WHERE project_id=? AND state='saved'", (pid,)) == 50
    fid = db._one("SELECT id FROM findings WHERE project_id=? AND hub_id='60'", (pid,))["id"]
    pages = [f"/projects/{pid}/findings", f"/projects/{pid}/findings?hubsync=unsent",
             f"/projects/{pid}/findings?hubsync=unsent&page=2", f"/projects/{pid}/findings?hubsync=differs",
             f"/projects/{pid}/findings/{fid}", f"/projects/{pid}"]
    results = [measure(web, url) for url in pages]
    for r in results:
        assert r["seconds"] < 3, r
        if "/findings/" not in r["url"]:
            assert r["sql"] < 120, r  # страницы проекта (план п. 2.3)
    # карточка считает одну находку, а не проект (план п. 2.3): запросов состояния – столько же, сколько у маленького
    # проекта, сама карточка без состояния делала их и раньше
    queries = []
    stop = record_queries(queries)
    hub_state.project_states(db, db.get_project(pid), HUB, keys=["SAST:60"])
    stop()
    assert len(queries) < 30, len(queries)
    states = hub_state.project_states(db, db.get_project(pid), HUB)
    unsent = sum(st["unsent"] for st in states["by_hub_id"].values())
    assert unsent == 300 - 100, unsent  # 300 решений, 100 из них доставлены
    # доставленное решение – «Отправлено в Hub» независимо от порядка последующего чтения, не «не отправлено»
    delivered = [states["by_hub_id"][str(i)] for i in range(51, 151)]
    assert not any(st["unsent"] for st in delivered), [st["delivery"] for st in delivered if st["unsent"]][:3]

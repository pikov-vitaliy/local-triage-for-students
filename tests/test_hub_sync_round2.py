"""Круг 2: точная карточка объекта и отсутствие продолжения закрытого чтения."""

import re

import pytest

from app import hub_sync as sync
from app.db import dumps, loads
from app.routes.hub_sync_routes import item_card
from test_hub_sync import FakeSyncHub, finish, run, step
from test_hub_sync_routes import confirm
from test_hub_sync_round1 import token
from test_hub_status_routes import project, sast
from test_web import ORIGIN, web  # noqa: F401


@pytest.mark.parametrize("kind,key,section", [
    ("SAST", "SAST:1", "findings"),
    ("SCA", "SCA_S:1", "sca/findings"),
    ("SAST", "SCA_S:1", ""),
    ("SCA", "SAST:1", ""),
    ("SAST", "SAST:2", ""),
    ("SCA", "SCA_S:2", ""),
])
def test_b21_card_requires_hub_type_and_id(kind, key, section):
    item = {"entity_kind": "issue", "entity_key": key,
            "local_json": dumps({"finding": {"id": 9, "kind": kind, "hub_id": "1"}})}
    assert item_card(7, item) == (f"/projects/7/{section}/9" if section else "")


def test_b21_type_collision_page_has_no_wrong_card(web, monkeypatch):
    pid = project(web, [sast("1")])
    assert confirm(web, pid, monkeypatch, app_confirmed=True).status_code == 200  # коллизия типа: общих нет (dev13)
    db = web.app.state.db
    rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
    hub = FakeSyncHub(1)
    hub.issues[0]["type"] = "SCA_S"
    finish(db, hub, rid)
    item = db._one("SELECT * FROM hub_sync_items WHERE run_id=? AND entity_key='SCA_S:1'", (rid,))
    assert "unmapped" in loads(item["diff_json"], {})["groups"]
    page = web.client.get(f"/projects/{pid}/hub-sync/{rid}")
    assert page.status_code == 200
    fragment = re.search(r"<summary>Находка SCA_S:1</summary>(.*?)<details[^>]*>", page.text, re.S)[1]
    assert 'href=' not in fragment
    assert "Сопоставленной карточки нет." in fragment
    assert "проверить и сохранить локальное решение" not in fragment


def stopped_run(web, monkeypatch):
    pid = project(web, [sast("1")])
    assert confirm(web, pid, monkeypatch).status_code == 200
    db = web.app.state.db
    rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
    hub = FakeSyncHub(1)
    step(db, hub)
    step(db, hub)
    assert sync.passport(run(db, rid))["inventory_complete"]
    url = f"/projects/{pid}/hub-sync/{rid}"
    assert web.client.post(url + "/stop", headers=ORIGIN).status_code == 200
    assert 'id="hub-sync-continue"' in web.client.get(url).text
    preview = web.client.post(url + "/continue-preview", headers=ORIGIN)
    assert preview.status_code == 200 and 'id="hub-sync-confirm"' in preview.text
    return db, pid, rid, url, token(preview)


def test_b22_new_read_closes_stopped_run_like_close_and_preserves_history(web, monkeypatch):
    db, pid, rid, url, old_token = stopped_run(web, monkeypatch)
    old = run(db, rid)
    items = db._all("SELECT * FROM hub_sync_items WHERE run_id=?", (rid,))
    assert confirm(web, pid, monkeypatch).status_code == 200
    closed = run(db, rid)
    assert closed["closed_at"] and closed["state"] == "closed"
    assert closed["run_json"] == old["run_json"]
    assert db._all("SELECT * FROM hub_sync_items WHERE run_id=?", (rid,)) == items
    assert db._one("SELECT id FROM hub_defect_sync_runs WHERE closed_at IS NULL")["id"] != rid
    before = db._all("SELECT * FROM hub_ops ORDER BY id")
    page = web.client.get(url)
    assert page.status_code == 200 and "Запуск закрыт" in page.text
    assert 'id="hub-sync-continue"' not in page.text
    preview = web.client.post(url + "/continue-preview", headers=ORIGIN)
    assert preview.status_code == 409 and "Запуск закрыт" in preview.text
    assert 'id="hub-sync-confirm"' not in preview.text
    assert web.client.post(url + "/continue", headers=ORIGIN,
                           data={"confirm": "yes", "confirmation": old_token}).status_code == 409
    assert db._all("SELECT * FROM hub_ops ORDER BY id") == before


@pytest.mark.parametrize("state", ["closed", "stopped", "ready"])
@pytest.mark.parametrize("surface", ["page", "preview"])
def test_b22_closed_run_never_offers_continue_even_with_legacy_state(web, monkeypatch, state, surface):
    db, _, rid, url, _ = stopped_run(web, monkeypatch)
    sync.close(db, rid)
    with db._tx() as c:
        # Старые автоматически закрытые строки сохраняли прежнее состояние.
        c.execute("UPDATE hub_defect_sync_runs SET state=? WHERE id=?", (state, rid))
        c.execute("UPDATE hub_sync_items SET coverage_json=? WHERE run_id=?",
                  (dumps({"exceptions": {"detail": "Ответ не получен"}}), rid))
    before = db._all("SELECT * FROM hub_ops ORDER BY id")
    if surface == "page":
        response = web.client.get(url)
        assert response.status_code == 200
        assert 'id="hub-sync-continue"' not in response.text
        assert "повтор исключений требует подтверждения продолжения" not in response.text
        assert "/recompare" not in response.text
    else:
        response = web.client.post(url + "/continue-preview", headers=ORIGIN)
        assert response.status_code == 409 and "Запуск закрыт" in response.text
        assert 'id="hub-sync-confirm"' not in response.text
    assert db._all("SELECT * FROM hub_ops ORDER BY id") == before


def test_continue_preview_lists_requests_in_number_order_after_rows_move(web, monkeypatch):
    """Итоговая проверка 0.10.0: список оставшихся запросов – в порядке их номеров, как их и продолжит синхронизация;
    PostgreSQL после UPDATE строки отдаёт её в другом месте, и без ORDER BY страница показывала бы другой порядок."""
    db, _, rid, url, _ = stopped_run(web, monkeypatch)
    generation = run(db, rid)["generation"]
    with db._tx() as c:
        ids = [c.execute("INSERT INTO hub_sync_requests(run_id, generation, request_key, entity_kind, entity_key, state,"
                         " request_json) VALUES (?, ?, ?, 'issue', ?, 'planned', ?) RETURNING id",
                         (rid, generation, f"порядок-{n}", f"SAST:{n}", dumps({"path": f"/порядок/{n}"}))).fetchone()[0]
               for n in (901, 902, 903)]

    def shown() -> list[str]:
        page = web.client.post(url + "/continue-preview", headers=ORIGIN)
        assert page.status_code == 200
        return re.findall(r"<code>GET (/порядок/\d+)</code>", page.text)
    assert shown() == ["/порядок/901", "/порядок/902", "/порядок/903"]
    with db._tx() as c:  # значения прежние, место первой строки новое; статистика – как у базы в эксплуатации
        c.execute("UPDATE hub_sync_requests SET id = id WHERE id = ?", (ids[0],))
        c.execute("ANALYZE hub_sync_requests")
    assert [r["id"] for r in db._all("SELECT id FROM hub_sync_requests WHERE id >= ?", (ids[0],))][-1] == ids[0]
    assert shown() == ["/порядок/901", "/порядок/902", "/порядок/903"]

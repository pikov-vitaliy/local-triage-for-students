"""Бэклог 97: страница чтения Hub называет общую причину неполных сведений – по части чтения и коду ответа Hub, число –
уникальные объекты; новых запросов к Hub нет. Данные выдуманы."""

from __future__ import annotations

from app.db import dumps
from app.routes.hub_sync_routes import incomplete_causes
from test_hub_sync import HUB
from test_hub_sync_dev2 import OLD_ADAPTER, deliver_text, waiting_manual
from test_web import web  # noqa: F401


def test_causes_group_by_part_and_status(web):  # noqa: F811
    db = web.app.state.db
    pid = db.create_project("Демо причин")
    db.update_project(pid, hub_app_id=7)
    rid = waiting_manual((db, pid), OLD_ADAPTER)
    deliver_text(db, "")  # одна неполная ручная запись – прежнее исключение
    with db._tx() as c:
        def op(status: int) -> int:
            return c.execute("INSERT INTO hub_ops(project_id, hub_url, app_id, purpose, state, request_json, targets_json, op_key,"
                             " result_json, created_at, updated_at) VALUES (?, ?, 7, 'read', 'done', '{}', '[]', ?, ?,"
                             " '2026-11-08', '2026-11-08') RETURNING id",
                             (pid, HUB, f"cause-{status}-{c.execute('SELECT COUNT(*) FROM hub_ops').fetchone()[0]}",
                              dumps({"status": status, "body_text": "Internal Server Error"}))).fetchone()[0]
        first, second, other, ok = op(500), op(500), op(404), op(200)
        for n in range(40):  # 40 находок: ошибка 500 в двух разных операциях – одна причина
            exceptions = {"risk": {"op_id": first if n % 2 else second, "reason": "HTTP 500"}}
            if n < 3:  # у трёх – ещё и вторая часть: объект считается в каждой своей причине один раз
                exceptions["detail"] = {"op_id": other, "reason": "HTTP 404"}
            if n < 2:  # у двух – ответ 200 не сохранён: это не отказ Hub (ревью Codex dev18, группа 3)
                exceptions["manual"] = {"op_id": ok, "reason": "Сырой ответ не сохранён.", "missing_raw": True}
            if n == 0:  # ответ 200 не разобран
                exceptions["branch:main"] = {"op_id": ok, "reason": "У ветки отсутствует имя."}
            c.execute("INSERT INTO hub_sync_items(run_id, entity_kind, entity_key, coverage_json) VALUES (?, 'issue', ?, ?)",
                      (rid, f"SCA_S:{7000 + n}", dumps({"exceptions": exceptions})))
        c.execute("INSERT INTO hub_sync_items(run_id, entity_kind, entity_key, coverage_json) VALUES (?, 'defect', '9001', ?)",
                  (rid, dumps({"exceptions": {"detail": {"op_id": first, "reason": "HTTP 500"}}})))
    before = db._all("SELECT id FROM hub_ops ORDER BY id")
    causes = incomplete_causes(db, rid)
    texts = [c["text"] for c in causes]
    assert texts[0] == "у 40 находок Hub ответил ошибкой 500 на чтение принятия риска («risk»)"
    assert "у 3 находок Hub ответил ошибкой 404 на чтение карточки находки («detail»)" in texts
    assert ("у 2 находок ответ Hub на чтение статуса находки («manual») не сохранён в приложении: Сырой ответ не "
            "сохранён.") in texts
    assert ("у 1 находки не удалось прочитать или обработать ветки «main» (ответ Hub 200): У ветки отсутствует "
            "имя.") in texts
    assert any(t.endswith("Hub ответил ошибкой 500 на чтение карточки дефекта («detail»)") for t in texts), texts
    assert not any("Hub не отдал" in t or ("ошибкой" in t and "200" in t) for t in texts)
    assert db._all("SELECT id FROM hub_ops ORDER BY id") == before, "новых операций нет"
    page = web.client.get(f"/projects/{pid}/hub-sync/{rid}").text
    if 'id="hub-sync-incomplete"' in page:
        assert 'id="hub-sync-causes"' in page and "у 40 находок Hub ответил ошибкой 500" in page

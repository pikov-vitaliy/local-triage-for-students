"""Неизвестный ответ шаблона сохраняется как транспортное свидетельство, не как блок Hub."""
import json

import pytest

from app import hub_ops, hub_template_model
from test_hub_defect_import import HUB, AS_JSON, imported, project, take, deliver, web  # noqa: F401
from test_hub_defect_update import deliver_raw
from test_hub_worker import FakeHub, FakeApp, Server, hw, PASSWORD, conf_for, job


def url(pid, row):
    return f"/projects/{pid}/hub/defects/{row['id']}/template-model"


@pytest.mark.parametrize("status,raw,truncated", [
    (200, ' {"synthetic_unknown": ["значение", null]} \n', False),
    (400, 'ошибка поддельного Hub', False),
    (200, '{"обрыв":', True),
])
def test_saved_raw_response_does_not_change_defect_or_enqueue_writes(web, status, raw, truncated):  # noqa: F811
    pid = project(web)
    row = imported(web, pid)
    db = web.app.state.db
    before = db.hub_defect(row["id"])
    base = url(pid, row)
    queued = web.client.post(base, headers=AS_JSON, data={"issue_id": "510001", "confirm": "1"})
    assert queued.status_code == 200, queued.text
    op_id = queued.json()["op_id"]
    work = take(web)
    assert work["method"] == "GET" and work["purpose"] == "read"
    assert work["path"] == "/templates/defects/model?issueType=SAST&issueId=510001&appId=7"
    assert work.get("body") is None
    hw.check_job(work, HUB)
    deliver_raw(web, work, status=status, text=raw, truncated=truncated)
    # Повторная доставка и опрос не создают новую операцию и не меняют дефект.
    deliver_raw(web, work, status=status, text=raw, truncated=truncated)
    for _ in range(2):
        response = web.client.get(f"{base}/{op_id}")
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["result"]["body_text"] == raw
        assert result["result"]["truncated"] == truncated
        assert "не собран" in result["note"]
    assert db.hub_defect(row["id"]) == before
    assert take(web) is None


def test_confirmation_membership_and_target_are_required(web):  # noqa: F811
    pid = project(web)
    row = imported(web, pid)
    base = url(pid, row)
    assert web.client.post(base, headers=AS_JSON, data={"issue_id": "510001"}).status_code == 400
    for invalid in ("999999", "-1", "", "1,2"):
        assert web.client.post(base, headers=AS_JSON,
                               data={"issue_id": invalid, "confirm": "1"}).status_code == 409
    with web.app.state.db._tx() as c:
        c.execute("UPDATE projects SET hub_app_id = 99 WHERE id = ?", (pid,))
    assert web.client.post(base, headers=AS_JSON,
                           data={"issue_id": "510001", "confirm": "1"}).status_code == 409
    assert take(web) is None


def test_old_worker_refusal_names_new_get_and_does_not_retry(web):  # noqa: F811
    pid = project(web)
    row = imported(web, pid)
    base = url(pid, row)
    queued = web.client.post(base, headers=AS_JSON, data={"issue_id": "510001", "confirm": "1"})
    assert queued.status_code == 200
    work = take(web)
    deliver_raw(web, work, status=0, not_sent=True,
                error="задание отклонено: GET /templates/defects/model не входит в белый список")
    got = web.client.get(f"{base}/{queued.json()['op_id']}").json()
    assert got["note"] == hub_template_model.OLD_WORKER
    assert "PUT" not in got["note"] and take(web) is None


def test_changed_composition_rolls_back_enqueue(web, monkeypatch):  # noqa: F811
    pid = project(web)
    row = imported(web, pid)
    db = web.app.state.db
    original = db.hub_enqueue
    def changed(**kwargs):
        with db._tx() as c:
            c.execute("UPDATE hub_defects SET targets_json = '[]' WHERE id = ?", (row["id"],))
        return original(**kwargs)
    monkeypatch.setattr(db, "hub_enqueue", changed)
    response = web.client.post(url(pid, row), headers=AS_JSON, data={"issue_id": "510001", "confirm": "1"})
    assert response.status_code == 409 and "Состав" in response.text
    assert take(web) is None


@pytest.mark.parametrize("method,path", [
    ("POST", "/templates/defects/model?issueType=SAST&issueId=1&appId=7"),
    ("PUT", "/templates/defects/model?issueType=SAST&issueId=1&appId=7"),
    ("GET", "/templates/defects/model?issueId=1&issueId=2"),
    ("GET", "/templates/defects/model?issueId=1&format=html"),
])
def test_new_path_is_read_only_and_exact(method, path):
    with pytest.raises(ValueError):
        hub_ops.check_request(method, path)
    with pytest.raises(hw.Refused):
        hw.check_job({"hub_url": HUB, "method": method, "path": path}, HUB)


def test_worker_delivers_unknown_model_from_fake_hub(monkeypatch):
    raw = b' {"synthetic_unknown":[1,null]} \n'
    class TemplateHub(FakeHub):
        def do_GET(self):
            if self.path.startswith("/hub/rest/templates/defects/model?"):
                self.server.owner.calls.append(("GET", self.path, None))
                return self._reply(200, raw)
            return super().do_GET()
    monkeypatch.setattr(hw, "HUB_SCHEMES", ("http", "https"))
    hub, app = Server(TemplateHub), Server(FakeApp)
    hub.calls, hub.expire_session = [], False
    app.jobs, app.hello, app.results, app.headers, app.fail_results = [], [], [], [], 0
    app.truncate_errors = False
    app.jobs = [{**job(hub, 1, "GET", "/templates/defects/model?issueType=SAST&issueId=1&appId=7"),
                 "purpose": "read", "app_id": 7}]
    try:
        assert hw.work(conf_for(hub, app), ask_password=lambda _: PASSWORD, sleep=lambda _: None, max_jobs=1) == 0
        assert app.results[0][1]["body_text"] == raw.decode()
        assert len([c for c in hub.calls if c[1].startswith("/hub/rest/templates/")]) == 1
        assert all(c[0] == "GET" or "/auth/" in c[1] for c in hub.calls)
    finally:
        hub.close()
        app.close()


def test_request_uses_target_type_and_rejects_ambiguous_type():
    row = {"app_id": 7, "targets_json": json.dumps([{"issue_id": 1, "issue_type": "SCA_S"}])}
    assert "issueType=SCA_S" in hub_template_model.request_for(row, "1")["path"]
    row["targets_json"] = json.dumps([{"issue_id": 1, "issue_type": "SCA_S"},
                                      {"issue_id": 1, "issue_type": "SAST"}])
    with pytest.raises(ValueError):
        hub_template_model.request_for(row, "1")

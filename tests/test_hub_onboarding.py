"""Шаг «Состояние Hub» в начале проекта и номер приложения ссылкой (0.10.0.dev13). Без реальных
данных: синтетический Hub, номер приложения 7."""

import pytest

from app import hub_onboarding, hub_pull, hub_sync as sync
from app.routes.projects import hub_app_number
from test_hub_defect_import import APP_ID, project
from test_hub_sync import ADAPTER, HUB, FakeSyncHub, finish
from test_web import ORIGIN, prepared, web  # noqa: F401


@pytest.mark.parametrize("raw, number", [
    ("952", 952),
    (" 952 ", 952),
    ("https://hub.example.org/#/appprofile/952/issues/SAST/9000001", 952),
    ("https://hub.example.org/#/appprofile/952", 952),
    ("https://hub.example.org/#/appprofile/952?tab=defects", 952),
    ("", None),
    ("0", None),
    ("952a", None),
    ("https://hub.example.org/#/defects/90022", None),
    ("https://hub.example.org/#/appprofile/x/issues", None),
    ("https://hub/appprofile/5", 5),
    ("мусор /appprofile/7/issues", None),
    ("https://hub.example.org/#/appprofile/7/issues и ещё текст", None),
    ("/appprofile/7", None),
    ("https://#/appprofile/7", None),
    ("https://hub.example.org:8443/#/appprofile/7", 7),
])
def test_app_number_from_number_or_link(raw, number):
    assert hub_app_number(raw) == number


def test_link_is_saved_as_number(web):
    pid = prepared(web)
    r = web.client.post(f"/projects/{pid}/params", headers=ORIGIN, follow_redirects=False,
                        data={"name": "Демо", "model": "", "hub_app_id": "https://hub.example.org/#/appprofile/31/issues"})
    assert r.status_code in (302, 303), r.text
    assert web.app.state.db.get_project(pid)["hub_app_id"] == 31
    bad = web.client.post(f"/projects/{pid}/params", headers=ORIGIN, data={"name": "Демо", "model": "", "hub_app_id": "не номер"})
    assert bad.status_code == 400 and "вставьте эту ссылку целиком" in bad.text
    assert web.app.state.db.get_project(pid)["hub_app_id"] == 31


def matching_hub(db, pid, issues=6, defects=1):
    """Синтетический Hub, у которого первая находка совпадает с находкой выгрузки проекта."""
    hub = FakeSyncHub(issues, defects)
    local = db._one("SELECT hub_id,kind FROM findings WHERE project_id=? AND kind='SAST' ORDER BY id LIMIT 1", (pid,))
    hub.issues[0].update(id=int(local["hub_id"]), type="SAST")
    return hub


def read(db, pid, hub, **kw):
    rid = sync.start(db, pid, HUB, APP_ID, adapter=ADAPTER, **kw)
    finish(db, hub, rid)
    return rid


def step(web, pid):
    return web.client.get(f"/projects/{pid}").text


def test_states_from_no_number_to_accepted_and_reminder(web):
    db = web.app.state.db
    pid = prepared(web)
    page = step(web, pid)
    assert 'id="step-hub"' in page and "Приложение в Hub не указано" in page and 'id="step-hub-sync"' not in page
    assert 'id="hub-step-note"' not in web.client.get(f"/projects/{pid}/defects").text, "без номера не напоминает"
    pid = project(web)
    page = step(web, pid)
    assert "Состояние Hub ещё не принималось" in page and 'id="step-hub-sync"' in page
    assert 'id="hub-step-note"' in web.client.get(f"/projects/{pid}/defects").text
    assert 'id="hub-step-note"' in web.client.get(f"/projects/{pid}/findings").text
    rid = read(db, pid, matching_hub(db, pid))
    state = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert state["state"] == "ready" and state["pull"]["count"] > 0, state
    assert "Прочитано – ждёт принятия" in step(web, pid) and 'id="step-hub-matched"' in step(web, pid)
    row = db._one("SELECT * FROM hub_defect_sync_runs WHERE id=?", (rid,))
    hub_pull.apply(db, rid, hub_pull.preview(db, row)["token"])
    state = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert state["state"] in ("accepted", "partial"), state
    if state["state"] == "accepted":
        assert 'id="hub-step-note"' not in web.client.get(f"/projects/{pid}/defects").text


def test_mismatch_state_and_history_of_previous_number(web):
    db = web.app.state.db
    pid = project(web)
    read(db, pid, FakeSyncHub(5, 0))  # общих с выгрузкой нет
    state = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert state["state"] == "app_mismatch", state
    page = step(web, pid)
    assert "Номер приложения не совпал с выгрузкой" in page and "общих 0 из" in page
    db.update_project(pid, hub_app_id=APP_ID + 1)
    state = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert state["state"] == "not_read" and state["history"]["app_id"] == APP_ID
    assert 'id="step-hub-history"' in step(web, pid)


def test_confirmed_number_is_shown_as_confirmed_not_as_checked(web):
    db = web.app.state.db
    pid = project(web)
    read(db, pid, FakeSyncHub(5, 0), app_confirmed=True)
    state = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert state["state"] != "app_mismatch", state
    page = step(web, pid)
    assert 'id="step-hub-confirmed"' in page and 'id="step-hub-matched"' not in page


def test_step_shows_name_difference_and_tabs_use_light_state(web, monkeypatch):
    db = web.app.state.db
    pid = project(web)
    hub = matching_hub(db, pid)
    for issue in hub.issues:
        issue["appName"] = "Чужое имя"
    read(db, pid, hub)
    page = step(web, pid)
    assert 'id="step-hub-names"' in page and "Чужое имя" in page
    calls = []
    monkeypatch.setattr(hub_pull, "preview", lambda *a, **k: calls.append(a) or {})
    assert 'id="hub-step-note"' in web.client.get(f"/projects/{pid}/defects").text
    assert 'id="hub-step-note"' in web.client.get(f"/projects/{pid}/findings").text
    assert not calls, "напоминание на вкладках не перебирает объекты прогона"
    assert hub_onboarding.state(db, db.get_project(pid), HUB, light=True)["state"] == "unapplied"


def test_matching_empty_hub_is_done_on_tabs_too(web):
    """Пустой проект и пустой Hub: сравнение совпадает, принимать нечего – шаг выполнен и на вкладках напоминания нет
    (ревью dev13, круг 2)."""
    db = web.app.state.db
    pid = db.create_project("Пустой")
    db.update_project(pid, hub_app_id=APP_ID)
    from test_hub_defects import hub_settings
    hub_settings(web, pid)
    read(db, pid, FakeSyncHub(0, 0))
    assert hub_onboarding.state(db, db.get_project(pid), HUB)["state"] == "matches"
    assert hub_onboarding.state(db, db.get_project(pid), HUB, light=True)["state"] == "matches"
    assert 'id="hub-step-note"' not in web.client.get(f"/projects/{pid}/defects").text


def test_closing_a_matching_run_keeps_matches(web):
    """Совпадение → «Закрыть запуск» → по-прежнему «Совпадает с Hub»; закрытый без совпадения – «остановлено»
    (ревью dev13, круг 4)."""
    db = web.app.state.db
    pid = db.create_project("Пустой")
    db.update_project(pid, hub_app_id=APP_ID)
    from test_hub_defects import hub_settings
    hub_settings(web, pid)
    rid = read(db, pid, FakeSyncHub(0, 0))
    sync.close(db, rid)
    for light in (False, True):
        assert hub_onboarding.state(db, db.get_project(pid), HUB, light=light)["state"] == "matches"
    assert 'id="hub-step-note"' not in web.client.get(f"/projects/{pid}/defects").text
    other = project(web)
    rid = read(db, other, matching_hub(db, other))
    sync.close(db, rid)
    assert hub_onboarding.state(db, db.get_project(other), HUB)["state"] == "stopped"

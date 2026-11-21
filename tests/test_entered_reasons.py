"""Причина «Текст для Hub изменился» (О8): отметка «Внесено в Hub» помнит, из чего собран текст SAST (текст решения,
рекомендация, название команды, статусы Hub, версия приложения); карточка называет изменившееся. Отметки до 0.9.9 –
честное «неизвестно». Данные выдуманы."""

from __future__ import annotations

import json
from types import SimpleNamespace

from app.routes import findings as routes
from test_defect import save_sast
from test_web import ORIGIN, prepared, shown_hash, start_run, wait_run, web  # noqa: F401

JSON = {**ORIGIN, "Accept": "application/json"}
REASON = "Подтверждено: owner из запроса попадает в SQL без параметров."


def marked(web) -> tuple[int, str]:  # noqa: F811
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    url, _ = save_sast(web, pid, "510001", "disagree", "true_positive", REASON)
    revision = str(db.get_review(pid, "510001")["revision"])
    r = web.client.post(url + "/entered", headers=JSON, data={"entered": "1", "review_revision": revision,
                                                              "text_hash": shown_hash(web.client, url)})
    assert r.status_code == 200 and r.json()["entered"] is True, r.text
    assert json.loads(db.get_review(pid, "510001")["entered_parts"])["team"]
    return pid, url


def test_team_name_change_is_named(web):  # noqa: F811
    pid, url = marked(web)
    assert 'id="entered-changed"' not in web.client.get(url).text
    web.app.state.db.set_settings({"team_name": "Другая команда"})
    card = web.client.get(url).text
    assert 'id="entered-changed"' in card and "Изменилось: название команды в настройках." in card


def test_mark_before_0_9_9_says_unknown(web):  # noqa: F811
    pid, url = marked(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE reviews SET entered_parts = '' WHERE project_id = ? AND hub_id = '510001'", (pid,))
    db.set_settings({"team_name": "Другая команда"})
    card = web.client.get(url).text
    assert "Отметка поставлена до версии 0.9.9" in card and "неизвестно" in card
    assert "статусы Hub" not in card.split('id="entered-changed"')[1].split("</div>")[0]


def test_unmark_clears_the_parts(web):  # noqa: F811
    pid, url = marked(web)
    db = web.app.state.db
    revision = str(db.get_review(pid, "510001")["revision"])
    r = web.client.post(url + "/entered", headers=JSON, data={"entered": "0", "review_revision": revision})
    assert r.status_code == 200, r.text
    assert db.get_review(pid, "510001")["entered_parts"] == ""


def test_reasons_function(monkeypatch):
    settings = SimpleNamespace(team_name="Платформа", hub_status_map={"true_positive": "Подтверждено"})
    review = {"final_comment": "А", "final_fix": "Б"}
    review["entered_parts"] = routes.entered_parts(settings, review)
    assert routes.entered_change_reasons(settings, review) == []
    assert routes.entered_change_reasons(settings, {**review, "entered_parts": ""}) is None
    assert routes.entered_change_reasons(settings, {**review, "entered_parts": "[1]"}) is None
    statuses = SimpleNamespace(team_name="Платформа", hub_status_map={"true_positive": "Исправить"})
    assert routes.entered_change_reasons(statuses, review) == [], "статусы Hub в текст SAST не входят"
    team = SimpleNamespace(team_name="Другая", hub_status_map={})
    tp = {"decision": "disagree", "final_verdict": "true_positive", "final_comment": "А", "final_fix": "Б"}
    tp["entered_parts"] = routes.entered_parts(settings, tp)
    assert routes.entered_change_reasons(team, tp) == ["название команды в настройках"]
    fp = {"decision": "disagree", "final_verdict": "false_positive", "final_comment": "А"}
    fp["entered_parts"] = routes.entered_parts(settings, fp)
    assert routes.entered_change_reasons(team, fp) == [], "в комментарии ложного срабатывания команды нет"
    monkeypatch.setattr(routes, "__version__", "9.9.9")
    reasons = routes.entered_change_reasons(settings, review)
    assert len(reasons) == 1 and "формат текста в версии приложения 9.9.9" in reasons[0]


def test_hash_and_parts_use_one_settings_snapshot(web, monkeypatch):  # noqa: F811
    """Настройки сменили в другой вкладке между построением текста и составляющих: оба – по одному снимку."""
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    url, _ = save_sast(web, pid, "510001", "disagree", "true_positive", REASON)
    revision = str(db.get_review(pid, "510001")["revision"])
    shown = shown_hash(web.client, url)
    real = routes.settings_of
    calls = []

    def flipping(request):
        calls.append(1)
        current = real(request)
        if len(calls) > 1:  # второе чтение увидело бы новую команду
            return SimpleNamespace(**{**vars(current), "team_name": "Другая команда"})
        return current

    monkeypatch.setattr(routes, "settings_of", flipping)
    r = web.client.post(url + "/entered", headers=JSON, data={"entered": "1", "review_revision": revision,
                                                              "text_hash": shown})
    monkeypatch.setattr(routes, "settings_of", real)
    assert r.status_code == 200, r.text
    parts = json.loads(db.get_review(pid, "510001")["entered_parts"])
    assert parts["team"] == routes.text_hash("Платформа")

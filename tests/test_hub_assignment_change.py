"""Смена назначения Hub (план dev17, п. 4.5; ревью шага 4): одна транзакция – новое назначение, решения из Hub прежнего
назначения в архив и сняты, сведения о библиотеках сброшены, переход к идентичности файла; подтверждение с итогом и
отпечатком; устаревший отпечаток – отказ; сбой – откат целиком. Данные выдуманы."""

from __future__ import annotations

import pytest

from app import package_transition
from test_hub_status_routes import project, sast, sca
from test_web import ORIGIN, web  # noqa: F401


def _hub_decision(db, pid, hub_id):
    with db._tx() as c:
        c.execute("INSERT INTO reviews(project_id, hub_id, updated_at) VALUES (?, ?, '2026-11-01T00:00:00+00:00')"
                  " ON CONFLICT(project_id, hub_id) DO NOTHING", (pid, hub_id))
        c.execute("UPDATE reviews SET decision = 'hub', final_verdict = 'false_positive', final_comment = 'Из Hub.',"
                  " decision_origin = 'hub_sync', reviewed = 1 WHERE project_id = ? AND hub_id = ?", (pid, hub_id))


def _hub_identity(db, pid, hub_id):
    with db._tx() as c:
        c.execute("UPDATE findings SET pkg_ecosystem = 'maven', pkg_name = 'org.example:lib', pkg_source = 'hub',"
                  " pkg_note = '', pkg_scope = 'https://hub.example.org|7' WHERE project_id = ? AND hub_id = ?",
                  (pid, hub_id))


def test_change_without_effects_is_applied_at_once(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("101")])
    r = web.client.post(f"/projects/{pid}/params", headers=ORIGIN, data={"name": "p", "hub_app_id": "8"},
                        follow_redirects=False)
    assert r.status_code in (302, 303) and "hub-assignment" not in r.headers["location"]
    assert db.get_project(pid)["hub_app_id"] == 8


def test_change_with_hub_decisions_asks_and_withdraws_them(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("101"), sca("73001")])
    _hub_decision(db, pid, "101")
    _hub_identity(db, pid, "73001")
    r = web.client.post(f"/projects/{pid}/params", headers=ORIGIN, data={"name": "p", "hub_app_id": "8"},
                        follow_redirects=False)
    assert r.status_code in (302, 303) and r.headers["location"].endswith(f"/projects/{pid}/hub-assignment?app=8")
    assert db.get_project(pid)["hub_app_id"] == 7, "до подтверждения назначение прежнее"
    page = web.client.get(f"/projects/{pid}/hub-assignment?app=8")
    assert page.status_code == 200 and 'id="hub-assignment-summary"' in page.text
    token = db.change_hub_assignment(pid, 8, dry=True)["token"]
    assert db.get_project(pid)["hub_app_id"] == 7, "предпросмотр ничего не пишет"
    r = web.client.post(f"/projects/{pid}/hub-assignment", headers=ORIGIN, data={"app": "8", "token": token},
                        follow_redirects=False)
    assert r.status_code in (302, 303)
    assert db.get_project(pid)["hub_app_id"] == 8
    review = db.get_review(pid, "101")
    assert review["decision"] == "" and review["decision_origin"] == "" and not review["reviewed"]
    archived = db._all("SELECT source_table, reason FROM sca_identity_archive WHERE project_id = ?", (pid,))
    assert any(a["source_table"] == "reviews" and "прежнего назначения" in a["reason"] for a in archived)
    finding = db.get_finding_by_hub_id(pid, "73001")
    row = db._one("SELECT pkg_source FROM findings WHERE id = ?", (finding["id"],))
    assert row["pkg_source"] == "", "сведения Hub о библиотеке прежнего назначения сброшены"


def test_stale_token_is_refused_and_nothing_changes(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("101")])
    _hub_decision(db, pid, "101")
    token = db.change_hub_assignment(pid, 8, dry=True)["token"]
    with db._tx() as c:  # после предпросмотра решение поменялось в другой вкладке
        c.execute("UPDATE reviews SET final_comment = 'Другое.' WHERE project_id = ? AND hub_id = '101'", (pid,))
    with pytest.raises(ValueError, match="Итог изменился"):
        db.change_hub_assignment(pid, 8, expect=token)
    assert db.get_project(pid)["hub_app_id"] == 7 and db.get_review(pid, "101")["decision_origin"] == "hub_sync"


def test_failure_rolls_back_the_whole_change(web, monkeypatch):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("101"), sca("73001")])
    _hub_decision(db, pid, "101")
    _hub_identity(db, pid, "73001")

    def broken(*args, **kwargs):
        raise RuntimeError("сбой перехода")

    monkeypatch.setattr(package_transition, "rebind_packages", broken)
    with pytest.raises(RuntimeError):
        db.change_hub_assignment(pid, 8)
    assert db.get_project(pid)["hub_app_id"] == 7
    assert db.get_review(pid, "101")["decision_origin"] == "hub_sync"
    row = db._one("SELECT pkg_source FROM findings WHERE project_id = ? AND hub_id = '73001'", (pid,))
    assert row["pkg_source"] == "hub"


def test_hub_url_change_applies_to_every_project(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("101")])
    _hub_decision(db, pid, "101")
    result = db.change_hub_url("https://hub2.example.org", dry=True)
    assert result["affects"] and result["projects"][pid]["hub_decisions_withdrawn"] == 1
    assert db.get_review(pid, "101")["decision_origin"] == "hub_sync", "предпросмотр ничего не пишет"
    db.change_hub_url("https://hub2.example.org", expect=result["token"])
    assert db.get_review(pid, "101")["decision_origin"] == ""


def _settings_form(web, **changes) -> dict:
    from app.settings_store import form_values
    values = form_values(web.app.state.web.base.with_stored(web.app.state.db.get_settings()))
    return {**values, "action": "save", **changes}


def test_hub_url_change_in_settings_asks_then_applies(web):  # noqa: F811
    """«Настройки»: смена адреса Hub при решениях из Hub – остальные настройки сохраняются сразу, адрес – только по
    подтверждению с итогом по проектам; устаревший отпечаток – отказ и новый итог."""
    db = web.app.state.db
    pid = project(web, [sast("101")])
    _hub_decision(db, pid, "101")
    r = web.client.post("/settings", headers={**ORIGIN, "Accept": "text/html"}, follow_redirects=False,
                        data=_settings_form(web, hub_url="https://hub2.example.org", team_name="Команда Б"))
    assert r.status_code == 200 and 'id="hub-url-summary"' in r.text and 'id="hub-url-apply"' in r.text
    assert db.get_settings().get("team_name") == "Команда Б", "остальные настройки сохранены"
    assert db.get_settings().get("hub_url") != "https://hub2.example.org", "адрес – только по подтверждению"
    assert db.get_review(pid, "101")["decision_origin"] == "hub_sync"
    stale = web.client.post("/settings/hub-url", headers=ORIGIN, data={"url": "https://hub2.example.org",
                                                                       "token": "0" * 32}, follow_redirects=False)
    assert stale.status_code == 409 and 'id="hub-url-error"' in stale.text
    token = db.change_hub_url("https://hub2.example.org", dry=True)["token"]
    ok = web.client.post("/settings/hub-url", headers=ORIGIN, data={"url": "https://hub2.example.org",
                                                                    "token": token}, follow_redirects=False)
    assert ok.status_code in (302, 303)
    assert db.get_settings().get("hub_url") == "https://hub2.example.org"
    assert db.get_review(pid, "101")["decision_origin"] == ""


def test_hub_url_change_without_effects_is_saved_at_once(web):  # noqa: F811
    db = web.app.state.db
    project(web, [sast("101")])
    r = web.client.post("/settings", headers={**ORIGIN, "Accept": "text/html"}, follow_redirects=False,
                        data=_settings_form(web, hub_url="https://hub3.example.org"))
    assert r.status_code in (302, 303), r.text[:300]
    assert db.get_settings().get("hub_url") == "https://hub3.example.org"


# ------------------------------------------------------------------ ревью Codex шага 4, круг 2


def _hub_lib(db, pid, hub_id, name="lib"):
    """Сведения Hub о библиотеке без группы: эффективная тройка – maven / name, у файла – группа есть."""
    with db._tx() as c:
        c.execute("UPDATE findings SET pkg_ecosystem = 'maven', pkg_name = ?, pkg_source = 'hub', pkg_note = '',"
                  " pkg_scope = 'https://hub.example.org|7' WHERE project_id = ? AND hub_id = ?", (name, pid, hub_id))


def test_assignment_change_uses_change_rules(web):  # noqa: F811
    """D1: возврат к тройке файла при смене назначения – изменение, не уточнение: подпись решения оператора не
    переписывается (решение принято по другой версии находки)."""
    from test_package_transition import made
    db, pid = made(web, ("73001", "org.example:lib", "maven"))
    _hub_lib(db, pid, "73001")
    db.save_review(pid, "73001", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True)
    sig = db.get_review(pid, "73001")["finding_sig"]
    summary = db.change_hub_assignment(pid, 8)["summary"]
    assert summary["change"] == 1 and summary["refine"] == 0
    assert db.get_review(pid, "73001")["finding_sig"] == sig, "подпись оператора не переписана"


def test_same_assignment_changes_nothing(web):  # noqa: F811
    """D4: назначение уже такое – перехода нет, решения и сведения Hub действующего назначения не трогаются."""
    db = web.app.state.db
    pid = project(web, [sast("101"), sca("73001")])
    _hub_decision(db, pid, "101")
    _hub_identity(db, pid, "73001")
    assert db.change_hub_assignment(pid, 7).get("unchanged")
    assert db.change_hub_url("https://hub.example.org").get("unchanged")
    assert db.get_review(pid, "101")["decision_origin"] == "hub_sync"
    assert db._one("SELECT pkg_source FROM findings WHERE project_id = ? AND hub_id = '73001'", (pid,))["pkg_source"] == "hub"
    assert db._all("SELECT 1 FROM sca_identity_archive WHERE project_id = ?", (pid,)) == []
    page = web.client.get(f"/projects/{pid}/hub-assignment?app=7", follow_redirects=False)
    assert page.status_code in (302, 303), "подтверждать нечего"


def test_change_between_preview_and_write_asks_for_confirmation(web, monkeypatch):  # noqa: F811
    """D3: без последствий по расчёту, но до записи появилось решение из Hub – смена не пишется молча, нужна
    страница подтверждения."""
    db = web.app.state.db
    pid = project(web, [sast("101")])
    real = db.change_hub_assignment
    calls = []

    def racing(project_id, hub_app_id, **kwargs):
        calls.append(kwargs)  # до вызова: запись с отпечатком отказывает исключением
        result = real(project_id, hub_app_id, **kwargs)
        if kwargs.get("dry"):
            _hub_decision(db, project_id, "101")  # другая вкладка приняла состояние Hub
        return result

    monkeypatch.setattr(db, "change_hub_assignment", racing)
    r = web.client.post(f"/projects/{pid}/params", headers=ORIGIN, data={"name": "p", "hub_app_id": "8"},
                        follow_redirects=False)
    assert r.status_code in (302, 303) and r.headers["location"].endswith(f"/projects/{pid}/hub-assignment?app=8")
    assert db.get_project(pid)["hub_app_id"] == 7 and db.get_review(pid, "101")["decision_origin"] == "hub_sync"
    assert any("expect" in k for k in calls), "запись – по отпечатку расчёта"


def test_hub_url_token_sees_app_number_change(web):  # noqa: F811
    """B6: в отпечатке смены адреса – номера приложений проектов."""
    db = web.app.state.db
    pid = project(web, [sast("101")])
    first = db.change_hub_url("https://hub2.example.org", dry=True)["token"]
    db.update_project(pid, hub_app_id=9)
    assert db.change_hub_url("https://hub2.example.org", dry=True)["token"] != first


def test_confirmation_shows_what_goes_to_the_archive(web):  # noqa: F811
    """B5: подтверждение называет, что уходит в архив (исследование прежней тройки)."""
    from app.sca_contract import input_ref
    from test_package_transition import made
    from test_sca_applicability import put_research
    db, pid = made(web, ("73001", "org.example:lib", "maven"))
    _hub_lib(db, pid, "73001")
    put_research(db, pid, input_ref("maven", "lib", "1.2.3"),
                 {"identity_resolution": {"state": "resolved", "coordinates": "lib"}})
    page = web.client.get(f"/projects/{pid}/hub-assignment?app=8")
    assert page.status_code == 200 and 'id="hub-assignment-entities"' in page.text
    assert "исследования компонента" in page.text
    assert "исследования компонента: в архив 1" in page.text, "числа по сущностям – и в строке группы"



def test_hub_url_confirmation_shows_identity_summary(web):  # noqa: F811
    """Ревью Codex шага 4, круг 3: подтверждение смены адреса показывает последствия по проекту – блок «Идентичность
    пакетов» с таблицей «что перенесено, что в архив»."""
    from app.sca_contract import input_ref
    from test_package_transition import made
    from test_sca_applicability import put_research
    db, pid = made(web, ("73001", "org.example:lib", "maven"))
    _hub_lib(db, pid, "73001")
    put_research(db, pid, input_ref("maven", "lib", "1.2.3"),
                 {"identity_resolution": {"state": "resolved", "coordinates": "lib"}})
    r = web.client.post("/settings", headers={**ORIGIN, "Accept": "text/html"}, follow_redirects=False,
                        data=_settings_form(web, hub_url="https://hub2.example.org"))
    assert r.status_code == 200 and 'id="hub-url-project-1-summary"' in r.text, r.text[:400]
    assert 'id="hub-url-project-1-entities"' in r.text and "исследования компонента" in r.text



def test_assignment_summary_counts_withdrawn_reviewed_marks(web):  # noqa: F811
    """Ревью Codex шага 4, круг 4: снятые «Проверено» у решений из Hub прежнего назначения – в сводке подтверждения;
    подтверждение называет и добавленную область npm."""
    db = web.app.state.db
    pid = project(web, [sast("101")])
    _hub_decision(db, pid, "101")
    summary = db.change_hub_assignment(pid, 8, dry=True)["summary"]
    assert summary["decisions"]["reviewed_removed"] == 1
    page = web.client.get(f"/projects/{pid}/hub-assignment?app=8")
    assert page.status_code == 200 and "Снимается «Проверено»" in page.text

"""Регрессии трёх замечаний операторской приёмки; только выдуманные компоненты."""

import dataclasses

import pytest

from app import sca_research as research
from hub_fixtures import SAST_ROWS, make_hub_xlsx
from test_component_research_ui import (answer_document, build_task, decide, expect_accepted,
                                       hidden, project_with_components, section)
from test_operator_tables import snapshots, versions_project
from test_web import ORIGIN, create_project, upload, web  # noqa: F401


@pytest.mark.parametrize("action", ["keep", "accept_risk", "remove", "investigate", "update", "replace"])
def test_decision_stores_only_fields_for_selected_action(web, action):
    pid = project_with_components(web)
    manifest = build_task(web, pid)
    expect_accepted(web, pid, answer_document(manifest))
    ref = manifest["rows"][0]["input_ref"]
    assert decide(web, pid, ref, action="update", rationale="Первоначальное обновление",
                  target_version="2.0.0").status_code == 303
    assert decide(web, pid, ref, action=action, rationale="Новое решение", target_version="3.0.0",
                  replacement_name="demo-replacement", replacement_version="4.0.0",
                  review_at="2099-12-31").status_code == 303
    db = web.app.state.db
    saved = db.decision(pid, ref)
    expected = {"target_version": "3.0.0" if action == "update" else "",
                "replacement_name": "demo-replacement" if action == "replace" else "",
                "replacement_version": "4.0.0" if action == "replace" else ""}
    assert {key: saved[key] for key in expected} == expected
    assert saved["rationale"] == "Новое решение" and saved["review_at"] == "2099-12-31"
    assert db.decision_history(pid, ref)[1]["target_version"] == "2.0.0"
    report = web.client.get(f"/projects/{pid}/components/{ref}/report").json()
    assert {key: report["components"][0]["decision"][key] for key in expected} == expected


def test_previous_decision_view_hides_inapplicable_fields_without_mutating_history():
    old = dict(action="accept_risk", target_version="3.0.0", replacement_name="demo-replacement",
               replacement_version="4.0.0", rationale="Прежнее решение")
    view = research.decision_view(old)
    assert view["target_version"] == view["replacement_name"] == view["replacement_version"] == ""
    assert old["target_version"] == "3.0.0"
    assert research.check_decision({**old, "target_version": "x" * 201}) == ""


def test_batch_decision_ignores_fields_from_other_actions(web):
    pid, rows = versions_project(web)
    values = dict(action="accept_risk", rationale="Риск принят для выбранных версий",
                  target_version="3.0.0", replacement_name="demo-replacement", replacement_version="4.0.0")
    web.app.state.db.save_decisions(pid, snapshots(rows), values)
    for saved in web.app.state.db.decisions(pid).values():
        assert saved["target_version"] == saved["replacement_name"] == saved["replacement_version"] == ""


def test_replace_to_update_keeps_previous_replacement_in_history(web):
    pid = project_with_components(web)
    ref = build_task(web, pid)["rows"][0]["input_ref"]
    assert decide(web, pid, ref, action="replace", rationale="Первое решение",
                  replacement_name="demo-replacement", replacement_version="4.0.0").status_code == 303
    assert decide(web, pid, ref, action="update", rationale="Второе решение", target_version="3.0.0",
                  replacement_name="demo-replacement", replacement_version="4.0.0").status_code == 303
    current, previous = web.app.state.db.decision_history(pid, ref)
    assert current["target_version"] == "3.0.0" and current["replacement_name"] == ""
    assert previous["replacement_name"] == "demo-replacement" and previous["replacement_version"] == "4.0.0"


def test_validation_error_points_to_field_without_refresh_instruction(web):
    pid = project_with_components(web)
    ref = build_task(web, pid)["rows"][0]["input_ref"]
    response = decide(web, pid, ref, action="update", rationale="Сохрани мой текст")
    assert response.status_code == 422
    error = section(response.text, "operator-decision")
    assert "Откройте страницу заново" not in error
    assert 'href="#decision-target-version"' in error
    assert 'aria-invalid="true"' in error
    assert "Сохрани мой текст" in error
    seen = {key: hidden(response.text, key) for key in ("revision", "expected_input_sig",
                                                      "expected_research_sig", "expected_research_revision")}
    result = web.client.post(f"/projects/{pid}/components/{ref}/decision", headers={**ORIGIN, "Accept": "application/json"},
                             data={**seen, "action": "update", "rationale": "Сохрани мой текст"})
    assert result.status_code == 422
    assert result.json()["error_field"] == "target_version"
    assert decide(web, pid, ref, action="update", rationale="Сохрани мой текст",
                  target_version="2.0.0", **seen).status_code == 303
    conflict = decide(web, pid, ref, action="keep", rationale="Из старой вкладки", **seen)
    assert conflict.status_code == 409 and "Откройте страницу заново" in conflict.text


@pytest.mark.parametrize("display", ["D:/apps/local-triage/examples/demo/repos", "D:\\apps\\local-triage\\examples\\demo\\repos"])
def test_project_demo_root_does_not_invite_working_clones(web, display):
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "with-code.xlsx", sast=SAST_ROWS, sca=())).status_code == 303
    empty_root = web.tmp / "empty-repos"
    empty_root.mkdir()
    web.app.state.web.base = dataclasses.replace(web.settings, repos_root=empty_root, repos_root_host=display,
                                                 repos_root_is_demo="1")
    html = web.client.get(f"/projects/{pid}").text
    assert "Демонстрационные репозитории" in html
    assert "start.ps1 -ReposRoot" in html
    assert "Клонируйте их в" not in html
    assert web.app.state.db.get_project(pid)["repos_dir"] == ""


@pytest.mark.parametrize("flag, warned, neutral", [("0", False, False), ("", False, True), ("1", True, False)])
def test_demo_folders_in_working_root_are_not_a_demo_sign(web, flag, warned, neutral):
    """Бэклог 94: папки демо-комплекта в рабочем корне рядом с клонами – не признак демо; предупреждение – только когда
    start.ps1 подключил демо-папку приложения (REPOS_ROOT_IS_DEMO=1); не задано – нейтральная строка без предупреждения."""
    from app.routes.projects import DEMO_CODEBASES
    pid = project_with_components(web)
    for name in DEMO_CODEBASES:
        (web.settings.repos_root / name).mkdir()
    web.app.state.web.base = dataclasses.replace(web.settings, repos_root_host="D:/work/repos", repos_root_is_demo=flag)
    html = web.client.get(f"/projects/{pid}").text
    assert ("Демонстрационные репозитории" in html) is warned
    assert ('id="repos-source"' in html) is neutral and ("источник не определён" in html) is neutral


def test_project_regular_root_keeps_clone_destination(web):
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "with-code.xlsx", sast=SAST_ROWS, sca=())).status_code == 303
    empty_root = web.tmp / "other-repos"
    empty_root.mkdir()
    web.app.state.web.base = dataclasses.replace(web.settings, repos_root=empty_root, repos_root_host="D:/work/repos",
                                                 repos_root_is_demo="0")
    html = web.client.get(f"/projects/{pid}").text
    assert "Демонстрационные репозитории" not in html
    assert "D:/work/repos" in html and "Клонируйте их в" in html

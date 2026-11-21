"""Транзакционная актуальность сценария исследования компонентов: состав, задание, импорт ответа и решение.

Проверяем то, что ломается только при гонке и при переимпорте выгрузки:

- переимпорт того же состава (новые строки и номера AST, те же пакеты и версии) даёт новое imports.id, но задание
  прежнее и ответ по нему принимается – состав, а не номер файла решает;
- смена состава между чтением и записью отказывает и не пишет ничего: ни ревизий, ни отметки об импорте;
- две кнопки «собрать задание» дают один снимок, а не два действующих задания;
- решение по пакету, ушедшему из выгрузки, не принимается как решение по актуальному составу, а история решения
  остаётся на месте;
- отметка о загрузке ответа пишется той же транзакцией, что и ревизии: частичного импорта не бывает;
- строки раздела показывают текущий состав выгрузки и до сборки задания, а ушедшие из выгрузки пакеты остаются
  видимыми с пометкой.

Тесты без sleep и без настоящей базы приложения: подменяется только выгрузка (тот же разбор, что у приложения).
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest
from starlette.requests import Request

from app import sca_research as research
from app.db import Database, DecisionStale, TaskSuperseded
from app.routes import components
from app.routes.common import db_of
from app.sca_contract import ANSWER_CONTRACT, VALIDATOR_VERSION
from hub_fixtures import SCA_ROWS
from test_sca_research import HUB_ROWS, answer_for, composition_of, hub_export, load_export
from test_sca_research_routes import (AS_JSON, build_task, kit_answer, project_with_sca, upload_answer)  # noqa: F401
from test_web import ORIGIN, web  # noqa: F401

CONTRACT = research.CONTRACT

#: Три пакета одного проекта: координаты maven, краткое имя maven и пакет npm с областью. Набор тот же, что у
#: ответов в tests/test_sca_research.py, поэтому принятый ответ строится тем же кодом.
HUB_ROWS = [
    {"Issue id": "73001", "CVSS score": "9.8", "Component name": "org.apache.tomcat.embed:tomcat-embed-core",
     "Component version": "9.0.83", "CVE id": "AST-2026-000101", "Non-vulnerable versions": "1.4.9"},
    {"Issue id": "73002", "CVSS score": "8.2", "Component name": "tomcat-embed-core",
     "Component version": "9.0.83", "CVE id": "CVE-2099-10001", "Non-vulnerable versions": "1.4.9"},
    {"Issue id": "73003", "CVSS score": "7.5", "Type": "npm", "Component name": "@babel/traverse",
     "Component version": "7.23.2", "CVE id": "AST-2026-000103", "Non-vulnerable versions": "7.23.5",
     "Codebase": "catalog-api", "Path": "catalog-api > @babel/traverse"},
]
#: Та же выгрузка, но у пакета появилась ещё одна находка с другим номером AST: состав не меняется.
EXTRA_AST_ROW = {"Issue id": "73004", "CVSS score": "6.5", "Component name": "org.apache.tomcat.embed:tomcat-embed-core",
                 "Component version": "9.0.83", "CVE id": "AST-2026-000999", "Non-vulnerable versions": "1.4.9"}
#: Другая версия того же пакета: состав уже другой, прежнее задание больше не отвечает выгрузке.
NEW_VERSION = "9.0.84"


def with_new_version(rows: list[dict]) -> list[dict]:
    """Та же выгрузка, но у координатного пакета другая версия: старой в составе уже нет."""
    return [dict(row, **{"Component version": NEW_VERSION})
            if row["Component name"] == "org.apache.tomcat.embed:tomcat-embed-core" else row for row in rows]



def save_task(db: Database, project_id: int, task_id: str = "t-20261017-abc123") -> tuple[dict, list[dict]]:
    """Собрать и сохранить задание по текущему составу, как это делает кнопка на странице."""
    rows, digest = composition_of(db, project_id)
    import_id = int((db.latest_import(project_id) or {}).get("id") or 0)
    task = db.insert_task(project_id, import_id, task_id, rows,
                          sorted({item["ecosystem"] for item in rows}), digest, "", CONTRACT, ANSWER_CONTRACT,
                          VALIDATOR_VERSION)
    return task, rows


@pytest.fixture
def loaded(tmp_path: Path):
    """Проект с настоящей выгрузкой из трёх пакетов."""
    db = Database(tmp_path / "triage.db")
    pid = db.create_project("Demo Library")
    load_export(db, pid, hub_export(tmp_path / "hub.xlsx", HUB_ROWS))
    return db, pid, tmp_path


# ============================================================== ответ приходит на прежнее задание

def test_reimport_of_the_same_composition_with_new_ast_rows_keeps_the_answer_importable(loaded):
    """Переимпорт того же состава даёт новое imports.id, но ответ по прежнему заданию остаётся годным."""
    db, pid, tmp = loaded
    task, rows = save_task(db, pid)
    assert task["state"] == "current"
    again = load_export(db, pid, hub_export(tmp / "again.xlsx", HUB_ROWS + [EXTRA_AST_ROW]))
    assert again["import_id"] != task["import_id"]  # номер файла выгрузки другой
    assert [item["input_ref"] for item in composition_of(db, pid)[0]] == [item["input_ref"] for item in rows]
    saved = db.save_research(pid, task["id"], research.research_results(answer_for(rows), rows))
    assert saved["saved"] == 3 and saved["unchanged"] == 0
    # номер файла выгрузки в задании остаётся прежним – это история, а не ошибка
    assert db.task(pid, task["task_id"])["import_id"] == task["import_id"]
    assert db.task(pid, task["task_id"])["imported_at"]


def test_answer_of_a_task_whose_composition_changed_is_refused_inside_the_transaction(loaded):
    db, pid, tmp = loaded
    task, rows = save_task(db, pid)
    load_export(db, pid, hub_export(tmp / "newer.xlsx", with_new_version(HUB_ROWS)))
    with pytest.raises(TaskSuperseded):
        db.save_research(pid, task["id"], research.research_results(answer_for(rows), rows))
    assert db.research(pid) == {} and db.task(pid, task["task_id"])["imported_at"] is None


def test_answer_for_a_row_outside_the_task_is_not_stored(loaded):
    """Ответ не по сохранённому заданию не пишется: подменять строку задания нельзя."""
    db, pid, _ = loaded
    task, rows = save_task(db, pid)
    results = research.research_results(answer_for(rows[:2]), rows[:2])
    results[0]["input_ref"] = research.input_ref("pypi", "чужой-пакет", "1.0.0")
    with pytest.raises(TaskSuperseded):
        db.save_research(pid, task["id"], results)
    assert db.research(pid) == {} and db.task(pid, task["task_id"])["imported_at"] is None


# ============================================================== сборка задания

def test_task_rows_of_a_changed_composition_are_refused_and_the_old_snapshot_stays(loaded):
    """Состав сменился между чтением строк и записью: прежнее задание и его строки остаются в силе."""
    db, pid, tmp = loaded
    task, rows = save_task(db, pid)
    stale_rows, stale_digest = composition_of(db, pid)
    load_export(db, pid, hub_export(tmp / "newer.xlsx", with_new_version(HUB_ROWS)))
    with pytest.raises(TaskSuperseded):
        db.insert_task(pid, int((db.latest_import(pid) or {}).get("id") or 0), "t-20261017-second", stale_rows,
                       sorted({item["ecosystem"] for item in stale_rows}), stale_digest, "", CONTRACT,
                       ANSWER_CONTRACT, VALIDATOR_VERSION)
    assert db.current_task(pid)["task_id"] == task["task_id"] and db.current_task(pid)["state"] == "current"
    assert len(db.task_rows(task["id"])) == 3
    assert db.task(pid, "t-20261017-second") is None


def test_two_creates_of_the_same_composition_keep_one_current_task(loaded):
    db, pid, _ = loaded
    first, _ = save_task(db, pid, "t-20261017-первое")
    second, _ = save_task(db, pid, "t-20261017-второе")
    assert second["task_id"] == first["task_id"] and second["id"] == first["id"]
    assert [item["state"] for item in db.tasks(pid)] == ["current"] and db.task(pid, "t-20261017-второе") is None


def test_two_simultaneous_creates_keep_one_snapshot(loaded):
    """Две кнопки, нажатые одновременно: тот же состав – тот же снимок, второго действующего задания не появляется."""
    db, pid, _ = loaded
    rows, digest = composition_of(db, pid)
    import_id = int((db.latest_import(pid) or {}).get("id") or 0)
    started = threading.Barrier(2)
    created: list[dict] = []

    def create(task_id: str) -> None:
        started.wait(timeout=10)
        created.append(db.insert_task(pid, import_id, task_id, rows, ["maven", "npm"], digest, "", CONTRACT,
                                      ANSWER_CONTRACT, VALIDATOR_VERSION))

    names = ("t-20261017-первое", "t-20261017-второе")
    threads = [threading.Thread(target=create, args=(name,)) for name in names]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    # кто успел раньше, тот и создал снимок; второй вернул то же самое задание, а не второе
    assert len(created) == 2 and created[0]["task_id"] == created[1]["task_id"]
    assert created[0]["task_id"] in names
    assert [item["state"] for item in db.tasks(pid)] == ["current"]
    assert db.task(pid, next(name for name in names if name != created[0]["task_id"])) is None


def test_changed_selection_of_packages_refuses_the_previous_rows(loaded):
    """Отбор – часть состава: сменились префиксы внутренних компонентов, прежние строки больше не годятся."""
    db, pid, _ = loaded
    old_rows, old_digest = composition_of(db, pid)
    assert len(old_rows) == 3
    db.set_settings({"sca_internal_prefixes": ["@babel"]})
    new_rows, new_digest = composition_of(db, pid)
    assert len(new_rows) == 2 and new_digest != old_digest
    import_id = int((db.latest_import(pid) or {}).get("id") or 0)
    with pytest.raises(TaskSuperseded):
        db.insert_task(pid, import_id, "t-20261017-old", old_rows, ["maven", "npm"], old_digest, "", CONTRACT,
                       ANSWER_CONTRACT, VALIDATOR_VERSION)
    created = db.insert_task(pid, import_id, "t-20261017-new", new_rows, ["maven"], new_digest, "", CONTRACT,
                             ANSWER_CONTRACT, VALIDATOR_VERSION)
    assert created["row_count"] == 2 and created["manifest_sha256"] == new_digest
    assert db.task_row(pid, research.input_ref("npm", "@babel/traverse", "7.23.2")) is None


# ============================================================== импорт ответа атомарно

def test_import_marks_are_written_with_revisions_or_not_at_all(loaded, monkeypatch):
    """Половины не бывает: сбой записи не оставляет ни одной ревизии и не ставит отметку об импорте."""
    db, pid, _ = loaded
    task, rows = save_task(db, pid)
    results = research.research_results(answer_for(rows), rows)

    def broken_touch(c, project_id, ts):  # noqa: ANN001 - подмена последнего шага транзакции
        raise sqlite3.OperationalError("сбой записи")

    monkeypatch.setattr(db, "_touch", broken_touch)
    with pytest.raises(sqlite3.OperationalError):
        db.save_research(pid, task["id"], results)
    monkeypatch.undo()
    assert db.research(pid) == {} and db.task(pid, task["task_id"])["imported_at"] is None
    # отметка о загрузке пишется той же транзакцией, а не отдельным шагом после импорта
    assert not hasattr(db, "mark_task_imported")
    saved = db.save_research(pid, task["id"], results)
    assert saved["saved"] == 3 and db.task(pid, task["task_id"])["imported_at"]


def test_repeated_import_of_the_same_answer_is_idempotent(loaded):
    db, pid, _ = loaded
    task, rows = save_task(db, pid)
    results = research.research_results(answer_for(rows), rows)
    first = db.save_research(pid, task["id"], results)
    stamp = db.task(pid, task["task_id"])["imported_at"]
    again = db.save_research(pid, task["id"], results)
    assert again["saved"] == 0 and again["unchanged"] == 3 and again["revisions"] == first["revisions"]
    assert db.task(pid, task["task_id"])["imported_at"] >= stamp


# ============================================================== решение человека

def decided(db: Database, pid: int, task: dict, rows: list[dict], index: int = 0) -> tuple[str, dict]:
    """Ответ агента и решение человека по одной строке: что человек видел на карточке."""
    db.save_research(pid, task["id"], research.research_results(answer_for(rows), rows))
    seen = db.research_row(pid, rows[index]["input_ref"])
    db.save_decision(pid, rows[index]["input_ref"], "keep", "Проверено в выпуске", "", "", "", "",
                     rows[index]["input_sig"], seen["answer_sig"], 0, seen["answer_sig"],
                     int(seen["revision"]))
    return rows[index]["input_ref"], seen


def test_decision_after_the_package_left_the_export_is_refused_and_history_is_kept(loaded):
    db, pid, tmp = loaded
    task, rows = save_task(db, pid)
    ref, seen = decided(db, pid, task, rows)
    without = [row for row in HUB_ROWS if row["Component name"] != rows[0]["name"]]
    load_export(db, pid, hub_export(tmp / "without.xlsx", without))
    with pytest.raises(DecisionStale):
        db.save_decision(pid, ref, "accept_risk", "Риск принят", "", "", "", "", rows[0]["input_sig"],
                         seen["answer_sig"], 1, seen["answer_sig"], int(seen["revision"]))
    assert db.decision(pid, ref)["action"] == "keep"  # история решения не тронута
    assert [item["revision"] for item in db.decision_history(pid, ref)] == [1]


def test_decision_made_for_another_version_of_the_package_is_refused(loaded):
    db, pid, tmp = loaded
    task, rows = save_task(db, pid)
    ref, seen = decided(db, pid, task, rows)
    load_export(db, pid, hub_export(tmp / "newer.xlsx", with_new_version(HUB_ROWS)))
    with pytest.raises(DecisionStale):
        db.save_decision(pid, ref, "update", "Обновить", "9.0.99", "", "", "", rows[0]["input_sig"],
                         seen["answer_sig"], 1, seen["answer_sig"], int(seen["revision"]),
                         expected_input_sig=rows[0]["input_sig"])
    assert db.decision(pid, ref)["action"] == "keep"


def test_decision_made_with_the_signature_the_person_saw_is_accepted(loaded):
    """Проверка не отказывает живому решению: подпись строки совпадает с той, что человек видел."""
    db, pid, tmp = loaded
    task, rows = save_task(db, pid)
    ref, seen = decided(db, pid, task, rows)
    load_export(db, pid, hub_export(tmp / "again.xlsx", HUB_ROWS + [EXTRA_AST_ROW]))
    again = db.save_decision(pid, ref, "accept_risk", "Условия применения те же", "", "", "", "",
                             rows[0]["input_sig"], seen["answer_sig"], 1, seen["answer_sig"],
                             int(seen["revision"]), expected_input_sig=rows[0]["input_sig"])
    assert again["revision"] == 2 and db.decision(pid, ref)["action"] == "accept_risk"


# ============================================================== строки раздела

def request_of(web) -> Request:
    """Настоящий Request без обращения к серверу: маршруты берут из него состояние приложения и адрес."""
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "scheme": "http",
             "path": "/", "raw_path": b"/", "root_path": "", "query_string": b"", "headers": [],
             "client": ("127.0.0.1", 50000), "server": ("127.0.0.1", 8765), "app": web.app, "state": {}}
    return Request(scope)


XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def upload_export(web, project_id: int, rows: list[dict], name: str = "hub.xlsx"):
    """Загрузить выгрузку через адрес импорта – так, как это делает человек."""
    path = hub_export(web.tmp / name, rows)
    return web.client.post(f"/projects/{project_id}/import", headers=ORIGIN, follow_redirects=False,
                           files={"file": (name, path.read_bytes(), XLSX)})


def test_list_shows_the_current_composition_before_a_task_is_built(web):
    """Пустой список врал: строки текущей выгрузки видны и до сборки задания, и задание при этом не создаётся."""
    pid = project_with_sca(web)
    request = request_of(web)
    context = components.list_context(request, db_of(request).get_project(pid))
    assert context["task"] is None
    assert sorted(row["name"] for row in context["rows"]) == ["demo-xml", "example-parser"]
    assert all(row["live"] and not row["in_task"] and not row["export_missing"] for row in context["rows"])
    assert web.app.state.db.current_task(pid) is None
    page = web.client.get(f"/projects/{pid}/components")
    assert page.status_code == 200 and "example-parser" in page.text


def test_package_left_out_of_the_export_stays_visible_with_a_mark(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    gone = next(item for item in manifest["rows"] if item["component"] == "example-parser")
    keep = next(item for item in manifest["rows"] if item["component"] == "demo-xml")
    remaining = [row for row in SCA_ROWS if row["Issue id"] not in ("73001", "73002")]
    assert upload_export(web, pid, remaining, "less.xlsx").status_code == 303
    assert web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN,
                           follow_redirects=False).status_code == 303
    request = request_of(web)
    context = components.list_context(request, db_of(request).get_project(pid))
    rows = {row["input_ref"]: row for row in context["rows"]}
    assert rows[gone["input_ref"]]["export_missing"] and not rows[gone["input_ref"]]["live"]
    assert rows[gone["input_ref"]]["task_stale"]
    assert rows[keep["input_ref"]]["live"] and rows[keep["input_ref"]]["in_task"]
    assert rows[keep["input_ref"]]["version"] == keep["version"]
    assert context["task"]["row_count"] == 1


def test_decision_on_a_current_package_without_a_task_is_saved(web):
    """Строка видна до сборки задания – решение по ней тоже принимается, а не отвергается как по несуществующей."""
    pid = project_with_sca(web)
    request = request_of(web)
    row = next(item for item in components.list_context(request, db_of(request).get_project(pid))["rows"]
               if item["name"] == "demo-xml")
    response = web.client.post(f"/projects/{pid}/components/{row['input_ref']}/decision", headers=ORIGIN,
                               data={"action": "investigate", "rationale": "Проверить у разработчиков",
                                     "revision": "0", "expected_input_sig": row["input_sig"]},
                               follow_redirects=False)
    assert response.status_code == 303, response.text
    saved = web.app.state.db.decision(pid, row["input_ref"])
    assert saved["action"] == "investigate" and saved["input_sig"] == row["input_sig"]


# ============================================================== адреса раздела

def test_answer_stays_importable_after_reimporting_the_same_composition(web):
    """Тот же сценарий через адреса: переимпорт с новыми номерами AST не закрывает импорт ответа."""
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    payload = kit_answer(manifest)
    # та же выгрузка приходит снова с новой находкой по тому же пакету
    again_rows = [dict(SCA_ROWS[0], **{"Issue id": "73004", "CVE id": "AST-2026-000999"}), *SCA_ROWS]
    assert upload_export(web, pid, again_rows, "again.xlsx").status_code == 303
    same = web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN, follow_redirects=False)
    assert same.status_code == 303 and same.headers["location"].endswith("ok=task_same&n=2")
    assert upload_answer(web, pid, payload).status_code == 303
    assert len(web.app.state.db.research(pid)) == 2


def test_task_build_after_the_composition_changed_refuses_and_keeps_the_previous_task(web, monkeypatch):
    """Состав сменился прямо перед записью: 409, прежнее задание и его строки остаются."""
    from app.hub_import import parse_workbook
    from app.triage import order_findings
    pid = project_with_sca(web)
    first = build_task(web, pid)
    db = web.app.state.db
    # новый состав уже отличается от действующего задания, поэтому кнопка идёт в запись
    assert upload_export(web, pid, [dict(row, **{"Component version": "2.0.1"}) for row in SCA_ROWS],
                         "next.xlsx").status_code == 303
    original = db.insert_task

    def race(*args, **kwargs):
        path = hub_export(web.tmp / "changed-during-task.xlsx",
                          [dict(row, **{"Component version": "3.0.0"}) for row in SCA_ROWS])
        parsed = parse_workbook(path)
        db.save_import(pid, path.name, parsed.format, parsed.sheets, parsed.summary, parsed.warnings,
                       order_findings(parsed.findings))
        return original(*args, **kwargs)

    monkeypatch.setattr(db, "insert_task", race)
    response = web.client.post(f"/projects/{pid}/components/task", headers=AS_JSON, follow_redirects=False)
    assert response.status_code == 409 and "изменился" in response.json()["detail"]
    assert db.current_task(pid)["task_id"] == first["task_id"] and db.current_task(pid)["state"] == "current"
    assert db.current_task(pid)["row_count"] == 2


def test_two_task_buttons_leave_one_task(web):
    pid = project_with_sca(web)
    for _ in range(2):
        assert web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN,
                               follow_redirects=False).status_code == 303
    tasks = web.app.state.db.tasks(pid)
    assert len(tasks) == 1 and tasks[0]["state"] == "current"
    assert web.client.post(f"/projects/{pid}/components/task", headers=AS_JSON,
                           follow_redirects=False).headers["location"].endswith("ok=task_same&n=2")


def test_decision_after_the_package_was_removed_refuses_and_keeps_the_draft(web):
    """Пакет ушёл из выгрузки прямо перед записью: 409, черновик возвращается, история решения на месте."""
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    assert upload_answer(web, pid, kit_answer(manifest)).status_code == 303
    db = web.app.state.db
    ref = manifest["rows"][0]["input_ref"]
    seen = db.research_row(pid, ref)
    form = {"action": "accept_risk", "rationale": "Условия применения проверены", "revision": "0",
            "expected_input_sig": seen["input_sig"],
            "expected_research_sig": seen["answer_sig"], "expected_research_revision": str(seen["revision"])}
    assert web.client.post(f"/projects/{pid}/components/{ref}/decision", headers=ORIGIN, data=form,
                           follow_redirects=False).status_code == 303
    remaining = [row for row in SCA_ROWS if row["Component name"] != manifest["rows"][0]["component"]]
    assert upload_export(web, pid, remaining, "less.xlsx").status_code == 303
    response = web.client.post(f"/projects/{pid}/components/{ref}/decision", headers=AS_JSON, data=form,
                               follow_redirects=False)
    assert response.status_code == 409
    assert db.decision(pid, ref)["action"] == "accept_risk"
    assert db.decision(pid, ref)["revision"] == 1
    page = web.client.post(f"/projects/{pid}/components/{ref}/decision", headers=ORIGIN, data=form,
                           follow_redirects=False)
    assert page.status_code == 409 and "Условия применения проверены" in page.text


def test_missing_package_stays_in_the_list_after_the_export_changed(web):
    """Страница карточки ушедшего пакета открывается: её факты и решение остаются видимыми с пометкой."""
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    gone = next(item for item in manifest["rows"] if item["component"] == "example-parser")
    remaining = [row for row in SCA_ROWS if row["Issue id"] not in ("73001", "73002")]
    assert web.client.post(f"/projects/{pid}/import", headers=ORIGIN, follow_redirects=False, files={
        "file": ("less.xlsx", hub_export(web.tmp / "less.xlsx", remaining).read_bytes(),
                 "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}).status_code == 303
    page = web.client.get(f"/projects/{pid}/components/{gone['input_ref']}")
    assert page.status_code == 200 and "example-parser" in page.text
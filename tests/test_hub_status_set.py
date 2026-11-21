"""Множественный вариант действующего статуса Hub (_HUB_STATUS_SET_SQL, замер стоимости dev18) даёт по каждой находке то же,
что построчное выражение _CURRENT_HUB_STATUS_SQL: принятое состояние, подтверждение записи (в том числе битое), запись без
версии (последняя по номеру, находка в составе нескольких записей), только выгрузка, другой Hub или приложение, виды SCA,
номер с ведущими нулями и нечисловой номер. Данные выдуманы."""

from __future__ import annotations

from app.db import _CURRENT_HUB_STATUS_SQL, _HUB_STATUS_SET_SQL, dumps
from app.models import Finding
from test_hub_status_routes import HUB, project
from test_web import web  # noqa: F401


def row_statuses(db, pid: int) -> dict[str, str]:
    return {r["hub_id"]: r["status"] for r in db._all(
        f"SELECT f.hub_id, {_CURRENT_HUB_STATUS_SQL} AS status FROM findings f WHERE f.project_id = ?", (pid,))}


def set_statuses(db, pid: int) -> dict[str, str]:
    rows = db._all(_HUB_STATUS_SET_SQL.format(cond=""), (pid, pid))
    total = db._one("SELECT COUNT(*) AS n FROM findings WHERE project_id = ?", (pid,))["n"]
    assert len(rows) == total and len({r["id"] for r in rows}) == total, "одна строка на находку, без дублей"
    return {r["hub_id"]: r["status"] for r in rows}


def test_hub_status_set_matches_row(web):  # noqa: F811
    db = web.app.state.db
    findings = [Finding(hub_id=h, kind=k, status=s) for h, k, s in (
        ("00101", "SAST", "Open"), ("102", "SAST", "Open"), ("103", "SAST", "To verify"), ("104", "SAST", "Open"),
        ("105", "SCA", "Open"), ("106", "SCA-license", ""), ("107", "SAST", "Open"), ("abc", "SAST", "Open"),
        ("108", "SAST", "Confirmed"), ("109", "SAST", "Open"), ("110", "SAST", "Open"), ("111", "SAST", "Open"),
        ("112", "SAST", ""), ("113", "DAST", "Open"), ("114", "SAST", "Open"))]
    pid = project(web, findings)
    other = project(web, [Finding(hub_id="102", kind="SAST", status="Open")])
    with db._tx() as c:
        def op(project_id, status, targets, hub=HUB, app=7, state="done"):
            return c.execute("INSERT INTO hub_ops(project_id, hub_url, app_id, purpose, state, request_json, targets_json, op_key,"
                             " created_at, updated_at) VALUES (?, ?, ?, 'status', ?, ?, ?, ?, '2026-11-06', '2026-11-06') RETURNING id",
                             (project_id, hub, app, state, dumps({"body": {"status": status}}), dumps([{"hub_id": t} for t in targets]),
                              f"k-{project_id}-{status}-{'-'.join(targets)}-{hub}-{app}-{state}")).fetchone()[0]

        def state(issue_type, issue_id, status, presence="present", app=7):
            c.execute("INSERT INTO hub_issue_states(project_id, hub_url, app_id, issue_type, issue_id, confirmed_json, confirmed_presence)"
                      " VALUES (?, ?, ?, ?, ?, ?, ?)", (pid, HUB, app, issue_type, issue_id, dumps({"detail": {"status": status}}), presence))

        def version(key, origin, op_id=None):
            c.execute("INSERT INTO hub_entity_versions(project_id, hub_url, app_id, entity_kind, entity_key, accepted_source_json)"
                      " VALUES (?, ?, 7, 'issue', ?, ?)", (pid, HUB, key, dumps({"origin": origin, "op_id": op_id})))

        confirm = op(pid, "False Positive", ["00101"])
        state("SAST", "101", "Fixed")
        version("SAST:101", "status_confirmation", confirm)          # подтверждение записи
        state("SAST", "102", "Fixed")
        version("SAST:102", "sync")                                  # принятая сверка
        op(pid, "False Positive", ["103"])
        op(pid, "Accepted risk", ["103", "104"])                     # последняя запись с находкой в составе
        op(pid, "False Positive", ["104"], state="failed")           # невыполненная не в счёт
        state("SCA_S", "105", "Confirmed")
        state("SCA_L", "106", "Open", presence="absent")             # отсутствующее состояние – выгрузка
        version("SAST:107", "status_confirmation", -1)               # битое подтверждение
        op(pid, "Fixed", ["108"], hub="https://other.example.org")   # другой Hub
        op(pid, "Fixed", ["109"], app=8)                             # другое приложение
        op(other, "Fixed", ["102"])                                  # другой проект
        state("SAST", "107", "Fixed")                                # битое подтверждение при существующем состоянии
        state("SAST", "110", "")                                     # пустой статус состояния – выгрузка
        c.execute("INSERT INTO hub_issue_states(project_id, hub_url, app_id, issue_type, issue_id, confirmed_json,"
                  " confirmed_presence) VALUES (?, ?, 7, 'SAST', '111', '{}', 'present')", (pid, HUB))  # статуса нет
        op(pid, "", ["112"])                                         # пустая запись статуса – дальше по цепочке
        state("SAST", "112", "Accepted risk")
        state("DAST", "113", "Confirmed")
        version("SAST:114", "sync")                                  # принятая версия против старой записи
        op(pid, "Fixed", ["114"])
        state("SAST", "114", "Confirmed")
        c.execute("INSERT INTO hub_entity_versions(project_id, hub_url, app_id, entity_kind, entity_key, accepted_source_json)"
                  " VALUES (?, ?, 8, 'issue', 'SAST:109', ?)", (pid, HUB, dumps({"origin": "sync"})))  # чужое приложение
        c.execute("UPDATE findings SET kind = 'OTHER' WHERE project_id = ? AND hub_id = 'abc'", (pid,))  # вид без типа
    row, got = row_statuses(db, pid), set_statuses(db, pid)
    assert got == row, {k: (row.get(k), got.get(k)) for k in set(row) | set(got) if row.get(k) != got.get(k)}
    assert row["00101"] == "False Positive" and row["102"] == "Fixed" and row["104"] == "Accepted risk"
    assert row["107"] == "Open" and row["114"] == "Confirmed"
    db.update_project(pid, hub_app_id=0)
    assert set_statuses(db, pid) == row_statuses(db, pid)
    with db._tx() as c:
        c.execute("UPDATE projects SET hub_app_id = NULL WHERE id = ?", (pid,))
    assert set_statuses(db, pid) == row_statuses(db, pid)
    db.update_project(pid, hub_app_id=7)
    db.set_settings({"hub_url": "https://other.example.org"})
    assert set_statuses(db, pid) == row_statuses(db, pid)


def test_old_write_competes_only_within_the_current_assignment(web):  # noqa: F811
    """Ревью 0.10.0.dev31: прежние записи статуса без принятой версии – последняя выполненная запись выбирается
    в текущем назначении проекта (адрес Hub из настроек, номер приложения проекта), даже если в другом назначении
    или другом проекте у того же номера запись новее; после смены назначения – запись нового назначения. Номер с
    пробелами и ведущими нулями сравнивается строкой, как в построчном выражении."""
    db = web.app.state.db
    findings = [Finding(hub_id=h, kind="SAST", status="Open") for h in ("201", "202", "0203", " 204")]
    pid = project(web, findings)
    other = project(web, [Finding(hub_id="201", kind="SAST", status="Open")])
    with db._tx() as c:
        def op(project_id, status, targets, hub=HUB, app=7):
            c.execute("INSERT INTO hub_ops(project_id, hub_url, app_id, purpose, state, request_json, targets_json, op_key,"
                      " created_at, updated_at) VALUES (?, ?, ?, 'status', 'done', ?, ?, ?, '2026-11-11', '2026-11-11')",
                      (project_id, hub, app, dumps({"body": {"status": status}}), dumps([{"hub_id": t} for t in targets]),
                       f"w-{project_id}-{status}-{'-'.join(targets)}-{hub}-{app}"))
        op(pid, "False Positive", ["201", "202"])                   # текущее назначение
        op(pid, "Fixed", ["201"], hub="https://other.example.org")  # новее, другой Hub
        op(pid, "Accepted risk", ["201"], app=8)                    # новее, другое приложение
        op(other, "Confirmed", ["201"])                             # новее, другой проект
        op(pid, "Confirmed", ["202"])                               # новее, то же назначение
        op(pid, "False Positive", ["0203", "204"])                  # номер как в выгрузке не совпадает
        op(pid, "Accepted risk", [" 204"])                          # номер с пробелом – строкой
    row, got = row_statuses(db, pid), set_statuses(db, pid)
    assert got == row, {k: (row.get(k), got.get(k)) for k in set(row) | set(got) if row.get(k) != got.get(k)}
    assert row["201"] == "False Positive" and row["202"] == "Confirmed"
    assert row["0203"] == "False Positive" and row[" 204"] == "Accepted risk"
    db.update_project(pid, hub_app_id=8)
    row = row_statuses(db, pid)
    assert set_statuses(db, pid) == row and row["201"] == "Accepted risk" and row["202"] == "Open"
    db.update_project(pid, hub_app_id=7)
    db.set_settings({"hub_url": "https://other.example.org/"})
    row = row_statuses(db, pid)
    assert set_statuses(db, pid) == row and row["201"] == "Fixed"

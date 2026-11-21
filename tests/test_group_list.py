"""«Вся группа в списке» (О3): группа SAST больше 50 – из карточки ссылка на список находок с отбором по точному ключу
группы второй редакции (ADR-0095); в списке – только находки группы и строка с якорной находкой; счётчик «другой код» –
полный. Выгрузка выдуманная."""

from __future__ import annotations

import re

from hub_fixtures import SAST_ROWS, make_hub_xlsx
from test_web import ORIGIN, create_project, upload, web  # noqa: F401

GROUP = [f"53{n:04d}" for n in range(55)]


def group_project(web) -> int:  # noqa: F811
    """55 находок одной строки и категории в разных кодовых базах, плюс находка той же категории на другой строке."""
    rows = [dict(SAST_ROWS[0], **{"Issue id": hub_id, "Codebase": f"cb-{n}"}) for n, hub_id in enumerate(GROUP)]
    rows.append(dict(SAST_ROWS[0], **{"Issue id": "539999", "Line number": "999"}))
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "group.xlsx", sast=rows)).status_code == 303
    return pid


def finding_id(web, pid: int, hub_id: str) -> int:  # noqa: F811
    return web.app.state.db.get_finding_by_hub_id(pid, hub_id)["id"]


def test_db_filter_selects_exactly_the_group(web):  # noqa: F811
    pid = group_project(web)
    db = web.app.state.db
    cond, params = db._filter_sql(pid, {"group": finding_id(web, pid, GROUP[3])})
    hub_ids = {r["hub_id"] for r in db._all(f"SELECT f.hub_id {db._LIST_FROM} WHERE {cond}", params)}
    assert hub_ids == set(GROUP), "другая строка той же категории – не группа"
    cond, params = db._filter_sql(pid, {"group": 10 ** 9})
    assert db._all(f"SELECT f.hub_id {db._LIST_FROM} WHERE {cond}", params) == [], "чужой id – пусто, не весь проект"


def test_card_links_to_the_whole_group_and_list_shows_it(web):  # noqa: F811
    pid = group_project(web)
    fid = finding_id(web, pid, GROUP[0])
    page = web.client.get(f"/projects/{pid}/findings/{fid}").text
    link = re.search(r'<a id="group-all" href="([^"]+)">вся группа в списке находок \((\d+)\)</a>', page)
    assert link and link.group(2) == "55", "ссылка «вся группа» с числом находок группы"
    assert "Показаны первые 50 из 54" in page
    listing = web.client.get(link.group(1).replace("&amp;", "&")).text
    assert 'id="group-filter"' in listing and GROUP[0] in listing
    assert "Показано 55 из 55" in listing, "в списке – вся группа"
    assert all(hub_id in listing for hub_id in GROUP)
    assert "539999" not in listing
    assert "Снять отбор группы" in listing


def test_bad_group_parameter_selects_nothing(web):  # noqa: F811
    pid = group_project(web)
    for value in ("1x", "0", "000", ""):
        page = web.client.get(f"/projects/{pid}/findings?group={value}").text
        assert "находки, по которой он задан, в проекте нет" in page, value
        assert "539999" not in page and GROUP[0] not in page, value
    assert "539999" in web.client.get(f"/projects/{pid}/findings").text


def test_other_code_count_is_full_not_first_fifty(web):  # noqa: F811
    pid = group_project(web)
    db = web.app.state.db
    with db._tx() as c:
        for n, hub_id in enumerate(GROUP):
            c.execute("INSERT INTO cases(project_id, hub_id, case_hash, context_json, updated_at, code_cmp)"
                      " VALUES (?, ?, 'h', '{}', '2026-10-23', ?)", (pid, hub_id, "mine" if n == 0 else "other"))
    page = web.client.get(f"/projects/{pid}/findings/{finding_id(web, pid, GROUP[0])}").text
    assert "другой код – ещё 54." in page
    assert 'id="group-other-all"' in page and "Показаны первые 50 из 54" in page



def test_zero_other_project_and_sca_anchor_select_nothing(web):  # noqa: F811
    pid = group_project(web)
    db = web.app.state.db
    other = group_project(web)
    from app.routes.findings import queue_neighbor
    assert queue_neighbor(db, pid, None, {"group": "0"}) is None, "ноль – пустая очередь, не весь проект"
    foreign = finding_id(web, other, GROUP[0])
    cond, params = db._filter_sql(pid, {"group": foreign})
    assert db._all(f"SELECT f.hub_id {db._LIST_FROM} WHERE {cond}", params) == [], "якорь из другого проекта"
    with db._tx() as c:
        c.execute("UPDATE findings SET kind = 'SCA' WHERE project_id = ? AND hub_id = ?", (pid, GROUP[1]))
    cond, params = db._filter_sql(pid, {"group": finding_id(web, pid, GROUP[1])})
    assert db._all(f"SELECT f.hub_id {db._LIST_FROM} WHERE {cond}", params) == [], "якорь не SAST"


def test_queue_walks_inside_the_group(web):  # noqa: F811
    from app.routes.findings import queue_neighbor
    pid = group_project(web)
    db = web.app.state.db
    anchor = db.get_finding_by_hub_id(pid, GROUP[0])
    selection = {"group": str(anchor["id"]), "sort": "severity_desc"}
    seen, current = set(), None
    for _ in range(60):
        nxt = queue_neighbor(db, pid, current, selection)
        if nxt is None or nxt in seen:
            break
        seen.add(nxt)
        current = db.get_finding(pid, nxt)
    assert {db.get_finding(pid, i)["hub_id"] for i in seen} == set(GROUP)


def test_missing_anchor_counts_the_group_as_the_link_shows_it(web):  # noqa: F811
    pid = group_project(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE findings SET missing = 1 WHERE project_id = ? AND hub_id = ?", (pid, GROUP[0]))
    page = web.client.get(f"/projects/{pid}/findings/{finding_id(web, pid, GROUP[0])}").text
    assert "вся группа в списке находок (54)" in page


def test_queue_neighbor_from_descriptors_matches_the_database(web, monkeypatch):  # noqa: F811
    """PERF-03: страница списка отдаёт обходу уже прочитанные дескрипторы – база читается один раз; ответ тот же,
    что при чтении базы: вся последовательность обхода, при пустом отборе (kind=SAST, missing=no по умолчанию) и при
    явном, с пропавшими находками в проекте."""
    from app.db import Database
    from app.routes.findings import queue_neighbor, selection_filters
    pid = group_project(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE findings SET missing = 1 WHERE project_id = ? AND hub_id IN (?, ?)", (pid, GROUP[0], GROUP[3]))

    def walk(selection, descriptors=None):
        ids, anchor = [], None
        while True:
            nxt = queue_neighbor(db, pid, anchor, selection, descriptors=descriptors, wrap=False)
            if nxt is None or nxt in ids:
                return ids
            ids.append(nxt)
            anchor = db.get_finding(pid, nxt)

    for selection in ({}, {"kind": "SAST"}, {"sort": "severity_desc"}, {"verdict": "none"}, {"missing": "yes"},
                      {"missing": "no"}, {"group": str(finding_id(web, pid, GROUP[1]))}):
        descriptors = db.finding_descriptors(pid, selection_filters(selection))
        expected = walk(selection)
        assert walk(selection, descriptors) == expected, selection
        if selection.get("missing") == "yes":
            assert len(expected) == 2, "пропавшие находки в очереди есть"
        elif not selection.get("group"):
            assert finding_id(web, pid, GROUP[0]) not in expected, "пропавшая находка по умолчанию исключена"

    calls = []
    original = Database.finding_descriptors
    monkeypatch.setattr(Database, "finding_descriptors", lambda self, *a, **k: calls.append(a) or original(self, *a, **k))
    assert web.client.get(f"/projects/{pid}/findings").status_code == 200
    assert len(calls) == 1, "страница списка читает дескрипторы один раз"

"""Сохранённые рабочие отборы списка компонентов (В14, ADR-0110, схема 24): миграция, канонизация отбора, страница,
сохранение, замена, предел, удаление, пометка утраченных условий. Данные выдуманы."""

from __future__ import annotations

import re
from db_support import connect_db
from pathlib import Path

from app.db import SAVED_FILTERS_MAX, Database
from app.routes.components import lost_conditions, saved_query
from hub_fixtures import SCA_ROWS
from test_component_research_ui import project_with_components
from test_web import ORIGIN, web  # noqa: F401


def schema_of(path: Path) -> int:
    con = connect_db(path)
    try:
        return int(con.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0])
    finally:
        con.close()


# ============================================================================ схема 24

def test_save_replaces_by_name_case_insensitively_and_keeps_the_limit(tmp_path: Path):
    db = Database(tmp_path / "triage.db")
    pid = db.create_project("p")
    first = db.save_component_filter(pid, "Уязвимые", "status=vulnerable")
    again = db.save_component_filter(pid, "уязвимые", "q=log4j&status=vulnerable")
    assert again == {"state": "updated", "id": first["id"]}
    rows = db.saved_component_filters(pid)
    assert len(rows) == 1 and rows[0]["name"] == "уязвимые" and rows[0]["query"] == "q=log4j&status=vulnerable"
    for n in range(SAVED_FILTERS_MAX - 1):
        assert db.save_component_filter(pid, f"Отбор {n}", f"q=x{n}")["state"] == "created"
    assert db.save_component_filter(pid, "Ещё один", "q=y")["state"] == "limit"
    assert db.save_component_filter(pid, "Отбор 3", "q=z")["state"] == "updated", "при пределе замена разрешена"
    db.close()


# ============================================================================ канонизация отбора

def test_saved_query_keeps_only_effective_conditions():
    assert saved_query("q=%20log4j%20&status=vulnerable&page=3&ok=decision&bogus=1") == (
        "q=log4j&status=vulnerable", True)
    assert saved_query("cvss_ver=3.1&cvss_op=gt&cvss_from=7,5") == ("cvss_from=7.5&cvss_op=gt&cvss_ver=3.1", True)
    assert saved_query("cvss_op=ge&sort=name_asc&page_size=50") == ("page_size=50&sort=name_asc", False), \
        "сортировка, размер страницы и cvss_op без условия CVSS – не отбор"
    assert saved_query("page_size=200") == ("", False), "размер по умолчанию не хранится"
    assert saved_query("cvss_from=8&cvss_to=7")[1], "условие без совпадений – тоже условие"
    family = "0123456789abcdef01234567"
    assert saved_query(f"group_by=family&family={family}") == (f"family={family}&group_by=family", True)


def test_canonical_form_is_stable_and_never_marked_lost():
    """Ревью Codex, круг 25: каноническая строка – неподвижная точка, у свежесохранённого отбора пометки нет."""
    for text in ("q=%20log4j%20&status=vulnerable&page=3&ok=decision&bogus=1", "cvss_ver=3.1&cvss_op=gt&cvss_from=7,5",
                 "cvss_op=ge&score=unknown&sort=name_asc&page_size=50", "decision=none&stale=1&ecosystem=npm",
                 "support=eol&advice=update&action=none&review_due=1&age=90&gaps=1",
                 "group_by=family&family=0123456789abcdef01234567&cvss_to=9"):
        canonical = saved_query(text)[0]
        assert saved_query(canonical)[0] == canonical, text
        assert lost_conditions(canonical) == [], text


def test_lost_conditions_compares_with_the_current_canonical_form():
    assert lost_conditions("q=log4j&status=vulnerable") == []
    assert lost_conditions("q=log4j&status=bogus") == ["status=bogus"]
    assert lost_conditions("removed=1") == ["removed=1"]


# ============================================================================ страница

def page(web, pid: int, query: str = "") -> str:  # noqa: F811
    return web.client.get(f"/projects/{pid}/components" + (f"?{query}" if query else "")).text


def save(web, pid: int, name: str, query: str):  # noqa: F811
    return web.client.post(f"/projects/{pid}/components/filters", headers=ORIGIN, follow_redirects=False,
                           data={"name": name, "query": query})


def row_links(html: str) -> list[str]:
    return re.findall(r'data-row-link href="(/projects/\d+/components/[^"?]+)', html)


def test_save_open_and_delete_through_the_page(web):  # noqa: F811
    pid = project_with_components(web)
    html = page(web, pid, "status=unresearched&page=2")
    hidden = re.search(r'id="save-filter-form".*?name="query" value="([^"]*)"', html, re.S).group(1)
    assert hidden == "status=unresearched", "сохраняется показанный отбор без номера страницы"
    r = save(web, pid, "<b>Не исследованы</b>", hidden)
    assert r.status_code == 303 and r.headers["location"].endswith("status=unresearched&ok=filter_saved")
    html = page(web, pid)
    assert "&lt;b&gt;Не исследованы&lt;/b&gt;" in html and "<b>Не исследованы</b>" not in html
    link = re.search(r'<a href="(/projects/\d+/components\?status=unresearched)" class="chip">', html).group(1)
    opened = web.client.get(link).text
    assert 'value="unresearched" selected' in opened
    assert row_links(opened) == row_links(page(web, pid, "status=unresearched")) and row_links(opened)
    db = web.app.state.db
    fid = db.saved_component_filters(pid)[0]["id"]
    r = web.client.post(f"/projects/{pid}/components/filters/{fid}/delete", headers=ORIGIN, follow_redirects=False,
                        data={"query": "q=abc"})
    assert r.status_code == 303 and r.headers["location"].endswith("q=abc&ok=filter_deleted")
    assert db.saved_component_filters(pid) == []
    other = web.client.post(f"/projects/{pid}/components/filters/{fid}/delete", headers=ORIGIN, data={"query": ""})
    assert other.status_code == 404


def test_foreign_filter_is_not_deleted_and_origin_is_checked(web):  # noqa: F811
    first = project_with_components(web)
    second = project_with_components(web)
    db = web.app.state.db
    fid = db.save_component_filter(first, "Чужой", "status=vulnerable")["id"]
    r = web.client.post(f"/projects/{second}/components/filters/{fid}/delete", headers=ORIGIN, data={"query": ""})
    assert r.status_code == 404 and len(db.saved_component_filters(first)) == 1
    bad = {"Origin": "http://evil.example"}
    r = web.client.post(f"/projects/{first}/components/filters", headers=bad, follow_redirects=False,
                        data={"name": "Через чужой сайт", "query": "q=parser"})
    assert r.status_code == 403
    r = web.client.post(f"/projects/{first}/components/filters/{fid}/delete", headers=bad, follow_redirects=False,
                        data={"query": ""})
    assert r.status_code == 403
    assert [f["name"] for f in db.saved_component_filters(first)] == ["Чужой"]


def test_refusal_and_deletion_keep_the_shown_page(web):  # noqa: F811
    """Ревью Codex, круг 25: отказ формы и удаление отбора возвращают на ту же страницу показанного списка."""
    rows = []
    for index in range(30):
        source = dict(SCA_ROWS[index % len(SCA_ROWS)])
        source["Issue id"] = str(910000 + index)
        source["Component name"] = f"org.example:paged-{index:02d}"
        source["Component version"] = "1.0.0"
        rows.append(source)
    pid = project_with_components(web, rows=rows)
    first, shown = page(web, pid, "page_size=25"), page(web, pid, "page_size=25&page=2")
    assert 'name="page" value="2"' in shown and row_links(shown) and row_links(shown) != row_links(first)
    r = web.client.post(f"/projects/{pid}/components/filters", headers=ORIGIN, follow_redirects=False,
                        data={"name": "", "query": "page_size=25", "page": "2"})
    assert r.status_code == 422 and row_links(r.text) == row_links(shown)
    fid = web.app.state.db.save_component_filter(pid, "Любой", "q=a")["id"]
    r = web.client.post(f"/projects/{pid}/components/filters/{fid}/delete", headers=ORIGIN, follow_redirects=False,
                        data={"query": "page_size=25", "page": "2"})
    assert r.status_code == 303 and r.headers["location"].endswith("page_size=25&page=2&ok=filter_deleted")


def test_long_query_is_not_cut_silently(web):  # noqa: F811
    """Ревью Codex, круг 25: строка отбора не усекается – условие после длинного поиска не теряется."""
    pid = project_with_components(web)
    long_search = "q=" + "%F0%9F%94%92" * 100
    r = save(web, pid, "Длинный", long_search + "&status=vulnerable")
    assert r.status_code == 303
    assert "status=vulnerable" in web.app.state.db.saved_component_filters(pid)[0]["query"]


def test_refusals_keep_the_shown_list_and_the_name(web):  # noqa: F811
    pid = project_with_components(web)
    r = save(web, pid, "   ", "q=parser")
    assert r.status_code == 422 and "Назовите отбор" in r.text and 'value="parser"' in r.text
    r = save(web, pid, "x" * 61, "q=parser")
    assert r.status_code == 422 and "длиннее 60" in r.text and "x" * 61 in r.text
    r = save(web, pid, "Весь список", "sort=name_asc")
    assert r.status_code == 422 and "нет условий" in r.text
    db = web.app.state.db
    for n in range(SAVED_FILTERS_MAX):
        db.save_component_filter(pid, f"Отбор {n}", f"q=x{n}")
    r = save(web, pid, "Ещё", "q=parser")
    assert r.status_code == 422 and "Сохранено уже 30" in r.text and 'value="Ещё"' in r.text


def test_name_loses_control_and_format_characters(web):  # noqa: F811
    pid = project_with_components(web)
    r = save(web, pid, "  a" + chr(0) + "b" + chr(0x202E) + "c" + chr(9) + chr(10) + "d  ", "q=parser")
    assert r.status_code == 303
    assert [f["name"] for f in web.app.state.db.saved_component_filters(pid)] == ["abc d"]


def test_saved_filter_with_lost_conditions_is_marked(web):  # noqa: F811
    pid = project_with_components(web)
    db = web.app.state.db
    db.save_component_filter(pid, "Старый", "q=parser&status=bogus")
    db.save_component_filter(pid, "Пустой", "removed=1")
    html = page(web, pid)
    assert "часть условий больше не действует" in html and "status=bogus" in html
    assert "ни одно условие больше не действует – откроется весь список" in html and "removed=1" in html
    assert db.saved_component_filters(pid)[1]["query"] == "q=parser&status=bogus", "запись при показе не меняется"

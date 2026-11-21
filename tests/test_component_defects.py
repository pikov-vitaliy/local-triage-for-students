"""Вкладка «Компоненты» (0.9.26.dev17): у компонента, находки которого входят в дефект
приложения, – значок «дефект ID<n> · №<Hub>» со ссылкой на карточку дефекта; счётчик «В дефекте»; отбор «Дефект».
Данные выдуманы."""

from __future__ import annotations

import re

from app.models import Finding
from app.routes.components import defects_by_component
from app.sca_contract import input_ref
from app.triage import order_findings
from test_web import create_project, web  # noqa: F401

HUB = "https://hub.example.org"


def seed(web) -> int:
    db = web.app.state.db
    pid = create_project(web.client)
    db.update_project(pid, hub_app_id=7)
    findings = [Finding(hub_id=h, kind="SCA", component="example-parser", version="1.4.2", build_type="pypi",
                        cve=["CVE-2099-0001"], cvss=8.1) for h in ("73001", "73002")]
    findings.append(Finding(hub_id="73003", kind="SCA", component="demo-xml", version="2.0.0", build_type="pypi",
                            cve=["CVE-2099-0002"], cvss=7.5))
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings(findings))
    return pid


def defect(web, pid: int, hub_ids, number: int, state: str = "done", hub_defect_id: str = "90092") -> dict:
    db = web.app.state.db
    row = db.hub_defect_insert(pid, kind="SCA", number=number, summary=f"ID{number} - example-parser (SCA)",
                               anchor_hub_id=hub_ids[0], targets=[{"hub_id": h, "issue_type": "SCA_S"} for h in hub_ids],
                               number_keys=[], command_text="Текст", hub_url=HUB, app_id=7)
    if state != "blank":
        db.hub_defect_update(row["id"], state=state, hub_defect_id=hub_defect_id)
    return db.hub_defect(row["id"])


def rows_of(html: str) -> dict[str, str]:
    """Разметка строк таблицы компонентов по input_ref."""
    return dict(re.findall(r'<tr id="component-([^"]+)"(.*?)</tr>', html, re.S))


def test_component_in_defect_has_badge_filter_and_stat(web):
    pid = seed(web)
    row = defect(web, pid, ["73001", "73002"], 12)
    parser, xml = input_ref("pypi", "example-parser", "1.4.2"), input_ref("pypi", "demo-xml", "2.0.0")
    found = defects_by_component(web.app.state.db, pid)
    assert list(found) == [parser] and len(found[parser]) == 1
    assert {k: found[parser][0][k] for k in ("id", "number", "hub_defect_id", "state", "label", "done", "card_url", "text")} == {
        "id": row["id"], "number": 12, "hub_defect_id": "90092", "state": "done", "label": "создан", "done": True,
        "card_url": f"/projects/{pid}/defects/{row['id']}", "text": "ID12 · №90092"}
    html = web.client.get(f"/projects/{pid}/components").text
    rows = rows_of(html)
    assert set(rows) == {parser, xml}
    assert f'href="/projects/{pid}/defects/{row["id"]}"' in rows[parser] and "дефект ID12 · №90092" in rows[parser]
    assert "component-defect" not in rows[xml]
    assert 'name="defect"' in html and 'href="/projects/' + str(pid) + '/components?defect=in"' in html
    # отбор «в дефекте» / «без дефекта»; неизвестное значение – не отбирает
    assert set(rows_of(web.client.get(f"/projects/{pid}/components?defect=in").text)) == {parser}
    assert set(rows_of(web.client.get(f"/projects/{pid}/components?defect=none").text)) == {xml}
    assert set(rows_of(web.client.get(f"/projects/{pid}/components?defect=zzz").text)) == {parser, xml}
    # карточка компонента – тот же значок
    card = web.client.get(f"/projects/{pid}/components/{parser}").text
    assert 'id="component-defects"' in card and "дефект ID12 · №90092" in card
    assert 'id="component-defects"' not in web.client.get(f"/projects/{pid}/components/{xml}").text


def test_unfinished_cancelled_and_failed_defects(web):
    """Дефект не в состоянии «создан» показан с его состоянием; отменённый и не принятый Hub – не дефект."""
    pid = seed(web)
    parser = input_ref("pypi", "example-parser", "1.4.2")
    blank = defect(web, pid, ["73001"], 3, state="blank")
    html = rows_of(web.client.get(f"/projects/{pid}/components").text)[parser]
    assert "подготовка дефекта ID3 · заготовка запрошена" in html and "badge-warn" in html
    db = web.app.state.db
    db.hub_defect_update(blank["id"], state="cancelled")
    assert "component-defect" not in rows_of(web.client.get(f"/projects/{pid}/components").text)[parser]
    failed = defect(web, pid, ["73002"], 4, state="failed", hub_defect_id="")
    assert failed["state"] == "failed"
    assert "component-defect" not in rows_of(web.client.get(f"/projects/{pid}/components").text)[parser]
    # сводка: «В дефекте» 0 → после созданного дефекта 1
    defect(web, pid, ["73001", "73002"], 5)
    html = web.client.get(f"/projects/{pid}/components").text
    assert "дефект ID5 · №90092" in html
    stat = re.search(r'href="/projects/%d/components\?defect=in">(.*?)</a>' % pid, html, re.S).group(1)
    assert ">1<" in stat and "В дефекте" in stat

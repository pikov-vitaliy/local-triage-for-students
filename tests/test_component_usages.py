"""О14 (этап Б плана): карточка исследования компонента показывает, где используется версия (OR-04: находки выгрузки
по кодовым базам с переходом к ним), сводка списка – отдельные счётчики пробелов и неизвестной поддержки (OR-07).
Выгрузка выдуманная."""

from __future__ import annotations

from app import sca_research as research
from test_sca_research_routes import CODEBASE, HUB_ID, build_task, project_with_sca
from test_web import web  # noqa: F401


def test_component_card_lists_where_the_version_is_used(web):  # noqa: F811
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    db = web.app.state.db
    ref = next(row["input_ref"] for row in manifest["rows"]
               if any(u["hub_id"] == HUB_ID for u in db.sca_usages(pid, row["input_ref"])))
    usages = db.sca_usages(pid, ref)
    assert usages and all(u["hub_id"] for u in usages)
    page = web.client.get(f"/projects/{pid}/components/{ref}").text
    assert 'id="component-usages"' in page
    fid = db.get_finding_by_hub_id(pid, HUB_ID)["id"]
    assert f'href="/projects/{pid}/sca/findings/{fid}?back=' in page and CODEBASE in page


def test_usages_of_another_version_and_an_unknown_ref_are_empty(web):  # noqa: F811
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    db = web.app.state.db
    refs = [row["input_ref"] for row in manifest["rows"]]
    found = [{u["hub_id"] for u in db.sca_usages(pid, ref)} for ref in refs]
    assert all(found) and not set.intersection(*found), "у каждой версии – свои находки"
    assert db.sca_usages(pid, "unk:0000000000000000") == []


def test_summary_counts_gaps_and_unknown_support_separately():
    rows = [
        {"status": "vulnerable", "researched": True, "decided": False, "decision_stale": False, "gaps": 2,
         "support_state": "unknown"},
        {"status": "no_known_vulnerabilities", "researched": True, "decided": True, "decision_stale": False,
         "gaps": 0, "support_state": "supported"},
        {"status": "", "researched": False, "decided": False, "decision_stale": False, "gaps": 0,
         "support_state": ""},
    ]
    summary = research.summaries(rows)
    assert summary["vulnerable"] == 1, "пробелы и неизвестная поддержка не прячут «уязвим»"
    assert summary["with_gaps"] == 1 and summary["support_unknown"] == 1, "неисследованные не считаются"


def test_invisible_mark_in_the_name_keeps_the_usage(tmp_path):
    """Имя с невидимым знаком (U+200B) в выгрузке: ключ задания и ключ места использования совпадают."""
    from app import sca
    from app.db import Database
    from app.models import Finding
    from app.sca_contract import input_ref
    from app.triage import order_findings
    db = Database(tmp_path / "t.db")
    try:
        pid = db.create_project("p")
        rows = [Finding(hub_id="1", kind="SCA", component="example-\u200bparser", version="1.4.2", codebase="a",
                        build_type="maven"),
                Finding(hub_id="2", kind="SCA", component="example-parser", version="1.4.3", codebase="b",
                        build_type="maven"),
                Finding(hub_id="3", kind="SCA", component="example-parser", version="1.4.2", codebase="c",
                        build_type="maven")]
        db.save_import(pid, "a.xlsx", "xlsx", [], {}, [], order_findings(rows))
        packages, _ = sca.package_report(db.sca_components(pid))
        refs = {(p["component"], p["version"]): input_ref(p["ecosystem"], p["component"], p["version"])
                for p in packages}
        assert {u["hub_id"] for u in db.sca_usages(pid, refs[("example-parser", "1.4.2")])} == {"1", "3"}
        assert {u["hub_id"] for u in db.sca_usages(pid, refs[("example-parser", "1.4.3")])} == {"2"}, \
            "другая версия того же имени – отдельно"
        db.save_import(pid, "b.xlsx", "xlsx", [], {}, [], order_findings(rows[1:]))  # находка 1 ушла из выгрузки
        assert {u["hub_id"] for u in db.sca_usages(pid, refs[("example-parser", "1.4.2")])} == {"3"}
    finally:
        db.close()


def test_usage_link_returns_to_the_component(web):  # noqa: F811
    from urllib.parse import quote, urlencode
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    db = web.app.state.db
    ref = next(row["input_ref"] for row in manifest["rows"] if db.sca_usages(pid, row["input_ref"]))
    usage = db.sca_usages(pid, ref)[0]
    component_url = f"/projects/{pid}/components/{ref}?" + urlencode({"back": f"/projects/{pid}/components"})
    page = web.client.get(component_url).text
    assert f'/sca/findings/{usage["id"]}?back={quote(component_url, safe="")}' in page
    card = web.client.get(f"/projects/{pid}/sca/findings/{usage['id']}?back={quote(component_url, safe='')}").text
    assert f'href="{component_url}"' in card.replace("&amp;", "&"), "возврат – к карточке компонента с её отбором"
    foreign = web.client.get(f"/projects/{pid}/sca/findings/{usage['id']}?back=/evil/components/x").text
    assert "/evil/" not in foreign


def test_return_to_the_component_survives_a_save(web):  # noqa: F811
    """После сохранения в карточке находки SCA адрес возврата остаётся карточкой компонента с её отбором."""
    from urllib.parse import parse_qs, quote, urlencode, urlsplit

    from app.routes.sca import redirect_with_back
    from types import SimpleNamespace
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    db = web.app.state.db
    ref = next(row["input_ref"] for row in manifest["rows"] if db.sca_usages(pid, row["input_ref"]))
    component_url = f"/projects/{pid}/components/{ref}?" + urlencode({"back": f"/projects/{pid}/components"})
    request = SimpleNamespace(query_params={"back": component_url}, path_params={"project_id": pid})
    response = redirect_with_back(request, f"/projects/{pid}/sca/findings/7?ok=sca_saved")
    location = urlsplit(response.headers["location"])
    assert parse_qs(location.query)["back"] == [component_url]
    other = SimpleNamespace(query_params={"back": "/projects/1/components/../../evil"}, path_params={"project_id": pid})
    assert "evil" not in redirect_with_back(other, f"/projects/{pid}/sca/findings/7").headers["location"]
    assert quote  # noqa: B018


def test_sca_card_shows_the_component_research_and_overview_counts_components(web):  # noqa: F811
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, HUB_ID)["id"]
    card = web.client.get(f"/projects/{pid}/sca/findings/{fid}").text
    assert 'id="component-research"' in card and "Ответа агента по этой версии пока нет" in card
    ref = next(row["input_ref"] for row in manifest["rows"]
               if any(u["hub_id"] == HUB_ID for u in db.sca_usages(pid, row["input_ref"])))
    assert f'href="/projects/{pid}/components?q=' in card and "Найти компонент в списке" in card, \
        "без исследования – поиск в списке, а не карточка, которой нет"
    assert ref
    overview = web.client.get(f"/projects/{pid}").text
    assert 'id="component-stats"' in overview and "Компоненты исследованы" in overview
    assert f"0 из {len(manifest['rows'])}" in overview



def test_overview_counts_researched_decided_and_stale(web):  # noqa: F811
    from test_sca_research_routes import decide, kit_answer, upload_answer
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    assert upload_answer(web, pid, kit_answer(manifest)).status_code == 303
    first = manifest["rows"][0]["input_ref"]
    assert decide(web, pid, first, action="investigate", rationale="Ждём подтверждение").status_code == 303
    db = web.app.state.db
    refs = {row["input_ref"] for row in manifest["rows"]}
    counts = db.component_counts(pid, refs)
    assert counts == {"total": len(refs), "researched": len(refs), "decided": 1, "stale": 0}
    with db._tx() as c:
        c.execute("UPDATE sca2_decisions SET review_at = '2000-01-01' WHERE project_id = ? AND input_ref = ?",
                  (pid, first))
    assert db.component_counts(pid, refs)["stale"] == 1, "наступивший пересмотр"
    overview = web.client.get(f"/projects/{pid}").text
    assert f"{len(refs)} из {len(refs)}" in overview and "требуют пересмотра 1" in overview



def test_review_date_is_parsed_the_same_in_card_and_counts(web):  # noqa: F811
    from app import sca_research as research
    from datetime import date
    assert research.review_due(date.today().strftime("%Y%m%d")), "компактная запись даты – тоже дата"
    assert not research.review_due("2000-99-99") and not research.review_due("")
    from test_sca_research_routes import decide
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    first = manifest["rows"][0]["input_ref"]
    assert decide(web, pid, first, action="investigate", rationale="Ждём").status_code == 303
    db = web.app.state.db
    refs = {row["input_ref"] for row in manifest["rows"]}
    for value, due in (("2000-99-99", 0), (date.today().strftime("%Y%m%d"), 1)):
        with db._tx() as c:
            c.execute("UPDATE sca2_decisions SET review_at = ? WHERE project_id = ? AND input_ref = ?",
                      (value, pid, first))
        assert db.component_counts(pid, refs)["stale"] == due, value

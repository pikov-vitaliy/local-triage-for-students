"""ADR-0096: отборы списка компонентов по сохранённому ответу агента – поиск по идентификаторам и координатам, балл
CVSS по версии шкалы с «≥»/«>» и верхней границей, четыре вида строки без балла и признак «оценка неполная»,
оспоренная применимая находка балл сохраняет, отборы поддержки, совета, действия, наступившего пересмотра и
свежести; неизвестные значения отбрасываются; отборы не обращаются к сети. Данные выдуманы."""

from __future__ import annotations

import socket
from datetime import date, timedelta

from app import sca_research as research
from test_web import web  # noqa: F401


def finding(applies="yes", score=None, version="3.1", fid="CVE-2099-0001", aliases=(), disputed=None):
    item = {"id": fid, "aliases": list(aliases), "applies": applies}
    item["cvss"] = None if score is None else {"score": score, "version": version, "vector": None}
    if disputed is not None:
        item["disputed"] = disputed
    return item


def row(name="example-parser", findings=(), researched=True, support="supported", advice="update", decision=None,
        fresh=None, gaps=0, coordinates="", reasons=()):
    ids = sorted({str(v).casefold() for f in findings for v in (f["id"], *f["aliases"])})
    return {"name": name, "version": "1.4.2", "ecosystem": "maven", "status": "vulnerable" if researched else "",
            "researched": researched, "decided": bool(decision), "decision_stale": bool(reasons),
            "decision_reasons": list(reasons), "decision": decision, "findings": list(findings),
            "support_state": support if researched else "", "advice": advice if researched else "",
            "fresh_at": fresh or date.today().isoformat(), "gaps": gaps, "search_ids": ids,
            "coordinates": coordinates}


def names(rows, **filters):
    return [r["name"] for r in research.filter_rows(rows, filters)]


def test_search_by_cve_alias_and_coordinates():
    rows = [row("a", [finding(fid="CVE-2099-1111", aliases=["GHSA-aaaa-bbbb-cccc"])]),
            row("b", coordinates="pkg:maven/org.example/parser@1.4.2"), row("c")]
    assert names(rows, q="cve-2099-1111") == ["a"]
    assert names(rows, q="GHSA-AAAA") == ["a"]
    assert names(rows, q="org.example/parser") == ["b"]


def test_cvss_bounds_strict_and_inclusive():
    rows = [row("seven", [finding(score=7.0)]), row("eight", [finding(score=8.1)]), row("zero", [finding(score=0.0)])]
    assert names(rows, cvss_from="7") == ["seven", "eight"], "«не ниже» включает границу"
    assert names(rows, cvss_from="7", cvss_op="gt") == ["eight"], "«строго выше» – нет"
    assert names(rows, cvss_to="7") == ["seven", "zero"], "«до» включительно; ноль – известный балл"
    assert names(rows, cvss_from="8", cvss_to="7") == [], "от больше до – пусто"
    assert research.score_filter({"cvss_from": "8", "cvss_to": "7"})["empty"]


def test_cvss_version_and_its_normalisation():
    rows = [row("v31", [finding(score=9.0, version="CVSS:3.1")]), row("v40", [finding(score=9.5, version="4.0")]),
            row("none", [finding(score=9.9, version=None)])]
    assert names(rows, cvss_ver="3.1", cvss_from="8") == ["v31"]
    assert names(rows, cvss_from="9.6") == ["none"], "«любая» включает «версия не указана»"
    assert research.cvss_version("v3.1") == "3.1" and research.cvss_version("x") == ""


def test_four_kinds_without_score_and_the_incomplete_mark():
    rows = [row("unres", researched=False), row("unknown", [finding(applies="unknown", score=9.8)]),
            row("noapp", [finding(applies="no", score=9.8)]), row("noscore", [finding()]),
            row("partial", [finding(score=8.0), finding(fid="CVE-2099-2")])]
    kinds = {r["name"]: research.row_score(r)["kind"] for r in rows}
    assert kinds == {"unres": "unresearched", "unknown": "applies_unknown", "noapp": "none_applicable",
                     "noscore": "score_unknown", "partial": ""}
    assert research.row_score(rows[4]) == {"kind": "", "score": 8.0, "incomplete": True}
    assert names(rows, cvss_from="7", cvss_op="gt") == ["partial"], "без балла в отбор по CVSS не входят"
    for kind in research.SCORE_KINDS:
        assert len(names(rows, score=kind)) == 1, kind


def test_disputed_applicable_finding_keeps_its_score():
    r = row("d", [finding(score=9.8, disputed={"by": "vendor", "note": "оспорено", "source_refs": []})])
    assert research.row_score(r)["score"] == 9.8
    assert names([r], cvss_from="9") == ["d"]


def test_support_advice_action_review_and_age():
    old = (date.today() - timedelta(days=100)).isoformat()
    rows = [row("eol", support="eol", advice="replace", fresh=old, gaps=2),
            row("unknown", support="unknown", decision={"action": "accept_risk"}, reasons=["review_date"]),
            row("fresh", decision={"action": "update"}), row("unres", researched=False)]
    assert names(rows, support="eol") == ["eol"]
    assert names(rows, support="unknown") == ["unknown"], "неисследованная строка – не «поддержка неизвестна»"
    assert names(rows, advice="replace") == ["eol"]
    assert names(rows, action="accept_risk") == ["unknown"]
    assert names(rows, action="none") == ["eol", "unres"]
    assert names(rows, review_due="1") == ["unknown"]
    assert names(rows, age="90") == ["eol"] and names(rows, gaps="1") == ["eol"]


def test_unknown_values_are_dropped_by_the_route(web):  # noqa: F811
    from test_sca_research_routes import project_with_sca
    pid = project_with_sca(web)
    page = web.client.get(f"/projects/{pid}/components?cvss_from=abc&support=weird&age=7&score=x").text
    assert "выборка пуста" not in page
    assert 'value="abc"' not in page


def test_compact_bar_and_comma_bound(web):  # noqa: F811
    """На виду поиск, состояние и решение; прочие поля – в «Все фильтры», раскрытом при выбранном; граница с
    запятой выводится в числовое поле с точкой (иначе браузер очищает поле и «Показать» теряет порог)."""
    from test_sca_research_routes import project_with_sca
    pid = project_with_sca(web)
    plain = web.client.get(f"/projects/{pid}/components").text
    assert '<details class="filters-more" id="component-filters-more">' in plain
    bar = plain.split('class="filter-bar"')[1].split("</div>")[0]
    assert all(f'id="{i}"' in bar for i in ("component-q", "component-status", "component-decision"))
    page = web.client.get(f"/projects/{pid}/components?cvss_from=7,5").text
    assert 'id="component-filters-more" open' in page and "Все фильтры · выбрано 1" in page
    assert 'id="cvss-from" min="0" max="10" step="0.1" value="7.5"' in page


def test_filters_never_touch_the_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("отборы не ходят в сеть")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    rows = [row("a", [finding(score=9.0)])]
    assert names(rows, q="cve", cvss_from="5", support="supported", advice="update", age="30") == []
    assert names(rows, cvss_from="5") == ["a"]



def test_version_alone_is_a_filter_and_a_reverse_range_is_always_empty():
    rows = [row("v31", [finding(score=5.0, version="3.1")]), row("v40", [finding(score=9.0, version="4.0")]),
            row("unres", researched=False)]
    assert names(rows, cvss_ver="3.1") == ["v31"], "только строки с баллом этой версии"
    assert names(rows, cvss_from="8", cvss_to="7", score="unresearched") == [], "обратный диапазон пуст всегда"


def test_bounds_are_taken_exactly_or_not_at_all():
    assert research._bound("7") == 7.0 and research._bound("7,5") == 7.5 and research._bound("10") == 10.0
    for bad in ("7.05", "-0.04", "10.04", "11", "8.000000oops", "", "abc", "1e1"):
        assert research._bound(bad) is None, bad
    rows = [row("seven", [finding(score=7.0)])]
    assert names(rows, cvss_from="7.05") == ["seven"], "негодная граница не применяется"


def test_only_resolved_coordinates_are_searched():
    source = {"input_ref": "maven:0000000000000000", "ecosystem": "maven", "name": "parser", "version": "1.0"}
    def view(state):
        payload = {"package_status": "incomplete", "public_findings": [],
                   "identity_resolution": {"state": state, "coordinates": "org.example:parser"}}
        return research.row_view(source, {"payload": payload, "revision": 1, "answer_sig": "x"}, None, "current")
    assert research.row_view and view("resolved")["coordinates"] == "org.example:parser"
    assert view("unknown")["coordinates"] == ""
    assert names([view("unknown")], q="org.example") == []

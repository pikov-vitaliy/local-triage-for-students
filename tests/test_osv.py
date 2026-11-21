"""Точный запрос OSV (app/osv.py, ADR-0112): соответствие экосистем, состав запроса, усечение ответа, отказ без сети."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app import osv  # noqa: E402
from app.config import ConfigError, osv_url_value  # noqa: E402
import pytest  # noqa: E402


def test_ecosystems_map_to_osv_names():
    assert osv.osv_ecosystem("maven") == "Maven" and osv.osv_ecosystem("Gradle") == "Maven"
    assert osv.osv_ecosystem("npm") == "npm" and osv.osv_ecosystem("pypi") == "PyPI" and osv.osv_ecosystem("pip") == "PyPI"
    assert osv.osv_ecosystem("cargo") == "crates.io" and osv.osv_ecosystem("go") == "Go"
    assert osv.osv_ecosystem("docker") is None and osv.osv_ecosystem("") is None and osv.osv_ecosystem(None) is None


def test_query_is_exactly_ecosystem_name_version():
    row = {"input_ref": "x", "ecosystem": "maven", "component": "org.example:lib", "version": "1.2.3",
           "hub_fix_candidate": "1.2.4", "vulnerability_ids": ["CVE-1"], "name": "Система", "identity_kind": "coordinates"}
    assert osv.query_for(row) == ({"package": {"ecosystem": "Maven", "name": "org.example:lib"}, "version": "1.2.3"}, "")
    assert osv.query_for({"ecosystem": "maven", "component": "", "version": "1"})[0] is None
    assert osv.query_for({"ecosystem": "maven", "component": "a:b", "version": ""})[0] is None
    assert osv.query_for({"ecosystem": "docker", "component": "nginx", "version": "1"})[0] is None
    # короткое имя Maven – без запроса (В2 круга 34); классификатор отброшен
    query, note = osv.query_for({"ecosystem": "maven", "component": "log4j-core", "version": "2.14.1", "identity_kind": "short_name"})
    assert query is None and "короткое имя" in note
    query, note = osv.query_for({"ecosystem": "maven", "component": "org.example:lib:jar", "version": "1", "identity_kind": "coordinates"})
    assert query == {"package": {"ecosystem": "Maven", "name": "org.example:lib"}, "version": "1"} and "классификатор" in note


def test_names_compare_by_ecosystem_rules():
    assert osv.normalize_name("PyPI", "Zope_Interface") == osv.normalize_name("PyPI", "zope-interface") == "zope-interface"
    assert osv.normalize_name("crates.io", "serde_json") == osv.normalize_name("crates.io", "serde-json")
    assert osv.normalize_name("NuGet", "Newtonsoft.Json") == "newtonsoft.json"
    assert osv.normalize_name("npm", "Zod") != osv.normalize_name("npm", "zod"), "npm – точное совпадение"
    assert osv.normalize_name("Maven", "org.example:Lib") == "org.example:Lib"


def test_unsupported_ecosystem_makes_no_request():
    answer = osv.lookup("http://127.0.0.1:9", {"ecosystem": "docker", "component": "nginx", "version": "1.0"})
    assert answer["status"] == "unsupported" and answer["query"] is None and answer["vulns"] == []
    assert "не поддерживается" in answer["note"]


def test_trim_limits_vulns_and_size():
    big = {"vulns": [{"id": f"OSV-{i}", "aliases": [], "summary": "x" * 2000,
                      "affected": [{"package": {"ecosystem": "npm", "name": "zod"}, "ranges": [], "versions": ["1"] * 100}],
                      "references": [{"url": f"https://r.example.invalid/{i}/{k}"} for k in range(9)]}
                     for i in range(60)]}
    parsed = osv.trim(big, "npm", "zod")
    vulns, note = parsed["vulns"], parsed["note"]
    assert 0 < len(vulns) < osv.MAX_VULNS and len(json.dumps(vulns, ensure_ascii=False)) <= osv.MAX_CHARS
    assert parsed["total"] == 60 and parsed["status"] == "partial"
    assert f"показаны {len(vulns)} из 60 уязвимостей (остальные не помещаются" in note and note.count("показаны") == 1
    assert all(len(v["references"]) == osv.MAX_REFS and "versions" not in json.dumps(v) for v in vulns)
    # одна запись, которая целиком не помещается, – хотя бы идентификаторы, не «пусто» (Б3 круга 34), статус partial
    huge = {"vulns": [{"id": "OSV-BIG", "aliases": ["CVE-1"], "summary": "y" * (osv.MAX_CHARS + 10)}]}
    parsed = osv.trim(huge, "npm", "zod")
    assert parsed["vulns"] == [{"id": "OSV-BIG", "aliases": ["CVE-1"]}] and parsed["status"] == "partial"
    assert "только идентификаторы" in parsed["note"]
    # огромный alias – запасная ветка тоже под пределом размера (В2 круга 35): остаётся один id
    giant_alias = {"vulns": [{"id": "OSV-ALIAS", "aliases": ["a" * (osv.MAX_CHARS + 10)]}]}
    parsed = osv.trim(giant_alias, "npm", "zod")
    assert parsed["vulns"] == [{"id": "OSV-ALIAS"}] and parsed["status"] == "partial"
    assert len(json.dumps(parsed["vulns"], ensure_ascii=False)) <= osv.MAX_CHARS
    # формат: {} и null – пусто без ошибки (status empty); объект без vulns, не объект, vulns не список, все записи
    # негодные – ValueError; негодная запись среди годных – пропуск и partial
    assert osv.trim({}, "npm", "zod")["status"] == "empty" and osv.trim({"vulns": None}, "npm", "zod")["status"] == "empty"
    assert osv.trim({"vulns": []}, "npm", "zod")["status"] == "empty"
    for bad in ({"vulns": "мусор"}, None, [1], {"error": "boom"}, {"vulns": [{"id": "X", "affected": 1}]},
                {"vulns": [{"id": ""}, 7]}):
        with pytest.raises(ValueError):
            osv.trim(bad, "npm", "zod")
    parsed = osv.trim({"vulns": [{"id": "X", "affected": 1}, {"id": "Y", "references": 5}, 7, {"id": "Z"}], "next_page_token": "t"}, "npm", "zod")
    assert [v["id"] for v in parsed["vulns"]] == ["Z"] and parsed["skipped"] == 3 and parsed["partial"] is True
    assert parsed["status"] == "partial" and "пропущено: 3" in parsed["note"] and "продолжение" in parsed["note"]
    # чистый ответ без потерь – ok; строгая структура: aliases не из строк, severity не список, published не строка –
    # запись пропускается (В3 круга 35), а не превращается в правдоподобный факт
    assert osv.trim({"vulns": [{"id": "A", "aliases": ["CVE-1"], "affected": [], "references": []}]}, "npm", "zod")["status"] == "ok"
    strict = osv.trim({"vulns": [{"id": "A", "aliases": [{}]}, {"id": "B", "severity": "high"}, {"id": "C", "published": 5},
                                 {"id": "D", "affected": [{"package": {"ecosystem": "npm", "name": "zod"}, "ranges": "x"}]},
                                 {"id": "E", "references": [{"url": 3}]}, {"id": "F"}]}, "npm", "zod")
    assert [v["id"] for v in strict["vulns"]] == ["F"] and strict["skipped"] == 5 and strict["status"] == "partial"
    # структура диапазонов и severity (В1 круга 38): негодные – запись пропущена, годные – сохранены в урезанном виде
    bad_ranges = osv.trim({"vulns": [{"id": "R1", "affected": [{"package": {"ecosystem": "npm", "name": "zod"}, "ranges": [7]}]},
                                     {"id": "R2", "affected": [{"package": {"ecosystem": "npm", "name": "zod"}, "ranges": [{"type": "ECOSYSTEM", "events": []}]}]},
                                     {"id": "R3", "affected": [{"package": {"ecosystem": "npm", "name": "zod"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": 1}]}]}]},
                                     {"id": "S1", "severity": [{"type": "CVSS_V3"}]},
                                     {"id": "OK", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N", "extra": 1}],
                                      "affected": [{"package": {"ecosystem": "npm", "name": "zod"}, "repo": "https://r.example.invalid",
                                                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}], "repo": "x"}]}]}]}, "npm", "zod")
    assert [v["id"] for v in bad_ranges["vulns"]] == ["R2", "OK"] and bad_ranges["skipped"] == 3  # R2: events [] – годный
    bad_repo = osv.trim({"vulns": [{"id": "G1", "affected": [{"package": {"ecosystem": "npm", "name": "zod"},
                                                              "ranges": [{"type": "GIT", "events": [{"introduced": "0"}], "repo": 17}]}]},
                                   {"id": "G2", "affected": [{"package": {"ecosystem": "npm", "name": "zod"},
                                                              "ranges": [{"type": "GIT", "events": [{"introduced": "0"}], "repo": None}]}]}]}, "npm", "zod")
    assert [v["id"] for v in bad_repo["vulns"]] == ["G2"] and bad_repo["skipped"] == 1, "repo не строка – запись негодная; null – нет repo"
    assert bad_repo["vulns"][0]["affected"][0]["ranges"][0] == {"type": "GIT", "events": [{"introduced": "0"}]}
    ok = bad_ranges["vulns"][1]
    assert ok["severity"] == [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}]
    assert ok["affected"] == [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}], "repo": "x"}]}]
    assert osv.trim({"vulns": [{"id": "G", "next_page_token": "x"}]}, "npm", "zod")["status"] == "ok"
    # страница только с токеном продолжения – допустимая форма OSV: partial, не ошибка (В2 круга 36)
    only_token = osv.trim({"next_page_token": "only"}, "npm", "zod")
    assert only_token["status"] == "partial" and only_token["vulns"] == [] and "продолжение" in only_token["note"]
    # токен неверного типа – не «нет продолжения», а ответ не по формату (Б1 круга 37); null и "" – нет продолжения
    for bad_token in (0, [], {}, False):
        with pytest.raises(ValueError, match="next_page_token"):
            osv.trim({"vulns": [], "next_page_token": bad_token}, "npm", "zod")
    assert osv.trim({"vulns": [], "next_page_token": None}, "npm", "zod")["status"] == "empty"
    assert osv.trim({"vulns": [], "next_page_token": ""}, "npm", "zod")["status"] == "empty"
    # предел размера – ровно по сериализации списка, включая разделители «, » (В1 круга 37)
    two = [{"id": "x" * 11988}, {"id": "y" * 11989}]  # 11 998 + 11 999 + «[», «]» и «, » = 24 001 > предела
    kept, cut = osv._fit(two)
    assert cut and len(kept) == 1 and len(json.dumps(kept, ensure_ascii=False)) <= osv.MAX_CHARS
    exact = [{"id": "x" * 11987}, {"id": "y" * 11989}]  # 24 000 – ровно предел, обе остаются
    kept, cut = osv._fit(exact)
    assert not cut and len(kept) == 2 and len(json.dumps(kept, ensure_ascii=False)) == osv.MAX_CHARS
    # огромный идентификатор не обрезается и не обходит предел – ошибка формата (В1 круга 36)
    with pytest.raises(ValueError, match="длиннее предела"):
        osv.trim({"vulns": [{"id": "x" * (osv.MAX_CHARS + 1)}]}, "npm", "zod")
    # affected без координат пакета – запись негодная, а не «другой пакет» (В4 круга 36)
    no_coords = osv.trim({"vulns": [{"id": "N1", "affected": [{"package": 7, "ranges": []}]},
                                    {"id": "N2", "affected": [{"ranges": []}]},
                                    {"id": "N3", "affected": [{"package": {"ecosystem": "npm"}, "ranges": []}]},
                                    {"id": "N5", "affected": [{"package": {"ecosystem": "npm", "name": " "}, "ranges": []}]},
                                    {"id": "N6", "affected": [{"package": {"ecosystem": "", "name": "zod"}, "ranges": []}]},
                                    {"id": "N4", "affected": [{"package": {"ecosystem": "PyPI", "name": "zod"}, "ranges": []}]}]}, "npm", "zod")
    assert [v["id"] for v in no_coords["vulns"]] == ["N4"] and no_coords["skipped"] == 5 and no_coords["vulns"][0]["affected"] == []
    parsed = osv.trim({"vulns": [{"id": "A", "affected": [{"package": {"ecosystem": "PyPI", "name": "Zope_Interface"}, "ranges": [{"type": "ECOSYSTEM", "events": []}]},
                                                           {"package": {"ecosystem": "npm", "name": "zope-interface"}, "ranges": []}]}]}, "PyPI", "zope-interface")
    assert parsed["vulns"][0]["affected"] == [{"ranges": [{"type": "ECOSYSTEM", "events": []}]}], "PyPI: имя по правилам PEP 503, другая экосистема отброшена"


def test_osv_url_setting():
    assert osv_url_value("", "https://api.osv.dev") == "https://api.osv.dev"
    assert osv_url_value("off", "x") == "" and osv_url_value("OFF", "x") == ""
    assert osv_url_value("https://osv.example.invalid/", "x") == "https://osv.example.invalid"
    assert osv_url_value("http://127.0.0.1:8080", "x") == "http://127.0.0.1:8080"
    for bad in ("ftp://a", "https://a/v1/query", "https://a/?x=1", "api.osv.dev", "https://api.osv.dev#fragment",
                "https://user:pw@api.osv.dev", "https://api osv.dev", "https://api.osv.dev:99999", "https://api.osv.dev:abc",
                "https://[::1", "https://"):
        with pytest.raises(ConfigError):
            osv_url_value(bad, "x")


def test_make_client_trust_by_scheme():
    assert osv.make_client("https://api.osv.dev").trust == "external"
    assert osv.make_client("http://127.0.0.1:8080").trust == "local"

"""Правило идентичности пакета SCA (план dev17, п. 3 и 4.2): таблица по всем строкам правила и пограничным случаям;
`Finding.package` не уходит в to_dict и data_json. Данные выдуманы."""

from __future__ import annotations

import json

import pytest

from app import package_identity as pi
from app.db import finding_data_sig
from app.models import Finding, ImportResult

LIB = {"groupId": "org.springframework", "name": "spring-core", "version": "5.3.1", "cpe": "", "fileName": "x.jar"}

CASES = [
    # (build_type, component, version, library, ecosystem, name, source, notes)
    # 1: нет library
    ("npm", "core", "1.0", None, "npm", "core", "file", ()),
    ("Maven", "spring-core", "5.3.1", "не объект", "maven", "spring-core", "file", ()),
    # 2: пустое имя
    ("npm", "core", "1.0", {"groupId": "%40angular", "name": " "}, "npm", "core", "file", ("no_name",)),
    # 3: область npm
    ("npm", "core", "1.0", {"groupId": "%40angular", "name": "core"}, "npm", "@angular/core", "hub", ()),
    ("maven", "core", "1.0", {"groupId": "@angular", "name": "core"}, "npm", "@angular/core", "hub", ()),
    ("", "core", "1.0", {"groupId": "%40angular", "name": "@angular/core"}, "npm", "@angular/core", "hub", ()),
    ("npm", "core", "1.0", {"groupId": "%40angular", "name": "@nuxt/core"}, "npm", "@nuxt/core", "hub",
     ("scope_conflict:@angular",)),
    # 4: координаты Maven
    ("npm", "spring-core", "5.3.1", LIB, "maven", "org.springframework:spring-core", "hub", ()),
    ("maven", "commons-io", "2.11.0", {"groupId": "commons-io", "name": "commons-io"}, "maven",
     "commons-io:commons-io", "hub", ()),
    ("maven", "x", "1", {"groupId": "org.a", "name": "org.a:x"}, "maven", "org.a:x", "hub", ()),
    ("maven", "x", "1", {"groupId": "org.a", "name": "org.b:x"}, "maven", "org.b:x", "hub", ("group_conflict:org.a",)),
    # 5: groupId пуст
    ("npm", "lodash", "4.17.21", {"groupId": "", "name": "lodash"}, "npm", "lodash", "hub", ()),
    ("npm", "lodash.merge", "4.6.2", {"name": "lodash"}, "npm", "lodash", "hub", ("name_replaced:lodash.merge",)),
    ("", "pkg", "1", {"name": "pkg"}, "", "pkg", "hub", ()),
    # 6: другая известная экосистема
    ("pip", "requests", "2.0", {"groupId": "psf", "name": "requests"}, "pypi", "requests", "file",
     ("rule_missing:pypi:psf",)),
    ("nuget", "Newtonsoft.Json", "13.0", {"name": "Newtonsoft.Json"}, "nuget", "Newtonsoft.Json", "file", ()),
    # расхождение версии – у всех строк с library
    ("npm", "spring-core", "5.3.2", LIB, "maven", "org.springframework:spring-core", "hub", ("version_mismatch:5.3.1",)),
    ("npm", "core", "1.0", {"groupId": "%40angular", "name": "", "version": "2.0"}, "npm", "core", "file",
     ("no_name", "version_mismatch:2.0")),
    ("npm", "x", "1.0", {"groupId": "", "name": "x", "version": "1.0"}, "npm", "x", "hub", ()),
]


@pytest.mark.parametrize("build_type,component,version,library,ecosystem,name,source,notes", CASES)
def test_resolve_table(build_type, component, version, library, ecosystem, name, source, notes):
    pkg = pi.resolve(build_type, component, version, library)
    assert (pkg.ecosystem, pkg.name, pkg.source, pkg.notes) == (ecosystem, name, source, notes)
    assert pkg.note == ";".join(notes)


def test_empty_name_never_synthesized():
    for group in ("%40angular", "org.a"):
        pkg = pi.resolve("npm", "c", "1", {"groupId": group, "name": ""})
        assert pkg.name == "c" and not pkg.name.endswith(("/", ":"))


def _data(component="spring-core", build_type="npm", version="5.3.1", **package):
    return {"component": component, "build_type": build_type, "version": version, "package": package}


def test_of_name_marks_and_display_name():
    hub = _data(ecosystem="maven", name="org.springframework:spring-core", source="hub", note="version_mismatch:5.3.0")
    assert pi.of(hub) == ("maven", "org.springframework:spring-core", "5.3.1")
    assert pi.name_of(hub) == "org.springframework:spring-core"
    assert pi.display_name(hub) == "spring-core", "заголовок дефекта по Maven – как сейчас"
    assert pi.marks(hub) == ["version_mismatch:5.3.0"]
    # источник file или пусто – Type и компонент выгрузки, даже если колонки заполнены
    assert pi.of(_data(ecosystem="maven", name="g:x", source="file")) == ("npm", "spring-core", "5.3.1")
    assert pi.of({"component": "core", "build_type": "npm", "version": "1"}) == ("npm", "core", "1")
    scoped = _data("core", "npm", "1.0", ecosystem="npm", name="@angular/core", source="hub")
    assert pi.display_name(scoped) == "@angular/core", "у npm с областью – настоящее имя"
    assert pi.marks({"component": "x"}) == []
    # без сведений Hub – компонент выгрузки как есть, даже координаты Maven: тексты существующих дефектов не меняются
    assert pi.display_name({"component": "org.a:lib", "build_type": "maven", "version": "1"}) == "org.a:lib"


def test_with_package_reads_columns_and_keeps_source():
    row = {"pkg_ecosystem": "maven", "pkg_name": "g:x", "pkg_source": "hub", "pkg_note": "", "pkg_scope": "h|7"}
    data = {"component": "x", "build_type": "npm", "version": "1"}
    out = pi.with_package(row, data)
    assert out["package"] == {"ecosystem": "maven", "name": "g:x", "source": "hub", "note": "", "scope": "h|7"}
    assert "package" not in data, "исходный словарь не меняется"
    assert pi.with_package({}, data)["package"]["source"] == ""
    # по плану – with_package(row): данные из строки (разобранные или data_json)
    assert pi.with_package({**row, "data_json": json.dumps(data)}) == out
    assert pi.with_package({**row, "data": data}) == out
    assert pi.with_package({**row, "data_json": "не JSON"})["package"]["name"] == "g:x"


def test_finding_package_is_runtime_only():
    f = Finding(hub_id="73001", kind="SCA", build_type="npm", component="spring-core", version="5.3.1")
    before = f.to_dict()
    f.package = {"ecosystem": "maven", "name": "org.springframework:spring-core", "source": "hub"}
    after = f.to_dict()
    assert after == before and "package" not in after
    assert json.dumps(after, sort_keys=True) == json.dumps(before, sort_keys=True)
    assert finding_data_sig(json.dumps(after, ensure_ascii=False)) == finding_data_sig(json.dumps(before,
                                                                                                    ensure_ascii=False))
    assert (f.package_ecosystem, f.package_name, f.package_display_name) == \
        ("maven", "org.springframework:spring-core", "spring-core")
    plain = Finding(hub_id="1", kind="SCA", build_type="npm", component="core", version="1")
    assert (plain.package_ecosystem, plain.package_name, plain.package_display_name) == ("npm", "core", "core")
    again = Finding.from_dict({**after, "package": f.package})
    assert again.package == f.package and "package" not in again.to_dict()
    result = ImportResult(findings=[f], format="hub", sheets=[], summary={}, warnings=[])
    assert "package" not in result.to_dict()["findings"][0]

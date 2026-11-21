"""SCA: пакет для внешних агентов (только библиотеки, версии и идентификаторы уязвимостей), разбор ответов агентов
и соответствия AST → CVE, текст для Hub, страница SCA и карточка SCA-находки с отметками «Проверено» и «Внесено
в Hub», сохранность отметок и ответов при повторной загрузке выгрузки."""

from __future__ import annotations

import csv
import importlib.util
import io
import json
import re
import zipfile
from pathlib import Path

import pytest

from app import sca
from app.db import Database
from app.hub_import import parse_workbook
from app.models import Finding
from app.triage import order_findings
from hub_fixtures import SAST_ROWS, SCA_ROWS, make_hub_xlsx
from test_web import ORIGIN, create_project, prepared, upload, web  # noqa: F401

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "demo"
AS_JSON = {**ORIGIN, "Accept": "application/json"}
EM_DASH = chr(0x2014)
# заготовка комментария, которую карточка SCA строила без ответа агента до 0.9.11 (ADR-0100): тексты, сохранённые с
# ней, по-прежнему узнаются как «обновить»
LEGACY_HUB_SUGGESTION = ("Обновить example-parser с версии 1.4.2 до 1.4.9 (безопасная версия по данным Hub).\n"
                         "Уязвимость: CVE-2099-10001.")
PARSER = ("example-parser", "1.4.2")  # библиотека тестовой выгрузки с двумя находками: 73001 (AST) и 73002 (CVE)


def component(name: str = "org.example:example-parser", version: str = "1.4.2", *, cve=(), vuln_ids=(),
              fixed=("1.4.9",), build=("maven",), findings: int = 1) -> dict:
    """Компонент в виде Database.sca_components – для проверок без базы."""
    return {"component": name, "version": version, "findings": findings, "hub_ids": [], "finding_ids": [],
            "cvss": 9.8, "urgent": True, "cve": list(cve), "vuln_ids": list(vuln_ids), "fixed_versions": list(fixed),
            "cwe": ["CWE-611"], "codebases": ["billing-core"], "build_types": list(build),
            "dep_paths": ["org.example:billing-core > example-parser"], "reviewed": 0, "entered": 0}


COMPONENTS = [component(vuln_ids=["AST-2026-000101"], cve=["CVE-2099-10001"], findings=2),
              component("demo-yaml-lib", "5.1.0", vuln_ids=["GHSA-abcd-1234-efgh"], fixed=["5.4.1"], build=["pypi"])]


def answers_json(*items: dict, source: str = "Агент 1") -> str:
    return json.dumps({"format": sca.ANSWER_FORMAT, "source": source, "components": list(items)},
                      ensure_ascii=False)


def answer(name: str = "org.example:example-parser", version: str = "1.4.2", **fields) -> dict:
    base = {"component": name, "version": version, "conclusion": "update", "recommended_version": "1.4.9",
            "ids": {"AST-2026-000101": ["CVE-2099-10002"]}, "explanation": "Исправлено в 1.4.9.",
            "links": ["https://osv.dev/vulnerability/CVE-2099-10002"]}
    return {**base, **fields}


# ============================================================================ пакет для внешних агентов

def test_package_has_only_library_names_versions_and_ids():
    rows = sca.package_rows(COMPONENTS)
    assert [set(row) for row in rows] == [{"ecosystem", "component", "version", "vulnerabilities",
                                          "hub_safe_version"}] * 2
    assert rows[0] == {"ecosystem": "maven", "component": "org.example:example-parser", "version": "1.4.2",
                       "vulnerabilities": ["CVE-2099-10001", "AST-2026-000101"], "hub_safe_version": "1.4.9"}
    archive = zipfile.ZipFile(io.BytesIO(sca.package_zip(rows)))
    assert sorted(archive.namelist()) == ["answer-template.json", "components.csv", "task.md"]
    everything = "\n".join(archive.read(name).decode("utf-8") for name in archive.namelist())
    # кодовые базы, пути зависимостей, CVSS и CWE в пакет не попадают
    for secret in ("billing-core", "org.example:billing-core >", "9.8", "CWE-611"):
        assert secret not in everything, secret
    template = json.loads(archive.read("answer-template.json"))
    assert template["format"] == sca.ANSWER_FORMAT and template["source"] == ""
    first = template["components"][0]
    assert first["ids"] == {"AST-2026-000101": []}  # у CVE соответствие не спрашивается
    assert (first["conclusion"], first["recommended_version"], first["explanation"], first["links"]) == ("", "", "", [])
    table = list(csv.reader(io.StringIO(archive.read("components.csv").decode("utf-8"))))
    assert table[0] == ["ecosystem", "component", "version", "vulnerabilities", "hub_safe_version"]
    assert table[2] == ["pypi", "demo-yaml-lib", "5.1.0", "GHSA-abcd-1234-efgh", "5.4.1"]


def test_task_text_rules_sources_and_template():
    text = sca.task_text(sca.package_rows(COMPONENTS))
    for needle in ("Ничего не придумывайте", "первоисточник", "OSV", "GitHub Advisory", "NVD", "Maven Central",
                   "БДУ ФСТЭК России", "Кода проекта в задании нет", "update", "not_applicable", "unclear",
                   "Заготовка ответа: 2 библиотеки"):
        assert needle in text, needle
    assert EM_DASH not in text
    assert not re.search(r"ФСТЭК(?! России)", text)
    block = re.search(r"```json\n(.*?)\n```", text, re.S).group(1)
    assert [c["component"] for c in json.loads(block)["components"]] == ["org.example:example-parser",
                                                                         "demo-yaml-lib"]
    # заготовка из задания читается как ответ: пустые выводы – с замечаниями, но без отказа
    report = sca.parse_answers(text, COMPONENTS)
    assert len(report.answers) == 2 and not report.unknown


def test_package_csv_does_not_turn_into_formulas_and_skips_duplicates():
    rows = sca.package_rows([component("@scope/pkg", "1.0", build=["npm"]), component("@scope/pkg", "1.0"),
                             component("=HYPERLINK(1)", "@2"), component("ok", "1.0", build=["+npm"])])
    # формула в имени не похожа на имя пакета – в пакет не попадает; неизвестная экосистема не передаётся
    assert [r["component"] for r in rows] == ["@scope/pkg", "ok"] and rows[1]["ecosystem"] == ""
    table = list(csv.reader(io.StringIO(sca.package_csv(rows))))
    assert table[1][1] == "'@scope/pkg"
    crafted = [{"ecosystem": "+npm", "component": "=HYPERLINK(1)", "version": "@2", "vulnerabilities": [],
                "hub_safe_version": ""}]
    table = list(csv.reader(io.StringIO(sca.package_csv(crafted))))
    assert table[1][1:3] == ["'=HYPERLINK(1)", "'@2"] and table[1][0] == "'+npm"


@pytest.mark.parametrize("name, version, reason", [
    ("src/main/java/org/example/Billing.java", "1.0", "путь"),
    ("C:\\work\\billing\\lib", "1.0", "путь"),
    ("../../etc/passwd", "1.0", "путь"),
    # абсолютные пути и «папка/файл»: раньше проходили фильтр
    ("C:/private/project", "1.0", "путь"),
    ("/opt/billing/lib", "1.0", "путь"),
    ("~/work/lib", "1.0", "путь"),
    ("src/Foo.java", "1.0", "путь"),
    ("config/app.yml", "1.0", "путь"),
    ("String sql = select", "1.0", "имя не похоже"),
    ("org.example:billing-core", "1.0 SELECT * FROM t", "версия не похожа"),
    ("org.internal:ledger", "2.1", "внутренний компонент"),
    ("@internal/ui-kit", "3.0.0", "внутренний компонент"),
])
def test_package_excludes_paths_code_and_internal_components(name, version, reason):
    prefixes = ("org.internal:", "@INTERNAL/")
    rows, excluded = sca.package_report([component(name, version), component("lodash", "4.17.21")], prefixes)
    assert [r["component"] for r in rows] == ["lodash"]
    assert len(excluded) == 1 and reason in excluded[0]["reason"] and excluded[0]["component"] == name
    assert name not in sca.task_text(rows) and name not in sca.package_csv(rows)


def test_package_keeps_real_coordinates_and_cleans_safe_versions():
    # имя проверяется по правилам своей экосистемы: у каждого – та, к которой оно относится
    named = [("org.example:example-parser", "maven"), ("@scope/pkg", "npm"), ("github.com/org/repo/v2", "go"),
             ("Newtonsoft.Json", "nuget"), ("highlight.js", "npm"), ("requests", "pypi"), ("@types/chart.js", "npm"),
             ("gopkg.in/yaml.v3", "go"), ("chart.js", "npm")]
    names = [n for n, _ in named]
    rows, excluded = sca.package_report([component(n, "1.2.3-rc.1+build", fixed=("1.4.9, ветка main; 2.0",),
                                                   build=[eco]) for n, eco in named])
    assert excluded == [] and [r["component"] for r in rows] == names
    assert rows[0]["hub_safe_version"] == "1.4.9, main, 2.0" and rows[0]["ecosystem"] == "maven"


# ============================================================================ ответы агентов

def test_answer_is_found_in_plain_json_fenced_block_and_text():
    plain = answers_json(answer())
    fenced = f"Вот результат проверки.\n\n```json\n{plain}\n```\n\nЕсли нужно, уточню."
    inline = "Ответ: " + json.dumps([answer()], ensure_ascii=False) + " – готово."
    for text in (plain, fenced, inline, chr(0xFEFF) + plain):
        report = sca.parse_answers(text, COMPONENTS)
        assert [(a.component, a.version, a.conclusion) for a in report.answers] == [
            ("org.example:example-parser", "1.4.2", "update")], text[:40]
    assert sca.parse_answers(plain, COMPONENTS).source == "Агент 1"
    assert sca.parse_answers(inline, COMPONENTS).source == sca.DEFAULT_SOURCE
    assert sca.parse_answers(plain, COMPONENTS, source="  Сервис 2 ").source == "Сервис 2"
    # одиночный объект и несколько блоков подряд (ответ частями)
    two = f"```json\n{answers_json(answer())}\n```\n```json\n{json.dumps(answer('demo-yaml-lib', '5.1.0'))}\n```"
    assert len(sca.parse_answers(two, COMPONENTS).answers) == 2


def test_answers_are_matched_to_project_libraries():
    items = [answer("ORG.EXAMPLE:Example-Parser ", "1.4.2"),  # без учёта регистра и пробелов
             answer("demo-yaml-lib", ""),  # без версии: библиотека с таким именем одна
             answer("left-pad", "1.0.0")]  # такой нет в проекте
    report = sca.parse_answers(answers_json(*items), COMPONENTS)
    assert sorted((a.component, a.version) for a in report.answers) == [("demo-yaml-lib", "5.1.0"),
                                                                       ("org.example:example-parser", "1.4.2")]
    assert report.unknown == ["left-pad@1.0.0"] and report.without_answer == []
    twins = [component("lib", "1.0"), component("lib", "2.0")]
    report = sca.parse_answers(answers_json(answer("lib", "")), twins)  # имя без версии неоднозначно
    assert report.answers == [] and report.unknown == ["lib"]
    assert report.without_answer == ["lib@1.0", "lib@2.0"]


def test_answer_fields_are_normalized_and_untrusted_text_is_cleaned():
    bidi, zero_width = chr(0x202E), chr(0x200B)
    item = answer(conclusion="Не применимо", recommended_version=" 1.4.9 ",
                  ids=[{"id": "ast-2026-000101", "aliases": "cve-2099-10002, GHSA-abcd-1234-efgh, мусор"},
                       {"id": "не идентификатор", "aliases": ["CVE-2099-1"]}],
                  explanation=f"Строка 1\x00{bidi}\n\n\n\nСтрока 2{zero_width}\tконец {EM_DASH} и всё",
                  links=["https://osv.dev/vulnerability/CVE-2099-10002", "javascript:alert(1)",
                         "data:text/html,x", "ftp://example.org/x", "https://user:pw@example.org/",
                         "[NVD](https://nvd.nist.gov/vuln/detail/CVE-2099-10002).", "https://пример.рф/",
                         "https://example.org/a b", {"url": "https://github.com/advisories"}])
    report = sca.parse_answers(answers_json(item), COMPONENTS)
    a = report.answers[0]
    assert a.conclusion == "not_applicable" and a.recommended_version == "1.4.9"
    assert a.ids == {"AST-2026-000101": ["CVE-2099-10002", "GHSA-abcd-1234-efgh"]}
    assert a.explanation == "Строка 1\n\nСтрока 2 конец – и всё"
    # из строки с пробелом берётся адрес до пробела – так ссылки выделяют и в тексте
    assert a.links == ["https://osv.dev/vulnerability/CVE-2099-10002",
                       "https://nvd.nist.gov/vuln/detail/CVE-2099-10002", "https://example.org/a",
                       "https://github.com/advisories"]
    assert any("отброшено ссылок – 5" in w for w in report.warnings)


def test_answer_warnings_for_human():
    items = [answer(conclusion="может быть", links=[]),
             answer("demo-yaml-lib", "5.1.0", conclusion="update", recommended_version="", links=["https://a.b/"]),
             answer("demo-yaml-lib", "5.1.0", conclusion="update", recommended_version="5.0.9",
                    explanation="x" * (sca.MAX_EXPLANATION + 10), links=["https://a.b/"])]
    report = sca.parse_answers(answers_json(*items), COMPONENTS)
    text = "\n".join(report.warnings)
    assert "«может быть» не распознан" in text and "нет ссылок на источники" in text
    assert "demo-yaml-lib@5.1.0: ответ повторяется – взят последний." in text
    assert "рекомендуемая версия ниже текущей" in text and "ниже версии исправления по данным Hub (5.4.1)" in text
    assert f"пояснение обрезано до {sca.MAX_EXPLANATION} знаков" in text
    yaml = next(a for a in report.answers if a.component == "demo-yaml-lib")
    assert yaml.recommended_version == "5.0.9" and len(yaml.explanation) == sca.MAX_EXPLANATION + 1  # с «…»
    first = sca.parse_answers(answers_json(answer("demo-yaml-lib", "5.1.0", recommended_version="",
                                                  links=["https://a.b/"])), COMPONENTS)
    assert first.warnings == ["demo-yaml-lib@5.1.0: нет версии для обновления."]


@pytest.mark.parametrize("text, message", [
    ("", "Вставьте ответ"),
    ("Агент ничего не нашёл.", "нет JSON"),
    ('{"components": [{"component": "a", "version": "1"', "обрывается"),
    ('{"components": [{"component": "a", "explanation": "обрыв', "обрывается"),
    ('{"components": [{"component": "a",, "version": "1"}]}', "строка 1, позиция"),
    ('{"result": "ok"}', "нет списка библиотек"),
    ("[" * 100_000 + "]" * 100_000, "слишком глубокая вложенность"),
    ("```json\n" + "[" * 100_000 + "]" * 100_000 + "\n```", "слишком глубокая вложенность"),
    ("Ответ: " + "[" * 50_000 + "]" * 50_000, "слишком глубокая вложенность"),
], ids=["empty", "no-json", "cut", "cut-in-string", "syntax", "no-components", "deep", "deep-fenced", "deep-text"])
def test_unreadable_answers_are_explained(text, message):
    with pytest.raises(sca.ScaInputError, match=message):
        sca.parse_answers(text, COMPONENTS)


def test_too_many_answer_records_are_refused(monkeypatch):
    monkeypatch.setattr(sca, "MAX_ANSWERS", 2)
    with pytest.raises(sca.ScaInputError, match="Слишком много записей"):
        sca.parse_answers(json.dumps([answer()] * 3), COMPONENTS)


def test_norm_helpers():
    assert sca.norm_id(" cve-2021-44228 ") == "CVE-2021-44228"
    assert sca.norm_id("ghsa-jfh8-c2jp-5v3q") == "GHSA-jfh8-c2jp-5v3q"
    assert sca.norm_id("BDU:2026-01234") == "BDU:2026-01234"
    for junk in ("", "CVE", "hello world", "AST-", "<script>-1"):
        assert sca.norm_id(junk) == "", junk
    assert sca.norm_conclusion(" Обновить. ") == "update" and sca.norm_conclusion("N/A") == "not_applicable"
    assert sca.norm_conclusion("НЕЯСНО") == "unclear" and sca.norm_conclusion("maybe") == ""
    assert sca.link_label("https://www.github.com/advisories/GHSA-x/") == "github.com/advisories/GHSA-x"
    assert sca.check_links("CVE-2099-1")[0] == ("NVD", "https://nvd.nist.gov/vuln/detail/CVE-2099-1")
    assert sca.check_links("BDU:2026-01234") == [("БДУ ФСТЭК России", "https://bdu.fstec.ru/vul/2026-01234")]
    assert sca.check_links("AST-2026-1") == []


def test_aliases_prefer_vendor_map_and_ignore_case():
    ids = ["AST-2026-1", "GHSA-JFH8-C2JP-5V3Q", "CVE-2099-1"]
    agent = {"ids": {"AST-2026-1": ["CVE-2099-7"], "ghsa-jfh8-c2jp-5v3q": ["CVE-2099-8"], "CVE-2099-1": []}}
    aliases = sca.aliases_for(ids, {"AST-2026-1": ["CVE-2099-9"]}, agent)
    assert aliases == {"AST-2026-1": {"aliases": ["CVE-2099-9"], "origin": "map"},
                       "GHSA-JFH8-C2JP-5V3Q": {"aliases": ["CVE-2099-8"], "origin": "agent"},
                       "CVE-2099-1": {"aliases": [], "origin": "agent"}}
    assert sca.describe_ids(ids, aliases) == ("AST-2026-1 (CVE-2099-9), GHSA-JFH8-C2JP-5V3Q (CVE-2099-8), "
                                              "CVE-2099-1")
    assert sca.aliases_for(["AST-1"], {}, None) == {"AST-1": {"aliases": [], "origin": ""}}


def test_versions():
    assert sca.version_key("2.3.9.RELEASE") == (2, 3, 9) and sca.version_key("v1.0.10") == (1, 0, 10)
    assert sca.version_key("latest") is None
    assert sca.compare_versions("1.0.10", "1.0.2") == 1 and sca.compare_versions("2.0", "2.0.0") == 0
    assert sca.compare_versions("x", "1") is None
    assert sca.major_change("2.3.1", "3.0.0") and not sca.major_change("2.3.1", "2.4.0")
    assert sca.first_version("2.3.9, 3.0.1") == "2.3.9" and sca.first_version("-") == ""
    notes = sca.answer_notes("2.3.1", {"conclusion": "update", "recommended_version": "3.0.0", "links": ["x"]},
                             ["2.3.9"])
    assert notes == [{"tone": "accent", "text": "смена старшей версии"}]


# ============================================================================ соответствие AST → CVE

def test_ast_map_csv_variants():
    report = sca.parse_ast_map("AST id;CVE id\nAST-2026-1;CVE-2099-1\nast-2026-2;CVE-2099-2 GHSA-abcd-1234-efgh\n"
                               "\nне пара;x\nAST-2026-3;AST-2026-4\n")
    assert report.header and report.skipped == [5, 6]
    assert report.pairs == [("AST-2026-1", "CVE-2099-1"), ("AST-2026-2", "CVE-2099-2"),
                            ("AST-2026-2", "GHSA-abcd-1234-efgh")]
    for text in (chr(0xFEFF) + "AST-2026-1,CVE-2099-1\n", "AST-2026-1\tCVE-2099-1\n", "AST-2026-1 CVE-2099-1\n",
                 'AST-2026-1,"CVE-2099-1, CVE-2099-1"\n'):
        assert sca.parse_ast_map(text).pairs == [("AST-2026-1", "CVE-2099-1")], repr(text)
    # запятая внутри ячейки при разделителе «;» не сбивает выбор разделителя
    assert len(sca.parse_ast_map("AST-1;CVE-2099-1,CVE-2099-2\nAST-2;CVE-2099-3\n").pairs) == 3
    with pytest.raises(sca.ScaInputError, match="Соответствий не найдено"):
        sca.parse_ast_map("AST;CVE\n")
    with pytest.raises(sca.ScaInputError, match="Вставьте"):
        sca.parse_ast_map("  ")


# ============================================================================ текст для Hub

def sca_finding(**fields) -> Finding:
    base = {"hub_id": "73001", "kind": "SCA", "component": "example-parser", "version": "1.4.2",
            "fixed_version": "1.4.9", "vuln_ids": ["AST-2026-000101"], "cve": []}
    return Finding.from_dict({**base, **fields})


def test_suggested_comment_by_conclusion():
    f = sca_finding()
    aliases = {"AST-2026-000101": {"aliases": ["CVE-2099-10002"], "origin": "agent"}}
    links = ["https://osv.dev/a", "https://osv.dev/b", "https://osv.dev/c"]
    update = sca.suggested_comment(f, {"conclusion": "update", "recommended_version": "1.4.10",
                                       "explanation": "Исправлено. " * 100, "links": links}, aliases)
    lines = update.split("\n")
    assert lines[0] == "Обновить example-parser с версии 1.4.2 до 1.4.10."
    assert lines[1] == "Уязвимость: CVE-2099-10002."  # публичное соответствие вместо AST (ADR-0101)
    assert len(lines[2]) <= sca.COMMENT_EXPLANATION and lines[2].endswith("Исправлено.")
    assert lines[3] == "Источники: https://osv.dev/a, https://osv.dev/b"
    assert sca.suggested_comment(f, {"conclusion": "not_applicable", "explanation": "Версия вне диапазона."},
                                 aliases).startswith("Не применимо: CVE-2099-10002 не затрагивает "
                                                     "example-parser 1.4.2.")
    assert sca.suggested_comment(f, {"conclusion": "unclear"}, {}) == ("Требуется проверка: уязвимость в "
                                                                      "example-parser 1.4.2.")
    # без ответа агента заготовки нет: версия исправления из Hub – справка, не основание (ADR-0100)
    assert sca.suggested_comment(f, None, {}) == ""
    assert sca.suggested_comment(sca_finding(fixed_version=""), None, {}) == ""
    # «обновить» без версии агента – без цели, версия Hub не подставляется
    no_target = sca.suggested_comment(f, {"conclusion": "update"}, {})
    assert no_target == "Обновить example-parser с версии 1.4.2."  # AST без соответствия не называется (ADR-0101)
    assert "1.4.9" not in no_target and "безопасн" not in no_target
    assert sca.suggested_comment(f, {"conclusion": ""}, {}) == ""


def test_hub_text_v1_status_fallback_and_dashes():
    """Прежний формат (до 0.9.0) сохраняется для распознавания прежних отметок «Внесено в Hub»."""
    f = sca_finding(cve=["CVE-2099-10001"])
    text = sca.hub_text_v1(f, "true_positive", "", {"true_positive": "Подтверждена"})
    assert text == ("Статус: Подтверждена\nКомментарий: Обновить example-parser с версии 1.4.2 до 1.4.9. "
                    "Уязвимости: AST-2026-000101, CVE-2099-10001.")
    assert sca.hub_text_v1(f, "false_positive", "").endswith("не затрагивает example-parser 1.4.2.")
    assert sca.hub_text_v1(f, "uncertain", f"Проверить {EM_DASH} позже\n\n\n\nконец") == (
        "Статус: Не подтверждено\nКомментарий: Проверить – позже\n\nконец")


# ============================================================================ демо

def load_demo_script():
    """scripts/make_demo_xlsx.py: книга демо строится заново – так тест видит расхождение генератора и ответов."""
    spec = importlib.util.spec_from_file_location("make_demo_xlsx", ROOT / "scripts" / "make_demo_xlsx.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_answers_match_demo_report(tmp_path):
    result = parse_workbook(load_demo_script().build(tmp_path / "demo.xlsx"))
    db = Database(tmp_path / "demo.db")
    try:
        pid = db.create_project("Demo")
        db.save_import(pid, "demo.xlsx", result.format, result.sheets, result.summary, result.warnings,
                       order_findings(result.findings, 9.0))
        components = db.sca_components(pid)
        text = (DEMO / "sca-answers.json").read_text(encoding="utf-8")
        report = sca.parse_answers(text, components)
        assert (report.unknown, report.warnings, report.without_answer) == ([], [], [])
        assert sorted(a.conclusion for a in report.answers) == ["not_applicable", "unclear", "update"]
        assert report.source == "Демо-агент"
        # ссылки демо ведут только на выдуманные адреса (зарезервированный домен .example)
        for a in report.answers:
            assert a.links and all(re.match(r"https://[a-z0-9.-]+\.example/", link) for link in a.links)
        package = sca.package_rows(components)
        assert [r["component"] for r in package] == [c["component"] for c in json.loads(text)["components"]]
    finally:
        db.close()


# ============================================================================ страница SCA

def answers_text(**overrides) -> str:
    return answers_json(answer("example-parser", "1.4.2", **overrides),
                        answer("demo-xml", "2.0.0", conclusion="unclear", recommended_version="2.0.4",
                               ids={"AST-2026-000103": []}, explanation="Совпадение не подтверждено.",
                               links=["https://osv.dev/list?q=demo-xml"]))


def post_answers(web, pid: int, text: str, source: str = "", follow: bool = False):
    return web.client.post(f"/projects/{pid}/sca/answers", data={"answers": text, "source": source}, headers=ORIGIN,
                           files={"file": ("", b"", "application/octet-stream")}, follow_redirects=follow)


def sca_card(web, pid: int, hub_id: str) -> tuple[int, str]:
    fid = web.app.state.db.get_finding_by_hub_id(pid, hub_id)["id"]
    return fid, web.client.get(f"/projects/{pid}/sca/findings/{fid}").text


def sca_text_ready(web, url: str, target: str = "9.9.9") -> dict:
    """Текст набора дефекта SCA для тестов выдачи (ADR-0091): Объяснение – строка на каждую уязвимость набора,
    целевая версия вручную и отметка «Версию проверил сам». Возвращает ответ на сохранение текста."""
    import re as _re
    card = web.client.get(url).text
    found = _re.search(r'name="text_revision" value="(\d+)"', card)
    first = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        "text_revision": found.group(1) if found else "0", "target_version": target})
    assert first.status_code == 200, first.text
    lines = [line.split(":", 1)[0].strip() for line in first.json()["explanation_draft"].split("\n") if ":" in line]
    explanation = "\n".join(f"{vuln_id}: Уязвимость компонента позволяет нарушителю нарушить работу продукта при "
                             "обработке входных данных." for vuln_id in lines) or (
        "Уязвимость компонента позволяет нарушителю нарушить работу продукта при обработке входных данных.")
    shown = shown_fields(web.client.get(url).text)  # отметка – к показанной проверке версии (ревью 82103ee)
    second = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **shown, "text_revision": str(first.json()["text_revision"]), "target_version": target, "version_checked": "1",
        "explanation": explanation})
    assert second.status_code == 200, second.text
    return second.json()


def shown_fields(html: str) -> dict:
    """Скрытые поля формы текста набора о том, что видел человек: отпечаток пакета, проверка версии, остаточные."""
    out = {}
    for name in ("shown_fp", "version_shown", "residual_shown"):
        found = re.search(rf'name="{name}" value="([^"]*)"', html)
        if found:
            out[name] = found.group(1)
    return out


def form_fields(html: str) -> dict:
    return {name: re.search(rf'name="{name}" value="([^"]*)"', html).group(1)
            for name in ("finding_version", "answer_id", "review_revision")}


def plain(html: str) -> str:
    """Текст страницы без разметки, пробелы свёрнуты."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", html))


def test_sca_page_lists_libraries_and_links_component_research(web):
    pid = prepared(web)
    r = web.client.get(f"/projects/{pid}/sca")
    assert r.status_code == 200
    html = r.text
    for needle in ("example-parser", "demo-xml", "AST-2026-000101", "CVE-2099-10001", 'id="answers-form"',
                   "Проверено <strong>0</strong> из 3", 'aria-current="page">SCA',
                   'id="component-research-link"', f'href="/projects/{pid}/components"'):
        assert needle in html, needle
    # Новый сценарий не предлагает старый пакет и расшифровку AST; прежние идентификаторы остаются в таблице.
    for retired in ('id="copy-task"', 'id="download-package"', 'id="ast-map-form"',
                    f'/projects/{pid}/sca/package.zip', f'/projects/{pid}/sca/components.csv',
                    f'/projects/{pid}/sca/components.json'):
        assert retired not in html, retired
    fid = web.app.state.db.get_finding_by_hub_id(pid, "73001")["id"]
    assert f'id="sca-continue" href="/projects/{pid}/sca/findings/{fid}"' in html
    # отборы с числом библиотек
    assert 'Без ответа агента <span class="chip-count">2</span>' in html
    assert 'Срочные <span class="chip-count">1</span>' in html
    assert web.client.get(f"/projects/{pid}/sca?show=urgent").text.count("<tr data-component=") == 1
    assert "Под этот отбор ничего не попало" in web.client.get(f"/projects/{pid}/sca?show=update").text
    assert web.client.get(f"/projects/{pid}/sca?show=<b>").status_code == 200  # неизвестный отбор – все


def test_sca_page_empty_states(web):
    pid = create_project(web.client)
    assert "Выгрузки ещё нет" in web.client.get(f"/projects/{pid}/sca").text
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "no-sca.xlsx", sca=())).status_code == 303
    assert "нет находок SCA Security" in web.client.get(f"/projects/{pid}/sca").text
    assert web.client.get("/projects/999/sca").status_code == 404


def test_old_package_downloads_are_retired_with_new_section_address(web):
    pid = prepared(web)
    # Старые исходящие маршруты намеренно возвращают 410: задание без AST собирается в новом разделе.
    for suffix in ("package.zip", "components.csv", "components.json"):
        response = web.client.get(f"/projects/{pid}/sca/{suffix}")
        assert response.status_code == 410, suffix
        assert f"/projects/{pid}/components" in response.text


def test_upload_answers_from_text_and_file(web):
    pid = prepared(web)
    r = post_answers(web, pid, "Готово:\n```json\n" + answers_text() + "\n```", source="Агент 1")
    assert r.status_code == 303 and r.headers["location"] == f"/projects/{pid}/sca?ok=sca_answers&n=2#components"
    html = web.client.get(r.headers["location"]).text
    assert "Ответы сохранены: 2 библиотеки." in html
    assert "обновить</span> <span class=\"mono\">до 1.4.9</span>" in html and "Агент 1" in html
    assert "AST-2026-000101 → CVE-2099-10002 по ответу агента" in plain(html)
    # файл важнее вставленного текста; ответ другого источника хранится рядом
    body = answers_json(answer("example-parser", "1.4.2", recommended_version="1.5.0"), source="Агент 2")
    r = web.client.post(f"/projects/{pid}/sca/answers", headers=ORIGIN, follow_redirects=False,
                        data={"answers": "не JSON"},
                        files={"file": ("answers.json", body.encode(), "application/json")})
    assert r.status_code == 303
    rows = web.app.state.db.sca_answers(pid, *PARSER)
    assert [(a["source"], a["recommended_version"]) for a in rows] == [("Агент 2", "1.5.0"), ("Агент 1", "1.4.9")]


def test_upload_answers_reports_problems(web):
    pid = prepared(web)
    r = post_answers(web, pid, answers_json(answer("example-parser", "1.4.2", links=[]), answer("left-pad", "1.0")))
    assert r.status_code == 200
    assert 'id="answers-report"' in r.text and "left-pad@1.0" in r.text and "нет ссылок на источники" in r.text
    r = post_answers(web, pid, answers_json(answer("left-pad", "1.0")))
    assert r.status_code == 400 and "Ни одного ответа не сохранено" in r.text
    broken = '{"components": [{"component": "<b>x</b>", "version": "1"'
    r = post_answers(web, pid, broken)
    assert r.status_code == 400 and "обрывается" in r.text
    # введённое возвращается в форму экранированным
    assert "&lt;b&gt;x&lt;/b&gt;" in r.text and "<b>x</b>" not in r.text
    big = web.client.post(f"/projects/{pid}/sca/answers", headers=ORIGIN, data={"answers": "x"},
                          files={"file": ("a.json", b"{" * (sca.MAX_ANSWER_BYTES + 1), "application/json")})
    assert big.status_code in (400, 413)


def test_answer_text_is_escaped_and_bad_links_are_not_rendered(web):
    pid = prepared(web)
    evil = answer("example-parser", "1.4.2", explanation='<script>alert("x")</script> <img src=x onerror=1>',
                  links=["javascript:alert(1)", "https://osv.dev/vulnerability/CVE-2099-10002"],
                  recommended_version="<i>1</i>")
    assert post_answers(web, pid, answers_json(evil)).status_code == 200  # замечание: ссылка отброшена
    for html in (web.client.get(f"/projects/{pid}/sca").text, sca_card(web, pid, "73001")[1]):
        assert "<script>alert" not in html and "<img src=x" not in html and "<i>1</i>" not in html
        assert "javascript:" not in html
    card = sca_card(web, pid, "73001")[1]
    assert "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;" in card
    assert ('<a href="https://osv.dev/vulnerability/CVE-2099-10002" rel="noopener noreferrer nofollow" '
            'target="_blank"') in card


def test_ast_map_upload_has_priority_over_agent(web):
    # Загрузка соответствия убрана из интерфейса прежней страницы: расшифровка AST нужна была только старому
    # исходящему пакету. Сам разбор и приём пары по адресу остаются – ими пользуются прежние данные и разделы
    # собранных ранее ответов, поэтому проверка продолжает требовать приоритет выгрузки поставщика над ответом
    # агента, но без формы на странице.
    pid = prepared(web)
    assert post_answers(web, pid, answers_text()).status_code == 303
    vendor = b"AST;CVE\nAST-2026-000101;CVE-2099-20001\n"
    r = web.client.post(f"/projects/{pid}/sca/ast-map", headers=ORIGIN, follow_redirects=False,
                        data={"mapping": ""}, files={"file": ("vendor.csv", vendor, "text/csv")})
    assert r.status_code == 303 and r.headers["location"] == f"/projects/{pid}/sca?ok=sca_map&n=1#ast-map"
    page = web.client.get(r.headers["location"]).text
    assert "новых пар – 1" in page and "AST-2026-000101 → CVE-2099-20001" in plain(page)
    assert 'id="ast-map-form"' not in page and 'id="ast-map-file"' not in page
    assert "Расшифровка внутренних номеров AST больше не предлагается" in plain(page)
    card = sca_card(web, pid, "73001")[1]
    assert "CVE-2099-20001" in card and "по выгрузке поставщика" in card
    assert "https://nvd.nist.gov/vuln/detail/CVE-2099-20001" in card  # где проверить – по найденному CVE
    r = web.client.post(f"/projects/{pid}/sca/ast-map", headers=ORIGIN,
                        data={"mapping": "AST-2026-000102;CVE-2099-3\nмусор;x\n"},
                        files={"file": ("", b"", "application/octet-stream")})
    assert r.status_code == 200 and 'id="ast-map-report"' in r.text and "(строки 2)" in r.text
    r = web.client.post(f"/projects/{pid}/sca/ast-map", headers=ORIGIN, data={"mapping": "нет пар"},
                        files={"file": ("", b"", "application/octet-stream")})
    assert r.status_code == 400 and "Соответствий не найдено" in r.text


# ============================================================================ карточка SCA-находки

def test_sca_card_review_copy_entered(web):
    pid = prepared(web)
    assert post_answers(web, pid, answers_text()).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    assert 'data-model-verdict="true_positive"' in card and 'id="copy-hub"' in card
    assert 'id="mark-entered" hidden' in card  # до копирования отметки «внесено» нет
    assert "Обновить example-parser с версии 1.4.2 до 1.4.9." in card  # заготовка комментария
    assert "Согласен с агентом" in card
    assert "Текст появится после выбора и сохранения решения" in card  # предпросмотра без решения нет (ADR-0088)
    fields = form_fields(card)
    url = f"/projects/{pid}/sca/findings/{fid}"
    # «Внесено в Hub» – о тексте сохранённого решения: без решения отметки нет
    r = web.client.post(f"{url}/entered", headers=AS_JSON, data={"entered": "1"})
    assert r.status_code == 400 and "Сначала сохраните решение" in r.json()["detail"]
    # «Обновить» – короткого текста нет (ADR-0091 п. 3): копирование отклоняется и ничего не записывает
    refused = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "decision": "agree", "final_verdict": "true_positive", "comment": "Обновить до 1.4.9.",
        "reviewed": "1", "action": "copy"})
    assert refused.status_code == 400 and "короткого текста" in refused.json()["detail"], refused.text
    db = web.app.state.db
    assert db.get_review(pid, "73001") is None
    answer_json = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "decision": "agree", "final_verdict": "true_positive", "comment": "Обновить до 1.4.9.",
        "reviewed": "1", "action": "save"}).json()
    assert answer_json["ok"] and answer_json["reviewed"] and answer_json["revision"] == 1
    assert answer_json["hub_text"] == ""
    assert answer_json["kapo_state"] == "not_finished", "«Подтверждено» без уточнения – анализ не завершён"
    assert answer_json["progress"] == {"total": 3, "reviewed": 1} and answer_json["notice"] == ""
    assert answer_json["entered"] is False and answer_json["decision"] == "agree"
    review = db.get_review(pid, "73001")
    assert (review["decision"], review["final_verdict"], review["entered_hub"]) == ("agree", "true_positive", 0)
    card = web.client.get(url).text
    assert 'id="copy-hub" title="' in card and '" hidden>Скопировать короткий текст' in card
    assert "У «Обновить» короткого текста нет" in card
    # отметка у «Обновить» – о тексте дефекта набора (ADR-0091 п. 22): без готового дефекта не ставится
    r = web.client.post(f"{url}/entered", headers=AS_JSON, data={"entered": "1", "review_revision": "1"})
    assert r.status_code == 400 and "Дефект набора ещё не готов" in r.json()["detail"]
    sca_text_ready(web, url)
    card = web.client.get(url).text
    sig = re.search(r'name="defect_sig" value="([^"]*)"', card).group(1)
    assert sig and "Отметить: дефект создан в Hub" in card
    # отметка с устаревшей редакцией или по другому тексту дефекта не ставится
    r = web.client.post(f"{url}/entered", headers=AS_JSON, data={"entered": "1", "review_revision": "0",
                                                               "defect_sig": sig})
    assert r.status_code == 409 and r.json()["reason"] == "revision"
    r = web.client.post(f"{url}/entered", headers=AS_JSON, data={"entered": "1", "review_revision": "1",
                                                               "defect_sig": "другой"})
    assert r.status_code == 400 and "Текст дефекта изменился" in r.json()["detail"]
    marked = web.client.post(f"{url}/entered", headers=AS_JSON, data={"entered": "1", "review_revision": "1",
                                                                    "defect_sig": sig}).json()
    # редакция решения не меняется и в ответ не входит: иначе скрипт записал бы её в форму устаревшей вкладки
    assert marked["ok"] and marked["entered"] and "revision" not in marked
    assert db.get_review(pid, "73001")["revision"] == 1
    assert db.get_review(pid, "73001")["entered_text_hash"] == sig
    assert marked["show"] == ["entered-badge", "entered-note"] and marked["hide"] == [
        "mark-entered", "entered-changed", "entered-unconfirmed", "entered-format-updated", "entered-defect-format-updated"]
    assert marked['times']['entered-at']=={'prefix':'Дефект создан в Hub ','datetime':marked['entered_at'],'suffix':'.'}
    assert marked["message"] == "Отмечено: дефект создан в Hub."
    page = web.client.get(url).text
    assert 'id="entered-badge" title=' in page and 'id="entered-note">' in page and 'id="mark-entered" hidden' in page
    assert 'id="entered-changed"' not in page
    unmarked = web.client.post(f"{url}/entered", headers=AS_JSON, data={"entered": "0"}).json()
    assert unmarked["entered"] is False and unmarked["show"] == ["mark-entered"]
    r = web.client.post(f"{url}/entered", headers=ORIGIN, follow_redirects=False, data={
        "entered": "1", "review_revision": str(db.get_review(pid, "73001")["revision"]), "defect_sig": sig})
    assert r.status_code == 303 and r.headers["location"] == f"{url}?ok=sca_defect_entered"
    assert "Отмечено: дефект создан в Hub." in web.client.get(r.headers["location"]).text
    # после смены текста дефекта карточка показывает «текст изменился»
    sca_text_ready(web, url, target="9.9.10")
    assert 'id="entered-changed"' in web.client.get(url).text
    listing = web.client.get(f"/projects/{pid}/sca").text
    assert "2 находки · проверено 1 · в Hub 1" in listing


def test_sca_card_without_answer_and_agree_rules(web):
    pid = prepared(web)
    fid, card = sca_card(web, pid, "73003")
    assert 'data-model-verdict=""' in card and 'id="agent-empty"' in card
    assert 'value="agree" form="review-form" disabled' in card
    # без ответа агента поле комментария пустое, версия Hub безопасной не названа (ADR-0100)
    assert re.search(r'<textarea[^>]*name="comment"[^>]*></textarea>', card)
    assert "безопасная версия" not in card.lower() and "заготовка комментария ниже" not in card
    fields = form_fields(card)
    url = f"/projects/{pid}/sca/findings/{fid}/review"
    r = web.client.post(url, headers=AS_JSON, data={**fields, "decision": "agree", "action": "copy"})
    assert r.status_code == 400 and "есть ответ агента" in r.json()["detail"]
    r = web.client.post(url, headers=ORIGIN, follow_redirects=False, data={
        **fields, "decision": "disagree", "final_verdict": "false_positive", "comment": "Не используется.",
        "reviewed": "1", "action": "save"})
    assert r.status_code == 303
    review = web.app.state.db.get_review(pid, "73003")
    # своё решение без ответа агента хранится без «не согласен», в форме – «Своё решение»
    # «Своё решение» хранится как «Не согласен» (предбоевая проверка 18.10.2026, Б10)
    assert (review["decision"], review["final_verdict"], review["reviewed"]) == ("disagree", "false_positive", 1)
    card = web.client.get(f"/projects/{pid}/sca/findings/{fid}").text
    assert 'value="disagree" form="review-form" checked' in card
    # короткий текст – компонент и обоснование (ADR-0101); у 73003 только AST – публичного номера нет
    assert '<pre id="hub-text" class="hub-text">demo-xml 2.0.0: Не используется.</pre>' in card
    # «Отложить» оставляет находку непроверенной; отметить её проверенной нельзя
    fields = form_fields(card)
    web.client.post(url, headers=ORIGIN, data={**fields, "decision": "later", "reviewed": "1", "action": "save"})
    assert web.app.state.db.get_review(pid, "73003")["reviewed"] == 0
    r = web.client.post(f"/projects/{pid}/sca/findings/{fid}/reviewed", headers=AS_JSON, data={"reviewed": "1"})
    assert r.status_code == 400 and r.json()["reason"] == "later"


def test_sca_card_refuses_stale_page(web):
    pid = prepared(web)
    assert post_answers(web, pid, answers_text()).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    fields = form_fields(card)
    url = f"/projects/{pid}/sca/findings/{fid}/review"
    # пока карточка была открыта, пришёл новый ответ агента
    assert post_answers(web, pid, answers_text(recommended_version="1.4.10")).status_code == 303
    r = web.client.post(url, headers=AS_JSON, data={**fields, "decision": "agree", "action": "copy"})
    assert r.status_code == 409 and r.json()["reason"] == "answer"
    r = web.client.post(url, headers=ORIGIN, data={**fields, "decision": "disagree", "final_verdict": "uncertain",
                                                   "comment": "Мой текст.", "action": "save"})
    assert r.status_code == 409 and "новый ответ внешнего агента" in r.text and "Мой текст.</textarea>" in r.text
    # решение из второй вкладки не затирает более новое
    fresh = form_fields(web.client.get(f"/projects/{pid}/sca/findings/{fid}").text)
    assert web.client.post(url, headers=ORIGIN, follow_redirects=False,
                           data={**fresh, "decision": "agree", "action": "save"}).status_code == 303
    r = web.client.post(url, headers=AS_JSON, data={**fresh, "decision": "agree", "action": "copy"})
    assert r.status_code == 409 and r.json()["reason"] == "revision"
    # отметка «Проверено» отдельно от решения – тоже с проверкой редакции
    newest = form_fields(web.client.get(f"/projects/{pid}/sca/findings/{fid}").text)
    reviewed_url = f"/projects/{pid}/sca/findings/{fid}/reviewed"
    r = web.client.post(reviewed_url, headers=AS_JSON, data={**fresh, "reviewed": "1"})
    assert r.status_code == 409
    ok = web.client.post(reviewed_url, headers=AS_JSON, data={**newest, "reviewed": "1"}).json()
    assert ok["ok"] and ok["reviewed"] and ok["progress"]["reviewed"] == 1


def test_sca_card_next_goes_through_unreviewed_and_ends_on_sca_page(web):
    pid = prepared(web)
    db = web.app.state.db
    order = [db.get_finding_by_hub_id(pid, h)["id"] for h in ("73001", "73002", "73003")]
    location = f"/projects/{pid}/sca/findings/{order[0]}"
    for fid in order:
        assert location.startswith(f"/projects/{pid}/sca/findings/{fid}")
        card = web.client.get(location).text
        r = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=ORIGIN, follow_redirects=False,
                            data={**form_fields(card), "decision": "disagree", "final_verdict": "true_positive",
                                  "reviewed": "1", "action": "next"})
        assert r.status_code == 303
        location = r.headers["location"]
    assert location == f"/projects/{pid}/sca?ok=sca_all_reviewed#components"
    assert "Непроверенных находок SCA больше нет" in web.client.get(location).text
    second = web.client.get(f"/projects/{pid}/sca/findings/{order[1]}?saved={order[0]}").text
    assert "Сохранено: <span class=\"mono\">73001</span>" in second


def test_reimport_keeps_sca_marks_and_answers(web):
    pid = prepared(web)
    assert post_answers(web, pid, answers_text()).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    web.client.post(f"{url}/review", headers=AS_JSON, data={**form_fields(card), "decision": "agree",
                                                            "final_verdict": "true_positive", "comment": "Обновить.",
                                                            "reviewed": "1", "action": "save"})
    sca_text_ready(web, url)
    sig = re.search(r'name="defect_sig" value="([^"]*)"', web.client.get(url).text).group(1)
    web.client.post(f"{url}/entered", headers=AS_JSON, data={"entered": "1", "review_revision": "1", "defect_sig": sig})
    db = web.app.state.db
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "again.xlsx")).status_code == 303
    review = db.get_review(pid, "73001")
    assert (review["reviewed"], review["entered_hub"], review["final_comment"]) == (1, 1, "Обновить.")
    assert db.get_finding_by_hub_id(pid, "73001")["id"] == fid
    page = web.client.get(f"/projects/{pid}/sca").text
    assert "2 находки · проверено 1 · в Hub 1" in page and "до 1.4.9" in page
    # новая версия библиотеки – это другое решение: отметка снимается, ответ по старой версии не показывается
    newer = [dict(row, **{"Component version": "1.4.9"}) if row["Component name"] == "example-parser" else row
             for row in SCA_ROWS]
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "newer.xlsx", sca=newer)).status_code == 303
    assert db.get_review(pid, "73001")["reviewed"] == 0
    card = web.client.get(url).text
    assert 'id="agent-empty"' in card and "example-parser@1.4.9" in card


def test_sca_routes_accept_only_sca_findings(web):
    pid = prepared(web)
    sast_id = web.app.state.db.get_finding_by_hub_id(pid, SAST_ROWS[0]["Issue id"])["id"]
    assert web.client.get(f"/projects/{pid}/sca/findings/{sast_id}").status_code == 404
    r = web.client.post(f"/projects/{pid}/sca/findings/{sast_id}/review", headers=AS_JSON,
                        data={"decision": "later", "action": "copy"})
    assert r.status_code == 404
    assert web.client.post(f"/projects/{pid}/sca/answers", data={"answers": "{}"}).status_code == 403  # чужой источник



def test_last_deferred_sca_finding_is_not_reported_as_all_reviewed(web):
    """«Отложить» и «Дальше» на последней непроверенной: сообщение – «других нет», а не «все проверены»."""
    pid = prepared(web)
    db = web.app.state.db
    others = [r["hub_id"] for r in db._all("SELECT hub_id FROM findings WHERE project_id = ? AND kind = 'SCA' "
                                           "AND missing = 0 AND hub_id <> '73001'", (pid,))]
    assert others
    for hub_id in others:  # все остальные находки SCA проверены
        db.save_review(pid, hub_id, decision="disagree", final_verdict="false_positive", final_comment="не тот",
                       reviewed=True, kapo_state="false_positive")
    fid, card = sca_card(web, pid, "73001")
    r = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=ORIGIN, data={
        **form_fields(card), "decision": "later", "final_verdict": "", "comment": "", "action": "next"},
        follow_redirects=False)
    assert r.status_code == 303, r.text
    assert f"/sca/findings/{fid}" in r.headers["location"] and "ok=sca_no_other" in r.headers["location"]
    assert r.headers["location"].endswith("#decision")
    page = web.client.get(r.headers["location"]).text
    assert "Других непроверенных находок SCA нет – осталась только эта" in page


def test_research_contract_answer_in_the_old_form_is_explained():
    """Хвост SCA-IMP: ответ по контракту исследования компонентов (формат 2) в старой форме ответа агента – понятная
    подсказка, куда его загружать, а не «нет списка библиотек»."""
    text = json.dumps({"contract": "local-triage/sca-answer/2", "task_id": "t-1", "rows": [{"input_ref": "pypi:x"}]})
    with pytest.raises(sca.ScaInputError, match="Компоненты"):
        sca.parse_answers(text, [])
    fenced = "Ответ:" + chr(10) + "```json" + chr(10) + text + chr(10) + "```"
    with pytest.raises(sca.ScaInputError, match="Компоненты"):
        sca.parse_answers(fenced, [])

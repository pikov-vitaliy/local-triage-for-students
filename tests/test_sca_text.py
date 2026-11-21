"""Дефект SCA по шаблону команды (ADR-0091): уязвимости набора, Объяснение, целевая версия, источники и текст. Эталон
текста написан вручную, все компоненты и идентификаторы выдуманы."""

from __future__ import annotations

from app import sca_text as t

RESEARCH = {
    "public_findings": [
        {"id": "CVE-2099-10001", "aliases": ["GHSA-aaaa-bbbb-cccc"], "applies": "yes",
         "description": "Подстановка имени класса в параметры подключения ведёт к выполнению кода.",
         "conditions": "атакующий управляет строкой подключения.",
         "ranges": [{"introduced": "1.0.0", "fixed": "1.2.5"}], "source_refs": ["e1"]},
        {"id": "CVE-2099-10002", "aliases": [], "applies": "yes",
         "description": "Отказ в обслуживании при разборе вложенных структур.", "conditions": None,
         "ranges": [{"introduced": "1.0.0", "fixed": "1.2.7"}], "source_refs": ["e2"]},
        {"id": "CVE-2099-10003", "aliases": [], "applies": "no", "description": "Не затрагивает 1.2.0.",
         "conditions": None, "ranges": [{"introduced": "2.0.0", "fixed": "2.0.1"}], "source_refs": []},
    ],
    "evidence": [
        {"evidence_ref": "e1", "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "source_type": "advisory",
         "level": "primary"},
        {"evidence_ref": "e2", "url": "https://example.org/blog", "source_type": "other", "level": "single_source"},
        {"evidence_ref": "r1", "url": "https://repo.example/kit/1.2.7", "source_type": "registry", "level": "primary"},
    ],
    "package_advice": {"action": "update", "target_version": "1.2.7", "source_refs": ["r1"]},
    "latest_stable_release": {"version": "1.2.7", "source_refs": ["r1"]},
    "research_coverage": [{"purpose": "vulnerabilities", "status": "ok", "complete": True}],
}


def test_set_vulns_merges_aliases_and_follows_membership():
    vulns = t.set_vulns(members={"200250": ["AST-2026-000150"]}, others={"200251": ["AST-2026-000151"]},
                        aliases={"AST-2026-000150": ["CVE-2099-10001"], "AST-2026-000151": ["CVE-2099-10003"]},
                        research=RESEARCH["public_findings"])
    mains = [v.main for v in vulns]
    assert mains == ["CVE-2099-10001", "CVE-2099-10002"], "AST слит с CVE и GHSA; применимая CVE исследования – в " \
                                                          "набор по умолчанию; CVE другой находки – нет"
    assert set(vulns[0].ids) == {"AST-2026-000150", "CVE-2099-10001", "GHSA-aaaa-bbbb-cccc"}
    assert vulns[0].hub_members == ["200250"]
    second = t.set_vulns(members={"200250": ["AST-2026-000150"]}, others={},
                         aliases={"AST-2026-000150": ["CVE-2099-10001"]}, research=RESEARCH["public_findings"],
                         default_set=False)
    assert [v.main for v in second] == ["CVE-2099-10001"], "в отдельный набор – только уязвимости его находок"
    excluded = t.set_vulns(members={"200250": ["CVE-2099-10001"]}, others={}, aliases={},
                           research=RESEARCH["public_findings"], excluded=["CVE-2099-10002"])
    assert [v.main for v in excluded] == ["CVE-2099-10001"]


def test_unknown_ast_stays_and_is_not_public():
    vulns = t.set_vulns(members={"1": ["AST-2026-999999"]}, others={}, aliases={}, research=[])
    assert [v.main for v in vulns] == ["AST-2026-999999"] and not vulns[0].public


def test_explanation_draft_and_problems():
    vulns = t.set_vulns(members={"1": ["CVE-2099-10001"]}, others={}, aliases={},
                        research=RESEARCH["public_findings"])
    bdu = {"CVE-2099-10002": [{"id": "BDU:2099-00001", "description": "Уязвимость разбора вложенных структур "
                                                                     "позволяет вызвать отказ в обслуживании."}]}
    draft = t.explanation_draft(vulns, bdu)
    assert draft.split("\n") == [
        "CVE-2099-10001: Подстановка имени класса в параметры подключения ведёт к выполнению кода. Условия: атакующий "
        "управляет строкой подключения.",
        "CVE-2099-10002: Уязвимость разбора вложенных структур позволяет вызвать отказ в обслуживании."]
    assert t.explanation_problems(draft, vulns) == []
    assert t.explanation_problems("CVE-2099-10001: коротко", vulns) == ["CVE-2099-10001", "CVE-2099-10002"]
    assert t.cyrillic_share(draft) > 0.5 and t.cyrillic_share("Only English text here") == 0.0


def test_target_priority_and_contradiction():
    today = "2026-10-23"
    assert t.resolve_target("1.3.0", {"action": "update", "target_version": "1.2.9"}, RESEARCH, None, today) \
        == t.Target("1.3.0", "manual")
    assert t.resolve_target("", {"action": "update", "target_version": "1.2.9"}, RESEARCH, None, today).version \
        == "1.2.9"
    keep = t.resolve_target("", {"action": "keep"}, RESEARCH, None, today)
    assert keep.version == "" and "противоречит" in keep.problem
    expired = t.resolve_target("", {"action": "keep", "review_at": "2026-10-01"}, RESEARCH, None, today)
    assert expired == t.Target("1.2.7", "research"), "решение с наступившим сроком пересмотра – не основание"
    assert t.resolve_target("", None, None, {"recommended_version": "1.2.6"}, today) == t.Target("1.2.6", "legacy")
    assert "Нет проверенной целевой версии" in t.resolve_target("", None, None, None, today).problem


def test_version_check():
    ok = t.check_version("maven", "1.2.0", "1.2.7", RESEARCH, "2026-10-20")
    assert ok.state == "verified" and "2026-10-20" in ok.detail
    hub = t.check_version("maven", "1.2.0", "1.2.5", RESEARCH)
    assert hub.state == "affected" and hub.affected == ["CVE-2099-10002"], "версия Hub сама уязвима"
    assert t.check_version("maven", "1.2.0", "1.2.7", None).state == "unverified"
    partial = {**RESEARCH, "research_coverage": [{"purpose": "vulnerabilities", "status": "partial",
                                                 "complete": False}]}
    assert t.check_version("maven", "1.2.0", "1.2.7", partial).state == "unverified"
    # цель не новее текущей – запрет, отметка «Версию проверил сам» его не снимает (ADR-0094 Р1.3)
    assert t.check_version("maven", "1.3.0", "1.2.9", RESEARCH).state == "not_newer", "не новее текущей"
    unpublished = {**RESEARCH, "latest_stable_release": {}, "package_advice": {"target_version": "1.2.8"}}
    check = t.check_version("maven", "1.2.0", "1.2.8", unpublished)
    assert check.state == "unverified" and "публикация" in check.detail
    assert t.check_version("maven", "1.2.0", "1.2.7-vendor", RESEARCH).state == "unverified", "порядок неизвестен"
    assert t.hub_note("maven", ["1.2.5"], "1.2.7", RESEARCH) == "", "ответ без проверки версий – пояснения нет"


def test_body_matches_team_template():
    vulns = t.set_vulns(members={"200250": ["CVE-2099-10001"]}, others={}, aliases={},
                        research=RESEARCH["public_findings"])
    explanation = ("CVE-2099-10001: Подстановка имени класса в параметры подключения ведёт к выполнению кода.\n"
                   "CVE-2099-10002: Отказ в обслуживании при разборе вложенных структур.")
    sources = t.research_sources(vulns, RESEARCH, "1.2.7")
    # реестр – доказательство публикации, но не источник для получателя дефекта (Г7); непервоисточник не входит
    assert sources == ["https://github.com/advisories/GHSA-aaaa-bbbb-cccc"], "непервоисточник и реестр не входят"
    note = "CVE-2099-10002 затрагивает версию 1.2.5 по данным исследования от 2026-10-20; указана версия 1.2.7."
    text = t.body("org.example.thirdparty:example-json-kit", vulns, explanation, "1.2.7", sources, note)
    assert text == (
        "Описание\n"
        "CVE-2099-10001 (https://nvd.nist.gov/vuln/detail/CVE-2099-10001)\n"
        "Также затрагивают эту версию:\n"  # по исследованию, Hub её не нашёл (ADR-0101)
        "CVE-2099-10002 (https://nvd.nist.gov/vuln/detail/CVE-2099-10002)\n"
        "\n"
        "Объяснение\n"
        "CVE-2099-10001: Подстановка имени класса в параметры подключения ведёт к выполнению кода.\n"
        "CVE-2099-10002: Отказ в обслуживании при разборе вложенных структур.\n"
        "\n"
        "Рекомендации\n"
        "CVE-2099-10002 затрагивает версию 1.2.5 по данным исследования от 2026-10-20; указана версия 1.2.7.\n"
        "Обновление org.example.thirdparty:example-json-kit до версии 1.2.7\n"
        "\n"
        "Источники\n"
        "https://nvd.nist.gov/vuln/detail/CVE-2099-10001\n"
        "https://nvd.nist.gov/vuln/detail/CVE-2099-10002\n"
        "https://github.com/advisories/GHSA-aaaa-bbbb-cccc\n")
    for banned in ("безопасн", "или новее", "ГОСТ", "Заключение", "Требуется от разработчика", "Сводка"):
        assert banned not in text


def test_links_by_kind():
    assert t.link_of("GHSA-AAAA-bbbb-CCCC") == "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"
    assert t.link_of("BDU:2099-00001") == "https://bdu.fstec.ru/vul/2099-00001"
    assert t.link_of("AST-2026-1") == ""


def test_ids_of_one_finding_are_separate_vulnerabilities():
    """Две CVE одной находки без известного соответствия – две уязвимости: совместное присутствие в находке
    соответствием не является (ADR-0091 п. 8)."""
    vulns = t.set_vulns(members={"1": ["CVE-2099-20001", "CVE-2099-20002"]}, others={}, aliases={}, research=[])
    assert [v.main for v in vulns] == ["CVE-2099-20001", "CVE-2099-20002"]
    excluded = t.set_vulns(members={"1": ["CVE-2099-20001", "CVE-2099-20002"]}, others={}, aliases={}, research=[],
                           excluded=["CVE-2099-20002"])
    assert [v.main for v in excluded] == ["CVE-2099-20001"]

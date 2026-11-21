"""Шаг 3 плана dev17 (п. 4.3), часть 1: загрузчики находки кладут эффективную идентичность пакета в data["package"];
экосистема, подпись решения SCA и снимок пакета – по эффективной тройке. Пока колонки pkg_* пусты (до принятия Hub),
всё как раньше. Данные выдуманы."""

from __future__ import annotations

from app import package_identity as pi
from app.db import dumps, review_signature
from app.ecosystem import finding_ecosystem
from app.models import Finding
from test_hub_status_routes import project, sca
from test_web import web  # noqa: F401


def _apply(db, pid: int, hub_id: str, ecosystem: str, name: str, note: str = "") -> None:
    with db._tx() as c:
        c.execute("UPDATE findings SET pkg_ecosystem = ?, pkg_name = ?, pkg_source = 'hub', pkg_note = ?,"
                  " pkg_scope = 'h|7' WHERE project_id = ? AND hub_id = ?", (ecosystem, name, note, pid, hub_id))


def test_empty_columns_change_nothing(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sca("73001")])
    row = db.get_finding_by_hub_id(pid, "73001")
    data = row["data"]
    assert data["package"]["source"] == ""
    plain = {k: v for k, v in data.items() if k != "package"}
    assert review_signature(data) == review_signature(plain), "подпись прежняя"
    assert finding_ecosystem(data) == finding_ecosystem(plain)
    assert pi.of(data) == ("", "org.example:lib", "1.2.3")
    assert "package" not in Finding.from_dict(data).to_dict()
    stored = db._one("SELECT data_json FROM findings WHERE project_id = ? AND hub_id = '73001'", (pid,))["data_json"]
    assert "package" not in stored


def test_empty_columns_keep_raw_strings(web):  # noqa: F811
    """Компонент и версия с пробелами по краям: без сведений Hub тройка и подпись – как прежде, без обрезки (ревью
    Kimi, шаг 3)."""
    db = web.app.state.db
    one = sca("73001")
    one.component, one.version = "lib ", " 1.0"
    pid = project(web, [one])
    data = db.get_finding_by_hub_id(pid, "73001")["data"]
    assert pi.of(data) == ("", "lib ", " 1.0")
    assert review_signature(data) == review_signature({k: v for k, v in data.items() if k != "package"})
    with db._tx() as c:
        state = db._sca_package_state(c, pid, "73001")
    assert [m["hub_id"] for m in state["members"]] == ["73001"]


def test_hub_identity_reaches_loaders_and_signature(web):  # noqa: F811
    db = web.app.state.db
    one, two = sca("73001"), sca("73002")
    one.component, one.build_type = "spring-core", "npm"
    two.component, two.build_type = "org.springframework:spring-core", "maven"
    pid = project(web, [one, two])
    before = review_signature(db.get_finding_by_hub_id(pid, "73001")["data"])
    _apply(db, pid, "73001", "maven", "org.springframework:spring-core")
    data = db.get_finding_by_hub_id(pid, "73001")["data"]
    assert finding_ecosystem(data) == "maven"
    f = Finding.from_dict(data)
    assert (f.package_name, f.package_display_name) == ("org.springframework:spring-core", "spring-core")
    after = review_signature(data)
    assert after != before and '"package": "org.springframework:spring-core"' in after
    rows = {r["hub_id"]: r for r in db.findings_data(pid)}
    assert rows["73001"]["data"]["package"]["source"] == "hub"
    listed, _ = db.list_findings(pid, kind="SCA")
    assert {r["hub_id"]: r["data"]["package"]["source"] for r in listed} == {"73001": "hub", "73002": ""}
    # снимок пакета: обе находки – одна тройка (maven, spring-core 1.2.3), хотя компонент и Type в выгрузке разные
    with db._tx() as c:
        state = db._sca_package_state(c, pid, "73001")
    assert sorted(m["hub_id"] for m in state["members"]) == ["73001", "73002"]
    stored = db._one("SELECT data_json FROM findings WHERE project_id = ? AND hub_id = '73001'", (pid,))["data_json"]
    assert "package" not in stored and dumps(data) != stored


def test_consumers_agree_on_hub_identity(web):  # noqa: F811
    """Часть 2 шага 3 (находки Kimi): при применённых сведениях Hub подпись сохранённого решения, ключ номера дефекта
    находки и ключ набора дефекта SCA – по одной эффективной тройке; без сведений – прежние значения."""
    from app.defect import defect_key_sca
    from app.routes.sca import set_key
    db = web.app.state.db
    one = sca("73001")
    one.component, one.build_type = "spring-core", "npm"
    pid = project(web, [one])
    with db._tx() as c:
        plain_keys = db.defect_keys_of_findings_in(c, pid, ["73001"])
    assert plain_keys == {defect_key_sca("spring-core", "1.2.3", "npm")}, "без сведений Hub – прежний ключ"
    _apply(db, pid, "73001", "maven", "org.springframework:spring-core")
    data = db.get_finding_by_hub_id(pid, "73001")["data"]
    effective = defect_key_sca("org.springframework:spring-core", "1.2.3", "maven")
    with db._tx() as c:
        assert db.defect_keys_of_findings_in(c, pid, ["73001"]) == {effective}
        source = db._source(c, pid, "73001")
    assert source["data"]["package"]["source"] == "hub"
    assert set_key(Finding.from_dict(data), 0) == effective and set_key(Finding.from_dict(data), 2) == effective + "#2"
    db.save_review(pid, "73001", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True)
    stored = db._one("SELECT finding_sig FROM reviews WHERE project_id = ? AND hub_id = '73001'", (pid,))["finding_sig"]
    assert stored == review_signature(data), "решение сохранено по той же тройке, которой его сверяет карточка"


def test_agent_answers_follow_effective_identity(web):  # noqa: F811
    """Ответы агента ищутся по эффективной тройке и в снимке, и в базе (ревью Kimi, шаг 3, круг 2)."""
    from app.routes.sca import _agent_answers
    db = web.app.state.db
    one = sca("73001")
    one.component, one.build_type = "spring-core", "npm"
    pid = project(web, [one])
    _apply(db, pid, "73001", "maven", "org.springframework:spring-core")
    f = Finding.from_dict(db.get_finding_by_hub_id(pid, "73001")["data"])
    seen = []
    real = type(db).sca_answers

    def spy(self, project_id, component, version, ecosystem=None, *a, **k):
        seen.append((ecosystem, component, version))
        return real(self, project_id, component, version, ecosystem, *a, **k)
    type(db).sca_answers = spy
    try:
        _agent_answers(db, pid, f)
    finally:
        type(db).sca_answers = real
    assert seen and seen[0] == ("maven", "org.springframework:spring-core", "1.2.3")
    snap = db.sca_snapshot(pid, "73001")
    assert isinstance(_agent_answers(snap, pid, f), list), "снимок принимает эффективную тройку без LookupError"


def test_component_groups_and_usages_by_effective_identity(web):  # noqa: F811
    """Часть 3 шага 3: группы компонентов и «Где используется» – по эффективной тройке; без сведений Hub группы
    прежние, у групп – источник идентичности, пометки и имена из выгрузки."""
    from app.sca_contract import input_ref
    db = web.app.state.db
    one, two = sca("73001"), sca("73002")
    one.component, one.build_type = "spring-core", "npm"
    two.component, two.build_type = "org.springframework:spring-core", "maven"
    pid = project(web, [one, two])
    before = {(g["ecosystem"], g["component"], g["version"]): g["hub_ids"] for g in db.sca_components(pid)}
    assert before == {("npm", "spring-core", "1.2.3"): ["73001"],
                      ("maven", "org.springframework:spring-core", "1.2.3"): ["73002"]}
    assert all(g["identity_source"] == "" for g in db.sca_components(pid))
    _apply(db, pid, "73001", "maven", "org.springframework:spring-core", note="version_mismatch:1.2.0")
    groups = db.sca_components(pid)
    assert len(groups) == 1
    g = groups[0]
    assert (g["ecosystem"], g["component"], sorted(g["hub_ids"])) == \
        ("maven", "org.springframework:spring-core", ["73001", "73002"])
    assert g["identity_source"] == "hub" and g["identity_notes"] == ["version_mismatch:1.2.0"]
    assert sorted(g["export_components"]) == ["org.springframework:spring-core", "spring-core"]
    ref = input_ref("maven", "org.springframework:spring-core", "1.2.3")
    assert sorted(u["hub_id"] for u in db.sca_usages(pid, ref)) == ["73001", "73002"]
    assert db.sca_usages(pid, input_ref("npm", "spring-core", "1.2.3")) == []


def test_import_findings_names_effective_package(web):  # noqa: F811
    """Занесение и сверка дефектов (import_findings_in) называют эффективное имя пакета; без сведений – компонент."""
    db = web.app.state.db
    one = sca("73001")
    one.component = "spring-core"
    pid = project(web, [one])
    assert db.import_findings(pid, ["73001"])["73001"]["component"] == "spring-core"
    sig = db.import_findings(pid, ["73001"])["73001"]["sig"]
    _apply(db, pid, "73001", "maven", "org.springframework:spring-core")
    found = db.import_findings(pid, ["73001"])["73001"]
    assert found["component"] == "org.springframework:spring-core" and found["sig"] == sig, "данные находки те же"


def test_main_answer_and_legacy_ecosystems_by_effective_identity(web):  # noqa: F811
    """Часть 5 шага 3: главный ответ агента ищется по эффективной тройке; экосистема ответа прежнего формата без
    экосистемы определяется по эффективным пакетам проекта."""
    db = web.app.state.db
    one = sca("73001")
    one.component, one.build_type = "spring-core", "npm"
    pid = project(web, [one])
    with db._tx() as c:
        assert db._package_ecosystems_in(c, pid, "spring-core", "1.2.3") == {"npm"}
    _apply(db, pid, "73001", "maven", "org.springframework:spring-core")
    data = db.get_finding_by_hub_id(pid, "73001")["data"]
    with db._tx() as c:
        assert db._package_ecosystems_in(c, pid, "spring-core", "1.2.3") == set()
        assert db._package_ecosystems_in(c, pid, "org.springframework:spring-core", "1.2.3") == {"maven"}
        c.execute("INSERT INTO sca_answers(project_id, source, component, version, ecosystem, conclusion, created_at,"
                  " updated_at) VALUES (?, 'agent', 'org.springframework:spring-core', '1.2.3', 'maven', 'update',"
                  " '2026-11-09', '2026-11-09')", (pid,))
        answer_id, _ = db._main_answer(c, pid, data)
    assert answer_id, "ответ по эффективной тройке найден"


def test_family_set_key_and_no_defect_by_effective_identity(web):  # noqa: F811
    """Часть 8 шага 3: ключ набора семейства дефекта и пометка «без дефекта» – по эффективной тройке."""
    from app.defect import defect_key_sca
    from app.defect_drafts import in_some_set, sca_identity
    from app.sca_contract import input_ref
    db = web.app.state.db
    one = sca("73001")
    one.component, one.build_type = "spring-core", "npm"
    pid = project(web, [one])
    with db._tx() as c:
        assert sca_identity(c, pid, [{"hub_id": "73001"}]) == (defect_key_sca("spring-core", "1.2.3", "npm"), [])
    _apply(db, pid, "73001", "maven", "org.springframework:spring-core")
    ref = input_ref("maven", "org.springframework:spring-core", "1.2.3")
    with db._tx() as c:
        assert sca_identity(c, pid, [{"hub_id": "73001"}]) == \
            (defect_key_sca("org.springframework:spring-core", "1.2.3", "maven"), [])
        assert in_some_set(c, pid, ["73001"]) == ["73001"]
        c.execute("INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, updated_at) VALUES"
                  " (?, '73001', ?, NULL, '2026-11-09')", (pid, ref))
        assert in_some_set(c, pid, ["73001"]) == [], "пометка «без дефекта» по эффективному пакету действует"


def _agree_reviewed(db, pid, hub_id, answer_sig):
    db.save_review(pid, hub_id, decision="agree", final_verdict="true_positive", final_comment="Обновить.", reviewed=True)
    with db._tx() as c:
        c.execute("UPDATE reviews SET answer_sig = ? WHERE project_id = ? AND hub_id = ?", (answer_sig, pid, hub_id))


def test_new_answer_and_research_reopen_by_effective_identity(web):  # noqa: F811
    """Часть 10 шага 3 (ревью Kimi): новый ответ агента и новая ревизия исследования по эффективной тройке снимают
    «Проверено» у согласий с прежним ответом."""
    from app.sca_contract import input_ref
    db = web.app.state.db
    one, two = sca("73001"), sca("73002")
    one.component = two.component = "spring-core"
    one.build_type = two.build_type = "npm"
    pid = project(web, [one, two])
    for hub_id in ("73001", "73002"):
        _apply(db, pid, hub_id, "maven", "org.springframework:spring-core")
    _agree_reviewed(db, pid, "73001", "прежний ответ")
    db.save_sca_answers(pid, "agent", [{"component": "org.springframework:spring-core", "version": "1.2.3",
                                        "ecosystem": "maven", "conclusion": "update", "recommended_version": "6.1.0",
                                        "explanation": "Уязвимость исправлена в 6.1.0."}])
    assert not db.get_review(pid, "73001")["reviewed"], "новый ответ по эффективной тройке снял «Проверено»"
    _agree_reviewed(db, pid, "73002", "research:прежний")
    with db._tx() as c:
        reopened = db._reopen_after_research(c, pid, {input_ref("maven", "org.springframework:spring-core", "1.2.3")},
                                             "2026-11-09")
    assert reopened == 1 and not db.get_review(pid, "73002")["reviewed"]


def test_set_form_checks_shown_package_and_identity_revision(web):  # noqa: F811
    """Часть 12 шага 3 (план dev17, п. 4.3, 4.5): форма выбора набора передаёт показанный пакет и ревизию идентичности
    находки; перенос сверяет оба в транзакции, при совпадении снимает причину pending_reason."""
    import pytest
    from app.db import StaleReview
    from app.sca_contract import input_ref
    from test_hub_status_routes import fid
    db = web.app.state.db
    pid = project(web, [sca("73001")])
    db.save_review(pid, "73001", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=False)
    page = web.client.get(f"/projects/{pid}/sca/findings/{fid(web, pid, '73001')}").text
    ref = input_ref("", "org.example:lib", "1.2.3")
    assert f'name="shown_ref" value="{ref}"' in page and 'name="shown_pkg_rev" value="0"' in page
    with db._tx() as c:
        c.execute("INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, updated_at, pending_reason) VALUES"
                  " (?, '73001', ?, 2, '2026-11-09', 'после слияния пакетов: место в наборах выбрать заново')", (pid, ref))
    sets = db.sca_sets(pid, ref)
    expect = {n: v["revision"] for n, v in sets.items()}
    expect.setdefault(2, 0)
    with db._tx() as c:
        c.execute("UPDATE findings SET pkg_rev = 3 WHERE project_id = ? AND hub_id = '73001'", (pid,))
    with pytest.raises(StaleReview):  # форма, открытая до перехода (ревизия 0), – отказ, причина на месте
        db.move_sca_member(pid, ref, "73001", 1, "", expect, expect_input_ref=ref, expect_pkg_rev=0)
    with pytest.raises(StaleReview):  # другой показанный пакет – отказ
        db.move_sca_member(pid, ref, "73001", 1, "", expect, expect_input_ref="npm|x|1", expect_pkg_rev=3)
    reason = db._one("SELECT pending_reason FROM sca_set_members WHERE project_id = ? AND hub_id = '73001'", (pid,))
    assert reason["pending_reason"].startswith("после слияния")
    db.move_sca_member(pid, ref, "73001", 1, "", {**expect, 1: 0}, expect_input_ref=ref, expect_pkg_rev=3)
    row = db._one("SELECT set_no, pending_reason FROM sca_set_members WHERE project_id = ? AND hub_id = '73001'", (pid,))
    assert (row["set_no"], row["pending_reason"]) == (1, ""), "выбор места из актуальной карточки снимает причину"


def test_reimport_keeps_reviewed_with_hub_identity(web):  # noqa: F811
    """Часть 13 шага 3 (план п. 4.4, ревью Kimi): принятие Hub → проверенное решение → повторный импорт того же файла:
    «Проверено» на месте, колонки идентичности сохранены, data_json – данные файла."""
    from app.triage import order_findings
    db = web.app.state.db
    one = sca("73001")
    one.component, one.build_type = "spring-core", "npm"
    pid = project(web, [one])
    _apply(db, pid, "73001", "maven", "org.springframework:spring-core")
    db.save_review(pid, "73001", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True)
    stored = db._one("SELECT data_json FROM findings WHERE project_id = ? AND hub_id = '73001'", (pid,))["data_json"]
    stats = db.save_import(pid, "x.xlsx", "xlsx", [], {}, [], order_findings([one]))
    assert stats["reopened"] == 0 and stats["unchanged"] == 1, stats
    assert db.get_review(pid, "73001")["reviewed"]
    row = db._one("SELECT data_json, pkg_source, pkg_name FROM findings WHERE project_id = ? AND hub_id = '73001'", (pid,))
    assert (row["pkg_source"], row["pkg_name"]) == ("hub", "org.springframework:spring-core")
    assert row["data_json"] == stored and "package" not in row["data_json"]


def test_leave_sets_keeps_member_with_pending_reason(web):  # noqa: F811
    """План dev17, п. 4.1: смена исхода «Обновить» не трогает участника с причиной pending_reason."""
    from app.sca_contract import input_ref
    db = web.app.state.db
    pid = project(web, [sca("73001"), sca("73002")])
    ref = input_ref("", "org.example:lib", "1.2.3")
    with db._tx() as c:
        c.execute("INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, updated_at, pending_reason) VALUES"
                  " (?, '73001', ?, 2, '2026-11-09', 'после слияния пакетов: место в наборах выбрать заново'),"
                  " (?, '73002', ?, 3, '2026-11-09', '')", (pid, ref, pid, ref))
        db.sca_leave_sets(c, pid, ref, ["73001", "73002"], "2026-11-09")
    rows = {r["hub_id"]: r["set_no"] for r in db._all("SELECT hub_id, set_no FROM sca_set_members WHERE project_id = ?",
                                                      (pid,))}
    assert rows == {"73001": 2}, "участник с причиной остался, без причины – вышел, как раньше"


def test_old_set_form_without_fields(web):  # noqa: F811
    """Форма без shown_ref и shown_pkg_rev (страница до обновления): без перехода идентичности работает как раньше; после
    перехода или при причине «выбрать место заново» – отказ, место и причина на месте (ревью Kimi, шаг 3, круг 5)."""
    import pytest
    from app.db import StaleReview
    from app.sca_contract import input_ref
    db = web.app.state.db
    pid = project(web, [sca("73001"), sca("73002")])
    ref = input_ref("", "org.example:lib", "1.2.3")
    db.move_sca_member(pid, ref, "73001", 1, "", {0: 0, 1: 0})  # без полей, идентичность не менялась – как раньше
    assert db._one("SELECT set_no FROM sca_set_members WHERE project_id = ? AND hub_id = '73001'", (pid,))["set_no"] == 1
    with db._tx() as c:
        c.execute("UPDATE sca_set_members SET pending_reason = 'после слияния пакетов' WHERE project_id = ?"
                  " AND hub_id = '73001'", (pid,))
    expect = {n: v["revision"] for n, v in db.sca_sets(pid, ref).items()}
    with pytest.raises(StaleReview):
        db.move_sca_member(pid, ref, "73001", 0, "", {**expect, 0: expect.get(0, 0)})
    assert db._one("SELECT pending_reason FROM sca_set_members WHERE project_id = ? AND hub_id = '73001'",
                   (pid,))["pending_reason"] == "после слияния пакетов"
    with db._tx() as c:
        c.execute("UPDATE findings SET pkg_rev = 1 WHERE project_id = ? AND hub_id = '73002'", (pid,))
    with pytest.raises(StaleReview):
        db.move_sca_member(pid, ref, "73002", 2, "", {0: 0, 2: 0})

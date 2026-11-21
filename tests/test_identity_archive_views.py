"""Шаг 5 плана dev17 (п. 4.6, «Архив в исторических представлениях»): исследования и решения, снятые переходом
идентичности пакетов, видны в истории – в карточке, списке и отчёте компонентов – и не подменяют главный ответ и
действующее решение; прежний адрес карточки перенесённой группы ведёт на новую, группы только в архиве – на карточку
для чтения. Пакеты и номера выдуманы."""

from __future__ import annotations

import json

from app.sca_contract import input_ref
from test_package_transition import NEW, OLD, made, task_row, transition
from test_sca_applicability import put_research
from test_web import web  # noqa: F401


def _research(db, pid, ref, coordinates):
    put_research(db, pid, ref, {"identity_resolution": {"state": "resolved", "coordinates": coordinates}})


def test_refine_redirects_old_card_to_the_moved_group(web):  # noqa: F811
    """Уточнение: исследование переходит вместе с группой; прежний адрес карточки – перенаправление на новую."""
    db, pid = made(web, ("73001", "lib", "maven"))
    s, t = input_ref(*OLD), input_ref(*NEW)
    _research(db, pid, s, "org.example:lib")
    task_row(db, pid, s, "maven", "lib", "1.2.3")
    transition(db, pid, {"73001": NEW[:2]})
    assert db.moved_ref(pid, s) == t and db.moved_from(pid, t) == [s]
    r = web.client.get(f"/projects/{pid}/components/{s}", follow_redirects=False)
    assert r.status_code in (302, 303) and r.headers["location"].endswith(f"/projects/{pid}/components/{t}")
    page = web.client.get(f"/projects/{pid}/components/{t}").text
    assert 'id="identity-archive"' not in page, "исследование перенесено – архива у группы нет"
    assert "Компонент не исследован" not in page


def test_change_shows_archived_research_on_the_new_card_without_using_it(web):  # noqa: F811
    """Смена экосистемы: исследование прежней тройки – в архиве; новая карточка показывает его в истории с прежней
    тройкой и причиной, но главный ответ из архива не берёт; прежний адрес – на новую карточку."""
    db, pid = made(web, ("73001", "lib", "npm"))
    s, t = input_ref("npm", "lib", "1.2.3"), input_ref(*NEW)
    _research(db, pid, s, "lib")
    task_row(db, pid, s, "npm", "lib", "1.2.3")
    transition(db, pid, {"73001": NEW[:2]})
    assert db._all("SELECT 1 FROM sca2_research WHERE project_id = ?", (pid,)) == []
    r = web.client.get(f"/projects/{pid}/components/{s}", follow_redirects=False)
    assert r.status_code in (302, 303) and r.headers["location"].endswith(f"/projects/{pid}/components/{t}")
    page = web.client.get(f"/projects/{pid}/components/{t}").text
    assert 'id="identity-archive"' in page and "npm lib@1.2.3" in page and "исследование" in page
    assert "Компонент не исследован" in page, "главный ответ не берётся из архива"
    report = web.client.get(f"/projects/{pid}/components/report?format=json")
    assert report.status_code == 200
    archived = json.loads(report.text).get("identity_archive") or []
    assert [(a["input_ref"], a["table"]) for a in archived] == [(s, "sca2_research")]


def test_split_keeps_the_old_group_readable_from_archive(web):  # noqa: F811
    """Расщепление: группа не переносится – её исследование только в архиве; строка списка помечена «архив», без
    состава в заданиях карточка – только для чтения с баннером; действующего решения из архива нет."""
    db, pid = made(web, ("73001", "lib", "maven"), ("73002", "lib", "maven"))
    s = input_ref(*OLD)
    _research(db, pid, s, "lib")
    with db._tx() as c:
        c.execute("INSERT INTO sca2_decisions(project_id, input_ref, revision, action, rationale, state, decided_at,"
                  " input_sig, research_sig) VALUES (?, ?, 1, 'accept', 'Оставить: риск принят.', 'current', 'x', '', '')",
                  (pid, s))
    transition(db, pid, {"73001": ("maven", "org.a:lib"), "73002": ("maven", "org.b:lib")})
    assert db.moved_ref(pid, s) == "" and s in db.archived_refs(pid)
    assert db.decisions(pid) == {}, "решение снято – действующего нет"
    page = web.client.get(f"/projects/{pid}/components/{s}")
    assert page.status_code == 200
    assert 'id="archive-banner"' in page.text and 'id="identity-archive"' in page.text
    assert "Оставить: риск принят." in page.text and "maven lib@1.2.3" in page.text
    assert web.client.get(f"/projects/{pid}/components/maven:{'0' * 16}").status_code == 404, "чужой адрес – как раньше"


def test_split_with_a_task_row_lists_the_old_group_as_archive(web):  # noqa: F811
    """Тот же случай, когда прежняя строка есть в сохранённом составе: строка списка – с пометкой «архив», её
    карточка показывает архив в истории."""
    db, pid = made(web, ("73001", "lib", "maven"), ("73002", "lib", "maven"))
    s = input_ref(*OLD)
    _research(db, pid, s, "lib")
    task_row(db, pid, s, "maven", "lib", "1.2.3")
    transition(db, pid, {"73001": ("maven", "org.a:lib"), "73002": ("maven", "org.b:lib")})
    listing = web.client.get(f"/projects/{pid}/components").text
    assert f"/projects/{pid}/components/{s}" in listing and ">архив</span>" in listing
    page = web.client.get(f"/projects/{pid}/components/{s}").text
    assert 'id="identity-archive"' in page and 'id="archive-banner"' not in page


def test_mark_texts_follow_the_rule_notes():
    """П. 4.6: пометки – по разнице эффективной идентичности с выгрузкой и по кодам pkg_note; без сведений Hub – нет."""
    from app import package_identity as pi
    def data(eco, name, note="", source="hub", build_type="npm", component="core"):
        return {"build_type": build_type, "component": component, "version": "1.2.3",
                "package": {"source": source, "ecosystem": eco, "name": name, "note": note}}
    assert pi.mark_texts(data("npm", "@angular/core")) == ["координаты дополнены по Hub: в выгрузке – core"]
    assert pi.mark_texts(data("maven", "org.example:core", "version_mismatch:1.2.4")) == [
        "экосистема уточнена по Hub: в выгрузке – npm", "координаты дополнены по Hub: в выгрузке – core",
        "версия по Hub – 1.2.4"]
    assert pi.mark_texts(data("npm", "other", "name_replaced:core")) == ["имя по Hub: в выгрузке – core"]
    assert pi.mark_texts(data("npm", "core", "no_name", source="file")) == ["в сведениях Hub нет имени библиотеки"]
    assert pi.mark_texts(data("pypi", "core", "rule_missing:pypi:org.example", source="file")) == [
        "у Hub есть groupId (org.example), правило для pypi не задано"]
    assert pi.mark_texts(data("", "core", source="file")) == []


def test_marks_on_pages_and_read_only_identity_report(web):  # noqa: F811
    """Пометки «координаты дополнены по Hub» – в таблице SCA, карточке находки и карточке компонента; отчёт перехода
    показывает перенос группы и ничего не пишет (операций Hub не появляется)."""
    db, pid = made(web, ("73001", "lib", "maven"))
    s, t = input_ref(*OLD), input_ref(*NEW)
    _research(db, pid, s, "org.example:lib")
    task_row(db, pid, s, "maven", "lib", "1.2.3")
    transition(db, pid, {"73001": NEW[:2]})
    mark = "координаты дополнены по Hub: в выгрузке – lib"
    fid = db.get_finding_by_hub_id(pid, "73001")["id"]
    assert mark in web.client.get(f"/projects/{pid}/sca").text
    card = web.client.get(f"/projects/{pid}/sca/findings/{fid}").text
    assert 'id="identity-marks"' in card and mark in card
    component = web.client.get(f"/projects/{pid}/components/{t}").text
    assert 'id="component-identity-marks"' in component and mark in component
    assert 'id="identity-report-link"' in web.client.get(f"/projects/{pid}/components").text
    ops = db._all("SELECT id FROM hub_ops")
    report = web.client.get(f"/projects/{pid}/identity-report")
    assert report.status_code == 200
    assert "Перенесено групп: 1." in report.text and "maven lib 1.2.3" in report.text
    assert db._all("SELECT id FROM hub_ops") == ops, "страница только читает"


def _mark(db, pid, old_ref, triple, to_ref, stamp):
    """Отметка группы, как её пишет вторая фаза перехода."""
    from app.db import dumps
    with db._tx() as c:
        c.execute("INSERT INTO sca_identity_archive(project_id, archived_at, source_table, key_json, row_json,"
                  " moved_to_ref, reason) VALUES (?, ?, 'group', ?, ?, ?, 'перенос')",
                  (pid, stamp, dumps({"input_ref": old_ref}), dumps({"triple": list(triple)}), to_ref))


def test_later_split_cancels_old_redirect_and_cycles_do_not_loop(web):  # noqa: F811
    """Ревью Codex, круг 2: A перенесена в B, затем B обратно в A, затем A расщеплена – прежний перенос A не действует,
    B ведёт в A, цикла перенаправлений нет."""
    db, pid = made(web, ("73001", "lib", "maven"))
    a, b = input_ref("maven", "a", "1.0"), input_ref("maven", "b", "1.0")
    _mark(db, pid, a, ("maven", "a", "1.0"), b, "2026-11-10T01:00:00+00:00")
    _mark(db, pid, b, ("maven", "b", "1.0"), a, "2026-11-10T02:00:00+00:00")
    _mark(db, pid, a, ("maven", "a", "1.0"), "", "2026-11-10T03:00:00+00:00")
    assert db.moved_ref(pid, a) == "" and db.moved_ref(pid, b) == a
    r = web.client.get(f"/projects/{pid}/components/{b}", follow_redirects=False)
    assert r.status_code in (302, 303) and r.headers["location"].endswith(f"/components/{a}")
    assert web.client.get(f"/projects/{pid}/components/{a}", follow_redirects=False).status_code == 404, \
        "архива у A нет – как раньше, без перенаправления"
    _mark(db, pid, a, ("maven", "a", "1.0"), b, "2026-11-10T04:00:00+00:00")  # A↔B – цикл
    assert db.moved_ref(pid, a) == "" and db.moved_ref(pid, b) == ""


def test_chain_of_moves_keeps_the_earliest_archive_on_the_last_card(web):  # noqa: F811
    """Ревью Codex, круг 2: исследование A снято при переносе A в B, затем B перенесена в C – карточка C показывает
    архив A, отчёт компонента C – тоже."""
    db, pid = made(web, ("73001", "lib", "maven"))
    a, b, c = input_ref("npm", "lib", "1.2.3"), input_ref("maven", "x:lib", "1.2.3"), input_ref(*NEW)
    from app.db import dumps
    with db._tx() as cur:
        cur.execute("INSERT INTO sca_identity_archive(project_id, archived_at, source_table, key_json, row_json, reason)"
                    " VALUES (?, '2026-11-10T01:00:00+00:00', 'sca2_research', ?, ?, 'перенос (изменение)')",
                    (pid, dumps({"input_ref": a, "revision": 1}), dumps({"input_ref": a, "revision": 1, "status": "complete"})))
    _mark(db, pid, a, ("npm", "lib", "1.2.3"), b, "2026-11-10T01:00:00+00:00")
    _mark(db, pid, b, ("maven", "x:lib", "1.2.3"), c, "2026-11-10T02:00:00+00:00")
    transition(db, pid, {"73001": NEW[:2]})  # находка живёт в C
    assert {a, b} <= set(db.moved_from(pid, c)), "вся цепочка, не только ближняя группа"
    page = web.client.get(f"/projects/{pid}/components/{c}").text
    assert 'id="identity-archive"' in page and "npm lib@1.2.3" in page
    assert web.client.get(f"/projects/{pid}/components/{a}", follow_redirects=False).headers["location"].endswith(
        f"/components/{c}"), "цепочка – сразу на живую карточку"


def test_archived_decision_without_task_is_listed_with_its_fields(web):  # noqa: F811
    """Ревью Codex, круг 2: решение без задания, снятое при расщеплении, – строкой списка «архив» по тройке отметки;
    поля решения (целевая версия) видны в архиве."""
    db, pid = made(web, ("73001", "lib", "maven"), ("73002", "lib", "maven"))
    s = input_ref(*OLD)
    with db._tx() as c:
        c.execute("INSERT INTO sca2_decisions(project_id, input_ref, revision, action, rationale, target_version, state,"
                  " decided_at, input_sig, research_sig) VALUES (?, ?, 1, 'update', 'Плановое обновление.', '2.0.0',"
                  " 'current', '2026-11-09T10:00:00+00:00', '', '')", (pid, s))
    transition(db, pid, {"73001": ("maven", "org.a:lib"), "73002": ("maven", "org.b:lib")})
    listing = web.client.get(f"/projects/{pid}/components").text
    assert f"/projects/{pid}/components/{s}" in listing and ">архив</span>" in listing
    page = web.client.get(f"/projects/{pid}/components/{s}").text
    assert "Плановое обновление." in page and "целевая версия: 2.0.0" in page


def test_component_report_of_an_archive_only_group_and_markdown(web):  # noqa: F811
    """Ревью Codex, круг 2: отчёт компонента, у которого осталось только архивное исследование, – не 404; Markdown-отчёт
    проекта называет снятое."""
    db, pid = made(web, ("73001", "lib", "maven"), ("73002", "lib", "maven"))
    s = input_ref(*OLD)
    _research(db, pid, s, "lib")
    transition(db, pid, {"73001": ("maven", "org.a:lib"), "73002": ("maven", "org.b:lib")})
    one = web.client.get(f"/projects/{pid}/components/{s}/report?format=json")
    assert one.status_code == 200 and json.loads(one.text)["identity_archive"][0]["input_ref"] == s
    md = web.client.get(f"/projects/{pid}/components/report?format=md").text
    assert "Снято переходом идентичности пакетов" in md and s in md


def test_moved_old_address_is_not_in_the_component_queue(web):  # noqa: F811
    """Ревью Codex, круг 2: после переноса A в B с исследованием прежняя строка задания A в списке не остаётся –
    «Сохранить и дальше» не возвращается через перенаправление."""
    db, pid = made(web, ("73001", "lib", "maven"))
    s, t = input_ref(*OLD), input_ref(*NEW)
    _research(db, pid, s, "org.example:lib")
    task_row(db, pid, s, "maven", "lib", "1.2.3")
    transition(db, pid, {"73001": NEW[:2]})
    listing = web.client.get(f"/projects/{pid}/components").text
    assert f"/projects/{pid}/components/{t}" in listing
    assert f"/projects/{pid}/components/{s}" not in listing


def test_pending_hint_until_hub_library_is_applied(web):  # noqa: F811
    """П. 4.4: у проекта с привязкой к Hub подсказка «сведения Hub о библиотеках ещё не применены» видна на страницах
    SCA и «Компоненты», пока к находкам не применено правило текущего назначения; после – не видна."""
    from app import package_transition as pt
    from test_hub_status_routes import HUB
    db, pid = made(web, ("73001", "lib", "maven"))
    for page in (f"/projects/{pid}/sca", f"/projects/{pid}/components"):
        text = web.client.get(page).text
        assert 'id="identity-pending"' in text and "к находкам SCA: 1." in text, page
    with db._tx() as c:
        c.execute("UPDATE findings SET pkg_source = 'file', pkg_scope = ? WHERE project_id = ?", (pt.scope_of(HUB, 7), pid))
    for page in (f"/projects/{pid}/sca", f"/projects/{pid}/components"):
        assert 'id="identity-pending"' not in web.client.get(page).text, page
    db.update_project(pid, hub_app_id=8)  # другое назначение – применять снова
    assert 'id="identity-pending"' in web.client.get(f"/projects/{pid}/sca").text


def test_name_replaced_with_group_id_is_marked():
    """Ревью Codex, круг 3: имя по Hub другое и при непустом groupId – пометка «имя по Hub», для Maven и npm."""
    from app import package_identity as pi
    maven = {"build_type": "maven", "component": "old-lib", "version": "1.0",
             "package": {"source": "hub", "ecosystem": "maven", "name": "org.example:new-lib", "note": ""}}
    npm = {"build_type": "npm", "component": "old", "version": "1.0",
           "package": {"source": "hub", "ecosystem": "npm", "name": "@scope/new", "note": ""}}
    assert pi.mark_texts(maven) == ["имя по Hub: в выгрузке – old-lib"]
    assert pi.mark_texts(npm) == ["имя по Hub: в выгрузке – old"]


def test_move_then_split_keeps_the_chain_archive_in_the_list(web):  # noqa: F811
    """Ревью Codex, круг 3: решение A без задания снято при переносе A в B, затем B расщеплена – строка B в списке с
    пометкой «архив», её карточка для чтения показывает решение A."""
    from app.db import dumps
    db, pid = made(web, ("73001", "lib", "maven"))
    a_ref, b_ref = input_ref("npm", "lib", "1.2.3"), input_ref("maven", "x:lib", "1.2.3")
    with db._tx() as c:
        c.execute("INSERT INTO sca_identity_archive(project_id, archived_at, source_table, key_json, row_json, reason)"
                  " VALUES (?, '2026-11-10T01:00:00+00:00', 'sca2_decisions', ?, ?, 'перенос (изменение)')",
                  (pid, dumps({"input_ref": a_ref, "revision": 1}),
                   dumps({"input_ref": a_ref, "revision": 1, "action": "accept", "rationale": "Риск принят до переноса."})))
    _mark(db, pid, a_ref, ("npm", "lib", "1.2.3"), b_ref, "2026-11-10T01:00:00+00:00")
    _mark(db, pid, b_ref, ("maven", "x:lib", "1.2.3"), "", "2026-11-10T02:00:00+00:00")
    assert b_ref in db.archived_refs(pid) and a_ref not in db.archived_refs(pid)
    listing = web.client.get(f"/projects/{pid}/components").text
    assert f"/projects/{pid}/components/{b_ref}" in listing
    page = web.client.get(f"/projects/{pid}/components/{b_ref}").text
    assert 'id="archive-banner"' in page and "Риск принят до переноса." in page


def test_identity_report_links_and_accept_history(web):  # noqa: F811
    """Ревью Codex, круг 3: в отчёте ссылка «архив» – только на открываемую карточку; история принятий с переходом –
    полный итог из сохранённого результата принятия; ссылка на отчёт – и без счётчика переходов, при сведениях Hub."""
    from app import hub_pull as pull
    from test_package_transition import synced
    db, pid, rid = synced(web, {"groupId": "org.example", "name": "lib", "version": "1.2.3"})
    shown = pull.preview(db, pull_run(db, rid))
    pull.apply(db, rid, shown["token"])
    _mark(db, pid, input_ref("maven", "gone", "1.0"), ("maven", "gone", "1.0"), "", "2026-11-10T03:00:00+00:00")
    report = web.client.get(f"/projects/{pid}/identity-report").text
    assert 'id="identity-report-accepts-table"' in report
    assert "<td>1 / 0 / 0 / 0</td>" in report, "перенос группы посчитан по подписи сохранённого итога"
    with db._tx() as c:  # принятие без перехода – сводка с нулями; в историю не входит
        c.execute("UPDATE hub_defect_sync_runs SET result_json = ? WHERE id = ?",
                  (json.dumps({"identity": {"findings": 0, "groups": []}}), rid))
    assert 'id="identity-report-accepts-table"' not in web.client.get(f"/projects/{pid}/identity-report").text
    assert "расщеплена или слита" in report, "без архива – без ссылки"
    with db._tx() as c:
        c.execute("UPDATE projects SET identity_rev = 0 WHERE id = ?", (pid,))
    assert 'id="identity-report-link"' in web.client.get(f"/projects/{pid}/components").text


def test_assignment_change_summary_has_no_internal_owner_list(web):  # noqa: F811
    """Ревью Codex, круг 3: служебный список семейств не уходит в сводку смены назначения."""
    from app import package_transition as pt
    from app.db import dumps
    db, pid = made(web, ("73001", "lib", "maven"))
    with db._tx() as c:  # идентичность по Hub и затронутое семейство дефекта – переход при смене назначения будет
        c.execute("UPDATE findings SET pkg_ecosystem = 'maven', pkg_name = 'org.example:lib', pkg_source = 'hub',"
                  " pkg_note = '', pkg_scope = 'h|7' WHERE project_id = ?", (pid,))
        owner = c.execute("INSERT INTO hub_defects(project_id, kind, number, state, origin, targets_json, number_keys_json,"
                          " sca_set_key, created_at, updated_at) VALUES (?, 'SCA', 9, 'done', 'app', ?, '[]', '', 'x', 'x')"
                          " RETURNING id", (pid, dumps([{"hub_id": "73001", "issue_type": "SCA_S"}]))).fetchone()[0]
        c.execute("UPDATE hub_defects SET draft_owner_id = id WHERE id = ?", (owner,))
    with db._tx() as c:
        summary = pt.change_assignment(c, pid, lambda cur: cur.execute(
            "UPDATE projects SET hub_app_id = 8 WHERE id = ?", (pid,)))
    assert summary.get("findings") == 1 and summary["defects"]["families"] == 1, summary
    assert "owners" not in summary["defects"]


def pull_run(db, rid):
    from test_hub_pull import run
    return run(db, rid)

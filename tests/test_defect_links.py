"""Дефекты на пути оператора (0.9.26.dev19): обзор групп SCA и «Находок» – колонка «Дефекты»
со значками и версиями без дефекта; строки версий SCA – значок и «без дефекта»; отборы «В дефекте» / «Без дефекта»;
карточки SAST и SCA – значок в шапке и «Дефект для этой находки уже есть»; список «Находки» – значок. Данные
выдуманы."""

from __future__ import annotations

import re

from app import defect_links
from app.models import Finding
from app.triage import order_findings
from test_web import create_project, web  # noqa: F401

HUB = "https://hub.example.org"


def seed(web) -> int:
    db = web.app.state.db
    pid = create_project(web.client)
    db.update_project(pid, hub_app_id=7)
    db.set_settings({"hub_url": HUB})
    findings = [
        Finding(hub_id="910202", kind="SCA", component="lodash", version="4.17.21", build_type="npm",
                cve=["CVE-2099-0001"], cvss=9.8),
        Finding(hub_id="910124", kind="SCA", component="lodash", version="4.17.23", build_type="npm",
                cve=["CVE-2099-0001"], cvss=9.8),
        Finding(hub_id="910290", kind="SCA", component="lodash", version="4.17.23", build_type="npm",
                cve=["CVE-2099-0002"], cvss=9.8),
        Finding(hub_id="73003", kind="SCA", component="demo-xml", version="2.0.0", build_type="npm",
                cve=["CVE-2099-0003"], cvss=7.5),
        Finding(hub_id="1001", kind="SAST", rule="Внедрение SQL", cwe=["CWE-89"], codebase="demo", file="a.py", line=2,
                snippet="q = 'SELECT ' + v", severity="high"),
        Finding(hub_id="1002", kind="SAST", rule="Внедрение SQL", cwe=["CWE-89"], codebase="demo", file="b.py", line=5,
                snippet="q = 'SELECT ' + w", severity="high"),
    ]
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings(findings))
    return pid


def defect(web, pid: int, kind: str, hub_ids, number: int, state: str = "done", hub_defect_id: str = "900028") -> dict:
    db = web.app.state.db
    typ = "SCA_S" if kind == "SCA" else "SAST"
    row = db.hub_defect_insert(pid, kind=kind, number=number, summary=f"ID{number} - демо ({kind})", anchor_hub_id=hub_ids[0],
                               targets=[{"hub_id": h, "issue_type": typ} for h in hub_ids], number_keys=[],
                               command_text="Текст", hub_url=HUB, app_id=7)
    if state != "blank":
        db.hub_defect_update(row["id"], state=state, hub_defect_id=hub_defect_id)
    return db.hub_defect(row["id"])


def fid(web, pid: int, hub_id: str) -> int:
    return int(web.app.state.db.get_finding_by_hub_id(pid, hub_id)["id"])


def test_by_hub_id_and_attach(web):
    pid = seed(web)
    done = defect(web, pid, "SCA", ["910124", "910290"], 10)
    blank = defect(web, pid, "SAST", ["1001"], 11, state="blank")
    by = defect_links.by_hub_id(web.app.state.db, pid)
    assert set(by) == {"910124", "910290", "1001"}
    assert by["910124"][0]["text"] == "ID10 · №900028" and by["910124"][0]["done"]
    assert by["1001"][0]["text"] == "ID11 · заготовка запрошена" and not by["1001"][0]["done"]
    assert set(defect_links.by_hub_id(web.app.state.db, pid, kind="SCA")) == {"910124", "910290"}
    rows = [{"hub_ids": ["910124", "910290"]}, {"hub_id": "1001"}, {"hub_id": "73003"}]
    defect_links.attach(rows, by)
    # заготовка – подготовка: значок есть, «в дефекте» – нет (как у карточки, hub_defect_bound)
    assert [r["in_defect"] for r in rows] == [True, False, False]
    assert [d["id"] for d in rows[0]["defects"]] == [done["id"]] and rows[1]["defects"][0]["id"] == blank["id"]
    assert rows[0]["defects"][0]["bound"] and not rows[1]["defects"][0]["bound"]
    web.app.state.db.hub_defect_update(blank["id"], state="cancelled")
    assert "1001" not in defect_links.by_hub_id(web.app.state.db, pid)


def test_sca_groups_versions_filters_and_card(web):
    pid = seed(web)
    row = defect(web, pid, "SCA", ["910124", "910290"], 10)
    url = f"/projects/{pid}/defects/{row['id']}"
    # обзор групп: колонка «Дефекты», у lodash – значок и версия без дефекта; у demo-xml – прочерк; «С решением» – версии
    groups = web.client.get(f"/projects/{pid}/sca?group_by=family").text
    assert "<th scope=\"col\">Дефекты</th>" in groups
    lodash = re.search(r"<tr>\s*<td><a class=\"rule-link break\"[^>]*><strong class=\"group-name\">lodash</strong></a>.*?</tr>", groups, re.S).group(0)
    assert f'href="{url}"' in lodash and "дефект ID10 · №900028" in lodash and "без дефекта: <span class=\"mono\">4.17.21</span>" in lodash
    xml = re.search(r"<tr>\s*<td><a class=\"rule-link break\"[^>]*><strong class=\"group-name\">demo-xml</strong></a>.*?</tr>", groups, re.S).group(0)
    assert "component-defect" not in xml and '<td class="group-defects"><span class="muted">–</span></td>' in xml
    # строки версий в открытой группе: значок у 4.17.23, «без дефекта» у 4.17.21
    family = re.search(r'href="([^"]*family=[^"]*)"', lodash).group(1).replace("&amp;", "&")
    page = web.client.get(family).text
    v23 = re.search(r'<tr data-component="lodash" data-version="4.17.23".*?</tr>', page, re.S).group(0)
    v21 = re.search(r'<tr data-component="lodash" data-version="4.17.21".*?</tr>', page, re.S).group(0)
    assert "дефект ID10 · №900028" in v23 and f'href="{url}"' in v23
    assert "без дефекта" in v21 and "component-defect" not in v21
    # в плоском списке «без дефекта» не пишется
    flat = web.client.get(f"/projects/{pid}/sca").text
    assert "без дефекта</span>" not in flat and "дефект ID10 · №900028" in flat
    # отборы
    assert 'В дефекте <span class="chip-count">1</span>' in flat and 'Без дефекта <span class="chip-count">2</span>' in flat
    assert flat.count("<tr data-component=") == 3
    assert web.client.get(f"/projects/{pid}/sca?show=in_defect").text.count("<tr data-component=") == 1
    assert web.client.get(f"/projects/{pid}/sca?show=no_defect").text.count("<tr data-component=") == 2
    # карточка находки SCA: значок в шапке и панель «Дефект для Hub»
    card = web.client.get(f"/projects/{pid}/sca/findings/{fid(web, pid, '910124')}").text
    assert 'id="finding-defect-badge"' in card and "дефект ID10 · №900028" in card and f'href="{url}"' in card
    assert 'id="defect-exists"' in card and "Дефект для этой находки уже есть" in card
    assert "Создайте дефект в Hub вручную" not in card
    other = web.client.get(f"/projects/{pid}/sca/findings/{fid(web, pid, '910202')}").text
    assert 'id="finding-defect-badge"' not in other and 'id="defect-exists"' not in other
    # Hub настроен: дефект создаётся из приложения, ручной путь не предлагается (замечание оператора, dev9)
    assert "Создайте дефект в Hub вручную" not in other


def status_mark(db, pid: int, hub_id: str, app_id: int = 7) -> None:
    """Отметка «статус внесён» от выполненной операции статуса этого Hub и приложения (как после «Отправить в Hub»);
    app_id другого приложения – отметка по правилу _ENTERED_HUB_SQL не засчитывается."""
    op = db.hub_enqueue(purpose="status", project_id=pid, hub_url=HUB, app_id=app_id,
                        request={"method": "POST", "path": "/issue/status/update", "body": {
                            "issueId": int(hub_id), "issueType": "SCA_S", "status": "False Positive", "reason": "x"}},
                        targets=[{"hub_id": hub_id, "issue_id": int(hub_id), "issue_type": "SCA_S", "revision": 1,
                                  "entered_hash": "h"}], key_extra=f"test-{app_id}")
    with db._tx() as c:
        c.execute("UPDATE hub_ops SET state = 'done' WHERE id = ?", (op["id"],))
    db.mark_entered(pid, hub_id, True, entered_hash="h", entered_origin="status", entered_op_id=op["id"])


def group_row(web, pid: int, name: str) -> str:
    groups = web.client.get(f"/projects/{pid}/sca?group_by=family").text
    return re.search(rf"<tr>\s*<td><a class=\"rule-link break\"[^>]*><strong class=\"group-name\">{name}</strong></a>.*?</tr>", groups, re.S).group(0)


def test_version_closed_by_hub_status_is_not_shown_as_missing_defect(web):
    """Версия, закрытая в Hub статусом «Ложное срабатывание», не показывается в обзоре как «без дефекта»,
    будто её забыли. Закрытая версия подписана «закрыто без дефекта», группа – «все версии закрыты»."""
    pid = seed(web)
    db = web.app.state.db
    defect(web, pid, "SCA", ["910124", "910290"], 9)
    db.save_review(pid, "910202", decision="agree", final_verdict="false_positive", final_comment="Не применимо.", reviewed=True)
    # отметка статуса от операции другого приложения Hub не засчитывается: версия по-прежнему «без дефекта»
    status_mark(db, pid, "910202", app_id=8)
    lodash = group_row(web, pid, "lodash")
    assert 'без дефекта: <span class="mono">4.17.21</span>' in lodash and "закрыто без дефекта" not in lodash
    assert "все версии закрыты" not in lodash
    # отметка от операции статуса этого Hub и приложения – версия закрыта
    status_mark(db, pid, "910202")
    lodash = group_row(web, pid, "lodash")
    assert "дефект ID9 · №900028" in lodash and 'закрыто без дефекта: <span class="mono">4.17.21</span>' in lodash
    assert "без дефекта: <span" not in lodash.replace("закрыто без дефекта: <span", "") and "все версии закрыты" in lodash
    family = re.search(r'href="([^"]*family=[^"]*)"', lodash).group(1).replace("&amp;", "&")
    v21 = re.search(r'<tr data-component="lodash" data-version="4.17.21".*?</tr>', web.client.get(family).text, re.S).group(0)
    assert ">закрыто без дефекта</span>" in v21 and ">без дефекта</span>" not in v21
    # ручная отметка «статус внесён» – тоже закрытие (человек внёс статус в Hub сам)
    db.mark_entered(pid, "910202", False)
    db.mark_entered(pid, "910202", True, entered_hash="h")
    assert "все версии закрыты" in group_row(web, pid, "lodash")


def test_group_is_closed_only_when_every_finding_is_closed(web):
    """Ревью dev27: находка без решения рядом с дефектом, частичное закрытие статусом и незавершённый дефект группу не
    закрывают; «риск принят» закрывает так же, как «ложное срабатывание»."""
    pid = seed(web)
    db = web.app.state.db
    # 4.17.23: одна находка закрыта статусом, вторая без решения – версия не закрыта, подсказок нет
    db.save_review(pid, "910124", decision="agree", final_verdict="false_positive", final_comment="x", reviewed=True)
    db.mark_entered(pid, "910124", True, entered_hash="h")
    lodash = group_row(web, pid, "lodash")
    assert "закрыто без дефекта" not in lodash and "все версии закрыты" not in lodash and "без дефекта:" not in lodash
    # вторая находка – «риск принят» со статусом в Hub: версия закрыта, у 4.17.21 подсказка «без дефекта»
    db.save_review(pid, "910290", decision="risk_accepted", final_verdict="true_positive", final_comment="x", reviewed=True)
    db.mark_entered(pid, "910290", True, entered_hash="h")
    lodash = group_row(web, pid, "lodash")
    assert 'закрыто без дефекта: <span class="mono">4.17.23</span>' in lodash
    assert 'без дефекта: <span class="mono">4.17.21</span>' in lodash and "все версии закрыты" not in lodash
    family = re.search(r'href="([^"]*family=[^"]*)"', lodash).group(1).replace("&amp;", "&")
    v21 = re.search(r'<tr data-component="lodash" data-version="4.17.21".*?</tr>', web.client.get(family).text, re.S).group(0)
    assert ">без дефекта</span>" in v21
    # дефект с неизвестным исходом у 4.17.21 – группа не закрыта; подтверждённый – закрыта
    row = defect(web, pid, "SCA", ["910202"], 13, state="unknown", hub_defect_id="90099")
    lodash = group_row(web, pid, "lodash")
    assert "все версии закрыты" not in lodash and 'без дефекта: <span class="mono">4.17.21' not in lodash
    db.hub_defect_update(row["id"], state="done")
    assert "все версии закрыты" in group_row(web, pid, "lodash")
    # находка в подтверждённом дефекте рядом с находкой без решения той же версии – версия не закрыта
    pid2 = seed(web)
    db.save_review(pid2, "910202", decision="agree", final_verdict="false_positive", final_comment="x", reviewed=True)
    db.mark_entered(pid2, "910202", True, entered_hash="h")  # 4.17.21 закрыта целиком
    owner = defect(web, pid2, "SCA", ["910124"], 9)
    lodash = group_row(web, pid2, "lodash")
    assert "все версии закрыты" not in lodash and 'закрыто без дефекта: <span class="mono">4.17.21</span>' in lodash
    # строка привязки второй находки к дефекту владельца (linking) подтверждённость владельца не наследует
    link = defect(web, pid2, "SCA", ["910290"], 9, state="linking")
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_owner_id = ? WHERE id = ?", (owner["id"], link["id"]))
    assert "все версии закрыты" not in group_row(web, pid2, "lodash")
    db.hub_defect_update(link["id"], state="done")
    assert "все версии закрыты" in group_row(web, pid2, "lodash")


def test_sast_list_groups_and_card(web):
    pid = seed(web)
    row = defect(web, pid, "SAST", ["1001"], 11, state="creating", hub_defect_id="")
    url = f"/projects/{pid}/defects/{row['id']}"
    listing = web.client.get(f"/projects/{pid}/findings?kind=SAST").text
    assert "дефект ID11 · создаётся" in listing and f'href="{url}"' in listing and "badge-warn component-defect" in listing
    assert listing.count("component-defect") == 1
    groups = web.client.get(f"/projects/{pid}/findings?kind=SAST&group_by=family").text
    assert "дефект ID11 · создаётся" in groups and "без дефекта:" not in groups
    card = web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '1001')}").text
    assert 'id="finding-defect-badge"' in card and "дефект ID11 · создаётся" in card
    assert 'id="finding-defect-badge"' not in web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '1002')}").text


def test_summary_states_and_numbers(web):
    """«Создан, привязка неполная» – с подписью и предупреждением; дефект без локального номера – только номер Hub
    (ревью dev17)."""
    from app.routes.components import defects_by_component
    from app.sca_contract import input_ref
    db = web.app.state.db
    pid = seed(web)
    mismatch = defect(web, pid, "SCA", ["910124"], 10, state="mismatch")
    item = defect_links.by_hub_id(db, pid)["910124"][0]
    assert not item["done"] and item["text"] == "ID10 · №900028 · создан, привязка неполная"
    db.hub_defect_update(mismatch["id"], state="cancelled")
    imported = defect(web, pid, "SCA", ["910290"], None)
    item = defect_links.by_hub_id(db, pid)["910290"][0]
    assert item["text"] == "№900028" and item["done"]
    page = web.client.get(f"/projects/{pid}/sca?show=in_defect").text
    assert "дефект №900028" in page and "IDNone" not in page and f'href="/projects/{pid}/defects/{imported["id"]}"' in page
    # невидимый знак в имени компонента из выгрузки: ключ пакета тот же, что у строк задания
    db.save_import(pid, "demo2.csv", "csv", [], {}, [], order_findings([
        Finding(hub_id="910124", kind="SCA", component="lodash", version="4.17.23", build_type="npm", cve=["CVE-2099-0001"], cvss=9.8),
        Finding(hub_id="910290", kind="SCA", component="lo" + chr(0x200B) + "dash", version="4.17.23", build_type="npm", cve=["CVE-2099-0002"], cvss=9.8),
    ]))
    found = defects_by_component(db, pid)
    assert input_ref("npm", "lodash", "4.17.23") in found


def test_hidden_owner_keeps_live_link_row(web):
    """Владелец семьи отменён, строка привязки действует: находка в дефекте, отборы и значок это видят (ревью dev19)."""
    db = web.app.state.db
    pid = seed(web)
    owner = defect(web, pid, "SCA", ["910124"], 10)
    link = db.hub_defect_insert(pid, kind="SCA", number=10, summary="ID10 - демо (SCA)", anchor_hub_id="910290",
                                targets=[{"hub_id": "910290", "issue_type": "SCA_S"}], number_keys=[], command_text="Текст",
                                hub_url=HUB, app_id=7)
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_owner_id = ?, state = 'done' WHERE id = ?", (owner["id"], link["id"]))
        c.execute("UPDATE hub_defects SET state = 'cancelled' WHERE id = ?", (owner["id"],))
    assert db.hub_defect_bound(pid, "910290") is not None
    by = defect_links.by_hub_id(db, pid)
    assert set(by) == {"910290"} and by["910290"][0]["id"] == owner["id"] and by["910290"][0]["text"] == "ID10 · №900028"
    assert web.client.get(f"/projects/{pid}/sca?show=in_defect").text.count("<tr data-component=") == 1
    assert web.client.get(f"/projects/{pid}/sca?show=no_defect").text.count("<tr data-component=") == 2


def test_without_defect_mark_on_every_page_of_the_group(web):
    """«Без дефекта» у версий открытой группы – и на второй странице, когда дефект на первой (ревью dev19)."""
    db = web.app.state.db
    pid = create_project(web.client)
    db.update_project(pid, hub_app_id=7)
    db.set_settings({"hub_url": HUB})
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([
        Finding(hub_id=str(40000 + n), kind="SCA", component="many", version=f"1.0.{n}", build_type="npm",
                cve=["CVE-2099-0001"], cvss=7.5) for n in range(30)]))
    defect(web, pid, "SCA", ["40000"], 3)
    groups = web.client.get(f"/projects/{pid}/sca?group_by=family&page_size=25").text
    family = re.search(r'href="([^"]*family=[^"]*)"', groups).group(1).replace("&amp;", "&")
    first = web.client.get(family).text
    assert family.endswith("#components"), "открытая группа – сразу у таблицы"
    second = web.client.get(family.split("#")[0] + "&page=2").text
    assert "дефект ID3 · №900028" in first and first.count("без дефекта</span>") >= 1
    assert "дефект ID3" not in second and second.count("без дефекта</span>") == second.count("<tr data-component=") > 0


def test_preparation_is_shown_but_not_counted_as_in_defect(web):
    """Заготовка и предпросмотр – подготовка: значок с состоянием есть, но отборы, группы и карточка версию «в дефекте»
    не считают (согласовано с hub_defect_bound; ревью dev19, круг 2); «создаётся» – уже привязка."""
    db = web.app.state.db
    pid = seed(web)
    blank = defect(web, pid, "SCA", ["910124"], 10, state="blank")
    assert db.hub_defect_bound(pid, "910124") is None
    flat = web.client.get(f"/projects/{pid}/sca").text
    assert "подготовка дефекта ID10 · заготовка запрошена" in flat
    assert 'В дефекте <span class="chip-count">0</span>' in flat and 'Без дефекта <span class="chip-count">3</span>' in flat
    assert web.client.get(f"/projects/{pid}/sca?show=no_defect").text.count("<tr data-component=") == 3
    groups = web.client.get(f"/projects/{pid}/sca?group_by=family").text
    lodash = re.search(r"<tr>\s*<td><a class=\"rule-link break\"[^>]*><strong class=\"group-name\">lodash</strong></a>.*?</tr>", groups, re.S).group(0)
    assert "подготовка дефекта ID10 · заготовка запрошена" in lodash and "без дефекта:" not in lodash
    card = web.client.get(f"/projects/{pid}/sca/findings/{fid(web, pid, '910124')}").text
    assert 'id="finding-defect-badge"' not in card and 'id="defect-exists"' not in card
    # в открытой группе у другой версии нет подсказки «без дефекта»: привязанных версий в группе нет (ревью dev20)
    family = re.search(r'href="([^"]*family=[^"]*)"', lodash).group(1).replace("&amp;", "&")
    opened = web.client.get(family).text
    assert "без дефекта</span>" not in opened and "подготовка дефекта ID10" in opened
    db.hub_defect_update(blank["id"], state="creating")
    assert db.hub_defect_bound(pid, "910124") is not None
    flat = web.client.get(f"/projects/{pid}/sca").text
    assert 'В дефекте <span class="chip-count">1</span>' in flat and "дефект ID10 · создаётся" in flat
    assert 'id="finding-defect-badge"' in web.client.get(f"/projects/{pid}/sca/findings/{fid(web, pid, '910124')}").text


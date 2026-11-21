"""Исследование провайдером только по компонентам без дефекта (0.10.0.dev24): выбор строк
«без дефекта» в блоке «Исследование провайдером» – в предпросмотр и в запуск идут строки задания, у компонентов
которых ни одна находка не привязана к дефекту приложения; состав предпросмотра и запуска один. Поддельный сервер
на этом компьютере. Данные выдуманы."""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fake_chat_api import FakeChatApi  # noqa: E402
from test_component_defects import defect  # noqa: E402
from test_sca_research_net import make_profile  # noqa: E402
from test_sca_research_net_ui import hidden, preview, start, wait_run  # noqa: E402
from test_sca_research_routes import build_task, project_with_sca  # noqa: E402
from test_web import web  # noqa: E402, F401

from app.routes.components import SELECTION_LABELS, selection_rows, views  # noqa: E402


names: dict[str, tuple[str, str]] = {}  # input_ref → (компонент, версия) задания


def prepared(web):  # noqa: F811
    """Проект с заданием; находки первого компонента задания привязаны к созданному дефекту."""
    db = web.app.state.db
    pid = project_with_sca(web)
    db.update_project(pid, hub_app_id=7)
    manifest = build_task(web, pid)
    refs = [row["input_ref"] for row in manifest["rows"]]
    assert len(refs) >= 2, "для проверки нужны хотя бы два компонента"
    by_ref = {}
    for comp in db.sca_components(pid):
        from app import sca
        from app.sca_contract import input_ref
        by_ref[input_ref(*sca.package_key(comp))] = [str(h) for h in comp.get("hub_ids") or []]
    in_defect = refs[0]
    defect(web, pid, by_ref[in_defect], 12)
    names.clear()
    names.update({row["input_ref"]: (row["component"], row["version"]) for row in manifest["rows"]})
    assert len(set(names.values())) == len(names)
    return pid, refs, in_defect


def asked(fake, names: dict[str, str]) -> set[str]:
    """input_ref строк, о которых провайдера действительно спросили: по первому сообщению пользователя каждого
    обращения (в нём строка задания с именем и версией компонента)."""
    import json
    out = set()
    for body in fake.chats():
        first = next(m["content"] for m in body["messages"] if m["role"] == "user")
        row = json.loads(first)["row"]
        hits = [ref for ref, key in names.items() if key == (row["component"], row["version"])]
        assert len(hits) == 1, row
        out.add(hits[0])
    return out


def preview_refs(page: str) -> int:
    return int(re.search(r'id="rows-title">[^<]*\((\d+)\)', page).group(1))


def test_selection_rows_without_defect_and_other_selections(web):  # noqa: F811
    db, settings = web.app.state.db, web.app.state.settings
    pid, refs, in_defect = prepared(web)
    task = db.current_task(pid)
    assert "no_defect" in SELECTION_LABELS
    got = [r["input_ref"] for r in selection_rows(db, settings, pid, task, "no_defect")]
    assert got == [r for r in refs if r != in_defect], "компонент в дефекте в отбор не входит, порядок задания сохранён"
    assert [r["input_ref"] for r in selection_rows(db, settings, pid, task, "all")] == refs
    assert [r["input_ref"] for r in selection_rows(db, settings, pid, task, "unresearched")] == refs
    assert selection_rows(db, settings, pid, task, "review_due") == []
    # признак тот же, что у отбора «Дефект» вкладки
    rows, _ = views(db, pid, settings.sca_internal_prefixes)
    assert {r["input_ref"] for r in rows if r["in_defect"]} == {in_defect}


def test_page_offers_the_selection_with_count_and_preview_lists_only_those_rows(web):  # noqa: F811
    db = web.app.state.db
    pid, refs, in_defect = prepared(web)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        html = web.client.get(f"/projects/{pid}/components").text
        assert f'<option value="no_defect">без дефекта ({len(refs) - 1})</option>' in html
        r = preview(web, pid, "no_defect")
        assert r.status_code == 200
        page = r.text
        assert "Строки задания – без дефекта" in page and preview_refs(page) == len(refs) - 1
        assert hidden(page, "selection") == "no_defect"
        assert fake.chats() == [], "предпросмотр ничего не отправляет"


def test_start_sends_only_components_without_defect(web):  # noqa: F811
    db = web.app.state.db
    pid, refs, in_defect = prepared(web)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        page = preview(web, pid, "no_defect").text
        r = start(web, pid, page)
        assert r.status_code == 303 and "/components/research/" in r.headers["location"], r.headers["location"]
        run = db.latest_research_run(pid)
        assert wait_run(web, run["id"])["state"] == "done"
        queued = [row["input_ref"] for row in db.research_run_rows(run["id"])]
        assert sorted(queued) == sorted(r for r in refs if r != in_defect)
        assert asked(fake, names) == {r for r in refs if r != in_defect}, "провайдеру ушли только строки без дефекта"
        run_page = web.client.get(f"/projects/{pid}/components/research/{run['id']}").text
        assert "без дефекта" in run_page


def test_defect_made_after_the_preview_changes_the_fingerprint(web):  # noqa: F811
    """Компонент ушёл в дефект между предпросмотром и согласием: состав другой – запуск отклоняется."""
    db = web.app.state.db
    pid = project_with_sca(web)
    db.update_project(pid, hub_app_id=7)
    manifest = build_task(web, pid)
    from app import sca
    from app.sca_contract import input_ref
    by_ref = {input_ref(*sca.package_key(c)): [str(h) for h in c.get("hub_ids") or []] for c in db.sca_components(pid)}
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        page = preview(web, pid, "no_defect").text
        defect(web, pid, by_ref[manifest["rows"][0]["input_ref"]], 12)
        r = start(web, pid, page)
        assert "err=research_changed" in r.headers["location"] and db.latest_research_run(pid) is None
        assert fake.chats() == []


def test_all_components_in_defects_gives_the_empty_notice(web):  # noqa: F811
    db = web.app.state.db
    pid = project_with_sca(web)
    db.update_project(pid, hub_app_id=7)
    build_task(web, pid)
    hub_ids = [str(h) for c in db.sca_components(pid) for h in c.get("hub_ids") or []]
    defect(web, pid, hub_ids, 12)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        r = preview(web, pid, "no_defect")
        assert r.status_code == 303 and "err=research_empty" in r.headers["location"]


# ---------------------------------------------------------------- отмеченные в таблице

def post_preview(web, pid: int, refs):  # noqa: F811
    from test_web import ORIGIN
    return web.client.post(f"/projects/{pid}/components/research/preview", headers=ORIGIN, follow_redirects=False,
                           data={"selection": "picked", "input_ref": list(refs)})


def post_start(web, pid: int, page: str, refs):  # noqa: F811
    from test_web import ORIGIN
    return web.client.post(f"/projects/{pid}/components/research/start", headers=ORIGIN, follow_redirects=False,
                           data={"selection": hidden(page, "selection"), "fingerprint": hidden(page, "fingerprint"),
                                 "nonce": hidden(page, "nonce"), "token": hidden(page, "token"), "confirm": "1",
                                 "input_ref": list(refs)})


def test_table_has_checkboxes_and_the_picked_button_only_when_research_is_possible(web):  # noqa: F811
    db = web.app.state.db
    pid, refs, _ = prepared(web)
    html = web.client.get(f"/projects/{pid}/components").text
    assert 'id="research-picked"' not in html and 'name="input_ref"' not in html, "без профиля исследования отметок нет"
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        html = web.client.get(f"/projects/{pid}/components").text
        assert 'id="research-picked"' in html and 'name="selection" value="picked"' in html
        assert f'formaction="/projects/{pid}/components/research/preview"' in html
        for ref in refs:
            assert f'name="input_ref" value="{ref}"' in html, ref


def test_picked_rows_go_to_preview_and_start_and_nothing_else(web):  # noqa: F811
    db = web.app.state.db
    pid, refs, in_defect = prepared(web)
    chosen = [refs[-1], in_defect]  # отметить можно и компонент в дефекте: выбор оператора
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        r = post_preview(web, pid, chosen + ["sca:v3|чужая строка"])
        assert r.status_code == 200
        page = r.text
        assert "Строки задания – отмеченные в таблице" in page and preview_refs(page) == len(set(chosen))
        carried = re.findall(r'name="input_ref" value="([^"]*)"', page)
        assert sorted(carried) == sorted(set(chosen)), "в согласие переносятся только найденные строки задания"
        assert fake.chats() == []
        # согласие с другим набором отметок – состав изменился
        r = post_start(web, pid, page, [refs[-1]])
        assert "err=research_changed" in r.headers["location"] and db.latest_research_run(pid) is None
        r = post_start(web, pid, page, carried)
        assert r.status_code == 303 and "/components/research/" in r.headers["location"], r.headers["location"]
        run = db.latest_research_run(pid)
        assert wait_run(web, run["id"])["state"] == "done"
        assert sorted(row["input_ref"] for row in db.research_run_rows(run["id"])) == sorted(set(chosen))
        assert asked(fake, names) == set(chosen), "провайдеру ушли только отмеченные строки"
        assert "отмеченные в таблице" in web.client.get(f"/projects/{pid}/components/research/{run['id']}").text


def test_picked_without_marks_or_with_unknown_rows_is_empty(web):  # noqa: F811
    db = web.app.state.db
    pid, refs, _ = prepared(web)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        for marks in ([], ["sca:v3|нет такой строки"]):
            r = post_preview(web, pid, marks)
            assert r.status_code == 303 and "err=research_empty" in r.headers["location"], marks
        assert fake.chats() == []


def test_marks_do_not_change_other_selections(web):  # noqa: F811
    db, settings = web.app.state.db, web.app.state.settings
    pid, refs, in_defect = prepared(web)
    task = db.current_task(pid)
    for name in ("all", "unresearched", "no_defect", "review_due"):
        assert selection_rows(db, settings, pid, task, name, [refs[0]]) == selection_rows(db, settings, pid, task, name)
    assert [r["input_ref"] for r in selection_rows(db, settings, pid, task, "picked", [refs[1], refs[0]])] == refs[:2]


# ---------------------------------------------------------------- ревью, круг 1

def test_defect_bound_between_row_selection_and_consent_write_is_caught(web, monkeypatch):  # noqa: F811
    """Барьер между отбором строк в запуске и записью согласия: компонент вошёл в дефект после того, как маршрут
    прочитал строки, – пересчёт внутри транзакции согласия видит другой состав, получение не создаётся."""
    from app.routes import components
    db = web.app.state.db
    pid, refs, in_defect = prepared(web)
    target = next(r for r in refs if r != in_defect)
    hub_ids = [str(h) for c in db.sca_components(pid) for h in c.get("hub_ids") or []
               if names[target] == (c.get("component") or c.get("name"), c.get("version"))]
    original = components.selection_rows
    calls = []

    def racing(*args, **kwargs):
        rows = original(*args, **kwargs)
        calls.append(len(rows))
        if len(calls) == 2:  # первый вызов – предпросмотр, второй – чтение строк в запуске: дефект появляется после него
            defect(web, pid, hub_ids, 13, hub_defect_id="90093")
        return rows

    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        assert hub_ids, "у выбранного компонента есть находки"
        monkeypatch.setattr(components, "selection_rows", racing)
        page = preview(web, pid, "no_defect").text
        r = start(web, pid, page)
        assert len(calls) == 3 and calls[2] == calls[1] - 1, calls
        assert "err=research_changed" in r.headers["location"], r.headers["location"]
        assert db.latest_research_run(pid) is None and fake.chats() == []


def test_count_in_the_selection_list_equals_the_preview_for_a_stale_task(web):  # noqa: F811
    """Строка осталась в сохранённом задании, а из текущей выгрузки её компонент пропал (новая выгрузка, задание не
    пересобрано): число в списке выбора на странице равно числу строк предпросмотра «без дефекта»."""
    from app import sca
    from app.models import Finding
    from app.sca_contract import input_ref
    from app.triage import order_findings
    db = web.app.state.db
    pid, refs, in_defect = prepared(web)
    gone = next(r for r in refs if r != in_defect)
    kept = [Finding.from_dict(db.get_finding_by_hub_id(pid, str(h))["data"]) for c in db.sca_components(pid)
            if input_ref(*sca.package_key(c)) != gone for h in c.get("hub_ids") or []]
    assert kept, "в новой выгрузке остались находки других компонентов"
    db.save_import(pid, "next.csv", "csv", [], {}, [], order_findings(kept))
    assert gone in [r["input_ref"] for r in db.task_rows(db.current_task(pid)["id"])], "задание не пересобрано"
    with FakeChatApi(models=["flash-model"]) as fake:
        db.update_project(pid, research_provider_id=make_profile(web, fake)["id"])
        html = web.client.get(f"/projects/{pid}/components").text
        shown = int(re.search(r'<option value="no_defect">без дефекта \((\d+)\)</option>', html).group(1))
        r = preview(web, pid, "no_defect")
        assert r.status_code == 200, r.headers.get("location")
        assert shown == preview_refs(r.text) == len(refs) - 1, (shown, preview_refs(r.text))
        assert fake.chats() == []


# ---------------------------------------------------------------- из карточки компонента (0.10.0.dev26)

def card(web, pid: int, ref: str) -> str:  # noqa: F811
    r = web.client.get(f"/projects/{pid}/components/{ref}")
    assert r.status_code == 200, r.status_code
    return r.text


def test_component_card_starts_research_of_this_one_row(web):  # noqa: F811
    """Исследование провайдером запускается из карточки компонента – только по её строке,
    с тем же предпросмотром и согласием; провайдеру уходит одна строка."""
    db = web.app.state.db
    pid, refs, in_defect = prepared(web)
    ref = refs[-1]
    page = card(web, pid, ref)
    assert 'id="research-one"' not in page and 'id="research-one-why"' in page and "Профиль исследования" in page
    with FakeChatApi(models=["flash-model"]) as fake:
        db.update_project(pid, research_provider_id=make_profile(web, fake)["id"])
        page = card(web, pid, ref)
        assert 'id="research-one"' in page and 'id="research-one-why"' not in page
        form = page.split('id="research-one-form"', 1)[1].split("</form>", 1)[0]
        assert 'name="selection" value="picked"' in form and f'name="input_ref" value="{ref}"' in form
        assert "Исследовать провайдером" in form, "строка ещё не исследована"
        r = post_preview(web, pid, [ref])
        assert r.status_code == 200 and preview_refs(r.text) == 1
        started = post_start(web, pid, r.text, [ref])
        assert started.status_code == 303 and "/components/research/" in started.headers["location"]
        run = db.latest_research_run(pid)
        assert wait_run(web, run["id"])["state"] == "done"
        assert asked(fake, names) == {ref}, "провайдеру ушла только строка карточки"
        # компонент в дефекте исследуется из своей карточки так же: это выбор оператора
        assert 'id="research-one"' in card(web, pid, in_defect)


def test_component_card_says_why_research_is_not_available(web):  # noqa: F811
    """Строки нет в текущем задании (новая выгрузка, задание не обновлено) – кнопки нет, причина и что сделать названы."""
    from app.models import Finding
    from app.sca_contract import input_ref
    from app.triage import order_findings
    db = web.app.state.db
    pid, refs, _ = prepared(web)
    kept = [Finding.from_dict(db.get_finding_by_hub_id(pid, str(h))["data"]) for c in db.sca_components(pid)
            for h in c.get("hub_ids") or []]
    extra = Finding(hub_id="79901", kind="SCA", component="demo-fresh", version="3.1.0", build_type="pypi",
                    cve=["CVE-2099-0909"], cvss=6.1)
    db.save_import(pid, "next.csv", "csv", [], {}, [], order_findings(kept + [extra]))
    with FakeChatApi(models=["flash-model"]) as fake:
        db.update_project(pid, research_provider_id=make_profile(web, fake)["id"])
        page = card(web, pid, input_ref("pypi", "demo-fresh", "3.1.0"))
        assert 'id="research-one"' not in page
        why = page.split('id="research-one-why">', 1)[1].split("</p>", 1)[0]
        assert "обновите задание" in why
        assert fake.chats() == []


def test_component_card_asks_to_update_the_task_when_the_composition_changed(web):  # noqa: F811
    """Ревью 0.10.0.dev26: строка осталась в задании и в выгрузке, но состав проекта изменился (ушёл соседний
    компонент) – запуск согласие отклонит, поэтому кнопки нет, блок просит обновить задание."""
    from app import sca
    from app.models import Finding
    from app.sca_contract import input_ref
    from app.triage import order_findings
    db = web.app.state.db
    pid, refs, in_defect = prepared(web)
    stays, gone = [r for r in refs if r != in_defect][:2] if len(refs) > 2 else (refs[-1], in_defect)
    kept = [Finding.from_dict(db.get_finding_by_hub_id(pid, str(h))["data"]) for c in db.sca_components(pid)
            if input_ref(*sca.package_key(c)) != gone for h in c.get("hub_ids") or []]
    db.save_import(pid, "next.csv", "csv", [], {}, [], order_findings(kept))
    with FakeChatApi(models=["flash-model"]) as fake:
        db.update_project(pid, research_provider_id=make_profile(web, fake)["id"])
        page = card(web, pid, stays)
        assert 'id="research-one"' not in page
        why = page.split('id="research-one-why">', 1)[1].split("</p>", 1)[0]
        assert "Состав проекта изменился" in why and "обновите задание" in why
        assert fake.chats() == []

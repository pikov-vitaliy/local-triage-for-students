"""Состояние относительно Hub на страницах (0.10.0.dev15, бэклог 88: видеть везде, что
отправлено, что не отправлено, что синхронизировано и принял ли Hub запись).

Причина провала dev14: отметка считала состояние своей логикой и расходилась с синхронизацией. Главная проверка здесь
– паритет: страница до пересчёта показывает ровно то, что сохранит пересчёт синхронизации того же прогона, по каждому
объекту (группы и сведения отправки), в том числе после локальных правок, сделанных уже после чтения."""
import json

from app import hub_state, hub_sync_compare as compare
from app.db import loads
from app.triage import order_findings
from test_hub_status_routes import HUB, decide, project, sast, send
from test_sync_golden_path import LiveHub, drain, synced, synchronize
from test_web import web  # noqa: F401


class RejectingHub(LiveHub):
    """Hub отказывает в смене статуса находки 6 (ответ 400 с причиной)."""

    def answer(self, request):
        if request["method"] == "POST" and request["path"] == "/issue/status/update":
            body = request["body"]
            ident = int((body.get("issues") or [body])[0]["issueId"])
            if ident == 6:
                return 400, json.dumps({"errorMessage": "Отказ Hub для проверки"}, ensure_ascii=False)
        return super().answer(request)


def stored(db, rid):
    return {(r["entity_kind"], r["entity_key"]): loads(r["diff_json"], {})
            for r in db._all("SELECT entity_kind,entity_key,diff_json FROM hub_sync_items WHERE run_id=?", (rid,))}


def states(db, pid, keys=None):
    return hub_state.project_states(db, db.get_project(pid), HUB, keys)


def assert_parity(db, pid, rid):
    """Страница до пересчёта = сохранённое сравнение после пересчёта, по каждому объекту прогона."""
    page = states(db, pid)
    compare.recompare(db, rid)
    saved = stored(db, rid)
    assert saved and set(saved) == set(page["items"]), (sorted(saved), sorted(page["items"]))
    for key, diff in saved.items():
        st = page["items"][key]
        assert st["groups"] == diff["groups"], (key, st["groups"], diff["groups"])
        assert st["delivery"] == diff["delivery"], (key, st["delivery"], diff["delivery"])
    after = states(db, pid)  # после пересчёта страница берёт сохранённое сравнение – и видит то же
    assert {k: (v["groups"], v["delivery"], v["badges"]) for k, v in after["items"].items()} == \
        {k: (v["groups"], v["delivery"], v["badges"]) for k, v in page["items"].items()}
    return page


def mixed_project(web):
    """Находки всех видов: совпадает, не отправлено, доставлено, Fixed с решением, справочное отличие, отказ Hub,
    отправка ждёт исполнителя (поставлена после чтения)."""
    db = web.app.state.db
    hub = RejectingHub(7)
    pid = project(web, [sast(str(i), line=i + 1) for i in range(1, 8)])
    synchronize(db, pid, hub)
    for ident in ("2", "3", "4", "6", "7"):
        decide(web, pid, ident)
    for ident in ("3", "6"):
        assert send(web, pid, ident).status_code == 200
    drain(db, hub)
    hub.issues[4]["status"] = "Fixed"
    hub.issues[4]["issueBranchBriefData"][0]["status"] = "Fixed"
    hub.issues[5]["category"] = {"category": "Новое правило", "cwes": [{"id": "CWE-20"}]}
    row = synced(db, pid, hub)
    assert send(web, pid, "7").status_code == 200  # после чтения: операция в очереди, Hub её ещё не видел
    return db, pid, hub, row


def test_page_state_equals_sync_comparison(web):
    db, pid, hub, row = mixed_project(web)
    page = assert_parity(db, pid, row["id"])
    by = page["by_hub_id"]
    assert by["1"]["group"] == "matched" and by["1"]["badges"] == [] and not by["1"]["delivery"]["state"]
    assert by["2"]["delivery"]["state"] == "unsent" and by["2"]["unsent"]
    # доставлено и прочитано: приложение и Hub изменились одинаково – совпадение до принятия, без значка
    assert by["3"]["group"] == "coincident" and not by["3"]["delivery"]["state"], by["3"]
    assert by["3"]["badges"] == [] and not by["3"]["differs"]
    assert by["4"]["delivery"]["state"] == "unsendable" and "unsendable" in by["4"]["groups"]
    assert by["5"]["group"] == "observed" and by["5"]["badges"] == [{"text": compare.LABELS["observed"], "tone": "accent"}]
    assert by["5"]["causes"] == ["Hub изменил справочный текст находки (поля category); статус и решение не менялись."]
    assert by["6"]["delivery"]["state"] == "refused" and by["6"]["delivery"]["error"], by["6"]
    assert by["6"]["badges"][0]["text"].startswith("Hub не принял: ")
    assert by["7"]["delivery"]["state"] == "queued"
    summary = page["summary"]
    assert summary["counts"]["unsent"] == 1 and summary["counts"]["refused"] == 1 and summary["counts"]["queued"] == 1
    assert summary["counts"]["unsendable"] == 1 and not summary["all_match"]


def test_local_edit_after_read_is_seen_before_recompare(web):
    """Правка после чтения: страница видит её сразу (до пересчёта синхронизации) и так же, как потом пересчёт."""
    db, pid, hub, row = mixed_project(web)
    compare.recompare(db, row["id"])
    assert states(db, pid)["by_hub_id"]["1"]["group"] == "matched"
    decide(web, pid, "1", comment="Новое основание оператора")
    decide(web, pid, "2", decision="later", verdict="")
    page = assert_parity(db, pid, row["id"])
    assert page["by_hub_id"]["1"]["delivery"]["state"] == "unsent"
    assert not page["by_hub_id"]["2"]["delivery"]["state"]


def test_stale_observation_keeps_delivery(web):
    """Устаревшее наблюдение не стирает «не отправлено» (план п. 2.1): у dev14 группа stale заменяла сведения
    отправки целиком, и неотправленное решение пропадало из вида."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    row = synced(db, pid, hub)
    with db._tx() as c:
        c.execute("UPDATE hub_sync_items SET stale_reason=? WHERE run_id=? AND entity_key='SAST:1'",
                  ("Наблюдение устарело для проверки.", row["id"]))
    compare.recompare(db, row["id"])
    diff = stored(db, row["id"])[("issue", "SAST:1")]
    assert diff["groups"] == ["stale"] and diff["delivery"]["state"] == "unsent", diff
    st = states(db, pid)["by_hub_id"]["1"]
    assert st["read"] == "stale" and [b["text"] for b in st["badges"]] == [
        hub_state.READ_LABELS["stale"], compare.DELIVERY_LABELS["unsent"]], st


def test_never_read_project_shows_unsent_without_claims_about_hub(web):
    """Hub не читался: о Hub ничего не утверждается – только «решение сохранено, в Hub не отправлялось»."""
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2", line=5)])
    decide(web, pid, "1")
    page = states(db, pid)
    one, two = page["by_hub_id"]["1"], page["by_hub_id"]["2"]
    assert one["read"] == "never" and one["delivery"]["state"] == "unsent" and one["groups"] == []
    assert one["badges"] == [{"text": compare.DELIVERY_LABELS["unsent"], "tone": "warn"}]
    assert two["read"] == "never" and two["badges"] == [] and not two["differs"]
    assert page["summary"]["never"] and page["summary"]["unsent"] == 1 and not page["summary"]["all_match"]


def test_no_hub_target_has_no_states(web):
    db = web.app.state.db
    pid = project(web, [sast("1")], hub_app_id=None)
    assert states(db, pid) == {"target": False, "items": {}, "by_hub_id": {}, "run": None, "latest": None,
                               "summary": None}


def test_new_finding_after_read_is_missing_with_same_label_after_recompare(web):
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    row = synchronize(db, pid, hub)
    db.save_import(pid, "repeat.xlsx", "xlsx", [], {}, [], order_findings([sast("1"), sast("2", line=5), sast("3", line=8)]))
    decide(web, pid, "3")
    before = states(db, pid)["by_hub_id"]["3"]
    assert before["read"] == "missing" and before["delivery"]["state"] == "unsent", before
    assert before["badges"][0] == {"text": hub_state.READ_LABELS["missing"], "tone": "warn"}
    compare.recompare(db, row["id"])
    after = states(db, pid)["by_hub_id"]["3"]
    assert after["read"] == "missing" and after["delivery"]["state"] == "unsent", after
    assert not states(db, pid)["summary"]["all_match"]


def test_card_counts_one_finding_like_the_project(web):
    db, pid, hub, row = mixed_project(web)
    whole = states(db, pid)
    for ident in ("1", "2", "4", "6", "7"):
        one = states(db, pid, keys=[f"SAST:{ident}"])
        assert set(one["items"]) == {("issue", f"SAST:{ident}")} and one["summary"] is None
        assert one["by_hub_id"][ident] == whole["by_hub_id"][ident], ident


def test_all_match_only_after_full_current_sync(web):
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    synchronize(db, pid, hub)
    synced(db, pid, hub)
    summary = states(db, pid)["summary"]
    assert summary["all_match"] and summary["unsent"] == 0 and summary["differs"] == 0, summary
    decide(web, pid, "1")
    summary = states(db, pid)["summary"]
    assert not summary["all_match"] and summary["counts"]["unsent"] == 1


def test_links_from_database_equal_run_links(web):
    """Связи находок с дефектами выборкой полей в базе – те же, что разбором наблюдений (`run_links`)."""
    from app import hub_sync_compare
    from test_hub_pull import PullHub, read
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2", line=5)])
    hub = PullHub(count=2)
    hub.issues[1]["defectId"] = 77
    rid = read((db, pid), hub)
    items = db._all("SELECT * FROM hub_sync_items WHERE run_id=?", (rid,))
    expected = hub_sync_compare.run_links(items)
    got = db.on_connection(lambda c: hub_state._links(c, rid, True))
    assert got == expected, (got, expected)
    assert got["listed_defects"]


def test_incomplete_read_keeps_unsent_visible(web):
    """Неполное чтение вместе с неотправленным решением: видны и то и другое, страница и пересчёт совпадают."""
    from test_sync_causes import BranchFailHub
    db = web.app.state.db
    hub = BranchFailHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    hub.issues[1]["issueBranchBriefData"].append({"branch": "feature", "status": "To verify", "isBranchDefault": False,
                                                 "lastSeen": 1800000000000})  # чтение этой ветки Hub не отдаёт
    row = synced(db, pid, hub)
    decide(web, pid, "1", comment="Уточнённое основание")  # правка после пересчёта: страница считает находку заново
    page = assert_parity(db, pid, row["id"])
    st = page["by_hub_id"]["1"]
    assert st["read"] == "incomplete" and st["delivery"]["state"] == "unsent", st
    assert [b["text"] for b in st["badges"]] == [hub_state.READ_LABELS["incomplete"], compare.DELIVERY_LABELS["unsent"]]


def test_other_app_number_is_not_read_yet(web):
    """Смена номера приложения в Hub: прежнее чтение к новому назначению не относится – «Hub не читался»."""
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    db.update_project(pid, hub_app_id=8)
    page = states(db, pid)
    st = page["by_hub_id"]["1"]
    assert page["summary"]["never"] and st["read"] == "never" and st["delivery"]["state"] == "unsent", st


def test_page_computation_writes_nothing(web):
    db, pid, hub, row = mixed_project(web)
    tables = ("hub_sync_pending", "hub_sync_items", "hub_defect_sync_runs", "reviews", "hub_ops", "hub_issue_states",
              "hub_entity_versions", "hub_sync_applications")
    before = {t: db._all(f"SELECT * FROM {t} ORDER BY 1") for t in tables}
    states(db, pid)
    states(db, pid, keys=["SAST:2"])
    assert {t: db._all(f"SELECT * FROM {t} ORDER BY 1") for t in tables} == before


def test_legacy_pending_rows_parity_before_and_after_reconcile(web):
    """Ожидание прежнего выпуска, которое сверка закроет: страница до записи переходов видит то же, что пересчёт после
    (план п. 2.1: общий расчёт сверки без записи)."""
    from test_hub_pull_pending import legacy_pending
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    row = synchronize(db, pid, hub)
    run_row = db._one("SELECT * FROM hub_defect_sync_runs WHERE id=?", (row["id"],))
    issue = db.on_connection(lambda c: compare.ComparisonContext(c, run_row)).issue_local("SAST:1")
    accepted = loads(issue["state"]["confirmed_json"], {})
    ident, _ = legacy_pending(db, row["id"], "issue", "SAST:1", issue, {}, accepted)
    assert states(db, pid)["by_hub_id"]["1"]["group"] == "matched"
    assert db._one("SELECT state FROM hub_sync_pending WHERE id=?", (ident,))["state"] == "pending"  # страница не пишет
    assert_parity(db, pid, row["id"])
    # пересчёт записал переход: ожидание без доказательства правки закрыто (страница видела это заранее)
    assert db._one("SELECT state FROM hub_sync_pending WHERE id=?", (ident,))["state"] in ("delivered", "discarded")

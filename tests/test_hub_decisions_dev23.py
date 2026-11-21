"""0.9.26.dev23: находкам состава дефекта из Hub без решения – решение «из Hub» и «Push в Hub»
без «Проверено»; номер находки без ведущих нулей при загрузке (бэклог 64); отметка «Внесено в Hub» по подтверждённому
составу, в том числе при «Проверить в Hub». Данные, адреса и номера выдуманы."""

import json

import openpyxl

from app import defect_drafts, hub_defects
from app.db import dumps, loads, text_hash
from app.hub_import import norm_hub_id, parse_workbook
from hub_fixtures import SAST_ROWS, SCA_ROWS, make_hub_xlsx
from test_defect import save_sast
from test_hub_defect_guard import recheck
from test_hub_defect_import import deliver, imported
from test_hub_defect_update import (SCA_OLD, assemble, hub_body, note, phase, read_job, sent_body, to_preview,
                                    to_put)
from test_hub_defects import FIX, REASON, hub_settings, sast_ready
from test_hub_pull import PullHub, accept, read
from test_hub_sync import store  # noqa: F401
from test_web import prepared, start_run, wait_run, web  # noqa: F401


def history_details(db, defect_id: int) -> list[dict]:
    return [loads(r["details_json"], {}) for r in db._all(
        "SELECT details_json FROM hub_defect_history WHERE defect_id = ? ORDER BY id", (defect_id,))]


def push_text_as_is(web, pid: int, row: dict, body: dict) -> dict:
    """«Push в Hub» текста черновика с правкой (иначе «Изменений для отправки нет»): до подтверждённого done."""
    db = web.app.state.db
    current = db.hub_defect(row["id"])
    defect_drafts.save(db, current, str(current["draft_revision"]), summary=current["draft_summary"],
                       command=current["draft_command_text"] + "\nДополнение оператора.")
    put = to_put(web, pid, db.hub_defect(row["id"]), first=body)
    deliver(web, put, 204, text="")
    links = tuple((link["id"], link["type"]) for link in body["linkedIssues"])
    read_job(web, sent_body(db, row["id"], links=links))
    fresh = db.hub_defect(row["id"])
    assert hub_defects.update_state(fresh)["phase"] in hub_defects.UPDATE_SUCCESS, hub_defects.update_state(fresh)
    return fresh


# ============================================================================ решение «из Hub» – занесение и Push


def test_import_gives_hub_decision_only_to_undecided_findings_and_push_works_without_reviewed(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    db = web.app.state.db
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)  # решение оператора с «Проверено»
    operator = db.get_review(pid, "510001")
    body = hub_body(links=((510001, "SAST"), (510004, "SAST")))
    row = imported(web, pid, "777", body)
    one, four = db.get_review(pid, "510001"), db.get_review(pid, "510004")
    assert (one["decision"], one["revision"], one["decision_origin"]) == (operator["decision"], operator["revision"], "operator")
    assert (four["decision"], four["final_verdict"], four["decision_origin"], four["reviewed"]) == (
        "hub", "true_positive", defect_drafts.HUB_DEFECT_ORIGIN, 0)
    assert four["decided_at"] and four["revision"] >= 1
    targets = {t["hub_id"]: t for t in json.loads(row["targets_json"])}
    assert targets["510004"]["revision"] == four["revision"], "цель строки – с редакцией решения «из Hub»"
    assert targets["510001"]["revision"] == one["revision"]
    assert any(d.get("hub_decisions") == ["510004"] for d in history_details(db, row["id"]))
    # «Текст из решений» – отказ: обоснования оператора у решения «из Hub» нет
    generated = assemble(web, pid, row)
    assert generated.status_code == 409 and "принято из Hub" in generated.text, generated.text
    # «Push в Hub» текста как есть – работает: «Проверено» и сверка кода у решения «из Hub» не требуются
    done = push_text_as_is(web, pid, row, body)
    marks = {t["hub_id"]: t for t in json.loads(done["targets_json"])}
    assert marks["510004"]["entered_origin"] == "defect" and marks["510004"]["entered_hash"]
    four = db.get_review(pid, "510004")
    assert four["entered_hub"] and four["entered_origin"] == "defect" and four["decision"] == "hub" and not four["reviewed"]
    assert db.get_review(pid, "510001")["entered_hub"]


def test_later_and_risk_decisions_are_kept_and_block_push_as_before(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    db = web.app.state.db
    db.save_review(pid, "510003", decision="later", final_verdict="", final_comment="", reviewed=False)
    before = db.get_review(pid, "510003")
    row = imported(web, pid, "777", hub_body(links=((510003, "SAST"),)))
    after = db.get_review(pid, "510003")
    assert (after["decision"], after["revision"], after["decision_origin"]) == ("later", before["revision"], before["decision_origin"])
    assert any(d.get("hub_decisions") == [] for d in history_details(db, row["id"]))
    to_preview(web, pid, row, hub_body(links=((510003, "SAST"),)))
    assert phase(db, row["id"]) == "refused" and "нет решения «Подтверждаю дефект»" in note(db, row["id"])


def test_sca_push_refuses_hub_status_decisions_and_mixed_composition(web):
    """Ревью dev23 (1): decision 'hub' пишет и Pull статусов (ложное срабатывание, риск принят) – такое решение не
    «из состава дефекта», Push по нему не идёт; «отложено» у другой находки состава – тоже отказ."""
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    db = web.app.state.db
    body = hub_body(links=((73001, "SCA_S"), (73002, "SCA_S")), summary=SCA_OLD)
    row = imported(web, pid, "777", body)
    with db._tx() as c:  # как после Pull статуса «False Positive» у опорной находки
        c.execute("UPDATE reviews SET decision = 'hub', final_verdict = 'false_positive', decision_origin = 'hub_sync',"
                  " revision = revision + 1 WHERE project_id = ? AND hub_id = '73001'", (pid,))
    current = db.hub_defect(row["id"])
    defect_drafts.save(db, current, str(current["draft_revision"]), summary=current["draft_summary"],
                       command=current["draft_command_text"] + "\nПравка.")
    to_preview(web, pid, db.hub_defect(row["id"]), body)
    assert phase(db, row["id"]) == "refused", note(db, row["id"])  # набор по ложному срабатыванию не готовится (ADR-0091)
    with db._tx() as c:
        c.execute("UPDATE reviews SET decision = 'hub', final_verdict = 'true_positive', decision_origin = ?"
                  " WHERE project_id = ? AND hub_id = '73001'", (defect_drafts.HUB_DEFECT_ORIGIN, pid))
        c.execute("UPDATE reviews SET decision = 'later', final_verdict = '', decision_origin = 'operator',"
                  " revision = revision + 1 WHERE project_id = ? AND hub_id = '73002'", (pid,))
    to_preview(web, pid, db.hub_defect(row["id"]), body)
    assert phase(db, row["id"]) == "refused" and "73002" in note(db, row["id"]), note(db, row["id"])


def test_sca_import_gives_update_decision_with_signature_and_push_sends_draft_as_is(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    db = web.app.state.db
    body = hub_body(links=((73001, "SCA_S"), (73002, "SCA_S")), summary=SCA_OLD)
    row = imported(web, pid, "777", body)
    from app.db import review_signature
    for hub_id in ("73001", "73002"):
        r = db.get_review(pid, hub_id)
        assert (r["decision"], r["final_verdict"], r["decision_origin"]) == ("hub", "true_positive", defect_drafts.HUB_DEFECT_ORIGIN)
        assert r["finding_sig"] == review_signature(db.get_finding_by_hub_id(pid, hub_id)["data"]), "решение SCA – по текущей версии находки"
    card = web.client.get(f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}")
    assert card.status_code == 200
    assert assemble(web, pid, row).status_code == 409
    done = push_text_as_is(web, pid, row, body)
    assert {t["hub_id"] for t in json.loads(done["targets_json"])} == {"73001", "73002"}
    assert all(db.get_review(pid, h)["entered_hub"] for h in ("73001", "73002"))
    # отметка по подтверждённому составу без отпечатка решения: карточка – «Дефект создан в Hub», а не «не подтверждён»
    assert not db.get_review(pid, "73001")["entered_decision_hash"]
    card = web.client.get(f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}").text
    assert "Дефект создан в Hub" in card and "дефект не подтверждён" not in card


def test_pull_accepting_a_defect_gives_hub_decisions_and_status_pull_keeps_them(store):
    db, pid = store
    hub = PullHub(count=2)
    rid = read(store, hub)
    accept(db, rid)
    one = db.get_review(pid, "1")
    assert (one["decision"], one["final_verdict"], one["decision_origin"]) == ("hub", "true_positive", defect_drafts.HUB_DEFECT_ORIGIN)
    assert db.get_review(pid, "2") is None or not db.get_review(pid, "2")["decision"], "находка не из состава – без решения"
    defect = db._one("SELECT * FROM hub_defects")
    assert loads(defect["targets_json"], [])[0]["revision"] == one["revision"]
    # следующий Pull: статус находки в Hub без решения (Fixed) решение по составу дефекта не снимает
    rid2 = read(store, hub)
    accept(db, rid2)
    again = db.get_review(pid, "1")
    assert (again["decision"], again["revision"]) == ("hub", one["revision"])


# ============================================================================ ведущие нули номера (бэклог 64)


def test_norm_hub_id():
    assert norm_hub_id("0012") == "12" and norm_hub_id("12") == "12" and norm_hub_id("0") == "0"
    assert norm_hub_id("000") == "0" and norm_hub_id(" 007 ") == "7"
    assert norm_hub_id("A-007") == "A-007" and norm_hub_id("0012:") == "0012:" and norm_hub_id("") == ""


def test_hub_export_numbers_lose_leading_zeros_but_plain_tables_keep_them(tmp_path):
    sast = [dict(SAST_ROWS[0], **{"Issue id": "0510001"}), dict(SAST_ROWS[1], **{"Issue id": "510002"})]
    sca = [dict(SCA_ROWS[0], **{"Issue id": "073001"})]
    result = parse_workbook(make_hub_xlsx(tmp_path / "hub.xlsx", sast=sast, sca=sca))
    assert result.format == "hub"
    assert sorted(f.hub_id for f in result.findings) == ["510001", "510002", "73001"]
    # таблица с колонками Hub – тоже номера Hub
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Находки"
    ws.append(["Issue id", "Practice", "Severity", "File", "Line number"])
    ws.append(["0009002", "SAST", "Medium", "src/a.py", "5"])
    wb.save(tmp_path / "t.xlsx")
    assert [f.hub_id for f in parse_workbook(tmp_path / "t.xlsx").findings] == ["9002"]
    # обычная таблица не из Hub: номер – как написан
    path = tmp_path / "plain.csv"
    path.write_text("ID;Вид;Файл;Строка;Критичность;Правило\n007;SAST;src/app.py;3;Высокий;Правило\n", encoding="utf-8")
    plain = parse_workbook(path)
    assert plain.format == "table" and [f.hub_id for f in plain.findings] == ["007"]


# ============================================================================ отметка по подтверждённому составу


def test_recheck_marks_unmarked_targets_with_current_revision_and_content_hash(web):
    """Дефект создан из приложения с пустыми отпечатками целей (текст как есть при неготовой заготовке),
    оператор пересохранил решения – отметок не было. «Проверить в Hub» с итогом «дефект на месте» ставит их."""
    from test_hub_defects import create, hub_job, to_preview as blank_preview
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = blank_preview(web, pid, url)
    create(web, pid, row["id"])
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    done = db.hub_defect(row["id"])
    assert done["state"] == "done" and db.get_review(pid, "510001")["entered_hub"]
    # отметки нет, у цели нет отпечатков и полей отметки (состав переписан Pull синхронизации), редакция
    # решения с тех пор выросла
    stale = [{k: v for k, v in {**t, "entered_hash": "", "decision_hash": ""}.items()
              if k not in ("entered_origin", "entered_defect_id", "entered_op_id", "entered_defect_revision")}
             for t in json.loads(done["targets_json"])]
    db.hub_defect_update(done["id"], targets_json=dumps(stale))
    with db._tx() as c:
        c.execute("UPDATE reviews SET entered_hub = 0, entered_hub_at = NULL, entered_origin = '', entered_op_id = NULL,"
                  " entered_text_hash = '', entered_decision_hash = '', entered_defect_id = NULL WHERE project_id = ?", (pid,))
    db.save_review(pid, "510001", decision="disagree", final_verdict="true_positive", final_comment="Пересохранено", reviewed=True)
    review = db.get_review(pid, "510001")
    assert not review["entered_hub"] and review["revision"] != stale[0]["revision"]
    response = recheck(web, pid, done["id"])
    assert response.status_code == 200, response.text
    hub_job(web, body={"id": 555, "summary": done["summary"], "description": done["body_html"] or "<p>x</p>",
                       "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    current = db.hub_defect(done["id"])
    assert hub_defects.RECHECK_OK in (loads(current["verify_json"], {}) or {}).get("recheck", "")
    target = json.loads(current["targets_json"])[0]
    content = text_hash(dumps({"summary": current["summary"], "command_text": current["command_text"]}))
    marked = db.get_review(pid, "510001")
    assert target["revision"] == marked["revision"] and target["entered_hash"] == content
    assert (target["entered_origin"], target["entered_defect_id"], target["entered_op_id"]) == ("defect", current["id"], current["confirm_op_id"])
    assert marked["entered_hub"] and marked["entered_origin"] == "defect" and marked["entered_text_hash"] == content
    assert marked["entered_defect_id"] == current["id"] and marked["entered_op_id"] == current["confirm_op_id"]
    # повтор – ничего не меняет (та же редакция, тот же текст)
    assert hub_defects.apply_marks(db, current) == 0
    assert db.get_review(pid, "510001")["entered_hub_at"] == marked["entered_hub_at"]


def test_recheck_keeps_an_earlier_manual_mark_and_survives_a_failure_before_closing(web, monkeypatch):
    """Ревью dev23 (2, 3): ручная отметка, поставленная до проверки, остаётся – проверка ничего не записывала; сбой при
    отметках до закрытия проверки – строка всё ещё ждёт операцию, повторная доставка доводит отметки и итог."""
    from test_hub_defect_import import take
    from test_hub_defects import create, hub_job, to_preview as blank_preview
    from test_hub_status_routes import worker_headers
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = blank_preview(web, pid, url)
    create(web, pid, row["id"])
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    done = db.hub_defect(row["id"])
    with db._tx() as c:
        c.execute("UPDATE reviews SET entered_hub = 0, entered_origin = '', entered_text_hash = '' WHERE project_id = ?", (pid,))
    revision = db.get_review(pid, "510001")["revision"]
    db.mark_entered(pid, "510001", True, revision=revision, entered_hash="ручной-текст")  # до проверки
    manual = db.get_review(pid, "510001")
    assert recheck(web, pid, done["id"]).status_code == 200
    job = take(web)
    body = {"id": 555, "summary": done["summary"], "description": done["body_html"] or "<p>x</p>",
            "linkedIssues": [{"id": 510001, "type": "SAST"}]}
    # сбой при отметках: доставка падает, строка ждёт ту же операцию, итога проверки нет
    monkeypatch.setattr(hub_defects, "apply_marks", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("сбой")))
    failed = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web), content=json.dumps(
        {"lease_token": job["lease_token"], "worker_id": "w1", "status": 200, "headers": {},
         "body_text": json.dumps(body, ensure_ascii=False), "error": ""}))
    assert failed.status_code == 500, failed.text  # исполнитель доставит ещё раз
    monkeypatch.undo()
    waiting = db.hub_defect(done["id"])
    assert waiting["verify_op_id"] == job["op_id"], "строка всё ещё ждёт эту операцию"
    assert hub_defects.RECHECK_OK not in (loads(waiting["verify_json"], {}) or {}).get("recheck", "")
    # повторная доставка того же результата – отметки и итог
    deliver(web, job, 200, body)
    current = db.hub_defect(done["id"])
    assert hub_defects.RECHECK_OK in (loads(current["verify_json"], {}) or {}).get("recheck", "")
    after = db.get_review(pid, "510001")
    assert (after["entered_text_hash"], after["entered_origin"], after["entered_hub_at"]) == (
        "ручной-текст", manual["entered_origin"], manual["entered_hub_at"]), "ручная отметка до проверки не перетирается"


def created_defect(web):
    """Дефект из карточки SAST, созданный и подтверждённый поддельным исполнителем: (pid, url, строка done)."""
    from test_hub_defects import create, hub_job, to_preview as blank_preview
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = blank_preview(web, pid, url)
    create(web, pid, row["id"])
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    done = db.hub_defect(row["id"])
    assert done["state"] == "done"
    return pid, url, done


def recheck_body(done: dict) -> dict:
    return {"id": 555, "summary": done["summary"], "description": done["body_html"] or "<p>x</p>",
            "linkedIssues": [{"id": 510001, "type": "SAST"}]}


def test_stale_recheck_handler_does_not_restore_a_withdrawn_mark(web):
    """Ревью dev23 (круг 2): обработчик, прочитавший проверку до её закрытия, после закрытия и снятия отметки оператором
    ничего не ставит – в транзакции отметки строка должна всё ещё ждать эту операцию (expect_op)."""
    from test_hub_defect_import import take
    pid, url, done = created_defect(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE reviews SET entered_hub = 0, entered_origin = '', entered_text_hash = '' WHERE project_id = ?", (pid,))
    assert recheck(web, pid, done["id"]).status_code == 200
    waiting = db.hub_defect(done["id"])  # строка, какой её прочитал устаревший обработчик
    deliver(web, take(web), 200, recheck_body(done))
    closed = db.hub_defect(done["id"])
    assert closed["verify_op_id"] is None and db.get_review(pid, "510001")["entered_hub"]
    db.mark_entered(pid, "510001", False)  # оператор снял отметку после закрытия проверки
    assert not db.get_review(pid, "510001")["entered_hub"]
    stale_op = ("verify_op_id", int(waiting["verify_op_id"]))
    assert hub_defects.apply_marks(db, waiting, "2026-11-01T00:00:00+00:00", only_unmarked=True, expect_op=stale_op) == 0
    assert not db.get_review(pid, "510001")["entered_hub"]
    assert db.hub_defect(done["id"])["targets_json"] == closed["targets_json"]


def test_old_format_target_keeps_its_decision_print_when_marked_after_recheck(web):
    """Ревью dev23 (круг 2): цель прежнего формата (без decision_hash, отпечаток решения в entered_hash) при отметке
    по составу переносит его в decision_hash – карточка по-прежнему видит, что обоснование изменилось."""
    from test_hub_defect_import import take
    pid, url, done = created_defect(web)
    db = web.app.state.db
    old = [{k: v for k, v in {**t, "entered_hash": "старый-отпечаток-решения"}.items()
            if k not in ("decision_hash", "entered_origin", "entered_defect_id", "entered_op_id", "entered_defect_revision")}
           for t in json.loads(done["targets_json"])]
    db.hub_defect_update(done["id"], targets_json=dumps(old))
    with db._tx() as c:
        c.execute("UPDATE reviews SET entered_hub = 0, entered_origin = '', entered_text_hash = '',"
                  " entered_decision_hash = '' WHERE project_id = ?", (pid,))
    save_sast(web, pid, "510001", "true_positive", "", "Новое обоснование оператора.", FIX, defect_confirm="1")
    assert recheck(web, pid, done["id"]).status_code == 200
    deliver(web, take(web), 200, recheck_body(done))
    current = db.hub_defect(done["id"])
    target = json.loads(current["targets_json"])[0]
    content = text_hash(dumps({"summary": current["summary"], "command_text": current["command_text"]}))
    marked = db.get_review(pid, "510001")
    assert (target["decision_hash"], target["entered_hash"]) == ("старый-отпечаток-решения", content)
    assert marked["entered_hub"] and marked["entered_decision_hash"] == "старый-отпечаток-решения"
    assert marked["entered_text_hash"] == content and marked["revision"] == target["revision"]
    card = web.client.get(url).text
    assert "id=\"entered-changed\"" in card or "изменил" in card, "карточка видит, что текст решения изменился"


def test_imported_defect_targets_without_confirmed_update_are_left_alone(web):
    """Занесённому без подтверждённого обновления отметки не ставятся (ADR-0124 п. 5): у его целей нет происхождения
    отметки, by_composition их не трогает; «Проверить в Hub» к занесённому не применяется – как раньше."""
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    db = web.app.state.db
    row = imported(web, pid, "777", hub_body(links=((510004, "SAST"),)))
    assert not db.get_review(pid, "510004")["entered_hub"]
    assert "entered_origin" not in json.loads(row["targets_json"])[0]
    same = hub_defects.by_composition(db, row)
    assert same["targets_json"] == row["targets_json"]
    assert hub_defects.apply_marks(db, row) == 0 and not db.get_review(pid, "510004")["entered_hub"]
    assert recheck(web, pid, row["id"]).status_code == 409

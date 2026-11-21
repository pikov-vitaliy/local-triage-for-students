"""Сборка служебного блока из модели шаблона Hub и шаг в «Push в Hub» (ADR-0139). Данные выдуманы, сети нет."""

from __future__ import annotations

import json

import pytest

from app import hub_block_builder as builder
from app import hub_block_version, hub_defects
from app.routes import hub_defect_routes
from test_defect import save_sast
from test_hub_defect_import import deliver, tab, take
from test_hub_defect_update import deliver_raw, hub_body, phase, put_click, read_job, ready, sent_body
from test_hub_defects import FIX, REASON, create, hello, hub_job, sast_ready, to_preview
from test_hub_status_routes import AS_JSON
from test_web import web  # noqa: F401

TEXT_ONLY = "<p>Текст дефекта без блока.</p>"
SCAN = {"date": 1784899298670, "initiator": "user1", "scanTarget": [{"branch": "main", "commit": "abc123", "url": "https://git.example.org/repo"}]}


def sast_model(ident=510001, line=1210, source="a < b", description="<h3>Description</h3><p>D</p>") -> dict:
    return {"application": {"id": "7"}, "issues": [{
        "id": ident, "link": f"https://hub.example.org/issues/SAST/{ident}", "title": "T", "type": "SAST", "severity": "Low", "category": "Категория",
        "cwes": [{"id": 497, "link": "https://cwe.example.org/497"}], "description": description, "scanObject": {"id": 6380, "name": "repo"}, "lastScan": SCAN,
        "path": [{"fileName": "src/A.java", "line": line, "sourceCode": source}, {"fileName": "src/B.java", "line": 2, "sourceCode": "b()"}]}]}


def sca_model(ident=73001, fix="4.18.0") -> dict:
    description = ("<h3>Description</h3><p>Описание & детали</p><h3>Detection</h3><p></p><h3>Explanation</h3><p>Почему</p>"
                   "<h3>Recommendation</h3><p></p><h3>Reference</h3><p>- https://a.example.org, - https://b.example.org</p>")
    return {"application": {"id": "7"}, "issues": [{
        "id": ident, "link": f"https://hub.example.org/issues/SCA_S/{ident}", "title": "pkg:npm/demo-lib", "type": "SCA Security", "severity": "Critical", "foundBy": "tool",
        "externalLink": "https://scan.example.org/1", "fixVersion": fix, "cve": {"id": "CVE-2099-0001", "link": "https://vuln.example.org/1"}, "cvss": {"score": "9.8"},
        "cwes": [{"id": 94}], "description": description, "scanObject": {"id": 6751, "name": "repo"}, "lastScan": {**SCAN, "initiator": ""}}]}


def test_sast_one_finding():
    block = builder.build_block("SAST", [sast_model()])
    lines = hub_defects.description_lines(block)
    assert lines[0] == hub_defects.IMPORT_BOUNDARY and lines.count(hub_defects.IMPORT_BOUNDARY) == 1
    assert hub_defects.hub_block("<p>Текст.</p>" + block) == (block, "")
    assert "Файл: src/A.java:1,210" in block and "Jul 24, 2026, 1:21:38 PM" in block and "#6380: repo" in block
    assert "a &lt; b" in block, "код экранируется"
    assert "<h3>Description</h3><p>D</p>" in block, "описание Hub как есть"
    assert block.count("{code}") == 2 and block.count("{panel}") == 2


def test_sast_several_findings_use_a_table():
    block = builder.build_block("SAST", [sast_model(), sast_model(510002)])
    assert "<th>Файл</th>" in block and block.count("<h2>ID:") == 2


def test_sca_one_and_several():
    one = builder.build_block("SCA", [sca_model()])
    assert "Компонент: pkg:npm/demo-lib" in one and "#6,751: repo" in one and "<table><tbody></tbody></table>" in one
    assert "<p>Описание & детали</p>" in one and "<p>Почему</p>" in one
    assert "Обновление demo-lib до версии 4.18.0" in one
    assert "<p>https://a.example.org</p>" in one and "<p>https://b.example.org</p>" in one
    several = builder.build_block("SCA", [sca_model(), sca_model(73002)])
    assert "<th>Версия исправления</th>" in several and several.count("Информация по цели сканирования") == 2


def test_sca_version_is_replaced_like_in_a_real_block():
    block = builder.build_block("SCA", [sca_model()])
    got = hub_block_version.retarget(block, "4.18.1")
    assert "Версия исправления: 4.18.1" in got.block and "Обновление demo-lib до версии 4.18.1" in got.block


def test_foreign_address_is_not_a_link_and_values_are_escaped():
    model = sast_model()
    model["issues"][0]["link"] = "javascript:alert(1)"
    model["issues"][0]["category"] = "<script>"
    block = builder.build_block("SAST", [model])
    assert "javascript:" not in block and "<script>" not in block and "&lt;script&gt;" in block


@pytest.mark.parametrize("models", [[], [{"issues": []}], [{"issues": [{}, {}]}], [{}]])
def test_incomplete_input_is_refused(models):
    with pytest.raises(ValueError):
        builder.build_block("SAST", models)


def test_empty_values_are_not_invented():
    block = builder.build_block("SAST", [{"issues": [{"id": 1}]}])
    assert "None" not in block and hub_defects.hub_block("<p>x</p>" + block)[1] == ""


def test_model_answer_must_name_the_finding():
    from app import hub_template_model as model
    assert model.model_of(sast_model(5), 5) is not None
    assert model.model_of(sast_model(5), 6) is None
    assert model.model_of({"issues": []}, 5) is None


# ---------------------------------------------------------------------------- шаг в Push


def text_only(links=((510001, "SAST"),)) -> dict:
    return hub_body(links=links, description=TEXT_ONLY)


def lost_block(web, build: bool = False) -> tuple[int, dict]:
    pid, row = ready(web, links=((510001, "SAST"),), build=False)
    db = web.app.state.db
    hello(web)
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET confirmed_object_json = ?, command_text = ?, draft_command_text = ? WHERE id = ?",
                  (json.dumps(text_only()), "Текст дефекта без блока.", "Текст дефекта без блока. Правка.", row["id"]))
    return pid, db.hub_defect(row["id"])


def act(web, pid, row_id, action, data=None):
    return web.client.post(f"/projects/{pid}/hub/defects/{row_id}/{action}", headers=AS_JSON, data=data or {})


def to_blank_refusal(web, pid, row) -> None:
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    blank = take(web)
    assert blank["path"].startswith("/defects/blank")
    deliver(web, blank, 400, {"message": "No issues suitable"}, error="Hub 400")


def test_push_builds_the_block_when_hub_refuses_the_blank(web):
    pid, row = lost_block(web)
    db = web.app.state.db
    to_blank_refusal(web, pid, row)
    job = take(web)
    assert job["method"] == "GET" and job["path"].startswith("/templates/defects/model?") and "issueId=510001" in job["path"]
    assert hub_defects.update_state(db.hub_defect(row["id"]))["step"] == "model"
    deliver(web, job, 200, sast_model())
    tab(web, pid)
    fresh = db.hub_defect(row["id"])
    state = hub_defects.update_state(fresh)
    assert state["phase"] == "preview", state
    assert "first_read" not in state and "model_done" not in state, "данные находок в состоянии попытки не остаются"
    assert hub_defects.BLOCK_BUILT in state["warnings"]
    assert json.loads(fresh["blank_json"])["built_from_model"] is True
    block = builder.build_block("SAST", [sast_model()])
    assert state["new"]["description"].endswith(block)
    assert "Текст дефекта без блока. Правка." in state["new"]["description"]
    # запись только по нажатию
    assert take(web) is None
    assert put_click(web, pid, fresh).status_code == 200
    read_job(web, text_only())
    put = take(web)
    assert put["method"] == "PUT" and put["body"]["description"].endswith(block)
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"]))
    assert phase(db, row["id"]) == "done", hub_defects.update_state(db.hub_defect(row["id"]))


def test_failure_on_a_finding_goes_without_block_and_builds_nothing(web):
    pid, row = lost_block(web)
    db = web.app.state.db
    to_blank_refusal(web, pid, row)
    deliver(web, take(web), 500, {}, error="Hub 500")
    tab(web, pid)
    fresh = db.hub_defect(row["id"])
    state = hub_defects.update_state(fresh)
    assert state["phase"] == "preview" and any("собрать не удалось" in w for w in state["warnings"]), state
    assert not fresh["blank_json"] or "built_from_model" not in fresh["blank_json"]
    assert hub_defects.IMPORT_BOUNDARY not in hub_defects.description_lines(state["new"]["description"])


def test_answer_about_another_finding_builds_nothing(web):
    pid, row = lost_block(web)
    db = web.app.state.db
    to_blank_refusal(web, pid, row)
    deliver(web, take(web), 200, sast_model(999))
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert any("не разобран" in w for w in state["warnings"]), state


def test_hub_failure_on_the_blank_does_not_start_reads(web):
    pid, row = lost_block(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    deliver(web, take(web), 500, {}, error="Hub 500")
    assert take(web) is None
    tab(web, pid)
    assert hub_defects.update_state(db.hub_defect(row["id"]))["phase"] == "preview"


def test_redelivery_changes_nothing(web):
    pid, row = lost_block(web)
    db = web.app.state.db
    to_blank_refusal(web, pid, row)
    job = take(web)
    deliver(web, job, 200, sast_model())
    tab(web, pid)
    before = db.hub_defect(row["id"])
    hub_defects.after_op(db, db.hub_op(job["op_id"]))
    after = db.hub_defect(row["id"])
    assert after["blank_json"] == before["blank_json"] and after["update_json"] == before["update_json"]
    assert take(web) is None


def test_composition_change_during_reads_builds_nothing(web):
    pid, row = lost_block(web)
    db = web.app.state.db
    to_blank_refusal(web, pid, row)
    job = take(web)
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET targets_json = ? WHERE id = ?",
                  (json.dumps(json.loads(row["targets_json"]) + [{"hub_id": "510002", "issue_id": 510002, "issue_type": "SAST"}]), row["id"]))
    deliver(web, job, 200, sast_model())
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert any("состав дефекта изменился" in w for w in state["warnings"]), state


def test_reads_go_one_by_one_without_the_page(web):
    pid, row = lost_block(web)
    db = web.app.state.db
    save_sast(web, pid, "510002", "true_positive", "", REASON, FIX)
    first_target = json.loads(row["targets_json"])[0]
    second_target = {**first_target, "hub_id": "510002", "issue_id": 510002, "revision": db.get_review(pid, "510002")["revision"], "sig": db.finding_sig(pid, "510002")}
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET targets_json = ? WHERE id = ?", (json.dumps([first_target, second_target]), row["id"]))
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only(links=((510001, "SAST"), (510002, "SAST"))))
    tab(web, pid)
    deliver(web, take(web), 400, {"message": "No issues suitable"}, error="Hub 400")
    first = take(web)
    assert "issueId=510001" in first["path"]
    deliver(web, first, 200, sast_model(510001))
    second = take(web)
    assert second is not None and "issueId=510002" in second["path"], "следующее чтение ставится само"
    deliver(web, second, 200, sast_model(510002))
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview", state
    assert state["new"]["description"].count("<h2>ID:") == 2


def test_defect_with_a_block_never_takes_this_step(web):
    pid, row = ready(web, build=True)
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web)
    assert take(web) is None
    assert hub_defects.update_state(web.app.state.db.hub_defect(row["id"]))["phase"] == "preview"


def test_own_where_section_goes_straight_to_the_model(web):
    pid, row = lost_block(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_command_text = ? WHERE id = ?",
                  ("Текст дефекта без блока.\n\nГде исправлять:\nВетка: main", row["id"]))
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    job = take(web)
    assert job["path"].startswith("/templates/defects/model?"), job["path"]


def where_row(web, section: str = "Где исправлять:\nВетка: main") -> tuple[int, dict]:
    pid, row = lost_block(web)
    with web.app.state.db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_command_text = ? WHERE id = ?", (f"Текст дефекта без блока.\n\n{section}", row["id"]))
    return pid, web.app.state.db.hub_defect(row["id"])


def test_section_stays_with_a_hint_and_second_push_has_no_changes(web):
    pid, row = where_row(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    deliver(web, take(web), 200, sast_model())
    tab(web, pid)
    fresh = db.hub_defect(row["id"])
    state = hub_defects.update_state(fresh)
    assert state["phase"] == "preview" and state["block_built"], state
    assert hub_defects.defect_where.has_head(state["new"]["command_text"]), "раздел не снимается сам"
    assert hub_defects.BLOCK_BUILT in state["warnings"] and hub_defects.WHERE_WITH_BLOCK in state["warnings"]
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert "собранный приложением" in page and "остался раздел" in page
    assert "Служебный блок Hub (собран приложением)" in page and "Служебный блок Hub (из заготовки)" not in page
    assert put_click(web, pid, fresh).status_code == 200
    read_job(web, text_only())
    put = take(web)
    assert put["method"] == "PUT" and "Где исправлять" in put["body"]["description"] and hub_defects.IMPORT_BOUNDARY in hub_defects.description_lines(put["body"]["description"])
    deliver(web, put, 204, text="")
    written = sent_body(db, row["id"])
    read_job(web, written)
    fresh = db.hub_defect(row["id"])
    assert phase(db, row["id"]) == "done", hub_defects.update_state(fresh)
    # второй Push: блок уже в Hub, чтений нет, разниц нет
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, written)
    assert take(web) is None
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "cancelled" and state["note"].startswith("Изменений для отправки нет"), state


def test_cancelled_preview_keeps_the_section_in_the_draft_and_reuses_the_block(web):
    pid, row = where_row(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    deliver(web, take(web), 200, sast_model())
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    raw = db.hub_defect(row["id"])["update_json"]
    assert act(web, pid, row["id"], "update-cancel", {"generation": state["generation"], "shown": hub_defects.text_hash(raw)}).status_code == 200
    fresh = db.hub_defect(row["id"])
    assert hub_defects.defect_where.has_head(fresh["draft_command_text"]), "черновик оператора не меняется"
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    assert take(web) is None, "тот же состав: блок уже собран"
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview" and hub_defects.BLOCK_BUILT in state["warnings"], state
    # оператор убрал раздел сам: блок остаётся, подсказки больше нет
    raw = db.hub_defect(row["id"])["update_json"]
    assert act(web, pid, row["id"], "update-cancel", {"generation": state["generation"], "shown": hub_defects.text_hash(raw)}).status_code == 200
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_command_text = ? WHERE id = ?", ("Текст дефекта без блока.", row["id"]))
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    assert take(web) is None
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview" and state["new"]["command_text"] == "Текст дефекта без блока.", state
    assert hub_defects.WHERE_WITH_BLOCK not in state["warnings"] and hub_defects.IMPORT_BOUNDARY in hub_defects.description_lines(state["new"]["description"])


def test_finding_in_hub_only_builds_nothing(web):
    pid, row = where_row(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only(links=((510001, "SAST"), (510777, "SAST"))))
    assert take(web) is None, "блок не описал бы все находки дефекта в Hub"
    tab(web, pid)
    fresh = db.hub_defect(row["id"])
    state = hub_defects.update_state(fresh)
    assert any(hub_defects.BLOCK_COMPOSITION in w for w in state.get("warnings", [])), state
    assert not (json.loads(fresh["blank_json"] or "{}") or {}).get("built_from_model")
    assert hub_defects.defect_where.has_head(state["new"]["command_text"]), "без блока раздел остаётся"


def simple_prepare(monkeypatch, kind: str = "SAST") -> None:
    """Подготовка Push без решений по каждой находке: здесь проверяется шаг чтения, а не правила подготовки."""
    def prepare(_request, row, **_):
        return {"kind": kind, "summary": str(row["draft_summary"]), "command_text": str(row["draft_command_text"]),
                "targets": json.loads(row["targets_json"]), "number_keys": [], "fingerprint": "", "anchor": "",
                "draft_revision": row["draft_revision"], "draft_fields_json": row["draft_fields_json"]}
    monkeypatch.setattr(hub_defect_routes, "prepare_update", prepare)


def test_finding_unlinked_in_hub_builds_nothing(web, monkeypatch):
    simple_prepare(monkeypatch)
    pid, row = where_row(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET targets_json = ? WHERE id = ?",
                  (json.dumps(json.loads(row["targets_json"]) + [{"hub_id": "510002", "issue_id": 510002, "issue_type": "SAST"}]), row["id"]))
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    assert take(web) is None
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert any(hub_defects.BLOCK_COMPOSITION in w for w in state.get("warnings", [])), state


def test_many_findings_are_read_one_by_one_and_all_get_into_the_block(web, monkeypatch):
    simple_prepare(monkeypatch)
    pid, row = where_row(web)
    db = web.app.state.db
    ids = [510001 + i for i in range(26)]
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET targets_json = ? WHERE id = ?",
                  (json.dumps([{"hub_id": str(i), "issue_id": i, "issue_type": "SAST"} for i in ids]), row["id"]))
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only(links=tuple((i, "SAST") for i in ids)))
    for issue in ids:
        job = take(web)
        assert job is not None and f"issueId={issue}" in job["path"], issue
        deliver(web, job, 200, sast_model(issue))
    assert take(web) is None
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview" and state["new"]["description"].count("<h2>ID:") == 26, state


def test_failure_in_the_middle_builds_nothing_and_keeps_the_section(web, monkeypatch):
    simple_prepare(monkeypatch)
    pid, row = where_row(web)
    db = web.app.state.db
    ids = [510001, 510002, 510003]
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET targets_json = ? WHERE id = ?",
                  (json.dumps([{"hub_id": str(i), "issue_id": i, "issue_type": "SAST"} for i in ids]), row["id"]))
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only(links=tuple((i, "SAST") for i in ids)))
    deliver(web, take(web), 200, sast_model(510001))
    deliver(web, take(web), 500, {}, error="Hub 500")
    assert take(web) is None, "после сбоя чтений больше нет"
    tab(web, pid)
    fresh = db.hub_defect(row["id"])
    state = hub_defects.update_state(fresh)
    assert any("собрать не удалось" in w for w in state.get("warnings", [])), state
    assert not (json.loads(fresh["blank_json"] or "{}") or {}).get("built_from_model")
    assert hub_defects.defect_where.has_head(state["new"]["command_text"])


def test_old_worker_is_named_and_nothing_is_built(web):
    pid, row = where_row(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    deliver_raw(web, take(web), 0, error="путь не входит в белый список исполнителя", not_sent=True)
    tab(web, pid)
    fresh = db.hub_defect(row["id"])
    state = hub_defects.update_state(fresh)
    assert any(hub_defects.hub_template_model.OLD_WORKER in w for w in state.get("warnings", [])), state
    assert not (json.loads(fresh["blank_json"] or "{}") or {}).get("built_from_model")


def test_sca_defect_with_several_findings_gets_a_block(web, monkeypatch):
    simple_prepare(monkeypatch, "SCA")
    pid, row = where_row(web)
    db = web.app.state.db
    ids = [73001, 73002]
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET kind = 'SCA', targets_json = ? WHERE id = ?",
                  (json.dumps([{"hub_id": str(i), "issue_id": i, "issue_type": "SCA_S"} for i in ids]), row["id"]))
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only(links=tuple((i, "SCA_S") for i in ids)))
    first = take(web)
    assert "issueType=SCA_S" in first["path"] and "issueId=73001" in first["path"]
    deliver(web, first, 200, sca_model(73001))
    deliver(web, take(web), 200, sca_model(73002))
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview", state
    assert state["new"]["description"].count("Информация по цели сканирования") == 2


def test_new_defect_of_a_new_project_is_number_one_with_the_block_from_hub(web):
    """Новый проект: первый дефект – ID1, блок даёт сам Hub, отметка состава в Hub не уходит, сборщик не участвует."""
    pid, url = sast_ready(web)
    hello(web)
    row = to_preview(web, pid, url)
    assert row["number"] == 1 and row["summary"].startswith("ID1 - "), row["summary"]
    assert row["command_text"] and not hub_defects.defect_where.has_head(row["command_text"])
    assert create(web, pid, row["id"]).status_code == 200
    job = hub_job(web, body={"id": 901})
    assert job["method"] == "POST" and "_targets" not in job["body"]
    assert hub_defects.IMPORT_BOUNDARY in hub_defects.description_lines(job["body"]["description"])
    assert not (json.loads(web.app.state.db.hub_defect(row["id"])["blank_json"]) or {}).get("built_from_model")


@pytest.mark.parametrize("value, want", [
    ('<a href="https://a.example.org/advisory">Advisory</a>', ['<a href="https://a.example.org/advisory">Advisory</a>']),
    ("https://example.org/advisory?id=1,2", ["https://example.org/advisory?id=1,2"]),
    ("https://example.org/advisory?ids=1,", ["https://example.org/advisory?ids=1,"]),
    ("- https://a.example.org, - https://b.example.org", ["https://a.example.org", "https://b.example.org"]),
    ("https://a.example.org<br>https://b.example.org", ["https://a.example.org", "https://b.example.org"]),
    ("См. страницу производителя", ["См. страницу производителя"]),
    ("", []),
])
def test_references_keep_links_whole(value, want):
    assert builder._references(value) == "".join(f"<p>{line}</p>\n" for line in want)


def test_empty_model_does_not_take_the_section_away(web):
    pid, row = where_row(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    deliver(web, take(web), 200, {"issues": [{"id": 510001}]})
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview" and hub_defects.defect_where.has_head(state["new"]["command_text"]), state


def test_network_failure_is_not_called_an_old_worker(web):
    pid, row = where_row(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    deliver_raw(web, take(web), 0, error="соединение отклонено", not_sent=True)
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert any("соединение отклонено" in w for w in state.get("warnings", [])), state
    assert not any(hub_defects.hub_template_model.OLD_WORKER in w for w in state.get("warnings", []))


def test_saved_built_block_is_not_used_when_hub_composition_changed(web):
    pid, row = where_row(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    deliver(web, take(web), 200, sast_model())
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    raw = db.hub_defect(row["id"])["update_json"]
    assert act(web, pid, row["id"], "update-cancel", {"generation": state["generation"], "shown": hub_defects.text_hash(raw)}).status_code == 200
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only(links=((510001, "SAST"), (510777, "SAST"))))
    assert take(web) is None
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert any(hub_defects.BLOCK_COMPOSITION in w for w in state.get("warnings", [])), state
    assert not state.get("block_built") and "Где исправлять" in state["new"]["command_text"]
    assert hub_defects.IMPORT_BOUNDARY not in hub_defects.description_lines(state["new"].get("description") or "")


def test_block_stays_out_of_the_write_when_hub_composition_changes_before_put(web):
    pid, row = where_row(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only())
    deliver(web, take(web), 200, sast_model())
    tab(web, pid)
    assert put_click(web, pid, db.hub_defect(row["id"])).status_code == 200
    read_job(web, text_only(links=((510001, "SAST"), (510777, "SAST"))))
    assert take(web) is None, "записи нет: состав в Hub изменился после предпросмотра"
    assert phase(db, row["id"]) != "done"


def test_composition_too_long_for_a_blank_request_goes_to_the_model(web, monkeypatch):
    simple_prepare(monkeypatch)
    pid, row = lost_block(web)
    db = web.app.state.db
    # предел issueIds – 2000 знаков (ADR-0144): 154 двенадцатизначных номера дают 2001 знак, состав в одну заготовку не входит
    ids = [900000000001 + i for i in range(154)]
    assert len(",".join(map(str, ids))) == 2001
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET targets_json = ? WHERE id = ?",
                  (json.dumps([{"hub_id": str(i), "issue_id": i, "issue_type": "SAST"} for i in ids]), row["id"]))
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, text_only(links=tuple((i, "SAST") for i in ids)))
    for issue in ids:
        job = take(web)
        assert job is not None and job["path"].startswith("/templates/defects/model?") and f"issueId={issue}" in job["path"], issue
        deliver(web, job, 200, sast_model(issue))
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview" and state["block_built"] and state["new"]["description"].count("<h2>ID:") == 154, state

"""Адреса раздела «Компоненты»: сборка задания, комплект, загрузка ответа, решение, отчёты и отказы.

Шаблоны страниц делает фронтенд, поэтому здесь проверяются адреса, отчёты, комплект и то, что контекст
собран из настоящих данных. Отдельно проверяется, что прежние сценарии (разбор SAST и прежние ответы агента
по пакетам SCA) от нового раздела не меняются.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace


from component_research_fixtures import complete_research_row

from app.sca_contract import ANSWER_CONTRACT, VALIDATOR_VERSION
from hub_fixtures import SCA_ROWS, make_hub_xlsx
from test_web import BASE, ORIGIN, create_project, upload, web  # noqa: F401

AS_JSON = {**ORIGIN, "Accept": "application/json"}
AST_ID = "AST-2026-000101"
HUB_ID = "73001"
CODEBASE = "billing-core"


def project_with_sca(web) -> int:
    """Проект с выгрузкой, в которой есть находки SCA."""
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx", sast=(), sca=SCA_ROWS)).status_code == 303
    return pid


def build_task(web, pid: int) -> dict:
    response = web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN, follow_redirects=False)
    assert response.status_code == 303, response.text
    manifest = web.client.get(f"/projects/{pid}/components/task.json").json()
    return manifest


def kit_answer(manifest: dict, *, tamper: str = "") -> str:
    """Принятый ответ по строкам манифеста: одна применимая уязвимость у первой строки."""
    rows = []
    for index, source in enumerate(manifest["rows"]):
        vulnerable = index == 0
        rows.append({
            "input_ref": source["input_ref"], "ecosystem": source["ecosystem"], "component": source["component"],
            "current_version": source["version"],
            "identity_resolution": {"state": "resolved", "coordinates": source["component"], "candidates": [],
                                    "note": "", "source_refs": ["ev-1"]},
            "latest_stable_release": {"version": "9.0.99", "released_at": "2026-09-30", "note": "",
                                      "source_refs": ["ev-1"]},
            "update_status": "update_available",
            "support_status": {"state": "eol", "scope": "oss", "as_of": "2026-10-01", "note": "Ветка закрыта",
                               "source_refs": ["ev-1"]},
            "public_findings": ([{"id": "CVE-2099-10001", "aliases": ["GHSA-4r9m-6cqx-x5h2"], "applies": "yes",
                                  "description": "Обход аутентификации", "ranges": [{"introduced": "0",
                                                                                     "fixed": "9.0.99"}],
                                  "conditions": "", "fixed_versions": ["9.0.99"],
                                  "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N", "version": "3.1"},
                                  "source_refs": ["ev-1"]}] if vulnerable else []),
            "research_coverage": [{"source": "OSV", "purpose": "vulnerabilities",
                                   "query": {"ecosystem": source["ecosystem"],
                                             "coordinates": source["component"], "version": source["version"]},
                                   "source_refs": ["ev-1"], "checked_at": "2026-10-16", "status": "ok",
                                   "complete": True, "note": ""}],
            "package_advice": {"action": "update" if vulnerable else "no_action",
                               "target_version": "9.0.99" if vulnerable else None,
                               "compatibility_notes": "" if vulnerable else "Обновлений нет",
                               "remaining_risks": []},
            "evidence": [{"evidence_ref": "ev-1", "url": "https://advisories.example.invalid/CVE-2099-10001",
                          "checked_at": "2026-10-16", "source_type": "advisory", "justification": "Запись OSV",
                          "quote": "CVE-2099-10001", "level": "primary"}],
            "gaps": [], "package_status": "vulnerable" if vulnerable else "no_known_vulnerabilities",
        })
    rows = [complete_research_row(item) for item in rows]
    if tamper == "version":
        rows[0]["current_version"] = "0.0.0-чужая"
    if tamper == "ast":
        rows[0]["evidence"][0]["justification"] = AST_ID
    answer = {"contract": ANSWER_CONTRACT, "task_id": manifest["task_id"],
              "manifest_sha256": manifest["manifest_sha256"], "validator_version": VALIDATOR_VERSION,
              "generated_at": "2026-10-17T10:00:00Z", "row_count": len(rows), "rows": rows}
    return json.dumps(answer, ensure_ascii=False)


def upload_answer(web, pid: int, text: str, *, headers=ORIGIN):
    return web.client.post(f"/projects/{pid}/components/answers", headers=headers, follow_redirects=False,
                           files={"file": ("answer.json", text.encode("utf-8"), "application/json")})


def decide(web, pid: int, input_ref: str, *, headers=ORIGIN, **fields):
    """Решение из формы карточки: кроме полей человек отправляет то, что видел (отпечатки строки и ответа)."""
    db = web.app.state.db
    row = db.task_row(pid, input_ref)
    seen = db.research_row(pid, input_ref)
    data = {"action": "keep", "rationale": "Проверено в выпуске", "revision": 0,
            "expected_input_sig": (row or seen or {}).get("input_sig", ""),
            "expected_research_sig": (seen or {}).get("answer_sig", ""),
            "expected_research_revision": str(int((seen or {}).get("revision") or 0)), **fields}
    return web.client.post(f"/projects/{pid}/components/{input_ref}/decision", data=data, headers=headers,
                           follow_redirects=False)


# ============================================================== сборка задания и комплект

def test_task_build_is_idempotent_and_manifest_is_public(web):
    pid = project_with_sca(web)
    response = web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"].endswith("ok=task&n=2")
    manifest = build_task(web, pid)
    assert manifest["contract"] == "local-triage/sca-task/3" and manifest["row_count"] == 2
    body = json.dumps(manifest, ensure_ascii=False)
    for secret in (CODEBASE, "catalog-api", HUB_ID, AST_ID):
        assert secret not in body, secret
    # повторная сборка при том же составе не создаёт второе задание
    again = web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN, follow_redirects=False)
    assert again.headers["location"].endswith("ok=task_same&n=2")
    assert web.client.get(f"/projects/{pid}/components/task.json").json()["task_id"] == manifest["task_id"]


def test_task_without_sca_findings_is_not_created(web):
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "no-sca.xlsx", sast=(), sca=())).status_code == 303
    response = web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN, follow_redirects=False)
    assert response.status_code == 303 and "err=task_empty" in response.headers["location"]
    assert web.client.get(f"/projects/{pid}/components/task.json").status_code == 404


def test_kit_download_contains_the_contract_and_nothing_local(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    response = web.client.get(f"/projects/{pid}/components/task/{manifest['task_id']}.zip")
    assert response.status_code == 200 and response.headers["content-type"] == "application/zip"
    assert manifest["task_id"] in response.headers["content-disposition"]
    archive = zipfile.ZipFile(io.BytesIO(response.content))
    assert sorted(archive.namelist()) == ["answer.schema.json", "answer.template.json", "components.json",
                                          "manifest.json", "task.md", "validate.py"]
    assert archive.read("validate.py") == (Path(__file__).resolve().parent.parent / "app" / "sca_contract.py"
                                            ).read_bytes()
    everything = "\n".join(archive.read(name).decode("utf-8") for name in archive.namelist())
    for secret in (CODEBASE, "catalog-api", HUB_ID, AST_ID, "Demo Library"):
        assert secret not in everything, secret
    assert web.client.get(f"/projects/{pid}/components/task/нет-такого.zip").status_code == 404


def test_manifest_and_schema_are_available_for_the_agent(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    schema = web.client.get(f"/projects/{pid}/components/answer.schema.json").json()
    assert schema["x-contract"] == ANSWER_CONTRACT and schema["properties"]["rows"]["items"]["required"]
    assert manifest["limits"]["evidence_per_row"] >= 100


def test_old_task_is_not_handed_out_after_the_composition_changes(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    newer = [dict(row) for row in SCA_ROWS if row["Component name"] != "demo-xml"]
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "newer.xlsx", sast=(), sca=newer)).status_code == 303
    assert "err=task_empty" not in web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN,
                                                  follow_redirects=False).headers["location"]
    assert web.client.get(f"/projects/{pid}/components/task/{manifest['task_id']}.zip").status_code == 409
    fresh = web.client.get(f"/projects/{pid}/components/task.json").json()
    assert fresh["task_id"] != manifest["task_id"] and fresh["row_count"] == 1
    assert web.client.get(f"/projects/{pid}/components/task/{fresh['task_id']}.zip").status_code == 200


# ============================================================== загрузка ответа

def test_answer_is_accepted_and_kept_as_a_revision(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    response = upload_answer(web, pid, kit_answer(manifest))
    assert response.status_code == 303 and response.headers["location"].endswith("ok=answers&n=2")
    db=web.app.state.db
    before=db.research(pid)
    assert len(before)==2 and all(r['revision']==1 and len(r['answer_sig'])==64 for r in before.values())
    # повторный импорт того же ответа ничего не меняет
    again = upload_answer(web, pid, kit_answer(manifest))
    assert again.headers["location"].endswith("ok=answers_same&n=2")
    after=db.research(pid)
    assert {ref:(r['revision'],r['answer_sig']) for ref,r in after.items()}=={ref:(r['revision'],r['answer_sig']) for ref,r in before.items()}


def test_rejected_answer_is_not_saved_partly(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    response = upload_answer(web, pid, kit_answer(manifest, tamper="version"), headers=AS_JSON)
    assert response.status_code == 422
    report = response.json()
    assert report["ok"] is False and any(item["code"] == "SCA-C002" for item in report["errors"])
    assert any("current_version" in item["path"] for item in report["errors"])
    db = web.app.state.db
    assert db.research(pid) == {}
    # браузерный вариант отдаёт ту же страницу списка с отчётом об ошибках; сам шаблон делает фронтенд,
    # поэтому проверяется только то, что решение не записано и код ответа честный
    form = upload_answer(web, pid, kit_answer(manifest, tamper="ast"), headers={**ORIGIN, "Accept": "text/html"})
    assert form.status_code == 422 and 'SCA-A001' in form.text and db.research(pid) == {}


def test_answer_with_internal_ast_numbers_is_rejected(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    response = upload_answer(web, pid, kit_answer(manifest, tamper="ast"), headers=AS_JSON)
    assert response.status_code == 422
    assert any(item["code"] == "SCA-A001" for item in response.json()["errors"])


def test_answer_without_task_is_refused(web):
    pid = project_with_sca(web)
    response = upload_answer(web, pid, "{}", headers=AS_JSON)
    assert response.status_code == 409 and response.json()["ok"] is False


# ============================================================== решение человека

def test_decision_is_saved_without_research_and_does_not_change_facts(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    input_ref = manifest["rows"][0]["input_ref"]
    response = decide(web, pid, input_ref, action="investigate", rationale="Ждём подтверждение координат")
    assert response.status_code == 303 and response.headers["location"].endswith("?ok=decision")
    db = web.app.state.db
    decision = db.decision(pid, input_ref)
    assert decision["action"] == "investigate" and decision["revision"] == 1
    assert db.research(pid) == {}, "решение без исследования не создаёт фактов"


def test_decision_needs_a_reason_and_a_target_version(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    input_ref = manifest["rows"][0]["input_ref"]
    # проверяем пути отказа по JSON: страницу карточки рисует фронтенд, а текст ошибки отдаёт сервер
    assert decide(web, pid, input_ref, headers=AS_JSON, rationale="").status_code == 422
    answer = decide(web, pid, input_ref, headers=AS_JSON, action="update", rationale="Патч есть")
    assert answer.status_code == 422 and "версию" in answer.json()["detail"]
    assert decide(web, pid, input_ref, headers=AS_JSON, action="replace", rationale="Заброшен").status_code == 422
    ok = decide(web, pid, input_ref, action="update", rationale="Обновление в ветке", target_version="9.0.99")
    assert ok.status_code == 303
    assert web.app.state.db.decision(pid, input_ref)["target_version"] == "9.0.99"


def test_decision_from_an_outdated_page_is_refused(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    input_ref = manifest["rows"][0]["input_ref"]
    assert decide(web, pid, input_ref, action="keep", rationale="Пока оставить", revision=0).status_code == 303
    stale = decide(web, pid, input_ref, headers=AS_JSON, action="keep", rationale="Пока оставить", revision=0)
    assert stale.status_code == 409 and stale.json()["revision"] == 1
    assert web.app.state.db.decision(pid, input_ref)["revision"] == 1


def test_decision_binds_to_the_research_the_person_saw(web):
    """Решение относится к увиденному ответу, а не к тому, что пришло после."""
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    input_ref = manifest["rows"][0]["input_ref"]
    assert upload_answer(web, pid, kit_answer(manifest)).status_code == 303
    seen = web.app.state.db.research_row(pid, input_ref)
    # форма без отпечатков исследования (забыли скрытые поля) – решение не сохраняется
    blind = web.client.post(f"/projects/{pid}/components/{input_ref}/decision", headers=AS_JSON,
                            data={"action": "keep", "rationale": "Проверено", "revision": 0},
                            follow_redirects=False)
    assert blind.status_code in (409, 422) and web.app.state.db.decision(pid, input_ref) is None
    old_form = {"action": "keep", "rationale": "По старому ответу", "revision": 0,
                "expected_input_sig": seen["input_sig"], "expected_research_sig": seen["answer_sig"],
                "expected_research_revision": str(seen["revision"])}
    # ответ агента изменился после того, как страницу открыли
    changed = json.loads(kit_answer(manifest))
    changed["rows"][0]["public_findings"][0]["conditions"] = "Изменились условия применения"
    assert upload_answer(web, pid, json.dumps(changed, ensure_ascii=False)).status_code == 303
    late = web.client.post(f"/projects/{pid}/components/{input_ref}/decision", headers=AS_JSON, data=old_form,
                           follow_redirects=False)
    assert late.status_code == 409 and web.app.state.db.decision(pid, input_ref) is None
    # форма, открытая заново, сохраняется
    assert decide(web, pid, input_ref, headers=AS_JSON, action="keep", rationale="По новому ответу") \
        .status_code == 200
    assert web.app.state.db.decision(pid, input_ref)["research_sig"] == \
        web.app.state.db.research_row(pid, input_ref)["answer_sig"]


def test_only_new_check_dates_do_not_make_the_decision_stale(web):
    """Повторное чтение тех же источников в другой день не меняет фактов и не требует нового решения."""
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    input_ref = manifest["rows"][0]["input_ref"]
    assert upload_answer(web, pid, kit_answer(manifest)).status_code == 303
    assert decide(web, pid, input_ref, action="accept_risk", rationale="Функция недоступна").status_code == 303
    answer = json.loads(kit_answer(manifest))
    for row in answer["rows"]:
        for source in [*row["research_coverage"], *row["evidence"]]:
            source["checked_at"] = "2026-10-17"
    assert upload_answer(web, pid, json.dumps(answer, ensure_ascii=False)).status_code == 303
    db = web.app.state.db
    assert db.research_row(pid, input_ref)["answer_sig"] == db.decision(pid, input_ref)["research_sig"]
    report = web.client.get(f"/projects/{pid}/components/{input_ref}/report", headers=AS_JSON).json()
    assert report["components"][0]["decision_stale"] is False
    assert report["components"][0]["decision"]["action"] == "accept_risk"


def test_replacement_needs_only_the_name_of_the_new_package(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    input_ref = manifest["rows"][0]["input_ref"]
    response = decide(web, pid, input_ref, action="replace", rationale="Проект заброшен",
                      replacement_name="tomcat-embed-core", replacement_version="")
    assert response.status_code == 303
    stored = web.app.state.db.decision(pid, input_ref)
    assert (stored["action"], stored["replacement_name"], stored["replacement_version"]) == \
        ("replace", "tomcat-embed-core", "")


def test_decision_after_new_research_is_marked_stale(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    input_ref = manifest["rows"][0]["input_ref"]
    assert upload_answer(web, pid, kit_answer(manifest)).status_code == 303
    assert decide(web, pid, input_ref, action="keep", rationale="Пока оставить", revision=0).status_code == 303
    db = web.app.state.db
    assert db.decision(pid, input_ref)["research_sig"] == db.research_row(pid, input_ref)["answer_sig"]
    assert db.research(pid)[input_ref]["status"] == "vulnerable"
    old=db.research_row(pid,input_ref)
    changed=json.loads(kit_answer(manifest));changed['rows'][0]['public_findings'][0]['conditions']='Уточнённая конфигурация'
    assert upload_answer(web,pid,json.dumps(changed)).status_code==303
    assert db.research_row(pid,input_ref)['revision']==old['revision']+1
    assert db.decision(pid,input_ref)['research_sig']==old['answer_sig']
    report=web.client.get(f'/projects/{pid}/components/{input_ref}/report',headers=AS_JSON).json()['components'][0]
    assert report['decision_stale'] and report['decision']['action']=='keep'
    assert report['public_findings'][0]['id']=='CVE-2099-10001'


def test_answer_can_be_pasted_and_invalid_text_is_rejected(web):
    pid=project_with_sca(web);manifest=build_task(web,pid)
    response=web.client.post(f'/projects/{pid}/components/answers',headers=ORIGIN,data={'text':kit_answer(manifest)},follow_redirects=False)
    assert response.status_code==303 and len(web.app.state.db.research(pid))==2
    before=web.app.state.db.research(pid)
    bad=web.client.post(f'/projects/{pid}/components/answers',headers=AS_JSON,data={'text':'{"invalid":true}'})
    assert bad.status_code==422 and web.app.state.db.research(pid)==before


def test_unknown_input_ref_is_not_found(web):
    pid = project_with_sca(web)
    assert decide(web, pid, "maven:0000000000000000").status_code == 404
    assert decide(web, pid, "не-строка").status_code == 404


# ============================================================== отчёты

def test_reports_hold_public_facts_and_no_local_data(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    input_ref = manifest["rows"][0]["input_ref"]
    assert upload_answer(web, pid, kit_answer(manifest)).status_code == 303
    assert decide(web, pid, input_ref, action="update", rationale="Обновление в ветке", target_version="9.0.99",
                  revision=0).status_code == 303
    for url in (f"/projects/{pid}/components/report", f"/projects/{pid}/components/{input_ref}/report"):
        response = web.client.get(url, headers=AS_JSON)
        assert response.status_code == 200, response.text
        document = response.json()
        assert document["contract"] == "local-triage/sca-report/2"
        body = json.dumps(document, ensure_ascii=False)
        for secret in (CODEBASE, "catalog-api", HUB_ID, AST_ID):
            assert secret not in body, secret
    one = web.client.get(f"/projects/{pid}/components/{input_ref}/report", headers=AS_JSON).json()
    assert len(one["components"]) == 1 and one["components"][0]["decision"]["action"] == "update"
    assert one["components"][0]["public_findings"][0]["id"] == "CVE-2099-10001"
    assert one["components"][0]["identity"]["coordinates"] == "org.example:" + manifest["rows"][0]["component"]
    text = web.client.get(f"/projects/{pid}/components/{input_ref}/report?format=md").text
    assert "Обновление в ветке" in text and manifest["rows"][0]["component"] in text
    assert CODEBASE not in text and AST_ID not in text


def test_report_of_a_row_without_research_is_not_empty_json(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    response = web.client.get(f"/projects/{pid}/components/{manifest['rows'][1]['input_ref']}/report",
                              headers=AS_JSON)
    assert response.status_code == 404


# ============================================================== контекст страниц

def test_list_context_is_built_from_stored_data(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    assert upload_answer(web, pid, kit_answer(manifest)).status_code == 303
    request = SimpleNamespace(app=web.app,
                              query_params={})
    context = __import__("app.routes.components", fromlist=["x"]).list_context(
        request, web.app.state.db.get_project(pid))
    assert context["total"] == 2 and context["shown"] == 2 and context["page"] == 1 and context["pages"] == 1
    assert context["task"]["row_count"] == 2 and context["task"]["researched"] == 2
    assert context["summary"] == {"total": 2, "vulnerable": 1, "no_known_vulnerabilities": 1, "incomplete": 0,
                                  "identity_unresolved": 0, "unresearched": 0, "decided": 0, "stale": 0,
                                  "with_gaps": 0, "support_unknown": 0, "in_defect": 0}
    first = context["rows"][0]
    assert first["status"] == "vulnerable" and first["status_label"] == "уязвим" and first["decided"] is False
    assert first["task_current"] and first["coverage"]["complete"] and first["findings_total"] == 1
    assert set(context["labels"]) >= {"status", "decision", "gap", "level", "task_state"}
    # ни номеров находок, ни названий кодовых баз в списке нет
    body = json.dumps(context["rows"], ensure_ascii=False, default=str)
    for secret in (CODEBASE, HUB_ID, AST_ID):
        assert secret not in body, secret


def test_detail_context_carries_facts_evidence_and_decision(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    input_ref = manifest["rows"][0]["input_ref"]
    assert upload_answer(web, pid, kit_answer(manifest)).status_code == 303
    assert decide(web, pid, input_ref, action="keep", rationale="Пока оставить", revision=0).status_code == 303
    request = SimpleNamespace(app=web.app, query_params={})
    module = __import__("app.routes.components", fromlist=["x"])
    context = module.detail_context(request, web.app.state.db.get_project(pid), input_ref)
    assert context["row"]["status"] == "vulnerable" and context["row"]["revision"] == 1
    assert context["findings"][0]["sources"][0]["url"].startswith("https://advisories.example.invalid/")
    assert context["coverage"][0]["status_label"] == "проверен"
    assert context["identity"]["coordinates"] == "org.example:" + manifest["rows"][0]["component"]
    assert context["decision"]["action"] == "keep" and context["revision"] == 1 and not context["decision_stale"]
    assert context["form"]["action"] == "keep" and context["report_urls"]["md"].endswith("format=md")
    assert [item["revision"] for item in context["history"]] == [1]
    # решение без ответа агента: фактов нет, решение есть, и это сказано прямо
    empty_pid = project_with_sca(web)
    empty_manifest = build_task(web, empty_pid)
    empty_ref = empty_manifest["rows"][0]["input_ref"]
    assert decide(web, empty_pid, empty_ref, action="investigate", rationale="Ждём подтверждение",
                  revision=0).status_code == 303
    empty = module.detail_context(request, web.app.state.db.get_project(empty_pid), empty_ref)
    assert empty["row"]["researched"] is False and not empty["findings"]
    assert empty["decision"]["action"] == "investigate" and "без ответа агента" in empty["decision_note"]


# ============================================================== прежние сценарии не тронуты

def test_old_sca_answers_and_reviews_are_untouched_by_the_new_section(web):
    """Новый раздел не читает и не меняет прежние ответы агента и отметки разбора."""
    pid = project_with_sca(web)
    db = web.app.state.db
    answer = {"component": "example-parser", "version": "1.4.2", "conclusion": "update", "recommended_version": "1.4.9",
              "ids": {}, "links": [], "explanation": "Обновление", "vulns": []}
    db.save_sca_answers(pid, "Прежний агент", [answer])
    assert len(db.sca_answers(pid)) == 1
    build_task(web, pid)
    assert upload_answer(web, pid, kit_answer(build_task(web, pid))).status_code == 303
    old = db.sca_answers(pid)
    assert len(old) == 1 and old[0]["source"] == "Прежний агент" and old[0]["recommended_version"] == "1.4.9"
    assert db.ast_map({"AST-2026-000101"}) == {}
    # прежняя страница SCA и прежняя выгрузка продолжают работать
    page = web.client.get(f"/projects/{pid}/sca")
    assert page.status_code == 200 and "example-parser" in page.text

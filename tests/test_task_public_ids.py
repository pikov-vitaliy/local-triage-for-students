"""Публичные идентификаторы уязвимостей в задании на исследование (план 0.9.13, B2, контракт К8): только CVE, GHSA и БДУ из выгрузки, нормализованные, без повторов, не больше 64;
внутренние номера анализатора (AST-…) в задание не попадают. Контракт задания – /3, контракт ответа и валидатор –
прежние; подпись пакета от контракта задания не зависит – решения по компонентам после обновления действуют; задание
прежнего контракта не переиспользуется даже при том же составе. Данные выдуманы."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app import sca_research as research  # noqa: E402
from app.sca_contract import TASK_CONTRACT  # noqa: E402
from hub_fixtures import SCA_ROWS, make_hub_xlsx  # noqa: E402
from test_sca_research_routes import AST_ID, build_task, decide, kit_answer, project_with_sca, upload_answer  # noqa: E402
from test_web import ORIGIN, create_project, upload, web  # noqa: E402, F401


def test_only_public_ids_normalized_and_capped():
    raw = ["cve-2024-1234", "CVE-2024-1234", "AST-2026-000101", "ghsa-4R9M-6CQX-X5H2", "BDU:2024-00001",
           "bdu:2024-00001", "CVE-2024-12345678", "CVE-24-1", "GHSA-xxxx-yyyy-zzzz", "", None, "GHSA-4r9m-6cqx"]
    assert research.public_vulnerability_ids(raw) == ["BDU:2024-00001", "CVE-2024-1234", "CVE-2024-12345678",
                                                      "GHSA-4r9m-6cqx-x5h2"]
    many = [f"CVE-2020-{n:04d}" for n in range(1, 100)]
    assert len(research.public_vulnerability_ids(many)) == research.PUBLIC_ID_LIMIT


def test_task_rows_carry_public_ids_but_never_ast():
    rows, _ = research.task_rows([
        {"ecosystem": "maven", "component": "org.example:lib", "version": "1.0.0",
         "cve": ["CVE-2099-10001"], "vuln_ids": ["AST-2026-000101", "GHSA-4r9m-6cqx-x5h2"], "findings": 2,
         "codebases": ["a"]},
        {"ecosystem": "npm", "component": "@example/parser", "version": "7.0.0", "cve": [],
         "vuln_ids": ["AST-2026-000103"], "findings": 1, "codebases": ["a"]},
    ])
    by_name = {r["name"]: r for r in rows}
    assert by_name["org.example:lib"]["vulnerability_ids"] == ["CVE-2099-10001", "GHSA-4r9m-6cqx-x5h2"]
    assert by_name["@example/parser"]["vulnerability_ids"] == []
    kit = json.dumps([research.row_text(r) for r in rows], ensure_ascii=False)
    manifest = json.dumps(research.manifest({"task_id": "t-1"}, rows), ensure_ascii=False)
    text = research.task_text({"task_id": "t-1"}, rows)
    assert "AST-" not in kit and "AST-" not in manifest
    assert "CVE-2099-10001" in kit and "CVE-2099-10001" in manifest
    assert "vulnerability_ids" in text and "подсказка" in text
    assert research.CONTRACT == "local-triage/sca-task/3" and manifest.count('"local-triage/sca-task/3"') == 1


def test_package_signature_does_not_depend_on_the_task_contract():
    """Подпись пакета – от прежней основы: подъём контракта задания пакеты не переименовывает (иначе решения по
    компонентам стали бы «устаревшими» после обновления)."""
    rows, _ = research.task_rows([{"ecosystem": "maven", "component": "org.example:lib", "version": "1.0.0",
                                   "cve": ["CVE-2099-10001"], "findings": 1, "codebases": ["a"]}])
    expected = research.input_sig(TASK_CONTRACT, "maven", "org.example:lib", "1.0.0", rows[0]["identity_kind"])
    assert rows[0]["input_sig"] == expected and research.IDENTITY_CONTRACT == "local-triage/sca-task/2"


def test_saved_task_stores_ids_and_old_contract_task_is_not_reused(web):  # noqa: F811
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    db = web.app.state.db
    task = db.current_task(pid)
    assert task["contract"] == "local-triage/sca-task/3"
    rows = {r["name"]: r for r in db.task_rows(task["id"])}
    # example-parser: в выгрузке AST-… и CVE-2099-10001; demo-xml – только AST-…
    assert json.loads(rows["example-parser"]["vulnerability_ids"]) == ["CVE-2099-10001"]
    assert json.loads(rows["demo-xml"]["vulnerability_ids"]) == []
    body = json.dumps(manifest, ensure_ascii=False)
    assert AST_ID not in body and "CVE-2099-10001" in body
    # ответ по заданию /3 принимается прежним валидатором; решение по строке действует
    assert upload_answer(web, pid, kit_answer(manifest)).status_code == 303
    first = manifest["rows"][0]["input_ref"]
    assert decide(web, pid, first).status_code == 303
    # задание прежнего контракта с тем же составом – не переиспользуется, создаётся /3
    with db._tx() as c:
        c.execute("UPDATE sca2_tasks SET contract = ? WHERE id = ?", ("local-triage/sca-task/2", task["id"]))
    r = web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN, follow_redirects=False)
    assert r.headers["location"].endswith(f"ok=task&n={manifest['row_count']}")
    fresh = db.current_task(pid)
    assert fresh["id"] != task["id"] and fresh["contract"] == "local-triage/sca-task/3"
    # прежний ответ (с task_id устаревшего задания) больше не принимается
    stale = upload_answer(web, pid, kit_answer(manifest), headers={**ORIGIN, "Accept": "application/json"})
    assert stale.status_code in (409, 422), stale.status_code  # валидатор: task_id не совпадает с действующим


def test_task_without_public_ids_is_still_rebuilt_for_the_new_contract(web):  # noqa: F811
    """Состав без единого публичного идентификатора: отпечаток состава с пустыми списками совпадает с прежним
    заданием /2 – оно всё равно заменяется заданием /3 (ревью плана, К8)."""
    pid = create_project(web.client)
    rows = [dict(SCA_ROWS[2])]  # demo-xml – только AST-…
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx", sast=(), sca=rows)).status_code == 303
    db = web.app.state.db
    build_task(web, pid)
    task = db.current_task(pid)
    with db._tx() as c:
        c.execute("UPDATE sca2_tasks SET contract = ? WHERE id = ?", ("local-triage/sca-task/2", task["id"]))
    r = web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN, follow_redirects=False)
    assert r.headers["location"].endswith("ok=task&n=1")
    assert db.current_task(pid)["id"] != task["id"]

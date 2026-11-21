"""LTA-003 (четвёртая проверка): ключ номера дефекта SCA кодирует тройку (экосистема, имя, версия) однозначно; шаг 12;
сообщения об отказе копирования для находки, которой нет в выгрузке."""

from __future__ import annotations

import itertools
from pathlib import Path


from app import defect
from app.db import Database
from test_audit_lta003 import load, sca_finding
from test_sca import form_fields
from test_web import ORIGIN, create_project, web  # noqa: F401

AS_JSON = {**ORIGIN, "Accept": "application/json"}


# ============================================================================ кодирование ключа

def test_audit_example_triples_do_not_collide():
    """Пример проверки: ("npm", "a@b", "c") и ("npm", "a", "b@c") давали один ключ."""
    assert defect.defect_key_sca("a@b", "c", "npm") != defect.defect_key_sca("a", "b@c", "npm")


def test_encoding_is_injective_for_awkward_values():
    parts = ["", "a", "a@b", "b@c", "c", "@", "|", "a|b", '"', "\\", ",", "[", "]", '","', "$", "Ж", "x@1|npm", "1.0@"]
    triples = list(itertools.product(parts, repeat=3))
    keys = {defect.defect_key_sca(name, version, eco) for eco, name, version in triples}
    assert len(keys) == len(triples), "разные тройки – разные ключи"
    assert all(key.startswith("sca:v3|") and "\n" not in key for key in keys)


def test_current_key_is_ascii_json_array_and_never_a_historical_key():
    key = defect.defect_key_sca("Ж|", "1", "npm")
    assert key == 'sca:v3|["npm","\\u0416|","1"]'
    assert not key.startswith(("sca:v2|", "sca:npm|"))


# ============================================================================ шаг 12

def numbers(path: Path, pid: int) -> dict[str, int]:
    db = Database(path)
    try:
        return {r["defect_key"]: r["number"] for r in db._all("SELECT defect_key, number FROM defects WHERE project_id = ?", (pid,))}
    finally:
        db.close()


# ============================================================================ HTTP: номера двух пакетов не склеиваются

def test_two_awkward_packages_get_their_own_defect_numbers(web):  # noqa: F811
    pid = create_project(web.client)
    db = web.app.state.db
    load(db, pid, [sca_finding("1", "npm", "CVE-2099-0001", component="a@b", version="c"),
                   sca_finding("2", "npm", "CVE-2099-0002", component="a", version="b@c")])
    got = {}
    for hub_id in ("1", "2"):
        row = db.get_finding_by_hub_id(pid, hub_id)
        url = f"/projects/{pid}/sca/findings/{row['id']}"
        saved = web.client.post(f"{url}/review", headers=AS_JSON, data={
            **form_fields(web.client.get(url).text), "decision": "disagree", "final_verdict": "true_positive",
            "comment": f"Решение {hub_id}.", "reviewed": "1", "action": "save"})
        assert saved.status_code == 200, saved.text
        from test_sca import sca_text_ready
        sca_text_ready(web, url)  # текст набора дефекта (ADR-0091)
        issued = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "", "confirm": "1"})
        assert issued.status_code == 200, issued.text
        got[hub_id] = issued.json()["number"]
        assert ("CVE-2099-0001" if hub_id == "1" else "CVE-2099-0002") in issued.json()["body"]
    assert got["1"] != got["2"], "номера разных пакетов не склеились"
    assert db.defect_number(pid, defect.defect_key_sca("a@b", "c", "npm")) == got["1"]
    assert db.defect_number(pid, defect.defect_key_sca("a", "b@c", "npm")) == got["2"]


# ============================================================================ сообщения об отказе копирования

def card_url(db, pid: int, hub_id: str) -> str:
    return f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, hub_id)['id']}"


def vanish(db, pid: int) -> None:
    load(db, pid, [sca_finding("9", "maven", "CVE-2099-0009", component="other", version="1")])


def copy_post(web, url: str, fields: dict, comment: str):
    return web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "decision": "disagree", "final_verdict": "false_positive", "comment": comment, "reviewed": "1",
        "action": "copy"})


def test_copy_of_a_vanished_finding_does_not_claim_the_input_was_saved(web):  # noqa: F811
    pid = create_project(web.client)
    db = web.app.state.db
    load(db, pid, [sca_finding("1", "npm", "CVE-2099-0001"), sca_finding("9", "maven", "CVE-2099-0009", component="other",
                                                                          version="1")])
    url = card_url(db, pid, "1")
    fields = form_fields(web.client.get(url).text)
    vanish(db, pid)  # находки «1» больше нет в выгрузке
    assert db.get_review(pid, "1") is None
    r = copy_post(web, url, fields, "Введённый комментарий.")
    assert r.status_code == 400 and r.json()["reason"] == "rejected"
    detail = r.json()["detail"]
    assert "введённое в форме не сохранено" in detail and "сохранены как история" not in detail
    assert "Раньше сохранённого решения по этой находке нет" in detail
    assert db.get_review(pid, "1") is None, "запрос ничего не записал"


def test_copy_of_a_vanished_finding_with_a_prior_decision_names_the_prior_history(web):  # noqa: F811
    pid = create_project(web.client)
    db = web.app.state.db
    load(db, pid, [sca_finding("1", "npm", "CVE-2099-0001"), sca_finding("9", "maven", "CVE-2099-0009", component="other",
                                                                          version="1")])
    url = card_url(db, pid, "1")
    db.save_review(pid, "1", decision="disagree", final_verdict="true_positive", final_comment="Прежний текст.",
                   reviewed=False)
    fields = form_fields(web.client.get(url).text)
    vanish(db, pid)
    r = copy_post(web, url, fields, "Новый текст, который не сохранится.")
    detail = r.json()["detail"]
    assert "введённое в форме не сохранено" in detail and "сохранённое раньше, осталось в истории" in detail
    assert db.get_review(pid, "1")["final_comment"] == "Прежний текст."


def test_sast_copy_of_a_vanished_finding_uses_the_same_honest_message(web):  # noqa: F811
    from test_audit_lta001 import reimport
    from test_defect import hidden_fields, save_sast
    from test_web import prepared, start_run, wait_run

    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    url, _ = save_sast(web, pid, "510001", "disagree", "false_positive", "Прежнее обоснование.")
    import re

    card = web.client.get(url).text
    fields = {**hidden_fields(card), "review_revision": re.search(r'name="review_revision" value="(\d+)"', card).group(1)}
    reimport(web, pid, drop={"510001"})
    r = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "decision": "disagree", "final_verdict": "false_positive", "comment": "Новое, не сохранится.",
        "reviewed": "1", "action": "copy"})
    detail = r.json()["detail"]
    assert r.status_code == 400 and "введённое в форме не сохранено" in detail and "сохранены как история" not in detail
    assert "сохранённое раньше, осталось в истории" in detail
    assert web.app.state.db.get_review(pid, "510001")["final_comment"] == "Прежнее обоснование."

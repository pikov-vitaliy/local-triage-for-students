"""Бэклог 95: открыт клон одной кодовой базы, у проекта ровно одна кодовая база без папки – кнопка «Сделать папку выше папкой
проекта и назначить этот клон кодовой базе». Одна транзакция с контрактом set_repos_dir и set_codebase_folder (срезы, ревизии
и отвязки, снятие «Проверено», manual = 1); прежнее состояние проверяется; ошибка второй записи откатывает обе. Данные выдуманы."""

from __future__ import annotations

import pytest

from app.models import Finding
from test_hub_status_routes import project
from test_web import ORIGIN, web  # noqa: F401


def seeded(web, codebases=("billing",)) -> int:
    root = web.settings.repos_root
    (root / "team" / "billing-clone" / ".git").mkdir(parents=True)
    findings = [Finding(hub_id=str(600 + n), kind="SAST", rule="r", codebase=cb, file="a.py", line=3, snippet="x",
                        severity="high") for n, cb in enumerate(codebases)]
    return project(web, findings)


def test_offer_shown_only_for_single_free_codebase(web):  # noqa: F811
    pid = seeded(web)
    page = web.client.get(f"/projects/{pid}/folders?path=team/billing-clone").text
    assert 'id="clone-offer"' in page and "назначить этот клон кодовой базе «billing»" in page
    assert "Таблица соответствия кодовых баз и папок" in page
    other = project(web, [Finding(hub_id="700", kind="SAST", rule="r", codebase="a", file="a.py", line=3, snippet="x",
                                  severity="high"),
                          Finding(hub_id="701", kind="SAST", rule="r", codebase="b", file="a.py", line=3, snippet="x",
                                  severity="high")])
    assert 'id="clone-offer"' not in web.client.get(f"/projects/{other}/folders?path=team/billing-clone").text


def test_success_applies_both_contracts(web):  # noqa: F811
    pid = seeded(web)
    db = web.app.state.db
    db.save_case(pid, "600", "h-600", {"status": "ok", "lines": ["x"]}, None)
    db.save_review(pid, "600", decision="agree", final_verdict="false_positive", final_comment="Проверено.", reviewed=True)
    r = web.client.post(f"/projects/{pid}/repos-clone", headers=ORIGIN, follow_redirects=False,
                        data={"clone": "team/billing-clone", "codebase": "billing", "expect_repos_dir": "", "confirm_reset": "1",
                              "expect_reset": "1:1"})
    assert r.status_code == 303, r.text
    assert db.get_project(pid)["repos_dir"] == "team"
    mapped = db.get_codebase_map(pid)["billing"]
    assert mapped["folder"] == "billing-clone" and int(mapped["manual"]) == 1
    assert db.get_case(pid, "600") is None, "срез прежней папки удалён"
    review = db.get_review(pid, "600")
    assert not review["reviewed"] and review["decision"] == "agree", "решение осталось, «Проверено» снято"


def test_stale_state_and_failure_change_nothing(web, monkeypatch):  # noqa: F811
    pid = seeded(web)
    db = web.app.state.db
    stale = web.client.post(f"/projects/{pid}/repos-clone", headers=ORIGIN, follow_redirects=False,
                            data={"clone": "team/billing-clone", "codebase": "billing", "expect_repos_dir": "other",
                                  "confirm_reset": "1", "expect_reset": "0:0"})
    assert stale.status_code == 409 and db.get_project(pid)["repos_dir"] == ""

    def broken(*args, **kwargs):
        raise RuntimeError("сбой второй записи")

    monkeypatch.setattr(type(db), "_set_codebase_folder_in", broken)
    with pytest.raises(RuntimeError):
        db.set_repos_dir_and_folder(pid, "team", "billing", "billing-clone", "")
    assert db.get_project(pid)["repos_dir"] == "", "первая запись откатилась"
    assert not (db.get_codebase_map(pid).get("billing") or {}).get("folder")


def test_same_root_still_needs_confirmation_with_counts(web):  # noqa: F811
    """Папка проекта та же, а у назначаемой кодовой базы есть срез и «Проверено»: без подтверждения – 409 с ценой обоих
    действий, ничего не меняется (ревью Codex dev18, группа 3, блокирующая находка)."""
    pid = seeded(web)
    db = web.app.state.db
    db.set_repos_dir(pid, "team")
    db.save_case(pid, "600", "h-600", {"status": "ok", "lines": ["x"]}, None)
    db.save_review(pid, "600", decision="agree", final_verdict="false_positive", final_comment="Проверено.", reviewed=True)
    page = web.client.get(f"/projects/{pid}/folders?path=team/billing-clone").text
    assert "Будет удалено срезов кода: 1; отметок «Проверено»: 1." in page
    data = {"clone": "team/billing-clone", "codebase": "billing", "expect_repos_dir": "team", "confirm_reset": "0"}
    r = web.client.post(f"/projects/{pid}/repos-clone", headers=ORIGIN, follow_redirects=False, data=data)
    assert r.status_code == 409 and "Будет удалено срезов кода: 1; отметок «Проверено»: 1." in r.text
    assert db.get_case(pid, "600") is not None and db.get_review(pid, "600")["reviewed"]
    assert not (db.get_codebase_map(pid).get("billing") or {}).get("folder")
    r = web.client.post(f"/projects/{pid}/repos-clone", headers=ORIGIN, follow_redirects=False,
                        data={**data, "confirm_reset": "1", "expect_reset": "1:1"})
    assert r.status_code == 303, r.text
    assert db.get_case(pid, "600") is None and not db.get_review(pid, "600")["reviewed"]


def test_reviewed_without_slice_needs_confirmation(web):  # noqa: F811
    """«Проверено» без сохранённого среза тоже снимается назначением – без подтверждения 409, ничего не меняется
    (ревью Kimi, выпуск dev18, блокирующая находка)."""
    pid = seeded(web)
    db = web.app.state.db
    db.set_repos_dir(pid, "team")
    db.save_review(pid, "600", decision="agree", final_verdict="false_positive", final_comment="Проверено.", reviewed=True)
    assert db.get_case(pid, "600") is None
    page = web.client.get(f"/projects/{pid}/folders?path=team/billing-clone").text
    assert "Будет удалено срезов кода: 0; отметок «Проверено»: 1." in page and 'value="0:1"' in page
    data = {"clone": "team/billing-clone", "codebase": "billing", "expect_repos_dir": "team", "confirm_reset": "0"}
    r = web.client.post(f"/projects/{pid}/repos-clone", headers=ORIGIN, follow_redirects=False, data=data)
    assert r.status_code == 409 and "отметок «Проверено»: 1." in r.text
    assert db.get_review(pid, "600")["reviewed"] and not (db.get_codebase_map(pid).get("billing") or {}).get("folder")


def test_cost_changed_after_warning_changes_nothing(web):  # noqa: F811
    """Показана цена «0:0», а до подтверждения другая вкладка сохранила срез и отметку: запись отказывает, ничего не
    удаляется; подтверждение без показанной цены – тоже отказ (ревью Kimi, выпуск dev18)."""
    pid = seeded(web)
    db = web.app.state.db
    db.set_repos_dir(pid, "team")
    page = web.client.get(f"/projects/{pid}/folders?path=team/billing-clone").text
    assert 'name="expect_reset" value="0:0"' in page and "Будет удалено" not in page
    db.save_case(pid, "600", "h-600", {"status": "ok", "lines": ["x"]}, None)
    db.save_review(pid, "600", decision="agree", final_verdict="false_positive", final_comment="Проверено.", reviewed=True)
    data = {"clone": "team/billing-clone", "codebase": "billing", "expect_repos_dir": "team", "confirm_reset": "1",
            "expect_reset": "0:0"}
    r = web.client.post(f"/projects/{pid}/repos-clone", headers=ORIGIN, follow_redirects=False, data=data)
    assert r.status_code == 409, r.text
    assert db.get_case(pid, "600") is not None and db.get_review(pid, "600")["reviewed"]
    assert not (db.get_codebase_map(pid).get("billing") or {}).get("folder")
    r = web.client.post(f"/projects/{pid}/repos-clone", headers=ORIGIN, follow_redirects=False,
                        data={k: v for k, v in data.items() if k != "expect_reset"})
    assert r.status_code == 409 and db.get_case(pid, "600") is not None
    with pytest.raises(ValueError):
        db.set_repos_dir_and_folder(pid, "team", "billing", "billing-clone", "team", (0, 0))
    assert db.get_case(pid, "600") is not None

"""Шаг 5 плана dev17 в браузере (п. 4.6): после перехода идентичности пакетов – пометки на карточке находки SCA,
прежний адрес карточки компонента ведёт на новую, где виден архив прежней тройки; страница «Отчёт перехода» –
только чтение. Переход записан в базу демо-проекта напрямую (как после «Принять состояние Hub»); данные выдуманы."""

from __future__ import annotations

import json
import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from app.db import Database, dumps  # noqa: E402
from app.ecosystem import canon_ecosystem  # noqa: E402
from app.sca_contract import input_ref  # noqa: E402
from e2e_support import create_demo  # noqa: E402

pytestmark = pytest.mark.e2e


def moved_package(app_server, pid: int) -> tuple[int, str, str]:
    """Первая находка SCA демо-проекта получает идентичность по Hub (координаты Maven) – как после перехода; в архиве
    – отметка переноса группы и снятая ревизия исследования прежней тройки. Возвращает (находка, прежний, новый адрес)."""
    db = Database(app_server.data_dir / "triage.db")
    try:
        row = db._one("SELECT id, data_json FROM findings WHERE project_id = ? AND kind = 'SCA' ORDER BY id LIMIT 1",
                      (pid,))
        data = json.loads(row["data_json"])
        old = (canon_ecosystem(data.get("build_type")), str(data.get("component") or ""), str(data.get("version") or ""))
        new = ("maven", f"org.demo:{old[1]}", old[2])
        old_ref, new_ref = input_ref(*old), input_ref(*new)
        same = [r["id"] for r in db._all("SELECT id, data_json FROM findings WHERE project_id = ? AND kind = 'SCA'",
                                         (pid,))
                if (lambda d: (canon_ecosystem(d.get("build_type")), str(d.get("component") or ""),
                               str(d.get("version") or "")))(json.loads(r["data_json"])) == old]
        with db._tx() as c:
            for fid in same:  # вся группа прежней тройки – иначе прежний адрес остаётся живым
                c.execute("UPDATE findings SET pkg_ecosystem = ?, pkg_name = ?, pkg_source = 'hub', pkg_note = '',"
                          " pkg_scope = 'h|7', pkg_rev = 1 WHERE id = ?", (new[0], new[1], fid))
            c.execute("UPDATE projects SET identity_rev = 1 WHERE id = ?", (pid,))
            stamp = "2026-11-10T09:00:00+00:00"
            c.execute("INSERT INTO sca_identity_archive(project_id, archived_at, source_table, key_json, row_json,"
                      " moved_to_ref, reason) VALUES (?, ?, 'group', ?, ?, ?, 'перенос (изменение)')",
                      (pid, stamp, dumps({"input_ref": old_ref}), dumps({"triple": list(old)}), new_ref))
            c.execute("INSERT INTO sca_identity_archive(project_id, archived_at, source_table, key_json, row_json,"
                      " reason) VALUES (?, ?, 'sca2_research', ?, ?, 'перенос (изменение): исследование не доказывает"
                      " новую тройку')",
                      (pid, stamp, dumps({"input_ref": old_ref, "revision": 1}),
                       dumps({"input_ref": old_ref, "revision": 1, "status": "complete",
                              "imported_at": "2026-11-09T10:00:00+00:00"})))
        return row["id"], old_ref, new_ref
    finally:
        db.close()


def test_identity_transition_pages(ui, app_server):
    page, watch = ui
    pid = create_demo(page)
    finding, old_ref, new_ref = moved_package(app_server, pid)

    page.goto(f"/projects/{pid}/sca/findings/{finding}")
    expect(page.locator("#identity-marks")).to_contain_text("по Hub")

    page.goto(f"/projects/{pid}/components/{old_ref}")
    expect(page).to_have_url(re.compile(rf"/projects/{pid}/components/{re.escape(new_ref)}$"))
    archive = page.locator("#identity-archive")
    expect(archive).to_contain_text("Архив перехода идентичности: 1")
    archive.locator("summary").click()
    expect(archive).to_contain_text("исследование")
    expect(archive).to_contain_text("исследование не доказывает новую тройку")

    page.goto(f"/projects/{pid}/components")
    page.locator("#identity-report-link").click()
    expect(page).to_have_url(re.compile(rf"/projects/{pid}/identity-report$"))
    expect(page.locator("#identity-report-groups")).to_contain_text("Перенесено групп: 1.")
    expect(page.locator("#identity-report-archive-table")).to_contain_text("исследования компонента")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert not watch.problems(), watch.problems()

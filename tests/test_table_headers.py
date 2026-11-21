"""Заголовки столбцов таблиц – `<th scope="col">` (KIMI-13, бэклог 45): у каждого `<th>` в шаблонах есть scope, а
журнал прогонов, паспорт прогона (таблица ресурсов) и пакетное решение компонентов отдают заголовки столбцов со
scope="col". Данные выдуманы."""

from __future__ import annotations

import json
import re
from pathlib import Path

from app.journal import encode
from test_operator_tables import versions_project
from test_web import ORIGIN, web  # noqa: F401

TEMPLATES = Path(__file__).resolve().parents[1] / "app" / "templates"
HEADER_CELL = re.compile(r"<th(?=[\s>])[^>]*>")  # <th> и <th …>, но не <thead>


def header_cells(html: str) -> list[str]:
    return HEADER_CELL.findall(html)


def test_every_header_cell_in_the_templates_has_scope():
    missing = [f"{path.relative_to(TEMPLATES).as_posix()}:{n}: {tag}"
               for path in sorted(TEMPLATES.rglob("*.html"))
               for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
               for tag in header_cells(line) if "scope=" not in tag]
    assert not missing, "заголовок таблицы без scope:\n" + "\n".join(missing)


def test_journal_pages_mark_column_headers(web):
    db = web.app.state.db
    pid = db.create_project("Заголовки")
    rid = db.create_run(pid, "demo-model", "all", "p1", [])
    with db._tx() as c:  # замеры ресурсов прогона – как их копит journal.resources у идущего прогона
        payload = json.loads(c.execute("SELECT payload_json FROM run_journal WHERE run_id = ?", (rid,)).fetchone()[0])
        payload["resources"] = {"samples": 2, "gpu_pct": {"count": 2, "sum": 120, "max": 80}}
        c.execute("UPDATE run_journal SET payload_json = ? WHERE run_id = ?", (encode(payload), rid))
    pages = {"/journal": 6, f"/journal/{rid}": 4}  # таблица прогонов; таблица «Ресурсы во время прогона»
    for path, count in pages.items():
        response = web.client.get(path)
        assert response.status_code == 200, path
        cells = header_cells(response.text)
        assert len(cells) == count and all('scope="col"' in tag for tag in cells), (path, cells)
    assert "Ресурсы во время прогона" in web.client.get(f"/journal/{rid}").text


def test_batch_decision_page_marks_column_headers(web):
    pid, rows = versions_project(web)
    response = web.client.post(f"/projects/{pid}/components/decisions/preview", headers=ORIGIN,
                               data={"input_ref": [r["input_ref"] for r in rows]})
    assert response.status_code == 200
    cells = header_cells(response.text)
    assert len(cells) == 4 and all('scope="col"' in tag for tag in cells), cells

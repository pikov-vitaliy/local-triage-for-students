"""Сборка служебного блока в браузере (ADR-0139): оператор нажимает «Push в Hub», видит предупреждение и блок в предпросмотре, запись – по нажатию.
Hub поддельный, данные выдуманы, сеть – только приложение на 127.0.0.1."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import no_horizontal_scroll, open_page  # noqa: E402
from test_defect_where_flow import stand  # noqa: E402,F401
from app import hub_defects  # noqa: E402
from test_hub_block_builder import lost_block, sast_model, text_only, where_row  # noqa: E402
from test_hub_defect_import import deliver, take  # noqa: E402
from test_hub_defect_update import read_job, sent_body  # noqa: E402
from test_web import web  # noqa: E402,F401

pytestmark = pytest.mark.e2e


def test_operator_sees_built_block_and_pushes(browser, stand):  # noqa: F811
    web, url = stand
    pid, row = lost_block(web)
    context, page, watch = open_page(browser, url, width=1600, height=1000)
    try:
        page.goto(f"/projects/{pid}/defects/{row['id']}")
        page.locator("#defect-update-prepare").click()
        page.wait_for_load_state()
        read_job(web, text_only())
        blank = take(web)
        deliver(web, blank, 400, {"message": "No issues suitable"}, error="Hub 400")
        model = take(web)
        assert model["path"].startswith("/templates/defects/model?")
        deliver(web, model, 200, sast_model())
        page.goto(f"/projects/{pid}/defects/{row['id']}")
        warnings = page.locator(f"#hub-update-warnings-{row['id']}")
        expect(warnings).to_contain_text("собран приложением")
        put = page.locator(f"#hub-update-put-form-{row['id']}")
        expect(put).to_be_visible()
        for theme in ("light", "dark"):
            page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
            no_horizontal_scroll(page)
        assert take(web) is None, "без нажатия записи нет"
        assert watch.page_errors == []
    finally:
        context.close()


def test_operator_sees_the_hint_about_the_section_and_the_block_written(browser, stand):  # noqa: F811
    web, url = stand
    pid, row = where_row(web)
    db = web.app.state.db
    context, page, watch = open_page(browser, url, width=1600, height=1000)
    try:
        page.goto(f"/projects/{pid}/defects/{row['id']}")
        page.locator("#defect-update-prepare").click()
        page.wait_for_load_state()
        read_job(web, text_only())
        deliver(web, take(web), 200, sast_model())
        page.goto(f"/projects/{pid}/defects/{row['id']}")
        expect(page.locator(f"#hub-update-text-{row['id']}")).to_contain_text("Где исправлять")
        expect(page.locator(f"#hub-update-warnings-{row['id']}")).to_contain_text("собран приложением")
        expect(page.locator(f"#hub-update-warnings-{row['id']}")).to_contain_text("остался раздел")
        expect(page.locator(f"#hub-update-hint-{row['id']}")).to_contain_text("собранный приложением")
        for theme in ("light", "dark"):
            page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
            no_horizontal_scroll(page)
        assert take(web) is None, "без нажатия записи нет"
        page.locator(f"#hub-update-put-{row['id']}").click()
        page.wait_for_load_state()
        read_job(web, text_only())
        put = take(web)
        assert put["method"] == "PUT" and hub_defects.IMPORT_BOUNDARY in hub_defects.description_lines(put["body"]["description"])
        deliver(web, put, 204, text="")
        read_job(web, sent_body(db, row["id"]))
        assert hub_defects.update_state(db.hub_defect(row["id"]))["phase"] == "done"
        assert watch.page_errors == []
    finally:
        context.close()

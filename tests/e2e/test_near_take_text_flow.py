"""Кнопка похожей находки в обеих темах; модель не вызывается, данные выдуманы."""
import re

import pytest
from playwright.sync_api import expect

from app.db import Database
from app.models import Finding
from e2e_support import open_page, start_app, stop_app
from fake_ollama import FakeOllama
from test_db import load

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("theme,width", [("light", 1600), ("dark", 1600), ("light", 1920), ("dark", 1920)])
def test_take_near_text_preserves_draft_until_confirmed(browser, tmp_path, theme, width):
    db = Database(tmp_path / "data" / "triage.db")
    pid = db.create_project("Проверка соседней находки")
    load(db, pid, [Finding(hub_id=str(995000 + i), kind="SAST", rule="Внедрение SQL", cwe=["CWE-89"],
                          file="demo.py", line=2 + i, severity="high") for i in range(2)])
    urls = [f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, str(995000 + i))['id']}" for i in range(2)]
    db.close()
    with FakeOllama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url, width=width, theme=theme, accept_dialogs=False)
        try:
            page.goto(urls[0])
            page.locator("label").filter(has=page.locator('input[name="decision"][value="true_positive"]')).click()
            page.fill("#comment", "Данные без проверки доходят до SQL.")
            page.fill("#fix", "Передавать значение параметром.")
            page.click("#save-btn")
            page.wait_for_url(re.compile(r"ok=saved"))
            page.goto(urls[1])
            model_before = page.locator("#step-2").inner_html()
            page.locator("#near-category summary").click()
            button = page.locator("#near-category").get_by_role("button", name="Взять текст", exact=True)
            expect(button).to_be_visible()
            mutations = []
            page.on("request", lambda r: mutations.append(r.url) if r.method != "GET" else None)
            button.click()
            expect(page.locator("#comment")).to_have_value("Данные без проверки доходят до SQL.")
            expect(page.locator("#fix")).to_have_value("Передавать значение параметром.")
            expect(page.locator('input[name="decision"][value="true_positive"]')).to_be_checked()
            expect(page.locator("#take-note")).to_be_visible()
            page.fill("#comment", "Несохранённое обоснование")
            page.fill("#fix", "Несохранённая рекомендация")
            page.once("dialog", lambda dialog: dialog.dismiss())
            button.click()
            expect(page.locator("#comment")).to_have_value("Несохранённое обоснование")
            expect(page.locator("#fix")).to_have_value("Несохранённая рекомендация")
            page.once("dialog", lambda dialog: dialog.accept())
            button.click()
            expect(page.locator("#comment")).to_have_value("Данные без проверки доходят до SQL.")
            expect(page.locator("#fix")).to_have_value("Передавать значение параметром.")
            assert page.locator("#step-2").inner_html() == model_before
            assert mutations == [], "подстановка не сохраняет и не отправляет"
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            page.click("#save-btn")
            page.wait_for_url(re.compile(r"ok=saved"))
            page.reload()
            expect(page.locator("#comment")).to_have_value("Данные без проверки доходят до SQL.")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)

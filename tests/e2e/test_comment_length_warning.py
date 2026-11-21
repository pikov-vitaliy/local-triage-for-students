"""Р8 (ADR-0101): комментарий для Hub длиннее 250 знаков – предупреждение у поля, сохранение не
запрещается. У SCA длина считается с приставкой «<номер> в <компонент> <версия>: ». Данные выдуманы."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import DEMO_ANSWERS, create_demo, open_page, run_triage, start_app, stop_app  # noqa: E402
from fake_ollama import FakeOllama, verdict_answer  # noqa: E402
from test_operator_sast_route import card_urls, seeded  # noqa: E402

SHORT = "Имя таблицы берётся из заранее заданной строки, поэтому SQL-инъекция исключена."
LONG = (SHORT + " ") * 4  # больше 250 знаков


def test_sast_false_positive_comment_warns_after_250(browser, tmp_path):
    pid, repos = seeded(tmp_path, 1)
    with FakeOllama(default_answer=verdict_answer("false_positive", evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
            page.fill("#comment", SHORT)
            expect(page.locator("#comment-count")).not_to_have_class(re.compile("text-warn"))
            page.fill("#comment", LONG)
            expect(page.locator("#comment-count")).to_contain_text("Длиннее 250 знаков")
            expect(page.locator("#comment-count")).to_have_class(re.compile("text-warn"))
            page.click("#copy-hub")  # сохранение и копирование не запрещены
            expect(page.locator("#copy-status")).to_contain_text("скопирован")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_sca_comment_warning_counts_the_prefix(ui):
    page, _ = ui
    pid = create_demo(page)
    page.goto(f"/projects/{pid}/sca#answers")
    page.set_input_files("#answers-file", str(DEMO_ANSWERS))
    page.click("#answers-submit")
    page.wait_for_url(re.compile(r"ok=sca_answers"))
    page.click("#sca-continue")
    page.wait_for_url(re.compile(r"/sca/findings/\d+"))
    prefix = int(page.locator("#comment").get_attribute("data-prefix-len") or "0")
    assert prefix > 0, "у демо-находки есть публичный номер – приставка непустая"
    page.locator("label").filter(has=page.locator("input[name=decision][value=disagree]")).click()
    page.select_option("#final-verdict", "false_positive")
    # текст сам короче 250, но вместе с приставкой длиннее – предупреждение
    page.fill("#comment", "х" * (250 - prefix + 1))
    expect(page.locator("#sca-comment-count")).to_contain_text("длиннее 250 знаков")
    expect(page.locator("#sca-comment-count")).to_have_class(re.compile("text-warn"))
    page.fill("#comment", "х" * (250 - prefix))
    expect(page.locator("#sca-comment-count")).not_to_have_class(re.compile("text-warn"))
    # у вывода «обновить» текст идёт в описание дефекта – предела нет
    page.fill("#comment", "х" * 600)
    expect(page.locator("#sca-comment-count")).to_contain_text("длиннее 250 знаков")
    page.select_option("#final-verdict", "true_positive")
    expect(page.locator("#sca-comment-count")).not_to_contain_text("длиннее 250 знаков")
    expect(page.locator("#sca-comment-count")).not_to_contain_text("с номером и компонентом")
    expect(page.locator("#sca-comment-count")).not_to_have_class(re.compile("text-warn"))
    page.select_option("#final-verdict", "false_positive")
    expect(page.locator("#sca-comment-count")).to_contain_text("длиннее 250 знаков")
    # ревью dev8: черновик восстанавливается без событий – счётчик считает по восстановленному решению, в обе стороны
    page.wait_for_timeout(600)
    page.reload()
    expect(page.locator("#final-verdict")).to_have_value("false_positive")
    expect(page.locator("#sca-comment-count")).to_contain_text("длиннее 250 знаков")
    page.select_option("#final-verdict", "true_positive")
    page.wait_for_timeout(600)
    page.reload()
    expect(page.locator("#final-verdict")).to_have_value("true_positive")
    expect(page.locator("#sca-comment-count")).not_to_contain_text("длиннее 250 знаков")
    page.select_option("#final-verdict", "false_positive")
    # комментарий начинается с номера находки – приставки не будет, предупреждение только после 250 своих знаков
    ids = (page.locator("#comment").get_attribute("data-prefix-ids") or "").split(", ")
    page.fill("#comment", ids[0] + ": " + "х" * (250 - len(ids[0]) - 2))
    expect(page.locator("#sca-comment-count")).not_to_have_class(re.compile("text-warn"))

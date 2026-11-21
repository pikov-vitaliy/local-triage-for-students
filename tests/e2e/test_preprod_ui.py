"""Пакет 3: черновик отметки, исходный ID и подтверждение удаления срезов в браузере."""

from __future__ import annotations
from db_support import connect_db

import re
import shutil
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import expect  # noqa: E402

from e2e_support import DEMO_REPOS, Watch, create_demo, make_fake_ollama, start_app, stop_app  # noqa: E402

pytestmark = pytest.mark.e2e

# Карточка SAST с 0.9.6 (ADR-0089): решения – кнопки «Ложное срабатывание» (n) и «Подтверждаю дефект» (y),
# списка итогового вердикта нет. У SCA всё по-прежнему: «Своё решение» (d) и вердикт из списка.
SAST_KEYS = {"false_positive": "n", "true_positive": "y"}


def choose_outcome(page, sast: bool, outcome: str) -> None:
    page.keyboard.press(SAST_KEYS[outcome] if sast else "d")
    if not sast:
        page.select_option("#final-verdict", outcome)


def outcome_is_chosen(page, sast: bool, outcome: str) -> None:
    value = outcome if sast else "disagree"
    expect(page.locator(f'input[name="decision"][value="{value}"]')).to_be_checked()
    if sast:
        expect(page.locator("#final-verdict")).to_have_count(0)
    else:
        expect(page.locator("#final-verdict")).to_have_value(outcome)


@pytest.mark.parametrize("hub_id,section", [("100101", "findings"), ("200201", "sca")])
def test_reviewed_only_draft_survives_navigation(ui, hub_id, section):
    page, _ = ui
    pid = create_demo(page)
    page.goto(f"/projects/{pid}/findings/by-id?hub_id={hub_id}")
    card_url = page.url
    box = page.locator("#reviewed-box")
    expect(box).not_to_be_checked()
    page.keyboard.press("v")
    expect(box).to_be_checked()
    page.goto(f"/projects/{pid}/{section}")
    page.goto(card_url)
    expect(box).to_be_checked()
    expect(page.locator("#copy-status")).to_contain_text(
        "Отметка «Проверено» не сохранена – нажмите «Сохранить»")
    expect(page.locator("#reviewed-badge")).to_be_hidden()
    # Обратное изменение только флажка тоже восстанавливается: сервер хранит проверенное решение.
    choose_outcome(page, section == "findings", "true_positive")
    page.fill("#comment", "Проверено по учебным данным.")
    if section == "findings":  # дефект SAST – с рекомендацией оператора (ADR-0092)
        page.fill("#fix", "Параметризовать запрос.")
    page.get_by_role("button", name="Сохранить", exact=True).click()
    expect(page.locator("#reviewed-badge")).to_be_visible()
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("v")
    expect(box).not_to_be_checked()
    page.goto(f"/projects/{pid}/{section}")
    page.goto(card_url)
    expect(box).not_to_be_checked()
    expect(page.locator("#copy-status")).to_contain_text("Отметка «Проверено» не сохранена")


@pytest.mark.parametrize("section,hub_id,target", [
    ("findings", "100101", "findings"), ("sca", "200201", "sca/findings")])
def test_open_by_hub_id(ui, section, hub_id, target):
    page, _ = ui
    pid = create_demo(page)
    page.goto(f"/projects/{pid}/{section}")
    page.get_by_label("ID находки", exact=True).fill(hub_id)
    page.get_by_role("button", name="Открыть", exact=True).click()
    expect(page).to_have_url(re.compile(rf"/projects/{pid}/{target}/\d+$"))
    expect(page.locator("h1")).to_contain_text(hub_id)


def test_mapping_confirms_only_changed_codebase(ui):
    page, _ = ui
    create_demo(page)
    page.click("#save-snapshots")
    page.wait_for_url(re.compile(r"ok=snapshots#step2"))
    select = page.get_by_label("Папка для кодовой базы billing-core", exact=True)
    count = select.get_attribute("data-reset-cases")
    assert int(count) > 0
    select.select_option("")
    messages = []
    page.on("dialog", lambda dialog: messages.append(dialog.message))
    with page.expect_request(lambda request: request.method == "POST" and request.url.endswith("/codebases")) as sent:
        page.click("#save-mapping")
    page.wait_for_url(re.compile(r"ok=mapped.*#step2"))
    assert messages == [f"Будет удалено срезов кода: {count}; отметок «Проверено»: 0. "
                        "После удаления клонов это единственная копия кода. Подтвердите удаление."]
    assert "confirm_reset=1" in sent.value.post_data
    expect(select).to_have_value("")


def test_folder_selection_confirms_snapshot_loss(browser, tmp_path: Path):
    root = tmp_path / "root"
    shutil.copytree(DEMO_REPOS, root / "local-triage-demo")
    (root / "other").mkdir()
    (tmp_path / "app").mkdir()
    fake = make_fake_ollama()
    server = None
    context = None
    try:
        server = start_app(tmp_path / "app", fake.url, repos_root=root)
        context = browser.new_context(base_url=server.url, locale="ru-RU")
        page = context.new_page()
        watch = Watch(base=server.url)
        page.on("pageerror", lambda error: watch.page_errors.append(str(error)))
        page.on("console", lambda message: watch.console_errors.append(message.text)
                if message.type == "error" else None)
        page.on("request", lambda request: watch.requests.append(request.url))
        pid = create_demo(page)
        page.click("#save-snapshots")
        page.wait_for_url(re.compile(r"ok=snapshots#step2"))
        snapshots = page.locator("#snapshots-count").inner_text()
        page.goto(f"/projects/{pid}/folders?path=other")
        # Сперва отказ: выбранная папка и срезы остаются на месте.
        messages = []

        def dismiss(dialog):
            messages.append(dialog.message)
            dialog.dismiss()

        page.on("dialog", dismiss)
        page.get_by_role("button", name="Выбрать эту папку", exact=True).click()
        assert len(messages) == 1
        assert "срезов кода:" in messages[0] and "единственная копия кода" in messages[0]
        assert "отметок «Проверено»: 0" in messages[0]
        page.goto(f"/projects/{pid}#step2")
        expect(page.locator("#snapshots-count")).to_have_text(snapshots)
        page.goto(f"/projects/{pid}/folders?path=other")
        page.remove_listener("dialog", dismiss)
        page.on("dialog", lambda dialog: dialog.accept())
        page.get_by_role("button", name="Выбрать эту папку", exact=True).click()
        page.wait_for_url(re.compile(r"ok=repos.*#step2"))
        expect(page.locator("#snapshots-count")).to_contain_text("0 из")
        assert not watch.problems(), watch.problems()
    finally:
        if context is not None:
            context.close()
        if server is not None:
            stop_app(server.process)
        fake.close()


def test_reviewed_draft_requires_recheck_after_new_verdict(ui, app_server):
    from e2e_support import run_triage
    from fake_ollama import verdict_answer

    page, _ = ui
    pid = create_demo(page)
    run_triage(page, pid)
    page.goto(f"/projects/{pid}/findings/by-id?hub_id=100101")
    card_url = page.url
    old_id = page.locator('input[name="verdict_id"]').input_value()
    choose_outcome(page, True, "true_positive")
    page.fill("#comment", "Мой черновик до нового разбора")
    expect(page.locator("#reviewed-box")).to_be_checked()
    page.goto(f"/projects/{pid}/findings")
    other = page.context.new_page()
    try:
        other.goto(card_url)
        app_server.fake.answers.append(verdict_answer("false_positive"))
        other.click("#reanalyze-box summary")  # шаг 4 «Второе мнение» необязательный и свёрнут
        other.click("#reanalyze-btn")
        expect(other.locator('input[name="verdict_id"]')).not_to_have_value(old_id, timeout=60000)
    finally:
        other.close()
    page.goto(card_url)
    assert page.locator('input[name="verdict_id"]').input_value() != old_id
    expect(page.locator("#reviewed-box")).not_to_be_checked()
    outcome_is_chosen(page, True, "true_positive")
    expect(page.locator("#comment")).to_have_value("Мой черновик до нового разбора")
    expect(page.locator("#copy-status")).to_contain_text(
        "Ответ модели или код изменились после черновика – проверьте решение заново")


@pytest.mark.parametrize("kind", ["sast", "sca"])
def test_conflict_save_clears_reviewed_in_form_and_draft(ui, app_server, tmp_path, kind):
    from e2e_support import run_triage
    from fake_ollama import verdict_answer
    from test_answer_token import open_first_card, second_answers, upload_b

    page, watch = ui
    watch.allowed_errors.append("status of 409")
    pid = create_demo(page)
    if kind == "sast":
        run_triage(page, pid)
        page.goto(f"/projects/{pid}/findings/by-id?hub_id=100101")
        token_name, notice = "verdict_id", "Вердикт модели изменился"
    else:
        open_first_card(page, pid)
        token_name, notice = "answer_id", "новый ответ внешнего агента"
    card_url = page.url
    old_id = page.locator(f'input[name="{token_name}"]').input_value()
    page.evaluate("document.activeElement && document.activeElement.blur()")
    choose_outcome(page, kind == "sast", "true_positive")
    page.fill("#comment", "Мой вывод до смены ответа")
    if kind == "sast":  # дефект SAST – с рекомендацией оператора (ADR-0092)
        page.fill("#fix", "Параметризовать запрос.")
    expect(page.locator("#reviewed-box")).to_be_checked()
    if kind == "sast":
        other = page.context.new_page()
        try:
            other.goto(card_url)
            app_server.fake.answers.append(verdict_answer("false_positive"))
            other.click("#reanalyze-box summary")  # шаг 4 «Второе мнение» необязательный и свёрнут
            other.click("#reanalyze-btn")
            expect(other.locator('input[name="verdict_id"]')).not_to_have_value(old_id, timeout=60000)
        finally:
            other.close()
    else:
        upload_b(page, pid, second_answers(tmp_path))
    with page.expect_response(lambda response: response.request.method == "POST"
                              and "/review" in response.url) as conflict:
        page.get_by_role("button", name="Сохранить", exact=True).click()
    assert conflict.value.status == 409
    expect(page.locator("body")).to_contain_text(notice)
    expect(page.locator("#reviewed-box")).not_to_be_checked()
    expect(page.locator("#comment")).to_have_value("Мой вывод до смены ответа")
    outcome_is_chosen(page, kind == "sast", "true_positive")
    expect(page.locator(f'input[name="{token_name}"]')).not_to_have_value(old_id)
    draft = page.evaluate("JSON.parse(sessionStorage.getItem('local-triage-draft:' + location.pathname))")
    # Черновик, полностью совпавший с формой, уже мог быть удалён при её инициализации.
    assert draft is None or (draft["r"] is False and draft["c"] == "Мой вывод до смены ответа")
    # Повторное сохранение без нового флажка не превращает черновик в проверенное решение.
    page.get_by_role("button", name="Сохранить", exact=True).click()
    page.wait_for_url(re.compile(r"ok=(?:sca_)?saved"))
    expect(page.locator("#reviewed-box")).not_to_be_checked()
    expect(page.locator("#reviewed-badge")).to_be_hidden()
    page.goto(f"/projects/{pid}")
    page.goto(card_url)
    expect(page.locator("#reviewed-box")).not_to_be_checked()
    expect(page.locator("#reviewed-badge")).to_be_hidden()
    expect(page.locator("#comment")).to_have_value("Мой вывод до смены ответа")


def test_reset_mapping_confirms_snapshot_loss(ui):
    page, _ = ui
    create_demo(page)
    select = page.get_by_label("Папка для кодовой базы billing-core", exact=True)
    select.select_option("catalog-api")
    page.click("#save-mapping")
    page.wait_for_url(re.compile(r"ok=mapped.*#step2"))
    page.click("#save-snapshots")
    page.wait_for_url(re.compile(r"ok=snapshots#step2"))
    count = select.get_attribute("data-reset-cases")
    assert int(count) > 0
    messages = []
    # Общая фикстура принимает диалог; наблюдатель проверяет, что подтверждение было ровно одно.
    page.on("dialog", lambda dialog: messages.append(dialog.message))
    with page.expect_request(lambda request: request.method == "POST" and request.url.endswith("/codebases")) as sent:
        page.locator('button[name="action"][value="reset"]').click()
    page.wait_for_url(re.compile(r"ok=reset.*#step2"))
    assert len(messages) == 1
    assert f"срезов кода: {count}; отметок «Проверено»: 0" in messages[0]
    assert "confirm_reset=1" in sent.value.post_data
    expect(select).to_have_value("billing-core")


@pytest.mark.parametrize("hub_id", ["100101", "200201"], ids=["sast", "sca"])
@pytest.mark.parametrize("action", ["copy", "save", "reload"])
def test_revision_conflict_requires_new_reviewed_mark(browser, tmp_path, hub_id, action):
    """Чужая редакция снимает проверку, но сохраняет текст; повторное сохранение не возвращает reviewed."""

    from e2e_support import open_page

    fake = make_fake_ollama()
    server = None
    context = None
    comment = "Мой вывод до изменения решения в другой вкладке"
    try:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url)
        watch.allowed_errors.append("status of 409")
        pid = create_demo(page)
        page.goto(f"/projects/{pid}/findings/by-id?hub_id={hub_id}")
        card_url = page.url
        draft_key = page.evaluate("'local-triage-draft:' + location.pathname")
        revision = page.locator('#review-revision').input_value()
        sast = hub_id == "100101"
        # «моё» решение – ложное срабатывание: его короткий комментарий копируется кнопкой (action == "copy");
        # у «Обновить» в SCA короткого текста нет (0.9.8)
        mine, theirs = "false_positive", "true_positive"
        choose_outcome(page, sast, mine)
        page.fill("#comment", comment)
        expect(page.locator("#reviewed-box")).to_be_checked()
        other = context.new_page()
        try:
            other.goto(card_url)
            choose_outcome(other, sast, theirs)
            other.fill("#comment", "Другое решение во второй вкладке")
            if sast and theirs == "true_positive":
                other.fill("#fix", "Параметризовать запрос.")
            other.get_by_role("button", name="Сохранить", exact=True).click()
            other.wait_for_url(re.compile(r"ok=(?:sca_)?saved"))
            expect(other.locator('#review-revision')).not_to_have_value(revision)
        finally:
            other.close()
        if action != "reload":
            with page.expect_response(lambda response: response.request.method == "POST"
                                      and "/review" in response.url) as conflict:
                if action == "copy":
                    page.click("#copy-hub")
                else:
                    page.get_by_role("button", name="Сохранить", exact=True).click()
            assert conflict.value.status == 409
            if action == "copy":
                assert conflict.value.json()["reason"] == "revision"
                expect(page.locator("#copy-status")).to_contain_text("изменил")
            else:
                assert "text/html" in conflict.value.headers["content-type"]
                expect(page.locator("body")).to_contain_text("изменил")
            expect(page.locator("#reviewed-box")).not_to_be_checked()
            draft = page.evaluate("key => JSON.parse(sessionStorage.getItem(key))", draft_key)
            assert draft is None or (draft["r"] is False and draft["c"] == comment)
        # Возвращаем GET карточки и после HTML-ответа на POST, без повторной отправки старой формы.
        page.goto(card_url)
        expect(page.locator('#review-revision')).not_to_have_value(revision)
        expect(page.locator("#reviewed-box")).not_to_be_checked()
        outcome_is_chosen(page, sast, mine)
        expect(page.locator("#comment")).to_have_value(comment)
        if action in ("copy", "reload"):
            expect(page.locator("#copy-status")).to_contain_text("решение заново")
        page.reload()
        expect(page.locator("#reviewed-box")).not_to_be_checked()
        expect(page.locator("#comment")).to_have_value(comment)
        page.get_by_role("button", name="Сохранить", exact=True).click()
        page.wait_for_url(re.compile(r"ok=(?:sca_)?saved"))
        expect(page.locator("#reviewed-box")).not_to_be_checked()
        expect(page.locator("#reviewed-badge")).to_be_hidden()
        assert not watch.problems(), watch.problems()
    finally:
        if context is not None:
            context.close()
        if server is not None:
            stop_app(server.process)
        fake.close()
    # Приложение держит SQLite в EXCLUSIVE: проверяем сохранённое решение после остановки стенда.
    with connect_db(server.data_dir / "triage.db") as db:
        saved = db.execute(
            "SELECT reviewed, decision, final_verdict, final_comment FROM reviews WHERE project_id=? AND hub_id=?",
            (pid, hub_id),
        ).fetchone()
    assert saved == (0, "disagree", mine, comment)

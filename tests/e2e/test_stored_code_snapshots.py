"""Срезы кода в базе вместо клонов после разбора (ADR-0072), в браузере: демо-проект на копии демо-репозиториев,
разбор поддельной моделью, решение и копирование до удаления клонов; второй проект – «Сохранить срезы кода» без
модели. Затем приложение остановлено, папка с клонами удалена целиком, приложение запущено заново: карточки
показывают тот же код из базы, решения, «Скопировать для Hub», текст дефекта и повторный разбор работают."""

import re
import shutil
import time
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import (DEMO_REPOS, AppStartError, clipboard, create_demo, finding_id_from,  # noqa: E402
                         make_fake_ollama, open_page, run_triage, start_app, stop_app, wait_run_done)

pytestmark = pytest.mark.e2e


def restart(tmp: Path, ollama_url: str, root: Path):
    """Запуск после остановки: процесс в Windows завершается без штатного выхода, и папку данных он отпускает,
    когда его отметка устареет (app/lockfile.py, до 20 с) – как после аварийной остановки."""
    deadline = time.monotonic() + 60
    while True:
        try:
            return start_app(tmp, ollama_url, repos_root=root)
        except AppStartError as e:
            if 'LockBusy' not in str(e) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def code_text(page) -> str:
    return page.locator("section.code-panel table").inner_text()


def decide_true_positive(page, comment: str) -> None:
    """«Подтверждаю дефект» (клавиша y, ADR-0089): обоснование и рекомендация, сохранение, заголовок дефекта."""
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("y")
    expect(page.locator('input[name="decision"][value="true_positive"]')).to_be_checked()
    page.fill("#comment", comment)
    page.fill("#fix", "Передавать значение параметром запроса.")
    page.locator("#review-form button[value=save]").click()
    page.wait_for_url(re.compile(r"ok=saved"))
    expect(page.locator("#defect-panel")).to_be_visible()
    page.click("#copy-defect-title")
    expect(page.locator("#defect-status")).to_contain_text("Заголовок дефекта скопирован")
    assert re.fullmatch(r"ID\d+ - .+ \(SAST\)", clipboard(page))


def first_sast(page, pid: int) -> int:
    page.goto(f"/projects/{pid}/continue")
    page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+(?:\?.*)?$"))
    return finding_id_from(page.url)


def step2(page, pid: int):
    page.goto(f"/projects/{pid}#step2")
    return page.locator("#step2")


def test_clones_removed_after_triage_and_after_saving_snapshots(browser, tmp_path: Path):
    root = tmp_path / "root"
    shutil.copytree(DEMO_REPOS, root / "local-triage-demo")  # копия: демо-папку репозитория не трогаем
    (tmp_path / "app").mkdir()
    fake = make_fake_ollama()
    server = start_app(tmp_path / "app", fake.url, repos_root=root)
    context = None
    try:
        context, page, watch = open_page(browser, server.url)
        # Проект A: разбор моделью, решение «истинная», копирование для Hub и дефект – пока клоны на месте
        pid = create_demo(page)
        expect(page.locator("#snapshots-count")).to_contain_text("0 из")
        expect(page.locator("#save-snapshots")).to_be_visible()
        run_triage(page, pid)
        expect(step2(page, pid).locator("#snapshots-ready")).to_be_visible()
        fid = first_sast(page, pid)
        expect(page.locator("#code-from-db")).to_have_count(0)
        code_a = code_text(page)
        decide_true_positive(page, "Подтверждено: значение из запроса попадает в SQL без параметров.")
        page.reload()
        expect(page.locator("#reviewed-badge")).to_be_visible()

        # Проект B: срезы без модели
        sent = len(fake.chats())
        pid_b = create_demo(page)
        page.click("#save-snapshots")
        page.wait_for_url(re.compile(r"ok=snapshots#step2"))
        expect(page.locator(".flash-ok")).to_contain_text("Срезы кода сохранены")
        expect(page.locator("#snapshots-ready")).to_be_visible()
        expect(page.locator("#save-snapshots")).to_have_count(0)
        # находка кодовой базы без клона (notify-gateway) не мешает удалить остальные клоны
        expect(page.locator("#snapshots-unmapped")).to_contain_text("Ещё 1 находка SAST без среза")
        assert len(fake.chats()) == sent  # модель не вызывалась
        fid_b = first_sast(page, pid_b)
        code_b = code_text(page)
        assert not watch.problems(), watch.problems()
        context.close()
        context = None

        # Приложение остановлено, папка с клонами удалена целиком, приложение запущено заново
        stop_app(server.process)
        shutil.rmtree(root / "local-triage-demo")
        server = restart(tmp_path / "app", fake.url, root)
        context, page, watch = open_page(browser, server.url)

        page.goto(f"/projects/{pid}/findings/{fid}")
        expect(page.locator("#code-from-db")).to_be_visible()
        expect(page.locator("#code-from-db")).to_contain_text("тот, который видела модель")
        expect(page.locator("#code-changed")).to_have_count(0)
        assert code_text(page) == code_a
        expect(page.locator("#reviewed-badge")).to_be_visible()
        expect(page.locator("#defect-panel")).to_be_visible()
        page.click("#copy-defect-title")
        expect(page.locator("#defect-status")).to_contain_text("Заголовок дефекта скопирован")
        page.click("#copy-defect-bar")  # у подтверждённого дефекта в Hub уходит текст дефекта
        expect(page.locator("#copy-status")).to_contain_text("Полный текст дефекта скопирован")
        block = step2(page, pid)
        expect(block).to_contain_text("клон удалён, срезы в базе")
        expect(block.locator("#snapshots-ready")).to_be_visible()
        # в «Клонировать только эти» – только кодовая база, которую не клонировали (notify-gateway в демо)
        expect(block.locator("#clone-list")).to_have_text("notify-gateway")
        expect(block).not_to_contain_text("Выбранная папка проекта не найдена")
        # повторный прогон без клонов: вердикты из кэша, решение остаётся проверенным
        run_triage(page, pid)
        page.goto(f"/projects/{pid}/findings/{fid}")
        expect(page.locator("#reviewed-badge")).to_be_visible()
        assert code_text(page) == code_a

        # Проект B: карточка без вердикта показывает код из базы; решение и дефект; разбор – по срезам из базы
        page.goto(f"/projects/{pid_b}/findings/{fid_b}")
        expect(page.locator("#code-from-db")).to_be_visible()
        expect(page.locator("#code-from-db")).not_to_contain_text("видела модель")
        assert code_text(page) == code_b
        decide_true_positive(page, "Подтверждено по срезу из базы приложения.")
        # «Спросить модель заново»: код у проектов A и B один, без отметки вердикты взялись бы из кэша
        sent = len(fake.chats())
        page.goto(f"/projects/{pid_b}#step3")
        page.check('input[name="fresh"]')
        page.get_by_role("button", name="Запустить триаж", exact=True).click()
        page.wait_for_url(re.compile(r"/runs/\d+$"))
        wait_run_done(page)
        prompts = "\n".join(str(m.get("content") or "") for chat in fake.chats()[sent:]
                            for m in chat.get("messages") or [])
        target = page.context.request.get(f"/projects/{pid_b}/findings/{fid_b}").text()
        assert prompts
        line = next(s for s in code_b.splitlines() if len(s.strip()) > 20)
        assert line.split("\t")[-1].strip() in prompts, "модель получила код из базы, а не строку выгрузки"
        assert 'id="code-changed"' not in target
        assert not watch.problems(), watch.problems()
    finally:
        if context is not None:
            context.close()
        stop_app(server.process)
        fake.close()

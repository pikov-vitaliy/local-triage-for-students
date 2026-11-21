"""Оператор настраивает сервер модели в сети организации (0.9.12, ADR-0102): форма профиля, «Проверить» – адреса
имени, подтверждение адреса, повторная проверка, ключ; профиль проекта; прогон уходит на этот сервер с ключом; имя
профиля – на странице прогона и в журнале; ключа нет ни на одной странице. Поддельный сервер слушает частный адрес
этого компьютера (внутренний адаптер); нет такого адреса – проверка пропускается с причиной, и это не сетевая
приёмка: сеть подтверждает владелец."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

from e2e_support import create_demo, e2e_reply, private_ipv4, run_triage
from fake_ollama import FakeOllama

pytestmark = pytest.mark.e2e

KEY = "e2e-lan-key-" + "Mx4" * 6  # ключ, созданный тестом: не настоящий


@pytest.fixture
def lan_fake():
    host = private_ipv4()
    if host is None:
        pytest.skip("у компьютера нет частного IPv4: e2e сервера в сети не выполнена – сетевую часть подтверждает "
                    "владелец")
    fake = FakeOllama(default_answer=e2e_reply, host=host)
    fake.host = host
    yield fake
    fake.close()


def test_lan_profile_from_the_form_to_a_run(ui, lan_fake):
    page, _ = ui
    page.goto("/settings/providers")
    page.get_by_role("link", name="Добавить профиль").click()
    page.fill('input[name="name"]', "Сервер в сети e2e")
    page.check('input[name="trust"][value="lan"]')
    page.fill('input[name="base_url"]', lan_fake.url)
    page.click("#provider-check")
    expect(page.locator("#provider-status")).to_contain_text("Отметьте адреса")
    assert lan_fake.paths() == [], "до подтверждения к серверу не обращаются"
    page.check(f'input[name="confirm"][value="{lan_fake.host}"]')
    page.click("#provider-check")
    expect(page.locator("#provider-status")).to_contain_text("Проверено: Ollama")
    page.check('input[name="requires_key"]')
    page.fill('input[name="key"]', KEY)
    page.click("#provider-save")
    page.wait_for_url(re.compile(r"/settings/providers\?ok=provider_saved"))
    expect(page.locator("#providers-table")).to_contain_text("задан, …" + KEY[-4:])
    assert KEY not in page.content()
    profile_link = page.locator("#providers-table tr", has_text="Сервер в сети e2e").get_by_role("link", name="Изменить")
    profile_id = re.search(r"/settings/providers/(\d+)", profile_link.get_attribute("href")).group(1)
    profile_link.click()
    assert KEY not in page.content()

    pid = create_demo(page)
    page.goto(f"/projects/{pid}")
    # профиль меняется прямо в шаге «Триаж»: список отправляет форму сам (data-autosubmit)
    page.select_option("#run-provider", profile_id)
    page.wait_for_url(re.compile(rf"/projects/{pid}\?ok=provider_changed"))
    expect(page.locator("#run-profile")).to_contain_text("Сервер в сети e2e – сервер в сети организации")
    expect(page.locator("#run-server")).to_have_text(lan_fake.url)
    before = len(lan_fake.headers)  # «Проверить» шла до ввода ключа – без него; запросы прогона – с ключом
    rid = run_triage(page, pid)
    expect(page.locator("#run-executor")).to_contain_text("Сервер в сети e2e (сеть организации)")
    assert lan_fake.chats(), "разбор ушёл на сервер профиля проекта"
    assert lan_fake.headers[before:] and all(h.get("Authorization") == f"Bearer {KEY}"
                                              for h in lan_fake.headers[before:])
    data = page.request.get("/journal/export.json").json()
    run = next(r for r in data["runs"] if r["run"]["id"] == rid)
    assert run["provider"]["name"] == "Сервер в сети e2e" and run["provider"]["where"] == "сеть организации"
    assert KEY not in page.content()

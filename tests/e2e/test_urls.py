"""LTA-004 в браузере: тот же набор адресов, что в tests/test_audit_lta004.py (tests/url_corpus.py), разбирается URL API
браузера (`new URL`) без сетевых запросов. Принятая сервером ссылка не должна менять в браузере ни имя сайта, ни путь, а
статус первоисточника по адресу браузера должен совпадать с серверным; четыре адреса из воспроизведения аудита
подтверждают, что браузер действительно переписывает адрес (набор осмыслен)."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import pytest

pytest.importorskip("playwright.sync_api")

from app import sca  # noqa: E402
from url_corpus import ACCEPT_PRIMARY, CORPUS, REJECT  # noqa: E402

pytestmark = pytest.mark.e2e

PARSE_FULL = """urls => urls.map(u => { try { const x = new URL(u);
    return {ok: true, href: x.href, host: x.hostname, port: x.port, path: x.pathname, protocol: x.protocol};
  } catch (e) { return {ok: false}; } })"""
PARSE = """urls => urls.map(u => { try { const x = new URL(u);
    return {ok: true, href: x.href, host: x.hostname, path: x.pathname, protocol: x.protocol};
  } catch (e) { return {ok: false}; } })"""


def default_port(protocol: str, port: str) -> str:
    return "" if port == {"http:": "80", "https:": "443"}.get(protocol) else port


def test_browser_reads_every_accepted_link_the_way_the_server_checked_it(ui):
    """Браузерная проверка идёт над результатом norm_link – тем, что приложение реально выведет и покажет."""
    page, _ = ui
    accepted = [(url, expected, why, sca.norm_link(url)) for url, expected, why in CORPUS if sca.norm_link(url)]
    assert len(accepted) >= 30
    parsed = page.evaluate(PARSE_FULL, [link for _, _, _, link in accepted])
    problems = []
    for (url, expected, why, link), seen in zip(accepted, parsed):
        server = urlsplit(link)
        if not seen["ok"]:
            problems.append(f"{why}: браузер не разобрал принятую ссылку {link!r}")
            continue
        server_port = default_port(seen["protocol"], str(server.port or ""))
        if seen["protocol"] not in ("http:", "https:") or seen["host"] != (server.hostname or "").lower():
            problems.append(f"{why}: имя сайта сервера {server.hostname} != браузера {seen['host']} ({link!r})")
        if seen["port"] != server_port:
            problems.append(f"{why}: порт сервера {server_port!r} != браузера {seen['port']!r} ({link!r})")
        if seen["path"] != (server.path or "/"):
            problems.append(f"{why}: путь сервера {server.path} != браузера {seen['path']} ({link!r})")
        if re.fullmatch(r"[\d.]+|\[.*\]", seen["host"]):
            problems.append(f"{why}: браузер открыл бы адрес IP {seen['host']} ({link!r})")
        if sca.is_primary_source(seen["href"]) is not (expected == ACCEPT_PRIMARY):
            problems.append(f"{why}: статус первоисточника по адресу браузера {seen['href']} другой")
    assert not problems, "\n".join(problems)


def test_the_audit_urls_are_really_rewritten_by_the_browser(ui):
    """Основание набора: браузер переписывает эти адреса (петля 127.0.0.1, удалённые «advisories/..»), а сервер их не принимает."""
    page, _ = ui
    audit = [u for u, _, why in CORPUS if why.startswith("аудит")]
    seen = page.evaluate(PARSE, audit)
    assert seen[0]["host"] == "127.0.0.1" and seen[1]["host"] == "127.0.0.1"
    assert seen[2]["path"] == "/audit-user/audit-repo/blob/main/advice.md" and seen[3]["path"] == seen[2]["path"]
    assert all(sca.norm_link(u) == "" for u in audit)


def test_rejected_corpus_entries_include_every_address_the_browser_turns_into_loopback(ui):
    page, _ = ui
    urls = [u for u, expected, _ in CORPUS if expected == REJECT]
    for url, seen in zip(urls, page.evaluate(PARSE, urls)):
        if seen["ok"] and seen["host"] in ("127.0.0.1", "[::1]", "localhost"):
            assert sca.norm_link(url) == "", url

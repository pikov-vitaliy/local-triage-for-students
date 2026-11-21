"""LTA-004: ссылки на источники проверяются по тому, что поймёт браузер.

Замечание аудита 15.10.2026 (реестр – docs/state/audit-2026-10-15.md): norm_link принимал «https://%31%32%37.0.0.1/» и
«https://127.0.0x0.1/», которые браузер превращает в «https://127.0.0.1/», а is_primary_source считал первоисточником
«github.com/advisories/../audit-user/…», хотя браузер удаляет «advisories/..». Набор адресов общий с браузерной
проверкой: tests/url_corpus.py, tests/e2e/test_urls.py.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from app import sca
from url_corpus import ACCEPT_PRIMARY, CORPUS, REJECT

AUDIT_URLS = [u for u, _, why in CORPUS if why.startswith("аудит")]


@pytest.mark.parametrize("url, expected, why", CORPUS, ids=[f"{i:02d}" for i in range(len(CORPUS))])
def test_corpus_server_decision(url, expected, why):
    link = sca.norm_link(url)
    if expected == REJECT:
        assert link == "", f"{why}: {url}"
        assert sca.is_primary_source(url) is False, "отвергнутый адрес не бывает первоисточником"
        return
    assert link, f"{why}: {url}"
    assert sca.is_primary_source(link) is (expected == ACCEPT_PRIMARY), f"{why}: {url}"


def test_the_four_audit_urls_are_all_refused():
    assert len(AUDIT_URLS) == 4
    assert all(sca.norm_link(u) == "" and not sca.is_primary_source(u) for u in AUDIT_URLS)


def test_ordinary_osv_nvd_ghsa_links_keep_working():
    for url in ("https://osv.dev/vulnerability/CVE-2099-1", "https://nvd.nist.gov/vuln/detail/CVE-2099-1",
                "https://github.com/advisories/GHSA-abcd-efgh-ijkl", "https://www.cve.org/CVERecord?id=CVE-2099-1"):
        assert sca.norm_link(url) == url and sca.is_primary_source(url)


def test_accepted_links_have_no_form_the_browser_would_rewrite():
    """Свойство принятых ссылок: имя сайта без процентов, точек в конце и адреса IP, путь без сегментов «.» и «..»."""
    for url, expected, _ in CORPUS:
        link = sca.norm_link(url)
        if not link:
            continue
        parts = urlsplit(link)
        assert "%" not in (parts.hostname or "") and not (parts.hostname or "").endswith(".")
        assert parts.hostname == parts.hostname.lower() and not parts.hostname.split(".")[-1].isdigit()
        assert all(seg not in (".", "..") and seg.lower() not in ("%2e", "%2e%2e", ".%2e", "%2e.")
                   for seg in parts.path.split("/"))


def test_norm_link_is_idempotent_and_does_not_decode_again():
    for url, expected, _ in CORPUS:
        link = sca.norm_link(url)
        assert sca.norm_link(link) == link
    assert sca.norm_link("https://example.org/a%252e%252e/b") == "https://example.org/a%252e%252e/b"


def test_links_in_markdown_and_text_go_through_the_same_check():
    assert sca.norm_link("[OSV](https://osv.dev/vulnerability/CVE-2099-1)") == "https://osv.dev/vulnerability/CVE-2099-1"
    assert sca.norm_link("см. https://127.0.0.1/ здесь") == ""
    links, dropped = sca.norm_links(["https://osv.dev/x", "https://%31%32%37.0.0.1/", "https://127.0.0x0.1/",
                                     "https://github.com/advisories/../u/r/blob/main/a.md"])
    assert links == ["https://osv.dev/x"] and dropped == 3


def test_github_advisory_needs_the_exact_path_and_host():
    primary = sca.is_primary_source
    assert primary("https://github.com/advisories/GHSA-abcd-efgh-ijkl")
    assert primary("https://github.com/advisories")
    assert not primary("https://github.com/advisories/GHSA-abcd-efgh-ijkl/more")
    assert not primary("https://github.com/advisories-x/GHSA-abcd-efgh-ijkl")
    assert not primary("https://gist.github.com/advisories")
    assert not primary("https://github.com/someone/repo")


def test_userinfo_ports_and_schemes():
    for url in ("https://user@osv.dev/x", "https://osv.dev@evil.example/", "https://osv.dev:8443/x",
                "http://osv.dev:80/x/", "ftp://osv.dev/x"):
        accepted = bool(sca.norm_link(url))
        assert accepted is (url == "http://osv.dev:80/x/"), url


def test_hub_text_keeps_only_primary_links_from_the_corpus():
    """Ссылки ответа агента: в карточке видны обычные, в текст для Hub идут только первоисточники по настоящему адресу."""
    from app import defect
    from app.models import Finding

    links = [url for url, _, _ in CORPUS]
    kept = [link for link in (sca.norm_link(u) for u in links) if link and sca.is_primary_source(link)]
    assert kept and all(urlsplit(k).hostname.lower().endswith(("osv.dev", "nist.gov", "github.com", "cve.org", "pypi.org",
                                                              "fstec.ru")) for k in kept)
    assert "https://github.com/advisories/../audit-user/audit-repo/blob/main/advice.md" not in kept
    assert defect  # модуль подключён: сама сборка текста проверена в test_review_fixes.py
    assert Finding


def test_one_checking_layer_for_both_public_functions():
    """Третья проверка: is_primary_source и norm_link не расходятся ни на одном адресе набора и ни на одной
    «грязной» записи – общие ограничения живут в одном слое."""
    for url, expected, why in CORPUS:
        if sca.is_primary_source(url):
            assert sca.norm_link(url), f"{why}: первоисточник, которого norm_link не принимает: {url!r}"
    for dirty in ("https://osv.dev/a\b", "https://osv.dev/a\tb", "https://osv.dev/a\nb", "https://osv.dev/\u043f",
                  "https://osv.dev/a b", "https://osv.dev/a\x00b", "https://osv.dev/a{b}"):
        assert not sca.is_primary_source(dirty), repr(dirty)


def test_control_characters_reject_the_whole_string_instead_of_cutting_a_prefix():
    for dirty in ("https://osv.dev/a\tb", "https://osv.dev/a\nb", "https://osv.dev/a\rb", "https://os\tv.dev/x",
                  "https://osv.dev/x\u200b"):
        assert sca.norm_link(dirty) == "", repr(dirty)
    assert sca.norm_link("  https://osv.dev/x \t") == "https://osv.dev/x", "пробелы вокруг значения снимаются"
    assert sca.norm_link("см. https://osv.dev/x здесь") == "https://osv.dev/x", "адрес внутри текста по-прежнему извлекается"


def test_a_labels_must_be_real_punycode():
    assert sca.norm_link("https://xn--80ak6aa92e.com/") and not sca.norm_link("https://xn--/")
    assert not sca.norm_link("https://xn--a.example/") and not sca.norm_link("https://xn--zzzzzzzzzzzzzzzzzzzz.example/")


def test_path_with_parentheses_is_kept_and_a_trailing_sentence_bracket_is_not():
    assert sca.norm_link("https://osv.dev/a(b)") == "https://osv.dev/a(b)"
    assert sca.norm_link("https://osv.dev/x)") == "https://osv.dev/x"
    assert sca.norm_link("(https://osv.dev/x)") == "https://osv.dev/x"

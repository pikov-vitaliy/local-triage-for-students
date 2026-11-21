"""Текущие CWE/CAPEC: обновление, исчезнувшие ID и возврат к рабочей задаче."""
from urllib.parse import urlencode

import pytest

from app.feeds import FeedError
from capec_fixtures import CAPEC_XML, capec_zip
from feed_fixtures import CWE_FULL_XML, cwe_zip
from test_web import create_project, prepared, web  # noqa: F401


def install(web, kind, version="10.0", date="2099-06-01", *, removed=False, name="Current Demo"):
    xml = CWE_FULL_XML if kind == "cwe" else CAPEC_XML
    xml = xml.replace('Version="9.99"', f'Version="{version}"')
    xml = xml.replace('Date="2099-04-30"', f'Date="{date}"').replace('Date="2099-01-24"', f'Date="{date}"')
    xml = xml.replace('Name="Improper Neutralization of Demo Input"', f'Name="{name}"')
    xml = xml.replace('Name="Demo Injection"', f'Name="{name}"')
    if removed:
        xml = xml.replace('ID="2099"', 'ID="2199"')
    path = web.tmp / f"{kind}.zip"
    if kind == "cwe":
        cwe_zip(path, xml)
    else:
        path.write_bytes(capec_zip(xml))
    return web.app.state.feeds.load(kind, path, path.name)


@pytest.mark.parametrize("kind", ["cwe", "capec"])
def test_missing_record_explains_current_feed_and_preserves_work(web, kind):
    pid = prepared(web)
    # Список с отбором – полноценная рабочая точка возврата без чтения настоящих находок.
    origin = f"/projects/{pid}/findings?kind=SAST&severity=high&page=2"
    install(web, kind, removed=True)
    response = web.client.get(f"/{kind}/{kind.upper()}-2099?" + urlencode({"origin": origin}),
                              headers={"Accept": "text/html"})
    assert response.status_code == 404
    assert f"{kind.upper()}-2099" in response.text and "10.0" in response.text
    assert 'id="task-origin"' in response.text and "page=2" in response.text
    assert "Поиск по каталогу" in response.text and "Загрузить каталог" in response.text
    assert "mitre.org/data/definitions/2099.html" in response.text


@pytest.mark.parametrize("kind", ["cwe", "capec"])
def test_not_loaded_and_invalid_id_are_distinct(web, kind):
    empty = web.client.get(f"/{kind}/{kind.upper()}-2099", headers={"Accept": "text/html"})
    assert empty.status_code == 404 and 'id="reference-not-loaded"' in empty.text
    invalid = web.client.get(f"/{kind}/not-an-id", headers={"Accept": "text/html"})
    assert invalid.status_code == 404 and 'id="reference-invalid"' in invalid.text
    assert "mitre.org/data/definitions/not-an-id" not in invalid.text


@pytest.mark.parametrize("kind", ["cwe", "capec"])
def test_same_url_reads_latest_record_and_removed_id_keeps_reason(web, kind):
    install(web, kind)
    url = f"/{kind}/{kind.upper()}-2099"
    install(web, kind, "10.1", name="Updated Demo")
    response = web.client.get(url)
    assert response.status_code == 200 and "Updated Demo" in response.text
    assert "10.1" in response.text and "2099-06-01" in response.text
    assert "Загружен" in response.text
    install(web, kind, "10.2", removed=True)
    missing = web.client.get(url, headers={"Accept": "text/html"})
    assert missing.status_code == 404 and "10.2" in missing.text
    assert "Отсутствие записи не означает устранение уязвимости" in missing.text


@pytest.mark.parametrize("kind", ["cwe", "capec"])
@pytest.mark.parametrize("previous,newer,older", [("9.9", "9.10", "9.8"), ("10.0", "10.0.1", "10" )])
def test_older_version_refused_without_replacing_current(web, kind, previous, newer, older):
    install(web, kind, previous)
    install(web, kind, newer)
    with pytest.raises(FeedError, match="старее"):
        install(web, kind, older, name="Old Demo")
    assert web.app.state.feeds.status()[kind]["version"] == newer
    assert "Current Demo" in web.client.get(f"/{kind}/{kind.upper()}-2099").text
    install(web, kind, newer, name="Same Version Reload")
    assert "Same Version Reload" in web.client.get(f"/{kind}/{kind.upper()}-2099").text


@pytest.mark.parametrize("kind", ["cwe", "capec"])
def test_older_source_date_refused_even_for_same_version(web, kind):
    install(web, kind)
    with pytest.raises(FeedError, match="старее"):
        install(web, kind, date="2099-05-31")
    assert web.app.state.feeds.status()[kind]["source_date"] == "2099-06-01"


@pytest.mark.parametrize("kind", ["cwe", "capec"])
def test_unknown_version_not_silently_replaces_known_version(web, kind):
    install(web, kind)
    with pytest.raises(FeedError, match="сравнить"):
        install(web, kind, version="unknown")


def test_missing_cross_catalog_target_is_marked(web):
    install(web, "capec")
    response = web.client.get("/capec/CAPEC-2099")
    assert "каталог CWE не загружен" in response.text
    install(web, "cwe", removed=True)
    response = web.client.get("/capec/CAPEC-2099")
    assert "нет в загруженном каталоге" in response.text


def test_empty_cwe_upload_keeps_work_context(web):
    pid = create_project(web.client)
    origin = f"/projects/{pid}/findings?kind=SAST"
    page = web.client.get("/cwe?" + urlencode({"origin": origin})).text
    empty = page.split('id="cwe-empty"', 1)[1].split("</section>", 1)[0]
    assert "/feeds?origin=" in empty and "#feed-cwe" in empty


@pytest.mark.parametrize("kind", ["cwe", "capec"])
def test_missing_page_rejects_external_return_urls(web, kind):
    install(web, kind, removed=True)
    response = web.client.get(f"/{kind}/2099?" + urlencode({"origin": "https://evil.example/", "back": "//evil.example/"}),
                              headers={"Accept": "text/html"})
    assert response.status_code == 404 and 'href="https://evil.example/' not in response.text
    assert 'href="//evil.example/' not in response.text


@pytest.mark.parametrize("kind", ["cwe", "capec"])
def test_missing_page_keeps_catalog_back_link_without_project(web, kind):
    install(web, kind, removed=True)
    response = web.client.get(f"/{kind}/2099?" + urlencode({"back": f"/{kind}?q=demo&page=2"}),
                              headers={"Accept": "text/html"})
    assert 'id="reference-back"' in response.text and "page=2" in response.text


@pytest.mark.parametrize("kind", ["cwe", "capec"])
def test_malformed_archive_keeps_current_links_and_metadata(web, kind):
    install(web, kind)
    before = web.app.state.feeds.status()[kind]
    path = web.tmp / "bad.zip"
    path.write_bytes(b"not a zip")
    with pytest.raises(FeedError):
        web.app.state.feeds.load(kind, path, path.name)
    assert web.app.state.feeds.status()[kind] == before
    assert web.client.get(f"/{kind}/2099").status_code == 200


def test_deprecated_record_from_current_catalog_remains_available(web):
    install(web, "capec")
    page = web.client.get("/capec/CAPEC-2101")
    assert page.status_code == 200 and "Deprecated" in page.text

"""Справочники уязвимостей: потоковый разбор выгрузки БДУ ФСТЭК России и каталога CWE, защита от вредного XML,
пределы, хранение с подменой одной транзакцией, страница «Справочники»."""

from __future__ import annotations

import html
import io
import re
import time
import tracemalloc
import zipfile
from collections.abc import Iterable, Iterator
from pathlib import Path

import psycopg
import pytest

from app import feeds
from app.feeds import FeedError, FeedStore, guarded_chunks, iter_records
from app.routes import cwe as cwe_routes
from feed_fixtures import BDU_XML, CWE_FULL_XML, CWE_XML, bdu_zip, cwe_zip, zip_bytes  # noqa: F401
from hub_fixtures import make_hub_xlsx  # noqa: F401
from test_web import ORIGIN, create_project, upload, web  # noqa: F401


@pytest.fixture
def store(tmp_path: Path):
    s = FeedStore(tmp_path / "feeds.db")
    yield s
    s.close()


def chunks_of(data: bytes, size: int) -> list[bytes]:
    return [data[k:k + size] for k in range(0, len(data), size)]


# ============================================================================ защита и пределы

@pytest.mark.parametrize("decl", ["<!DOCTYPE x [<!ENTITY a 'b'>]>", "<!ENTITY a SYSTEM 'file:///etc/passwd'>",
                                  "<! doctype x>"])
def test_doctype_and_entity_are_rejected(decl: str, monkeypatch):
    monkeypatch.setattr(feeds, "CHUNK", 7)  # объявление разрезано на стыке кусков
    data = f'<?xml version="1.0"?>{decl}<vulnerabilities></vulnerabilities>'.encode()
    with pytest.raises(FeedError, match="DOCTYPE или ENTITY"):
        list(guarded_chunks(io.BytesIO(data)))


def test_only_utf8_and_size_limits():
    with pytest.raises(FeedError, match="UTF-8"):
        list(guarded_chunks(io.BytesIO('<?xml version="1.0" encoding="utf-16"?><a/>'.encode("utf-16"))))
    with pytest.raises(FeedError, match="размера"):
        list(guarded_chunks(io.BytesIO(b"<a>" + b"x" * 100 + b"</a>"), limit=50))


def test_records_are_dropped_from_tree_after_use():
    big = "<vulnerabilities>" + "".join(f"<vul><identifier>BDU:2099-{n:05d}</identifier><junk>{'x' * 50}</junk></vul>"
                                        f"<other>{n}</other>" for n in range(500)) + "</vulnerabilities>"
    roots = []
    seen = 0
    for elem in iter_records(chunks_of(big.encode(), 333), {"vul"}, on_root=roots.append):
        seen += 1
        assert len(roots[0]) <= 20  # в корне – только записи из последнего прочитанного куска, не весь файл
    assert seen == 500 and len(roots[0]) == 0


def test_broken_xml_is_a_clear_error():
    with pytest.raises(FeedError, match="повреждён"):
        list(iter_records([b"<vulnerabilities><vul><identifier>BDU:1"], {"vul"}))


# ============================================================================ разбор и хранение

def test_bdu_load_and_lookup(store: FeedStore, tmp_path: Path):
    meta = store.load("bdu", bdu_zip(tmp_path / "vulxml.zip"), "vulxml.zip")
    assert meta["records"] == 2 and meta["source_date"] == "2099-03-11" and meta["filename"] == "vulxml.zip"
    found = store.bdu_by_cve(["cve-2099-10002", "CVE-2099-10001", "CVE-2099-99999", "не CVE"])
    assert set(found) == {"CVE-2099-10002", "CVE-2099-10001"}
    record = found["CVE-2099-10002"][0]
    assert record["id"] == "BDU:2099-00001" and record["solution"].startswith("Обновление программного")
    assert record["severity"].startswith("Высокий") and record["cvss3"].startswith("7,5 AV:N")
    assert record["sources"] == ["https://example.org/advisories/parser-1",
                                 "https://osv.dev/vulnerability/CVE-2099-10002"]
    assert record["cwes"] == [{"id": "CWE-1333", "name": "Неэффективная сложность регулярного выражения"}]
    assert record["published"] == "2099-02-03"
    # русские названия классов CWE – из БДУ, даже если каталог CWE не загружен
    assert store.cwe_info(["CWE-1333"])["CWE-1333"]["name_ru"] == "Неэффективная сложность регулярного выражения"
    assert store.status()["bdu"]["records"] == 2


def test_cwe_load_with_namespace_and_categories(store: FeedStore, tmp_path: Path):
    meta = store.load("cwe", cwe_zip(tmp_path / "cwec_latest.xml.zip"), "cwec_latest.xml.zip")
    assert (meta["records"], meta["version"], meta["source_date"]) == (3, "9.99", "2099-04-30")
    info = store.cwe_info(["89", "CWE-9999", "CWE-404"])
    assert set(info) == {"CWE-89", "CWE-9999"}
    # расширенное описание хранится списком абзацев (в прежней версии приложения – строкой)
    assert info["CWE-89"]["name"].startswith("Improper Neutralization")
    assert info["CWE-89"]["extended"] == ["Extended text."]
    assert info["CWE-9999"]["description"] == "Demo summary." and info["CWE-9999"]["kind"] == "category"


def test_cwe_full_record_sections(store: FeedStore, tmp_path: Path):
    """Полная запись: все разделы каталога разобраны, поле full отличает её от записи прежней версии."""
    meta = store.load("cwe", cwe_zip(tmp_path / "cwec_latest.xml.zip", CWE_FULL_XML), "cwec_latest.xml.zip")
    assert (meta["records"], meta["ref_records"], meta["version"], meta["source_date"]) == (6, 3, "9.99", "2099-04-30")
    record = store.cwe_page("CWE-2099")["record"]
    assert record["full"] == 1 and record["kind"] == "weakness" and record["structure"] == "Simple"
    assert "alert(1)" in record["description"]
    assert record["extended"] == ["Extended first paragraph.", "Extended second paragraph."]
    assert record["alt_terms"] == [{"term": "Demo injection", "description": "Другое название класса из каталога."}]
    assert record["ordinalities"] == ["Primary"]
    assert record["background"] == ["Background detail of the demo class."]
    assert [p["kind"] for p in record["platforms"]] == ["Language", "Technology", "Operating_System", "Architecture"]
    assert record["platforms"][1] == {"kind": "Technology", "class": "Web Based", "name": "", "prevalence": "Often"}
    assert record["modes"] == [{"phase": "Implementation", "note": "Phase note."}, {"phase": "Architecture", "note": ""}]
    assert record["likelihood"] == "High"
    assert record["consequences"] == [{"scope": ["Confidentiality", "Integrity"],
                                       "impact": ["Read Application Data", "Modify Application Data"],
                                       "likelihood": "High", "note": "Consequence note."}]
    assert record["detection"] == [{"method": "Automated Static Analysis", "description": ["Detection text."],
                                    "effectiveness": "High", "effectiveness_notes": "Detection notes."}]
    assert record["mitigations"] == [{"phases": ["Implementation", "Architecture"], "strategy": "Reduce",
                                      "description": ["Mitigation text."], "effectiveness": "High",
                                      "effectiveness_notes": "Mitigation notes."}]
    assert record["functional_areas"] == ["Demo area"] and record["affected_resources"] == ["Demo resource"]
    assert record["taxonomies"] == [{"name": "Demo taxonomy", "entry_id": "T-1", "entry_name": "Demo entry",
                                     "mapping_fit": "Exact"}]
    assert record["attack_patterns"] == ["CAPEC-209"]  # значение не CAPEC отброшено
    assert record["notes"] == [{"type": "Other", "text": "Note text."}]
    assert record["mapping_notes"] == {"usage": "Allowed", "rationale": "Rationale text.",
                                       "comments": "Comments text.", "reasons": ["Demo"]}
    assert record["observed"] == [{"reference": "CVE-2099-10001", "description": "Observed in the demo product.",
                                   "link": "https://example.org/cve-2099-10001"},
                                  {"reference": "CVE-2099-10099", "description": "Not in the BDU sample.", "link": ""}]


def test_cwe_examples_intro_text_and_code(store: FeedStore, tmp_path: Path):
    """Примеры: вступление абзацами, код построчно с отступом, «плохой» и «хороший» код разделены."""
    store.load("cwe", cwe_zip(tmp_path / "cwec_latest.xml.zip", CWE_FULL_XML), "cwec_latest.xml.zip")
    examples = store.cwe_page("CWE-2099")["record"]["examples"]
    assert [e["intro"] for e in examples] == [["Example intro."], ["Second example intro."]]
    assert [b["kind"] for b in examples[0]["blocks"]] == ["text", "code", "text", "code"]
    assert examples[0]["blocks"][0] == {"kind": "text", "paragraphs": ["Intro to bad code."]}
    assert examples[0]["blocks"][1] == {"kind": "code", "nature": "Bad", "language": "Python",
                                        "code": "value = demo_input()\nrun(value)"}
    assert examples[0]["blocks"][3]["nature"] == "Good"
    # каждая строка блока margin-left получает отступ своего уровня, xhtml:br даёт перенос строки;
    # пробелы автора сразу после xhtml:br (без перевода строки XML) – его отступ, он сохраняется
    assert examples[1]["blocks"][0]["code"] == "    int main(void) {\n        return demo();\n    }"
    assert examples[0]["refs"] == [{"ref_id": "REF-2", "section": "Page 5"}]


def test_cwe_links_and_reverse_links(store: FeedStore, tmp_path: Path):
    """Связи сохраняются как объявленные, обратные вычисляются, члены категории видны с обеих сторон."""
    store.load("cwe", cwe_zip(tmp_path / "cwec_latest.xml.zip", CWE_FULL_XML), "cwec_latest.xml.zip")
    links = store.cwe_page("CWE-2099")["links"]
    assert links["ChildOf"] == ["CWE-2098"] and links["ParentOf"] == ["CWE-2100"]
    assert links["CanPrecede"] == ["CWE-2101"] and links["PeerOf"] == ["CWE-2102"]
    # обратная связь строится из объявленной: CWE-2101 объявляет CanPrecede к CWE-2099
    assert store.cwe_page("CWE-2101")["links"]["CanFollow"] == ["CWE-2099"]
    assert store.cwe_page("CWE-2100")["links"]["ChildOf"] == ["CWE-2099"]
    assert store.cwe_page("CWE-2098")["links"]["ParentOf"] == ["CWE-2099"]
    assert store.cwe_page("CWE-2099")["links"]["MemberOf"] == ["CWE-3000"]
    category = store.cwe_page("CWE-3000")
    assert category["links"]["HasMember"] == ["CWE-2099"]
    assert category["record"]["relationships"] == [{"cwe_id": "CWE-2099", "view_id": ""}]
    assert category["record"]["summary"] == "Demo summary." and category["record"]["kind"] == "category"
    assert category["record"]["mapping_notes"]["usage"] == "Prohibited"


def test_cwe_list_index_search(store: FeedStore, tmp_path: Path):
    """Список строится по индексу: вид записи, русское название из БДУ, порядок по номеру."""
    store.load("cwe", cwe_zip(tmp_path / "cwec_latest.xml.zip", CWE_FULL_XML), "cwec_latest.xml.zip")
    store.load("bdu", bdu_zip(tmp_path / "vulxml.zip"), "vulxml.zip")
    items = store.cwe_list()
    assert [i["id"] for i in items] == ["CWE-2098", "CWE-2099", "CWE-2100", "CWE-2101", "CWE-2102", "CWE-3000"]
    assert items[-1]["kind"] == "category" and items[-1]["abstraction"] == ""
    assert items[1]["abstraction"] == "Base" and items[1]["status"] == "Stable"
    # русское название подставляется из БДУ по тому же номеру: CWE-1333 в этом каталоге нет
    assert all(i["name_ru"] == "" for i in items)


def test_cwe_refs_dictionary(store: FeedStore, tmp_path: Path):
    """Справочник ссылок: поля источника и дата из раздельных элементов даты."""
    store.load("cwe", cwe_zip(tmp_path / "cwec_latest.xml.zip", CWE_FULL_XML), "cwec_latest.xml.zip")
    refs = store.cwe_refs(["REF-1", "REF-2", "REF-404"])
    assert refs["REF-1"] == {"id": "REF-1", "authors": ["Demo Author"], "title": "Demo title", "edition": "1",
                             "publication": "Demo publication", "publisher": "Demo publisher", "date": "2098-12-05",
                             "url": "https://example.org/ref1"}
    assert refs["REF-2"]["date"] == "2099" and refs["REF-2"]["url"] == "javascript:alert(1)"
    assert "REF-404" not in refs and store.cwe_refs([]) == {}


XHTML = 'xmlns:x="http://www.w3.org/1999/xhtml"'


def test_cwe_id_accepts_only_a_whole_number():
    """Номер из адреса и запроса: вся строка – номер; цифры внутри слов номером не считаются."""
    for value in ("89", " CWE-89 ", "cwe-089", "CWE89", "Cwe - 89"):
        assert feeds.cwe_id(value) == "CWE-89", value
    for value in ("ISO 27001", "SHA1", "garbage2099tail", "CWE-209900", "89abc", "", None):
        assert feeds.cwe_id(value) == "", value


def test_cwe_paragraphs_keep_inline_markup_in_one_paragraph():
    """Строчная разметка (<b>, <i>) не дробит абзац и не расходует предел абзацев."""
    elem = feeds.ET.fromstring(f"<d {XHTML}><x:p>Use <x:b>checked</x:b> input.</x:p>Tail text.<x:br/>"
                               f"After break.<x:ul><x:li>Item</x:li></x:ul></d>")
    assert feeds._paragraphs(elem) == ["Use checked input.", "Tail text.", "After break.", "- Item"]
    many = "".join(f"w{i} <x:b>b{i}</x:b> " for i in range(60))
    elem = feeds.ET.fromstring(f"<d {XHTML}><x:p>{many}</x:p><x:p>FINAL_ADVICE</x:p></d>")
    assert len(feeds._paragraphs(elem)) == 2 and feeds._paragraphs(elem)[-1] == "FINAL_ADVICE"
    # таблица – отдельными абзацами по строкам, ячейки через « | », <br/> внутри ячейки – пробел
    elem = feeds.ET.fromstring(f"<d {XHTML}>Before.<x:table><x:tr><x:th>Register</x:th><x:th>Default</x:th></x:tr>"
                               f"<x:tr><x:td>KEY_0</x:td><x:td>AES key<x:br/>Default 0x0</x:td></x:tr></x:table></d>")
    assert feeds._paragraphs(elem) == ["Before.", "Register | Default", "KEY_0 | AES key Default 0x0"]
    code = feeds.ET.fromstring(f"<c {XHTML}><x:div>start<x:table><x:tr><x:td>a</x:td><x:td>b</x:td></x:tr>"
                               f"</x:table>end</x:div></c>")
    assert feeds._code_text(code) == "start\na | b\nend"


def test_cwe_code_keeps_author_indent_and_word_boundaries():
    """Код примера: служебные переводы строк XML не склеивают слова, отступ автора после <br/> сохраняется."""
    elem = feeds.ET.fromstring(f"<c {XHTML}><x:div>if ok:<x:br/>    run()</x:div></c>")
    assert feeds._code_text(elem) == "if ok:\n    run()"
    elem = feeds.ET.fromstring(f"<c {XHTML}><x:div>\n\t\t\t// validate that the NR\n\t\tfile only<x:br/>\n"
                               f"\t\t\t.irq_i\t\t\t(irq_i),  \n\t\t</x:div></c>")
    assert feeds._code_text(elem) == "// validate that the NR file only\n.irq_i (irq_i),"


def test_cwe_long_lists_and_category_notes(store: FeedStore, tmp_path: Path):
    """Списки записи CWE не режутся пределом БДУ (у CWE-200 – 59 шаблонов CAPEC); у категории есть Notes."""
    patterns = "".join(f'<Related_Attack_Pattern CAPEC_ID="{i}"/>' for i in range(1, 60))
    elem = feeds.ET.fromstring(f'<Weakness ID="200" Name="Demo"><Related_Attack_Patterns>{patterns}'
                               f"</Related_Attack_Patterns></Weakness>")
    assert len(feeds.parse_cwe(elem)["attack_patterns"]) == 59
    store.load("cwe", cwe_zip(tmp_path / "cwec_latest.xml.zip", CWE_FULL_XML), "cwec_latest.xml.zip")
    assert {"type": "", "text": "Category note."} in [
        {**n, "type": ""} for n in store.cwe_page("CWE-3000")["record"]["notes"]]


def test_feed_snapshot_holds_the_store_lock(store: FeedStore):
    """Пока страница читает снимком, подмена справочника (под той же блокировкой) ждёт."""
    import threading
    taken: list[bool] = []
    with store.snapshot():
        worker = threading.Thread(target=lambda: taken.append(store._lock.acquire(blocking=False)))
        worker.start()
        worker.join()
    assert taken == [False]


def test_cwe_record_of_previous_version_is_readable(store: FeedStore, tmp_path: Path):
    """Запись, оставленная прежней версией приложения, читается как раньше: связи пусты, описание строкой."""
    store.load("cwe", cwe_zip(tmp_path / "cwec_latest.xml.zip"), "cwec_latest.xml.zip")
    with store._lock:  # имитация базы, записанной прежней версией: только cwe с одним полем
        store._conn.execute('INSERT INTO feeds.cwe(id, data_json) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET data_json = EXCLUDED.data_json',
                            ("CWE-1", '{"id": "CWE-1", "name": "Old", "description": "Old description.",'
                                     ' "extended": "Old extended.", "kind": "weakness"}'))
        store._conn.execute("DELETE FROM feeds.cwe_index WHERE id = 'CWE-1'")
    page = store.cwe_page("CWE-1")
    assert page["record"]["description"] == "Old description." and page["record"]["extended"] == "Old extended."
    assert page["links"] == {} and page["name_ru"] == ""


def test_reload_replaces_and_failed_load_keeps_previous(store: FeedStore, tmp_path: Path):
    store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")
    smaller = BDU_XML.replace("CVE-2099-10001", "CVE-2099-20001")
    store.load("bdu", bdu_zip(tmp_path / "b.zip", smaller), "b.zip")
    assert "CVE-2099-10001" not in store.bdu_by_cve(["CVE-2099-10001"]) and store.bdu_by_cve(["CVE-2099-20001"])
    assert store.status()["bdu"]["filename"] == "b.zip"
    with pytest.raises(FeedError, match="DOCTYPE"):
        store.load("bdu", bdu_zip(tmp_path / "c.zip", BDU_XML.replace("<vulnerabilities>",
                                                                      "<!DOCTYPE v><vulnerabilities>", 1)), "c.zip")
    assert store.status()["bdu"]["filename"] == "b.zip" and store.counts()["bdu"] == 2
    assert store.staging_rows() == 0


@pytest.mark.parametrize("content, message", [
    (b"not a zip", "не архив ZIP"),
    (zip_bytes("readme.txt", "x"), "ровно один файл XML"),
    (zip_bytes("a.xml", "<vulnerabilities/>", {"b.xml": b"<x/>"}), "ровно один файл XML"),
    (zip_bytes("export/vulxml.xml", "<vulnerabilities></vulnerabilities>"), "нет записей"),
    (zip_bytes("export/vulxml.xml", "<vulnerabilities><vul><identifier>BDU:1"), "повреждён"),
])
def test_bad_archives_are_rejected(store: FeedStore, tmp_path: Path, content: bytes, message: str):
    path = tmp_path / "bad.zip"
    path.write_bytes(content)
    with pytest.raises(FeedError, match=message):
        store.load("bdu", path, "bad.zip")
    assert store.status() == {}


def test_compression_ratio_and_record_limits(store: FeedStore, tmp_path: Path, monkeypatch):
    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("export/vulxml.xml", b"<vulnerabilities>" + b" " * (5 * 1024 * 1024) + b"</vulnerabilities>")
    with pytest.raises(FeedError, match="сжат подозрительно"):
        store.load("bdu", bomb, "bomb.zip")
    monkeypatch.setitem(feeds.MAX_RECORDS, "bdu", 1)
    with pytest.raises(FeedError, match="Записей больше 1"):
        store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")


def test_one_load_at_a_time(store: FeedStore, tmp_path: Path):
    assert feeds._IMPORT_SLOT.acquire(blocking=False)
    try:
        with pytest.raises(FeedError, match="уже загружается"):
            store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")
    finally:
        feeds._IMPORT_SLOT.release()


# ============================================================================ страница «Справочники»

def wait_job(web, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = web.client.get("/feeds/job").json()
        if job["done"]:
            return job
        time.sleep(0.05)
    raise AssertionError("загрузка справочника не закончилась")


def upload_feed(web, kind: str, name: str, data: bytes):
    return web.client.post(f"/feeds/{kind}", headers=ORIGIN, follow_redirects=False,
                           files={"file": (name, data, "application/zip")})


def test_feeds_page_upload_and_status(web, tmp_path: Path):
    page = web.client.get("/feeds")
    assert page.status_code == 200 and 'id="feed-bdu-empty"' in page.text and "ФСТЭК России" in page.text
    assert 'href="/feeds" aria-current="page"' in page.text
    r = upload_feed(web, "bdu", "vulxml.zip", bdu_zip(tmp_path / "v.zip").read_bytes())
    assert r.status_code == 303 and r.headers["location"] == "/feeds?ok=feed_started"
    job = wait_job(web)
    assert job["state"] == "done" and "загружено записей – 2" in job["message"]
    page = web.client.get("/feeds").text
    assert 'id="feed-bdu-records">2<' in page and "vulxml.zip" in page and 'id="feed-job"' in page
    assert upload_feed(web, "cwe", "cwec_latest.xml.zip", cwe_zip(tmp_path / "c.zip").read_bytes()).status_code == 303
    assert wait_job(web)["state"] == "done"
    assert not list((web.settings.data_dir / "tmp").glob("feed-*"))  # временная копия удалена


def test_feeds_upload_errors(web, tmp_path: Path):
    r = upload_feed(web, "bdu", "vulxml.xml", b"<x/>")
    assert r.status_code == 400 and "Нужен архив .zip" in r.text
    assert upload_feed(web, "nvd", "a.zip", b"x").status_code == 404
    r = web.client.post("/feeds/bdu", headers=ORIGIN, files={"file": ("", b"", "application/zip")})
    assert r.status_code == 400 and "Выберите файл" in r.text
    # разбор не удался – ошибка в состоянии загрузки, прежний справочник не тронут
    assert upload_feed(web, "bdu", "bad.zip", b"not a zip").status_code == 303
    job = wait_job(web)
    assert job["state"] == "error" and "не архив ZIP" in job["message"]
    assert web.client.post("/feeds/bdu", files={"file": ("a.zip", b"x", "application/zip")}).status_code == 403


# ============================================================================ пределы одной записи

def lazy(head: bytes, body: Iterable[bytes], tail: bytes) -> Iterator[bytes]:
    """Поток XML кусками, которые создаются по мере чтения: сам тест не держит файл в памяти."""
    yield head
    yield from body
    yield tail


def records_of(chunks, tags=frozenset({"vul"})) -> list:
    return list(iter_records(chunks, set(tags)))


def test_one_huge_element_is_cut_while_parsing_without_memory_growth():
    piece = b"x" * (1024 * 1024)
    head = b"<vulnerabilities><vul><identifier>BDU:2099-00001</identifier><description>"
    tracemalloc.start()
    try:
        recs = records_of(lazy(head, (piece for _ in range(32)), b"</description></vul></vulnerabilities>"))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert len(recs) == 1
    record = feeds.parse_bdu(recs[0])
    assert len(record["description"]) == feeds.MAX_TEXT
    assert peak < 6 * 1024 * 1024  # 32 МБ текста прошли через разбор, а память – единицы мегабайт


def test_huge_record_is_rejected_before_it_is_accumulated(monkeypatch):
    monkeypatch.setattr(feeds, "MAX_RECORD_TEXT", 200_000)
    part = b"<p>" + b"y" * 60_000 + b"</p>"
    tracemalloc.start()
    try:
        with pytest.raises(FeedError, match="Запись справочника слишком большая"):
            records_of(lazy(b"<vulnerabilities><vul>", (part for _ in range(10_000)), b"</vul></vulnerabilities>"))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 4 * 1024 * 1024  # отказ на 200 тыс. знаков, а не после 600 МБ


def test_nesting_depth_limit():
    deep = b"<vulnerabilities><vul>" + b"<a>" * 100 + b"</a>" * 100 + b"</vul></vulnerabilities>"
    with pytest.raises(FeedError, match="глубокая вложенность"):
        records_of([deep])


def test_elements_per_record_limit(monkeypatch):
    monkeypatch.setattr(feeds, "MAX_RECORD_ELEMENTS", 100)
    data = b"<vulnerabilities><vul>" + b"<x/>" * 200 + b"</vul></vulnerabilities>"
    with pytest.raises(FeedError, match="слишком много элементов"):
        records_of([data])
    ok = b"<vulnerabilities>" + b"<vul><x/></vul>" * 500 + b"</vulnerabilities>"
    assert len(records_of([ok])) == 500  # предел – на запись, а не на файл


def test_large_bdu_inventory_imports_without_losing_following_fields(store, tmp_path):
    """Тысячи версий ПО и окружений – допустимая запись, а не XML-бомба."""
    soft = "<soft><name>Example</name><vendor>Example</vendor><version>1</version></soft>"
    xml = ("<vulnerabilities><vul><identifier>BDU:2099-90001</identifier>"
           "<vulnerable_software>" + soft * 8000 + "</vulnerable_software>"
           "<environment>" + "<env><name>Example OS</name></env>" * 10000 + "</environment>"
           "<solution>Обновить пакет.</solution><identifiers>"
           '<identifier type="CVE">CVE-2099-90001</identifier></identifiers>'
           "</vul></vulnerabilities>")
    archive = tmp_path / "large.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr("export/vulxml.xml", xml)
    meta = store.load("bdu", archive, "large.zip")
    assert meta["records"] == 1
    record = store.bdu_by_cve(["CVE-2099-90001"])["CVE-2099-90001"][0]
    assert record["solution"] == "Обновить пакет."
    assert len(record["software"]) == feeds.MAX_SOFTWARE


def test_real_element_limit_is_bounded_in_memory():
    """Настоящий предел, без подмены константы: приём границы и отказ следующего элемента."""
    tracemalloc.start()
    try:
        recs = records_of(lazy(b"<vul>", (b"<x/>" for _ in range(feeds.MAX_RECORD_ELEMENTS - 1)), b"</vul>"))
        assert len(recs[0]) == feeds.MAX_RECORD_ELEMENTS - 1
        del recs
        with pytest.raises(FeedError, match="слишком много элементов"):
            records_of(lazy(b"<vul>", (b"<x/>" for _ in range(feeds.MAX_RECORD_ELEMENTS)), b"</vul>"))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 64 * 1024 * 1024


@pytest.mark.parametrize("state", ["idle", "done", "error"])
@pytest.mark.parametrize("message", ["feed_started", "feed_cancel"])
def test_finished_feed_hides_stale_notification(web, state, message):
    job = web.app.state.feed_job
    job.state, job.message = state, "Итог загрузки" if state != "idle" else ""
    page = web.client.get(f"/feeds?ok={message}")
    assert page.status_code == 200
    assert "Файл принят: справочник загружается" not in page.text
    assert "Загрузка останавливается:" not in page.text
    if state != "idle":
        assert "Итог загрузки" in page.text


@pytest.mark.parametrize("data, message", [
    (b'<vulnerabilities><vul a="' + b"z" * 5000 + b'"/></vulnerabilities>', "длинный атрибут"),
    (b"<vulnerabilities><vul " + b" ".join(b'a%d="1"' % n for n in range(40)) + b"/></vulnerabilities>",
     "много атрибутов"),
    (b"<vulnerabilities><" + b"t" * 400 + b"/></vulnerabilities>", "длинное имя"),
])
def test_attribute_and_name_limits(data: bytes, message: str):
    with pytest.raises(FeedError, match=message):
        records_of([data])


def test_giant_construct_without_parser_events_is_rejected():
    """Огромный атрибут: разборщик копит его молча, до конца тега обработчики не вызываются."""
    piece = b"q" * (1024 * 1024)
    tracemalloc.start()
    try:
        with pytest.raises(FeedError, match="слишком длинная конструкция"):
            records_of(lazy(b'<vulnerabilities><vul a="', (piece for _ in range(64)), b'"/></vulnerabilities>'))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 16 * 1024 * 1024


def test_stored_fields_are_bounded(store: FeedStore, tmp_path: Path):
    long_url = "https://example.org/" + "a" * 2000
    sources = "\n".join([long_url] + [f"https://example.org/{n}" for n in range(100)])
    xml = BDU_XML.replace('score="7,5"', 'score="7,5' + "9" * 100 + '"').replace(
        "https://example.org/advisories/parser-1\nhttps://osv.dev/vulnerability/CVE-2099-10002", sources)
    store.load("bdu", bdu_zip(tmp_path / "v.zip", xml), "v.zip")
    record = store.bdu_by_cve(["CVE-2099-10002"])["CVE-2099-10002"][0]
    assert len(record["sources"]) == feeds.MAX_LIST and all(len(s) <= feeds.MAX_SOURCE for s in record["sources"])
    assert record["cvss3"].split(" ", 1)[0] == ("7,5" + "9" * 100)[:feeds.MAX_SCORE]


def test_record_size_in_base_is_bounded(store: FeedStore, tmp_path: Path, monkeypatch):
    monkeypatch.setattr(feeds, "MAX_RECORD_JSON", 4000)
    xml = BDU_XML.replace("Обновление программного обеспечения до версии 1.4.9 или более поздней", "р" * 5000)
    store.load("bdu", bdu_zip(tmp_path / "v.zip", xml), "v.zip")
    for (data,) in store._conn.execute("SELECT data_json FROM feeds.bdu"):
        assert len(data.encode("utf-8")) <= 4000
    assert store.bdu_by_cve(["CVE-2099-10002"])["CVE-2099-10002"][0]["solution"] == "р" * 1000
    monkeypatch.setattr(feeds, "MAX_RECORD_JSON", 100)  # меньше обязательных полей – файл не принимается
    with pytest.raises(FeedError, match="слишком большая для справочника"):
        store.load("bdu", bdu_zip(tmp_path / "w.zip", xml), "w.zip")


# ============================================================================ срок, отмена, место, сбой посередине

def tables(store: FeedStore) -> set[str]:
    return {r[0] for r in store._conn.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'feeds'")}


def many_records(n: int) -> str:
    return ('<?xml version="1.0" encoding="utf-8"?><vulnerabilities>'
            + "".join(f'<vul><identifier>BDU:2099-{k:05d}</identifier><identifiers><identifier type="CVE">'
                      f"CVE-2099-{k + 30000}</identifier></identifiers></vul>" for k in range(n))
            + "</vulnerabilities>")


def assert_previous_kept(store: FeedStore) -> None:
    assert store.status()["bdu"]["filename"] == "a.zip" and store.counts()["bdu"] == 2
    assert not {t for t in tables(store) if t.endswith("_new")}
    assert not feeds._IMPORT_SLOT.locked()


def test_deadline_stops_load_and_keeps_previous(store: FeedStore, tmp_path: Path):
    store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")
    with pytest.raises(FeedError, match="не уложилась"):
        store.load("bdu", bdu_zip(tmp_path / "b.zip", many_records(3000)), "b.zip", deadline_s=0)
    assert_previous_kept(store)


def test_cancel_stops_load_and_keeps_previous(store: FeedStore, tmp_path: Path, monkeypatch):
    store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")
    assert store.cancel() is False  # загрузки нет – и просить нечего
    original = feeds.parse_bdu
    calls = []

    def parse_and_cancel(elem):
        calls.append(1)
        if len(calls) == 1500:  # первая пачка уже записана
            assert store.cancel() is True
        return original(elem)

    monkeypatch.setattr(feeds, "parse_bdu", parse_and_cancel)
    with pytest.raises(FeedError, match="Загрузка остановлена"):
        store.load("bdu", bdu_zip(tmp_path / "b.zip", many_records(3000)), "b.zip")
    assert_previous_kept(store)
    monkeypatch.setattr(feeds, "parse_bdu", original)
    assert store.load("bdu", bdu_zip(tmp_path / "c.zip"), "c.zip")["records"] == 2  # следующая не отменена


def test_server_out_of_disk_and_limit_during_load(store: FeedStore, tmp_path: Path, monkeypatch):
    """Свободного места сервера приложение не видит (ADR-0133): его нехватка – отказ PostgreSQL, понятная ошибка, прежний справочник цел. Предел
    размера проверяется до каждой пачки."""
    store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")

    def no_space(*_args):
        raise psycopg.errors.DiskFull("нет места")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_fill", no_space)
        with pytest.raises(FeedError, match="закончилось место"):
            store.load("bdu", bdu_zip(tmp_path / "b.zip"), "b.zip")
    assert_previous_kept(store)
    # предел достигнут посередине: проверка перед каждой пачкой
    real, calls = store._used_bytes, {"n": 0}

    def growing():
        calls["n"] += 1
        return real() if calls["n"] < 4 else feeds.MAX_DB_BYTES + 1

    monkeypatch.setattr(store, "_used_bytes", growing)
    monkeypatch.setattr(feeds, "BATCH", 100)
    with pytest.raises(FeedError, match="загрузка остановлена"):
        store.load("bdu", bdu_zip(tmp_path / "c.zip", many_records(1000)), "c.zip")
    monkeypatch.setattr(store, "_used_bytes", real)
    assert_previous_kept(store)
    assert store.staging_rows() == 0


def test_database_size_limit(store: FeedStore, tmp_path: Path, monkeypatch):
    store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")
    monkeypatch.setattr(feeds, "MAX_DB_BYTES", 1)
    with pytest.raises(FeedError, match="Справочники выросли"):
        store.load("bdu", bdu_zip(tmp_path / "b.zip"), "b.zip")
    assert_previous_kept(store)


def test_broken_xml_after_written_batches_keeps_previous(store: FeedStore, tmp_path: Path, monkeypatch):
    store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")
    monkeypatch.setattr(feeds, "BATCH", 10)
    broken = many_records(100).replace("</vulnerabilities>", "<vul><identifier>BDU:1")
    with pytest.raises(FeedError, match="повреждён"):
        store.load("bdu", bdu_zip(tmp_path / "b.zip", broken), "b.zip")
    assert_previous_kept(store)
    assert store.bdu_by_cve(["CVE-2099-30001"]) == {}


def test_cancel_address_without_running_load(web):
    r = web.client.post("/feeds/cancel", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/feeds"
    assert web.client.post("/feeds/cancel", follow_redirects=False).status_code == 403


# ============================================================================ страницы справочника CWE

def load_cwe(web, tmp_path: Path, text: str = CWE_FULL_XML) -> None:
    r = upload_feed(web, "cwe", "cwec_latest.xml.zip", cwe_zip(tmp_path / "c.zip", text).read_bytes())
    assert r.status_code == 303
    assert wait_job(web)["state"] == "done"


def test_cwe_pages_without_catalog(web):
    """Каталог не загружен: список – пустое состояние со ссылкой на «Справочники», карточка – 404 с той же подсказкой."""
    page = web.client.get("/cwe")
    assert page.status_code == 200 and 'id="cwe-empty"' in page.text and 'href="/feeds#feed-cwe"' in page.text
    assert 'href="/cwe" aria-current="page"' in page.text  # ссылка в шапке
    for address in ("/cwe/CWE-89", "/cwe/89"):
        r = web.client.get(address)
        assert r.status_code == 404 and "Каталог CWE не загружен" in r.text and "Справочники" in r.text
    assert web.client.get("/bdu/CVE-2099-10001").status_code == 404


def test_cwe_list_search_filter_and_paging(web, tmp_path: Path, monkeypatch):
    """Список: поиск по номеру, английскому и русскому названию, фильтр вида записи, постраничность."""
    load_cwe(web, tmp_path)
    page = web.client.get("/cwe")
    assert page.status_code == 200 and 'data-page="cwe"' in page.text and 'href="/cwe/CWE-2099"' in page.text
    assert "Improper Neutralization of Demo Input" in page.text and "9.99" in page.text
    # поиск по номеру, по английскому названию и по совпадению без учёта регистра
    assert 'href="/cwe/CWE-2101"' in web.client.get("/cwe?q=2101").text
    assert 'href="/cwe/CWE-2098"' in web.client.get("/cwe?q=parent%20class").text
    assert 'href="/cwe/CWE-2102"' not in web.client.get("/cwe?q=Demo%20Parent%20Class").text
    # фильтр вида записи оставляет только категорию
    # число сводки – ссылка, таблица показывает ровно столько записей
    summary = web.client.get("/cwe").text
    for label in ("Записей в каталоге", "Weaknesses", "Categories"):
        link = re.search(r'<a class="stat stat-filter[^"]*" href="([^"]+)"[^>]*><span class="stat-label">' + label + r'</span><span class="stat-value">(\d+)</span>', summary)
        assert link, label
        target = web.client.get(html.unescape(link.group(1)).split("#")[0]).text
        assert target.count('data-label="ID"') == int(link.group(2)), label
    kinds = web.client.get("/cwe?kind=category")
    assert 'href="/cwe/CWE-3000"' in kinds.text and 'href="/cwe/CWE-2099"' not in kinds.text
    assert web.client.get("/cwe?kind=nonsense").text.count('data-label="ID"') == 6  # неизвестный фильтр не отбирает
    assert "ничего нет" in web.client.get("/cwe?q=нетакого").text
    # постраничность: в тесте на странице две записи из шести
    monkeypatch.setattr(cwe_routes, "PAGE_SIZE", 2)
    first = web.client.get("/cwe").text
    assert "Показано 2 из 6" in first and "Страница 1 из 3" in first and 'page=2' in first
    assert 'aria-current="page"' in first  # текущая страница теперь видима в номерной навигации
    second = web.client.get("/cwe?page=2").text
    assert "Страница 2 из 3" in second and 'href="/cwe/CWE-3000"' not in second and 'page=1' in second
    last = web.client.get("/cwe?page=3").text
    assert "Страница 3 из 3" in last and 'href="/cwe/CWE-3000"' in last and 'page=4' not in last
    assert "Страница 3 из 3" in web.client.get("/cwe?page=999").text  # номер за пределами – последняя страница
    assert "Страница 1 из 3" in web.client.get("/cwe?page=abc").text  # не число – первая
    assert "Показано 1 из 1" in web.client.get("/cwe?q=CWE-3000").text  # поиск сужает список
    # переход по страницам сохраняет фильтр и поиск
    filtered = web.client.get("/cwe?kind=weakness&q=demo").text
    assert "kind=weakness" in filtered and "q=demo" in filtered and "page=2" in filtered


def test_cwe_detail_sections_and_navigation(web, tmp_path: Path):
    """Карточка класса: разделы страницы, ссылки внутрь приложения, код примера, источники, экранирование."""
    load_cwe(web, tmp_path)
    for address in ("/cwe/CWE-2099", "/cwe/2099"):
        page = web.client.get(address)
        assert page.status_code == 200, address
        text = page.text
        assert 'data-page="cwe"' in text and "Improper Neutralization of Demo Input" in text
        # заголовки разделов – как у MITRE (содержимое и разделы – как в источнике)
        for header in ("Description", "Extended Description", "Alternate Terms", "Relationships", "Applicable Platforms",
                       "Modes Of Introduction", "Likelihood Of Exploit", "Common Consequences", "Detection Methods",
                       "Potential Mitigations", "Demonstrative Examples", "Observed Examples", "Taxonomy Mappings",
                       "Notes", "References"):
            assert f">{header}<" in text, header
        # связи – переходами внутри приложения, в том числе вычисленные обратные
        assert 'href="/cwe/CWE-2098"' in text and 'href="/cwe/CWE-2101"' in text
        # примеры: код в моноширинном блоке, плохой и хороший помечены рамкой
        assert 'class="cwe-code cwe-code-err"' in text and 'class="cwe-code cwe-code-ok"' in text
        assert "value = checked(demo_input())" in text and "bad code" in text and "good code" in text
        # источники из справочника ссылок, внешний адрес – ссылкой с условиями использования в подвале
        assert "Demo title" in text and 'href="https://example.org/ref1" rel="noopener noreferrer"' in text
        assert "termsofuse.html" in text and "условиям использования CWE" in text
    # текст каталога экранируется: разметка из выгрузки не попадает в страницу как элементы
    assert "<script>alert(1)</script>" not in text and "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert 'href="javascript:alert(1)"' not in text  # адрес из REF-2 не проходит правило norm_link
    assert "Demo title 2" in text and "REF-2" in text  # источник примера показан номером и названием
    page = web.client.get("/cwe/CWE-3000").text
    assert "Demo summary." in page and 'href="/cwe/CWE-2099"' in page  # категория: состав и краткое описание


def test_cwe_detail_missing_and_old_record(web, tmp_path: Path):
    """Несуществующий номер – 404; запись прежней версии приложения открывается с подсказкой о перезагрузке."""
    load_cwe(web, tmp_path)
    r = web.client.get("/cwe/CWE-4040")
    assert r.status_code == 404 and "Такого класса в каталоге нет" in r.text
    with web.app.state.feeds._lock:  # запись без новых полей, как её оставляла прежняя версия
        web.app.state.feeds._conn.execute(
            'INSERT INTO feeds.cwe(id, data_json) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET data_json = EXCLUDED.data_json',
            ("CWE-2097", '{"id": "CWE-2097", "name": "Old class", "description": "Old description.",'
                         ' "extended": "Old extended.", "kind": "weakness"}'))
    page = web.client.get("/cwe/CWE-2097").text
    assert 'id="cwe-old"' in page and "Перезагрузите каталог CWE" in page
    assert "Old description." in page and "Old extended." in page and 'id="cwe-examples-title"' not in page


def test_bdu_page_from_observed_example(web, tmp_path: Path):
    """Наблюдаемый пример ведёт на страницу БДУ по CVE внутри приложения, если запись есть; иначе – текст."""
    load_cwe(web, tmp_path)
    assert upload_feed(web, "bdu", "vulxml.zip", bdu_zip(tmp_path / "v.zip").read_bytes()).status_code == 303
    assert wait_job(web)["state"] == "done"
    text = web.client.get("/cwe/CWE-2099").text
    assert 'href="/bdu/CVE-2099-10001"' in text  # запись БДУ по этому номеру есть
    assert '>CVE-2099-10099<' in text and 'href="/bdu/CVE-2099-10099"' not in text  # записи нет
    page = web.client.get("/bdu/CVE-2099-10002")
    assert page.status_code == 200 and "BDU:2099-00001" in page.text and 'data-page="bdu"' in page.text
    assert 'href="https://example.org/advisories/parser-1"' in page.text
    assert 'href="/cwe/CWE-1333"' in page.text  # классы CWE в записи БДУ – ссылками
    assert "Как устранить" in page.text and "example-parser" in page.text
    assert web.client.get("/bdu/CVE-2099-10001").status_code == 200  # вторая запись БДУ по другому номеру
    assert web.client.get("/bdu/CVE-2099-99999").status_code == 404
    assert web.client.get("/bdu/не-cve").status_code == 404


def test_cwe_detail_russian_name_and_strict_address(web, tmp_path: Path):
    """Русское название из БДУ – рядом с английским при совпадении номера; адрес принимает только номер целиком,
    поиск со словами и цифрами («ISO 27001») ищет по названиям."""
    load_cwe(web, tmp_path, CWE_XML)
    assert upload_feed(web, "bdu", "vulxml.zip", bdu_zip(tmp_path / "v.zip").read_bytes()).status_code == 303
    assert wait_job(web)["state"] == "done"
    page = web.client.get("/cwe/CWE-1333")
    assert page.status_code == 200
    assert "Inefficient Regular Expression Complexity" in page.text
    assert "Неэффективная сложность регулярного выражения" in page.text and "название по БДУ ФСТЭК России" in page.text
    assert web.client.get("/cwe/cwe-01333").status_code == 200 and web.client.get("/cwe/1333").status_code == 200
    for address in ("/cwe/garbage1333tail", "/cwe/CWE-133300", "/cwe/1333abc"):
        assert web.client.get(address).status_code == 404, address
    found = web.client.get("/cwe?q=Regular%20Expression%201333").text  # слова с номером – поиск по названию
    assert 'href="/cwe/CWE-1333"' not in found
    found = web.client.get("/cwe?q=CWE-1333").text
    assert 'href="/cwe/CWE-1333"' in found and 'href="/cwe/CWE-89"' not in found


def test_cwe_links_in_findings_pages(web, tmp_path: Path):
    """Номер CWE в карточке находки, в списке находок, в таблице SCA и в карточке SCA – переход в справочник."""
    load_cwe(web, tmp_path, CWE_XML)  # в демонстрационной выгрузке номер CWE-89
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx")).status_code == 303
    card = web.client.get(f"/projects/{pid}/findings/1")
    assert card.status_code == 200, card.text
    assert 'href="/cwe/CWE-89?origin=' in card.text and "Класс слабости (CWE)" in card.text
    listing = web.client.get(f"/projects/{pid}/findings")
    assert listing.status_code == 200 and 'href="/cwe/CWE-89?origin=' in listing.text
    table = web.client.get(f"/projects/{pid}/sca")
    assert table.status_code == 200 and 'href="/cwe/CWE-1333?origin=' in table.text
    sca_card = web.client.get(re.search(r'href="(/projects/\d+/sca/findings/[^"]+)"', table.text).group(1))
    assert sca_card.status_code == 200, sca_card.text
    assert 'id="cwe-info"' in sca_card.text and 'href="/cwe/CWE-1333?origin=' in sca_card.text


def test_templates_have_no_safe_filter():
    """Новые страницы справочника выводят данные каталога автоэкранированием шаблона: фильтр |safe не применяется."""
    offenders = []
    for path in sorted((Path(__file__).resolve().parents[1] / "app" / "templates" / "cwe").glob("*.html")):
        if "|safe" in path.read_text(encoding="utf-8"):
            offenders.append(path.name)
    assert offenders == []

"""Маска принадлежности (ADR-0118): слова организации заменяются на границе отправки модели – в любом запросе;
карточка и база хранят код как есть."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent
for folder in (ROOT, TESTS):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from app import affiliation, model_traffic  # noqa: E402
from app.config import ConfigError, Settings, normalize_setting  # noqa: E402
from app.settings_store import save  # noqa: E402
from fake_ollama import verdict_answer  # noqa: E402
from test_triage import Env, env, sast  # noqa: E402, F401

WORDS = ("Exampletown", "ACME", "Контор*", "exampleorg")


@pytest.fixture
def words():
    affiliation.configure(WORDS)
    return WORDS


def test_words_match_whole_words_and_identifier_parts(words):
    assert affiliation.mask_text("AcmeRuClient calls acme.example and ACME_KEY") == \
        "OrgRuClient calls org.example and ORG_KEY"
    assert affiliation.mask_text("getACMEData from exampletown-billing") == "getORGData from org-billing"
    assert affiliation.mask_text("Конторы и КОНТОРА, контора") == "Орг и ОРГ, орг", "«*» – по началу слова"
    assert affiliation.mask_text("src/exampleorg/Exampletown.java:12") == "src/org/Org.java:12"


def test_other_words_are_left_alone(words):
    text = "acmeist Acmeist example.org Contora"
    assert affiliation.mask_text(text) == text
    assert affiliation.mask_text("") == ""


def test_without_words_the_text_and_payload_are_the_same_objects():
    affiliation.configure(())
    payload = {"messages": [{"role": "user", "content": "Exampletown"}]}
    assert affiliation.mask_payload(payload) is payload
    assert affiliation.mask_text("ACME") == "ACME" and not affiliation.active()


def test_payload_masks_messages_and_system_but_not_protocol_fields(words):
    """Круг 1 Codex: имя модели, схема ответа, инструменты и роли – как есть, иначе запрос уйдёт к несуществующей
    модели или с противоречивой схемой; текст для модели – сообщения (и блоки Messages API) и system."""
    payload = {"model": "acme-coder:latest",
               "messages": [{"role": "user", "content": "class AcmeService {}"},
                            {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "acme"}}]},
                            {"role": "tool", "content": "page about Exampletown"},
                            {"role": "user", "content": [{"type": "text", "text": "ACME_HOST"},
                                                         {"type": "tool_result", "tool_use_id": "acme1",
                                                          "content": [{"type": "text", "text": "Контора"}]}]}],
               "system": [{"type": "text", "text": "Acme rules"}],
               "options": {"num_ctx": 4096},
               "format": {"properties": {"acme": {"enum": ["ACME", "x"]}}, "required": ["acme"]},
               "tools": [{"type": "function", "function": {"name": "acme", "description": "ACME search"}}]}
    masked = affiliation.mask_payload(payload)
    assert masked["messages"][0]["content"] == "class OrgService {}"
    assert masked["messages"][1]["tool_calls"] == payload["messages"][1]["tool_calls"], "вызовы инструментов – как есть"
    assert masked["messages"][2]["content"] == "page about Org"
    blocks = masked["messages"][3]["content"]
    assert blocks[0]["text"] == "ORG_HOST" and blocks[1]["tool_use_id"] == "acme1"
    assert blocks[1]["content"][0]["text"] == "Орг"
    assert masked["system"] == [{"type": "text", "text": "Org rules"}]
    for key in ("model", "options", "format", "tools"):
        assert masked[key] == payload[key], key
    assert payload["messages"][0]["content"] == "class AcmeService {}", "исходный объект не меняется"
    assert affiliation.mask_payload({"system": "ACME", "prompt": "ACME"}) == {"system": "ORG", "prompt": "ACME"}
    assert affiliation.mask_payload(["ACME"]) == ["ACME"], "не словарь – как есть"


def test_words_of_any_alphabet_split_by_unicode_case():
    """Круг 1 Codex: диакритика и другие алфавиты – части по регистру Unicode, а не только ASCII и кириллица."""
    affiliation.configure(("Café", "München", "CAF"))
    assert affiliation.mask_text("Café café CAFÉ MünchenClient getMÜNCHENData") == \
        "Org org ORG OrgClient getORGData"
    assert affiliation.mask_text("cafés Cafe caf") == "cafés Cafe org", "без «*» – только целиком"
    assert affiliation._parts("getACMEData") == ["get", "ACME", "Data"]
    assert affiliation._parts("日本語acme") == ["日本語acme"], "буквы без регистра границ не дают"


def test_osv_client_sends_package_names_unmasked(words):
    """Круг 2 Codex: проверяется отправленное тело, а не только флаг – OSV получает имя пакета как есть, клиент
    модели тем же транспортом – с маской."""
    import http.server
    import threading

    from app import osv
    from app.llm_chat import ChatCompletionsClient
    from app.llm_http import ServerClient
    got: list[bytes] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            got.append(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
            body = b'{"vulns": []}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        client = osv.make_client(url)
        assert client.affiliation_mask is False
        client.post_json("/v1/query", {"package": {"name": "@acme/ui", "ecosystem": "npm"}, "version": "1.0.0"},
                         timeout=5)
        assert b"@acme/ui" in got[-1] and b"org" not in got[-1]
        model = ChatCompletionsClient(url)
        model.trust = "local"  # адрес этого компьютера, как у клиента OSV в тестах
        assert getattr(ServerClient(url), "affiliation_mask", True) is True
        model.post_json("/v1/query", {"messages": [{"role": "user", "content": "@acme/ui"}]}, timeout=5)
        assert b"@org/ui" in got[-1] and b"acme" not in got[-1]
    finally:
        server.shutdown()
        server.server_close()


def test_setting_is_checked_and_deduplicated():
    assert normalize_setting("affiliation_words", "Exampletown, ACME*; exampletown\n Контора") == \
        ("Exampletown", "ACME*", "Контора")
    assert normalize_setting("affiliation_words", ["ACME", ""]) == ("ACME",)
    assert normalize_setting("affiliation_words", "") == ()
    for bad in ("x", "example.org", "ex*ample", "a" * 51, "12ab", "ACME**"):
        with pytest.raises(ConfigError, match="Слова принадлежности"):
            normalize_setting("affiliation_words", bad)
    with pytest.raises(ConfigError, match="не больше 200"):
        normalize_setting("affiliation_words", [f"w{i:03d}".replace("0", "o").replace("1", "i")
                                                .replace("2", "z").replace("3", "e").replace("4", "a")
                                                .replace("5", "s").replace("6", "b").replace("7", "t")
                                                .replace("8", "g").replace("9", "q") for i in range(201)])
    assert Settings().editable()["affiliation_words"] == []
    assert Settings().with_stored({"affiliation_words": ["ACME", "bad word"]}).affiliation_words == ()
    assert Settings().with_stored({"affiliation_words": ["ACME"]}).affiliation_words == ("ACME",)


def journal_requests(recorder: model_traffic.Recorder) -> list[dict]:
    events = []
    for path in sorted(recorder.folder.glob("*.jsonl")) if recorder.folder.is_dir() else []:
        events += [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [e for e in events if e.get("event") == "request" and str(e.get("url", "")).endswith("/api/chat")]


def test_run_sends_masked_text_and_the_journal_keeps_what_was_sent(env: Env, tmp_path: Path):
    affiliation.configure(("Exampletown", "ACME*", "Контора"))
    recorder = model_traffic.Recorder(tmp_path / "data" / "model-traffic")
    model_traffic.set_recorder(recorder)
    try:
        env.fake.answers = [verdict_answer("true_positive", 90)]
        rule = "Внедрение SQL-кода в AcmeRepo (Контора, exampletown-billing)"
        env.load([sast("A", 15, rule=rule)])
        run = env.run()
        assert run["state"] == "done"
        sent = json.dumps(env.fake.chats()[0], ensure_ascii=False)
        for word in ("Acme", "ACME", "Контора", "xampletown"):
            assert word not in sent, word
        assert "OrgRepo (Орг, org-billing)" in sent
        request = journal_requests(recorder)[0]
        assert "AcmeRepo" not in request["body"] and "OrgRepo (Орг, org-billing)" in request["body"]
        # база приложения хранит находку как есть: маска – только на границе отправки
        stored = env.db.case_input(env.project_id, "A")
        assert stored["data"]["rule"] == rule
    finally:
        model_traffic.set_recorder(None)


def test_saving_settings_applies_the_words_at_once(env: Env):
    assert not affiliation.active()
    save(env.db, env.settings, {"affiliation_words": ("ACME",)})
    assert affiliation.words() == ("ACME",) and affiliation.mask_text("AcmeService") == "OrgService"
    assert env.settings.with_stored(env.db.get_settings()).affiliation_words == ("ACME",)
    save(env.db, env.settings, {"affiliation_words": ()})
    assert not affiliation.active()

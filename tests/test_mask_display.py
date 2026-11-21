"""Маскирование секретов при показе – флажок проекта (0.10.0.dev14, ADR-0141). Модели код уходит с
масками всегда; срезы, отпечатки и решения от флажка не зависят. Данные выдуманные."""

import json
import re

from app import mask_display, masking
from app.models import Finding
from test_display_window import card_of
from test_web import ORIGIN, prepared, start_run, wait_run, web  # noqa: F401

SECRET = "Zx9-SuperSecretValue-77"
EXTRA = "Qw7-OtherColumnSecret-52"


def plant_secret(web, pid) -> None:
    """Строка с паролем рядом со строкой находки 510001 в демо-клоне."""
    db = web.app.state.db
    row = db._one("SELECT data_json FROM findings WHERE project_id=? AND hub_id='510001'", (pid,))
    f = Finding.from_dict(json.loads(row["data_json"]))
    path = web.tmp / "repos" / "team" / "billing-core" / f.file
    lines = path.read_text(encoding="utf-8").split("\n")
    lines[f.line] = f'        String password = "{SECRET}";'  # строка сразу после строки срабатывания
    path.write_text("\n".join(lines), encoding="utf-8")


def params(web, pid, *, mask: bool):
    data = {"name": "Демо", "model": "", "mask_form": "1", **({"mask_secrets": "1"} if mask else {})}
    r = web.client.post(f"/projects/{pid}/params", data=data, headers=ORIGIN, follow_redirects=False)
    assert r.status_code in (302, 303), r.text


def test_new_projects_and_old_ones_show_masks_by_default(web):
    db = web.app.state.db
    pid = prepared(web)
    assert db.get_project(pid)["mask_secrets"] == 1, "прежние и новые проекты – с масками, пока оператор не снимет"
    r = web.client.post("/projects", data={"name": "Без поля"}, headers=ORIGIN, follow_redirects=False)
    default = int(r.headers["location"].split("/projects/")[1].split("?")[0])
    assert db.get_project(default)["mask_secrets"] == 1, "без поля формы – по умолчанию с масками"
    r = web.client.post("/projects", data={"name": "Без масок", "mask_form": "1"}, headers=ORIGIN, follow_redirects=False)
    plain = int(r.headers["location"].split("/projects/")[1].split("?")[0])
    assert db.get_project(plain)["mask_secrets"] == 0
    r = web.client.post("/projects", data={"name": "С масками", "mask_form": "1", "mask_secrets": "1"}, headers=ORIGIN,
                        follow_redirects=False)
    masked = int(r.headers["location"].split("/projects/")[1].split("?")[0])
    assert db.get_project(masked)["mask_secrets"] == 1
    assert mask_display.masked(None) and mask_display.masked({}) and not mask_display.masked({"mask_secrets": 0})


def test_toggle_shows_plain_file_but_model_case_and_review_stay_masked(web):
    db = web.app.state.db
    pid = prepared(web)
    plant_secret(web, pid)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    before = db.get_case(pid, "510001")
    assert before and SECRET not in json.dumps(before["context"], ensure_ascii=False), "срез разбора – с маской"
    calls = len(web.fake.chats())
    card = card_of(web, pid, "510001")
    assert SECRET not in card and 'id="code-plain"' not in card
    assert "показ кода с масками" in web.client.get(f"/projects/{pid}").text
    db.save_review(pid, "510001", decision="agree", final_verdict="false_positive",
                   final_comment="Значение – тестовая заглушка, в рабочей конфигурации не используется.", reviewed=True)
    review = db.get_review(pid, "510001")

    params(web, pid, mask=False)
    assert db.get_project(pid)["mask_secrets"] == 0
    card = card_of(web, pid, "510001")
    assert 'id="code-plain"' in card and SECRET in card, "текущий файл в клоне – без масок"
    assert "показ кода без масок" in web.client.get(f"/projects/{pid}").text
    assert db.get_case(pid, "510001") == before, "отпечаток и срез разбора не меняются"
    assert db.get_review(pid, "510001") == review, "решение и «Проверено» не меняются"
    assert len(web.fake.chats()) == calls, "модель не вызывалась"

    # новый разбор при снятом флажке (fresh – без кэша): в новых запросах модели литерала нет (ревью dev14, круг 1)
    assert wait_run(web, start_run(web, pid, fresh="1"))["state"] == "done"
    fresh = web.fake.chats()[calls:]
    assert fresh, "разбор действительно обратился к модели"
    for chat in fresh:
        assert SECRET not in json.dumps(chat, ensure_ascii=False), "модели – всегда с масками"

    params(web, pid, mask=True)
    card = card_of(web, pid, "510001")
    assert SECRET not in card and 'id="code-plain"' not in card


def test_export_line_and_extra_follow_the_flag():
    f = Finding(hub_id="1", kind="SAST", file="A.java", line=3, language="Java", rule="Пароль в коде", cwe=["CWE-798"],
                snippet=f'String password = "{SECRET}";', extra={"Комментарий": f'password = "{SECRET}"'})
    key = b"k" * 32
    assert SECRET not in mask_display.export_line(f, key, {"mask_secrets": 1})
    assert SECRET in mask_display.export_line(f, key, {"mask_secrets": 0})
    assert mask_display.export_line(f, None, {"mask_secrets": 0}) != "", "без маски строка не пропадает"


EXTRA_SECRET = "Qw7-ExtraFieldSecret-31"


def put_extra(db, pid, kind):
    """Пароль в прочей колонке выгрузки у первой находки нужного типа; вернуть (hub_id, номер строки)."""
    row = db._one("SELECT id, hub_id, data_json FROM findings WHERE project_id=? AND kind=? ORDER BY id LIMIT 1", (pid, kind))
    data = json.loads(row["data_json"])
    data["extra"] = {**(data.get("extra") or {}), "Комментарий": f'password = "{EXTRA_SECRET}"'}
    with db._tx() as c:
        c.execute("UPDATE findings SET data_json=? WHERE id=?", (json.dumps(data, ensure_ascii=False), row["id"]))
    return row["hub_id"], row["id"]


def test_extra_fields_sast_and_sca_follow_the_flag_and_params_without_field_keep_it(web):
    """Ревью Kimi dev14, круг 2: прочие колонки выгрузки в карточках SAST и SCA – по флажку; сохранение параметров без
    поля флажка (старая форма) значение не меняет."""
    db = web.app.state.db
    pid = prepared(web)
    _, sast_id = put_extra(db, pid, "SAST")
    _, sca_id = put_extra(db, pid, "SCA")
    sast_url, sca_url = f"/projects/{pid}/findings/{sast_id}", f"/projects/{pid}/sca/findings/{sca_id}"
    for url in (sast_url, sca_url):
        page = web.client.get(url)
        assert page.status_code == 200 and EXTRA_SECRET not in page.text, url
    params(web, pid, mask=False)
    for url in (sast_url, sca_url):
        assert EXTRA_SECRET in web.client.get(url).text, ("без масок – исходное поле", url)
    r = web.client.post(f"/projects/{pid}/params", data={"name": "Демо", "model": ""}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code in (302, 303) and db.get_project(pid)["mask_secrets"] == 0, "без поля формы значение прежнее"
    params(web, pid, mask=True)
    r = web.client.post(f"/projects/{pid}/params", data={"name": "Демо", "model": ""}, headers=ORIGIN, follow_redirects=False)
    assert db.get_project(pid)["mask_secrets"] == 1


def test_plain_panel_names_reason_when_line_is_out_of_file(web):
    """Ревью Codex dev14, круг 8: файл есть, но строка находки за его пределами – панель называет причину, а не «файла
    нет»."""
    db = web.app.state.db
    pid = prepared(web)
    row = db._one("SELECT data_json FROM findings WHERE project_id=? AND hub_id='510001'", (pid,))
    f = Finding.from_dict(json.loads(row["data_json"]))
    (web.tmp / "repos" / "team" / "billing-core" / f.file).write_text("class A {}\n", encoding="utf-8")
    params(web, pid, mask=False)
    card = card_of(web, pid, "510001")
    assert 'id="code-plain-missing"' in card and "за пределами файла" in card, "причина недоступности названа"
    assert "текущего файла в клоне нет" not in card


LABEL = re.compile(r"<SECRET_[0-9a-f]{6}>")
UNKNOWN = "<SECRET_000000>"


def test_model_text_labels_are_revealed_only_without_the_flag(web):
    """Бэклог 111: модель видела код с метками, её ответ хранится с метками. При снятом флажке карточка показывает в
    «Подробностях разбора» значение на месте метки, когда его даёт текущий файл клона; метка, которой там нет,
    остаётся меткой с подписью. Вердикт в базе, срез разбора и поля форм не меняются; при флажке – только метки."""
    db = web.app.state.db
    pid = prepared(web)
    plant_secret(web, pid)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    case = db.get_case(pid, "510001")
    label = re.search(r'password = \\"(<SECRET_[0-9a-f]{6}>)', json.dumps(case["context"], ensure_ascii=False)).group(1)
    data = {**case["verdict"]["data"], "what_code_does": f"Пароль задан литералом {label}.",
            "why": [f"Значение {label} стоит прямо в коде.", f"Метка {UNKNOWN} – из другого места."],
            "data_flow": [f"{label} уходит в подключение к базе."], "explanation": f"Литерал {label} в коде."}
    with db._tx() as c:
        c.execute("UPDATE verdicts SET data_json = ? WHERE id = ?", (json.dumps(data, ensure_ascii=False), case["verdict"]["id"]))
    stored = db.get_case(pid, "510001")
    escaped = label.replace("<", "&lt;").replace(">", "&gt;")  # так метка выглядит в HTML карточки

    def details(card: str) -> str:
        return card.split('id="verdict-more"', 1)[1].split("</details>", 1)[0]

    card = card_of(web, pid, "510001")
    assert escaped in details(card) and SECRET not in card
    assert 'id="labels-note"' not in card, "флажок включён – ничего не раскрывается и подписи нет"

    params(web, pid, mask=False)
    card = card_of(web, pid, "510001")
    shown = details(card)
    assert f"Пароль задан литералом {SECRET}." in shown and f"Значение {SECRET} стоит прямо в коде." in shown
    assert f"{SECRET} уходит в подключение к базе." in shown
    assert escaped not in shown.split('id="labels-note"')[0], "известная метка заменена везде"
    assert UNKNOWN.replace("<", "&lt;").replace(">", "&gt;") in shown.split('id="labels-note"')[0], "неизвестная осталась"
    note = shown.split('id="labels-note"', 1)[1].split("</p>", 1)[0]
    assert "заменены значениями" in note and 'id="labels-left"' in note and "SECRET_000000" in note
    assert "значение в базе не хранится" in note and label[1:-1] not in note
    for field in re.findall(r"<textarea[^>]*>(.*?)</textarea>", card, re.S) + re.findall(r'value="([^"]*)"', card):
        assert SECRET not in field, "в поля форм значение не попадает"
    assert db.get_case(pid, "510001") == stored, "вердикт и срез разбора в базе – с метками, как были"
    assert SECRET not in json.dumps(db.get_case(pid, "510001"), ensure_ascii=False, default=str)

    # код изменился: значения в текущем файле больше нет – метка остаётся меткой
    f = Finding.from_dict(json.loads(db._one("SELECT data_json FROM findings WHERE project_id=? AND hub_id='510001'",
                                              (pid,))["data_json"]))
    path = web.tmp / "repos" / "team" / "billing-core" / f.file
    path.write_text(path.read_text(encoding="utf-8").replace(SECRET, "Other-Value-000-Different"), encoding="utf-8")
    shown = details(card_of(web, pid, "510001"))
    assert SECRET not in shown and escaped in shown.split('id="labels-note"')[0]
    assert label[1:-1] in shown.split('id="labels-left"', 1)[1]

    params(web, pid, mask=True)
    card = card_of(web, pid, "510001")
    assert SECRET not in card and 'id="labels-note"' not in card


def test_label_values_come_from_the_export_line_and_never_with_the_flag():
    """Метка из строки выгрузки раскрывается и без клона; метка из кода при отвязанном клоне – нет; при включённом
    флажке и у SCA словарь пуст."""
    key = b"k" * 32
    off, on = {"mask_secrets": 0}, {"mask_secrets": 1}
    f = Finding(hub_id="1", kind="SAST", file="A.java", line=3, language="Java", rule="SQL-инъекция", cwe=["CWE-89"],
                snippet=f'String password = "{SECRET}";', extra={"Комментарий": f'token = "{EXTRA}"'})
    label = LABEL.search(mask_display.export_line(f, key, on)).group(0)
    values = mask_display.label_values(off, None, f, key)
    assert values == {label: SECRET}, "клона нет – только строка выгрузки"
    assert mask_display.reveal(f"литерал {label} и {UNKNOWN}", values) == f"литерал {SECRET} и {UNKNOWN}"
    assert mask_display.label_values(on, None, f, key) == {} and mask_display.label_values(None, None, f, key) == {}
    assert mask_display.label_values(off, None, f, None) == {}, "без ключа маскирования раскрывать нечем"
    sca = Finding(hub_id="2", kind="SCA_S", file="pom.xml", line=1, snippet=f.snippet)
    assert mask_display.label_values(off, None, sca, key) == {}
    # прочие колонки выгрузки – через переданную функцию маскирования
    extra_label = LABEL.search(masking.mask_text(f.extra["Комментарий"], key)[0]).group(0)
    values = mask_display.label_values(off, None, f, key, also=[lambda: masking.mask_text(f.extra["Комментарий"], key)])
    assert values == {label: SECRET, extra_label: EXTRA}
    # находка о секрете в коде: строка выгрузки скрыта целиком – значение метки – вся строка
    cred = Finding(hub_id="3", kind="SAST", file="A.java", line=3, language="Java", rule="Пароль в коде",
                   cwe=["CWE-798"], snippet=f'String password = "{SECRET}";')
    whole = LABEL.search(mask_display.export_line(cred, key, on)).group(0)
    assert SECRET in mask_display.label_values(off, None, cred, key)[whole]

    note = mask_display.labels_note
    verdict = type("V", (), {"what_code_does": f"{label}", "why": [f"{UNKNOWN}", "без меток"], "data_flow": [],
                             "explanation": ""})()
    assert note(off, verdict, {label: SECRET}) == {"revealed": 1, "left": [UNKNOWN]}
    assert note(on, verdict, {label: SECRET}) is None and note(off, None, {}) is None
    plain = type("V", (), {"what_code_does": "меток нет", "why": [], "data_flow": [], "explanation": ""})()
    assert note(off, plain, {}) is None
    # метка только в поле, которое карточка у такого вердикта не показывает, в подпись не попадает (ревью 10.11)
    hidden = type("V", (), {"what_code_does": "меток нет", "why": [], "data_flow": [], "explanation": UNKNOWN})()
    assert note(off, hidden, {}) is None
    old = type("V", (), {"what_code_does": "", "why": [], "data_flow": [label], "explanation": UNKNOWN})()
    assert note(off, old, {label: SECRET}) == {"revealed": 1, "left": [UNKNOWN]}


def test_recording_keeps_values_only_inside_and_drops_colliding_labels(monkeypatch):
    key = b"k" * 32
    with masking.recording() as book:
        masked = masking.mask_text(f'password = "{SECRET}"', key)[0]
    label = LABEL.search(masked).group(0)
    assert book == {label: SECRET}
    masking.mask_text(f'password = "{EXTRA}"', key)
    assert book == {label: SECRET}, "вне recording() значения не запоминаются"
    monkeypatch.setattr(masking, "_number", lambda key, value: "abcdef")
    with masking.recording() as book:
        masking.mask_text(f'password = "{SECRET}"\ntoken = "{EXTRA}"\npassword = "{SECRET}"', key)
    assert book == {"<SECRET_abcdef>": None}, "у двух значений одна метка – по ней значение не восстановить"
    assert mask_display.reveal("<SECRET_abcdef>", {k: v for k, v in book.items() if v is not None}) == "<SECRET_abcdef>"

"""Этап 3.2: замечания контрольной независимой проверки версии 0.3.1 (docs/state/review-stage-3.md).

Проверяется поведение, а не текст сценариев:
* SCA: при «Согласен с агентом» в дефект идёт исправленный человеком комментарий; решение сверяется с текущей версией
  находки и признаком «нет в выгрузке»; пропавшая находка в дефект не попадает; разные итоги в группе библиотеки
  блокируют общий дефект; шаги обновления базы 3 → 4 → 5 не подтверждают соответствия AST → CVE без истории;
* пакет SCA: сомнительные имена (правила экосистемы, «папка/имя», внутреннее название) уходят агенту только после
  подтверждения человеком, сервер принимает подтверждение только для имён из текущего списка сомнительных;
* справочники: общий бюджет текста и атрибутов записи, проверка места до записи пачки, сбой создания таблиц и подмены,
  место после неудачной загрузки возвращается;
* оценка токенов: ответ модели не принимается, если по её счёту промпт длиннее окна;
* образ ВМ: сценарий доступа по сети (Git Bash, поддельные ufw и iptables) открывает порт только после проверки
  ограничения и возвращается к 127.0.0.1 при отказе; файл пароля – только для владельца.
"""

from __future__ import annotations

import io
import html
import os
import psycopg
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from app import feeds
from app import sca as sca_logic
from app.db import Database
from app.feeds import FeedError, FeedStore
from app.models import Finding, ScaAnswer
from app.routes import sca as sca_routes
from feed_fixtures import bdu_zip
from hub_fixtures import SCA_BASE, SCA_ROWS, make_hub_xlsx
from test_db_stage2 import load, sca
from test_feeds import assert_previous_kept, many_records
from test_triage import Env, sast
from test_web import ORIGIN, create_project, upload, web  # noqa: F401
from fake_ollama import FakeOllama

ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / "deploy" / "vm"
COMPONENT = "org.example:example-parser"


# ============================================================================ SCA: решения и дефект

@pytest.fixture
def sca_env(tmp_path: Path):
    db = Database(tmp_path / "triage.db")
    store = FeedStore(tmp_path / "feeds.db")
    pid = db.create_project("Проект")
    load(db, pid, [sca("1", vuln="AST-1"), sca("2", vuln="AST-2")])
    answer = ScaAnswer(component=COMPONENT, version="1.4.2", conclusion="update", recommended_version="1.4.9",
                       explanation="Пояснение агента: исправлено в 1.4.9.", ids={"AST-1": ["CVE-2099-0001"]},
                       vulnerabilities=["AST-1", "AST-2"])
    db.save_sca_answers(pid, "Агент", [answer])
    yield db, store, pid
    store.close()
    db.close()


def finding(db: Database, pid: int, hub_id: str) -> Finding:
    return Finding.from_dict(db.get_finding_by_hub_id(pid, hub_id)["data"])


def agree(db: Database, pid: int, hub_id: str, comment: str | None = None) -> str:
    """«Согласен с агентом» по текущему ответу; comment=None – предложенный комментарий без правок."""
    f = finding(db, pid, hub_id)
    latest = sca_routes._latest_answer(db, pid, f)
    ids = sca_logic.finding_ids(f)
    suggestion = sca_logic.suggested_comment(f, latest, sca_logic.aliases_for(ids, db.ast_map(ids), latest))
    db.save_review(pid, hub_id, decision="agree", final_verdict="true_positive",
                   final_comment=suggestion if comment is None else comment, reviewed=True,
                   answer_sig=sca_routes.answer_signature(latest))
    return suggestion


def defect_of(db: Database, store: FeedStore, pid: int, hub_id: str, text: bool = False,
              target: str = "1.4.9") -> dict:
    """Дефект SCA по находке; text=True – с готовым текстом набора (ADR-0091): целевая версия вручную с отметкой
    «Версию проверил сам» и строка Объяснения на каждую уязвимость набора."""
    f, review = finding(db, pid, hub_id), db.get_review(pid, hub_id)
    if not text:
        return sca_routes.sca_defect(db, store, pid, f, review)
    record = {"target_basis": "manual", "target_version": target}
    first = sca_routes.sca_defect(db, store, pid, f, review, override=record)
    if first["state"] != "text":
        return first
    record["explanation"] = "".join(
        f"{v['main']}: Уязвимость компонента позволяет нарушителю нарушить работу продукта при обработке данных."
        + chr(10) for v in first["vulns"]).strip()
    # «Версию проверил сам» – о тексте целиком (ADR-0091 п. 21): подпись снимается с готового текста
    second = sca_routes.sca_defect(db, store, pid, f, review, override=record)
    if second["state"] != "text":
        return second
    record["version_checked_sig"] = second["version_confirm_sig"]
    return sca_routes.sca_defect(db, store, pid, f, review, override=record)


def test_defect_text_is_set_text_not_review_comment(sca_env):
    """Комментарий решения в дефект SCA не идёт: текст – Объяснение набора и целевая версия (ADR-0091)."""
    db, store, pid = sca_env
    agree(db, pid, "1")
    agree(db, pid, "2")
    edited = "Обновить до 1.4.9: уязвимый разбор включён в сборке, команда проверила вызов."
    agree(db, pid, "1", edited)
    assert defect_of(db, store, pid, "1")["state"] == "text"  # без текста набора дефект не готов
    view = defect_of(db, store, pid, "1", text=True)
    assert view["ready"], view["hint"]
    assert "команда проверила вызов" not in view["body"] and "Пояснение агента" not in view["body"]
    assert "Уязвимость компонента позволяет нарушителю" in view["body"] and "1.4.9" in view["body"]


def test_decision_on_previous_finding_version_blocks_defect(sca_env):
    db, store, pid = sca_env
    agree(db, pid, "1")
    agree(db, pid, "2")
    assert defect_of(db, store, pid, "1", text=True)["ready"]
    # новая выгрузка: у находки 1 появилась CVE – решение принималось по другой версии
    load(db, pid, [sca("1", vuln="AST-1", cve="CVE-2099-7777"), sca("2", vuln="AST-2")])
    view = defect_of(db, store, pid, "1", text=True)
    assert not view["ready"] and view["state"] == "changed" and "прежней версии находки" in view["hint"]
    # из карточки 2 дефект готов, но находка 1 со старым решением в него не входит; у находки 2 – публичное
    # соответствие: набор только с AST дефекта не даёт (ADR-0101)
    db.save_ast_map([("AST-2", "CVE-2099-0002")])
    other = defect_of(db, store, pid, "2", text=True)
    assert other["ready"] and "CVE-2099-7777" not in other["body"], other["hint"]
    assert any(x["hub_id"] == "1" and "прежней версии" in x["reason"] for x in other["excluded"])


def test_missing_finding_never_enters_defect(sca_env):
    db, store, pid = sca_env
    agree(db, pid, "1")
    agree(db, pid, "2")
    load(db, pid, [sca("1", vuln="AST-1")])  # находки 2 в новой выгрузке нет
    assert db.get_finding_by_hub_id(pid, "2")["missing"] == 1
    gone = defect_of(db, store, pid, "2", text=True)
    assert not gone["ready"] and gone["state"] == "missing"
    view = defect_of(db, store, pid, "1", text=True)
    assert view["ready"] and "AST-2" not in view["body"] and "CVE-2099-0001" in view["body"], view["hint"]
    assert view["members"] == ["1"]


def test_conflicting_outcomes_split_package_instead_of_blocking(sca_env):
    """Разные исходы в пакете не блокируют дефект (ADR-0091): находка с «не применимо» не входит в набор и названа
    в note, а из её карточки дефекта нет – только короткий комментарий."""
    db, store, pid = sca_env
    agree(db, pid, "1")
    db.save_review(pid, "2", decision="disagree", final_verdict="false_positive", final_comment="Не затронута.",
                   reviewed=True)
    view = defect_of(db, store, pid, "1", text=True)
    assert view["ready"] and view["members"] == ["1"], view["hint"]
    assert "2 – не применимо" in view["note"]
    other = defect_of(db, store, pid, "2", text=True)
    assert not other["ready"] and other["state"] == "short_only"


# ============================================================================ шаги обновления базы 4 и 5

# ============================================================================ пакет SCA: сомнительные имена

@pytest.mark.parametrize("name, ecosystem, doubtful", [
    ("private/project", "pypi", True),
    ("private/project", "maven", True),
    ("private/project", "", True),  # экосистема неизвестна: «папка/имя» без домена
    ("internal-auth-lib", "npm", True),
    ("Company.Internal.Billing", "nuget", True),
    ("billing", "go", True),  # у Go – путь модуля с доменом
    ("org.example:example-parser", "maven", False),
    ("example-parser", "maven", False),
    ("requests", "pypi", False),
    ("@types/chart.js", "npm", False),
    ("github.com/org/repo/v2", "go", False),
    ("Newtonsoft.Json", "nuget", False),
])
def test_package_doubt_checks_coordinates_by_ecosystem(name: str, ecosystem: str, doubtful: bool):
    assert bool(sca_logic.package_doubt(name, "1.0", [ecosystem] if ecosystem else [])) is doubtful


def test_doubtful_names_need_explicit_confirmation(web, tmp_path: Path):
    doubtful = dict(SCA_BASE, **{"Issue id": "73009", "CVSS score": "7.5", "Component name": "private/project",
                                 "Component version": "1.0.0", "CVE id": "CVE-2099-20001", "Type": "pypi",
                                 "Non-vulnerable versions": "1.0.1", "CWE ID": "79"})
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(tmp_path / "hub.xlsx", sca=[*SCA_ROWS, doubtful])).status_code == 303
    page = web.client.get(f"/projects/{pid}/sca").text
    key=sca_logic.doubt_key('private/project','1.0.0','pypi')
    assert 'id="package-doubtful"' in page and f'value="{key}"' in html.unescape(page)

    def kit() -> str:
        """Состав задания нового сценария: прежний экспорт не выдаётся, комплект собирается в разделе
        «Компоненты». Ответ на вопрос «что уходит агенту» прежний и остаётся прежним."""
        assert web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN,
                               follow_redirects=False).status_code == 303
        manifest = web.client.get(f"/projects/{pid}/components/task.json").json()
        archive = zipfile.ZipFile(io.BytesIO(web.client.get(
            f"/projects/{pid}/components/task/{manifest['task_id']}.zip").content))
        parts = [archive.read(name).decode("utf-8") for name in archive.namelist()]
        parts.append(web.client.get(f"/projects/{pid}/components/task.json").text)
        return "\n".join(parts)

    assert "private/project" not in kit() and "example-parser" in kit()
    # подделанное значение формы: имя не из списка сомнительных в пакет не добавляется
    r = web.client.post(f"/projects/{pid}/sca/package/confirm", data={"item": ["C:/work/lib@1.0"]}, headers=ORIGIN,
                        follow_redirects=False)
    assert r.status_code == 303 and web.app.state.db.sca_confirmed(pid) == set()
    r = web.client.post(f"/projects/{pid}/sca/package/confirm", data={"item": [key]},
                        headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and "n=1" in r.headers["location"]
    assert "private/project" in kit()
    # отозвать: пустой выбор – снова не уходит
    web.client.post(f"/projects/{pid}/sca/package/confirm", data={}, headers=ORIGIN, follow_redirects=False)
    assert "private/project" not in kit()
    assert web.client.post(f"/projects/{pid}/sca/package/confirm", data={}).status_code == 403  # без Origin


def test_defect_title_checks_ecosystem():
    assert sca_routes.title_warnings("private/project", "1.0", "pypi")
    assert sca_routes.title_warnings("org.example:example-parser", "1.4.2", "maven") == []


# ============================================================================ справочники

def test_attributes_of_many_elements_count_toward_record_budget(monkeypatch):
    """Каждый атрибут по отдельности в пределах, а вместе – больше бюджета записи: отказ до накопления."""
    monkeypatch.setattr(feeds, "MAX_RECORD_TEXT", 50_000)
    attrs = b'<x a="' + b"v" * 1000 + b'" b="' + b"w" * 1000 + b'"/>'
    data = b"<vulnerabilities><vul>" + attrs * 100 + b"</vul></vulnerabilities>"
    with pytest.raises(FeedError, match="текста и атрибутов"):
        list(feeds.iter_records([data], {"vul"}))
    small = b"<vulnerabilities>" + (b"<vul>" + attrs * 10 + b"</vul>") * 50 + b"</vulnerabilities>"
    assert len(list(feeds.iter_records([small], {"vul"}))) == 50  # бюджет – на запись, а не на файл


def test_space_is_checked_before_the_batch_is_written(tmp_path: Path, monkeypatch):
    store = FeedStore(tmp_path / "feeds.db")
    try:
        store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")
        # до загрузки места хватает, на первую пачку – нет: ни одна пачка не записана
        monkeypatch.setattr(feeds, "MAX_DB_BYTES", store._used_bytes() + 1000)
        writes = []
        real_tx = store._tx

        def spy_tx():
            writes.append(1)
            return real_tx()

        monkeypatch.setattr(store, "_tx", spy_tx)
        with pytest.raises(FeedError, match="загрузка остановлена"):
            store.load("bdu", bdu_zip(tmp_path / "b.zip", many_records(500)), "b.zip")
        assert len(writes) == 2, "только очистка до и после: ни одной пачки"
        monkeypatch.setattr(store, "_tx", real_tx)
        assert_previous_kept(store)
        assert store.staging_rows() == 0
    finally:
        store.close()


def test_failure_inside_final_swap_keeps_previous_feed(tmp_path: Path, monkeypatch):
    store = FeedStore(tmp_path / "feeds.db")
    try:
        store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")
        real_fill = store._fill

        def fill_then_break_swap(*args):
            meta = real_fill(*args)
            # подмена дойдёт до таблицы, которой нет: сбой внутри транзакции после DROP и вставки прежних таблиц
            monkeypatch.setitem(feeds._KIND_TABLES, "bdu", ("bdu", "bdu_cve", "cwe_ru", "broken"))
            return meta

        monkeypatch.setattr(store, "_fill", fill_then_break_swap)
        with pytest.raises(psycopg.errors.UndefinedTable):
            store.load("bdu", bdu_zip(tmp_path / "b.zip", many_records(50)), "b.zip")
        monkeypatch.setitem(feeds._KIND_TABLES, "bdu", ("bdu", "bdu_cve", "cwe_ru"))
        assert_previous_kept(store)
        assert store.bdu_by_cve(["CVE-2099-30001"]) == {}
        assert store.staging_rows() == 0
    finally:
        store.close()


def test_failure_after_written_batches_is_cleaned_up(tmp_path: Path, monkeypatch):
    store = FeedStore(tmp_path / "feeds.db")
    try:
        store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")
        real_fill = store._fill

        def broken_fill(*args):
            real_fill(*args)
            raise psycopg.OperationalError("сбой записи")

        monkeypatch.setattr(store, "_fill", broken_fill)
        with pytest.raises(psycopg.OperationalError):
            store.load("bdu", bdu_zip(tmp_path / "b.zip"), "b.zip")
        assert_previous_kept(store)
        assert store.staging_rows() == 0
    finally:
        store.close()


def test_failed_import_leaves_no_size_behind(tmp_path: Path, monkeypatch):
    """Неудачная загрузка очищает feeds_imp: следующая проходит предварительную проверку размера."""
    store = FeedStore(tmp_path / "feeds.db")
    try:
        store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")
        before = store._used_bytes()
        monkeypatch.setattr(feeds, "BATCH", 50)
        broken = many_records(3000).replace("</vulnerabilities>", "<vul><identifier>BDU:1")
        with pytest.raises(FeedError, match="повреждён"):
            store.load("bdu", bdu_zip(tmp_path / "b.zip", broken), "b.zip")
        assert store._used_bytes() == before and store.staging_rows() == 0
        monkeypatch.setattr(feeds, "MAX_DB_BYTES", store._used_bytes() + 512 * 1024)
        assert store.load("bdu", bdu_zip(tmp_path / "c.zip"), "c.zip")["records"] == 2
    finally:
        store.close()


def test_rows_left_by_a_crash_do_not_get_into_the_next_load(tmp_path: Path):
    store = FeedStore(tmp_path / "feeds.db")
    try:
        store._conn.execute("INSERT INTO feeds_imp.bdu(id, data_json) VALUES ('BDU:0000-00000', '{}')")
        assert store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")["records"] == 2
        assert store.counts()["bdu"] == 2 and store.staging_rows() == 0
    finally:
        store.close()


def test_load_by_another_process_is_refused_and_its_rows_stay(tmp_path: Path):
    """Владение feeds_imp – блокировка базы: второй процесс получает отказ и чужую загрузку не чистит."""
    store = FeedStore(tmp_path / "feeds.db")
    try:
        with psycopg.connect(store._store.conninfo, autocommit=True) as other:
            other.execute("SELECT pg_advisory_lock(%s)", (feeds.IMPORT_LOCK,))
            other.execute("INSERT INTO feeds_imp.bdu(id, data_json) VALUES ('BDU:0000-00000', '{}')")
            with pytest.raises(FeedError) as caught:
                store.load("bdu", bdu_zip(tmp_path / "a.zip"), "a.zip")
            assert str(caught.value) == feeds.BUSY and store.staging_rows() == 1
    finally:
        store.close()


# ============================================================================ оценка токенов: счёт модели

@pytest.fixture
def triage_env(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    environment = Env(tmp_path, fake, mask_key)
    environment.runner.start()
    yield environment
    environment.close()
    fake.close()


def test_answer_rejected_when_model_counts_prompt_longer_than_window(triage_env: Env):
    """Оценка длины – эвристика: если сама модель насчитала в промпте больше окна, начало могло быть обрезано –
    вердикт не привязывается, у находки понятная ошибка."""
    triage_env.fake.stats["prompt_eval_count"] = 10**6
    triage_env.load([sast("A", 15)])
    run = triage_env.run()
    assert run["state"] == "done" and run["failed"] == 1
    item = triage_env.db.recent_items(run["id"])[0]
    assert "не поместился в окно контекста" in item["error"]
    assert triage_env.db.get_case(triage_env.project_id, "A")["verdict_id"] is None


# ============================================================================ образ ВМ: доступ по сети, пароли

def _git_bash() -> str | None:
    if os.name != "nt":
        return shutil_which("bash")
    for candidate in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe"):
        if Path(candidate).is_file():
            return candidate
    return None


def shutil_which(name: str) -> str | None:
    import shutil

    return shutil.which(name)


def posix(p: Path) -> str:
    text = p.as_posix()
    return "/" + text[0].lower() + text[2:] if os.name == "nt" and len(text) > 1 and text[1] == ":" else text


# Поддельные команды ВМ с состоянием (этап 3.3, дополнено на этапе 3.4): systemctl «перезапускает» приложение
# на адрес из TRIAGE_BIND в .env и записывает публикацию порта (publish, её видит docker) и сокет (listen, его видит
# ss); без userland-proxy (FAKE_NO_PROXY) порт публикуется правилом DNAT – сокета нет, публикация есть. При отказе
# (FAKE_RESTART) прежнее состояние остаётся – как у настоящего контейнера. ufw reload «применяет» блок after.rules
# в цепочку DOCKER-USER; iptables -S показывает цепочки с правилами, которые тест может поставить ПЕРЕД нашими
# (FAKE_DU_FIRST, FAKE_FWD_FIRST). docker ps и docker inspect показывают работающий контейнер приложения
# и его публикацию; FAKE_DOCKER_FAIL – Docker не отвечает, FAKE_DOCKER_STOPPED – контейнер не работает,
# FAKE_DOCKER_OTHER – посторонний контейнер публикует тот же порт на данном адресе (any – с пустым адресом, на всех).
SYSTEMCTL_FAKE = r"""#!/bin/bash
[ "$1" = restart ] || exit 0
bind=$(grep -E '^TRIAGE_BIND=' "$D/.env" | tail -n 1 | cut -d= -f2-)
case "${FAKE_RESTART:-ok}" in
  fail) exit 1 ;;
  noop) exit 0 ;;
  fail-local) [ "$bind" = 127.0.0.1 ] && exit 1 ;;
  fail-public) [ "$bind" = 0.0.0.0 ] && exit 1 ;;
esac
echo "$bind" > "$FAKE_STATE/publish"
if [ -n "${FAKE_NO_PROXY:-}" ]; then : > "$FAKE_STATE/listen"; else echo "$bind:8765" > "$FAKE_STATE/listen"; fi
exit 0
"""
SS_FAKE = r"""#!/bin/bash
echo "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
[ -s "$FAKE_STATE/listen" ] && echo "LISTEN 0      4096   $(cat "$FAKE_STATE/listen") 0.0.0.0:*"
exit 0
"""
UFW_FAKE = r"""#!/bin/bash
if [ "$1" = reload ]; then
  [ -n "${FAKE_UFW_RELOAD_FAIL:-}" ] && exit 1
  awk '/^# local-triage: begin/ { f = 1; next } /^# local-triage: end/ { f = 0 } f && /^-I DOCKER-USER 1 /' "$RULES" \
    | sed -e 's/^-I DOCKER-USER 1 /-A DOCKER-USER /' -e 's/! -s \([0-9.]*\) /! -s \1\/32 /' > "$FAKE_STATE/docker-user"
fi
exit 0
"""
DOCKER_FAKE = r"""#!/bin/bash
[ -n "${FAKE_DOCKER_FAIL:-}" ] && exit 1
case "$1" in
  ps)
    [ -z "${FAKE_DOCKER_STOPPED:-}" ] && [ -s "$FAKE_STATE/publish" ] && echo c-app
    [ -n "${FAKE_DOCKER_OTHER:-}" ] && echo c-other
    exit 0 ;;
  inspect)
    shift 3  # inspect -f <формат>
    for id in "$@"; do
      case "$id" in
        c-app)
          a="$(cat "$FAKE_STATE/publish")"
          if [ "$a" = 0.0.0.0 ] && [ -n "${FAKE_PUBLISH_V6:-}" ]; then echo "/local-triage 0.0.0.0|8765 ::|8765"
          else echo "/local-triage $a|8765"; fi ;;
        c-other) [ "$FAKE_DOCKER_OTHER" = any ] && echo "/other |8765" || echo "/other $FAKE_DOCKER_OTHER|8765" ;;
        *) echo "Error: No such object: $id" >&2; exit 1 ;;
      esac
    done
    exit 0 ;;
esac
exit 0
"""
IPTABLES_FAKE = r"""#!/bin/bash
[ "$1" = -S ] || exit 0
case "$2" in
  DOCKER-USER)
    echo "-N DOCKER-USER"
    [ -n "${FAKE_DU_FIRST:-}" ] && echo "$FAKE_DU_FIRST"
    cat "$FAKE_STATE/docker-user" 2>/dev/null ;;
  FORWARD)
    echo "-P FORWARD DROP"
    [ -n "${FAKE_FWD_FIRST:-}" ] && echo "$FAKE_FWD_FIRST"
    echo "-A FORWARD -j DOCKER-USER" ;;
esac
exit 0
"""


@pytest.fixture
def network(tmp_path: Path):
    bash = _git_bash()
    if bash is None:
        pytest.skip("нет Git Bash")
    tools = tmp_path / "tools"
    tools.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    (state / "listen").write_text("127.0.0.1:8765\n", encoding="utf-8", newline="\n")
    (state / "publish").write_text("127.0.0.1\n", encoding="utf-8", newline="\n")
    fakes = {"ufw": UFW_FAKE, "iptables": IPTABLES_FAKE, "systemctl": SYSTEMCTL_FAKE, "ss": SS_FAKE,
             "docker": DOCKER_FAKE}
    for name, body in fakes.items():
        (tools / name).write_text(body, encoding="utf-8", newline="\n")
    opt = tmp_path / "opt"
    opt.mkdir()
    (opt / ".env").write_text("TRIAGE_PORT=8765\nTRIAGE_BIND=127.0.0.1\n", encoding="utf-8", newline="\n")
    rules = tmp_path / "after.rules"
    rules.write_text("*filter\nCOMMIT\n", encoding="utf-8", newline="\n")
    base = {**os.environ, "D": posix(opt), "RULES": posix(rules), "WAIT_S": "0", "FAKE_STATE": posix(state),
            **{name.upper(): posix(tools / name) for name in fakes}}

    def run(*args: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run([bash, posix(VM / "guest" / "network-access.sh"), *args], env={**base, **extra},
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)

    def env_value(key: str) -> str:
        return next((line.split("=", 1)[1] for line in (opt / ".env").read_text(encoding="utf-8").splitlines()
                     if line.startswith(f"{key}=")), "")

    def listen() -> str:
        return (state / "listen").read_text(encoding="utf-8").strip()

    def publish() -> str:
        return (state / "publish").read_text(encoding="utf-8").strip()

    def guarded() -> bool:
        return "local-triage: begin" in rules.read_text(encoding="utf-8")

    return {"run": run, "bind": lambda: env_value("TRIAGE_BIND"), "allow": lambda: env_value("TRIAGE_ALLOW"),
            "rules": rules, "listen": listen, "publish": publish, "guarded": guarded, "state": state}


def test_network_open_only_after_rule_is_verified(network: dict):
    r = network["run"]("open", "192.0.2.10")
    assert r.returncode == 0, r.stdout + r.stderr
    assert network["bind"]() == "0.0.0.0" and network["listen"]() == "0.0.0.0:8765"
    assert network["allow"]() == "192.0.2.10" and network["run"]("check").returncode == 0
    assert network["run"]("open", "192.0.2.10").returncode == 0  # повторно: блок заменяется, а не дописывается
    text = network["rules"].read_text(encoding="utf-8")
    assert text.count("# local-triage: begin") == 1 and "-I DOCKER-USER 1 " in text and "! -s 192.0.2.10 -j DROP" in text
    r = network["run"]("close")
    assert r.returncode == 0, r.stdout + r.stderr
    assert network["bind"]() == "127.0.0.1" and network["listen"]() == "127.0.0.1:8765" and not network["guarded"]()
    assert network["run"]("check").returncode != 0


@pytest.mark.parametrize("extra, reason", [
    ({"FAKE_UFW_RELOAD_FAIL": "1"}, "ufw reload"),
    # правило есть, но перед ним RETURN или ACCEPT: соединение до DROP не дойдёт
    ({"FAKE_DU_FIRST": "-A DOCKER-USER -j RETURN"}, "стоит не первым"),
    ({"FAKE_DU_FIRST": "-A DOCKER-USER -p tcp -j ACCEPT"}, "стоит не первым"),
    # в FORWARD до перехода в DOCKER-USER пакет принимается другим правилом
    ({"FAKE_FWD_FIRST": "-A FORWARD -i en+ -j ACCEPT"}, "стоит не первым"),
    # перезапуск на всех адресах не удался: приложение остаётся на 127.0.0.1
    ({"FAKE_RESTART": "fail-public"}, "не перезапустилось"),
])
def test_network_open_falls_back_to_localhost_on_failure(network: dict, extra: dict, reason: str):
    r = network["run"]("open", "192.0.2.10", **extra)
    assert r.returncode == 1 and reason in r.stdout, r.stdout
    assert network["bind"]() == "127.0.0.1" and network["listen"]() == "127.0.0.1:8765"
    assert "только на 127.0.0.1 ВМ" in r.stdout


def test_network_open_refuses_when_app_is_still_public(network: dict):
    """Перед открытием приложение должно подтверждённо слушать только 127.0.0.1: «успешный» перезапуск, после
    которого прежний контейнер слушает все адреса, – отказ, а не публикация с непроверенным состоянием."""
    (network["state"] / "listen").write_text("0.0.0.0:8765\n", encoding="utf-8", newline="\n")
    (network["state"] / "publish").write_text("0.0.0.0\n", encoding="utf-8", newline="\n")
    r = network["run"]("open", "192.0.2.10", FAKE_RESTART="noop")
    assert r.returncode == 1 and "опубликован и слушается только на 127.0.0.1" in r.stdout
    assert "ВНИМАНИЕ" in r.stdout and network["bind"]() == "127.0.0.1"


def test_network_open_reports_when_return_to_localhost_fails(network: dict):
    """Перезапуск не удаётся совсем: код 1, предупреждение, правило ограничения (если уже записано) остаётся."""
    assert network["run"]("open", "192.0.2.10").returncode == 0
    r = network["run"]("open", "192.0.2.10", FAKE_RESTART="fail")
    assert r.returncode == 1 and "ВНИМАНИЕ" in r.stdout
    assert network["guarded"]()  # ограничение не снято


@pytest.mark.parametrize("mode", ["fail", "noop"])
def test_network_close_keeps_guard_until_app_is_local(network: dict, mode: str):
    """close: перезапуск не удался (fail) или «удался», а контейнер по-прежнему слушает все адреса (noop) – правило
    ограничения остаётся, код 1, сообщение не говорит «только 127.0.0.1»."""
    assert network["run"]("open", "192.0.2.10").returncode == 0
    r = network["run"]("close", FAKE_RESTART=mode)
    assert r.returncode == 1 and "оставлено" in r.stdout
    assert "приложение – только на 127.0.0.1" not in r.stdout
    assert network["guarded"]() and network["listen"]() == "0.0.0.0:8765"
    assert network["run"]("check").returncode == 0  # ограничение по-прежнему действует
    # после устранения причины close проходит
    assert network["run"]("close").returncode == 0 and not network["guarded"]()


def test_network_check_requires_rule_first_for_allowed_address(network: dict):
    assert network["run"]("check").returncode != 0  # адреса нет – ограничения нет
    assert network["run"]("open", "192.0.2.10").returncode == 0
    assert network["run"]("check").returncode == 0
    assert network["run"]("check", FAKE_DU_FIRST="-A DOCKER-USER -j RETURN").returncode != 0
    assert network["run"]("check", FAKE_FWD_FIRST="-A FORWARD -j ACCEPT").returncode != 0


def test_network_open_rejects_bad_address(network: dict):
    for bad in ("", "0.0.0.0", "300.1.1.1", "192.0.2.0/24", "example.org"):
        assert network["run"]("open", bad).returncode == 2
    assert network["bind"]() == "127.0.0.1"


def test_start_sh_uses_network_check():
    start = (VM / "guest" / "start.sh").read_text(encoding="utf-8")
    block = start[start.index('if [ "$BIND" != 127.0.0.1 ]; then'):start.index('# Публикация порта работающим контейнером')]
    assert "na check" in block and "env_set TRIAGE_BIND 127.0.0.1" in block
    # нет сценария (или он не читается) – проверка ограничения не проходит, приложение остаётся на 127.0.0.1
    assert 'na() { [ -r "$NA" ] || return 2;' in start


@pytest.mark.skipif(os.name != "nt", reason="ACL Windows")
def test_build_restrict_keeps_existing_secret_files_readable(tmp_path: Path):
    """restrict из build.sh на папке secrets: файлы прошлой сборки (known_hosts) остаются доступны владельцу,
    новые – тоже, наследованных прав других пользователей нет."""
    bash = _git_bash()
    if bash is None:
        pytest.skip("нет Git Bash")
    build = (VM / "build.sh").read_text(encoding="utf-8")
    func = build[build.index("restrict() {"):]
    func = func[:func.index("\n}\n") + 3]
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "known_hosts-build").write_text("old\n", encoding="utf-8")
    script = ('w() { cygpath -w "$1"; }\ndie() { echo "ОТКАЗ: $*"; exit 1; }\n'
              + f'PY="{posix(Path(sys.executable))}"\nHERE="{posix(VM)}"\n' + func
              + f'restrict "{posix(secrets)}"\ncat "{posix(secrets)}/known_hosts-build"\n'
              + f'echo new > "{posix(secrets)}/known_hosts-copy" && cat "{posix(secrets)}/known_hosts-copy"\n')
    r = subprocess.run([bash, "-c", script], capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=60)
    assert r.returncode == 0 and r.stdout.split() == ["old", "new"], r.stdout + r.stderr
    acl = subprocess.run(["icacls", str(secrets / "known_hosts-build")], capture_output=True, text=True,
                         encoding="oem", errors="replace").stdout
    entries = [line for line in acl.splitlines() if "(" in line and ":" in line]
    assert len(entries) == 1 and os.environ.get("USERNAME", "").lower() in entries[0].lower()


def test_password_file_is_owner_only(tmp_path: Path):
    """Пароль копии прошлой проверки заменяется только явно (replace_secret, этап 3.5): write_secret на
    существующем файле отказывает и не трогает его; после замены – новый пароль и права только владельца."""
    sys.path.insert(0, str(VM))
    try:
        from secret_file import replace_secret, write_secret
    finally:
        sys.path.remove(str(VM))
    path = tmp_path / "triage-password-copy"
    path.write_text("old", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_secret(str(path), "новый-пароль\n")
    assert path.read_text(encoding="utf-8") == "old"
    replace_secret(str(path), "новый-пароль\n")
    assert path.read_text(encoding="utf-8") == "новый-пароль\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["triage-password-copy"]  # подготовленных файлов нет
    if os.name == "nt":
        acl = subprocess.run(["icacls", str(path)], capture_output=True, text=True, encoding="oem",
                             errors="replace").stdout
        entries = [line for line in acl.splitlines()[:-1] if ":" in line and "(" in line]
        assert entries and all("(I)" not in line for line in entries)  # без наследованных прав
        assert len(entries) == 1 and os.environ.get("USERNAME", "").lower() in entries[0].lower()
    else:
        assert (path.stat().st_mode & 0o777) == 0o600

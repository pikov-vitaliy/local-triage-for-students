"""Сценарии образа ВМ (deploy/vm): база образа строится заново в PostgreSQL только из демо-данных и ответов модели,
полученных во время сборки; приложение в ВМ опубликовано только на 127.0.0.1, SSH сборки проверяет ключ сервера строго,
выпуск OVA – только после подтверждённой очистки.

Сборка ВМ и OVA (VMware) здесь не запускается. Проверяются: сборка демо-базы (demo_db_build.py) на настоящей
демо-выгрузке examples/demo с поддельной моделью, отказ переносить что-либо из готовой базы (в том числе вердикт
с допустимым отпечатком и подменённым текстом), образ без вердиктов при недоступной модели, последняя проверка
состава (demo_db_check.py), поведение шагов images, data и export сценария build.sh (через Git Bash, с поддельными
docker, vmrun, ovftool и Python), первая загрузка и refresh start.sh с поддельным docker, очистка базы в cleanup.sh,
настройки Compose и тексты сценариев."""

from __future__ import annotations

import importlib.util
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import db_support
import pytest
from psycopg.conninfo import conninfo_to_dict

from app.config import DEFAULT_STATUS_MAP
from fake_ollama import FakeOllama, verdict_answer

ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / "deploy" / "vm"
MODEL = "qwen2.5-coder:14b"
VM_MODEL = "qwen2.5-coder:3b"
# текст, который возвращает поддельная модель при сборке: именно он должен оказаться в вердиктах образа
MODEL_TEXT = "ОТВЕТ-МОДЕЛИ-ПРИ-СБОРКЕ"
# посторонние тексты, подложенные в готовую базу с допустимыми отпечатками: ни один не должен попасть в образ
LEAKS = ("РАБОЧИЙ-ВЕРДИКТ-КРАТКО", "РАБОЧЕЕ-ОБЪЯСНЕНИЕ", "РАБОЧЕЕ-ИСПРАВЛЕНИЕ", "РАБОЧИЙ-КОММЕНТАРИЙ-HUB")


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"deploy_vm_{name}", VM / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(VM))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(VM))
    return module


check = _load("demo_db_check")
builder = _load("demo_db_build")
REPORTS = {p.name for p in check.demo_reports(ROOT)}


def _repos_root(tmp: Path) -> Path:
    """Корень папок с репозиториями, как в ВМ: <корень>/demo/examples/demo с клонами."""
    root = tmp / "repos-root"
    shutil.copytree(ROOT / "examples" / "demo", root / "demo" / "examples" / "demo")
    return root


def model_answer(_body: dict) -> dict:
    return verdict_answer(summary=f"{MODEL_TEXT}: строка запроса собирается из параметра id.")


def build(root: Path, out: Path, fake: FakeOllama | None = None, **extra) -> dict:
    triage = {"triage_url": fake.url, "triage_model": MODEL, "gpu_wait_s": 0, "wait_s": 120} if fake else {}
    args = {"conninfo": extra.pop("conninfo", None) or db_support.empty_database(), **triage, **extra}
    return builder.build(ROOT, root, out, ollama_url="http://ollama:11434", model=VM_MODEL, **args)


@pytest.fixture(scope="module")
def demo(tmp_path_factory) -> dict:
    """База образа, собранная с поддельной моделью: вердикты – из прогона при сборке."""
    tmp = tmp_path_factory.mktemp("demo")
    root = _repos_root(tmp)
    conninfo = db_support.empty_database()
    fake = FakeOllama(default_answer=model_answer)
    try:
        result = build(root, tmp / "out", fake, conninfo=conninfo)
    finally:
        fake.close()
    return {"root": root, "out": tmp / "out", "conninfo": conninfo, "result": result, "tmp": tmp}


def rows(conninfo: str, query: str, *args) -> list[tuple]:
    con = check.connect(conninfo)
    try:
        return con.execute(query, args).fetchall()
    finally:
        con.close()


def sql(conninfo: str, *statements: tuple) -> None:
    con = check.connect(conninfo)
    with con:
        for statement in statements:
            con.execute(*statement)
    con.close()


def copy_database(conninfo: str) -> str:
    """Новая база – копия conninfo; удаляется вместе с базами теста."""
    target = db_support.empty_database()
    name, source = conninfo_to_dict(target)["dbname"], conninfo_to_dict(conninfo)["dbname"]
    admin = db_support._admin()
    admin.execute(f"DROP DATABASE {name}")
    admin.execute(f"CREATE DATABASE {name} TEMPLATE {source}")
    return target


def all_text(conninfo: str) -> str:
    """Всё содержимое таблиц базы текстом – то, что вошло бы в копию pg_dump."""
    con = check.connect(conninfo)
    try:
        parts = []
        for table in check.table_names(con):
            parts += [str(row[0]) for row in con.execute("SELECT t::text FROM " + ".".join(f'"{part}"' for part in table.split(".")) + " t")]
        return "\n".join(parts)
    finally:
        con.close()


# ============================================================================ база образа – заново из демо-данных

def test_image_database_is_built_from_demo_data_and_build_time_model(demo: dict):
    result, out, db = demo["result"], demo["out"], demo["conninfo"]
    sast = result["sast"]
    assert result["mask_key"] == "новый" and result["schema_version"]
    assert result["name"].startswith("Демо:") and result["counts"]["findings"] == len(check.expected_hub_ids(ROOT))
    assert result["verdicts"]["source"] == "модель при сборке" and result["verdicts"]["model"] == MODEL
    assert result["verdicts"]["count"] == sast and result["counts"]["verdicts"] == sast
    assert result["counts"]["questions"] == 0 and result["counts"]["reviews"] == 0
    assert sorted(p.name for p in out.iterdir()) == []  # база – в PostgreSQL, в папке только ключ
    settings = {k: json.loads(v) for k, v in rows(db, "SELECT key, value_json FROM settings")}
    assert settings["team_name"] == "" and settings["sca_internal_prefixes"] == []
    assert settings["ollama_url"] == "http://ollama:11434" and settings["default_model"] == VM_MODEL
    assert all(s in settings["hub_status_map"].values() for s in DEFAULT_STATUS_MAP.values())
    answers = [r[0] for r in rows(db, "SELECT component FROM sca_answers")]
    assert answers and set(answers) <= {"org.example.thirdparty:example-xml-parser", "demo-yaml-lib",
                                        "demo-http-client"}
    assert rows(db, "SELECT repos_dir FROM projects") == [(builder.VM_REPOS_DIR,)]
    assert {r[0] for r in rows(db, "SELECT raw_json FROM verdicts")} == {"{}"}  # исходный ответ модели не хранится
    texts = [json.loads(r[0])["summary"] for r in rows(db, "SELECT data_json FROM verdicts")]
    assert texts and all(t.startswith(MODEL_TEXT) for t in texts)
    assert check.check(db, check.expected_hub_ids(ROOT), REPORTS)["counts"]["verdicts"] == sast


def test_tampered_verdict_with_valid_hash_does_not_reach_image(demo: dict, tmp_path: Path, monkeypatch):
    """Готовая база с вердиктами демо-находок, у которых отпечаток случая допустимый (совпадает со срезом демо-кода),
    а свободный текст (summary, explanation, fix, hub_comment) подменён. Сборка не принимает готовую базу ни
    аргументом, ни переменной GIVEN_DATA, ни как базу назначения: вердикты образа – только ответы модели этой сборки."""
    given = copy_database(demo["conninfo"])
    sql(given, ("UPDATE verdicts SET data_json = (data_json::jsonb || jsonb_build_object('summary', ?::text, "
                "'explanation', ?::text, 'fix', ?::text, 'hub_comment', ?::text))::text", LEAKS))
    hashes = {r[0] for r in rows(given, "SELECT case_hash FROM verdicts")}
    assert hashes == {r[0] for r in rows(demo["conninfo"], "SELECT case_hash FROM verdicts")}
    assert all(leak in all_text(given) for leak in LEAKS)  # подложено на самом деле
    monkeypatch.setenv("GIVEN_DATA", given)
    # готовую базу некуда передать: у сборки нет такого параметра, а прежний вызов с тремя путями отвергается
    assert "source_data" not in inspect.signature(builder.build).parameters
    r = subprocess.run([sys.executable, str(VM / "demo_db_build.py"), str(ROOT), given, str(demo["root"]),
                        "--conninfo", given, "--out", str(tmp_path / "cli"), "--model", VM_MODEL], capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=120)
    assert r.returncode == 2 and not (tmp_path / "cli").exists()
    # база назначения с данными – тоже отказ, до любых записей
    with pytest.raises(builder.BuildError, match="не пустая"):
        build(demo["root"], tmp_path / "busy", conninfo=given)
    assert not (tmp_path / "busy").exists()
    image = db_support.empty_database()
    fake = FakeOllama(default_answer=model_answer)
    try:
        result = build(demo["root"], tmp_path / "out", fake, conninfo=image)
    finally:
        fake.close()
    content = all_text(image)
    for leak in LEAKS:
        assert leak not in content, leak
    texts = [json.loads(r[0]) for r in rows(image, "SELECT data_json FROM verdicts")]
    assert len(texts) == result["sast"] and all(t["summary"].startswith(MODEL_TEXT) for t in texts)


def test_without_model_image_has_no_verdicts(demo: dict, tmp_path: Path):
    """Модели на сервере нет: при auto – база без вердиктов (демо разбирается при показе), причина – в составе;
    при require – отказ. Без прогона – тоже без вердиктов."""
    fake = FakeOllama(models=["other-model:1b"])
    try:
        result = build(demo["root"], tmp_path / "auto", fake)
        assert result["verdicts"]["source"] == "нет" and result["verdicts"]["count"] == 0
        assert "нет модели" in result["verdicts"]["reason"] and result["counts"]["verdicts"] == 0
        assert fake.chats() == []  # ни одного запроса разбора
        with pytest.raises(builder.BuildError, match="недоступна"):
            build(demo["root"], tmp_path / "require", fake, triage_mode="require")
    finally:
        fake.close()
    image = db_support.empty_database()
    result = build(demo["root"], tmp_path / "none", conninfo=image)
    assert result["verdicts"]["source"] == "нет" and result["counts"]["verdicts"] == 0
    assert check.check(image, check.expected_hub_ids(ROOT), REPORTS)["counts"]["verdicts"] == 0


def test_model_busy_with_other_models_means_no_verdicts(demo: dict, tmp_path: Path):
    fake = FakeOllama(default_answer=model_answer, loaded=["other-model:1b"])
    try:
        result = build(demo["root"], tmp_path / "out", fake)
    finally:
        fake.close()
    assert result["verdicts"]["source"] == "нет" and "занята" in result["verdicts"]["reason"]


def test_partial_build_time_run_is_refused(demo: dict, tmp_path: Path):
    """Прогон при сборке дал вердикты не всем находкам SAST: образ с частью вердиктов не собирается."""
    fake = FakeOllama(answers=["не JSON", "снова не JSON"], default_answer=model_answer)
    try:
        with pytest.raises(builder.BuildError, match="дал вердикты"):
            build(demo["root"], tmp_path / "out", fake)
    finally:
        fake.close()


def test_out_folder_must_be_empty(demo: dict, tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "лишний.txt").write_bytes(b"x")
    with pytest.raises(builder.BuildError, match="не пустая"):
        build(demo["root"], out)


# ============================================================================ последняя проверка состава

@pytest.fixture
def built(demo: dict) -> str:
    return copy_database(demo["conninfo"])


def problems(conninfo: str) -> list[str]:
    with pytest.raises(check.DemoDataError) as e:
        check.check(conninfo, check.expected_hub_ids(ROOT), REPORTS)
    return e.value.problems


def test_check_only_reads_the_database(built: str):
    con = check.connect(built, read_only=True)
    try:
        with pytest.raises(Exception, match="read-only"):
            con.execute("DELETE FROM meta")
    finally:
        con.close()


def test_check_rejects_foreign_project_and_rows(built: str):
    sql(built, ("INSERT INTO projects(name, created_at, updated_at) VALUES ('Рабочая система', 'x', 'x')",))
    assert any("проектов в базе: 2" in p for p in problems(built))
    # внешний ключ не пускает чужой проект: как у базы, собранной не приложением
    sql(built, ("DELETE FROM projects WHERE name = 'Рабочая система'",), ("SET session_replication_role = replica",),
        ("INSERT INTO reviews(project_id, hub_id, final_comment, updated_at) VALUES (999, 'X-1', 'рабочий', 'x')",))
    assert any("reviews" in p for p in problems(built))


def test_check_rejects_stray_verdict_ast_map_meta_settings_and_tables(built: str):
    sql(built, ("INSERT INTO verdicts(case_hash, model, prompt_version, verdict, data_json, created_at)"
                " VALUES ('h', 'm', 'p', 'true_positive', '{\"why\": \"рабочий код\"}', 'x')",))
    assert any("ответы модели" in p for p in problems(built))
    sql(built, ("DELETE FROM verdicts WHERE case_hash = 'h'",),
        ("INSERT INTO ast_map(ast_id, vuln_id, created_at) VALUES ('AST-2099-999999', 'CVE-2099-1', 'x')",))
    assert any("AST" in p for p in problems(built))
    sql(built, ("DELETE FROM ast_map",), ("CREATE TABLE notes(text TEXT)",))
    assert any("notes" in p for p in problems(built))
    sql(built, ("DROP TABLE notes",), ("CREATE SCHEMA work",), ("CREATE TABLE work.notes(text TEXT)",))
    assert any("work.notes" in p for p in problems(built))  # pg_dump взял бы и другую схему
    sql(built, ("DROP SCHEMA work CASCADE",), ("INSERT INTO meta(key, value) VALUES ('rev:999:core', 'abc')",))
    assert any("служебные" in p for p in problems(built))
    sql(built, ("DELETE FROM meta WHERE key = 'rev:999:core'",),
        ("INSERT INTO settings(key, value_json, updated_at) VALUES ('customer', '\"x\"', 'x')",))
    assert any("customer" in p for p in problems(built))


def test_check_rejects_foreign_findings(built: str):
    sql(built, ("SET session_replication_role = replica",),
        ("UPDATE findings SET hub_id = 'WORK-1' WHERE id = (SELECT MIN(id) FROM findings)",))
    assert any("WORK-1" in p for p in problems(built))


def test_check_validates_new_journal_identity_and_run_ownership(built: str):
    assert check.check(built, check.expected_hub_ids(ROOT), REPORTS)["project"]
    sql(built, ("UPDATE meta SET value='wrong' WHERE key='journal_installation'",))
    assert any('идентификатор журнала' in p for p in problems(built))
    sql(built, ("UPDATE meta SET value=? WHERE key='journal_installation'", ('a'*32,)),
        ("SET session_replication_role = replica",), ("INSERT INTO run_journal(run_id) VALUES (999999)",))
    assert any('журнале' in p for p in problems(built))


def test_check_rejects_foreign_imports(built: str):
    sql(built, ("UPDATE imports SET filename = 'customer-report.xlsx'",))
    assert any("выгрузки" in p for p in problems(built))


# ============================================================================ build.sh export: поведение

def _git_bash() -> str | None:
    """Git Bash, а не bash из WSL (System32): сценарии сборки рассчитаны на него."""
    if os.name != "nt":
        return shutil.which("bash")
    for candidate in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe"):
        if Path(candidate).is_file():
            return candidate
    found = shutil.which("bash")
    return found if found and "system32" not in found.lower() else None


def posix(p: Path) -> str:
    text = p.as_posix()
    return "/" + text[0].lower() + text[2:] if os.name == "nt" and text[1] == ":" else text


@pytest.fixture
def fake_build(tmp_path: Path) -> dict:
    bash = _git_bash()
    if bash is None:
        pytest.skip("нет Git Bash")
    tools = tmp_path / "tools"
    tools.mkdir()
    called = tmp_path / "ovftool-called"
    (tools / "vmrun").write_text("#!/bin/bash\necho 'Total running VMs: 0'\n", encoding="utf-8", newline="\n")
    (tools / "ovftool").write_text(f"#!/bin/bash\ntouch '{called.as_posix()}'\n", encoding="utf-8", newline="\n")
    build_dir, vm_dir = tmp_path / "build", tmp_path / "vm"
    (build_dir / "src").mkdir(parents=True)
    (build_dir / "logs").mkdir()
    vm_dir.mkdir()
    (build_dir / "src" / ".revision").write_text("abc\n", encoding="utf-8")
    (vm_dir / "local-triage-demo.vmdk").write_bytes(b"disk")
    (vm_dir / "local-triage-demo.vmx").write_text("x", encoding="utf-8")

    env = {**os.environ, "BUILD": posix(build_dir), "VMDIR": posix(vm_dir), "VMRUN": posix(tools / "vmrun"),
           "OVFTOOL": posix(tools / "ovftool"), "MSYS_NO_PATHCONV": "1"}

    # поддельный Python: отмечает, что его вызвали (шаг data не должен дойти до сборки базы)
    py_called = tmp_path / "python-called"
    (tools / "python").write_text(f"#!/bin/bash\ntouch '{posix(py_called)}'\nexit 1\n", encoding="utf-8",
                                  newline="\n")
    env["PY"] = posix(tools / "python")

    def run(step: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run([bash, posix(VM / "build.sh"), step], env={**env, **extra}, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=120)

    return {"run": run, "called": called, "mark": build_dir / "logs" / "finalized.json", "log": build_dir / "logs",
            "py_called": py_called, "build": build_dir, "tools": tools}


def test_data_step_refuses_given_data_folder(fake_build: dict, tmp_path: Path):
    """Своя папка данных (GIVEN_DATA) больше не принимается: шаг data отказывает до любой работы с базой."""
    given = tmp_path / "given"
    given.mkdir()
    (given / "triage.db").write_bytes(b"x")
    r = fake_build["run"]("data", GIVEN_DATA=str(given))
    assert r.returncode != 0 and "GIVEN_DATA больше не поддерживается" in r.stdout + r.stderr
    assert not fake_build["py_called"].exists()
    r = fake_build["run"]("data", DEMO_VERDICTS="maybe")
    assert r.returncode != 0 and "DEMO_VERDICTS" in r.stdout + r.stderr and not fake_build["py_called"].exists()


def test_checks_through_tunnel_need_known_verdict_mode(fake_build: dict):
    """Проверки приложения в ВМ ждут состав вердиктов, записанный шагом data; без него – отказ."""
    script = (VM / "build.sh").read_text(encoding="utf-8")
    body = script[script.index("demo_verdicts() {"):script.index("tunnel_check() {")]
    logs = fake_build["log"]
    for value, expected in (("all", "all"), ("none", "none"), ("maybe", "ОТКАЗ")):
        (logs / "demo-verdicts").write_text(value + "\n", encoding="utf-8", newline="\n")
        r = subprocess.run([_git_bash(), "-c", f'BUILD="{logs.parent.as_posix()}"\n{body}\n'
                            "demo_verdicts || echo ОТКАЗ"], capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60)
        assert r.stdout.strip() == expected, (value, r.stdout, r.stderr)


def test_export_refused_without_finalize_marker(fake_build: dict):
    r = fake_build["run"]("export")
    assert r.returncode != 0 and "нет подтверждения очистки" in r.stdout + r.stderr
    assert not fake_build["called"].exists()  # OVA не выпускался


def test_export_refused_when_disk_changed_after_finalize(fake_build: dict):
    fake_build["mark"].write_text('{"rev": "abc", "vmdk": "0:0", "vmx": "0:0", "cleanup": "ok"}\n', encoding="utf-8")
    r = fake_build["run"]("export")
    assert r.returncode != 0 and "изменились после finalize" in r.stdout + r.stderr
    assert not fake_build["called"].exists()


# ============================================================================ build.sh images и data: поведение

COMPOSE_TEXT = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
DB_PINNED = re.search(r"postgres:[^ \"}]+@sha256:[0-9a-f]{64}", COMPOSE_TEXT).group(0)
DB_TAG = DB_PINNED.split("@", 1)[0]

BUILD_DOCKER = r"""#!/bin/bash
echo "docker $*" >> "$FAKE_STATE/commands"
case "$1" in
  run) [ -n "${FAKE_RUN_FAIL:-}" ] && exit 1; echo container; exit 0 ;;
  cp) printf 'DUMP' > "$3"; exit 0 ;;
  image) exit 1 ;;
  save) printf 'IMAGE %s' "$2"; exit 0 ;;
  exec)
    case "$3" in
      pg_isready) [ -n "${FAKE_NOT_READY:-}" ] && exit 1; exit 0 ;;
      pg_dump) [ -n "${FAKE_DUMP_FAIL:-}" ] && exit 1; exit 0 ;;
      sha256sum) printf "${FAKE_DUMP_IN_CONTAINER:-DUMP}" | sha256sum; exit 0 ;;
      pg_restore)
        case " $* " in
          *" -f - "*) [ -n "${FAKE_PLAIN_EMPTY:-}" ] && exit 0; printf '%s\n' "${FAKE_PLAIN:-INSERT INTO meta VALUES (1);}"; exit 0 ;;
          *) [ -n "${FAKE_RESTORE_FAIL:-}" ] && exit 1; exit 0 ;;
        esac ;;
    esac ;;
esac
exit 0
"""
# Python сборки: demo_db_build.py пишет ключ и состав, проверки отвечают по переменным
BUILD_PYTHON = r"""#!/bin/bash
echo "python $*" >> "$FAKE_STATE/commands"
case "$3" in
  *demo_db_build.py)
    while [ $# -gt 0 ]; do
      case "$1" in
        --out) out="$2"; shift ;;
        --summary) summary="$2"; shift ;;
      esac
      shift
    done
    mkdir -p "$out"
    [ -n "${FAKE_EXTRA_FILE:-}" ] && printf 'x' > "$out/triage.db"
    printf '{"verdicts": {"source": "нет"}}\n' > "$summary"
    echo '{"ok": 1}' ;;
  *prepare_demo_data.py) [ -n "${FAKE_CHECK_FAIL:-}" ] && { echo '{"error": "нет"}'; exit 1; }; echo '{"ok": 1}' ;;
  *demo_db_check.py) [ -n "${FAKE_FINAL_FAIL:-}" ] && { echo '{"error": "нет"}'; exit 1; }; echo '{"ok": 1}' ;;
esac
exit 0
"""


@pytest.fixture
def data_step(fake_build: dict, tmp_path: Path) -> dict:
    tools, build_dir = fake_build["tools"], fake_build["build"]
    state = tmp_path / "state"
    state.mkdir()
    bin_dir = tools / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(BUILD_DOCKER, encoding="utf-8", newline="\n")
    (tools / "build-python").write_text(BUILD_PYTHON, encoding="utf-8", newline="\n")
    (build_dir / "src" / "docker-compose.yml").write_text(COMPOSE_TEXT, encoding="utf-8", newline="\n")
    (build_dir / "src" / "app").mkdir()
    (build_dir / "src" / "app" / "__init__.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8", newline="\n")
    (build_dir / "src" / ".revision").write_text("abcdef0123456789\n", encoding="utf-8")
    (build_dir / "src" / "examples" / "demo").mkdir(parents=True)
    (build_dir / "src" / "examples" / "demo" / "README.md").write_text("демо\n", encoding="utf-8")
    env = {"PATH": os.pathsep.join([str(bin_dir), os.environ["PATH"]]), "PY": posix(tools / "build-python"),
           "FAKE_STATE": posix(state), "DEMO_VERDICTS": "none", "DB_BUILD_WAIT_TRIES": "1"}

    def run(step: str = "data", **extra: str) -> subprocess.CompletedProcess:
        return fake_build["run"](step, **{**env, **extra})

    def commands() -> list[str]:
        log = state / "commands"
        return log.read_text(encoding="utf-8").splitlines() if log.exists() else []

    return {"run": run, "commands": commands, "stage": build_dir / "stage", "build": build_dir}


def test_images_step_saves_pinned_database_image_by_tag(data_step: dict):
    """Образ базы – по закреплённой ссылке из docker-compose.yml исходников; в архив идёт тег: дайджест docker load
    может не сохранить, в ВМ образ берётся по тегу (TRIAGE_DB_IMAGE). Третий архив рядом с приложением и Ollama."""
    r = data_step["run"]("images")
    assert r.returncode == 0, r.stdout + r.stderr
    commands = data_step["commands"]()
    pull, tag, save = (commands.index(c) for c in (f"docker pull -q {DB_PINNED}", f"docker tag {DB_PINNED} {DB_TAG}",
                                                   f"docker save {DB_TAG}"))
    assert pull < tag < save
    archives = sorted(p.name for p in (data_step["stage"] / "images").iterdir())
    assert archives == sorted(["local-triage-9.9.9.tar.gz", "local-triage-ollama-cpu-0.40.4.tar.gz",
                               DB_TAG.replace(":", "-") + ".tar.gz"])


def test_data_step_builds_dump_in_temporary_container(data_step: dict):
    """База строится во временном контейнере того же образа (порт на 127.0.0.1), в архив идут demo.dump и mask.key;
    проверки – на новых базах из этой копии; контейнер удаляется; пароль в аргументы команд не попадает."""
    r = data_step["run"]()
    assert r.returncode == 0, r.stdout + r.stderr
    commands = data_step["commands"]()
    run = next(c for c in commands if c.startswith("docker run "))
    assert DB_PINNED in run and "-p 127.0.0.1:5436:5432" in run and "--tmpfs /var/lib/postgresql/data" in run
    assert "--locale=C --lc-ctype=C.UTF-8" in run and "POSTGRES_DB=triage" in run
    assert re.search(r"-e POSTGRES_PASSWORD( |$)", run), "значение пароля – из окружения, не в аргументах"
    joined = "\n".join(commands)
    assert "POSTGRES_PASSWORD=" not in joined and "password=" not in joined
    position = {name: next(i for i, c in enumerate(commands) if name in c) for name in (
        "demo_db_build.py", "pg_dump -Fc", "docker cp", "CREATE DATABASE triage_check", "prepare_demo_data.py",
        "CREATE DATABASE triage_final", "demo_db_check.py", "pg_restore -f -")}
    assert list(position) == sorted(position, key=position.get), position
    assert "dbname=triage " in commands[position["demo_db_build.py"]] + " "
    assert "dbname=triage_check" in commands[position["prepare_demo_data.py"]]
    assert "dbname=triage_final" in commands[position["demo_db_check.py"]]
    assert commands[-1] == "docker rm -f lt-build-db"
    with tarfile.open(data_step["stage"] / "data.tar.gz") as archive:
        assert sorted(archive.getnames()) == ["demo.dump"]
    assert not (data_step["stage"] / "demo-plain.sql").exists() and not (data_step["stage"] / "data-check").exists()
    assert (data_step["build"] / "logs" / "demo-verdicts").read_text(encoding="utf-8").strip() == "none"


@pytest.mark.parametrize(("extra", "message"), [
    ({"FAKE_PLAIN": "COPY x FROM 'C:/work/repos';"}, "путь с диска сборочного компьютера"),
    ({"FAKE_PLAIN": "/d/" + "builds/local-triage-build"}, "путь с диска сборочного компьютера"),
    ({"FAKE_PLAIN_EMPTY": "1"}, "в простом тексте пуста"),
    ({"FAKE_EXTRA_FILE": "1"}, "лишние файлы"),
    ({"FAKE_FINAL_FAIL": "1"}, "в базе не только демо"),
    ({"FAKE_CHECK_FAIL": "1"}, "проверка не прошла"),
    ({"FAKE_RESTORE_FAIL": "1"}, "не восстанавливается"),
    ({"FAKE_DUMP_FAIL": "1"}, "pg_dump не прошёл"),
    ({"FAKE_DUMP_IN_CONTAINER": "OTHER"}, "отличается от копии в контейнере"),
    ({"FAKE_NOT_READY": "1"}, "не ответила"),
    ({"FAKE_RUN_FAIL": "1"}, "не запустилась"),
])
def test_data_step_stops_without_archive_and_removes_container(data_step: dict, extra: dict, message: str):
    r = data_step["run"](**extra)
    assert r.returncode != 0 and message in r.stdout + r.stderr, r.stdout + r.stderr
    assert not (data_step["stage"] / "data.tar.gz").exists()
    assert data_step["commands"]()[-1] == "docker rm -f lt-build-db"


def test_data_step_stops_when_source_has_no_pinned_image(data_step: dict):
    (data_step["build"] / "src" / "docker-compose.yml").write_text("services:\n  db:\n    image: postgres:latest\n",
                                                                  encoding="utf-8", newline="\n")
    r = data_step["run"]()
    assert r.returncode != 0 and "нет закреплённого образа базы" in r.stdout + r.stderr
    assert not data_step["commands"](), "до docker дело не дошло"


# ============================================================================ первая загрузка ВМ: start.sh

GUEST_DOCKER = r"""#!/bin/bash
echo "$*" >> "$FAKE_STATE/commands"
case "$1" in
  image) [ -n "${FAKE_NO_IMAGES:-}" ] && [ ! -e "$FAKE_STATE/loaded" ] && exit 1; exit 0 ;;
  load) : > "$FAKE_STATE/loaded"; exit 0 ;;
  volume) [ -e "$FAKE_STATE/volume" ]; exit $? ;;
  ps) [ -e "$FAKE_STATE/app-up" ] && echo c-app; exit 0 ;;
  inspect) echo "/local-triage 127.0.0.1|8765"; exit 0 ;;
  compose)
    # как настоящий Compose: без пароля в .env docker-compose.yml не читается
    grep -qE '^POSTGRES_PASSWORD=.' .env || { echo "compose без пароля" >> "$FAKE_STATE/commands"; exit 1; }
    shift
    while [ "$1" = -f ]; do shift 2; done
    case "$1" in
      stop) rm -f "$FAKE_STATE/app-up"; exit 0 ;;
      up)
        case " $* " in
          *" db "*) [ -n "${FAKE_DB_UP_FAIL:-}" ] && exit 1; : > "$FAKE_STATE/volume"; exit 0 ;;
          *)
            # приложение на пустой базе создало бы свою схему: демо потом не восстановить
            [ -s "$FAKE_STATE/tables" ] || echo 41 > "$FAKE_STATE/tables"
            : > "$FAKE_STATE/volume"; : > "$FAKE_STATE/app-up"; exit 0 ;;
        esac ;;
      exec)
        case "$4" in
          pg_isready) [ -n "${FAKE_DB_NOT_READY:-}" ] && exit 1; exit 0 ;;
          psql) [ -n "${FAKE_PSQL_FAIL:-}" ] && exit 1; cat "$FAKE_STATE/tables" 2>/dev/null || echo 0; exit 0 ;;
          pg_restore)
            cat > "$FAKE_STATE/restored"
            [ -n "${FAKE_RESTORE_FAIL:-}" ] && exit 1
            echo 40 > "$FAKE_STATE/tables"; exit 0 ;;
        esac ;;
    esac ;;
esac
exit 0
"""
GUEST_RPC = r"""#!/bin/bash
mkdir -p "$FAKE_STATE/guestinfo"
read -r op key val <<< "$1"
name="${key#guestinfo.triage.}"
case "$op" in
  info-set) printf '%s' "$val" > "$FAKE_STATE/guestinfo/$name" ;;
  info-get) [ -f "$FAKE_STATE/guestinfo/$name" ] && cat "$FAKE_STATE/guestinfo/$name" ;;
esac
exit 0
"""
GUEST_IP = '#!/bin/bash\necho "2: ens33    inet 192.0.2.10/24 brd 192.0.2.255 scope global ens33"\n'


def _env_file_value(env_path: Path, key: str) -> str:
    return next((ln.split("=", 1)[1] for ln in env_path.read_text(encoding="utf-8").splitlines()
                 if ln.startswith(f"{key}=")), "")


@pytest.fixture
def guest(tmp_path: Path) -> dict:
    """Папка /opt/local-triage в момент первой загрузки копии из OVA: .env без пароля, demo.dump, тома базы ещё нет."""
    bash = _git_bash()
    if bash is None:
        pytest.skip("нет Git Bash")
    tools, state, opt = tmp_path / "tools", tmp_path / "state", tmp_path / "opt"
    for d in (tools, state, opt, opt / "data", opt / "images"):
        d.mkdir()
    fakes = {"docker": GUEST_DOCKER, "vmware-rpctool": GUEST_RPC, "ip": GUEST_IP, "curl": "#!/bin/bash\nexit 0\n",
             "ssh-keygen": "#!/bin/bash\nexit 0\n"}
    for name, body in fakes.items():
        (tools / name).write_text(body, encoding="utf-8", newline="\n")
    env_file = opt / ".env"
    env_file.write_text((VM / "guest" / "env.vm").read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    (opt / "data" / "demo.dump").write_bytes(b"PGDMP-demo")
    (opt / "images" / "db.tar.gz").write_bytes(b"x")
    (state / "commands").write_text("", encoding="utf-8")
    base = {**os.environ, "PATH": os.pathsep.join([str(tools), os.environ["PATH"]]), "D": posix(opt),
            "FAKE_STATE": posix(state), "CURL": posix(tools / "curl"), "DB_WAIT_TRIES": "1"}

    def start(mode: str = "boot", **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run([bash, posix(VM / "guest" / "start.sh"), mode], env={**base, **extra}, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=120)

    def commands() -> list[str]:
        return (state / "commands").read_text(encoding="utf-8").splitlines()

    def status() -> str:
        return (state / "guestinfo" / "status").read_text(encoding="utf-8")

    def app_started() -> bool:
        return (state / "app-up").exists()

    return {"start": start, "commands": commands, "status": status, "app_started": app_started, "state": state, "opt": opt,
            "env": lambda key: _env_file_value(env_file, key), "tables": state / "tables", "restored": state / "restored"}


def _up_commands(commands: list[str]) -> list[int]:
    return [i for i, c in enumerate(commands) if " up -d --no-build --pull never" in c]


def test_first_boot_creates_password_and_restores_demo_before_the_app(guest: dict):
    r = guest["start"]()
    assert r.returncode == 0, r.stdout + r.stderr
    assert guest["status"]() == "ok" and guest["app_started"]()
    assert re.fullmatch(r"[A-Za-z0-9]{32}", guest["env"]("POSTGRES_PASSWORD"))
    assert guest["restored"].read_bytes() == b"PGDMP-demo", "pg_restore получает demo.dump"
    commands = guest["commands"]()
    assert "compose без пароля" not in commands, "пароль создан раньше любого вызова compose"
    restore = next(i for i, c in enumerate(commands) if " pg_restore " in c)
    assert "--single-transaction" in commands[restore] and "--exit-on-error" in commands[restore]
    first_up, app_up = _up_commands(commands)
    assert commands[first_up].endswith(" db") and first_up < restore < app_up and not commands[app_up].endswith(" db")
    assert not (guest["opt"] / "db-pending").exists()


def test_next_boots_do_not_touch_the_database(guest: dict):
    assert guest["start"]().returncode == 0
    password = guest["env"]("POSTGRES_PASSWORD")
    guest["restored"].unlink()
    guest["tables"].write_text("41\n", encoding="utf-8", newline="\n")
    r = guest["start"]()
    assert r.returncode == 0, r.stdout + r.stderr
    assert guest["env"]("POSTGRES_PASSWORD") == password, "том базы хранит прежний пароль"
    assert not guest["restored"].exists(), "непустая база не восстанавливается заново"
    assert guest["tables"].read_text(encoding="utf-8").strip() == "41"


def test_each_copy_gets_its_own_password(guest: dict, tmp_path: Path):
    assert guest["start"]().returncode == 0
    first = guest["env"]("POSTGRES_PASSWORD")
    env_file = guest["opt"] / ".env"
    env_file.write_text("".join(ln + "\n" for ln in env_file.read_text(encoding="utf-8").splitlines()
                                if not ln.startswith("POSTGRES_PASSWORD=")), encoding="utf-8", newline="\n")
    (guest["state"] / "volume").unlink()
    guest["tables"].unlink()
    assert guest["start"]().returncode == 0
    assert guest["env"]("POSTGRES_PASSWORD") != first


def test_password_is_not_replaced_when_the_volume_exists(guest: dict):
    """Том базы есть, а пароля нет: новый пароль к тому не подойдёт – отказ, приложение не запускается."""
    (guest["state"] / "volume").write_text("", encoding="utf-8")
    r = guest["start"]()
    assert r.returncode == 1 and guest["status"]() == "db-password-failed"
    assert guest["env"]("POSTGRES_PASSWORD") == "" and not guest["app_started"]()
    assert not _up_commands(guest["commands"]())


@pytest.mark.parametrize(("extra", "status"), [({"FAKE_DB_UP_FAIL": "1"}, "db-failed"), ({"FAKE_DB_NOT_READY": "1"}, "db-failed"),
                                               ({"FAKE_PSQL_FAIL": "1"}, "db-failed"),
                                               ({"FAKE_RESTORE_FAIL": "1"}, "db-restore-failed")])
def test_database_failure_stops_the_boot_before_the_app(guest: dict, extra: dict, status: str):
    r = guest["start"](**extra)
    assert r.returncode == 1, r.stdout + r.stderr
    assert guest["status"]() == status and not guest["app_started"]()
    assert (guest["opt"] / "db-pending").exists()
    if "FAKE_PSQL_FAIL" in extra:
        assert not guest["restored"].exists(), "не узнали, пуста ли база, – не восстанавливаем"


def test_empty_database_without_dump_is_a_failure(guest: dict):
    (guest["opt"] / "data" / "demo.dump").unlink()
    r = guest["start"]()
    assert r.returncode == 1 and guest["status"]() == "db-restore-failed" and not guest["app_started"]()


def test_refresh_does_not_start_the_app_until_database_is_ready(guest: dict):
    """Первая загрузка не восстановила базу: таймер refresh не запускает приложение на пустой базе (оно создало бы свою
    схему, и демо больше не восстановилось бы), а повторяет подготовку; удалось – приложение запускается, статус ok."""
    assert guest["start"](FAKE_RESTORE_FAIL="1").returncode == 1
    r = guest["start"]("refresh", FAKE_RESTORE_FAIL="1")
    assert r.returncode == 1 and guest["status"]() == "db-restore-failed"
    assert not guest["app_started"]() and not guest["tables"].exists()
    r = guest["start"]("refresh")
    assert r.returncode == 0, r.stdout + r.stderr
    assert guest["status"]() == "ok" and guest["app_started"]()
    assert guest["restored"].read_bytes() == b"PGDMP-demo" and guest["tables"].read_text(encoding="utf-8").strip() == "40"
    assert not (guest["opt"] / "db-pending").exists()


def test_refresh_never_touches_a_prepared_database(guest: dict):
    assert guest["start"]().returncode == 0
    guest["restored"].unlink()
    before = len(guest["commands"]())
    assert guest["start"]("refresh").returncode == 0
    new = guest["commands"]()[before:]
    assert not any(" exec " in c or " pg_restore " in c for c in new) and not guest["restored"].exists()


def test_images_are_loaded_when_database_image_is_missing(guest: dict):
    assert guest["start"](FAKE_NO_IMAGES="1").returncode == 0
    assert any(c.startswith("load -i images/db.tar.gz") for c in guest["commands"]())
    start = text("guest", "start.sh")
    assert 'docker image inspect "$TRIAGE_DB_IMAGE"' in start


# ============================================================================ очистка образа: cleanup.sh

def _shell_function(script: str, name: str) -> str:
    start = script.index(f"\n{name}() {{") + 1
    return script[start:script.index("\n}\n", start) + 3]


@pytest.fixture
def cleanup(guest: dict, tmp_path: Path) -> dict:
    """Функции cleanup.sh целиком на поддельном docker: сам сценарий здесь не запускается – он выключает компьютер."""
    assert guest["start"]().returncode == 0
    data = guest["opt"] / "data"
    (data / "feeds.db").write_bytes(b"x")
    (data / "instance.lock").write_bytes(b"x")
    (data / "model-traffic").mkdir()
    (data / "model-traffic" / "1.json").write_text("{}", encoding="utf-8")
    state, opt = guest["state"], guest["opt"]
    docker = tmp_path / "tools" / "docker"
    # после down -v настоящий Compose удаляет контейнеры и том
    docker.write_text(r"""#!/bin/bash
echo "$*" >> "$FAKE_STATE/commands"
case "$1" in
  volume) [ -e "$FAKE_STATE/volume" ]; exit $? ;;
  ps) [ -e "$FAKE_STATE/containers" ] && echo c-app; exit 0 ;;
  compose) case " $* " in *" down -v "*) [ -n "${FAKE_DOWN_NOOP:-}" ] || rm -f "$FAKE_STATE/volume" "$FAKE_STATE/containers";; esac; exit 0 ;;
esac
exit 0
""", encoding="utf-8", newline="\n")
    (state / "containers").write_text("", encoding="utf-8")
    script = text("guest", "cleanup.sh")
    body = "".join(_shell_function(script, name) for name in ("reset_database", "check_database_reset"))
    runner = tmp_path / "run-cleanup.sh"
    runner.write_text(f'set -euo pipefail\nD="{posix(opt)}"\nDB_VOLUME=local-triage_pgdata\n{body}\nreset_database\n'
                      "check_database_reset\necho ГОТОВО\n", encoding="utf-8", newline="\n")
    base = {**os.environ, "PATH": os.pathsep.join([str(tmp_path / "tools"), os.environ["PATH"]]), "FAKE_STATE": posix(state)}

    def run(**extra: str) -> subprocess.CompletedProcess:
        return subprocess.run([_git_bash(), posix(runner)], env={**base, **extra}, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)

    return {"run": run, "data": data, **{k: guest[k] for k in ("env", "commands", "opt")}}


def test_cleanup_leaves_only_what_first_boot_restores_from(cleanup: dict):
    r = cleanup["run"]()
    assert r.returncode == 0 and "ГОТОВО" in r.stdout, r.stdout + r.stderr
    assert any(" down -v --remove-orphans" in c for c in cleanup["commands"]())
    assert cleanup["env"]("POSTGRES_PASSWORD") == "", "пароль базы в образ не попадает"
    assert not re.search(r"(?m)^POSTGRES_PASSWORD=", (cleanup["opt"] / ".env").read_text(encoding="utf-8"))
    assert sorted(p.name for p in cleanup["data"].iterdir()) == ["demo.dump"]
    assert cleanup["env"]("TRIAGE_IMAGE"), "остальные настройки на месте"


def test_cleanup_control_fails_when_the_volume_survives(cleanup: dict):
    r = cleanup["run"](FAKE_DOWN_NOOP="1")
    assert r.returncode != 0 and "ГОТОВО" not in r.stdout and "Том базы" in r.stdout


def test_cleanup_control_fails_without_dump(cleanup: dict):
    (cleanup["data"] / "demo.dump").unlink()
    r = cleanup["run"]()
    assert r.returncode != 0 and "Нет demo.dump" in r.stdout


def test_cleanup_order_and_no_sqlite_conditions():
    """Таймер refresh остановлен раньше удаления контейнеров (иначе поднял бы их), контроль – после заполнения нулями."""
    script = text("guest", "cleanup.sh")
    body = script[script.index('echo "== приложение отвечает"'):]
    assert (body.index("systemctl stop local-triage-refresh.timer") < body.index("reset_database")
            < body.index("/zero.fill") < body.index("check_database_reset"))
    assert "systemctl disable" not in body, "в образе таймер остаётся включённым"
    assert 'docker image inspect "$(grep -E \'^TRIAGE_DB_IMAGE=' in script
    for name in ("cleanup.sh", "start.sh"):
        assert "triage.db" not in text("guest", name)
    assert "triage.db" not in text("build.sh")


# ============================================================================ настройки Compose и .env

@pytest.fixture
def compose_config(tmp_path: Path):
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("нет docker")

    def config(password: str | None = "secret-for-config") -> subprocess.CompletedProcess:
        env_file = tmp_path / ".env"
        lines = (VM / "guest" / "env.vm").read_text(encoding="utf-8")
        env_file.write_text(lines + (f"POSTGRES_PASSWORD={password}\n" if password else ""), encoding="utf-8", newline="\n")
        env = {k: v for k, v in os.environ.items() if k not in ("POSTGRES_PASSWORD", "COMPOSE_PROJECT_NAME")}
        return subprocess.run([docker, "compose", "-f", str(ROOT / "docker-compose.yml"), "-f",
                               str(VM / "guest" / "docker-compose.vm.yml"), "--project-directory", str(tmp_path),
                               "--env-file", str(env_file), "config", "--format", "json"],
                              env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)

    return config


def test_vm_compose_runs_database_service(compose_config):
    r = compose_config()
    assert r.returncode == 0, r.stderr
    config = json.loads(r.stdout)
    db, triage = config["services"]["db"], config["services"]["triage"]
    assert db["image"] == DB_TAG, "в ВМ образ базы – по тегу загруженного архива"
    assert "ports" not in db and db["environment"]["POSTGRES_DB"] == "triage"
    assert any(v["source"] == "pgdata" and v["target"] == "/var/lib/postgresql/data" for v in db["volumes"])
    assert "pgdata" in config["volumes"] and config["name"] == "local-triage"
    assert triage["depends_on"]["db"]["condition"] == "service_healthy" and "ollama" in triage["depends_on"]
    assert set(triage["networks"]) == {"default", "llm"} and config["networks"]["llm"]["internal"] is True
    assert [(p["host_ip"], p["published"]) for p in triage["ports"]] == [("127.0.0.1", "8765")]
    assert triage["environment"]["PGHOST"] == "db" and triage["environment"]["PGPASSWORD"] == "secret-for-config"


def test_vm_compose_requires_password(compose_config):
    assert compose_config(password=None).returncode != 0


def test_env_template_has_database_image_tag_and_no_password():
    env = text("guest", "env.vm")
    assert re.search(rf"(?m)^TRIAGE_DB_IMAGE={re.escape(DB_TAG)}$", env), "тег совпадает с образом docker-compose.yml"
    assert not re.search(r"(?m)^POSTGRES_PASSWORD=", env)
    build_script = text("build.sh")
    assert 's|^TRIAGE_DB_IMAGE=.*|TRIAGE_DB_IMAGE=${db%%@*}|' in build_script


# ============================================================================ тексты сценариев

def text(*parts: str) -> str:
    return (VM.joinpath(*parts)).read_text(encoding="utf-8")


def test_app_published_only_on_localhost_by_default():
    assert '"${TRIAGE_BIND:-127.0.0.1}:' in text("guest", "docker-compose.vm.yml")
    assert re.search(r"(?m)^TRIAGE_BIND=127\.0\.0\.1$", text("guest", "env.vm"))
    assert "ssh -L 8765:127.0.0.1:8765 triage@" in text("guest", "issue.append")
    start = text("guest", "start.sh")
    assert 'BIND="${BIND:-127.0.0.1}"' in start and "report hostkey" in start


def test_build_ssh_checks_host_key_strictly():
    build = text("build.sh")
    assert "StrictHostKeyChecking=no" not in build and "UserKnownHostsFile=/dev/null" not in build
    assert "StrictHostKeyChecking=yes" in build and "HostKeyAlias" in build
    assert 'guestvar "$1" hostkey' in build  # ключ – через канал гипервизора
    for name in ("ssh_tunnel.py", "first_login.py"):
        assert "RejectPolicy" in text(name)


def test_finalize_marker_written_only_after_cleanup():
    """Порядок шагов finalize (поведение export без маркера – test_export_refused_*)."""
    build = text("build.sh")
    finalize = build[build.index("step_finalize() {"):build.index("step_export() {")]
    clean = finalize.index("bin/cleanup.sh")
    assert finalize.index('rm -f "$MARK"') < clean < finalize.index('disk_state > "$MARK"')
    assert finalize.index("база не работает или её порт опубликован") < clean
    for step in ("step_vm", "step_install", "step_firstboot"):
        body = build[build.index(f"{step}() {{"):]
        assert 'rm -f "$MARK"' in body[:body.index("\n}")]


def test_build_data_step_builds_database_anew():
    build = text("build.sh")
    data = build[build.index("step_data() {"):build.index("step_iso() {")]
    assert "retarget" not in data and "prepare_demo_data.py\")\" prepare" not in data
    # база образа без готовой базы: в вызове demo_db_build.py нет папки данных, вердикты – прогон при сборке
    call = data[data.index('demo_db_build.py")"'):data.index("--summary")]
    assert '"$(w "$BUILD/src")" "$(w "$STAGE/repos-root")"' in call and "--triage-model" in data
    assert "keep-key" not in build
    assert not (VM / "retarget_demo_data.py").exists()
    verify = build[build.index("step_verify() {"):build.index("chain_note()")]
    assert verify.index("port_closed") < verify.index("--change") < verify.index("--demo-button")
    assert "Permission denied" in verify


def test_image_keeps_no_build_server_address(demo: dict):
    """Профили образа (раздел 0.3 плана 0.9.12): включён один профиль local на Ollama ВМ; сборочный «Сервер сборки
    образа» выключен и без адреса; снимки его прогона – без адреса, с пометкой; адреса сборочного компьютера нет нигде
    в базе; проверка состава ловит адрес, если он остался."""
    image = demo["conninfo"]
    providers = rows(image, "SELECT id, name, trust, base_url, enabled, auth FROM llm_providers ORDER BY id")
    assert tuple(providers[0])[1:] == ("Ollama из «Настроек»", "local", "http://ollama:11434", 1, "none")
    assert [tuple(p)[1:5] for p in providers[1:]] == [("Сервер сборки образа", "local", "", 0)]
    executions = {tuple(r) for r in rows(image, "SELECT base_url, note FROM llm_executions")}
    assert executions == {("", "адрес сборки не сохраняется")}
    assert [tuple(r) for r in rows(image, "SELECT provider_id FROM projects")] == [(None,)]
    assert "127.0.0.1" not in all_text(image), "адреса сборочного сервера нет в базе"
    copy = copy_database(image)
    sql(copy, ("UPDATE llm_executions SET base_url = 'http://10.1.2.3:11434'",))
    con = check.connect(copy)
    try:
        assert any("адресом не ВМ" in p for p in check.profile_problems(con, check.table_names(con)))
    finally:
        con.close()


def test_question_on_a_build_answer_goes_to_the_project_profile(demo: dict, tmp_path: Path):
    """Ответ получен при сборке (адрес исполнителя не сохраняется): вопрос по нему задаётся профилю проекта, а
    подпись исполнителя говорит, что адрес сборки не сохраняется."""
    from app.ask import question_profile
    from app.config import Settings
    from app.db import Database
    from app.executors import executor_label
    copy = copy_database(demo["conninfo"])
    pid = rows(copy, "SELECT id FROM projects")[0][0]
    verdict_id = rows(copy, "SELECT verdict_id FROM cases WHERE verdict_id IS NOT NULL LIMIT 1")[0][0]
    db = Database(copy)
    try:
        settings = Settings(data_dir=tmp_path, repos_root=demo["root"], ollama_url="http://ollama:11434",
                            default_model=VM_MODEL)
        assert question_profile(db, settings, pid, verdict_id)["id"] == 1
        assert executor_label(db, db.verdict_execution(verdict_id)) == \
            "Сервер сборки образа (адрес сборки не сохраняется)"
    finally:
        db.close()


@pytest.mark.parametrize(("url", "vm"), [("http://ollama:11434", True), ("http://ollama:11434/api/chat", True),
                                         ("http://ollama:11434).", True),
                                         ("http://ollama:11434@10.20.30.40:11434", False),
                                         ("http://ollama:114340", False), ("https://ollama:11434", False),
                                         ("http://ollama.evil:11434", False), ("http://10.0.0.5:11434", False)])
def test_vm_address_is_compared_by_its_parts(url, vm):
    """Адрес ВМ в JSON образа сравнивается по схеме, узлу и порту, а не по началу строки."""
    assert check.vm_url(url) is vm

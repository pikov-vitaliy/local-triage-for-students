"""Этап 3.4: замечания третьей контрольной проверки версии 0.3.3 (docs/state/review-stage-3.md).

Проверяется поведение:
* шаг обновления базы 7: в базах, прошедших шаг 4 версии 0.3.1, согласие «Согласен с агентом», принятое по ответу
  A с соответствиями AST → CVE, не возвращается в силу после смены ответа на B и повторной загрузки A (цикл
  A → B → обновление → A); сохраняются только отпечатки, доказанно принадлежащие ответу без соответствий;
* доступ к ВМ по сети: закрытие подтверждается публикацией порта по данным Docker, а не пустым списком сокетов;
  без userland-proxy (DNAT без сокета) прежняя публичная публикация не принимается за закрытие; Docker не ответил,
  контейнер не работает или посторонний контейнер публикует порт – отказ, ограничение остаётся;
* файл секрета: права только владельца – с момента создания (ни одной наследованной записи), совместный доступ
  к файлу до записи секрета запрещён, существующий файл не переиспользуется.
"""

from __future__ import annotations

import os
from db_support import connect_db
import sys
from pathlib import Path

import pytest

from app.db import Database
from app.models import ScaAnswer
from app.routes import sca as sca_routes
from test_stage32_review import COMPONENT, finding, network  # noqa: F401  (network – фикстура)
from test_stage33_review import STEP5_032

ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / "deploy" / "vm"
STEP6_033 = "Этап 3.3: шаг 5 версии 0.3.2 считал updated_at временем подтверждения решения."

ANSWER_A = ScaAnswer(component=COMPONENT, version="1.4.2", conclusion="update", recommended_version="1.4.9",
                     explanation="Ответ A.", ids={"AST-1": ["CVE-2099-0001"]}, vulnerabilities=["AST-1"])
ANSWER_B = ScaAnswer(component=COMPONENT, version="1.4.2", conclusion="update", recommended_version="1.4.10",
                     explanation="Ответ B.", vulnerabilities=["AST-1"])
PLAIN = ScaAnswer(component="other", version="1.4.2", conclusion="update", recommended_version="1.4.9",
                  explanation="Без соответствий.", vulnerabilities=["AST-3"])


# ============================================================================ шаг обновления базы 7

def _as_schema(path: Path, version: int, step4_note: str) -> None:
    """База прежней версии: схема version, в журнале шаг 4 с данным описанием и последующие шаги до version."""
    notes = {5: STEP5_032, 6: STEP6_033}
    con = connect_db(path)
    with con:
        con.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", (str(version),))
        con.execute("DELETE FROM schema_version WHERE version >= 4")
        con.execute("INSERT INTO schema_version(version, applied_at, note) VALUES (4, '2026-10-15T11:48:13+00:00', ?)",
                    (step4_note,))
        for step in range(5, version + 1):
            con.execute("INSERT INTO schema_version(version, applied_at, note) VALUES (?, '2026-10-15T12:00:00+00:00', ?)",
                        (step, notes[step]))
    con.close()


def _state(db: Database, pid: int, hub_id: str) -> str:
    f = finding(db, pid, hub_id)
    state, _ = sca_routes.decision_state(f, db.get_review(pid, hub_id), sca_routes._latest_answer(db, pid, f),
                                         db.get_finding_by_hub_id(pid, hub_id))
    return state


# ============================================================================ доступ к ВМ по сети: Docker

def test_network_open_without_socket_is_confirmed_by_docker(network: dict):  # noqa: F811
    """Без userland-proxy сокета нет: открытие подтверждается публикацией по данным Docker."""
    r = network["run"]("open", "192.0.2.10", FAKE_NO_PROXY="1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert network["publish"]() == "0.0.0.0" and network["listen"]() == ""
    assert network["run"]("check").returncode == 0


def test_network_close_refuses_when_public_publication_has_no_socket(network: dict):  # noqa: F811
    """Обход из проверки: перезапуск «удался», прежний контейнер публикует порт на всех адресах правилом DNAT,
    сокета нет. Пустой список ss – не доказательство: ограничение остаётся, код 1."""
    assert network["run"]("open", "192.0.2.10", FAKE_NO_PROXY="1").returncode == 0
    r = network["run"]("close", FAKE_RESTART="noop", FAKE_NO_PROXY="1")
    assert r.returncode == 1 and "оставлено" in r.stdout, r.stdout
    assert network["guarded"]() and network["publish"]() == "0.0.0.0" and network["listen"]() == ""
    assert network["run"]("check").returncode == 0
    r = network["run"]("close", FAKE_NO_PROXY="1")  # контейнер перешёл на 127.0.0.1 – закрытие проходит
    assert r.returncode == 0, r.stdout
    assert not network["guarded"]() and network["publish"]() == "127.0.0.1"


@pytest.mark.parametrize("extra", [{"FAKE_DOCKER_FAIL": "1"}, {"FAKE_DOCKER_STOPPED": "1"},
                                   {"FAKE_DOCKER_OTHER": "0.0.0.0"}, {"FAKE_DOCKER_OTHER": "any"}])
def test_network_close_keeps_guard_when_docker_is_ambiguous(network: dict, extra: dict):  # noqa: F811
    """Docker не ответил, контейнер приложения не работает или посторонний контейнер публикует тот же порт на
    адресах ВМ (в том числе с пустым адресом – на всех): закрытие не подтверждено, ограничение остаётся."""
    assert network["run"]("open", "192.0.2.10").returncode == 0
    r = network["run"]("close", **extra)
    assert r.returncode == 1 and "оставлено" in r.stdout, r.stdout
    assert network["guarded"]() and network["run"]("check").returncode == 0


@pytest.mark.parametrize("extra", [{"FAKE_DOCKER_FAIL": "1"}, {"FAKE_DOCKER_STOPPED": "1"},
                                   {"FAKE_DOCKER_OTHER": "0.0.0.0"}])
def test_network_open_refuses_when_docker_is_ambiguous(network: dict, extra: dict):  # noqa: F811
    r = network["run"]("open", "192.0.2.10", **extra)
    assert r.returncode == 1 and "ОТКАЗ" in r.stdout, r.stdout
    assert network["bind"]() == "127.0.0.1" and network["publish"]() == "127.0.0.1"
    assert "ВНИМАНИЕ" in r.stdout  # вернуть на 127.0.0.1 подтверждённо не удалось: Docker неоднозначен


def test_network_status_shows_docker_publication(network: dict):  # noqa: F811
    r = network["run"]("status")
    assert "публикация Docker: local-triage 127.0.0.1" in r.stdout, r.stdout
    assert "Docker не ответил" in network["run"]("status", FAKE_DOCKER_FAIL="1").stdout


# ============================================================================ файл секрета

def _secret_file():
    sys.path.insert(0, str(VM))
    try:
        import secret_file
    finally:
        sys.path.remove(str(VM))
    return secret_file


@pytest.mark.skipif(os.name != "nt", reason="ACL Windows")
def test_secret_has_owner_only_rights_from_creation(tmp_path: Path, monkeypatch):
    """В момент создания у файла уже ровно одна запись – текущего пользователя, без наследованных прав каталога,
    даже если каталог явно разрешает чтение группе «Пользователи»."""
    import subprocess

    secret_file = _secret_file()
    folder = tmp_path / "open-folder"
    folder.mkdir()
    assert subprocess.run(["icacls", str(folder), "/grant", "*S-1-5-32-545:(OI)(CI)R"],
                          capture_output=True).returncode == 0
    seen = []
    real = secret_file.restrict

    def spy(path: str) -> None:
        seen.append(secret_file.acl_entries(path))  # до restrict: права, полученные при создании
        real(path)

    monkeypatch.setattr(secret_file, "restrict", spy)
    path = folder / "triage-password"
    secret_file.write_secret(str(path), "пароль\n")
    assert len(seen) == 1 and len(seen[0]) == 1 and secret_file._is_user(seen[0][0], secret_file._user())
    out = subprocess.run(["icacls", str(path)], capture_output=True, text=True, encoding="oem").stdout
    assert "(I)" not in out  # наследованных записей нет
    assert path.read_text(encoding="utf-8") == "пароль\n"


@pytest.mark.skipif(os.name != "nt", reason="совместный доступ Windows")
def test_secret_cannot_be_opened_by_others_before_it_is_written(tmp_path: Path):
    """Пока файл создан и не заполнен, открыть его ещё раз нельзя (совместный доступ запрещён): дескриптор,
    открытый до записи секрета, получить не удаётся."""
    secret_file = _secret_file()
    path = tmp_path / "triage-password"
    fd = secret_file._create_owner_only(str(path))
    try:
        with pytest.raises(PermissionError):
            open(path, "rb")
    finally:
        os.close(fd)


def test_secret_refuses_existing_file(tmp_path: Path):
    """Файл с тем же именем уже есть (его мог создать другой) – создание отказывает, а не открывает его."""
    secret_file = _secret_file()
    path = tmp_path / "triage-password"
    path.write_text("чужой\n", encoding="utf-8")
    with pytest.raises((SystemExit, FileExistsError)):
        secret_file._create_owner_only(str(path))
    assert path.read_text(encoding="utf-8") == "чужой\n"


@pytest.mark.skipif(os.name == "nt", reason="права POSIX")
def test_secret_is_0600_from_creation_on_posix(tmp_path: Path):
    secret_file = _secret_file()
    old = os.umask(0)
    try:
        fd = secret_file._create_owner_only(str(tmp_path / "s"))
        os.close(fd)
    finally:
        os.umask(old)
    assert (tmp_path / "s").stat().st_mode & 0o777 == 0o600

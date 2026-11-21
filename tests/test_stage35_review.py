"""Этап 3.5: замечания четвёртой контрольной проверки версии 0.3.4 (docs/state/review-stage-3.md).

Проверяется поведение:
* файл секрета: write_secret на существующем файле отказывает и не удаляет его; замена – только явная
  (replace_secret или prepare_secret и commit_secret): новый файл готовится рядом с правами владельца, прежний
  остаётся до успешной подготовки, при отказе подмены подготовленный файл с секретом не теряется; first_login.py
  готовит файл нового пароля до смены пароля на ВМ;
* шаг обновления 7 вместе с отпечатком снимает отметку «Проверено»; шаг 8 возвращает на проверку согласия
  «Согласен с агентом» с пустым отпечатком в базах, уже прошедших шаг 7 версии 0.3.4: находка снова
  в «непроверенных», в ходе разбора и в обходе. Находки SAST, своё решение, «Риск принят» и согласия
  с отпечатком не трогаются.
"""

from __future__ import annotations

from db_support import connect_db
import sys
from pathlib import Path

import pytest

from app import db as db_module  # noqa: F401  (схема базы в тестах прежних этапов)
from app.models import ScaAnswer
from legacy_support import DECIDED, EARLY, set_times
from test_stage32_review import COMPONENT
from test_stage33_review import STEP5_032
from test_stage34_review import STEP6_033

ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / "deploy" / "vm"
BASE = "http://127.0.0.1:8765"
STEP7_034 = "Этап 3.4: шаги 5 и 6 сверяли отпечаток решения только с последним ответом по библиотеке."

ANSWER_A = ScaAnswer(component=COMPONENT, version="1.4.2", conclusion="update", recommended_version="1.4.9",
                     explanation="Ответ A.", ids={"AST-1": ["CVE-2099-0001"]}, vulnerabilities=["AST-1"])
PLAIN = ScaAnswer(component="other", version="1.4.2", conclusion="update", recommended_version="1.4.9",
                  explanation="Без соответствий.", vulnerabilities=["AST-3"])


# ============================================================================ файл секрета

def _secret_file():
    sys.path.insert(0, str(VM))
    try:
        import secret_file
    finally:
        sys.path.remove(str(VM))
    return secret_file


def test_write_secret_refuses_existing_file(tmp_path: Path):
    """Публичная функция: файл уже есть – отказ, файл не удалён и не изменён, лишних файлов нет."""
    secret_file = _secret_file()
    path = tmp_path / "triage-password-copy"
    path.write_text("прежний\n", encoding="utf-8")
    with pytest.raises(FileExistsError):
        secret_file.write_secret(str(path), "новый\n")
    assert path.read_text(encoding="utf-8") == "прежний\n"
    assert [p.name for p in tmp_path.iterdir()] == ["triage-password-copy"]


def test_write_secret_creates_new_file(tmp_path: Path):
    secret_file = _secret_file()
    path = tmp_path / "triage-password"
    secret_file.write_secret(str(path), "пароль\n")
    assert path.read_text(encoding="utf-8") == "пароль\n"
    secret_file._check_owner_only(str(path))


def test_replace_secret_replaces_and_keeps_owner_only(tmp_path: Path):
    secret_file = _secret_file()
    path = tmp_path / "triage-password-copy"
    path.write_text("прежний\n", encoding="utf-8")
    secret_file.replace_secret(str(path), "новый\n")
    assert path.read_text(encoding="utf-8") == "новый\n"
    secret_file._check_owner_only(str(path))
    assert [p.name for p in tmp_path.iterdir()] == ["triage-password-copy"]
    secret_file.replace_secret(str(tmp_path / "nothing-before"), "первый\n")  # прежнего файла может не быть
    assert (tmp_path / "nothing-before").read_text(encoding="utf-8") == "первый\n"


def test_replace_secret_keeps_old_file_when_preparation_fails(tmp_path: Path, monkeypatch):
    """Права нового файла не подтвердились – прежний файл цел, подготовленный удалён."""
    secret_file = _secret_file()
    path = tmp_path / "triage-password-copy"
    path.write_text("прежний\n", encoding="utf-8")

    def broken(_path: str) -> None:
        raise SystemExit("права не подтвердились")

    monkeypatch.setattr(secret_file, "restrict", broken)
    with pytest.raises(SystemExit):
        secret_file.replace_secret(str(path), "новый\n")
    assert path.read_text(encoding="utf-8") == "прежний\n"
    assert [p.name for p in tmp_path.iterdir()] == ["triage-password-copy"]


def test_prepare_removes_new_file_when_final_check_fails(tmp_path: Path, monkeypatch):
    """Новый файл записан, но последняя проверка прав не прошла – подготовленный файл удалён, прежний цел."""
    secret_file = _secret_file()
    path = tmp_path / "triage-password-copy"
    path.write_text("прежний\n", encoding="utf-8")

    def broken(_path: str) -> None:
        raise SystemExit("права не подтвердились")

    monkeypatch.setattr(secret_file, "_check_owner_only", broken)
    with pytest.raises(SystemExit):
        secret_file.replace_secret(str(path), "новый\n")
    assert path.read_text(encoding="utf-8") == "прежний\n"
    assert [p.name for p in tmp_path.iterdir()] == ["triage-password-copy"]


def test_commit_failure_keeps_old_file_and_prepared_secret(tmp_path: Path, monkeypatch):
    """Подмена не удалась: прежний файл цел; у commit_secret подготовленный файл с новым секретом остаётся (это может
    быть единственная копия пароля), его путь – в сообщении; replace_secret его убирает (секрет у вызывающего)."""
    secret_file = _secret_file()
    path = tmp_path / "triage-password-copy"
    path.write_text("прежний\n", encoding="utf-8")
    pending = secret_file.prepare_secret(str(path), "новый\n")
    assert Path(pending).parent == tmp_path and Path(pending).read_text(encoding="utf-8") == "новый\n"
    assert path.read_text(encoding="utf-8") == "прежний\n"  # до подмены прежний не тронут

    def broken(_src, _dst):
        raise PermissionError("занят")

    monkeypatch.setattr(secret_file.os, "replace", broken)
    with pytest.raises(SystemExit) as failed:
        secret_file.commit_secret(pending, str(path))
    assert pending in str(failed.value)
    assert path.read_text(encoding="utf-8") == "прежний\n"
    assert Path(pending).read_text(encoding="utf-8") == "новый\n"
    secret_file.discard_secret(pending)
    with pytest.raises(SystemExit):
        secret_file.replace_secret(str(path), "новый\n")
    assert [p.name for p in tmp_path.iterdir()] == ["triage-password-copy"]
    assert path.read_text(encoding="utf-8") == "прежний\n"


def test_commit_secret_check_fails_after_replace(tmp_path: Path, monkeypatch):
    """Подмена прошла, повторная проверка прав отказала: прежнего файла уже нет, новый секрет лежит в path
    (не потерян), подготовленного имени больше нет, отказ называет path."""
    secret_file = _secret_file()
    path = tmp_path / "triage-password-copy"
    path.write_text("прежний\n", encoding="utf-8")
    pending = secret_file.prepare_secret(str(path), "новый\n")

    def refuse(target):
        raise SystemExit(f"на {target} есть права не только владельца")

    monkeypatch.setattr(secret_file, "_check_owner_only", refuse)
    with pytest.raises(SystemExit) as failed:
        secret_file.commit_secret(pending, str(path))
    assert str(path) in str(failed.value)
    assert path.read_text(encoding="utf-8") == "новый\n"
    assert not Path(pending).exists()
    assert [p.name for p in tmp_path.iterdir()] == ["triage-password-copy"]


def test_first_login_prepares_password_file_before_change():
    """first_login.py: файл нового пароля готовится до отправки текущего пароля на смену, подменяет прежний только
    после проверки sudo; при отказе после отправки нового пароля файл не удаляется."""
    text = (VM / "first_login.py").read_text(encoding="utf-8")
    assert "write_secret" not in text
    prepare = text.index("pending = prepare_secret(newfile")
    assert prepare < text.index("ch.send((old")
    assert text.index("sent = True") < text.index("ch.send((new")
    assert text.index("sudo -S") < text.index("commit_secret(pending, newfile)")
    handler = text[text.index("except BaseException:"):text.index("commit_secret(pending, newfile)")]
    assert "if sent:" in handler and "discard_secret(pending)" in handler.split("else:")[1]


# ============================================================================ шаги обновления 7 и 8

def _as_schema(path: Path, version: int, step4_note: str, clear: tuple[str, ...] = ()) -> None:
    """База прежней версии: схема version, в журнале шаг 4 с данным описанием и последующие шаги; clear – решения,
    у которых шаги 4–7 прежних версий уже очистили отпечаток, оставив отметку «Проверено»."""
    notes = {5: STEP5_032, 6: STEP6_033, 7: STEP7_034}
    con = connect_db(path)
    with con:
        con.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", (str(version),))
        con.execute("DELETE FROM schema_version WHERE version >= 4")
        con.execute("INSERT INTO schema_version(version, applied_at, note) VALUES (4, '2026-10-15T11:48:13+00:00', ?)",
                    (step4_note,))
        for step in range(5, version + 1):
            con.execute("INSERT INTO schema_version(version, applied_at, note) VALUES (?, '2026-10-15T12:00:00+00:00', ?)",
                        (step, notes[step]))
        for hub_id in clear:
            con.execute("UPDATE reviews SET answer_sig = '' WHERE hub_id = ?", (hub_id,))
    con.close()
    # решения приняты после последней загрузки: экосистема на момент решения доказана, шаг 11 их не возвращает на проверку
    set_times(path, import_at=EARLY, reviewed_at=DECIDED)

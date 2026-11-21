"""Страж чистоты репозитория: во всех текстовых файлах, которые попадут в git, нет длинного тире, сокращения
«ФСТЭК» без «России», путей с диска разработчика, реального проекта и людей владельца, номеров Hub его проекта;
у сценариев PowerShell есть BOM (без него Windows PowerShell 5.1 читает кириллицу неверно).

Слова для поиска собираются из частей: иначе тест нашёл бы сам себя."""

from __future__ import annotations

import shutil
import sys
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from hygiene_rules import (  # noqa: E402 – правила общие со стражем пакета npm
    BINARY, LONG_DASH, FSTEC, FSTEC_BARE, LOCAL_PATHS, REAL_PROJECT, STAND_LAN, CONTROL, hub_number_hits)
# Тесты-стражи сами содержат образцы запрещённого: для них – только тире
GUARDS = {"tests/test_docs.py", "tests/test_sca.py", "tests/test_repo_hygiene.py", "scripts/hygiene_rules.py"}


def repo_files() -> list[Path]:
    """Файлы, которые попадут в git: отслеживаемые и новые, кроме игнорируемых."""
    git = shutil.which("git")
    if not git or not (ROOT / ".git").exists():
        pytest.skip("нет git или репозитория")
    out = subprocess.run([git, "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT,
                         capture_output=True, timeout=60)
    if out.returncode != 0:
        pytest.skip("git ls-files не сработал")
    names = [n for n in out.stdout.decode("utf-8", "replace").split("\0") if n]
    return [ROOT / n for n in names if (ROOT / n).is_file() and Path(n).suffix.lower() not in BINARY]


def text_of(path: Path) -> str:
    return path.read_bytes().decode("utf-8-sig", "replace")


def test_texts_are_clean():
    problems = []
    for path in repo_files():
        rel = path.relative_to(ROOT).as_posix()
        text = text_of(path)
        if LONG_DASH in text:
            problems.append(f"{rel}: длинное тире")
        found = CONTROL.search(text)
        if found:
            line = text.count(chr(10), 0, found.start()) + 1
            problems.append(f"{rel}:{line}: управляющий знак {ord(found.group(0)):#04x}")
        if rel not in GUARDS and FSTEC_BARE.search(text):
            problems.append(f"{rel}: «{FSTEC}» без «России»")
        found = None if rel in GUARDS else LOCAL_PATHS.search(text)
        if found:
            problems.append(f"{rel}: путь «{found.group(0)}»")
        found = REAL_PROJECT.search(text)
        if found:
            problems.append(f"{rel}: «{found.group(0)}» – реальный проект или имя")
        found = None if rel in GUARDS else STAND_LAN.search(text)
        if found:
            problems.append(f"{rel}: адрес стенда «{found.group(0)}»")
        for what, shown, at in hub_number_hits(text):
            line = text.count(chr(10), 0, at) + 1
            problems.append(f"{rel}:{line}: {what} не из вымышленных – «{shown}»")
    assert not problems, "\n".join(problems)


def test_powershell_scripts_have_bom():
    scripts = [p for p in repo_files() if p.suffix.lower() == ".ps1"]
    assert scripts
    missing = [p.relative_to(ROOT).as_posix() for p in scripts if not p.read_bytes().startswith(b"\xef\xbb\xbf")]
    assert not missing, missing


@pytest.mark.parametrize("text, clean", [
    ("дефект ID1 · " + chr(0x2116) + "90001", True), ("дефект ID1 · " + chr(0x2116) + "8" + "001", False),
    ("приказ " + chr(0x2116) + " 240", True), ("«" + chr(0x2116) + "12345,»", True),
    ("у находки 510001 близнец", True), ("находки 100115 нет, есть 100116", True), ("находка 73002", True),
    ("находки 4" + "1001 и 4" + "1002", False), ("находке 17" + "40001 отказ", False),
    ("https://hub.example.org/#/defects/90002", True), ("https://hub.example.org/#/defects/80" + "01", False),
    ("#/appprofile/952/issues/SAST/9000001", True), ("#/appprofile/952/issues/SAST/17" + "40001", False),
    ("1500 находок и 12 дефектов", True), ("pytest 8448 прошли", True),
    (chr(0x2116) + "  4" + "5678", False), (chr(0x2116) + " **4" + "5678**", False),
    ("находка **4" + "5678**", False), ("находки 90001 и 4" + "5678", False), ("находке " + chr(0x2116) + " 510001, 4" + "5678", False),
    ("находки 90001, 510002 и 100116", True), ("находка 370000", True), ("находка 3" + "7000", False), ("приказ " + chr(0x2116) + " 1234", True),
    ("постановление Правительства от 01.02.2024 " + chr(0x2116) + " 1236", True), ("дефект " + chr(0x2116) + " 1234", False),
    ("находка: 4" + "5678", False), ("дефекты " + chr(0x2116) + " 90001, 4" + "5678", False),
    ("Согласно письму закрыт дефект " + chr(0x2116) + " 4" + "5678", False), ("дефекты " + chr(0x2116) + " 90001, 90002 и 90003", True),
    ("находка: 510001", True), ("письмо от 03.04.2025 " + chr(0x2116) + " 12-34/5678", True),
])
def test_hub_numbers_rule(text: str, clean: bool):
    """Правило номеров Hub: вымышленные номера проходят, похожие на настоящие – нет; счётчики и номера документов
    (до трёх цифр после знака номера) правило не задевает."""
    hits = hub_number_hits(text)
    assert (not hits) is clean, hits

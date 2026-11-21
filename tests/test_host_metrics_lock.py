"""Сборщик метрик компьютера не умирает, когда host.json открыт читателем: замена снимка
повторяется, не вышло – снимок пропускается, следующий цикл пишет новый. Настоящий Windows PowerShell, папка данных –
временная."""
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/host-metrics.ps1"


def wait_for(check, timeout: float):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.2)
    return None


def sequence(path: Path) -> int:
    try:
        return int(json.loads(path.read_text(encoding="utf-8-sig"))["sequence"])
    except (OSError, ValueError, KeyError):
        return 0


def collector_survives_a_locked_snapshot(script: Path, data_dir: Path) -> tuple[bool, int, int]:
    """(жив ли сборщик после блокировки, номер снимка до блокировки, номер после неё)."""
    executable = shutil.which("powershell")
    instance = "lock-test-" + str(os.getpid())
    child = subprocess.Popen([executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                              str(script), "-Action", "Run", "-DataDir", str(data_dir), "-Instance", instance],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    folder = data_dir / "telemetry"
    host = folder / "host.json"
    try:
        assert wait_for(lambda: sequence(host) >= 1, 30), "сборщик не записал первый снимок"
        before = sequence(host)
        # читатель держит файл без права удаления (как Python и многие программы): Windows отказывает в замене
        with open(host, "rb"):
            time.sleep(8)  # больше цикла сборщика (5 с) – хотя бы одна замена приходится на блокировку
            locked_until = sequence(host)
        after = wait_for(lambda: sequence(host) > locked_until and sequence(host), 20) or 0
        return child.poll() is None, before, after
    finally:
        (folder / "stop").write_text(instance, encoding="utf-8")
        try:
            child.wait(timeout=20)
        except subprocess.TimeoutExpired:
            child.kill()


def test_once_reports_a_locked_snapshot_and_leaves_no_temp_file(tmp_path):
    """Разовый сбор (Once) при открытом снимке – ошибка, как раньше, но временный файл убран (ревью Codex, круг 17)."""
    if os.name != "nt" or not shutil.which("powershell"):
        pytest.skip("Проверка сборщика Windows")
    run = [shutil.which("powershell"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
           str(SCRIPT), "-Action", "Once", "-DataDir", str(tmp_path)]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    assert subprocess.run(run, capture_output=True, timeout=60, creationflags=flags).returncode == 0
    with open(tmp_path / "telemetry" / "host.json", "rb"):
        locked = subprocess.run(run, capture_output=True, timeout=60, creationflags=flags)
    assert locked.returncode != 0, "разовый сбор сообщает об ошибке замены"
    assert not list((tmp_path / "telemetry").glob("host-*.tmp")), "временный файл убран и при ошибке"


def test_collector_keeps_running_while_the_snapshot_is_open(tmp_path):
    if os.name != "nt" or not shutil.which("powershell"):
        pytest.skip("Проверка сборщика Windows")
    alive, before, after = collector_survives_a_locked_snapshot(SCRIPT, tmp_path)
    assert alive, "сборщик завершился, пока снимок был открыт читателем"
    assert after > before, "после снятия блокировки сборщик пишет новые снимки"
    assert not list((tmp_path / "telemetry").glob("host-lock-test-*.tmp")), "временный файл пропущенного снимка убран"

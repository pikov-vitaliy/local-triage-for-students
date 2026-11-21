"""Сборщик метрик хоста на Windows – поведенчески, настоящими процессами (0.9.13, ревью D1): запуск даёт свежий
снимок с адресами компьютера; повторный и одновременный запуск заменяют прежний сборщик – работает ровно один;
адреса не прочитались – запуск отказывает, даже если рядом старый снимок с адресами; остановка – сигналом.
Временная папка данных; другие системы – пропуск с причиной."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "host-metrics.ps1"
POWERSHELL = (shutil.which("powershell.exe") or "") if sys.platform == "win32" else ""

pytestmark = pytest.mark.skipif(not POWERSHELL, reason="сборщик метрик – сценарий Windows PowerShell")


def collector(action: str, data: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    # Диагностика PowerShell может иметь кодировку консоли, отличную от ANSI Python.
    # Непредставимые байты сохраняются как escape; код выхода, причина отказа и снимок проверяются ниже.
    return subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                           str(SCRIPT), "-Action", action, "-DataDir", str(data)],
                          capture_output=True, text=True, errors="backslashreplace", timeout=120, env=env)


def snapshot(data: Path) -> dict:
    """Запущенный сборщик заменяет файл целиком: в Windows чтение в этот момент получает PermissionError."""
    for _ in range(50):
        try:
            return json.loads((data / "telemetry" / "host.json").read_text(encoding="utf-8-sig"))
        except PermissionError:
            time.sleep(0.1)
    return json.loads((data / "telemetry" / "host.json").read_text(encoding="utf-8-sig"))


# Свой сборщик – только по точным аргументам, которые ставит Start (host-metrics.ps1): -File "<этот сценарий>",
# -Action Run и -DataDir "<временная папка теста>" в кавычках целиком – соседняя папка с тем же началом пути не
# совпадает. Пути передаются через окружение, а не в текст запроса: сам запрос под условие не попадает, а знаки
# подстановки -like ([ ] * ?) в пути ничего не значат (сравнение – IndexOf без учёта регистра).
OWN = ("$s = '-File \"' + $env:HM_SCRIPT + '\"'; $d = '-DataDir \"' + $env:HM_DATA + '\"'; "
       "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" -ErrorAction Stop | Where-Object { "
       "$c = [string]$_.CommandLine; $c.Contains(' -Action Run ') -and "
       "$c.IndexOf($s, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and "
       "$c.IndexOf($d, [StringComparison]::OrdinalIgnoreCase) -ge 0 }")


def own(data: Path, then: str) -> list[int]:
    """Свои процессы сборщика на папке теста; then – что сделать с каждым в том же запросе (без промежутка между
    опознанием и действием). Ошибка запроса – падение, а не «процессов нет»."""
    env = {**os.environ, "HM_SCRIPT": str(SCRIPT), "HM_DATA": str(data)}
    out = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", f"{OWN} | ForEach-Object {{ {then} }}"],
                         capture_output=True, text=True, timeout=60, env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    return [int(line) for line in out.stdout.split()]


def pids(data: Path) -> list[int]:
    return own(data, "$_.ProcessId")


def stop_all(data: Path) -> None:
    """Сигнал остановки и ожидание 20 с; не вышедший сам сборщик теста завершается (опознание и завершение – одним
    запросом), затем остановка подтверждается. Уборка идёт до конца, даже если отдельный шаг упал."""
    problems: list[str] = []
    try:
        stopped = collector("Stop", data)
        if stopped.returncode != 0:
            problems.append("Stop: " + stopped.stdout + stopped.stderr)
    except Exception as e:  # noqa: BLE001 – уборка продолжается
        problems.append(f"Stop: {e!r}")
    deadline = time.monotonic() + 20
    left: list[int] = []
    while time.monotonic() < deadline:
        try:
            left = pids(data)
        except AssertionError as e:
            problems.append(f"поиск процессов: {e}")
            break
        if not left:
            break
        time.sleep(1)
    killed = own(data, "Invoke-CimMethod -InputObject $_ -MethodName Terminate -ErrorAction Stop | Out-Null; "
                       "$_.ProcessId") if left else []
    gone = time.monotonic() + 10
    while pids(data) and time.monotonic() < gone:
        time.sleep(0.5)
    assert not pids(data), "процессы сборщика теста остались после уборки"
    assert not problems, problems
    assert not killed, f"сборщик не остановился по сигналу за 20 с и завершён уборкой: {killed}"


def without_addresses(tmp_path: Path) -> dict[str, str]:
    """Окружение, где Get-NetIPAddress ничего не отдаёт: подменный модуль NetTCPIP первым в пути модулей. Его
    наследует и скрытый процесс сборщика – Start-Process передаёт окружение родителя."""
    module = tmp_path / "modules" / "NetTCPIP"
    module.mkdir(parents=True)
    (module / "NetTCPIP.psm1").write_text("function Get-NetIPAddress { param($AddressFamily, $ErrorAction) }\n"
                                          "Export-ModuleMember -Function Get-NetIPAddress\n", encoding="utf-8")
    env = dict(os.environ)
    env["PSModulePath"] = str(module.parent) + os.pathsep + env.get("PSModulePath", "")
    return env


def test_start_gives_a_fresh_snapshot_with_addresses_and_replaces_itself(tmp_path):
    data = tmp_path / "data"
    try:
        first = collector("Start", data)
        assert first.returncode == 0, first.stdout + first.stderr
        snap = snapshot(data)
        assert snap["addresses"] and abs(time.time() - snap["sampled_at"]) < 30
        before = snap["collector_id"]
        results = []
        both = [threading.Thread(target=lambda: results.append(collector("Start", data))) for _ in range(2)]
        for t in both:
            t.start()
        for t in both:
            t.join()
        assert [r.returncode for r in results] == [0, 0], [r.stdout + r.stderr for r in results]
        time.sleep(7)  # прежние сборщики выходят на следующем цикле (5 с)
        assert len(pids(data)) == 1, "после замены и двух одновременных запусков работает ровно один сборщик"
        assert snapshot(data)["collector_id"] != before and snapshot(data)["addresses"]
    finally:
        stop_all(data)


def test_start_fails_when_the_new_collector_reads_no_addresses(tmp_path):
    data = tmp_path / "data"
    try:
        first = collector("Start", data)
        assert first.returncode == 0, first.stdout + first.stderr
        before = snapshot(data)
        assert before["addresses"], "рядом – прежний снимок с адресами"
        second = collector("Start", data, env=without_addresses(tmp_path))
        assert second.returncode != 0, "запуск без адресов компьютера не засчитан успешным"
        assert "Get-NetIPAddress" in second.stdout + second.stderr  # причина отказа названа (текст – в кодировке консоли)
        snap = snapshot(data)
        assert snap["collector_id"] != before["collector_id"] and snap["addresses"] == []
    finally:
        stop_all(data)

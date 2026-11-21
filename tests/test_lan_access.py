"""Доступ к интерфейсу из локальной сети (ADR-0103): второй адрес публикации порта – только по явному выбору
владельца; без адреса – как в ADR-0014, только 127.0.0.1; пустой адрес Docker Compose не принимает."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


def test_base_compose_publishes_only_on_loopback():
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert '- "127.0.0.1:${TRIAGE_PORT:-8765}:8765"' in text
    assert "TRIAGE_LAN_ADDR" not in text, "второй адрес – только в отдельном файле"


def test_lan_compose_requires_an_address_and_trusts_it():
    text = (ROOT / "docker-compose.lan.yml").read_text(encoding="utf-8")
    assert '- "${TRIAGE_LAN_ADDR:?TRIAGE_LAN_ADDR не задан}:${TRIAGE_PORT:-8765}:8765"' in text
    assert 'TRUSTED_HOSTS: "${TRIAGE_LAN_ADDR:?TRIAGE_LAN_ADDR не задан},${TRUSTED_HOSTS:-}"' in text
    assert "0.0.0.0" not in text.split("services:", 1)[1]


def test_env_example_keeps_local_only_by_default():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "\nTRIAGE_LAN_ADDR=\n" in text


@pytest.mark.skipif(not POWERSHELL, reason="нет PowerShell")
def test_start_script_checks_and_stores_the_address(tmp_path: Path):
    """Test-LanAddress принимает только IPv4 одного адаптера (не 0.0.0.0, 127.x, 169.254.x, групповые); Set-LanAddress
    меняет только строку TRIAGE_LAN_ADDR. Сценарий подключается через «.» – Docker не трогается."""
    (tmp_path / ".env").write_text("REPOS_ROOT=D:/repos\nTRIAGE_PORT=8765\n", encoding="utf-8")
    script = ROOT / "start.ps1"
    cases = ["192.0.2.10", "10.0.0.5", "0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1", "256.1.1.1",
             "192.168.1", "abc", "192.0.2.10:8765"]
    checks = "; ".join(f"Write-Output ('{c}=' + (Test-LanAddress '{c}'))" for c in cases)
    command = (f". '{script}'; {checks}; "
               f"Set-LanAddress '{tmp_path}' ' 192.0.2.10 '; "
               f"$on = Get-EnvValue (Read-Lines '{tmp_path}\\.env') 'TRIAGE_LAN_ADDR'; "
               "Write-Output ('on=' + $on); "
               f"Set-LanAddress '{tmp_path}' ''; "
               f"$off = Get-EnvValue (Read-Lines '{tmp_path}\\.env') 'TRIAGE_LAN_ADDR'; "
               "Write-Output ('off=' + $off); "
               "Write-Output ('missing=' + (Test-LocalAddress '203.0.113.77'))")
    out = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                         capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert out.returncode == 0, out.stderr
    lines = dict(line.split("=", 1) for line in out.stdout.splitlines() if "=" in line)
    assert lines["192.0.2.10"] == "True" and lines["10.0.0.5"] == "True"
    for bad in cases[2:]:
        assert lines[bad] == "False", bad
    assert lines["on"] == "192.0.2.10" and lines["off"] == "" and lines["missing"] == "False"
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "REPOS_ROOT=D:/repos" in env and "TRIAGE_PORT=8765" in env and env.count("TRIAGE_LAN_ADDR=") == 1


def test_start_script_adds_the_lan_file_only_for_a_present_address():
    text = (ROOT / "start.ps1").read_bytes().decode("utf-8-sig")
    assert "if ((Test-LanAddress $lanAddr) -and (Test-LocalAddress $lanAddr)) {" in text
    assert "$base += @('-f', 'docker-compose.lan.yml')" in text
    assert "[string]$LanAddress = ''" in text and "[switch]$LocalOnly" in text
    assert "$env:TRIAGE_LAN_ADDR = $lanAddr" in text, "Compose получает проверенный адрес"
    assert text.index("if ($LanAddress -and $LocalOnly)") < text.index("Initialize-EnvFile $PSScriptRoot")
    assert text.index("$wrong = Get-WrongPublications") < text.index("& docker @compose up -d --no-build")


@pytest.mark.skipif(not POWERSHELL, reason="нет PowerShell")
def test_lan_address_from_env_lines_and_wrong_publications():
    """Адрес из .env – как его поймёт человек (кавычки, пробелы, комментарий); публикации не на 127.0.0.1 и не на
    проверенном адресе (0.0.0.0, чужой, без адреса) – отказ."""
    script = ROOT / "start.ps1"
    lines = {"q": 'TRIAGE_LAN_ADDR="192.0.2.10"', "s": "TRIAGE_LAN_ADDR=' 192.0.2.10 '",
             "c": "TRIAGE_LAN_ADDR=192.0.2.10 # мой ПК", "e": "TRIAGE_LAN_ADDR=", "n": "OTHER=1"}
    quoted = {k: v.replace("'", "''") for k, v in lines.items()}  # строка PowerShell в одинарных кавычках
    checks = "; ".join(f"Write-Output ('{k}=' + (Get-LanAddressValue @('{v}')))" for k, v in quoted.items())
    ports = ("$ok = @([pscustomobject]@{host_ip='127.0.0.1'}, [pscustomobject]@{host_ip='192.0.2.10'}); "
             "$bad = @([pscustomobject]@{host_ip='127.0.0.1'}, [pscustomobject]@{host_ip='0.0.0.0'}, "
             "[pscustomobject]@{host_ip=''}); "
             "Write-Output ('ok=' + ((Get-WrongPublications $ok @('127.0.0.1','192.0.2.10')) -join '|')); "
             "Write-Output ('bad=' + ((Get-WrongPublications $bad @('127.0.0.1','192.0.2.10')) -join '|')); "
             "Write-Output ('local=' + ((Get-WrongPublications $ok @('127.0.0.1')) -join '|'))")
    out = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                          f". '{script}'; {checks}; {ports}"],
                         capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert out.returncode == 0, out.stderr
    got = dict(line.split("=", 1) for line in out.stdout.splitlines() if "=" in line)
    assert got["q"] == got["s"] == got["c"] == "192.0.2.10" and got["e"] == "" and got["n"] == ""
    bad = got["bad"].split("|")  # вывод PowerShell – в кодировке консоли: русская подпись «все адаптеры» не сверяется
    assert got["ok"] == "" and len(bad) == 2 and bad[0] == "0.0.0.0" and bad[1] and got["local"] == "192.0.2.10"


def _docker_ready() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        return subprocess.run([docker, "info", "--format", "{{.ServerVersion}}"], capture_output=True,
                              timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.mark.skipif(not _docker_ready(), reason="нет Docker")
def test_compose_merges_publications_and_trusted_hosts(tmp_path: Path):
    """Настоящий Docker Compose: с файлом сети остаются 127.0.0.1 и адрес из переменной окружения, к TRUSTED_HOSTS из
    .env добавляется адрес; пустой адрес – отказ. Своего .env у теста – отдельный файл (--env-file)."""
    import json
    import os
    env_file = tmp_path / "test.env"
    env_file.write_text("POSTGRES_PASSWORD=x\nTRUSTED_HOSTS=triage.example\nTRIAGE_LAN_ADDR=10.9.9.9\n", encoding="utf-8")
    base = [shutil.which("docker"), "compose", "--env-file", str(env_file), "-f", str(ROOT / "docker-compose.yml"),
            "-f", str(ROOT / "docker-compose.lan.yml"), "config", "--format", "json"]
    # окружение запускающего процесса не влияет: переменные приложения из него убираются (их приоритет – выше .env)
    clean = {k: v for k, v in os.environ.items() if not k.upper().startswith(("TRIAGE_", "TRUSTED_HOSTS"))}
    run_env = {**clean, "TRIAGE_LAN_ADDR": "192.0.2.10"}
    out = subprocess.run(base, capture_output=True, text=True, encoding="utf-8", timeout=60, env=run_env)
    assert out.returncode == 0, out.stderr
    service = json.loads(out.stdout)["services"]["triage"]
    assert sorted(p.get("host_ip") for p in service["ports"]) == ["127.0.0.1", "192.0.2.10"], \
        "переменная окружения процесса важнее строки .env – start.ps1 передаёт проверенный адрес так"
    assert service["environment"]["TRUSTED_HOSTS"] == "192.0.2.10,triage.example"
    empty = {**clean, "TRIAGE_LAN_ADDR": ""}
    out = subprocess.run(base, capture_output=True, text=True, encoding="utf-8", timeout=60, env=empty)
    assert out.returncode != 0 and "TRIAGE_LAN_ADDR" in (out.stderr + out.stdout)


def test_guard_accepts_the_lan_address_and_rejects_foreign_origin(tmp_path: Path):
    """Интерфейс по адресу сети: имя хоста из TRUSTED_HOSTS проходит, POST с этой же страницы – тоже, с чужой – 403;
    имя, которого нет в TRUSTED_HOSTS, – 400 с подсказкой."""
    from fastapi.testclient import TestClient

    from app.config import Settings, _hosts
    from app.main import create_app
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url="http://127.0.0.1:9",
                        trusted_hosts=_hosts("192.0.2.10"))
    (tmp_path / "repos").mkdir()
    with TestClient(create_app(settings), base_url="http://192.0.2.10:8765") as client:
        assert client.get("/healthz").status_code == 200
        same = client.post("/lan-probe", headers={"Origin": "http://192.0.2.10:8765"}, follow_redirects=False)
        assert same.status_code in (404, 405), "проверку источника прошёл, такого адреса нет"
        foreign = client.post("/lan-probe", headers={"Origin": "http://192.0.2.12:8765"}, follow_redirects=False)
        assert foreign.status_code == 403
    with TestClient(create_app(settings), base_url="http://192.0.2.99:8765") as client:
        r = client.get("/healthz")
        assert r.status_code == 400 and "TRIAGE_LAN_ADDR" in r.text


# ============================================================================ основной поток start.ps1 – поведением

SHELLS = [shell for shell in (shutil.which("pwsh"), shutil.which("powershell")) if shell]

HARNESS = r"""
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$global:calls = @(); $global:urls = @()
$global:BadPorts = __BAD__; $global:UpFails = __UPFAIL__; $global:DockerDown = __DOWN__
function docker {
    $line = ' ' + ($args -join ' ') + ' '
    $global:calls += ,('CALL' + $line + '|lan=' + $env:TRIAGE_LAN_ADDR)
    if ($args[0] -eq 'info') { $global:LASTEXITCODE = $(if ($global:DockerDown) { 1 } else { 0 }); return '27.0' }
    if ($args[0] -eq 'volume') { $global:LASTEXITCODE = 0; return }
    if ($args[0] -eq 'image') { $global:LASTEXITCODE = 0; return 'abc123' }
    if ($line -match ' config ') {
        $ports = @(@{ host_ip = '127.0.0.1'; published = '18765'; target = 8765 })
        if ($line -match 'docker-compose.lan.yml') {
            $ip = $(if ($global:BadPorts) { '0.0.0.0' } else { $env:TRIAGE_LAN_ADDR })
            $ports += @{ host_ip = $ip; published = '18765'; target = 8765 }
        }
        $global:LASTEXITCODE = 0
        return (@{ services = @{ triage = @{ ports = $ports; environment = @{ OLLAMA_URL = 'http://host.docker.internal:11434' };
            volumes = @(@{ target = '/repos'; source = '__REPOS__' }, @{ target = '/data'; source = '__DATA__' }) } } } |
            ConvertTo-Json -Depth 8)
    }
    if ($line -match ' run ') { $global:LASTEXITCODE = 0; return '{"state": "ok", "schema": 33, "expected": 33, "pending": []}' }
    if ($line -match ' up .* db ') { $global:LASTEXITCODE = 0; return }
    if ($line -match ' up ') { $global:LASTEXITCODE = $(if ($global:UpFails) { 1 } else { 0 }); return }
    $global:LASTEXITCODE = 0
}
function Invoke-WebRequest { param($Uri, [switch]$UseBasicParsing, $TimeoutSec, [switch]$NoProxy)
    $global:urls += ,("URL " + $Uri)
    $body = $(if ("$Uri" -like '*/api/ollama') { '{"url":"http://host.docker.internal:11434","version":"0.40","models":["m"],"error":"","default_model":"m","default_model_found":true}' } else { '{"status":"ok"}' })
    [pscustomobject]@{ StatusCode = 200; RawContentStream = [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($body)) }
}
function Get-NetIPAddress { param($IPAddress, $ErrorAction)
    if (-not "$IPAddress") { return @([pscustomobject]@{ IPAddress = '192.0.2.10' }, [pscustomobject]@{ IPAddress = 'fe80::1%5' }) }
    if ("$IPAddress" -eq '192.0.2.10') { return [pscustomobject]@{ IPAddress = $IPAddress } }
    throw 'no such address'
}
$env:TRIAGE_LAN_ADDR = '0.0.0.0'
& '__SCRIPT__' __ARGS__ *> '__OUT__'
'EXIT=' + $LASTEXITCODE
$global:calls
$global:urls
"""


def run_flow(shell: str, tmp_path: Path, args: str, env_text: str, *, bad: bool = False, up_fails: bool = False,
             docker_down: bool = False) -> dict:
    """start.ps1 целиком в отдельной папке приложения с подменами docker, Invoke-WebRequest и Get-NetIPAddress (функции
    важнее программ и командлетов): настоящий Docker, сеть и адаптеры не трогаются."""
    app = tmp_path / "app"
    (app / "repos").mkdir(parents=True)
    shutil.copy(ROOT / "start.ps1", app / "start.ps1")
    (app / ".env").write_text(env_text, encoding="utf-8")
    script = (HARNESS.replace("__BAD__", "$true" if bad else "$false")
              .replace("__UPFAIL__", "$true" if up_fails else "$false")
              .replace("__DOWN__", "$true" if docker_down else "$false")
              .replace("__REPOS__", str(app / "repos").replace("\\", "/"))
              .replace("__DATA__", str(app / "data").replace("\\", "/"))
              .replace("__SCRIPT__", str(app / "start.ps1")).replace("__ARGS__", args)
              .replace("__OUT__", str(app / "out.txt")))
    out = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                         capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    lines = out.stdout.splitlines()
    exit_line = next((ln for ln in lines if ln.startswith("EXIT=")), "EXIT=?")
    return {"exit": exit_line[5:], "calls": [ln for ln in lines if ln.startswith("CALL ")],
            "urls": [ln[4:] for ln in lines if ln.startswith("URL ")],
            "env": (app / ".env").read_text(encoding="utf-8"), "stderr": out.stderr,
            "out": (app / "out.txt").read_bytes().decode("utf-8-sig", errors="replace")
            if (app / "out.txt").exists() else ""}


ENV = "REPOS_ROOT={repos}\nTRIAGE_PORT=18765\n"


MIGRATE_HARNESS = {"state": "migrate", "schema": 33, "expected": 34, "pending": ["0002_a.sql"]}


@pytest.mark.skipif(not SHELLS, reason="нет PowerShell")
def test_empty_base_beside_sqlite_file_does_not_start_application(tmp_path: Path, monkeypatch):
    """Иначе приложение создало бы пустую схему, и перенос после этого отказал бы."""
    monkeypatch.setitem(globals(), "HARNESS", HARNESS.replace("""return '{"state": "ok", "schema": 33, "expected": 33, "pending": []}'""",
                                                              """return '{"state": "empty", "schema": null, "expected": 33, "pending": []}'"""))
    (tmp_path / "app" / "data").mkdir(parents=True)
    (tmp_path / "app" / "data" / "triage.db").write_bytes(b"x")
    out = run_flow(SHELLS[0], tmp_path, "-NoBrowser", env_text(tmp_path))
    assert out["exit"] != "0" and not any(" up " in c and " db " not in c for c in out["calls"]), out["calls"]


@pytest.mark.skipif(not SHELLS, reason="нет PowerShell")
@pytest.mark.parametrize("backup_ok", [False, True])
def test_schema_update_needs_flag_and_a_good_copy(tmp_path: Path, monkeypatch, backup_ok: bool):
    """Без -Migrate запуск останавливается; копия не удалась – схема не меняется, приложение не запускается; повтор после устранения сбоя идёт."""
    import json as json_module
    shell = SHELLS[0]
    for base in (tmp_path, tmp_path / "second"):
        folder = base / "app" / "scripts"
        folder.mkdir(parents=True)
        (folder / "backup-db.ps1").write_text(f"exit {0 if backup_ok else 1}\n", encoding="utf-8")
    harness_text = HARNESS
    state = json_module.dumps(MIGRATE_HARNESS).replace("\"", "`\"")
    monkeypatch.setitem(globals(), "HARNESS", harness_text.replace(
        """if ($line -match ' run ') { $global:LASTEXITCODE = 0; return '{"state": "ok", "schema": 33, "expected": 33, "pending": []}' }""",
        """if ($line -match 'tools migrate ') { $global:Migrated = $true; $global:LASTEXITCODE = 0; return '{"applied": ["0002_a.sql"]}' }
    if ($line -match ' run ') { $global:LASTEXITCODE = $(if ($global:Migrated) { 0 } else { 1 }); if ($global:Migrated) { return '{"state": "ok", "schema": 34, "expected": 34, "pending": []}' }; return '{"state": "migrate", "schema": 33, "expected": 34, "pending": ["0002_a.sql"]}' }"""))
    assert state
    without = run_flow(shell, tmp_path, "-NoBrowser", env_text(tmp_path))
    assert without["exit"] != "0" and not any("tools migrate " in c or (" up " in c and " db " not in c) for c in without["calls"])
    with_flag = run_flow(shell, tmp_path / "second", "-NoBrowser -Migrate", (env_text(tmp_path / "second")))
    calls = with_flag["calls"]
    if backup_ok:
        assert any("tools migrate " in c for c in calls), calls
    else:
        assert with_flag["exit"] != "0" and not any("tools migrate " in c or (" up " in c and " db " not in c) for c in calls), calls


def env_text(tmp_path: Path, extra: str = "") -> str:
    return ENV.format(repos=str(tmp_path / "app" / "repos").replace("\\", "/")) + extra


@pytest.mark.skipif(not SHELLS, reason="нет PowerShell")
@pytest.mark.parametrize("shell", SHELLS)
def test_flow_publishes_the_checked_address_and_stores_it_after_start(shell: str, tmp_path: Path):
    """-LanAddress: Compose получает проверенный адрес, а не унаследованный из окружения 0.0.0.0; адрес в .env – после
    запуска; адрес сети опрашивается."""
    got = run_flow(shell, tmp_path, "-LanAddress 192.0.2.10 -NoBrowser", env_text(tmp_path))
    assert got["exit"] == "0", got["out"] + got["stderr"]
    config = [c for c in got["calls"] if " config " in c]
    assert config and all("docker-compose.lan.yml" in c and c.endswith("|lan=192.0.2.10") for c in config)
    assert any(" up " in c for c in got["calls"])
    assert "TRIAGE_LAN_ADDR=192.0.2.10" in got["env"]
    assert "http://192.0.2.10:18765/healthz" in got["urls"]


@pytest.mark.skipif(not SHELLS, reason="нет PowerShell")
@pytest.mark.parametrize("shell", SHELLS)
def test_flow_refuses_wrong_publications_before_up(shell: str, tmp_path: Path):
    got = run_flow(shell, tmp_path, "-LanAddress 192.0.2.10 -NoBrowser", env_text(tmp_path), bad=True)
    assert got["exit"] == "1"
    assert not any(" up " in c for c in got["calls"]), "контейнер не пересоздаётся"
    assert "TRIAGE_LAN_ADDR" not in got["env"], "адрес не записан"


@pytest.mark.skipif(not SHELLS, reason="нет PowerShell")
@pytest.mark.parametrize("shell", SHELLS)
def test_flow_does_not_store_the_address_when_start_fails(shell: str, tmp_path: Path):
    got = run_flow(shell, tmp_path, "-LanAddress 192.0.2.10 -NoBrowser", env_text(tmp_path), up_fails=True)
    assert got["exit"] == "1" and "TRIAGE_LAN_ADDR" not in got["env"]


@pytest.mark.skipif(not SHELLS, reason="нет PowerShell")
@pytest.mark.parametrize("shell", SHELLS)
def test_flow_checks_conflicting_parameters_before_anything(shell: str, tmp_path: Path):
    before = env_text(tmp_path, "TRIAGE_LAN_ADDR=192.0.2.10\n")
    got = run_flow(shell, tmp_path, "-LanAddress 192.0.2.10 -LocalOnly -NoBrowser", before)
    assert got["exit"] == "1" and got["calls"] == [] and got["env"] == before


@pytest.mark.skipif(not SHELLS, reason="нет PowerShell")
@pytest.mark.parametrize("shell", SHELLS)
def test_flow_local_only_clears_the_address_even_without_docker(shell: str, tmp_path: Path):
    got = run_flow(shell, tmp_path, "-LocalOnly -NoBrowser", env_text(tmp_path, "TRIAGE_LAN_ADDR=192.0.2.10\n"),
                   docker_down=True)
    assert got["exit"] == "1"  # Docker не запущен
    assert "TRIAGE_LAN_ADDR=\n" in got["env"] or got["env"].rstrip().endswith("TRIAGE_LAN_ADDR=")


@pytest.mark.skipif(not SHELLS, reason="нет PowerShell")
@pytest.mark.parametrize("shell", SHELLS)
def test_flow_falls_back_to_loopback_when_the_address_is_gone(shell: str, tmp_path: Path):
    """Адрес из .env (с комментарием) больше не у этого компьютера: без файла сети, только 127.0.0.1, предупреждение –
    после запуска."""
    got = run_flow(shell, tmp_path, "-NoBrowser", env_text(tmp_path, "TRIAGE_LAN_ADDR=10.9.9.9 # old\n"))
    assert got["exit"] == "0", got["out"] + got["stderr"]
    config = [c for c in got["calls"] if " config " in c]
    assert config and not any("docker-compose.lan.yml" in c for c in config)
    assert any(" up " in c for c in got["calls"])
    out = got["out"]
    assert "TRIAGE_LAN_ADDR=10.9.9.9" in out and out.index("TRIAGE_LAN_ADDR=10.9.9.9") > out.index("http://127.0.0.1:18765")
    assert "TRIAGE_LAN_ADDR=10.9.9.9 # old" in got["env"], ".env не тронут"

"""Настоящая повторная запись снимка в Windows PowerShell и PowerShell 7."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import pytest


@pytest.mark.parametrize('shell', ['powershell', 'pwsh'])
def test_host_collector_can_replace_snapshot_twice_in_same_process(tmp_path, shell):
    executable=shutil.which(shell)
    if os.name!='nt' or not executable:
        pytest.skip('Проверка сборщика Windows, выбранная оболочка недоступна')
    script=Path(__file__).resolve().parents[1]/'scripts/host-metrics.ps1'
    quote=lambda p:"'"+str(p).replace("'","''")+"'"
    command=("$ErrorActionPreference='Stop'; "
             f"& {quote(script)} -Action Once -DataDir {quote(tmp_path)}; "
             f"$first=Get-Content -LiteralPath {quote(tmp_path/'telemetry/host.json')} -Raw | ConvertFrom-Json; "
             f"& {quote(script)} -Action Once -DataDir {quote(tmp_path)}; "
             f"$second=Get-Content -LiteralPath {quote(tmp_path/'telemetry/host.json')} -Raw | ConvertFrom-Json; "
             "if ($first.collector_id -eq $second.collector_id) {throw 'Snapshot was not replaced'}; "
             "$second | ConvertTo-Json -Depth 4 -Compress")
    result=subprocess.run([executable,'-NoProfile','-NonInteractive','-Command',command],capture_output=True,
                          timeout=30,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    assert result.returncode==0,result.stderr.decode('utf-8','replace')
    snapshot=json.loads(result.stdout.decode('utf-8-sig'))
    assert snapshot['schema']==1 and snapshot['memory']['total_bytes']>0
    assert snapshot['host_scope']=='ollama_host'

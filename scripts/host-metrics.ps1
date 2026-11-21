<#
.SYNOPSIS
Метрики физической памяти и CPU компьютера Ollama. Start запускает скрытый процесс; Stop завершает его через сигнал.
#>
[CmdletBinding()]
param(
    [ValidateSet('Start','Stop','Run','Once')][string]$Action='Once',
    [string]$DataDir=(Join-Path $PSScriptRoot '..\data'),
    [string]$Instance=''
)
$ErrorActionPreference='Stop'
$targetDir=[IO.Path]::GetFullPath($DataDir)
$folder=Join-Path $targetDir 'telemetry'
[IO.Directory]::CreateDirectory($folder) | Out-Null
$statePath=Join-Path $folder 'collector.json'
$stopPath=Join-Path $folder 'stop'
if ($Action -eq 'Stop') {
    if (Test-Path -LiteralPath $statePath) {
        $state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        [IO.File]::WriteAllText($stopPath,[string]$state.instance)
    }
    return
}
$hash=[Security.Cryptography.SHA256]::Create()
$key=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($targetDir.ToLowerInvariant())))).Replace('-','')
$hash.Dispose()
if ($Action -eq 'Start') {
    # Замена сборщика – под своим замком целиком: два одновременных запуска (два start.ps1) не мешают друг другу.
    $replace=New-Object Threading.Mutex($false,('Local\LocalTriageMetricsStart-'+$key))
    $held=$false
    try {
        try {$held=$replace.WaitOne(60000)} catch [Threading.AbandonedMutexException] {$held=$true}
        if (-not $held) {throw 'Другой запуск сборщика метрик не закончился за 60 с.'}
        # Прежний сборщик (в том числе прежней версии – без адресов компьютера) держит замок сбора: новый при нём
        # молча завершился бы. Поэтому – сигнал остановки прежнему и ожидание замка (цикл сборщика – 5 с). Чужие
        # процессы не завершаются никогда: не остановился сам – запуск отказывает с причиной.
        if (Test-Path -LiteralPath $statePath) {
            try {
                $old=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
                if ($old.instance) {[IO.File]::WriteAllText($stopPath,[string]$old.instance)}
            } catch {}
        }
        $probe=New-Object Threading.Mutex($false,('Local\LocalTriageMetrics-'+$key))
        try {
            $got=$false
            try {$got=$probe.WaitOne(20000)} catch [Threading.AbandonedMutexException] {$got=$true}
            if ($got) {$probe.ReleaseMutex()}
        } finally {$probe.Dispose()}
        if (-not $got) {throw 'Прежний сборщик метрик не остановился за 20 с: закройте его процесс (powershell host-metrics.ps1) или перезагрузите компьютер.'}
        $token=[Guid]::NewGuid().ToString('N')
        $arguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),'-Action','Run','-DataDir',('"'+$targetDir+'"'),'-Instance',$token)
        $child=Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -WindowStyle Hidden -PassThru
        # успех – свежий снимок нового сборщика (его collector_id) при живом процессе: только тогда в снимках есть
        # адреса компьютера (внешние провайдеры, ADR-0104)
        $hostPath=Join-Path $folder 'host.json'
        $noAddresses=$false
        $deadline=[DateTime]::UtcNow.AddSeconds(30)
        while ([DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 500
            if ($child.HasExited) {throw 'Сборщик метрик завершился сразу после запуска.'}
            try {
                $snap=Get-Content -LiteralPath $hostPath -Raw | ConvertFrom-Json
                $age=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0-[double]$snap.sampled_at
                if ($snap.collector_id -eq $token -and $age -ge -5 -and $age -le 30) {
                    # пригодность для приложения: без адресов компьютера внешние запросы не уйдут (app/telemetry.py)
                    if (@($snap.addresses).Count -gt 0) {return}
                    $noAddresses=$true
                }
            } catch {}
        }
        if ($noAddresses) {throw 'Сборщик метрик запущен, но адреса этого компьютера не прочитались (Get-NetIPAddress).'}
        throw 'Сборщик метрик не записал снимок за 30 с.'
    } finally {
        if ($held) {$replace.ReleaseMutex()}
        $replace.Dispose()
    }
}
$mutex=New-Object Threading.Mutex($false,('Local\LocalTriageMetrics-'+$key))
$owns=$false
try {
    try {$owns=$mutex.WaitOne(0)} catch [Threading.AbandonedMutexException] {$owns=$true}
    if (-not $owns) {return}
    if (-not $Instance) {$Instance=[Guid]::NewGuid().ToString('N')}
    if (-not ('TriageHostMetrics' -as [type])) { Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TriageHostMetrics {
  [StructLayout(LayoutKind.Sequential)] public struct Memory {
    public uint Length, Load;
    public ulong Total, Available, TotalPage, AvailablePage, TotalVirtual, AvailableVirtual, Extended;
  }
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GlobalMemoryStatusEx(ref Memory status);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetSystemTimes(out long idle, out long kernel, out long user);
  [DllImport("kernel32.dll")] public static extern uint GetActiveProcessorCount(ushort group);
}
'@
    }
    $utf8=New-Object Text.UTF8Encoding($false)
    $seq=0
    $previous=$null
    $addrStamp=$null
    $addrs=@()
    $state=@{instance=$Instance;pid=$PID;started_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()}
    if ($Action -eq 'Run') {[IO.File]::WriteAllText($statePath,($state|ConvertTo-Json -Compress),$utf8)}
    do {
        if ($Action -eq 'Run') {
            if ((Test-Path -LiteralPath $stopPath) -and [IO.File]::ReadAllText($stopPath) -eq $Instance) {break}
            $lease=Join-Path $folder 'lease'
            if ((Test-Path -LiteralPath $lease) -and (([DateTime]::UtcNow-(Get-Item -LiteralPath $lease).LastWriteTimeUtc).TotalMinutes -gt 10)) {break}
            if (-not (Test-Path -LiteralPath $lease) -and ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-$state.started_at -gt 600)) {break}
        }
        $memory=New-Object TriageHostMetrics+Memory
        $memory.Length=[Runtime.InteropServices.Marshal]::SizeOf($memory)
        $mem=$null
        if ([TriageHostMetrics]::GlobalMemoryStatusEx([ref]$memory)) {
            $mem=@{total_bytes=$memory.Total;available_bytes=$memory.Available;used_bytes=($memory.Total-$memory.Available)}
        }
        [long]$idle=0;[long]$kernel=0;[long]$user=0
        $cpu=$null
        # GetSystemTimes охватывает одну группу процессоров. Не выдаём её за весь многогрупповой хост.
        if ([TriageHostMetrics]::GetActiveProcessorCount(65535) -le 64 -and [TriageHostMetrics]::GetSystemTimes([ref]$idle,[ref]$kernel,[ref]$user)) {
            if ($previous) {
                $total=($kernel-$previous.kernel)+($user-$previous.user)
                if ($total -gt 0) {$cpu=[Math]::Round([Math]::Max(0,[Math]::Min(100,100*($total-($idle-$previous.idle))/$total)),1)}
            }
            $previous=@{idle=$idle;kernel=$kernel;user=$user}
        }
        # адреса этого компьютера раз в минуту: внешний профиль модели не должен вести на сам компьютер (ADR-0104)
        if (-not $addrStamp -or ([DateTime]::UtcNow-$addrStamp).TotalSeconds -ge 60) {
            $addrs=@(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { ($_.IPAddress -split '%')[0] } | Sort-Object -Unique | Select-Object -First 64)
            $addrStamp=[DateTime]::UtcNow
        }
        $seq++
        $snapshot=@{schema=1;collector_id=$Instance;sequence=$seq;sampled_at=([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0);host_scope='ollama_host';memory=$mem;cpu_pct=$cpu;addresses=@($addrs);error=$null}
        $temp=Join-Path $folder ('host-'+$Instance+'.tmp')
        $destination=Join-Path $folder 'host.json'
        [IO.File]::WriteAllText($temp,($snapshot|ConvertTo-Json -Depth 4 -Compress),$utf8)
        # Замена снимка: host.json в этот момент может читать приложение (общая папка контейнера) – тогда Windows
        # отказывает в замене. Несколько попыток; не вышло – снимок пропускается, а сборщик работает дальше: без него
        # внешние запросы встают на паузу. Разовый сбор (Once) сообщает об ошибке как раньше.
        $replaced=$false
        for ($attempt=1; -not $replaced; $attempt++) {
            try {
                if (Test-Path -LiteralPath $destination) {[IO.File]::Replace($temp,$destination,[NullString]::Value)} else {[IO.File]::Move($temp,$destination)}
                $replaced=$true
            } catch {
                if ($attempt -ge 5) {
                    $failure=$_
                    try {[IO.File]::Delete($temp)} catch {}
                    if ($Action -ne 'Run') {throw $failure}
                    break
                }
                Start-Sleep -Milliseconds 200
            }
        }
        if ($Action -eq 'Once') {break}
        Start-Sleep -Seconds 5
    } while ($true)
} finally {
    if ($owns) {$mutex.ReleaseMutex()}
    $mutex.Dispose()
}

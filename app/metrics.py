"""Метрики для страницы прогона: видеокарта (nvidia-smi) и модели, загруженные в Ollama (/api/ps).

gpu_stats() вызывает nvidia-smi не чаще раза в 2 с (ответ кэшируется), ждёт не дольше 3 с и возвращает None, если
nvidia-smi нет (нет видеокарты NVIDIA или контейнер запущен без неё). Вызов блокирующий: из асинхронного кода его
вызывают через пул потоков.
"""

from __future__ import annotations

import math
import os
import shutil
import subprocess
import threading
import time
from typing import Any

from app.llm import LlmError
from app.llm_ollama import OllamaClient

GPU_QUERY = "name,memory.used,memory.total,temperature.gpu,utilization.gpu,power.draw"
GPU_TIMEOUT_S = 3.0
GPU_CACHE_S = 2.0  # свежий ответ
GPU_FAIL_CACHE_S = 10.0  # после сбоя или таймаута – не дёргать nvidia-smi каждый раз
GPU_MISSING_CACHE_S = 60.0  # nvidia-smi нет – проверять редко
MIB = 1024 * 1024

_lock = threading.Lock()
_cache: dict[str, Any] = {"until": 0.0, "value": None}


def clear_cache() -> None:
    """Сбросить кэш gpu_stats (для тестов и после смены окружения)."""
    with _lock:
        _cache.update(until=0.0, value=None)


def _number(text: str) -> float | None:
    """Значение nvidia-smi без единиц; «[N/A]», «[Not Supported]», nan, inf и подобное – None."""
    try:
        value = float(text.strip())
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def _int(value: float | None) -> int | None:
    return None if value is None else int(round(value))


def parse_gpu_csv(text: str) -> dict[str, Any] | None:
    """Вывод nvidia-smi --query-gpu=GPU_QUERY --format=csv,noheader,nounits -> сводка по видеокартам.

    Одна видеокарта – её значения; несколько – память и мощность суммируются (если у какой-то карты значение
    неизвестно, сумма тоже неизвестна – None), температура и загрузка – наибольшие из известных; по каждой карте –
    в списке gpus. Значение вне разумных пределов (отрицательная память, загрузка больше 100 %, занято больше, чем
    есть) – неизвестно. Испорченная строка среди нормальных – карта с неизвестными значениями. Нет ни одной
    нормальной строки – None.
    """
    gpus, valid = [], 0
    for line in str(text or "").splitlines():
        if not line.strip():
            continue
        parts = [p.strip() for p in line.rsplit(",", 5)]
        if len(parts) != 6 or not parts[0]:
            gpus.append({"name": "", "memory_used_mb": None, "memory_total_mb": None, "temperature_c": None,
                         "utilization_pct": None, "power_w": None})
            continue
        valid += 1
        used, total, temp, util, power = (_number(p) for p in parts[1:])
        total = total if total is not None and total > 0 else None
        used = used if used is not None and used >= 0 and (total is None or used <= total) else None
        temp = temp if temp is not None and -40 <= temp <= 150 else None
        util = util if util is not None and 0 <= util <= 100 else None
        power = power if power is not None and power >= 0 else None
        gpus.append({
            "name": parts[0],
            "memory_used_mb": _int(used),
            "memory_total_mb": _int(total),
            "temperature_c": _int(temp),
            "utilization_pct": _int(util),
            "power_w": None if power is None else round(power, 1),
        })
    if not valid:
        return None

    def total_of(key: str) -> int | float | None:
        values = [g[key] for g in gpus]
        return None if any(v is None for v in values) else sum(values)

    def max_of(key: str) -> int | None:
        values = [g[key] for g in gpus if g[key] is not None]
        return max(values) if values else None

    names = [g["name"] or "неизвестная видеокарта" for g in gpus]
    if len(names) == 1:
        name = names[0]
    elif len(set(names)) == 1:
        name = f"{len(names)} × {names[0]}"
    else:
        name = " + ".join(names)
    used, total = total_of("memory_used_mb"), total_of("memory_total_mb")
    power = total_of("power_w")
    return {
        "name": name,
        "memory_used_mb": used,
        "memory_total_mb": total,
        "memory_pct": round(100.0 * used / total, 1) if used is not None and total else None,
        "temperature_c": max_of("temperature_c"),
        "utilization_pct": max_of("utilization_pct"),
        "power_w": None if power is None else round(power, 1),
        "count": len(gpus),
        "gpus": gpus,
    }


def _run_nvidia_smi(exe: str) -> str | None:
    """Вывод nvidia-smi или None (ошибка, таймаут, ненулевой код возврата)."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0  # без окна консоли в Windows
    try:
        done = subprocess.run([exe, f"--query-gpu={GPU_QUERY}", "--format=csv,noheader,nounits"],
                              capture_output=True, text=True, encoding="utf-8", errors="replace",
                              stdin=subprocess.DEVNULL, timeout=GPU_TIMEOUT_S, check=False, creationflags=flags)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def gpu_stats() -> dict[str, Any] | None:
    """Видеокарта сейчас: name, memory_used_mb, memory_total_mb, memory_pct, temperature_c, utilization_pct,
    power_w, count, gpus (по каждой карте). Нет nvidia-smi или он не ответил – None."""
    with _lock:  # один вызов nvidia-smi на всех: остальные ждут и берут его ответ
        now = time.monotonic()
        if now < _cache["until"]:
            return _cache["value"]
        exe = shutil.which("nvidia-smi")
        if exe is None:
            value, ttl = None, GPU_MISSING_CACHE_S
        else:
            value = parse_gpu_csv(_run_nvidia_smi(exe) or "")
            ttl = GPU_CACHE_S if value is not None else GPU_FAIL_CACHE_S
        _cache.update(until=time.monotonic() + ttl, value=value)
        return value


def snapshot(client: OllamaClient, host: bool = True) -> dict[str, Any]:
    """Метрики для страницы прогона. Не бросает исключений: если Ollama недоступна – ollama_ok=False.

    {"time": unix-время, "gpu": gpu_stats() или None,
     "models": [{"name", "size_mb", "vram_mb", "vram_share" (доля модели в видеопамяти, 0–1), "context"}],
     "vram_used_mb", "vram_total_mb", "vram_source": "nvidia-smi" | "ollama" | "",
     "ollama_ok": bool, "ollama_error": str}
    Без nvidia-smi занятая видеопамять – сумма size_vram загруженных моделей, всего памяти – неизвестно (None).
    host=False – сервер модели не на этом компьютере (профиль lan, ADR-0102): видеокарта этого компьютера (nvidia-smi)
    не показывается, видеопамять – по /api/ps сервера профиля.
    """
    try:
        gpu = gpu_stats() if host else None
    except Exception:  # метрики видеокарты не должны ронять страницу прогона
        gpu = None
    loaded: list[dict[str, Any]] = []
    error = ""
    try:
        loaded = client.ps()
    except LlmError as e:
        error = str(e)
    except Exception as e:  # метрики не должны ронять страницу прогона
        error = f"Не удалось получить загруженные модели: {type(e).__name__}."
    models = []
    for m in loaded:
        size, vram = m.get("size") or 0, m.get("size_vram") or 0
        models.append({
            "name": m.get("name") or "",
            "size_mb": round(size / MIB),
            "vram_mb": round(vram / MIB),
            "vram_share": round(min(1.0, vram / size), 3) if size else None,
            "context": m.get("context"),
        })
    if gpu is not None and gpu.get("memory_used_mb") is not None:
        used, total, source = gpu["memory_used_mb"], gpu.get("memory_total_mb"), "nvidia-smi"
    elif models:
        used, total, source = sum(m["vram_mb"] for m in models), None, "ollama"
    else:
        used, total, source = None, None, ""
    return {
        "time": round(time.time(), 3),
        "gpu": gpu,
        "models": models,
        "vram_used_mb": used,
        "vram_total_mb": total,
        "vram_source": source,
        "ollama_ok": not error,
        "ollama_error": error,
    }

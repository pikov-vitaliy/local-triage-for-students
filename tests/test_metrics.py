"""Метрики: разбор вывода nvidia-smi, кэш и таймаут, снимок для страницы прогона."""

from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import metrics  # noqa: E402
from app.llm import OllamaClient  # noqa: E402
from tests.fake_ollama import FakeOllama  # noqa: E402

ONE_GPU = "NVIDIA GeForce RTX 5080, 9123, 16303, 54, 97, 251.37\n"


class FakeRun:
    """Подмена subprocess.run: считает вызовы и отдаёт заданный вывод или исключение."""

    def __init__(self, stdout=ONE_GPU, returncode=0, error=None):
        self.stdout, self.returncode, self.error = stdout, returncode, error
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(args, self.returncode, stdout=self.stdout, stderr="")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def gpu(monkeypatch):
    """nvidia-smi «есть», вызов подменён, время управляемое; кэш чистый до и после теста."""
    metrics.clear_cache()
    run, clock = FakeRun(), Clock()
    monkeypatch.setattr(metrics.shutil, "which", lambda name: "/usr/bin/nvidia-smi")
    monkeypatch.setattr(metrics.subprocess, "run", run)
    monkeypatch.setattr(metrics.time, "monotonic", clock)
    yield run, clock
    metrics.clear_cache()


# ============================================================================ разбор вывода nvidia-smi

def test_parse_one_gpu():
    stats = metrics.parse_gpu_csv(ONE_GPU)
    assert stats == {
        "name": "NVIDIA GeForce RTX 5080", "memory_used_mb": 9123, "memory_total_mb": 16303, "memory_pct": 56.0,
        "temperature_c": 54, "utilization_pct": 97, "power_w": 251.4, "count": 1,
        "gpus": [{"name": "NVIDIA GeForce RTX 5080", "memory_used_mb": 9123, "memory_total_mb": 16303,
                  "temperature_c": 54, "utilization_pct": 97, "power_w": 251.4}],
    }


def test_parse_not_available_values():
    stats = metrics.parse_gpu_csv("NVIDIA T4, 512, 15360, [N/A], [Not Supported], [N/A]\n")
    assert stats["temperature_c"] is None
    assert stats["utilization_pct"] is None
    assert stats["power_w"] is None
    assert stats["memory_pct"] == 3.3


def test_parse_several_gpus():
    text = "NVIDIA A, 1000, 8000, 50, 10, 100.0\nNVIDIA A, 3000, 8000, 70, 90, [N/A]\n"
    stats = metrics.parse_gpu_csv(text)
    assert stats["name"] == "2 × NVIDIA A"
    assert stats["memory_used_mb"] == 4000 and stats["memory_total_mb"] == 16000
    assert stats["temperature_c"] == 70 and stats["utilization_pct"] == 90
    assert stats["power_w"] is None  # у второй карты мощность неизвестна – сумма тоже
    assert stats["count"] == 2
    mixed = metrics.parse_gpu_csv("NVIDIA A, 1, 2, 3, 4, 5\nNVIDIA B, 1, 2, 3, 4, 5\n")
    assert mixed["name"] == "NVIDIA A + NVIDIA B"


def test_parse_partial_memory_is_not_summed():
    stats = metrics.parse_gpu_csv("NVIDIA A, 1000, 8000, 50, 10, 1.0\nNVIDIA A, [N/A], 8000, 60, 20, 2.0\n")
    assert stats["memory_used_mb"] is None
    assert stats["memory_total_mb"] == 16000
    assert stats["memory_pct"] is None
    assert stats["power_w"] == 3.0


def test_parse_non_finite_values():
    stats = metrics.parse_gpu_csv("NVIDIA A, nan, 8000, inf, -inf, NaN\n")
    assert stats["memory_used_mb"] is None
    assert stats["temperature_c"] is None and stats["utilization_pct"] is None and stats["power_w"] is None
    assert stats["memory_total_mb"] == 8000


def test_parse_out_of_range_values():
    stats = metrics.parse_gpu_csv("NVIDIA A, -5, 8000, 300, 150, -1\n")
    assert stats["memory_used_mb"] is None
    assert stats["temperature_c"] is None and stats["utilization_pct"] is None and stats["power_w"] is None
    more_than_total = metrics.parse_gpu_csv("NVIDIA A, 9000, 8000, 50, 50, 10\n")
    assert more_than_total["memory_used_mb"] is None and more_than_total["memory_total_mb"] == 8000


def test_parse_broken_line_among_good_ones():
    stats = metrics.parse_gpu_csv("NVIDIA A, 1000, 8000, 50, 10, 1.0\nобрывок строки\n")
    assert stats["count"] == 2
    assert stats["memory_used_mb"] is None and stats["memory_total_mb"] is None and stats["power_w"] is None
    assert stats["temperature_c"] == 50
    assert stats["name"] == "NVIDIA A + неизвестная видеокарта"


def test_parse_garbage():
    assert metrics.parse_gpu_csv("") is None
    assert metrics.parse_gpu_csv("NVIDIA-SMI has failed because it couldn't communicate with the driver.") is None


# ============================================================================ gpu_stats: вызов, кэш, сбои

def test_gpu_stats_calls_nvidia_smi_with_timeout(gpu):
    run, _ = gpu
    stats = metrics.gpu_stats()
    assert stats["name"] == "NVIDIA GeForce RTX 5080"
    args, kwargs = run.calls[0]
    assert args == ["/usr/bin/nvidia-smi", f"--query-gpu={metrics.GPU_QUERY}", "--format=csv,noheader,nounits"]
    assert metrics.GPU_QUERY == "name,memory.used,memory.total,temperature.gpu,utilization.gpu,power.draw"
    assert kwargs["timeout"] == 3.0
    assert kwargs["check"] is False


def test_gpu_stats_is_cached_for_two_seconds(gpu):
    run, clock = gpu
    first = metrics.gpu_stats()
    clock.now += 1.9
    assert metrics.gpu_stats() is first
    assert len(run.calls) == 1
    clock.now += 0.2
    metrics.gpu_stats()
    assert len(run.calls) == 2


def test_gpu_stats_without_nvidia_smi(gpu, monkeypatch):
    run, clock = gpu
    monkeypatch.setattr(metrics.shutil, "which", lambda name: None)
    assert metrics.gpu_stats() is None
    clock.now += 30
    assert metrics.gpu_stats() is None
    assert run.calls == []


@pytest.mark.parametrize("fake_run", [
    FakeRun(error=subprocess.TimeoutExpired("nvidia-smi", 3.0)),
    FakeRun(error=FileNotFoundError("nvidia-smi")),
    FakeRun(returncode=9, stdout="NVIDIA-SMI has failed"),
])
def test_gpu_stats_failure_is_none_and_backs_off(gpu, monkeypatch, fake_run):
    _, clock = gpu
    monkeypatch.setattr(metrics.subprocess, "run", fake_run)
    assert metrics.gpu_stats() is None
    clock.now += 5
    assert metrics.gpu_stats() is None
    assert len(fake_run.calls) == 1
    clock.now += 6
    metrics.gpu_stats()
    assert len(fake_run.calls) == 2


# ============================================================================ snapshot

def test_snapshot_with_gpu(gpu):
    with FakeOllama(loaded=["qwen2.5-coder:14b"]) as fake:
        snap = metrics.snapshot(OllamaClient(fake.url))
    assert snap["ollama_ok"] is True and snap["ollama_error"] == ""
    assert snap["gpu"]["temperature_c"] == 54
    assert snap["vram_used_mb"] == 9123 and snap["vram_total_mb"] == 16303
    assert snap["vram_source"] == "nvidia-smi"
    assert snap["models"] == [{"name": "qwen2.5-coder:14b", "size_mb": 8572, "vram_mb": 8572, "vram_share": 1.0,
                               "context": 4096}]
    assert snap["time"] > 0


def test_snapshot_without_gpu_uses_ollama_vram(gpu, monkeypatch):
    monkeypatch.setattr(metrics.shutil, "which", lambda name: None)
    with FakeOllama(loaded=["gpt-oss:20b"], vram_share=0.75) as fake:
        snap = metrics.snapshot(OllamaClient(fake.url))
    assert snap["gpu"] is None
    assert snap["vram_source"] == "ollama"
    assert snap["vram_used_mb"] == round(13_793_441_244 * 0.75 / metrics.MIB)
    assert snap["vram_total_mb"] is None
    assert snap["models"][0]["vram_share"] == 0.75


def test_snapshot_nothing_loaded(gpu, monkeypatch):
    monkeypatch.setattr(metrics.shutil, "which", lambda name: None)
    with FakeOllama() as fake:
        snap = metrics.snapshot(OllamaClient(fake.url))
    assert snap["models"] == []
    assert snap["vram_used_mb"] is None and snap["vram_source"] == ""
    assert snap["ollama_ok"] is True


def test_snapshot_when_ollama_is_down(gpu):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    snap = metrics.snapshot(OllamaClient(f"http://127.0.0.1:{port}"))
    assert snap["ollama_ok"] is False
    assert "не отвечает" in snap["ollama_error"]
    assert snap["gpu"] is not None
    assert snap["vram_source"] == "nvidia-smi"


def test_snapshot_with_forbidden_url(gpu):
    snap = metrics.snapshot(OllamaClient("http://example.org:11434"))
    assert snap["ollama_ok"] is False
    assert "не входит в разрешённые" in snap["ollama_error"]


def test_snapshot_with_huge_sizes(gpu, monkeypatch):
    monkeypatch.setattr(metrics.shutil, "which", lambda name: None)
    with FakeOllama() as fake:
        fake.loaded = [{"name": "qwen2.5-coder:14b", "size": 10 ** 400, "size_vram": 10 ** 400,
                        "context_length": 4096}]
        snap = metrics.snapshot(OllamaClient(fake.url))
    assert snap["ollama_ok"] is True
    assert snap["models"][0]["size_mb"] == 0 and snap["models"][0]["vram_share"] is None


def test_snapshot_survives_gpu_failure(gpu, monkeypatch):
    def broken():
        raise ValueError("сбой разбора")

    monkeypatch.setattr(metrics, "gpu_stats", broken)
    with FakeOllama(loaded=["qwen2.5-coder:14b"]) as fake:
        snap = metrics.snapshot(OllamaClient(fake.url))
    assert snap["gpu"] is None
    assert snap["vram_source"] == "ollama"
    assert snap["ollama_ok"] is True


def test_snapshot_survives_unexpected_error(gpu):
    class Broken:
        def ps(self):
            raise RuntimeError("сбой")

    snap = metrics.snapshot(Broken())
    assert snap["ollama_ok"] is False
    assert "RuntimeError" in snap["ollama_error"]

"""Целевой lint ruff (ruff.toml; бэклог п. 24, аудит Kimi KIMI-10) прогоняется вместе с тестами: обязательный
набор правил для app, tests и scripts должен быть чистым. Без ruff в окружении тест падает, а не пропускается."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def test_targeted_lint_is_clean():
    assert importlib.util.find_spec("ruff") is not None, \
        "ruff не установлен – lint обязателен: .venv\\Scripts\\python -m pip install -r requirements-dev.txt"
    result = subprocess.run([sys.executable, "-m", "ruff", "check", "app", "tests", "scripts", "--no-cache",
                             "--output-format", "concise"], cwd=ROOT, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=300)
    assert result.returncode == 0, "ruff нашёл замечания по обязательному набору (ruff.toml):\n" + \
        (result.stdout or "") + (result.stderr or "")

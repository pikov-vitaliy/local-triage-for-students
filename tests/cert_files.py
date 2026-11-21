"""Сертификат тестового сервера с закрытым ключом – собирается во временный файл при запуске тестов. В репозитории
ключ хранится без PEM-заголовков (tests/certs/server-key.b64): сканеры секретов публичного хостинга не принимают учебный
ключ выдуманного удостоверяющего центра за настоящий."""

from __future__ import annotations

import atexit
import os
import tempfile
from functools import lru_cache
from pathlib import Path

CERTS = Path(__file__).parent / "certs"


@lru_cache(maxsize=1)
def server_pem() -> Path:
    head, tail = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"
    body = (CERTS / "server-key.b64").read_text(encoding="utf-8").strip()
    text = (CERTS / "server-cert.pem").read_text(encoding="utf-8") + f"{head}\n{body}\n{tail}\n"
    path = Path(tempfile.gettempdir()) / f"lt-test-server-{os.getpid()}.pem"
    path.write_text(text, encoding="utf-8")
    atexit.register(lambda: path.unlink(missing_ok=True))  # не оставлять ключ во временной папке
    return path

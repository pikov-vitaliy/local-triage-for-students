"""Замер страницы списка находок на большой синтетической выгрузке (хвост PERF-01: страница списка
должна быть быстрой при любом объёме – до 0,5 с на 10 000 находок).

Поднимает приложение из окружения разработки на временной папке данных с поддельным адресом Ollama (порт 9 –
соединений нет), загружает выгрузку Hub на N находок SAST (выдуманных, одной кодовой базы) и трижды запрашивает
страницы списка: первая, 25-я, сортировка по критичности, группы, страница проекта. Печатает время запросов и
частей (лёгкие поля всех строк, полные строки показанной страницы). Ничего не пишет в репозиторий и в рабочие данные.

Запуск из корня репозитория:
    .venv\\Scripts\\python -B scripts/bench/findings_list_bench.py [ПАПКА] [N]
По умолчанию – временная папка и N = 10 000. Ориентир 25.10.2026 (этот компьютер): список 0,26–0,28 с,
первый запрос после запуска – 2,4 с (прогрев шаблонов), загрузка выгрузки – 2,8 с. На 50 000 (PERF-03, 26.10):
загрузка 17,5 с, список 0,85–1,0 с (до правки 1,39–1,72 с – дескрипторы читались дважды), группы до 1,5 с."""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from hub_fixtures import INVOICE, MITRE, SAST_BASE, SQL_LINE, make_hub_xlsx  # noqa: E402
from test_web import BASE, create_project, upload, write_repos  # noqa: E402


def main() -> None:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp(prefix="lt-bench-"))
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 10_000
    root.mkdir(parents=True, exist_ok=True)
    write_repos(root / "repos")
    rows = [dict(SAST_BASE, **{"Issue id": str(600_000 + i), "Severity": ("High", "Medium", "Low")[i % 3],
                               "Category": "Внедрение SQL-кода", "File": INVOICE, "Line number": str(10 + i % 200),
                               "Source code": f"{SQL_LINE} : {10 + i % 200}", "CWE ID": "89",
                               "CWE link": MITRE.format(89)}) for i in range(n)]
    xlsx = make_hub_xlsx(root / "big.xlsx", sast=rows, sca=())
    settings = Settings(data_dir=root / "data", repos_root=root / "repos", ollama_url="http://127.0.0.1:9",
                        max_upload_mb=50, team_name="Тестовая команда")
    app = create_app(settings)
    with TestClient(app, base_url=BASE) as client:
        pid = create_project(client)
        started = time.perf_counter()
        response = upload(client, pid, xlsx)
        print(f"загрузка {n} находок: {response.status_code}, {time.perf_counter() - started:.2f} с")
        db = app.state.db
        for label, call in (("лёгкие поля всех строк", lambda: db.finding_descriptors(pid, {})),
                            ("полные строки страницы (200)", lambda: db.list_findings(pid, limit=200))):
            started = time.perf_counter()
            call()
            print(f"{label}: {time.perf_counter() - started:.3f} с")
        for path in (f"/projects/{pid}/findings", f"/projects/{pid}/findings?page=25",
                     f"/projects/{pid}/findings?sort=severity_desc", f"/projects/{pid}/findings?group_by=family",
                     f"/projects/{pid}"):
            times = []
            for _ in range(3):
                started = time.perf_counter()
                response = client.get(path)
                times.append(time.perf_counter() - started)
            print(f"GET {path}: {response.status_code}, " + ", ".join(f"{t:.3f}" for t in times) + " с")
    print(f"папка замера: {root}")


if __name__ == "__main__":
    main()

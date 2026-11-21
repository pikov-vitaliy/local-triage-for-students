# -*- coding: utf-8 -*-
"""Проверки данных приложения для образа ВМ на компьютере сборки (саму базу образа строит demo_db_build.py).

Запускает приложение из чистой копии (git archive) в этом же процессе, проходит те же шаги, что человек
в интерфейсе, и останавливает приложение штатно (база закрыта, прогон не на паузе):

  check    – готовая база образа (--data): приложение открывается, демо-проект с кодом из клонов и вердиктами
             (--expect-verdicts all) или без них (none – вердиктов при сборке не было, демо разбирается при показе),
             «Создать демо-проект» находит клоны (проверочный проект удаляется); модель не нужна;
  probe    – проба маленькой модели: отдельная папка данных, демо-проект, прогон выбранных находок (--ids)
             и один вопрос «Спросить модель»; печатает время и вердикты.

Готовой базы с вердиктами этот сценарий больше не готовит: вердикты демо создаются только прогоном модели во время
сборки базы образа (demo_db_build.py), а не переносятся из другой базы.

Корень папок с репозиториями (--root) должен содержать demo/examples/demo – копию examples/demo с клонами: так же
лежит демо в ВМ (/srv/repos/demo/examples/demo), и там его находит кнопка «Создать демо-проект» (она ищет
examples/demo не глубже двух уровней от корня).

База – в PostgreSQL (--conninfo, пароль – в переменной PGPASSWORD): для check – новая база, восстановленная из копии образа
(проверочный проект создаётся и удаляется в ней), для probe – пустая.

Запуск – Python из виртуального окружения приложения:
  python deploy/vm/prepare_demo_data.py probe --src <копия приложения> --conninfo <строка подключения> --data <пустая папка>
      --root <корень> --port 8771 --ollama http://127.0.0.1:11434 --model qwen2.5-coder:3b
Печатает итог в JSON последней строкой.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import uuid

import psycopg
from psycopg.conninfo import conninfo_to_dict


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=("probe", "check"))
    p.add_argument("--src", required=True, help="чистая копия приложения (git archive)")
    p.add_argument("--conninfo", required=True, help="строка подключения к базе; пароль – в PGPASSWORD")
    p.add_argument("--data", required=True, help="папка данных приложения (DATA_DIR): ключ маскирования или пустая")
    p.add_argument("--root", required=True, help="корень папок с репозиториями, внутри – demo/")
    p.add_argument("--port", type=int, default=8771)
    p.add_argument("--ollama", default="http://127.0.0.1:11434")
    p.add_argument("--model", required=True)
    p.add_argument("--ids", default="", help="probe: ID находок через запятую (пусто – первые три SAST)")
    p.add_argument("--question", default="Почему ты так решил? Покажи строку, на которую опираешься.")
    p.add_argument("--expect-verdicts", choices=("all", "none"), default="all",
                   help="check: вердикты у всех находок SAST (all) или вердиктов нет (none)")
    return p.parse_args()


class Client:
    """HTTP к приложению на 127.0.0.1: Origin для POST, без перехода по перенаправлениям."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.origin = f"http://127.0.0.1:{port}"

    def request(self, method: str, path: str, form: dict | list | None = None, files: dict | None = None,
                accept: str = "text/html", timeout: float = 1800) -> tuple[int, dict, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        headers = {"Host": f"127.0.0.1:{self.port}", "Accept": accept}
        body = None
        if method == "POST":
            headers["Origin"] = self.origin
            if files:
                boundary = uuid.uuid4().hex
                parts = []
                for k, v in (form or {}).items():
                    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
                for k, (name, data) in files.items():
                    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; filename="{name}"\r\n'
                                 f'Content-Type: application/octet-stream\r\n\r\n'.encode() + data + b"\r\n")
                parts.append(f"--{boundary}--\r\n".encode())
                body = b"".join(parts)
                headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            else:
                body = urllib.parse.urlencode(form or {}, doseq=True).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data

    def json(self, path: str) -> dict:
        status, _, data = self.request("GET", path, accept="application/json")
        if status != 200:
            raise SystemExit(f"GET {path}: {status} {data[:300]!r}")
        return json.loads(data)

    def post_redirect(self, path: str, form: dict | list | None = None, files: dict | None = None) -> str:
        status, headers, data = self.request("POST", path, form, files)
        if status not in (302, 303):
            raise SystemExit(f"POST {path}: {status} {data[:600].decode('utf-8', 'replace')}")
        return headers.get("location", "")


def libpq_env(conninfo: str) -> dict[str, str]:
    """Приложение берёт адрес базы из переменных libpq, как в контейнере."""
    names = {"host": "PGHOST", "port": "PGPORT", "dbname": "PGDATABASE", "user": "PGUSER", "password": "PGPASSWORD"}
    return {names[key]: str(value) for key, value in conninfo_to_dict(conninfo).items() if key in names}


def start_app(args: argparse.Namespace):
    os.environ.update({
        "DATA_DIR": args.data,
        "REPOS_ROOT": args.root,
        "OLLAMA_URL": args.ollama,
        "DEFAULT_MODEL": args.model,
        **libpq_env(args.conninfo),
    })
    sys.path.insert(0, args.src)
    os.chdir(args.src)
    import uvicorn  # noqa: E402

    config = uvicorn.Config("app.main:create_app", factory=True, host="127.0.0.1", port=args.port,
                            log_level="warning", access_log=False, timeout_graceful_shutdown=3)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(120):
        if server.started:
            return server, thread
        time.sleep(0.5)
    raise SystemExit("приложение не запустилось за 60 с")


def stop_app(server, thread) -> None:
    server.should_exit = True
    thread.join(timeout=60)
    if thread.is_alive():
        raise SystemExit("приложение не остановилось за 60 с")


def create_demo(c: Client) -> int:
    """«Создать демо-проект»: приложение само находит демо-клоны в <корень>/demo/examples/demo/repos."""
    loc = c.post_redirect("/projects/demo")
    if "ok=project_demo" not in loc or "nocode" in loc:
        raise SystemExit(f"демо-проект создан без клонов ({loc}): демо должно лежать в <корень>/demo/examples/demo")
    return int(loc.split("/projects/")[1].split("?")[0])


def run_and_wait(c: Client, pid: int, model: str, scope: str, ids: list[str]) -> dict:
    form = [("model", model), ("scope", scope)] + [("hub_id", i) for i in ids]
    loc = c.post_redirect(f"/projects/{pid}/runs", form)
    run_id = int(loc.rsplit("/", 1)[1])
    started = time.time()
    while True:
        st = c.json(f"/runs/{run_id}/status")
        run = st["run"]
        if run["state"] in ("done", "error", "stopped"):
            st["wall_s"] = round(time.time() - started, 1)
            return st
        print(f"  прогон {run_id}: {run['state']} {run['done']}/{run['total']}", flush=True)
        time.sleep(10)


def table_names(conninfo: str) -> list[str]:
    with psycopg.connect(conninfo) as con:
        return [r[0] for r in con.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1")]


def db_summary(conninfo: str) -> dict:
    tables = table_names(conninfo)
    out: dict = {"tables": tables}
    if "verdicts" in tables:
        with psycopg.connect(conninfo) as con:
            out["verdicts"] = {r[0]: r[1] for r in con.execute(
                "SELECT verdict, count(*) FROM verdicts GROUP BY verdict")}
    return out


def sast_rows(c: Client, pid: int) -> list[tuple[str, int]]:
    """(ID находки в Hub, номер карточки) для находок SAST – со страницы списка (база занята приложением)."""
    status, _, data = c.request("GET", f"/projects/{pid}/findings")
    html = data.decode("utf-8", "replace")
    rows = re.findall(r'name="hub_id" value="([^"]+)".*?href="/projects/%d/findings/(\d+)' % pid, html, re.S)
    return [(h, int(f)) for h, f in rows]


def ask(c: Client, pid: int, fid: int, model: str, question: str) -> dict:
    t = time.time()
    status, _, data = c.request("POST", f"/projects/{pid}/findings/{fid}/ask",
                                {"question": question, "model": model}, accept="application/json")
    took = round(time.time() - t, 1)
    try:
        payload = json.loads(data)
    except ValueError:
        payload = {"raw": data[:300].decode("utf-8", "replace")}
    return {"status": status, "seconds": took, "answered": payload.get("answered"),
            "answer": str((payload.get("question") or {}).get("answer") or payload.get("detail") or "")[:600]}


def check(args: argparse.Namespace) -> None:
    import subprocess

    checker = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_app.py")
    server, thread = start_app(args)
    try:
        out = subprocess.run([sys.executable, "-X", "utf8", checker, "127.0.0.1", "--port", str(args.port),
                              "--demo-button", "--expect-verdicts", args.expect_verdicts],
                             capture_output=True, text=True, encoding="utf-8", timeout=300)
    finally:
        stop_app(server, thread)
    print(out.stdout.strip() or out.stderr.strip())
    if out.returncode != 0:
        raise SystemExit(1)


def main() -> None:
    args = parse_args()
    if args.mode == "check":
        return check(args)
    if table_names(args.conninfo):
        raise SystemExit("база по --conninfo не пустая: для пробы нужна пустая")
    os.makedirs(args.data, exist_ok=True)
    if not os.path.isdir(os.path.join(args.root, "demo", "examples", "demo", "repos")):
        raise SystemExit(f"в {args.root} нет demo/examples/demo/repos")
    result: dict = {"mode": args.mode, "model": args.model}
    server, thread = start_app(args)
    c = Client(args.port)
    try:
        pid = create_demo(c)
        result["project_id"] = pid
        rows = sast_rows(c, pid)
        wanted = [i for i in args.ids.split(",") if i]
        rows = [r for r in rows if r[0] in wanted] if wanted else rows[:3]
        ids = [r[0] for r in rows]
        st = run_and_wait(c, pid, args.model, "selected", ids)
        result["run"] = st["run"]
        result["wall_s"] = st["wall_s"]
        result["feed"] = [{k: item.get(k) for k in ("hub_id", "state", "verdict", "seconds", "error")}
                          for item in st["feed"]]
        fid = rows[0][1]
        result["ask"] = ask(c, pid, fid, args.model, args.question)
        result["ask_warm"] = ask(c, pid, fid, args.model, "Как исправить это место? Коротко.")
    finally:
        stop_app(server, thread)
    result["db"] = db_summary(args.conninfo)
    result["leftovers"] = [n for n in ("telemetry/instance.lock",) if os.path.exists(os.path.join(args.data, n))
                           and os.path.getsize(os.path.join(args.data, n)) > 0]
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()

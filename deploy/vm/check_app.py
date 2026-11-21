# -*- coding: utf-8 -*-
"""Проверка приложения в ВМ с компьютера, как его откроет человек: через SSH-туннель (порт приложения в ВМ
опубликован только на 127.0.0.1; build.sh запускает проверку через ssh_tunnel.py).

  python check_app.py 127.0.0.1 --port <порт туннеля> [--ask] [--model <модель>]

Без --demo-button, --live и --ask проверка только читает: база ВМ не меняется.
Проверяет: главная страница открывается (имя хоста разрешено), есть демо-проект, у его находок SAST есть
готовые вердикты (--expect-verdicts all, по умолчанию) или вердиктов нет ни у одной (none: модель при сборке была
недоступна, демо разбирается при показе; --ask тогда не задаётся). С --ask задаёт вопрос «Спросить модель» по первой находке SAST и меряет время ответа.
Печатает JSON; код возврата 0 – всё прошло.
"""
from __future__ import annotations

import argparse
import http.client
import json
import re
import sys
import time
import urllib.parse

VERDICTS = ("true_positive", "false_positive", "uncertain")  # классы значка вердикта модели


def get(host: str, port: int, path: str, timeout: float = 30) -> tuple[int, str]:
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    c.request("GET", path, headers={"Host": f"{host}:{port}"})
    r = c.getresponse()
    body = r.read().decode("utf-8", "replace")
    c.close()
    return r.status, body


def post(host: str, port: int, path: str, form: dict, accept: str = "text/html", timeout: float = 60):
    body = urllib.parse.urlencode(form).encode()
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    c.request("POST", path, body=body, headers={
        "Host": f"{host}:{port}", "Origin": f"http://{host}:{port}", "Accept": accept,
        "Content-Type": "application/x-www-form-urlencoded"})
    r = c.getresponse()
    raw = r.read()
    location = r.getheader("location") or ""
    c.close()
    return r.status, location, raw


def live_run(host: str, port: int, pid: int, model: str, n: int, question: str) -> dict:
    """Прогон n находок SAST маленькой моделью и вопрос по первой из них – во временном проекте."""
    _, listing = get(host, port, f"/projects/{pid}/findings")
    rows = re.findall(r'name="hub_id" value="([^"]+)".*?href="/projects/%d/findings/(\d+)' % pid, listing, re.S)[:n]
    form = [("model", model), ("scope", "selected")] + [("hub_id", h) for h, _ in rows]
    body = urllib.parse.urlencode(form)
    c = http.client.HTTPConnection(host, port, timeout=60)
    c.request("POST", f"/projects/{pid}/runs", body=body, headers={
        "Host": f"{host}:{port}", "Origin": f"http://{host}:{port}", "Content-Type": "application/x-www-form-urlencoded"})
    r = c.getresponse(); r.read(); loc = r.getheader("location") or ""; c.close()
    m = re.search(r"/runs/(\d+)", loc)
    if not m:
        return {"error": f"прогон не запущен ({r.status} {loc})"}
    run_id, t = int(m.group(1)), time.time()
    while True:
        _, st = get(host, port, f"/runs/{run_id}/status")
        run = json.loads(st)["run"]
        if run["state"] in ("done", "error", "stopped"):
            break
        if time.time() - t > 1800:
            return {"error": "прогон не закончился за 30 минут"}
        time.sleep(5)
    res = {"run": {k: run[k] for k in ("state", "total", "done", "failed", "model_calls")},
           "run_seconds": round(time.time() - t, 1), "items": json.loads(st)["feed"]}
    res["items"] = [{k: i.get(k) for k in ("hub_id", "state", "verdict", "seconds", "error")} for i in res["items"]]
    asks = []
    for q in (question, "Как исправить это место? Коротко."):
        status, _, raw = post(host, port, f"/projects/{pid}/findings/{rows[0][1]}/ask", {"question": q, "model": model},
                              accept="application/json", timeout=1800)
        t2 = time.time()
        payload = json.loads(raw) if raw[:1] == b"{" else {}
        qq = payload.get("question") or {}
        asks.append({"answered": payload.get("answered"), "seconds": qq.get("seconds"), "tokens": qq.get("tokens"),
                     "error": str(qq.get("error") or payload.get("detail") or "")[:300],
                     "answer": str(qq.get("answer") or "")[:300]})
    res["asks"] = asks
    if run["failed"] or not any(a["answered"] for a in asks):
        res["error"] = "маленькая модель не разобрала находки или не ответила на вопрос"
    return res


def demo_button(host: str, port: int, live: int = 0, model: str = "", question: str = "") -> dict:
    """«Создать демо-проект»: клоны демо-репозиториев найдены (статус «найдена» у обеих кодовых баз), затем
    созданный проект удаляется."""
    status, location, _ = post(host, port, "/projects/demo", {})
    res: dict = {"status": status, "redirect": location}
    m = re.search(r"/projects/(\d+)\?ok=(\w+)", location)
    if not m:
        res["error"] = "демо-проект не создан"
        return res
    pid, ok = int(m.group(1)), m.group(2)
    res["ok"] = ok
    _, page = get(host, port, f"/projects/{pid}")
    states = {}
    for row in page.split("<tr")[1:]:
        for cb in ("billing-core", "catalog-api"):
            if cb in row and cb not in states:
                text = re.sub(r"<[^>]+>", " ", row)
                states[cb] = "не найдена" if "не найдена" in text else ("найдена" if "найдена" in text else "?")
    res["codebases"] = states
    if live and model:
        res["live"] = live_run(host, port, pid, model, live, question)
    status, location, _ = post(host, port, f"/projects/{pid}/delete", {"confirm": "yes"})
    res["deleted"] = status in (302, 303)
    if ok != "project_demo" or any(v != "найдена" for v in states.values()) or len(states) != 2:
        res["error"] = "клоны демо-репозиториев не найдены"
    elif "error" in res.get("live", {}):
        res["error"] = res["live"]["error"]
    return res


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--ask", action="store_true")
    p.add_argument("--demo-button", action="store_true",
                   help="нажать «Создать демо-проект», проверить, что клоны найдены, и удалить этот проект")
    p.add_argument("--live", type=int, default=0,
                   help="с --demo-button: в созданном проекте разобрать N находок моделью --model и задать вопрос "
                        "«Спросить модель» (время – в отчёте), затем удалить проект; демо-проект не меняется")
    p.add_argument("--model", default="")
    p.add_argument("--expect-verdicts", choices=("all", "none"), default="all",
                   help="all – вердикты у всех находок SAST; none – вердиктов в демо-проекте нет")
    p.add_argument("--question", default="Почему ты так решил? Ответь коротко и покажи строку кода, на которую опираешься.")
    a = p.parse_args()
    out: dict = {"url": f"http://{a.host}:{a.port}/"}
    status, page = get(a.host, a.port, "/")
    out["home_status"] = status
    if status != 200 or "Локальный триаж" not in page:
        out["error"] = "главная страница не открылась"
        print(json.dumps(out, ensure_ascii=False))
        return 1
    demo = re.search(r'href="/projects/(\d+)"[^>]*>\s*Демо:', page)
    if not demo:
        out["error"] = "на главной странице нет демо-проекта"
        print(json.dumps(out, ensure_ascii=False))
        return 1
    pid = int(demo.group(1))
    out["demo_project"] = pid
    status, listing = get(a.host, a.port, f"/projects/{pid}/findings")
    rows = re.findall(r'name="hub_id" value="([^"]+)".*?href="/projects/%d/findings/(\d+)' % pid, listing, re.S)
    out["sast"] = len(rows)
    out["verdict_labels"] = {v: len(re.findall(r'class="badge verdict verdict-%s"' % v, listing)) for v in VERDICTS}
    labelled = sum(out["verdict_labels"].values())
    out["expect_verdicts"] = a.expect_verdicts
    if not rows or (a.expect_verdicts == "all" and labelled < len(rows)):
        out["error"] = "у находок SAST нет готовых вердиктов"
        print(json.dumps(out, ensure_ascii=False))
        return 1
    if a.expect_verdicts == "none" and labelled:
        out["error"] = "в демо-проекте есть вердикты, хотя при сборке их не было"
        print(json.dumps(out, ensure_ascii=False))
        return 1
    if a.expect_verdicts == "none" and a.ask:
        out["error"] = "--ask без вердиктов не задаётся"
        print(json.dumps(out, ensure_ascii=False))
        return 1
    hub_id, fid = rows[0]
    status, card = get(a.host, a.port, f"/projects/{pid}/findings/{fid}")
    out["card"] = {"hub_id": hub_id, "status": status,
                   "code_from_clone": "код из клона" in card,
                   "verdict": next((v for v in VERDICTS if 'verdict-hero-%s"' % v in card), None)}
    if a.demo_button:
        out["demo_button"] = demo_button(a.host, a.port, a.live, a.model, a.question)
        if "error" in out["demo_button"]:
            out["error"] = out["demo_button"]["error"]
            print(json.dumps(out, ensure_ascii=False))
            return 1
    if a.ask:
        body = urllib.parse.urlencode({"question": a.question, "model": a.model}).encode()
        c = http.client.HTTPConnection(a.host, a.port, timeout=1800)
        t = time.time()
        c.request("POST", f"/projects/{pid}/findings/{fid}/ask", body=body, headers={
            "Host": f"{a.host}:{a.port}", "Origin": f"http://{a.host}:{a.port}", "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"})
        r = c.getresponse()
        raw = r.read()
        took = round(time.time() - t, 1)
        c.close()
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {"detail": raw[:300].decode("utf-8", "replace")}
        q = payload.get("question") or {}
        out["ask"] = {"status": r.status, "seconds": took, "answered": payload.get("answered"),
                      "model": q.get("model"), "answer": str(q.get("answer") or payload.get("detail") or "")[:500],
                      "error": str(q.get("error") or "")[:500], "model_seconds": q.get("seconds"),
                      "tokens": q.get("tokens"), "tps": q.get("tps")}
        if not payload.get("answered"):
            out["error"] = "модель не ответила на вопрос"
            print(json.dumps(out, ensure_ascii=False))
            return 1
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

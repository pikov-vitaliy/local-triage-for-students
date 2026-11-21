# -*- coding: utf-8 -*-
"""База приложения для образа ВМ строится заново – только из демо-данных examples/demo и ответов модели,
полученных во время этой сборки.

Ни одна готовая база (своя папка данных, база прошлого прогона, база другой сборки) не читается: в ней могут
оказаться рабочие проекты, вопросы к модели, решения и комментарии людей, ответы агентов по чужим библиотекам,
настройки команды – и свободный текст вердиктов. Отпечаток случая (case_hash) описывает входные данные модели,
а не её ответ, поэтому подмену текста вердикта при том же отпечатке по базе не распознать. Новая база собирается
так же, как её собрало бы приложение:

* проект «Демо: …» – из демо-выгрузки examples/demo/demo-hub-report.xlsx (тем же кодом, что кнопка «Создать
  демо-проект»), папка проекта – demo/examples/demo/repos, как в ВМ;
* ответы агента по SCA – из examples/demo/sca-answers.json (тем же разбором, что загрузка ответа);
* настройки – значения по умолчанию, адрес Ollama и модель – для ВМ; ключ маскирования – новый;
* вердикты демо-находок SAST – только из прогона модели во время сборки (--triage-model на сервере Ollama
  --triage-url, очередь приложения TriageRunner, как кнопка «Разобрать»). Модель недоступна или занята чужими
  моделями – при --triage-mode auto вердиктов в базе нет (демо разбирается при показе), причина – в составе;
  при --triage-mode require – отказ. Если прогон был, вердикты должны быть у всех находок SAST, иначе отказ.
  Исходный ответ модели (raw) в базе не хранится.

Затем база проверяется целиком (demo_db_check.composition_problems). Копию для образа снимает build.sh (pg_dump -Fc): мёртвые
строки в неё не попадают.

  python demo_db_build.py <src приложения> <корень папок с репозиториями> --conninfo <строка подключения> --out <папка>
      --ollama-url http://ollama:11434 --model qwen2.5-coder:3b
      [--triage-url http://127.0.0.1:11434 --triage-model gpt-oss:20b --triage-mode auto|require]
      [--summary <файл JSON>]

Корень папок с репозиториями должен содержать demo/examples/demo/repos (как /srv/repos в ВМ). База по --conninfo должна быть
пустой (пароль – в переменной PGPASSWORD), папка --out – пустой или не существовать: в неё пишется ключ маскирования.
Код возврата 0 – база собрана; печатает состав в JSON (поле verdicts: source «модель при сборке» или «нет», модель,
число вердиктов, причина).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

DEMO_DIR = ("examples", "demo")
DEMO_REPORT = "demo-hub-report.xlsx"
DEMO_ANSWERS = "sca-answers.json"
VM_REPOS_DIR = "demo/examples/demo/repos"
_MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}")
TRIAGE_MODES = ("auto", "require")


class BuildError(ValueError):
    """База для образа не собрана: problems – причины по-русски."""

    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def model_unavailable(client, model: str, wait_s: float = 0, pause_s: float = 30) -> str:
    """Почему модель нельзя взять для прогона при сборке; пустая строка – можно. Модель должна быть на сервере,
    а в памяти Ollama – не быть чужих моделей (чужие не выгружаются: ждём до wait_s секунд)."""
    from app.llm import LlmError, norm_model_name

    wanted = norm_model_name(model)
    try:
        names = {norm_model_name(m.get("name")) for m in client.list_models()}
    except LlmError as e:
        return f"сервер Ollama не отвечает ({e})"
    if wanted not in names:
        return f"на сервере Ollama нет модели {model}"
    deadline = time.monotonic() + wait_s
    while True:
        try:
            other = sorted(n for n in (norm_model_name(m.get("name")) for m in client.ps()) if n and n != wanted)
        except LlmError as e:
            return f"сервер Ollama не отвечает ({e})"
        if not other:
            return ""
        if time.monotonic() >= deadline:
            return f"Ollama занята моделями {', '.join(other)}"
        time.sleep(pause_s)


BUILD_PROFILE = "Сервер сборки образа"
BUILD_NOTE = "адрес сборки не сохраняется"


def _unload(client, model: str) -> None:
    """Своя модель после прогона выгружается клиентом приложения (проверки адреса те же, что у разбора; сборочный
    профиль – local, выгрузка разрешена), чтобы не мешать другим задачам на видеокарте; сбой сборку не отменяет."""
    try:
        client.unload_model(model)
    except Exception:  # noqa: BLE001
        pass


def _triage(db, settings, pid: int, model: str, mask_key: bytes, wait_s: float, client_factory) -> dict:
    """Прогон всех находок SAST демо-проекта моделью model очередью приложения. Возвращает итог прогона."""
    from app.triage import TriageRunner

    runner = TriageRunner(db, settings, client_factory=client_factory, mask_key=mask_key)
    runner.start()
    try:
        run_id = runner.enqueue(pid, model, "all", fresh=True)
        deadline = time.monotonic() + wait_s
        while True:
            run = db.get_run(run_id) or {}
            if run.get("state") in ("done", "error", "stopped"):
                break
            if time.monotonic() > deadline:
                runner.stop(run_id)
                raise BuildError([f"прогон модели {model} не закончился за {wait_s:.0f} с"])
            time.sleep(0.2)
    finally:
        if not runner.shutdown(timeout=120):
            raise BuildError(["очередь разбора не остановилась"])
    errors = sorted({str(i.get("error") or "")[:200] for i in db.recent_items(run_id) if i.get("error")})
    return {"id": run_id, "state": run.get("state"), "last_error": str(run.get("last_error") or "")[:300],
            "errors": errors[:5]}


def build(src: Path, repos_root: Path, out_dir: Path, *, conninfo: str, ollama_url: str, model: str, triage_url: str = "",
          triage_model: str = "", triage_mode: str = "auto", wait_s: float = 6 * 3600, gpu_wait_s: float = 900,
          client_factory=None) -> dict:
    """Собирает базу по conninfo заново из демо-данных src и, если задана triage_model,
    прогона этой модели во время сборки (см. описание модуля). Возвращает состав базы и сведения о вердиктах.
    BuildError – не собрано."""
    from app.config import Settings
    from app.db import Database
    from app.hub_import import parse_workbook
    from app.llm import OllamaClient
    from app.routes.projects import store_import
    from app.sca import parse_answers

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from demo_db_check import composition_problems, connect, summary, table_names  # noqa: E402

    src, repos_root, out_dir = Path(src), Path(repos_root), Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        raise BuildError([f"папка {out_dir} не пустая"])
    con = connect(conninfo, read_only=True)
    try:
        if table_names(con):
            raise BuildError(["база для образа не пустая: готовая база не принимается"])
    finally:
        con.close()
    if not _MODEL_NAME.fullmatch(model):
        raise BuildError(["имя модели для ВМ не похоже на имя модели Ollama"])
    if triage_model and not _MODEL_NAME.fullmatch(triage_model):
        raise BuildError(["имя модели для прогона при сборке не похоже на имя модели Ollama"])
    if triage_mode not in TRIAGE_MODES:
        raise BuildError([f"--triage-mode: {' или '.join(TRIAGE_MODES)}"])
    demo = Path(src, *DEMO_DIR)
    if not (repos_root / VM_REPOS_DIR).is_dir():
        raise BuildError([f"в {repos_root} нет {VM_REPOS_DIR}"])
    out_dir.mkdir(parents=True, exist_ok=True)
    factory = client_factory or OllamaClient

    verdicts: dict = {"source": "нет", "model": "", "count": 0, "reason": "прогон при сборке не задан"}
    if triage_model:
        reason = model_unavailable(factory(triage_url), triage_model, gpu_wait_s) if triage_url else \
            "не задан адрес Ollama для прогона"
        if reason and triage_mode == "require":
            raise BuildError([f"модель для вердиктов демо недоступна: {reason}"])
        verdicts = {"source": "нет", "model": triage_model, "count": 0,
                    "reason": reason or ""}

    settings = Settings(data_dir=out_dir, repos_root=repos_root, ollama_url=ollama_url, default_model=model)
    db = Database(conninfo)
    try:
        key = db.mask_key()  # ключ в базе и в её копии (ADR-0133)
        db.seed_settings(settings.editable())
        db.ensure_default_profile(ollama_url, model)  # профиль 1 – Ollama ВМ (local); сборочный адрес его не трогает
        result = parse_workbook(demo / DEMO_REPORT, settings.max_upload_bytes)
        application = str(result.summary.get("application") or "").strip() or "Demo Library"
        pid = db.create_project(f"Демо: {application}"[:200])
        db.set_repos_dir(pid, VM_REPOS_DIR)
        store_import(settings, db, pid, DEMO_REPORT, result)
        report = parse_answers((demo / DEMO_ANSWERS).read_text(encoding="utf-8"), db.sca_components(pid), "")
        if report.answers:
            db.save_sca_answers(pid, report.source, report.answers)
        sast = {str(row.get("hub_id") or "") for row in db.findings_data(pid, kinds=("SAST",))}
        if triage_model and not verdicts["reason"]:
            # прогон – на сервере сборочного компьютера отдельным профилем проекта (раздел 0.3 плана 0.9.12):
            # профиль 1 и настройки остаются у Ollama ВМ; после прогона сборочный профиль выключается, а его адрес
            # стирается и из профиля, и из снимков исполнителя – в образ адрес сборочного компьютера не попадает
            build_profile = db.create_provider({
                "name": BUILD_PROFILE, "kind": "ollama", "base_url": triage_url, "trust": "local", "enabled": 1,
                "default_model": triage_model,
                "capabilities_json": json.dumps({"supports_ps": True, "allows_unload": True})})
            bid = int(build_profile["id"])
            db.update_project(pid, provider_id=bid)
            try:
                verdicts["run"] = _triage(db, settings, pid, triage_model, key, wait_s, factory)
            finally:
                _unload(factory(triage_url), triage_model)
                db.update_project(pid, provider_id=None)
                db.update_provider(bid, {"base_url": "", "enabled": 0})
                with db._tx() as c:
                    c.execute("UPDATE llm_executions SET base_url = '', note = ? WHERE provider_id = ?",
                              (BUILD_NOTE, bid))
            verdicts["source"] = "модель при сборке"
        with db._tx() as c:
            c.execute("UPDATE verdicts SET raw_json = '{}'")  # исходный ответ модели в образ не идёт
    finally:
        db.close()

    con = connect(conninfo, read_only=True)
    try:
        with_verdict = con.execute(
            "SELECT COUNT(*) FROM cases c JOIN findings f ON f.project_id = c.project_id AND f.hub_id = c.hub_id"
            " WHERE f.kind = 'SAST' AND c.verdict_id IS NOT NULL").fetchone()[0]
        expected = {f.hub_id for f in parse_workbook(demo / DEMO_REPORT).findings}
        problems = composition_problems(con, expected, {DEMO_REPORT})
        info = summary(con)
    finally:
        con.close()
    verdicts["count"] = int(with_verdict)
    if verdicts["source"] == "нет" and info["counts"]["verdicts"]:
        problems.append("в базе есть вердикты, хотя прогона при сборке не было")
    if verdicts["source"] != "нет" and with_verdict != len(sast):
        run = verdicts.get("run") or {}
        problems.append(f"прогон модели {triage_model} при сборке дал вердикты {with_verdict} из {len(sast)} находок"
                        f" SAST (состояние {run.get('state')}; {'; '.join(run.get('errors') or []) or 'без ошибок'})")
    leftovers = sorted(p.name for p in out_dir.iterdir())
    if problems or leftovers:
        raise BuildError(problems or [f"в папке {out_dir} лишние файлы: {leftovers}"])
    return {**info, "verdicts": verdicts, "sast": len(sast), "mask_key": "новый"}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("src", help="чистая копия приложения (git archive)")
    p.add_argument("repos_root", help="корень папок с репозиториями, внутри – demo/examples/demo/repos")
    p.add_argument("--conninfo", required=True, help="строка подключения к пустой базе; пароль – в PGPASSWORD")
    p.add_argument("--out", required=True, help="пустая папка для ключа маскирования")
    p.add_argument("--ollama-url", default="http://ollama:11434", help="адрес Ollama в ВМ")
    p.add_argument("--model", required=True, help="модель по умолчанию в ВМ")
    p.add_argument("--triage-url", default="", help="Ollama сборочного компьютера для вердиктов демо")
    p.add_argument("--triage-model", default="", help="модель для вердиктов демо; пусто – без вердиктов")
    p.add_argument("--triage-mode", choices=TRIAGE_MODES, default="auto",
                   help="auto – модель недоступна: без вердиктов; require – модель недоступна: отказ")
    p.add_argument("--wait-s", type=float, default=6 * 3600, help="предел времени прогона, секунды")
    p.add_argument("--gpu-wait-s", type=float, default=900, help="сколько ждать, пока Ollama выгрузит чужие модели")
    p.add_argument("--summary", default="", help="файл для состава базы (JSON)")
    a = p.parse_args()
    sys.path.insert(0, a.src)
    try:
        result = build(Path(a.src), Path(a.repos_root), Path(a.out), conninfo=a.conninfo, ollama_url=a.ollama_url, model=a.model,
                       triage_url=a.triage_url, triage_model=a.triage_model, triage_mode=a.triage_mode,
                       wait_s=a.wait_s, gpu_wait_s=a.gpu_wait_s)
    except BuildError as e:
        print(json.dumps({"error": "база для образа не собрана", "problems": e.problems}, ensure_ascii=False))
        return 1
    text = json.dumps(result, ensure_ascii=False)
    if a.summary:
        Path(a.summary).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

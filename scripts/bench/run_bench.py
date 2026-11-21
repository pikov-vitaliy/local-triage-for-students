"""Стенд замера моделей «Локального триажа»: эталонный набор (results/bench/cases.json, его собирает
build_cases.py) через конвейер приложения. Описание, метрики и ограничения – docs/model-benchmark.md.

Каждый случай проходит тот же путь, что находка SAST в приложении (app/triage.py, TriageRunner._process_item):
  * срез кода – app.context.build_context с ключом маскирования. Ключ – стенда (results/bench/mask.key), а не
    ключ приложения из его data/: промпты одинаковы для всех моделей и не зависят от рабочей базы;
  * промпт текущей версии – app.prompts.build_sast_messages, затем второй проход маскирования
    TriageRunner._masked; промпт, который не помещается в окно контекста, сокращается так же, как в прогоне;
  * параметры генерации – triage.model_options (окно контекста – MODEL_NUM_CTX приложения, 16384; предел ответа
    num_predict – 3072, не больше четверти окна); --num-ctx и --num-predict их заменяют;
  * режим рассуждений: без --think – как в приложении (gpt-oss – low, остальным моделям think не передаётся, и
    рассуждающие модели думают по своему умолчанию). Клиент приложения передаёт think только моделям gpt-oss,
    поэтому --think стенд подставляет сам: обёртка над OllamaClient._chat заменяет поле think в теле запроса
    к /api/chat для любой модели (low, medium, high, xhigh – строкой; true, false – логическим значением).
    Приложение не меняется. Обёртка же запоминает done_reason, объём рассуждения и ответа каждой попытки;
  * вызов – app.llm_ollama.OllamaClient.chat_json с полями, типами и проверкой ответа из app.prompts; разбор –
    app.prompts.parse_verdict.
Модули приложения импортируются из его папки (по умолчанию – этот репозиторий) только на чтение. В папке
приложения стенд пишет только в results/ (она в .gitignore); в папке с кодом OWASP Benchmark ничего не пишется,
байт-код тоже.

Видеокарта общая. Перед каждым вызовом модели проверяется /api/ps. Если загружена другая модель – или та же, но
с другим окном контекста (вызов с окном приложения заставил бы Ollama её перезагрузить), – стенд ждёт, пока она
выгрузится сама (не дольше --wait-max секунд, по умолчанию 10 минут), и отмечает ожидание в записи случая. Чужие
модели стенд не выгружает и не перезагружает никогда. Если дождаться не удалось, прогон останавливается (код 3);
продолжить можно той же командой. После каждого вызова записывается, какая часть своей модели в видеопамяти
(size_vram / size из /api/ps) и не появилась ли рядом чужая. Если ту же модель в это же время вызывает другой
процесс, /api/ps этого не показывает – время ответов тогда завышено.

Результаты: журнал <out>.jsonl – запись на каждый случай сразу после ответа (с fsync); повторный запуск той же
командой продолжает прерванный прогон. Итог с метриками – <out>.json: в нём digest модели (/api/tags), режим
think (запрошенный и отправленный), num_predict, доля оборванных ответов, версия приложения. По умолчанию out –
results/bench/runs/<модель>__think-<режим>__np<num_predict>.json: в имени файла «:» и «/» заменены на «_»,
режим – low, medium, high, xhigh, true, false или none (think не передавался: модель рассуждает по умолчанию).
Сводная таблица всех итогов – summary.py.

Запуск из корня репозитория (ключи -I и -B обязательны):
    .venv\\Scripts\\python -I -B scripts/bench/run_bench.py --model gpt-oss:20b
    ... run_bench.py --model gpt-oss:20b --think medium
    ... run_bench.py --model qwen3.5:9b-q4_K_M --think false
    ... run_bench.py --model deepseek-r1:14b --think true --num-predict 8192
    ... run_bench.py --model qwen2.5-coder:14b --limit 20
    ... run_bench.py --model gpt-oss:20b --ids BenchmarkTest00001,100101 --out results/bench/probe/x.json
    ... run_bench.py --model gpt-oss:20b --dry-run [--show 100109]   (срезы и промпты без вызова модели)

Адрес Ollama по умолчанию – переменная окружения OLLAMA_URL (как у приложения), без неё – http://127.0.0.1:11434.

Коды выхода: 0 – готово; 1 – неверный запуск; 2 – журнал собран с другим промптом или параметрами (--restart
начинает заново, прежний журнал переименовывается); 3 – чужая модель не выгрузилась за --wait-max; 4 – с ключом
--require-loaded модель не загружена; 5 – Ollama не отвечает; 130 – прервано (Ctrl+C).
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True  # модули приложения – только на чтение: без __pycache__ в его папке

import argparse  # noqa: E402
import contextlib  # noqa: E402
import datetime as dt  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import statistics  # noqa: E402
import time  # noqa: E402
from collections import Counter, defaultdict  # noqa: E402
from pathlib import Path  # noqa: E402
from types import SimpleNamespace  # noqa: E402
from typing import Any  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
DEFAULT_APP = REPO
BENCH_DIR = REPO / "results" / "bench"
DEFAULT_CASES = BENCH_DIR / "cases.json"
RESULTS_DIR = BENCH_DIR / "runs"
MASK_KEY_PATH = BENCH_DIR / "mask.key"  # ключ маскирования стенда: одинаковые промпты для всех моделей
DEFAULT_URL = (os.environ.get("OLLAMA_URL") or "").strip().rstrip("/") or "http://127.0.0.1:11434"
THINK_LEVELS = ("low", "medium", "high")  # что принимает от стенда клиент приложения (gpt-oss)
THINK_CHOICES = ("low", "medium", "high", "xhigh", "true", "false")  # --think: уходит в Ollama для любой модели
UNSET = object()  # --think не задан: поле think в запросе – как у приложения
WAIT_MAX_S = 600.0
WAIT_POLL_S = 5.0
RAW_HEAD = 1500  # сколько знаков неразобранного ответа модели хранить в журнале
RESULT_FORMAT = 2
APP_MODULES = ("config.py", "context.py", "llm.py", "masking.py", "models.py", "prompts.py", "triage.py")
# клиент модели вынесен из llm.py в 0.9.12: в отпечатке приложения – если файлы есть (у прежних версий их нет)
APP_MODULES_SINCE_0912 = ("llm_net.py", "llm_ollama.py")
VERDICTS = ("true_positive", "false_positive", "uncertain")
SHORT = {"true_positive": "TP", "false_positive": "FP", "uncertain": "неясно"}
# Начало текста LlmError из app.llm.chat_json, когда модель ответила, но ответ не принят
FORMAT_ERRORS = {"Модель дважды ответила не по формату": "format", "Ответ модели оборван": "truncated"}
CORRECT_RULE = ("Верный ответ – вердикт совпал с ожидаемым или входит в also_ok случая (для BenchmarkTest00051, "
                "BenchmarkTest00052 и 100102 допускается uncertain). Это правило одно для точности, "
                "чувствительности и специфичности. Случай без разобранного ответа (ответ не по формату, оборван, "
                "сбой сервера, нет кода) считается неверным.")
OWASP_ORDER = ("sqli", "cmdi", "pathtraver", "xss", "ldapi", "xpathi", "trustbound", "weakrand")


class Stop(Exception):
    """Прогон не начат или остановлен. code – код выхода, текст – по-русски."""

    def __init__(self, code: int, text: str) -> None:
        super().__init__(text)
        self.code = code


# ============================================================================ мелочи

def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def safe_name(text: str) -> str:
    """Имя модели -> часть имени файла: «:» и «/» на NTFS недопустимы (gpt-oss:20b -> gpt-oss_20b)."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(text).strip()).strip("._") or "model"


def num(value: float | None, digits: int = 1) -> str:
    return "–" if value is None else f"{value:.{digits}f}".replace(".", ",")


def pct(value: float | None) -> str:
    return "–" if value is None else f"{value * 100:.1f}".replace(".", ",") + " %"


def duration(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds} с"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} мин {sec} с"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} ч {minutes} мин"


def rate(part: int, whole: int) -> float | None:
    return round(part / whole, 4) if whole else None


def mean(values: list) -> float | None:
    values = [v for v in values if isinstance(v, (int, float))]
    return round(statistics.fmean(values), 3) if values else None


def median(values: list) -> float | None:
    values = [v for v in values if isinstance(v, (int, float))]
    return round(statistics.median(values), 3) if values else None


def inside(path: Path, folder: Path) -> bool:
    try:
        path.resolve().relative_to(folder.resolve())
    except ValueError:
        return False
    return True


def forbidden(path: Path, app_dir: Path) -> bool:
    """Внутри папки приложения стенд пишет и держит свои файлы только в results/ (она в .gitignore)."""
    return inside(path, app_dir) and not inside(path, app_dir / "results")


def say(text: str = "") -> None:
    print(text, flush=True)


# ============================================================================ приложение и набор

def load_app(app_dir: Path) -> SimpleNamespace:
    """Модули приложения – на чтение. Отпечаток – хеши исходников модулей конвейера на момент запуска."""
    if not (app_dir / "app" / "triage.py").is_file():
        raise Stop(1, f"В папке {app_dir} нет приложения (app/triage.py): укажите --app.")
    if str(app_dir) not in sys.path:
        sys.path.insert(0, str(app_dir))
    import app as app_pkg  # noqa: PLC0415
    from app import config, context, llm, masking, models, prompts, triage  # noqa: PLC0415

    if not inside(Path(triage.__file__), app_dir):
        raise Stop(1, f"Модуль app.triage загружен не из {app_dir}: {triage.__file__}.")
    files, digest = {}, hashlib.sha256()
    for name in APP_MODULES + tuple(n for n in APP_MODULES_SINCE_0912 if (app_dir / "app" / n).is_file()):
        data = (app_dir / "app" / name).read_bytes()
        files[name] = sha256_hex(data)[:12]
        digest.update(name.encode() + b"\0" + data + b"\0")
    return SimpleNamespace(config=config, context=context, llm=llm, masking=masking, models=models,
                           prompts=prompts, triage=triage, fingerprint=digest.hexdigest()[:16], files=files,
                           version=str(getattr(app_pkg, "__version__", "") or "") or None)


def load_cases(path: Path) -> tuple[list[dict], str]:
    try:
        data = path.read_bytes()
        cases = json.loads(data.decode("utf-8"))
    except (OSError, ValueError) as e:
        raise Stop(1, f"Набор {path} не прочитан: {e}") from None
    if not isinstance(cases, list) or not cases or not all(isinstance(c, dict) and c.get("id") for c in cases):
        raise Stop(1, f"Набор {path}: ожидается непустой список записей с полем id.")
    return cases, sha256_hex(data)


def split_list(text: str | None) -> list[str]:
    return [part.strip() for part in str(text or "").split(",") if part.strip()]


def select_cases(cases: list[dict], args: argparse.Namespace) -> list[dict]:
    chosen = list(cases)
    ids = split_list(args.ids)
    if ids:
        known = {str(c["id"]) for c in cases}
        unknown = [i for i in ids if i not in known]
        if unknown:
            raise Stop(1, f"В наборе нет случаев: {', '.join(unknown)}.")
        want = set(ids)
        chosen = [c for c in chosen if str(c["id"]) in want]
    if args.source:
        chosen = [c for c in chosen if c.get("source") == args.source]
    categories = split_list(args.category)
    if categories:
        chosen = [c for c in chosen if c.get("category") in categories]
    if args.limit:
        chosen = chosen[:args.limit]
    if not chosen:
        raise Stop(1, "Под условия отбора не попал ни один случай.")
    return chosen


# ============================================================================ случай -> промпт (как в прогоне)

SECRET_TAG = re.compile(r"<SECRET_[0-9a-f]{6}>")
# оговорка конфигурации 4 (бэклог 101): только у стенда, промпт приложения не меняется
SECRET_NOTE = ("Метка вида <SECRET_…> – метка маскирования приложения, не само значение: строку в кавычках приложение "
               "заменило до отправки. Судите о находке по тому, как значение используется в коде, а не по метке.")


def value_shape(value: str) -> str:
    """Форма исходного значения без самого значения: длина и состав."""
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        chars = "hex"
    elif re.fullmatch(r"[A-Za-z0-9]+", value):
        chars = "alnum"
    else:
        chars = "mixed"
    return f"len={len(value)} chars={chars}"


@contextlib.contextmanager
def recording_secrets(ns: SimpleNamespace, table: dict[str, str]):
    """Метка -> форма исходного значения: запись в момент, когда маскирование приложения само ставит метку
    (masking._Masker.placeholder), – те же границы значения, что у приложения, в том числе экранированные кавычки и
    многострочные строки (ревью Codex, 101, круг 1). Обёртка действует только в процессе стенда и снимается сразу."""
    cls = ns.masking._Masker
    original = cls.placeholder

    def record(self, kind, value):
        tag = original(self, kind, value)
        if kind == "SECRET":
            table[tag] = value_shape(value)
        return tag
    cls.placeholder = record
    ns.context.clear_mask_cache()  # файл, замаскированный раньше, берётся из кэша без вызова placeholder
    try:
        yield table
    finally:
        cls.placeholder = original


def shape_messages(messages: list[dict], table: dict[str, str]) -> list[dict]:
    """--mask-shape: <SECRET_xxxxxx> -> <SECRET_xxxxxx len=N chars=hex|alnum|mixed> в сообщениях пользователя после
    маскирования; системное сообщение – как у версии промпта."""
    def repl(m: re.Match) -> str:
        shape = table.get(m.group(0))
        return f"{m.group(0)[:-1]} {shape}>" if shape else m.group(0)
    return [{**m, "content": SECRET_TAG.sub(repl, m["content"])} if m.get("role") == "user" else m for m in messages]


def note_messages(messages: list[dict]) -> list[dict]:
    """--secret-note: оговорка о метке в конце системного сообщения."""
    return [{**m, "content": m["content"].rstrip() + "\n\n" + SECRET_NOTE} if m.get("role") == "system" else m
            for m in messages]


def prepare(ns: SimpleNamespace, runner: Any, case: dict, key: bytes, options: dict, spec: Any = None,
            variant: dict | None = None) -> SimpleNamespace:
    """Срез кода, промпт и подгонка под окно контекста – как TriageRunner._process_item до вызова модели.

    Цикл подгонки повторяет прогон (он встроен в _process_item и отдельно не вызывается); все вычисления – функциями
    приложения. messages = None – кода нет, приложение пропустило бы находку («Нет кода для разбора»)."""
    triage = ns.triage
    f = ns.models.Finding(hub_id=str(case["id"]), kind="SAST", rule=case["rule"], cwe=[case["cwe"]],
                          codebase=case["codebase"], file=case.get("hub_file") or case["file"], line=case["line"],
                          snippet=case["snippet"], language=case["language"])
    repo_dir = Path(case["repo_root"]) if case.get("repo_root") else None
    max_chars = triage.CONTEXT_CHARS
    variant = variant or {}
    version = spec.version if spec is not None else None
    table: dict[str, str] = {}
    recorder = recording_secrets(ns, table) if variant.get("mask_shape") else contextlib.nullcontext()
    with recorder:
        return _prepare_fit(ns, runner, case, key, options, f, repo_dir, max_chars, version, variant, table)


def _prepare_fit(ns, runner, case, key, options, f, repo_dir, max_chars, version, variant, table):
    """Тело prepare: срез, сообщения, подгонка под окно (как прогон приложения)."""
    triage, llm, prompts = ns.triage, ns.llm, ns.prompts
    ctx = ns.context.build_context(repo_dir, f, max_chars=max_chars, mask_key=key)
    messages: list[dict] | None = None
    shrinks = 0
    for attempt in range(triage.FIT_ATTEMPTS + 1):
        if not ctx.lines:
            messages = None
            break
        # mask_key: строка срабатывания из выгрузки попадает в промпт только маскированной; _masked – последняя
        # сетка перед отправкой, как в прогоне
        messages = runner._masked(prompts.build_sast_messages(f, ctx, mask_key=key, prompt_version=version))
        if variant.get("mask_shape"):
            messages = shape_messages(messages, table)
        if variant.get("secret_note"):
            messages = note_messages(messages)
        if attempt == triage.FIT_ATTEMPTS or llm.prompt_fits(messages, options):
            break
        excess = llm.prompt_tokens(messages) - (llm.prompt_budget(options) or 0)
        code = "\n".join(ctx.lines)
        keep = max(0.0, 1.0 - excess / max(1, llm.estimate_tokens(code))) * 0.9
        max_chars = int((len(code) + 10 * len(ctx.lines)) * keep)
        if max_chars < triage.MIN_CONTEXT_CHARS:
            break
        ctx = ns.context.build_context(repo_dir, f, max_chars=max_chars, mask_key=key)
        shrinks += 1
    # показанный код окончательного запроса – для сверки цитат sast-v7 (как у удалённого стенда)
    shown = prompts.shown_code(messages, ctx) if messages else []
    return SimpleNamespace(case=case, finding=f, ctx=ctx, messages=messages, max_chars=max_chars, shrinks=shrinks,
                           case_hash=triage.case_hash(f, ctx), shown=shown,
                           tokens_est=llm.prompt_tokens(messages) if messages else 0,
                           steering=prompts.steering_lines(ctx), request_key="")


def request_key(ns: SimpleNamespace, model: str, prep: SimpleNamespace, options: dict, think: str | None,
                version: str | None = None) -> str:
    """Ключ записи журнала: prompts.request_key – хеш запроса к модели целиком (версия промпта, модель, сообщения
    после маскирования, параметры, режим рассуждений). Совпал – случай уже разобран тем же запросом."""
    if prep.messages:
        return ns.prompts.request_key(model, prep.messages, options, think, version)
    payload = {"no_code": prep.case_hash, "model": ns.llm.norm_model_name(model), "think": think,
               "prompt_version": version or ns.prompts.PROMPT_VERSION}
    return sha256_hex(json.dumps(payload, sort_keys=True))


def config_key(ns: SimpleNamespace, model: str, think: str | None, options: dict, spec: Any = None,
               variant: dict | None = None) -> str:
    """Что должно совпадать у всех записей одного журнала: модель, режим рассуждений, версия и текст системного
    промпта, параметры генерации; вариант стенда (бэклог 101) – только когда он задан, прежние ключи не меняются."""
    spec = spec if spec is not None else ns.prompts.spec_for(None)  # версия приложения – номер и текст вместе
    payload = {"model": ns.llm.norm_model_name(model), "think": think, "prompt_version": spec.version,
               "system_prompt": sha256_hex(spec.system),
               "options": {str(k): v for k, v in {**ns.llm.DEFAULT_OPTIONS, **options}.items()}}
    if variant and any(variant.values()):
        payload["variant"] = {k: bool(v) for k, v in sorted(variant.items()) if v}
    return sha256_hex(json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str))[:16]


# ============================================================================ видеокарта

def vram(entry: dict | None) -> dict | None:
    if not entry:
        return None
    size, size_vram = int(entry.get("size") or 0), int(entry.get("size_vram") or 0)
    return {"name": entry.get("name"), "size": size, "size_vram": size_vram,
            "ratio": round(size_vram / size, 4) if size else None, "context": entry.get("context")}


def gb(size: int | None) -> str:
    return "?" if not size else num(size / 1024 ** 3) + " ГБ"


def describe_loaded(entries: list[dict]) -> str:
    return ", ".join(f"{m.get('name')} ({gb(m.get('size_vram'))} в видеопамяти)" for m in entries)


def split_loaded(ns: SimpleNamespace, loaded: list[dict], model: str) -> tuple[list[dict], dict | None]:
    key = ns.llm.norm_model_name(model)
    foreign = [m for m in loaded if ns.llm.norm_model_name(m.get("name")) != key]
    own = next((m for m in loaded if ns.llm.norm_model_name(m.get("name")) == key), None)
    return foreign, own


def other_context(own: dict | None, own_contexts: set[int]) -> int | None:
    """Своя модель загружена с чужим окном контекста (её загрузил кто-то другой): вызов с нашим окном заставил бы
    Ollama перезагрузить её – это та же выгрузка чужого экземпляра. -> его окно или None.

    own_contexts – окна, которые считаются своими: окно прогона и окна, которые /api/ps показал у своей модели
    после собственных вызовов стенда (Ollama может показывать окно с учётом параллельных слотов, а не num_ctx)."""
    ctx = (own or {}).get("context")
    return int(ctx) if ctx and int(ctx) not in own_contexts else None


def gpu_gate(ns: SimpleNamespace, client: Any, model: str, own_contexts: set[int], wait_max: float,
             poll: float) -> dict:
    """Перед вызовом модели: если загружена другая модель (или своя, но с другим окном контекста) – ждать, пока она
    выгрузится сама (не дольше wait_max). Чужие модели не выгружаются и не перезагружаются.
    -> {waited_s, foreign_before, own_before}; не дождались – Stop(3)."""
    started = time.monotonic()
    seen: list[str] = []
    told = False
    while True:
        try:
            loaded = client.ps()
        except ns.llm.LlmError as e:
            raise Stop(5, f"Ollama не отвечает на /api/ps: {e}") from None
        foreign, own = split_loaded(ns, loaded, model)
        busy = list(foreign)
        if other_context(own, own_contexts):
            busy.append({**own, "name": f"{own.get('name')} с окном {own.get('context')}"})
        waited = time.monotonic() - started
        if not busy:
            if told:
                say(f"    дождались: видеокарта освободилась за {duration(waited)}")
            return {"waited_s": round(waited, 1) if seen else 0.0, "foreign_before": seen, "own_before": vram(own)}
        for m in busy:
            if m.get("name") not in seen:
                seen.append(str(m.get("name")))
        if waited >= wait_max:
            raise Stop(3, f"Видеокарта занята ({describe_loaded(busy)}) дольше {duration(wait_max)}. Чужие модели "
                          "стенд не выгружает и не перезагружает: прогон остановлен, продолжить можно той же командой.")
        if not told:
            say(f"    жду: загружено {describe_loaded(busy)} – вызов вытеснил или перезагрузил бы чужую модель. Жду, "
                f"пока она выгрузится сама (не дольше {duration(wait_max)}).")
            told = True
        time.sleep(min(poll, max(0.2, wait_max - waited)))


# ============================================================================ вызов модели

def install_chat_hook(client: Any, override: Any, calls: list) -> None:
    """Обёртка над client._chat (через него OllamaClient.chat_json шлёт каждую попытку в /api/chat).

    override – значение поля think для любой модели (str или bool); UNSET – тело запроса не меняется (как в
    приложении). Тело копируется: chat_json использует его снова для повтора. В calls дописывается по записи на
    попытку: done_reason, токены ответа, длина рассуждения и ответа, что ушло в think."""
    original = client._chat

    def chat(body: dict, name: str) -> dict:
        if override is not UNSET:
            body = {**body, "think": override}
        data = original(body, name)
        message = data.get("message") if isinstance(data.get("message"), dict) else {}
        calls.append({"done_reason": str(data.get("done_reason") or "") or None,
                      "eval_count": data.get("eval_count"),
                      "thinking_chars": len(str(message.get("thinking") or "")),
                      "content_chars": len(str(message.get("content") or "")),
                      "think_sent": body.get("think", "(нет)")})
        return data

    client._chat = chat


def response_marks(calls: list) -> dict:
    """Поля записи случая по попыткам: копия calls; hit_length – хоть одна попытка упёрлась в num_predict
    (done_reason = length), даже если целый объект JSON успел закрыться и ответ принят."""
    return {"responses": [dict(c) for c in calls],
            "hit_length": any(c.get("done_reason") == "length" for c in calls),
            "thinking_chars": sum(int(c.get("thinking_chars") or 0) for c in calls)}


def error_kind(e: Exception) -> str:
    text = str(e)
    for prefix, kind in FORMAT_ERRORS.items():
        if text.startswith(prefix):
            return kind
    if getattr(e, "stats", None) is None:
        return "prompt"  # до обращения к модели: промпт не помещается в окно контекста
    return "format" if getattr(e, "raw", "") else "server"


def measures(ns: SimpleNamespace, stats: Any, seconds: float) -> dict:
    """Замеры ответа: TriageRunner._measures (время без загрузки модели, время генерации) и статистика Ollama."""
    out: dict[str, Any] = {"seconds": round(seconds, 3), "model_call": bool(stats is not None and stats.attempts > 0)}
    if stats is None:
        return out
    m = ns.triage.TriageRunner._measures(stats, seconds)
    out.update(model_seconds=round(m["model_seconds"], 3), eval_seconds=round(m["eval_seconds"], 3),
               output_tokens=stats.output_tokens, prompt_tokens=stats.prompt_tokens, eval_tps=stats.eval_tps,
               prompt_tps=stats.prompt_tps, load_s=stats.load_s, total_s=stats.total_s, attempts=stats.attempts)
    return out


def base_record(prep: SimpleNamespace, cfg: SimpleNamespace, gate: dict) -> dict:
    c, ctx = prep.case, prep.ctx
    return {
        "type": "case", "id": str(c["id"]), "source": c.get("source"), "category": c.get("category"),
        "cwe": c.get("cwe"), "expected": c.get("expected"), "also_ok": list(c.get("also_ok") or []),
        "hint_comment": bool(c.get("hint_comment")),
        "status": None, "error_kind": None, "error": None, "raw_head": None,
        "verdict": None, "confidence": None, "summary": None, "why": None, "evidence_lines": None, "cwe_fit": None,
        "hub_comment": None,
        "model": cfg.model, "think": cfg.think, "prompt_version": cfg.prompt_version, "config_key": cfg.config_key,
        "app_fingerprint": cfg.fingerprint, "request_key": prep.request_key, "case_hash": prep.case_hash,
        "context": {"status": ctx.status, "export_line_check": ctx.export_line_check, "target_line": ctx.target_line,
                    "start_line": ctx.start_line, "end_line": ctx.end_line, "lines": len(ctx.lines),
                    "max_chars": prep.max_chars, "shrinks": prep.shrinks, "masked": dict(ctx.masked),
                    "steering_lines": list(prep.steering)},
        "prompt_tokens_est": prep.tokens_est,
        "gpu": dict(gate),
        "ts": now_iso(),
    }


def run_case(ns: SimpleNamespace, client: Any, prep: SimpleNamespace, cfg: SimpleNamespace, gate: dict) -> dict:
    """Один случай: вызов модели и разбор ответа – как TriageRunner._process_item. Ollama перестала отвечать –
    Stop(5), случай не записывается (продолжение прогона разберёт его заново)."""
    llm, prompts, triage = ns.llm, ns.prompts, ns.triage
    rec = base_record(prep, cfg, gate)
    if not prep.messages:
        rec.update(status="skipped", error_kind="no_code", model_call=False,
                   error=f"Нет кода для разбора: {prep.ctx.note or prep.ctx.status}.")
        return rec
    cfg.calls.clear()  # заполняет обёртка install_chat_hook по ходу вызова: запись на каждую попытку
    started = time.monotonic()
    try:
        spec = cfg.spec
        obj, stats = client.chat_json(cfg.model, prep.messages, spec.fields, spec.required, spec.enums,
                                      options=cfg.options, think=cfg.think_arg, types=spec.types,
                                      validate=prompts.check_verdict_answer)
    except llm.LlmError as e:
        seconds = time.monotonic() - started
        if not triage.TriageRunner._server_alive(client):
            raise Stop(5, f"Ollama перестала отвечать: {e} Случай {rec['id']} не записан – продолжить можно той же "
                          "командой.") from None
        kind = error_kind(e)
        rec.update(status="parse_error" if kind in ("format", "truncated") else "error", error_kind=kind,
                   error=str(e), raw_head=(getattr(e, "raw", "") or "")[:RAW_HEAD] or None,
                   stats_partial=bool(triage._stats_partial(e)))
        rec.update(measures(ns, getattr(e, "stats", None), seconds))
        rec.update(response_marks(cfg.calls))
        return rec
    seconds = time.monotonic() - started
    rec.update(measures(ns, stats, seconds))
    rec.update(response_marks(cfg.calls))
    try:
        # ctx – срез, который видела модель; shown – его строки в окончательном запросе (цитаты sast-v7)
        v = prompts.parse_verdict(obj, prep.ctx, prompt_version=cfg.spec.version, shown=getattr(prep, "shown", None))
    except Exception as e:  # noqa: BLE001 – сбой разбора ответа – ошибка этого случая, прогон идёт дальше
        rec.update(status="parse_error", error_kind="parse_verdict", error=f"{type(e).__name__}: {e}",
                   raw_head=json.dumps(obj, ensure_ascii=False, default=str)[:RAW_HEAD])
        return rec
    rec.update(status="ok", verdict=v.verdict, confidence=v.confidence, summary=v.summary, why=list(v.why),
               evidence_lines=list(v.evidence_lines), cwe_fit=v.cwe_fit, hub_comment=v.hub_comment)
    return rec


def after_call(ns: SimpleNamespace, client: Any, model: str, rec: dict) -> None:
    """После вызова: сколько своей модели в видеопамяти и не появилась ли рядом чужая (тогда замер под нагрузкой)."""
    try:
        loaded = client.ps()
    except ns.llm.LlmError:
        return  # если Ollama упала, это выяснится перед следующим случаем
    foreign, own = split_loaded(ns, loaded, model)
    rec["gpu"].update(own_after=vram(own), foreign_after=[str(m.get("name")) for m in foreign])


# ============================================================================ журнал

class Journal:
    """Журнал прогона (JSONL): строка на случай и на начало и конец каждого запуска. Каждая строка – с fsync."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        tail_ok = True
        if path.exists() and path.stat().st_size:
            with path.open("rb") as fh:
                fh.seek(-1, os.SEEK_END)
                tail_ok = fh.read(1) == b"\n"
        # errors="replace": одиночный суррогат в ответе модели не должен ронять прогон на записи журнала
        self.fh = path.open("a", encoding="utf-8", errors="replace", newline="\n")
        if not tail_ok:  # прошлый запуск оборвался на середине строки
            self.fh.write("\n")

    def write(self, rec: dict) -> None:
        self.fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        self.fh.flush()
        os.fsync(self.fh.fileno())

    def close(self) -> None:
        self.fh.close()


def read_journal(path: Path) -> tuple[list[dict], int]:
    records, broken = [], 0
    if not path.exists():
        return records, broken
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                broken += 1  # оборванная строка после сбоя
                continue
            if isinstance(rec, dict):
                records.append(rec)
    return records, broken


def describe_configs(records: list[dict]) -> str:
    seen = []
    for r in records:
        if not r.get("model"):
            continue
        item = f"модель {r.get('model')}, think {r.get('think') or 'none'}, промпт {r.get('prompt_version')}"
        if item not in seen:
            seen.append(item)
    return "; ".join(seen[:4])


# ============================================================================ метрики

def is_correct(case: dict, rec: dict | None) -> bool:
    if not rec or rec.get("status") != "ok":
        return False
    return rec.get("verdict") == case.get("expected") or rec.get("verdict") in (case.get("also_ok") or [])


def bucket(pairs: list[tuple[dict, dict]]) -> dict:
    """Метрики по набору пар (случай, запись журнала). Ожидаемый ответ – из текущего cases.json."""
    known = [(c, r) for c, r in pairs if c.get("expected") in VERDICTS]
    answered = [(c, r) for c, r in pairs if r.get("status") == "ok"]
    called = [r for _, r in pairs if r.get("model_call")]
    correct = [(c, r) for c, r in known if is_correct(c, r)]
    tp = [(c, r) for c, r in known if c["expected"] == "true_positive"]
    fp = [(c, r) for c, r in known if c["expected"] == "false_positive"]
    unc = [(c, r) for c, r in known if c["expected"] == "uncertain"]
    tp_as_fp = [(c, r) for c, r in tp if r.get("status") == "ok" and r.get("verdict") == "false_positive"]
    fp_as_tp = [(c, r) for c, r in fp if r.get("status") == "ok" and r.get("verdict") == "true_positive"]
    said_unc = [(c, r) for c, r in answered if r.get("verdict") == "uncertain"]
    wrong = [(c, r) for c, r in answered if c.get("expected") in VERDICTS and not is_correct(c, r)]
    answered_known = [(c, r) for c, r in answered if c.get("expected") in VERDICTS]
    parse_errors = [r for _, r in pairs if r.get("status") == "parse_error"]
    errors = [r for _, r in pairs if r.get("status") == "error"]
    skipped = [r for _, r in pairs if r.get("status") == "skipped"]
    retried = [r for _, r in answered if (r.get("attempts") or 0) > 1]
    truncated = [r for r in called if r.get("error_kind") == "truncated"]
    hit_length = [r for r in called if r.get("hit_length") or r.get("error_kind") == "truncated"]
    out_tokens = sum(int(r.get("output_tokens") or 0) for r in called)
    eval_s = sum(float(r.get("eval_seconds") or 0) for r in called)
    return {
        "n": len(pairs), "known": len(known), "answered": len(answered), "model_calls": len(called),
        "correct": len(correct), "accuracy": rate(len(correct), len(known)),
        "accuracy_answered": rate(sum(is_correct(c, r) for c, r in answered_known), len(answered_known)),
        "tp": len(tp), "tp_correct": sum(is_correct(c, r) for c, r in tp),
        "sensitivity": rate(sum(is_correct(c, r) for c, r in tp), len(tp)),
        "fp": len(fp), "fp_correct": sum(is_correct(c, r) for c, r in fp),
        "specificity": rate(sum(is_correct(c, r) for c, r in fp), len(fp)),
        "uncertain_expected": len(unc), "uncertain_expected_correct": sum(is_correct(c, r) for c, r in unc),
        "uncertain_answers": len(said_unc), "uncertain_rate": rate(len(said_unc), len(answered)),
        "tp_as_fp": len(tp_as_fp), "tp_as_fp_rate": rate(len(tp_as_fp), len(tp)),
        "fp_as_tp": len(fp_as_tp), "fp_as_tp_rate": rate(len(fp_as_tp), len(fp)),
        "confidence_wrong_mean": mean([r.get("confidence") for _, r in wrong]),
        "confidence_flip_mean": mean([r.get("confidence") for _, r in tp_as_fp + fp_as_tp]),
        "confidence_correct_mean": mean([r.get("confidence") for c, r in answered if is_correct(c, r)]),
        "parse_errors": len(parse_errors), "unparsed_rate": rate(len(parse_errors), len(called)),
        # оборван – ответ отвергнут: упёрся в num_predict, не закрыв объект JSON (в т. ч. не дорассуждав);
        # hit_length – хоть одна попытка упёрлась в num_predict, включая принятые ответы
        "truncated": len(truncated), "truncated_rate": rate(len(truncated), len(called)),
        "hit_length": len(hit_length), "hit_length_rate": rate(len(hit_length), len(called)),
        "thinking_chars_mean": mean([r.get("thinking_chars") for r in called if "thinking_chars" in r]),
        "errors": len(errors), "skipped": len(skipped),
        "retried": len(retried), "retry_rate": rate(len(retried), len(answered)),
        "time_mean_s": mean([r.get("model_seconds") for r in called]),
        "time_median_s": median([r.get("model_seconds") for r in called]),
        "time_with_load_mean_s": mean([r.get("seconds") for r in called]),
        "time_total_s": round(sum(float(r.get("seconds") or 0) for r in called), 1),
        "tps": round(out_tokens / eval_s, 2) if eval_s > 0 else None,
        "tps_case_mean": mean([r.get("eval_tps") for r in called if (r.get("eval_tps") or 0) > 0]),
        "prompt_tps_mean": mean([r.get("prompt_tps") for r in called if (r.get("prompt_tps") or 0) > 0]),
        "output_tokens_mean": mean([r.get("output_tokens") for r in called]),
        "prompt_tokens_mean": mean([r.get("prompt_tokens") for r in called]),
    }


def gpu_summary(pairs: list[tuple[dict, dict]]) -> dict:
    recs = sorted((r for _, r in pairs), key=lambda r: str(r.get("ts") or ""))
    owns = [r["gpu"]["own_after"] for r in recs if (r.get("gpu") or {}).get("own_after")]
    ratios = [o["ratio"] for o in owns if o.get("ratio") is not None]
    waited = [r for r in recs if ((r.get("gpu") or {}).get("waited_s") or 0) > 0]
    contended = [r for r in recs if (r.get("gpu") or {}).get("foreign_after")]
    foreign: list[str] = []
    for r in recs:
        for name in (r.get("gpu") or {}).get("foreign_before", []) + (r.get("gpu") or {}).get("foreign_after", []):
            if name not in foreign:
                foreign.append(name)
    return {
        "vram_after_load": owns[0] if owns else None,
        "vram_ratio_min": min(ratios) if ratios else None,
        "partial_offload": bool(ratios) and min(ratios) < 0.999,
        "contexts": sorted({o.get("context") for o in owns if o.get("context")}),
        "waited_cases": len(waited),
        "waited_s": round(sum(float(r["gpu"]["waited_s"]) for r in waited), 1),
        "contended_cases": len(contended),
        "contended_ids": [r["id"] for r in contended][:20],
        "foreign_models": foreign,
    }


def build_result(pairs: list[tuple[dict, dict]], meta: dict) -> dict:
    by_source: dict[str, list] = defaultdict(list)
    by_category: dict[str, list] = defaultdict(list)
    by_hint: dict[str, list] = defaultdict(list)
    confusion: dict[str, Counter] = defaultdict(Counter)
    for c, r in pairs:
        by_source[str(c.get("source"))].append((c, r))
        by_category[str(c.get("category"))].append((c, r))
        # подсказка в комментарии у самой строки: у OWASP Benchmark – часть тестов, у Juice Shop – метки авторов
        # (build_cases_projects.py); разрез по источнику, ключи OWASP прежние
        if c.get("source") == "owasp" or c.get("hint_comment"):
            src = str(c.get("source"))
            by_hint[f"{src}_hint" if c.get("hint_comment") else f"{src}_no_hint"].append((c, r))
        answer = r.get("verdict") if r.get("status") == "ok" else f"нет ответа ({r.get('status')})"
        confusion[str(c.get("expected"))][str(answer)] += 1
    order = list(OWASP_ORDER) + sorted(k for k in by_category if k not in OWASP_ORDER)
    errors = [{"id": r["id"], "source": c.get("source"), "category": c.get("category"), "expected": c.get("expected"),
               "verdict": r.get("verdict"), "confidence": r.get("confidence"), "status": r.get("status"),
               "error_kind": r.get("error_kind"), "summary": r.get("summary") or r.get("error")}
              for c, r in pairs if c.get("expected") in VERDICTS and not is_correct(c, r)]
    fingerprints = sorted({str(r.get("app_fingerprint")) for _, r in pairs if r.get("app_fingerprint")})
    return {
        **meta,
        "done": len(pairs),
        "complete": len(pairs) == meta["selected"],
        "app_fingerprints_used": fingerprints,
        "correct_rule": CORRECT_RULE,
        "metrics": bucket(pairs),
        "by_source": {k: bucket(v) for k, v in sorted(by_source.items())},
        "by_category": {k: bucket(by_category[k]) for k in order if k in by_category},
        "by_hint": {k: bucket(v) for k, v in sorted(by_hint.items())},
        "confusion": {k: dict(v) for k, v in sorted(confusion.items())},
        "errors": errors,
        "gpu": gpu_summary(pairs),
        "generated_at": now_iso(),
    }


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1, default=str) + "\n", encoding="utf-8",
                   errors="replace")
    os.replace(tmp, path)


# ============================================================================ запуск

def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Замер модели на эталонном наборе через конвейер «Локального триажа».")
    p.add_argument("--model", required=True, help="имя модели в Ollama, например gpt-oss:20b")
    p.add_argument("--think", type=str.lower, choices=THINK_CHOICES,
                   help="поле think запроса к Ollama для любой модели: low|medium|high|xhigh – строкой, true|false – "
                        "логическим значением; по умолчанию – как в приложении (gpt-oss – low, другим не передаётся)")
    p.add_argument("--num-predict", type=int, default=0,
                   help="предел длины ответа, токенов (по умолчанию – как в приложении: 3072, не больше четверти окна)")
    p.add_argument("--limit", type=int, default=0, help="только первые N отобранных случаев")
    p.add_argument("--prompt-version", default="", help="версия промпта: sast-v6 или sast-v7 (по умолчанию – версия "
                                                        "приложения)")
    p.add_argument("--mask-shape", action="store_true",
                   help="метки секретов с формой исходного значения: <SECRET_xxxxxx len=N chars=hex|alnum|mixed> "
                        "(бэклог 101; только стенд)")
    p.add_argument("--secret-note", action="store_true",
                   help="оговорка в системном сообщении: <SECRET_…> – метка маскирования, не значение (бэклог 101; "
                        "только стенд)")
    p.add_argument("--out", help="итоговый JSON; журнал – рядом, с расширением .jsonl; относительный путь – от "
                                 "текущей папки; по умолчанию results/bench/runs/<модель>__think-<режим>__np<N>.json")
    p.add_argument("--ids", help="только эти случаи, через запятую")
    p.add_argument("--source", choices=("owasp", "demo", "secrets"), help="только случаи этого источника")
    p.add_argument("--category", help="только эти категории, через запятую (sqli, cmdi, …)")
    p.add_argument("--cases", default=str(DEFAULT_CASES),
                   help="эталонный набор (по умолчанию results/bench/cases.json, его собирает build_cases.py)")
    p.add_argument("--app", default=str(DEFAULT_APP), help="папка приложения (по умолчанию – этот репозиторий)")
    p.add_argument("--url", default=DEFAULT_URL,
                   help="адрес Ollama (по умолчанию OLLAMA_URL, без неё – http://127.0.0.1:11434)")
    p.add_argument("--num-ctx", type=int, default=0, help="окно контекста (по умолчанию – как в приложении, 16384)")
    p.add_argument("--timeout", type=float, default=900.0, help="срок ответа модели, секунд (как в приложении: 900)")
    p.add_argument("--wait-max", type=float, default=WAIT_MAX_S, help="сколько ждать выгрузки чужой модели, секунд")
    p.add_argument("--require-loaded", action="store_true", help="не начинать, если модель не загружена (/api/ps)")
    p.add_argument("--retry-errors", action="store_true", help="разобрать заново случаи со сбоем сервера")
    p.add_argument("--restart", action="store_true", help="журнал с другими параметрами переименовать и начать заново")
    p.add_argument("--dry-run", action="store_true", help="только срезы и промпты: модель не вызывается, ничего не "
                                                          "пишется")
    p.add_argument("--show", help="с --dry-run: показать промпт этих случаев целиком, через запятую")
    args = p.parse_args(argv)
    if args.limit < 0:
        p.error("--limit не может быть отрицательным")
    if args.num_predict < 0:
        p.error("--num-predict не может быть отрицательным")
    return args


def think_mode(ns: SimpleNamespace, model: str, info: dict | None,
               requested: str | None) -> tuple[str | None, str | None, Any]:
    """-> (think для chat_json, режим – метка в журнале и имени файла, override для обёртки install_chat_hook).

    Без --think – как в прогоне приложения: модели семейства gpt-oss (по сведениям сервера, а без них – по имени)
    уходит low, остальным поле think не передаётся (в имени файла none). С 0.9.12 клиент сам уровень не выбирает
    (ADR-0102): стенд передаёт уже разрешённое значение. С --think обёртка ставит поле think в каждый запрос:
    true/false – логическим значением, уровни – строкой."""
    if requested is None:
        if not ns.llm.is_gpt_oss(model, info):
            return None, None, UNSET
        return "low", "low", UNSET
    level = requested.strip().casefold()
    override: Any = {"true": True, "false": False}.get(level, level)
    # обёртка заменяет поле think в теле запроса; известный клиенту уровень передаём и в chat_json, чтобы и без
    # обёртки запрос был ближе к заданному (с 0.9.12 клиент уровень сам не выбирает)
    return (level if level in THINK_LEVELS else None), level, override


def variant_suffix(args: argparse.Namespace) -> str:
    """Часть имени файла для версии промпта и варианта стенда; без флагов – пусто (прежние имена)."""
    parts = [getattr(args, "prompt_version", "") or ""]
    parts += [name for name, on in (("mask-shape", getattr(args, "mask_shape", False)),
                                    ("secret-note", getattr(args, "secret_note", False))) if on]
    return "".join(f"__{p}" for p in parts if p)


def resolve_out(args: argparse.Namespace, model: str, think: str | None, num_predict: int) -> Path:
    if args.out:
        out = Path(args.out).resolve()  # относительный путь – от текущей папки
    else:
        out = RESULTS_DIR / (f"{safe_name(model)}__think-{think or 'none'}__np{int(num_predict)}"
                             f"{variant_suffix(args)}.json")
    if out.suffix.lower() != ".json":
        out = out.with_name(out.name + ".json")
    return out


def run(args: argparse.Namespace, client_factory: Any = None) -> int:
    app_dir = Path(args.app)
    ns = load_app(app_dir)
    try:
        spec = ns.prompts.spec_for(getattr(args, "prompt_version", "") or None)
    except KeyError:
        raise Stop(1, f"Версия промпта «{args.prompt_version}» неизвестна: {', '.join(ns.prompts.SPECS)}.") from None
    variant = {"mask_shape": bool(getattr(args, "mask_shape", False)),
               "secret_note": bool(getattr(args, "secret_note", False))}
    cases_path = Path(args.cases)
    cases, cases_sha = load_cases(cases_path)
    selected = select_cases(cases, args)
    for path in (MASK_KEY_PATH, cases_path):
        if forbidden(path, app_dir):
            raise Stop(1, f"{path} – внутри папки приложения, но не в results/: стенд там своих файлов не держит.")
    model = args.model.strip()
    settings = ns.config.Settings()
    options = ns.triage.model_options(args.num_ctx or settings.num_ctx)
    if args.num_predict:
        options["num_predict"] = int(args.num_predict)
    key = ns.masking.load_or_create_key(MASK_KEY_PATH)
    runner = ns.triage.TriageRunner(None, settings, mask_key=key)  # нужен только _masked: база не используется
    client = (client_factory or ns.llm.OllamaClient)(args.url, timeout=args.timeout)
    try:
        client.check_url()
    except ns.llm.LlmError as e:
        raise Stop(1, str(e)) from None

    info, version = None, None
    try:
        version = client.version()
        names = {ns.llm.norm_model_name(m.get("name")) for m in client.list_models()}
        if ns.llm.norm_model_name(model) in names:
            info = client.model_info(model)
        elif not args.dry_run:
            raise Stop(1, f"Модели «{model}» нет в Ollama ({args.url}). Загрузить: ollama pull {model}")
        else:
            say(f"Модели «{model}» нет в Ollama: режим рассуждений определён по имени модели.")
    except ns.llm.LlmError as e:
        if not args.dry_run:
            raise Stop(5, f"Ollama не отвечает: {e}") from None
        say(f"Ollama недоступна ({e}): режим рассуждений определён по имени модели.")
    think_arg, think, override = think_mode(ns, model, info, args.think)
    calls: list[dict] = []
    install_chat_hook(client, override, calls)
    if override is UNSET:
        think_sent = think if think else "(не передаётся)"
    else:
        think_sent = override

    out = resolve_out(args, model, think, options["num_predict"])
    if forbidden(out, app_dir):
        raise Stop(1, f"{out} – внутри папки приложения, но не в results/: укажите --out в results/ или вне "
                      "приложения.")
    journal_path = out.with_suffix(".jsonl")
    cfg = SimpleNamespace(model=model, think=think, think_arg=think_arg, options=options, calls=calls,
                          prompt_version=spec.version, fingerprint=ns.fingerprint, spec=spec, variant=variant,
                          config_key=config_key(ns, model, think, options, spec, variant))

    preps = []
    for case in selected:
        prep = prepare(ns, runner, case, key, options, spec, variant)
        prep.request_key = request_key(ns, model, prep, options, think, spec.version)
        preps.append(prep)

    records, broken = read_journal(journal_path)
    case_records = [r for r in records if r.get("type") == "case"]
    alien = [r for r in records if r.get("config_key") and r.get("config_key") != cfg.config_key]
    if alien and not args.dry_run:
        if not args.restart:
            raise Stop(2, f"Журнал {journal_path} собран с другими параметрами ({describe_configs(alien)}), а сейчас – "
                          f"модель {model}, think {think or 'none'}, промпт {cfg.prompt_version}"
                          f" (ключ параметров {cfg.config_key}). Смешивать нельзя: укажите другой --out или добавьте "
                          "--restart (прежний журнал будет переименован).")
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        old = journal_path.with_name(f"{journal_path.stem}.{stamp}.old.jsonl")
        os.replace(journal_path, old)
        say(f"Прежний журнал переименован: {old}")
        records, case_records, broken = [], [], 0
    index: dict[str, dict] = {}
    for r in case_records:
        if r.get("config_key") == cfg.config_key and r.get("request_key"):
            index[r["request_key"]] = r  # последняя запись по ключу – действующая
    # окна контекста, которые /api/ps показывал у своей модели после вызовов стенда (этот журнал, те же параметры)
    own_contexts = {int(options["num_ctx"])}
    for r in case_records:
        seen_ctx = (((r.get("gpu") or {}).get("own_after")) or {}).get("context")
        if r.get("config_key") == cfg.config_key and seen_ctx:
            own_contexts.add(int(seen_ctx))
    wanted = {p.request_key for p in preps}
    selected_ids = {str(p.case["id"]) for p in preps}
    # записи по отобранным случаям, но с другим запросом (изменились промпт, срез или параметры) – в итог не входят
    stale = len({r.get("request_key") for r in case_records
                 if str(r.get("id")) in selected_ids and r.get("request_key") not in wanted})

    meta = {
        "result_format": RESULT_FORMAT, "model": model, "think": think, "think_requested": args.think,
        "think_sent": think_sent, "num_predict": options["num_predict"], "num_ctx": options["num_ctx"],
        "digest": str((info or {}).get("digest") or "") or None,
        "model_info": {"digest": str((info or {}).get("digest") or "")[:12], "size": (info or {}).get("size"),
                       "params": ((info or {}).get("details") or {}).get("parameter_size"),
                       "quant": ((info or {}).get("details") or {}).get("quantization_level"),
                       "family": ((info or {}).get("details") or {}).get("family")},
        "ollama_url": args.url, "ollama_version": version,
        "prompt_version": cfg.prompt_version, "system_prompt_sha": sha256_hex(cfg.spec.system)[:16],
        "config_key": cfg.config_key, "app_dir": str(app_dir), "app_version": ns.version,
        "app_fingerprint": ns.fingerprint, "app_files": ns.files,
        "options": {**ns.llm.DEFAULT_OPTIONS, **options}, "timeout_s": args.timeout,
        "cases_file": str(cases_path), "cases_sha256": cases_sha, "cases_total": len(cases),
        "selection": {"ids": split_list(args.ids) or None, "source": args.source,
                      "category": split_list(args.category) or None, "limit": args.limit or None},
        "selected": len(preps), "full_set": len(preps) == len(cases),
        "journal": str(journal_path), "stale_records": stale, "broken_lines": broken,
    }

    if args.dry_run:
        return dry_run(ns, args, preps, index, meta, out)

    say(f"Модель {model} (digest {meta['model_info']['digest'] or '?'}), think {think or 'none'} (в запросе: "
        f"{json.dumps(think_sent, ensure_ascii=False)}), промпт {cfg.prompt_version}, окно {options['num_ctx']}, "
        f"предел ответа {options['num_predict']}; Ollama {version}.")
    say(f"Случаев: {len(preps)}; уже в журнале: {sum(1 for p in preps if p.request_key in index)}. Журнал: "
        f"{journal_path}")
    if stale:
        say(f"В журнале {stale} записей с другим запросом (изменились промпт или срез) – в итог не входят.")
    if args.require_loaded:
        try:
            _, own = split_loaded(ns, client.ps(), model)
        except ns.llm.LlmError as e:
            raise Stop(5, f"Ollama не отвечает на /api/ps: {e}") from None
        if own is None:
            raise Stop(4, f"Модель «{model}» сейчас не загружена (/api/ps), а задан --require-loaded: прогон не "
                          "начат, модель не вызывалась.")
        if other_context(own, own_contexts):
            raise Stop(4, f"Модель «{model}» загружена с окном контекста {own.get('context')}, а прогон приложения "
                          f"идёт с окном {options['num_ctx']}: вызов перезагрузил бы её. Задан --require-loaded – "
                          "прогон не начат, модель не вызывалась.")

    journal = Journal(journal_path)
    session_started = time.monotonic()
    journal.write({"type": "session", "event": "start", "ts": now_iso(), "config_key": cfg.config_key,
                   "model": model, "think": think, "prompt_version": cfg.prompt_version,
                   "app_fingerprint": ns.fingerprint, "selected": len(preps), "argv": sys.argv[1:]})
    ran, reason, code = 0, "done", 0
    try:
        total = len(preps)
        for n, prep in enumerate(preps, 1):
            done = index.get(prep.request_key)
            if done is not None and not (args.retry_errors and done.get("status") == "error"):
                continue
            gate = gpu_gate(ns, client, model, own_contexts, args.wait_max, WAIT_POLL_S) if prep.messages else {}
            rec = run_case(ns, client, prep, cfg, gate)
            if rec.get("model_call"):
                after_call(ns, client, model, rec)
                seen_ctx = (rec["gpu"].get("own_after") or {}).get("context")
                if seen_ctx:  # так Ollama показывает окно экземпляра, который загрузил сам стенд
                    own_contexts.add(int(seen_ctx))
            journal.write(rec)
            index[prep.request_key] = rec
            ran += 1
            say(progress_line(n, total, prep.case, rec))
    except Stop as e:
        reason, code = {3: "gpu_busy", 5: "ollama_down"}.get(e.code, "stopped"), e.code
        say(str(e))
    except KeyboardInterrupt:
        reason, code = "interrupted", 130
        say("Прервано (Ctrl+C): сделанное сохранено в журнале, продолжить можно той же командой.")
    finally:
        journal.write({"type": "session", "event": "end", "ts": now_iso(), "config_key": cfg.config_key,
                       "reason": reason, "ran": ran, "seconds": round(time.monotonic() - session_started, 1)})
        journal.close()

    sessions = [r for r in read_journal(journal_path)[0]
                if r.get("type") == "session" and r.get("config_key") == cfg.config_key]
    pairs = [(p.case, index[p.request_key]) for p in preps if p.request_key in index]
    result = build_result(pairs, {**meta, "sessions": sessions, "last_stop": reason})
    write_json(out, result)
    say(final_lines(result, out))
    return code


def progress_line(n: int, total: int, case: dict, rec: dict) -> str:
    expected = SHORT.get(case.get("expected"), str(case.get("expected")))
    if rec.get("status") == "ok":
        answer = f"{SHORT.get(rec.get('verdict'), rec.get('verdict'))} {rec.get('confidence')}%"
        mark = "верно" if is_correct(case, rec) else "ОШИБКА"
    else:
        answer, mark = f"нет ответа ({rec.get('error_kind')})", "ОШИБКА"
    speed = f"{num(rec.get('eval_tps'), 0)} ток/с" if rec.get("eval_tps") else ""
    wait = f"  ждали {duration(rec['gpu']['waited_s'])}" if (rec.get("gpu") or {}).get("waited_s") else ""
    width = len(str(total))
    return (f"[{n:>{width}}/{total}] {rec['id']:<19} {str(case.get('source')):<5} {str(case.get('category')):<18} "
            f"ожид. {expected:<6} ответ {answer:<22} {mark:<6} {num(rec.get('seconds'))} с  {speed}{wait}")


def final_lines(result: dict, out: Path) -> str:
    m, g = result["metrics"], result["gpu"]
    lines = [
        "",
        f"Итог: {result['model']} (think {result['think'] or 'none'}, num_predict {result.get('num_predict')}, "
        f"digest {str(result.get('digest') or '?')[:12]}), случаев {result['done']} из {result['selected']}"
        + ("" if result["complete"] else " – прогон неполный"),
        f"  оборвано по num_predict: {m['truncated']} ({pct(m['truncated_rate'])}); упёрлись в предел, включая "
        f"принятые: {m['hit_length']} ({pct(m['hit_length_rate'])}); рассуждение в среднем "
        f"{num(m['thinking_chars_mean'], 0)} знаков",
        f"  точность {pct(m['accuracy'])} ({m['correct']}/{m['known']}); настоящие {pct(m['sensitivity'])}, "
        f"ложные {pct(m['specificity'])}, «неясно» {pct(m['uncertain_rate'])}",
        f"  истинная названа ложной: {m['tp_as_fp']}; ложная названа истинной: {m['fp_as_tp']}; уверенность на "
        f"ошибках {num(m['confidence_wrong_mean'])}",
        f"  время на находку: медиана {num(m['time_median_s'])} с, среднее {num(m['time_mean_s'])} с (без загрузки "
        f"модели); {num(m['tps'])} ток/с; не разобрано {m['parse_errors']}, сбоев {m['errors']}",
    ]
    vr = g.get("vram_after_load")
    if vr:
        lines.append(f"  видеопамять: {gb(vr.get('size_vram'))} из {gb(vr.get('size'))} ({pct(vr.get('ratio'))}), "
                     f"окно {vr.get('context')}" + (" – часть модели в памяти процессора" if g["partial_offload"]
                                                    else ""))
    if g["waited_cases"]:
        lines.append(f"  ждали выгрузки чужих моделей: {g['waited_cases']} раз, всего {duration(g['waited_s'])} "
                     f"({', '.join(g['foreign_models'])})")
    if g["contended_cases"]:
        lines.append(f"  во время {g['contended_cases']} ответов рядом была загружена чужая модель – их время "
                     "ненадёжно")
    lines.append(f"  итог: {out}")
    return "\n".join(lines)


def dry_run(ns: SimpleNamespace, args: argparse.Namespace, preps: list, index: dict, meta: dict, out: Path) -> int:
    """Без модели: срезы, промпты, оценка размера и проверки маскирования. Журнал и итог не пишутся (пишется только
    ключ маскирования стенда при первом запуске)."""
    budget = ns.llm.prompt_budget(ns.triage.model_options(meta["options"]["num_ctx"]))
    say(f"Проверка без модели: {meta['model']}, think {meta['think'] or 'none'}, промпт {meta['prompt_version']}, "
        f"окно {meta['options']['num_ctx']}, на промпт до {budget} токенов.")
    say(f"Итог будет: {out}; журнал: {meta['journal']} (готово по журналу: "
        f"{sum(1 for p in preps if p.request_key in index)} из {len(preps)}).")
    problems = []
    for p in preps:
        c, ctx = p.case, p.ctx
        user = (p.messages or [{}, {}])[1].get("content", "") if p.messages else ""
        span = f"{ctx.start_line}–{ctx.end_line}" if ctx.start_line else "без номеров"
        masked = ", ".join(f"{k} {v}" for k, v in sorted(ctx.masked.items())) or "–"
        notes = []
        if p.shrinks:
            notes.append(f"срез сокращён {p.shrinks} раз")
        if p.steering:
            notes.append(f"похоже на указания: строки {p.steering}")
        if ctx.export_line_check == "differs" or ctx.status != "ok":
            shown = "Строка срабатывания в выгрузке" in user or ctx.status == "export_line_only"
            notes.append("строка выгрузки в промпте" if shown else "строки выгрузки в промпте НЕТ")
        if ns.masking.is_credential_finding(c.get("rule"), [c.get("cwe")]):
            literals = [s for s in re.findall(r'"([^"]{4,})"', c.get("snippet") or "")]
            leaked = [s for s in literals if any(s in str(m.get("content")) for m in (p.messages or []))]
            notes.append("секрет в промпте ОТКРЫТ" if leaked else "секрет скрыт")
            if leaked:
                problems.append(f"{c['id']}: значение из строки срабатывания попало в промпт открытым")
        if not p.messages:
            problems.append(f"{c['id']}: нет кода – приложение пропустило бы находку")
        elif p.tokens_est > (budget or 10 ** 9):
            problems.append(f"{c['id']}: промпт ~{p.tokens_est} токенов не помещается – будет ошибка")
        say(f"{c['id']:<19} {str(c.get('source')):<5} {str(c.get('category')):<18} "
            f"{SHORT.get(c.get('expected'), c.get('expected')):<6} {ctx.status}/{ctx.export_line_check or '–'} "
            f"строки {span} (>>{ctx.target_line}) ~{p.tokens_est} ток. скрыто: {masked}"
            + (f"; {'; '.join(notes)}" if notes else ""))
    for wanted in split_list(args.show):
        p = next((p for p in preps if str(p.case["id"]) == wanted), None)
        if p is None:
            say(f"\n{wanted}: нет среди отобранных случаев")
            continue
        say(f"\n===== {wanted}: сообщение пользователя (системное – prompts.SYSTEM_PROMPT) =====")
        say(p.messages[1]["content"] if p.messages else "(промпта нет: нет кода)")
    sizes = [p.tokens_est for p in preps if p.messages]
    say(f"\nПромпт, оценка сверху: от {min(sizes) if sizes else 0} до {max(sizes) if sizes else 0} токенов, "
        f"бюджет {budget}. Ключ параметров {meta['config_key']}, отпечаток приложения {meta['app_fingerprint']}.")
    if problems:
        say("Замечания:\n  " + "\n  ".join(problems))
    else:
        say("Замечаний нет.")
    return 0


def main(argv: list[str] | None = None, client_factory: Any = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = parse_args(argv)
    try:
        return run(args, client_factory)
    except Stop as e:
        print(str(e), file=sys.stderr, flush=True)
        return e.code
    except KeyboardInterrupt:
        print("Прервано (Ctrl+C).", file=sys.stderr, flush=True)
        return 130


if __name__ == "__main__":
    sys.exit(main())

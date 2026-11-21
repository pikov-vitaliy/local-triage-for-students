"""Замер к записке docs/model-errors-note.md (план dev7, раздел 9). Приложение не меняется, все примеры вымышленные.

Часть mask: одна и та же находка о секрете в трёх видах среза:
  all     – как в приложении: у находки о секрете все строки в кавычках заменены метками (ADR-0117);
  secrets – как у обычной находки: скрыты только значения у ключей со словом-секретом;
  none    – без маскирования: нет меток, заметки о них и счётчика скрытых значений, нет последней сетки;
  values  – сообщение как в all, заметка и счётчик те же, но на месте меток настоящие значения: отличаются только они;
  neutral – как all, но метка <STR_…> вместо <SECRET_…>;
  hint    – как neutral, и в метке вид значения (тип содержимого, текст, слово, прочая строка).
Промпт разбора – текущий (app.prompts.build_sast_messages), вызов – как в прогоне (chat_json, think по умолчанию).
Подмена is_credential_finding действует только в этом процессе.

Часть translate: перевод вымышленных бюллетеней, проверка, что идентификаторы и версии не потеряны.
Часть common: общий текст дефекта по нескольким решениям, проверка, что места не выдуманы и не потеряны.

Запуск из корня репозитория:
    .venv\\Scripts\\python -I -B scripts/bench/model_notes_probe.py --part mask --out results/bench/probe/mask.jsonl
Прерванный прогон продолжается той же командой: готовые записи журнала не повторяются. Ключ записи содержит модель
и версию промпта, ключ маскирования хранится рядом с журналом (<out>.key), поэтому другая модель и другой промпт считаются
заново, а продолжение видит те же метки.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
from collections import defaultdict  # noqa: E402
from pathlib import Path  # noqa: E402

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BENCH))

import run_bench  # noqa: E402

RULE = "Use of Hard-coded Password"
_MIME = [("html", "text/html"), ("css", "text/css"), ("js", "text/javascript"), ("json", "application/json"),
         ("png", "image/png"), ("gif", "image/gif"), ("svg", "image/svg+xml"), ("pdf", "application/pdf"),
         ("zip", "application/zip"), ("gz", "application/gzip"), ("mp3", "audio/mpeg"), ("mp4", "video/mp4"),
         ("woff2", "font/woff2"), ("csv", "text/csv"), ("xml", "application/xml"), ("ics", "text/calendar")]


def _mime_table(extra: tuple[str, str]) -> tuple[str, int]:
    rows = _MIME[:9] + [extra] + _MIME[9:]
    body = "\n".join(f"  {k}: '{v}'," for k, v in rows)
    return f"// Соответствие расширений файлов и типов содержимого\nexport const mimeTypes = {{\n{body}\n}};\n", 12


_I18N = ("export const labels = {\n  login: 'Имя пользователя',\n  password: 'Введите пароль',\n"
         "  repeat: 'Повторите пароль',\n  submit: 'Войти',\n};\n")
_JAVA_PARAM = ("package demo.web;\n\npublic final class LoginForm {\n"
               "    private static final String LOGIN_PARAM = \"username\";\n"
               "    private static final String PASSWORD_PARAM = \"password\";\n\n"
               "    public String read(java.util.Map<String, String> form) {\n"
               "        return form.get(PASSWORD_PARAM);\n    }\n}\n")
_PY_FIELD = ("from demo.forms import Form\n\nPASSWORD_FIELD_NAME = \"user_password\"\n\n\n"
             "def read(form: Form) -> str:\n    return form[PASSWORD_FIELD_NAME]\n")
_JS_CONFIG = ("import { connect } from './driver.js';\n\nexport function open() {\n"
              "  const dbPassword = 'Kv7!mZq2rT';\n  return connect({ host: 'db.example.test', user: 'svc', "
              "password: dbPassword });\n}\n")
_JAVA_CONN = ("package demo.db;\n\nimport java.sql.*;\n\npublic final class Db {\n"
              "    public Connection open(String url) throws SQLException {\n"
              "        return DriverManager.getConnection(url, \"admin\", \"N0tSoS3cret!\");\n    }\n}\n")
_JS_ACCOUNTS = ("export const accounts = [\n  { user: 'reader', pass: 'r3ad-Only-77' },\n"
                "  { user: 'svc', pass: 'h8Lw-92xQ' },\n];\n")
_PY_TOKEN = ("import requests\n\nAPI_PASSWORD = \"p4ss-Fj29-xKq7\"\n\n\ndef fetch(url: str):\n"
             "    return requests.get(url, auth=(\"robot\", API_PASSWORD))\n")

_t1, _l1 = _mime_table(("pkpass", "application/vnd.apple.pkpass"))
_t2, _l2 = _mime_table(("kdbx", "application/x-keepass2"))
MASK_CASES = [
    {"id": "fp-mime-pkpass", "truth": "fp", "file": "src/mimeTypes.js", "text": _t1, "line": _l1, "lang": "javascript"},
    {"id": "fp-mime-keepass", "truth": "fp", "file": "src/mimeTypes2.js", "text": _t2, "line": _l2, "lang": "javascript"},
    {"id": "fp-i18n-label", "truth": "fp", "file": "src/labels.js", "text": _I18N, "line": 3, "lang": "javascript"},
    {"id": "fp-java-param", "truth": "fp", "file": "src/LoginForm.java", "text": _JAVA_PARAM, "line": 5, "lang": "java"},
    {"id": "fp-py-field", "truth": "fp", "file": "src/form.py", "text": _PY_FIELD, "line": 3, "lang": "python"},
    {"id": "tp-js-config", "truth": "tp", "file": "src/db.js", "text": _JS_CONFIG, "line": 4, "lang": "javascript"},
    {"id": "tp-java-conn", "truth": "tp", "file": "src/Db.java", "text": _JAVA_CONN, "line": 7, "lang": "java"},
    {"id": "tp-js-accounts", "truth": "tp", "file": "src/accounts.js", "text": _JS_ACCOUNTS, "line": 3, "lang": "javascript"},
    {"id": "tp-py-token", "truth": "tp", "file": "src/client.py", "text": _PY_TOKEN, "line": 3, "lang": "python"},
    {"id": "tp-weak-word", "truth": "tp", "file": "src/weak.js", "line": 2, "lang": "javascript",
     "text": "export function login(api) {\n  const password = 'qwerty';\n  return api.signIn('root', password);\n}\n"},
    {"id": "tp-weak-digits", "truth": "tp", "file": "src/Weak.java", "line": 3, "lang": "java",
     "text": "public final class Weak {\n    public void open(Client c) {\n"
             "        c.login(\"root\", \"admin123\");\n    }\n}\n"},
]

_MIME_SHAPE = re.compile(r"[a-z]+/[\w.+-]+")
_QUOTED = re.compile(r"'([^'\n]*)'|\"([^\"\n]*)\"")


def _kind_of(value: str) -> str:
    """Вид значения для варианта hint: сведения о форме строки без самой строки."""
    if _MIME_SHAPE.fullmatch(value):
        return "тип содержимого"
    if " " in value:
        return "текст из слов"
    if re.fullmatch(r"[A-Za-z_]+", value):
        return "одно слово"
    return "строка из букв, цифр и знаков"


def relabel(ns, key: bytes, source: str, messages: list[dict], condition: str) -> list[dict]:
    """neutral: метка без слова SECRET; hint: то же и вид значения; values: настоящее значение вместо метки.
    Меняются только сообщения пользователя: системное сообщение как в приложении."""
    masker = ns.masking._Masker(key)
    table = {}
    for m in _QUOTED.finditer(source):
        value = m.group(1) if m.group(1) is not None else m.group(2)
        table[masker.placeholder("SECRET", value)] = value

    def repl(m: re.Match) -> str:
        tag = m.group(0)
        if condition == "values":
            return table.get(tag, tag)
        name = tag.replace("<SECRET_", "<STR_")
        if condition == "hint" and tag in table:
            return f"{name[:-1]} вид={_kind_of(table[tag])}>"
        return name

    pattern = re.compile(r"<SECRET_[0-9a-f]{6}>")
    return [{**m, "content": pattern.sub(repl, m["content"])} if m.get("role") == "user" else m for m in messages]

TRANSLATE_CASES = [
    ("demo-1", "A flaw in the `parseHeader()` function of ExampleHTTP before 2.14.3 allows a remote attacker to cause "
               "a denial of service via a crafted Transfer-Encoding header (CVE-2031-10001). Upgrade to 2.14.3 or later."),
    ("demo-2", "ExampleXML versions 1.2.0 through 1.9.7 do not limit entity expansion when `resolveExternal` is enabled. "
               "An attacker who controls the input document can read local files. CVE-2031-10002 is fixed in 1.9.8 and "
               "2.0.1. As a workaround, set `resolveExternal=false`."),
    ("demo-3", "The session cookie issued by ExampleAuth 4.x lacks the HttpOnly flag. Combined with a cross-site "
               "scripting issue elsewhere in an application, this may let an attacker steal the session token. This is "
               "tracked as CVE-2031-10003 and was addressed in 4.7.2; 3.x is not affected."),
    ("demo-4", "A race condition in `FileCache.put` in ExampleCache prior to 0.31.0 may allow a local user to replace a "
               "cache entry between the check and the write. Severity is moderate (CVSS 5.3). Fix: CVE-2031-10004, 0.31.0."),
]

COMMON_CASES = [
    ("group-1", "SQL-инъекция", [
        ("src/orders/OrderDao.java:41", "Значение status из запроса склеивается с текстом SQL без параметра."),
        ("src/orders/OrderDao.java:77", "Значение sort подставляется в ORDER BY без проверки по списку допустимых столбцов."),
        ("src/report/ReportDao.java:120", "Значение from из формы склеивается с текстом SQL без параметра."),
    ]),
    ("group-2", "Межсайтовый скриптинг", [
        ("web/profile.js:18", "Имя пользователя из ответа сервера записывается в innerHTML без экранирования."),
        ("web/search.js:52", "Строка поиска из адреса записывается в innerHTML без экранирования."),
    ]),
    ("group-3", "Обход пути", [
        ("src/files/Download.java:33", "Имя файла из запроса соединяется с папкой выгрузки без проверки выхода за её пределы."),
        ("src/files/Preview.java:60", "Имя файла из запроса открывается без проверки выхода за пределы папки."),
        ("src/files/Export.java:15", "Имя файла из параметра соединяется с папкой без нормализации пути."),
        ("src/files/Upload.java:88", "Имя загружаемого файла используется как путь без очистки."),
    ]),
]

TRANSLATE_SYSTEM = ("Переведи описание уязвимости с английского на русский для специалиста по безопасности. Не добавляй "
                    "и не убирай сведения. Идентификаторы CVE, номера версий, имена продуктов, функций и параметров "
                    "оставь как есть. Ответ – объект JSON с единственным ключом text.")
COMMON_SYSTEM = ("По решениям оператора о нескольких находках одного правила напиши общий текст дефекта на русском: "
                 "одно предложение о сути, затем перечень мест, по одной строке на место, в виде «файл:строка – что "
                 "не так», затем одно предложение, что исправить. Используй только сведения из решений, места не "
                 "придумывай и не пропускай. Ответ – объект JSON с единственным ключом text.")


def say(text: str) -> None:
    print(text, flush=True)


def read_done(path: Path) -> dict[str, dict]:
    done: dict[str, dict] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            rec = json.loads(line)
            done[rec["key"]] = rec
    return done


def append(path: Path, rec: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def mask_view(ns, runner, key: bytes, repo: Path, case: dict, condition: str):
    """-> (срез, сообщения). secrets – подмена признака «находка о секрете», none – без ключа и без последней сетки."""
    f = ns.models.Finding(hub_id=case["id"], kind="SAST", rule=RULE, cwe=["CWE-259"], codebase="demo",
                          file=case["file"], line=case["line"], snippet=case["text"].splitlines()[case["line"] - 1].strip(),
                          language=case["lang"])
    real = ns.masking.is_credential_finding
    if condition in ("secrets", "none"):
        ns.masking.is_credential_finding = lambda *_a, **_k: False
        ns.context.is_credential_finding = ns.masking.is_credential_finding
    try:
        mask_key = None if condition == "none" else key
        ctx = ns.context.build_context(repo, f, max_chars=ns.triage.CONTEXT_CHARS, mask_key=mask_key)
        messages = ns.prompts.build_sast_messages(f, ctx, mask_key=mask_key)
        if mask_key is not None:
            messages = runner._masked(messages)
        if condition in ("neutral", "hint", "values"):
            messages = relabel(ns, key, case["text"], messages, condition)
    finally:
        ns.masking.is_credential_finding = real
        ns.context.is_credential_finding = real
    return ctx, messages


def run_mask(ns, client, runner, key: bytes, options: dict, think, model: str, out: Path, seeds: int) -> None:
    done = read_done(out)
    version = ns.prompts.spec_for().version
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        for case in MASK_CASES:
            path = repo / case["file"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(case["text"], encoding="utf-8")
        for seed in range(1, seeds + 1):
            for case in MASK_CASES:
                for condition in ("all", "secrets", "none", "neutral", "hint", "values"):
                    rec_key = f"{model}|{version}|{case['id']}|{condition}|{seed}"
                    if rec_key in done:
                        continue
                    ctx, messages = mask_view(ns, runner, key, repo, case, condition)
                    user = next(m["content"] for m in messages if m.get("role") == "user")
                    rec = {"key": rec_key, "model": model, "prompt": version, "case": case["id"],
                           "truth": case["truth"], "condition": condition, "seed": seed,
                           "sent": [ln for ln in user.splitlines() if str(case["line"]) in ln[:12]][:1],
                           "tags_left": len(re.findall(r"<SECRET_[0-9a-f]{6}>", user)), "masked": ctx.masked}
                    started = time.monotonic()
                    try:
                        obj, _stats = client.chat_json(model, messages, ns.prompts.VERDICT_FIELDS,
                                                       ns.prompts.VERDICT_REQUIRED, ns.prompts.VERDICT_ENUMS,
                                                       options={**options, "seed": seed}, think=think,
                                                       types=ns.prompts.VERDICT_TYPES,
                                                       validate=ns.prompts.check_verdict_answer)
                        v = ns.prompts.parse_verdict(obj, ctx)
                        rec.update(verdict=v.verdict, confidence=v.confidence, summary=v.summary)
                    except ns.llm.LlmError as e:
                        rec.update(verdict="error", error=str(e)[:200])
                    rec["seconds"] = round(time.monotonic() - started, 1)
                    append(out, rec)
                    say(f"{rec_key}: {rec['verdict']} за {rec['seconds']} с")


def tokens_of(text: str) -> set[str]:
    found = set(re.findall(r"CVE-\d{4}-\d+", text))
    found |= set(re.findall(r"\b\d+\.\d+(?:\.\d+)?\b", text))
    found |= set(re.findall(r"`([^`]+)`", text))
    return found


def run_texts(ns, client, options: dict, think, model: str, out: Path, seeds: int, part: str) -> None:
    done = read_done(out)
    cases = TRANSLATE_CASES if part == "translate" else COMMON_CASES
    for seed in range(1, seeds + 1):
        for case in cases:
            rec_key = f"{part}|{model}|{case[0]}|{seed}"
            if rec_key in done:
                continue
            if part == "translate":
                system, user = TRANSLATE_SYSTEM, case[1]
                must = tokens_of(case[1])
            else:
                lines = "\n".join(f"{where}: {text}" for where, text in case[2])
                system, user = COMMON_SYSTEM, f"Правило: {case[1]}\nРешения:\n{lines}"
                must = {where for where, _text in case[2]}
            messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
            rec = {"key": rec_key, "part": part, "model": model, "case": case[0], "seed": seed}
            started = time.monotonic()
            try:
                obj, _stats = client.chat_json(model, messages, {"text": "текст"}, ["text"], {},
                                               options={**options, "seed": seed}, think=think)
                text = str(obj.get("text") or "")
                rec["text"] = text
                rec["lost"] = sorted(t for t in must if t not in text)
                if part == "common":
                    rec["invented"] = sorted(set(re.findall(r"[\w./-]+\.\w+:\d+", text)) - must)
                rec["length"] = len(text)
                rec["cyrillic"] = round(len(re.findall(r"[А-Яа-яЁё]", text)) / max(1, len(text)), 2)
            except ns.llm.LlmError as e:
                rec["error"] = str(e)[:200]
            rec["seconds"] = round(time.monotonic() - started, 1)
            append(out, rec)
            say(f"{rec_key}: потеряно {rec.get('lost')}, за {rec['seconds']} с")


def summary(out: Path) -> None:
    table: dict[tuple[str, str, str, str], list[str]] = defaultdict(list)
    for rec in read_done(out).values():
        if "condition" in rec:
            run = (str(rec.get("model") or "?"), str(rec.get("prompt") or "?"), rec["case"], rec["condition"])
            table[run].append(rec["verdict"])
    for (model, prompt, case, condition), verdicts in sorted(table.items()):
        say(f"{model} {prompt} {case:18} {condition:8} {verdicts}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--part", choices=("mask", "translate", "common"), required=True)
    parser.add_argument("--model", default="gpt-oss:20b")
    parser.add_argument("--out", required=True)
    parser.add_argument("--seeds", type=int, default=2)
    parser.add_argument("--url", default="http://127.0.0.1:11434")
    args = parser.parse_args()
    ns = run_bench.load_app(ROOT)
    settings = ns.config.Settings()
    options = ns.triage.model_options(settings.num_ctx)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    key = ns.masking.load_or_create_key(out.with_name(out.name + ".key"))
    runner = ns.triage.TriageRunner(None, settings, mask_key=key)
    client = ns.llm.OllamaClient(args.url, timeout=900)
    client.check_url()
    think = "low" if ns.llm.is_gpt_oss(args.model, client.model_info(args.model)) else None
    if args.part == "mask":
        run_mask(ns, client, runner, key, options, think, args.model, out, args.seeds)
        summary(out)
    else:
        run_texts(ns, client, options, think, args.model, out, args.seeds, args.part)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

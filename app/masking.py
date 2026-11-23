"""Маскирование секретов и персональных данных до того, как код попадёт в промпт модели.

Главное – mask_text(text, key) -> (текст, счётчики). Найденные значения заменяются плейсхолдерами
<SECRET_n>, <INN_n>, <SNILS_n>, <PHONE_n>, <EMAIL_n>, <PASSPORT_n>, где n – первые 6 hex HMAC-SHA256(ключ, значение):
одинаковые значения получают один номер, а исходное значение без ключа не восстановить. Замена идёт внутри строки,
поэтому число строк и их нумерация не меняются (у приватного ключа PEM и у блока YAML тело заменяется одним номером,
переводы строк остаются на месте). Счётчики – плоский словарь по типам плейсхолдеров, только ненулевые:
{"SECRET": 2, "EMAIL": 1}.

Что ищется (простые регулярные выражения, без внешних библиотек):
  секреты – приватные ключи PEM (и обрезанные, без строки END); ключи AWS; токены GitHub, GitLab, Slack, JWT, Google,
            Stripe, npm, Яндекса; заголовки Bearer и Basic; имя и пароль в адресе (scheme://user:pass@host);
            значения ключей со словами password, passwd, passphrase, pass, pwd, pw, secret, token, credentials,
            пароль, api_key, private_key, secret_key, access_key, signing_key, encryption_key, master_key, client_key –
            в коде (ключ = "…", setPassword("…"), password.equals("…"), третий аргумент getConnection), в YAML
            (в том числе блоки «|» и «>» и списки под ключом), .properties, .env, XML, Dockerfile (ENV) и в строках
            подключения; строки base64 и hex от 32 знаков с высокой энтропией внутри строковых литералов и после
            «:» или «=»;
  ПДн     – ИНН (10 и 12 цифр) и СНИЛС с проверкой контрольной суммы, телефоны +7 и 8, e-mail, паспорт РФ рядом
            со словом «паспорт».
Маскирование работает с запасом: лишний плейсхолдер на безобидной строке допустим, пропуск секрета – нет.

Для находок о жёстко заданных секретах (CWE-798, 259, 321 и родственные – is_credential_finding) этого мало:
срез такой находки строится с заменой всех строковых литералов (строка срабатывания целиком не скрывается –
ADR-0117: код приходит уже проверенным на секреты, а имена переменных и настроек нужны модели и человеку)
(mask_all_literals) – видно устройство кода, но не значения.

Ключ HMAC – 32 случайных байта: у приложения в базе (Database.mask_key, ADR-0133), файл (load_or_create_key) – только у инструментов вне приложения: замеры, демо-база, создаётся один раз и никуда не передаётся.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import hmac
import math
import os
import re
import time
from collections import Counter
from pathlib import Path

from app import i18n

KEY_SIZE = 32
SECRET_TYPES = ("SECRET",)
PII_TYPES = ("INN", "SNILS", "PHONE", "EMAIL", "PASSPORT")

# Плейсхолдер, уже стоящий в тексте: так считаются замаскированные места в готовом срезе (count_placeholders).
PLACEHOLDER_RE = re.compile(r"<(SECRET|INN|SNILS|PHONE|EMAIL|PASSPORT)_([0-9a-f]{6})>")


# ============================================================================ ключ HMAC

def load_or_create_key(path: Path) -> bytes:
    """Ключ HMAC для номеров плейсхолдеров. Нет файла – создаёт его один раз (32 случайных байта, права 0600).

    Файл другой длины – ValueError: молча создавать новый ключ нельзя, иначе у тех же значений сменятся номера.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        pass
    else:
        try:
            os.write(fd, os.urandom(KEY_SIZE))
        finally:
            os.close(fd)
    key = b""
    for _ in range(50):  # файл мог только что создать соседний поток: ждём, пока он допишет ключ
        key = path.read_bytes()
        if len(key) >= KEY_SIZE:
            break
        time.sleep(0.02)
    if len(key) != KEY_SIZE:
        raise ValueError(i18n._("Файл ключа маскирования {name} повреждён: ожидалось {size} байта. Удалите его – "
                                "будет создан новый ключ, номера плейсхолдеров в новых срезах сменятся.",
                                name=path.name, size=KEY_SIZE))
    return key


# ============================================================================ плейсхолдеры и счётчики

def _number(key: bytes, value: str) -> str:
    """Номер плейсхолдера: первые 6 hex HMAC-SHA256(key, значение в UTF-8)."""
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:6]


class _Masker:
    """Выдаёт плейсхолдеры и считает замены по типам. Номер значения считается один раз: у блока YAML или ключа
    PEM одно и то же большое значение заменяется в каждой его строке."""

    def __init__(self, key: bytes):
        self.key = key
        self.by_type: Counter = Counter()
        self._numbers: dict[str, str] = {}

    def placeholder(self, kind: str, value: str) -> str:
        self.by_type[kind] += 1
        number = self._numbers.get(value)
        if number is None:
            number = self._numbers[value] = _number(self.key, value)
        label = f"<{kind}_{number}>"
        book = _RECORD.get()
        if book is not None:  # две разные строки с одной меткой – значение по метке не восстановить
            book[label] = value if book.get(label, value) == value else None
        return label


# Показ без масок (бэклог 111): значения выданных меток запоминаются только внутри recording() и только в словаре,
# который получает вызвавший; в базу, журнал, промпт и тексты для Hub они отсюда не попадают.
_RECORD: contextvars.ContextVar[dict[str, str | None] | None] = contextvars.ContextVar("mask_record", default=None)


@contextlib.contextmanager
def recording():
    """Пока открыт, каждая выданная метка записывается со своим значением: {метка: значение}. У двух разных значений
    с одной меткой (совпали первые 6 hex) значение – None."""
    book: dict[str, str | None] = {}
    token = _RECORD.set(book)
    try:
        yield book
    finally:
        _RECORD.reset(token)


def recording_active() -> bool:
    """Идёт запись значений меток: готовый маскированный текст из памяти брать нельзя – метки должны быть выданы."""
    return _RECORD.get() is not None


def _new_masker(key) -> _Masker:
    if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
        raise ValueError("ключ маскирования – не меньше 16 байт (load_or_create_key)")
    return _Masker(bytes(key))


def _counts(by_type: Counter) -> dict[str, int]:
    return {k: v for k, v in sorted(by_type.items()) if v}


def count_placeholders(text: str) -> dict[str, int]:
    """Сколько плейсхолдеров в тексте, по типам: {"SECRET": 2, "INN": 1}."""
    return _counts(Counter(m.group(1) for m in PLACEHOLDER_RE.finditer(text or "")))


def _splice(m, group, replacement):
    """Текст совпадения, где группа group заменена на replacement (остальное – как было, переводы строк целы)."""
    whole = m.group(0)
    a, b = m.start(group) - m.start(0), m.end(group) - m.start(0)
    return whole[:a] + replacement + whole[b:]


def _first_group(m, groups):
    """Номер первой совпавшей группы из groups (у значения в кавычках три варианта: "…", '…', `…`)."""
    return next(g for g in groups if m.group(g) is not None)


# Значение – не секрет, а ссылка на него или шаблон: ${DB_PASS}, {{ token }}, %(pwd)s, %s, {0}, <password>,
# параметры запроса SQL (?, :pwd, $1, @pwd), звёздочки. Такие значения не маскируются (как и уже стоящие плейсхолдеры).
_REFERENCE = re.compile(r"\s*(?:\$\{.*\}|\$\(.*\)|\{\{.*\}\}|#\{.*\}|%\(?\w*\)?[sdr]|\{\w*\}|<[^<>]*>|\?|:\w+"
                        r"|\$\d+|@\w+|[*xX•]+)\s*")
# Пустые и служебные значения в конфигурации и коде: password = null, token: str.
_NOT_SECRET_WORDS = {"null", "none", "nil", "true", "false", "undefined", "empty", "str", "string", "int", "bool",
                     "boolean", "number", "bytes", "any", "object", "unknown", "char", "byte", "long"}


def _is_reference(value: str) -> bool:
    return bool(_REFERENCE.fullmatch(value)) or not value.strip()


# ============================================================================ детекторы секретов

# Приватный ключ PEM: маркеры BEGIN и END остаются, в теле каждая строка ключевого материала (base64 от 16 знаков)
# заменяется одним и тем же плейсхолдером; кавычки, «\n» и «+» кода вокруг остаются на своих строках.
_PEM = re.compile(r"(-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----)([\s\S]{1,20000}?)"
                  r"(-----END[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----)")
_PEM_BEGIN = re.compile(r"-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----")
_KEY_MATERIAL = re.compile(r"[A-Za-z0-9+/=]{40,}")
_KEY_LINE = re.compile(r"(?<!\\)[A-Za-z0-9+/=]{16,}")  # не с «n» после «\»: экранирование «\n» остаётся целым
# Строка тела ключа без END (обрезанный ключ): base64 от 16 знаков, вокруг – кавычки, «\n», «+» кода.
_PEM_BODY_LINE = re.compile(r"[ \t\"'`+]*(?:[A-Za-z0-9+/=]{16,})(?:\\n)?[ \t\"'`+;,]*\r?")

# Имя и пароль в адресе: scheme://user:pass@host -> scheme://<SECRET_n>@host. Пароль – до последнего «@», за
# которым идёт хост: в пароле бывают «/», «#», «?» и «@».
_URL_CREDENTIALS = re.compile(r"\b([a-z][a-z0-9+.-]{0,30}://)([^\s/?#@:'\"`<>]{1,200}:[^\s'\"`<>]{0,500})@"
                              r"(?=[A-Za-z0-9.\-\[\]:]+(?:[/?#'\"`<>\s,;)]|$))", re.I)

# Токены с узнаваемым началом.
_TOKENS = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}"                                   # AWS access key ID
    r"|gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}"  # GitHub
    r"|gl(?:pat|dt|rt|cbt|ptt)-[A-Za-z0-9_-]{20,}"                 # GitLab
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"                               # Slack
    r"|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"  # JWT
    r"|AIza[0-9A-Za-z_-]{35}"                                      # Google API key
    r"|(?:sk|rk)_live_[0-9A-Za-z]{20,}"                            # Stripe
    r"|npm_[A-Za-z0-9]{36}"                                        # npm
    r"|y0_[A-Za-z0-9_-]{40,}|AQVN[A-Za-z0-9_-]{35,}"               # Яндекс OAuth, ключ Yandex Cloud API
    r")(?![A-Za-z0-9_])")

# Заголовок авторизации: Bearer <токен>, Basic <base64> (в токене должна быть цифра – иначе это просто слово).
_AUTH_HEADER = re.compile(r"\b(?:bearer|basic)[ \t]+([A-Za-z0-9._~+/-]{16,}=*)", re.I)

# Имя ключа со словом-секретом (apiKey, X-Api-Key, db.password, DB_PASS, JWT_SIGNING_KEY, …). Длина вокруг слова
# ограничена: иначе на длинных строках из точек и слов перебор становится квадратичным.
_KEY_WORDS = (r"(?:pass(?:word|wd|phrase)?|pwd|pw|secret|token|credentials?|пароль"
              r"|(?:api|private|secret|access|signing|encryption|master|client)[_-]?key)")
_KEY_NAME = r"[A-Za-z0-9_.-]{0,64}" + _KEY_WORDS + r"[A-Za-z0-9_.-]{0,64}"
_KEY_NAME_XML = r"[A-Za-z0-9_.:-]{0,64}" + _KEY_WORDS + r"[A-Za-z0-9_.:-]{0,64}"
_KEY_START = r"(?<![A-Za-z0-9_.-])"

# Значение в кавычках (группы: "…", '…', `…`). Экранированная кавычка внутри допускается. В '…' не бывает «"»,
# в `…` – никаких кавычек: так строка SQL вида "... password = '" + pwd + "'" не маскируется, и путь данных
# в ней остаётся виден.
_QUOTED = (r"(?:\"((?:\\.|[^\"\\`\r\n]){1,4000})\""
           r"|'((?:\\.|[^'\"\\`\r\n]){1,4000})'"
           r"|`((?:\\.|[^`'\"\\\r\n]){1,4000})`)")
# Необязательный тип перед присваиванием: val password: String = "…", password: str = "…",
# let token: &'static str = "…", secret: Option<&str> = ….
_TYPE_HINT = r"(?::[ \t]*[&*'(\[A-Za-z_][^=\r\n;{}]{0,60}?[ \t]*(?==))?"
_ASSIGN = r"[\"']?\]?[ \t]*" + _TYPE_HINT + r"(?::=|=>|=|:)[ \t]*"
# Префикс строки перед кавычкой: r"…", b'…', f"…", rb"…" (Python), $"…", @"…" (C#).
_PREFIX = r"(?:[rRbBuUfF$@]{1,3}(?=[\"'`]))?"

# ключ = "значение" (а также : := => и ключ в кавычках, как в JSON, или в скобках: $cfg['db_password'] => '…').
_KV_QUOTED = re.compile(_KEY_START + r"[\"']?(" + _KEY_NAME + r")" + _ASSIGN + _PREFIX + _QUOTED, re.I)
# Значение после ключа-секрета длиннее предела _QUOTED: скрывается всё от кавычки до конца строки – предел разбора
# не должен оставлять открытым ни значение, ни его хвост за экранированной кавычкой.
_KV_HUGE = re.compile(_KEY_START + r"[\"']?(" + _KEY_NAME + r")" + _ASSIGN + _PREFIX
                      + r"(?:\"((?:\\.|[^\"\\\r\n]){4000}[^\r\n]*)|'((?:\\.|[^'\\\r\n]){4000}[^\r\n]*)"
                      r"|`((?:\\.|[^`\\\r\n]){4000}[^\r\n]*))", re.I)
# ключ = 'значение' с двойной кавычкой внутри ('demo"secret'): _QUOTED такие не берёт ради строк SQL вида
# "… password = '" + pwd + "'", поэтому здесь значение-склейка ("…" + x + "…") пропускается отдельно.
_KV_SINGLE = re.compile(_KEY_START + r"[\"']?(" + _KEY_NAME + r")" + _ASSIGN + _PREFIX
                        + r"'((?:\\.|[^'\\\r\n]){1,4000})'", re.I)
_CONCAT = re.compile(r"\"[ \t]*\+|\+[ \t]*\"")
# Незакрытое значение после ключа-секрета: password = "значение до конца строки (одно слово, без пробелов).
_KV_OPEN = re.compile(_KEY_START + r"[\"']?(" + _KEY_NAME + r")" + _ASSIGN + _PREFIX
                      + r"[\"'`]([^\s\"'`]{4,})[ \t]*\r?$", re.I | re.M)
# ключ = """…""" (Python, текстовый блок Java) или `…` (шаблонная строка JS): значение бывает на нескольких строках;
# экранированная кавычка внутри значения его не заканчивает.
_KV_BLOCK = re.compile(_KEY_START + r"[\"']?(" + _KEY_NAME + r")" + _ASSIGN
                       + r"[rRbBuUfF]{0,2}(\"\"\"|'''|`)((?:\\[\s\S]|(?!\2)[^\\])*\\?)(?:\2|\Z)", re.I)
# ключ = &quot;значение&quot; – кавычки записаны HTML-сущностями (шаблоны, строка кода из выгрузки); ключ тоже бывает
# в таких кавычках, а внутри значения – другие сущности (&amp;).
_ENTITY_QUOTE = r"&(?:quot|apos|#34|#39|#x22|#x27);"
_KV_ENTITY = re.compile(_KEY_START + r"(" + _KEY_NAME + r")(?:" + _ENTITY_QUOTE + r")?[ \t]*(?::=|=>|=|:)[ \t]*"
                        + _ENTITY_QUOTE + r"(.{1,4000}?)" + _ENTITY_QUOTE, re.I)
# Заголовок Authorization: значение в кавычках или после «Authorization:» маскируется всегда, даже без цифр и
# короткое (Basic с base64 из одних букв, токен из букв); у Digest – всё до конца строки. Переменная после запятой
# без кавычек – не значение.
_AUTH_VALUE_START = r"\bauthorization(?:[\"']?[ \t]*[:=,][ \t]*[\"']|[ \t]*:[ \t]*)"
_AUTH_SCHEMES = r"(?:bearer|basic|token|digest|negotiate)"
_AUTH_EXPLICIT = re.compile(_AUTH_VALUE_START + r"(?:(?:bearer|basic|token|negotiate)[ \t]+)?(?!" + _AUTH_SCHEMES
                            + r"\b)([A-Za-z0-9._~+/-]{4,}=*)", re.I)
_AUTH_DIGEST = re.compile(_AUTH_VALUE_START + r"digest[ \t]+([^\r\n]+)", re.I)
# "ключ", "значение" – put("password", "…"), setProperty("db.password", "…"), os.environ.get("DB_PWD", "…").
_KV_PAIR = re.compile(r"([\"'])(" + _KEY_NAME + r")\1[ \t]*,[ \t]*" + _PREFIX + _QUOTED, re.I)
# Вызов-сеттер или билдер со словом-секретом в имени: setPassword("…"), .password("…"), withApiKey("…") – первый
# строковый аргумент. Чтение и проверка (getPassword("ключ"), checkPassword) – нет.
_SETTER = re.compile(r"(?<![\w$])(?!(?:get|read|load|find|lookup|fetch|resolve|has|is|check|validate|verify|encode"
                     r"|hash|decode|decrypt|encrypt|compare|match|remove|delete|clear|reset|generate|create|parse"
                     r"|print|log|require|expect|assert|contains|mask|hide|prompt|ask|input|show|render)[A-Z_])"
                     r"(?:[A-Za-z]{0,24}?)" + _KEY_WORDS + r"[ \t]*\([ \t]*" + _PREFIX + _QUOTED, re.I)
# Сравнение со строкой: password.equals("…"), pwd == "…", apiToken !== '…', user.getPassword().equals("…").
# Слово-секрет – в конце имени (token_type == 'dot' в разборщике – не секрет), значение – от 4 знаков.
_KEY_NAME_END = r"[A-Za-z0-9_.-]{0,64}" + _KEY_WORDS
_COMPARE = re.compile(_KEY_START + _KEY_NAME_END + r"(?:\(\))?[ \t]*(?:\.[ \t]*equals(?:IgnoreCase)?[ \t]*\("
                      r"[ \t]*|[!=]==?[ \t]*)" + _PREFIX + _QUOTED, re.I)
# "…".equals(password)
_COMPARE_BACK = re.compile(_QUOTED + r"[ \t]*\.[ \t]*equals(?:IgnoreCase)?[ \t]*\([ \t]*" + _KEY_NAME_END
                           + r"(?:\(\))?[ \t]*\)", re.I)
# DriverManager.getConnection(url, "user", "пароль") – третий аргумент.
_GET_CONNECTION = re.compile(r"\bgetConnection[ \t]*\([ \t]*(?:\"[^\"\r\n]*\"|[^,()\"\r\n]{1,300})[ \t]*,[ \t]*"
                             r"(?:\"[^\"\r\n]*\"|[^,()\"\r\n]{1,200})[ \t]*,[ \t]*" + _QUOTED)
# XML: <password>…</password> и <add key="DbPassword" value="…"/>.
_XML_ELEMENT = re.compile(r"<(" + _KEY_NAME_XML + r")(?:[ \t][^<>\r\n]*)?>([^<\r\n]{1,4000})</\1>", re.I)
_XML_KEY_VALUE = re.compile(r"\b(?:key|name)[ \t]*=[ \t]*([\"'])" + _KEY_NAME + r"\1[ \t]+value[ \t]*=[ \t]*"
                            r"([\"'])([^\"'\r\n]{1,4000})\2", re.I)
# XML (Hadoop, Spring): <name>db.password</name> <value>…</value> – на одной строке или на соседних.
_XML_NAME_VALUE = re.compile(r"<name>[ \t]*" + _KEY_NAME_XML + r"[ \t]*</name>[ \t]*(?:\r?\n[ \t]*)?<value>"
                             r"([^<\r\n]{1,4000})</value>", re.I)
# .env и переменные окружения: КЛЮЧ=значение без пробелов вокруг «=» – значение маскируется целиком, даже если оно
# похоже на имя через точку (DB_PASSWORD=demo.password.value): в .env это не ссылка, а само значение.
_ENV_ASSIGN = re.compile(r"^([ \t]*(?:export[ \t]+)?([A-Z][A-Z0-9_]{0,100})=)([^\s'\"`#$][^\s'\"`]{0,3999})"
                         r"(?:[ \t]+#[^\r\n]*)?[ \t]*\r?$", re.M)
# Без кавычек до конца строки – .properties, YAML, .env, .npmrc: db.password=…, token: …, export API_KEY=…
# («|» и «>» в начале значения – указатель блока YAML, он обрабатывается отдельно: _mask_yaml_blocks).
_KV_LINE = re.compile(_KEY_START + r"(" + _KEY_NAME + r")[ \t]*[:=][ \t]*"
                      r"([^\s\"'`#;,(){}<>$%=|][^\s\"'`;,(){}<>]{0,3999})[ \t]*(?:#[^\r\n]*)?\r?$", re.I | re.M)
# Без кавычек, а за значением – «;», «,», «)», «&» или «|» (.env, shell, строка подключения):
# PASSWORD=Qw3rty!2024; и export DB_PASSWORD=… && ./run.sh. Слово из одних букв (this.password = password;) –
# имя переменной, а не секрет: такое значение не маскируется.
_KV_INLINE = re.compile(_KEY_START + r"(" + _KEY_NAME + r")[ \t]*[:=][ \t]*"
                        r"([^\s\"'`#;,(){}<>$%=|&][^\s\"'`;,(){}<>|&]{0,999})(?=[ \t]*[;,)&|])", re.I)
_PLAIN_WORD = re.compile(r"[A-Za-z_$][A-Za-z_$]*")
# Dockerfile: ENV POSTGRES_PASSWORD значение
_DOCKER_ENV = re.compile(r"^([ \t]*ENV[ \t]+" + _KEY_NAME + r"[ \t]+)([^\s=][^\r\n]{0,3999}?)[ \t]*\r?$", re.I | re.M)
# Командная строка: curl -u user:пароль, mysql -pпароль (пароль сразу за -p).
_CLI_USER = re.compile(r"(?<!\S)(?:-u|--user)[ \t]+[^\s:'\"]+:([^\s'\"]+)")
_CLI_MYSQL = re.compile(r"\bmysql(?:dump|admin|import|sh)?\b[^\r\n]*?[ \t]-p([^\s'\"-][^\s'\"]*)")
# Манифест Kubernetes «kind: Secret»: значения под data: и stringData: – секреты (base64 или открытым текстом).
_K8S_SECRET = re.compile(r"(?m)^[ \t]*kind[ \t]*:[ \t]*[\"']?Secret[\"']?[ \t]*\r?$")
_K8S_DATA = re.compile(r"[ \t]*(?:data|stringData)[ \t]*:[ \t]*\r?")
_DOTTED_NAME = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+")  # settings.API_KEY – ссылка, не значение
# YAML: ключ-секрет без значения (вложенный блок или список ниже) или со значением-блоком «|», «>», «|-», «>-».
_YAML_KEY = re.compile(r"([ \t]*)(?:-[ \t]+)?[\"']?" + _KEY_NAME + r"[\"']?[ \t]*:[ \t]*(?:([|>][0-9+-]*)[ \t]*)?"
                       r"(?:#.*)?\r?", re.I)
_YAML_ITEM = re.compile(r"([ \t]*-[ \t]+)(?![\[{])(\S.*?)[ \t]*\r?$")       # - значение
_YAML_PAIR = re.compile(r"([ \t]*[\w.-]{1,64}[ \t]*:[ \t]+)(?![|>][0-9+-]*\s*$)(\S.*?)[ \t]*\r?$")  # ключ: значение
# Переменная окружения в манифесте Kubernetes и Compose: «- name: DB_PASSWORD», строкой ниже «value: …».
_YAML_ENV_NAME = re.compile(r"[ \t]*(?:-[ \t]+)?name[ \t]*:[ \t]*[\"']?" + _KEY_NAME + r"[\"']?[ \t]*\r?", re.I)
_YAML_ENV_VALUE = re.compile(r"([ \t]*value[ \t]*:[ \t]*)(?![|>][0-9+-]*\s*$)(\S.*?)[ \t]*\r?$")

# Строковый литерал на одной строке: "…", '…', `…`. Незакрытый литерал продолжается до конца строки – так разбор
# линейный даже на строке из одних кавычек. Группы 1–3 – закрывающая кавычка (у незакрытого литерала её нет).
_LITERAL = re.compile(r"\"(?:\\.|[^\"\\\r\n])*(?:(\")|\\?(?=[\r\n])|\\?\Z)"
                      r"|'(?:\\.|[^'\\\r\n])*(?:(')|\\?(?=[\r\n])|\\?\Z)"
                      r"|`(?:\\.|[^`\\\r\n])*(?:(`)|\\?(?=[\r\n])|\\?\Z)")
# Внутри литерала: параметр строки подключения или адреса – Password=…; ?token=…& (без пробелов вокруг «=»:
# с пробелами это скорее текст SQL вида «PASSWORD = password_», его не трогаем).
_CONN_PARAM = re.compile(r"(?<![A-Za-z0-9_.-])" + _KEY_NAME + r"=([^;&\"'`\s<>]{1,1000})", re.I)
# Вне литерала – то же после разделителя строки подключения: jdbc.url=jdbc:sqlserver://db;user=sa;password=…
_CONN_PARAM_BARE = re.compile(r"(?<=[;?&])[ \t]*" + _KEY_NAME + r"=([^;&\"'`\s<>]{1,1000})", re.I)
# Внутри литерала: длинная строка из алфавита base64 или hex.
_RUN = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
# Вне литерала – та же строка сразу после «:» или «=» (data: в Secret Kubernetes, ключ в .env, хеш в комментарии).
_RUN_AFTER = re.compile(r"(?<=[:=])([ \t]*)([A-Za-z0-9+/_=-]{32,})")
_HEX = re.compile(r"[0-9a-fA-F]+")
# Строка преобразования шифра Java «алгоритм/режим/дополнение» (RSA/ECB/OAEPWithSHA-256AndMGF1Padding) – не ключ,
# а важная для разбора криптографии подробность; по энтропии её от ключа не отличить.
_CIPHER_TRANSFORM = re.compile(r"[A-Za-z0-9]+/(?:ECB|CBC|CTR|GCM|CCM|CFB\d*|OFB\d*|PCBC|CTS|OCB|SIV|XTS|NONE)/"
                               r"[A-Za-z0-9-]+", re.I)


def _entropy(s: str) -> float:
    """Энтропия Шеннона в битах на символ."""
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _entropy_threshold(n: int, symbols: int) -> float:
    """Порог энтропии для строки длины n: ожидаемая энтропия случайной строки из алфавита в symbols знаков
    (с поправкой Миллера – Мэдоу на короткую выборку) минус запас 0,45 бита. Слова, имена классов и пути обычно
    ниже порога, случайные ключи длиной 32–88 – выше."""
    return math.log2(symbols) - (symbols - 1) / (2 * n * math.log(2)) - 0.45


def looks_random(run: str) -> bool:
    """Строка base64/hex от 32 знаков похожа на ключ: смесь классов символов и энтропия не ниже порога для её длины.

    Не ключи: маршруты и пути (с «/» в начале и ещё хотя бы одним «/», или с «//») и строки преобразования шифра.
    """
    path_like = (run.startswith("/") and run.count("/") >= 2) or "//" in run
    if len(run) < 32 or path_like or _CIPHER_TRANSFORM.fullmatch(run):
        return False
    has_digit = any(c.isdigit() for c in run)
    if _HEX.fullmatch(run):
        return has_digit and any(c.isalpha() for c in run) and _entropy(run) >= _entropy_threshold(len(run), 16)
    return (has_digit and any(c.islower() for c in run) and any(c.isupper() for c in run)
            and _entropy(run) >= _entropy_threshold(len(run), 64))


def _mask_pem(text: str, masker: _Masker) -> str:
    def repl(m):
        body = m.group(2).replace("\\n", "\n")  # «\n» внутри строкового литерала – тоже граница строки ключа
        if not _KEY_MATERIAL.search(body):
            return m.group(0)  # между маркерами нет ключа – это код, который ищет маркеры
        value = "".join(_KEY_LINE.findall(body))  # весь ключ – одно значение, один номер
        masked_body = _KEY_LINE.sub(lambda _: masker.placeholder("SECRET", value), m.group(2))
        return m.group(1) + masked_body + m.group(3)

    text = _PEM.sub(repl, text)
    if not _PEM_BEGIN.search(text):
        return text
    # Ключ без строки END (обрезан при копировании): тело – непрерывный блок строк base64 сразу после BEGIN.
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if not _PEM_BEGIN.search(line):
            continue
        body = []
        for j in range(i + 1, len(lines)):
            if not _PEM_BODY_LINE.fullmatch(lines[j]):
                break
            body.append(j)
        value = "".join("".join(_KEY_LINE.findall(lines[j].replace("\\n", " "))) for j in body)
        for j in body:
            lines[j] = _KEY_LINE.sub(lambda _, v=value: masker.placeholder("SECRET", v), lines[j])
    return "\n".join(lines)


def _value_repl(masker: _Masker, groups, min_len: int = 1):
    """Замена значения в совпадении (группа значения – первая совпавшая из groups), если это не ссылка вида ${...}
    и не короче min_len знаков."""
    def repl(m):
        group = _first_group(m, groups)
        value = m.group(group)
        if _is_reference(value) or len(value.strip()) < min_len:
            return m.group(0)
        return _splice(m, group, masker.placeholder("SECRET", value))
    return repl


def _quoted_groups(pattern):
    """Номера групп значения в кавычках (_QUOTED) – это три последние группы шаблона."""
    n = pattern.groups
    return (n - 2, n - 1, n)


def _block_repl(masker: _Masker):
    """ключ = \"\"\"…\"\"\": каждая непустая строка значения – один и тот же плейсхолдер, переводы строк на месте."""
    def repl(m):
        value = m.group(3)
        if _is_reference(value) or PLACEHOLDER_RE.fullmatch(value.strip()):
            return m.group(0)
        parts = []
        for k, part in enumerate(value.split("\n")):
            if not part.strip():
                parts.append(part)
                continue
            cr = "\r" if part.endswith("\r") else ""
            indent = "" if k == 0 else part[:_indent_width(part)]
            parts.append(indent + masker.placeholder("SECRET", value) + cr)
        return _splice(m, 3, "\n".join(parts))
    return repl


def _sub_lines_with(text: str, needle: str, pattern, repl) -> str:
    """pattern.sub только на строках, где есть needle (без учёта регистра): шаблон, который начинается с кавычки,
    не перебирает каждую кавычку длинного файла."""
    if needle not in text.lower():
        return text
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if needle in line.lower():
            lines[i] = pattern.sub(repl, line)
    return "\n".join(lines)


def _mask_quoted_values(text: str, masker: _Masker) -> str:
    """ключ = "значение", многострочное значение, "ключ", "значение", сеттеры, сравнения, getConnection, XML –
    значение, если это не ссылка."""
    text = _KV_BLOCK.sub(_block_repl(masker), text)
    for pattern in (_KV_QUOTED, _KV_PAIR, _SETTER, _GET_CONNECTION):
        text = pattern.sub(_value_repl(masker, _quoted_groups(pattern)), text)
    text = _KV_HUGE.sub(_value_repl(masker, (2, 3, 4)), text)  # длиннее предела: до конца строки
    for pattern in (_KV_OPEN, _KV_ENTITY):  # незакрытое, в кавычках-сущностях
        text = pattern.sub(_value_repl(masker, (2,)), text)

    def single_repl(m):  # 'значение' с двойной кавычкой внутри, но не склейка строк SQL
        value = m.group(2)
        if _CONCAT.search(value) or _is_reference(value) or PLACEHOLDER_RE.fullmatch(value.strip()):
            return m.group(0)
        return _splice(m, 2, masker.placeholder("SECRET", value))

    text = _KV_SINGLE.sub(single_repl, text)
    # сравнение с «.» или «EOF» – не пароль
    text = _COMPARE.sub(_value_repl(masker, _quoted_groups(_COMPARE), min_len=4), text)
    text = _sub_lines_with(text, "equals", _COMPARE_BACK,
                           _value_repl(masker, _quoted_groups(_COMPARE_BACK), min_len=4))
    text = _XML_ELEMENT.sub(_value_repl(masker, (2,)), text)
    text = _XML_KEY_VALUE.sub(_value_repl(masker, (3,)), text)
    return _XML_NAME_VALUE.sub(_value_repl(masker, (1,)), text)


def _bare_value_ok(value: str) -> bool:
    """Значение без кавычек – не секрет: ссылка, служебное слово, имя через точку, тип."""
    return (_is_reference(value) or value.lower() in _NOT_SECRET_WORDS or bool(_DOTTED_NAME.fullmatch(value))
            or bool(re.fullmatch(r"(?:Optional|List|Dict|Union)\[.*\]", value)))


def _mask_line_values(text: str, masker: _Masker, env_style: bool = True) -> str:
    def line_repl(m):
        value = m.group(2)
        if _bare_value_ok(value):
            return m.group(0)
        return _splice(m, 2, masker.placeholder("SECRET", value))

    def inline_repl(m):
        value = m.group(2)
        if _bare_value_ok(value) or _PLAIN_WORD.fullmatch(value) or re.fullmatch(r"\d{1,3}", value):
            return m.group(0)  # имя переменной (this.password = password;) или маленькое число – не секрет
        return _splice(m, 2, masker.placeholder("SECRET", value))

    def docker_repl(m):
        value = m.group(2)
        return m.group(0) if _bare_value_ok(value) else _splice(m, 2, masker.placeholder("SECRET", value))

    def env_repl(m):
        value = m.group(3)
        if (not re.search(_KEY_WORDS, m.group(2), re.I) or _is_reference(value)
                or value.lower() in _NOT_SECRET_WORDS):
            return m.group(0)
        return _splice(m, 3, masker.placeholder("SECRET", value))

    if env_style:
        text = _ENV_ASSIGN.sub(env_repl, text)
    text = _KV_LINE.sub(line_repl, text)
    text = _KV_INLINE.sub(inline_repl, text)
    text = _DOCKER_ENV.sub(docker_repl, text)
    for pattern in (_CONN_PARAM_BARE, _CLI_USER, _CLI_MYSQL):
        text = pattern.sub(_value_repl(masker, (1,)), text)
    return text


def _indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _mask_yaml_blocks(text: str, masker: _Masker) -> str:
    """YAML: значение-блок после ключа-секрета (password: | и >-) и вложенный блок под ключом-секретом без значения
    (secrets:\\n  - …, password:\\n  value: …). Строки блока маскируются на месте, число строк не меняется."""
    lines = text.split("\n")
    k8s_secret = bool(_K8S_SECRET.search(text))
    i = 0
    while i < len(lines):
        if _YAML_ENV_NAME.fullmatch(lines[i]):  # - name: DB_PASSWORD / value: … (первая непустая строка ниже)
            k = next((k for k in range(i + 1, min(i + 4, len(lines))) if lines[k].strip()), None)
            value = _YAML_ENV_VALUE.fullmatch(lines[k]) if k is not None else None
            if value and not _is_reference(value.group(2)) and not PLACEHOLDER_RE.fullmatch(value.group(2)):
                lines[k] = _splice(value, 2, masker.placeholder("SECRET", value.group(2)))
            i += 1
            continue
        m = _YAML_KEY.fullmatch(lines[i])
        if m:
            indent, block = len(m.group(1).expandtabs()), m.group(2)
        elif k8s_secret and _K8S_DATA.fullmatch(lines[i]):
            indent, block = _indent_width(lines[i].expandtabs()), None
        else:
            i += 1
            continue
        body = []
        j = i + 1
        while j < len(lines):
            line = lines[j].rstrip("\r")
            if line.strip() and _indent_width(line.expandtabs()) <= indent:
                break
            if line.strip():
                body.append(j)
            j += 1
        if block:  # значение-блок: все строки – одно значение, один номер
            value = "\n".join(lines[k].strip() for k in body)
            for k in body:
                line = lines[k]
                cr = "\r" if line.endswith("\r") else ""
                if not PLACEHOLDER_RE.fullmatch(line.strip()):
                    lines[k] = line[:_indent_width(line)] + masker.placeholder("SECRET", value) + cr
        else:  # вложенный блок: элементы списка и значения «ключ: значение»
            for k in body:
                item = _YAML_ITEM.fullmatch(lines[k]) or _YAML_PAIR.fullmatch(lines[k])
                if item and not _is_reference(item.group(2)) and not PLACEHOLDER_RE.fullmatch(item.group(2)):
                    lines[k] = _splice(item, 2, masker.placeholder("SECRET", item.group(2)))
        i = j if body else i + 1
    return "\n".join(lines)


def _literal_parts(m) -> tuple[str, str, str]:
    """Совпадение _LITERAL -> (открывающая кавычка, содержимое, закрывающая кавычка или "" у незакрытого)."""
    literal = m.group(0)
    closed = any(m.group(g) is not None for g in (1, 2, 3))
    return literal[0], (literal[1:-1] if closed else literal[1:]), (literal[-1] if closed else "")


def _mask_literals(text: str, masker: _Masker) -> str:
    """Внутри строковых литералов: параметры строк подключения и длинные случайные строки base64/hex; вне
    литералов – такие же строки сразу после «:» или «=»."""
    def run_repl(m):
        run = m.group(0)
        return masker.placeholder("SECRET", run) if looks_random(run) else run

    def param_repl(m):
        value = m.group(1)
        if _is_reference(value):
            return m.group(0)
        return _splice(m, 1, masker.placeholder("SECRET", value))

    def literal_repl(m):
        opening, inner, closing = _literal_parts(m)
        inner = _CONN_PARAM.sub(param_repl, inner)
        inner = _RUN.sub(run_repl, inner)
        return opening + inner + closing

    def after_repl(m):
        run = m.group(2)
        return m.group(1) + masker.placeholder("SECRET", run) if looks_random(run) else m.group(0)

    text = _LITERAL.sub(literal_repl, text)
    return _RUN_AFTER.sub(after_repl, text)


def _mask_secrets(text: str, masker: _Masker, env_style: bool = True) -> str:
    text = _mask_pem(text, masker)
    text = _URL_CREDENTIALS.sub(lambda m: _splice(m, 2, masker.placeholder("SECRET", m.group(2))), text)
    text = _TOKENS.sub(lambda m: masker.placeholder("SECRET", m.group(0)), text)

    def auth_repl(m):
        if not any(c.isdigit() for c in m.group(1)):
            return m.group(0)
        return _splice(m, 1, masker.placeholder("SECRET", m.group(1)))

    for pattern in (_AUTH_DIGEST, _AUTH_EXPLICIT):
        text = pattern.sub(lambda m: _splice(m, 1, masker.placeholder("SECRET", m.group(1))), text)
    text = _AUTH_HEADER.sub(auth_repl, text)
    text = _mask_quoted_values(text, masker)
    text = _mask_literals(text, masker)
    text = _mask_yaml_blocks(text, masker)
    return _mask_line_values(text, masker, env_style)


# ============================================================================ детекторы ПДн

# E-mail (до цифровых правил: иначе цифры из адреса ушли бы в ИНН и адрес остался бы виден наполовину).
_EMAIL = re.compile(r"(?<![\w.%+-])[\w.%+-]+@[\w-]+(?:\.[\w-]+)*\.[^\W\d_]{2,}(?![\w-])")
# Паспорт РФ: слово «паспорт» (или passport), затем в пределах 40 знаков серия (4 цифры) и номер (6 цифр).
_PASSPORT = re.compile(r"(?:паспорт|passport)[^\d\r\n]{0,40}?(\d{2}[ \t]?\d{2}[ \t]*(?:№|N|No\.?|#|-)?[ \t]*\d{6})"
                       r"(?!\d)", re.I)
# СНИЛС: 123-456-789 01, 123 456 789 01 или 11 цифр подряд.
_SNILS = re.compile(r"(?<![\d.])(\d{3})([- ]?)(\d{3})\2(\d{3})[- ]?(\d{2})(?![\d.]?\d)")
# Телефон +7 или 8 и ещё 10 цифр: +7 (916) 123-45-67, 8 916 123 45 67, 89161234567.
_PHONE = re.compile(r"(?<![\d+])(?:\+7|8)[ \t\-(]{0,3}\d{3}[ \t\-)]{0,3}\d{3}[ \t\-]{0,2}\d{2}[ \t\-]{0,2}\d{2}(?!\d)")
# ИНН: ровно 10 или 12 цифр (не часть числа, не дробная часть, не 0x…).
_INN = re.compile(r"(?<![\d.])(?<!0[xX])(\d{12}|\d{10})(?![\d.]?\d)")


def _digits(s: str) -> str:
    return "".join(c for c in s if c.isdigit())


def inn_ok(digits: str) -> bool:
    """ИНН: 10 цифр (организация) или 12 (физическое лицо) с верными контрольными цифрами."""
    if not digits.isdigit() or len(digits) not in (10, 12):
        return False
    d = [int(c) for c in digits]

    def check(weights):
        return sum(w * x for w, x in zip(weights, d, strict=False)) % 11 % 10  # весов меньше, чем цифр

    if len(d) == 10:
        return digits[:2] != "00" and check((2, 4, 10, 3, 5, 9, 4, 6, 8)) == d[9]
    return (check((7, 2, 4, 10, 3, 5, 9, 4, 6, 8)) == d[10]
            and check((3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)) == d[11])


def snils_ok(digits: str) -> bool:
    """СНИЛС: 11 цифр, контрольное число – по весам 9…1 (определено для номеров больше 001-001-998)."""
    if not digits.isdigit() or len(digits) != 11 or int(digits[:9]) <= 1001998:
        return False
    total = sum(int(c) * w for c, w in zip(digits[:9], range(9, 0, -1), strict=True))
    if total > 101:
        total %= 101
    return (0 if total in (100, 101) else total) == int(digits[9:])


def _phone_value(s: str) -> str:
    d = _digits(s)
    return "7" + d[1:] if d.startswith("8") else d  # 8 916 … и +7 916 … – один номер


def _mask_pii(text: str, masker: _Masker) -> str:
    text = _EMAIL.sub(lambda m: masker.placeholder("EMAIL", m.group(0).lower()), text)
    text = _PASSPORT.sub(lambda m: _splice(m, 1, masker.placeholder("PASSPORT", _digits(m.group(1)))), text)

    def snils_repl(m):
        value = _digits(m.group(0))
        return masker.placeholder("SNILS", value) if snils_ok(value) else m.group(0)

    text = _SNILS.sub(snils_repl, text)
    text = _PHONE.sub(lambda m: masker.placeholder("PHONE", _phone_value(m.group(0))), text)

    def inn_repl(m):
        return masker.placeholder("INN", m.group(1)) if inn_ok(m.group(1)) else m.group(0)

    return _INN.sub(inn_repl, text)


# ============================================================================ главная функция

def mask_text(text: str, key: bytes, *, env_style: bool = True) -> tuple[str, dict[str, int]]:
    """Маскирует секреты и ПДн в тексте; возвращает (текст, счётчики по типам: {"SECRET": 2, "EMAIL": 1}).

    key – ключ HMAC (bytes, не меньше 16 байт); номер плейсхолдера – первые 6 hex HMAC-SHA256 значения.
    env_style – строки вида КЛЮЧ=значение читаются как .env: значение скрывается целиком, даже если похоже на имя
    через точку. Для исходного кода (там DB_PASSWORD=settings.DB_PASSWORD – ссылка) передавать False.
    Число строк не меняется: каждая замена – внутри своей строки. Маскировать лучше весь файл, а уже потом вырезать
    срез: ключ PEM на границе среза или обрезанный длинный токен иначе не узнаются.
    """
    masker = _new_masker(key)
    text = str(text or "")
    text = _mask_secrets(text, masker, env_style)
    text = _mask_pii(text, masker)
    return text, _counts(masker.by_type)


# ============================================================================ находки о жёстко заданных секретах

# CWE жёстко заданных и открыто хранимых учётных данных и ключей.
CREDENTIAL_CWES = frozenset({"CWE-798", "CWE-259", "CWE-321", "CWE-522", "CWE-547", "CWE-256", "CWE-257",
                             "CWE-260", "CWE-312", "CWE-313", "CWE-314", "CWE-315", "CWE-316", "CWE-526", "CWE-555",
                             "CWE-615"})
_CREDENTIAL_RULE = re.compile(r"password|passwd|парол|secret|секрет|credential|учётн|учетн"
                              r"|private[\s_-]*key|закрыт\w*[\s_-]+ключ|api[\s_-]*key", re.I)
# «Жёстко заданный» сам по себе – не секрет: у правил вида hardcoded_sql_expressions (CWE-89),
# hardcoded_bind_all_interfaces, hardcoded_tmp_directory строка находки – SQL, адрес или путь, а не секрет.
# Секретом такую находку делает слово о ключе, токене или учётных данных рядом.
_HARDCODED_RULE = re.compile(r"hard[\s_-]*cod|жёстко|жестко", re.I)
_HARDCODED_SECRET_WORD = re.compile(r"key|ключ|token|токен|cred|pass|парол|secret|секрет", re.I)


def is_credential_finding(rule: str, cwe) -> bool:
    """Находка о секрете в коде: CWE из CREDENTIAL_CWES (cwe – строка или список); в названии правила password,
    пароль, secret, credential, private key, api key; или hardcoded / «жёстко заданный» вместе со словом о ключе,
    токене, пароле или учётных данных. У таких находок сама строка – секрет, и общего маскирования мало."""
    cwes = cwe if isinstance(cwe, (list, tuple, set)) else [cwe]
    if any(str(c or "").strip().upper() in CREDENTIAL_CWES for c in cwes):
        return True
    text = str(rule or "")
    if _CREDENTIAL_RULE.search(text):
        return True
    return bool(_HARDCODED_RULE.search(text) and _HARDCODED_SECRET_WORD.search(text))


def mask_line(line: str, key: bytes) -> tuple[str, int]:
    """Строка целиком -> отступ + <SECRET_n> (n – HMAC строки без отступа). -> (строка, замен 0 или 1).

    Уже стоящий плейсхолдер и пустая строка не трогаются."""
    masker = _new_masker(key)
    stripped = line.strip()
    if not stripped or PLACEHOLDER_RE.fullmatch(stripped):
        return line, 0
    cr = "\r" if line.endswith("\r") else ""
    return line[:_indent_width(line)] + masker.placeholder("SECRET", stripped) + cr, 1


def mask_all_literals(text: str, key: bytes) -> tuple[str, int]:
    """Все непустые строковые литералы "…", '…', `…` на одной строке -> "<SECRET_n>" (кроме уже стоящих
    плейсхолдеров); незакрытый литерал – до конца строки. -> (текст, замен). Для срезов находок о секретах:
    значения скрыты, устройство кода видно."""
    masker = _new_masker(key)

    def repl(m):
        opening, inner, closing = _literal_parts(m)
        if not inner.strip() or PLACEHOLDER_RE.fullmatch(inner):
            return m.group(0)
        return opening + masker.placeholder("SECRET", inner) + closing

    text = _LITERAL.sub(repl, str(text or ""))
    return text, masker.by_type["SECRET"]


# Конец текста перед литералом – присваивание ключу-секрету: password = , "api_key": , token := , secret =>;
# литерал бывает и на следующей строке после «=».
_ASSIGN_TAIL = re.compile(_KEY_START + r"[\"']?" + _KEY_NAME + r"[\"']?\]?[ \t]*" + _TYPE_HINT
                          + r"(?::=|=>|=|:)\s*"
                          # значение по умолчанию: password = process.env.DB_PASS || "…", os.getenv("X") or "…";
                          # в скобках – и на следующих строках: password = (\n os.getenv("X")\n or "…"\n)
                          # (внутри скобок допускаются вложенные вызовы вроде getenv("X"), но не закрывающая скобка
                          # самого присваивания: за ней уже другое выражение)
                          + r"(?:\(\s*(?:(?:[^;=()]|\([^;=()]{0,80}\)){0,160}?(?:\|\||\?\?|\?:|\bor\b)\s*)?"
                          + r"|[^;\r\n=]{0,80}?(?:\|\||\?\?|\?:|\bor\b)[ \t]*)?"
                          # обёртка значения: Some("…"), Optional.of("…"), String::from("…"), SecretStr("…")
                          + r"(?:(?:Some|Ok|Optional\.of|String::from|String\.valueOf|SecretStr|SecretString|Secret"
                          + r"|new[ \t]+String)\(\s*)?"
                          + r"[rRbBuUfF$@]{0,3}$", re.I)


_KEY_HINTS = ("pass", "pw", "secret", "token", "credential", "key", "пароль")  # быстрый отсев до регулярного выражения


def secret_assignment_before(prefix: str) -> bool:
    """Текст перед строковым литералом кончается присваиванием ключу со словом-секретом (между «=» и литералом –
    пробелы, переводы строк, скобка или значение по умолчанию через ||, ??, ?:, or). Смотрятся последние 200 знаков:
    на длинной минифицированной строке проверка не становится квадратичной."""
    prefix = prefix[-200:]
    low = prefix.lower()
    return any(hint in low for hint in _KEY_HINTS) and bool(_ASSIGN_TAIL.search(prefix))


# Начало литерала: префиксы строк Python, C++ (u8, L, R) и Rust (b, r, #), строки C# (@, $), затем кавычки.
_TOKEN_OPEN = re.compile(r"(?:u8|[uUL])?[rRbBuUfF]{0,2}(#*)(?:@\$?|\$@)?(\"\"\"|'''|[\"'`])")
_CPP_RAW_OPEN = re.compile(r"(?:u8|[uUL])?R\"([^()\\\s]{0,16})\(")


def mask_literal_token(token: str, key: bytes) -> str:
    """Строковый литерал целиком – с кавычками, возможно многострочный или незакрытый – -> кавычки на месте,
    каждая непустая строка содержимого – один и тот же плейсхолдер (номер – HMAC всего содержимого), переводы строк
    целы. Разделители сырых строк сохраняются: R"метка(…)метка" в C++, r#"…"# в Rust – иначе разбор кода дальше
    литерала сбился бы. Начало литерала не распознано – скрывается всё. Пустой литерал и уже стоящий плейсхолдер
    не трогаются. Для находок о секретах в коде."""
    masker = _new_masker(key)
    raw = _CPP_RAW_OPEN.match(token)
    m = _TOKEN_OPEN.match(token)
    if raw:
        opening, closing_mark = raw.group(0), ")" + raw.group(1) + '"'
    elif m:
        opening, closing_mark = m.group(0), m.group(2) + m.group(1)  # у Rust r#"…"# за кавычкой столько же «#»
    else:
        opening, closing_mark = "", ""
    body = token[len(opening):]
    closing = closing_mark if closing_mark and len(body) >= len(closing_mark) and body.endswith(closing_mark) else ""
    if closing:
        body = body[:-len(closing)]
    if not body.strip() or PLACEHOLDER_RE.fullmatch(body.strip()):
        return token
    parts = []
    for k, part in enumerate(body.split("\n")):
        if not part.strip():
            parts.append(part)
            continue
        cr = "\r" if part.endswith("\r") else ""
        indent = "" if k == 0 else part[:_indent_width(part)]
        parts.append(indent + masker.placeholder("SECRET", body) + cr)
    return opening + "\n".join(parts) + closing

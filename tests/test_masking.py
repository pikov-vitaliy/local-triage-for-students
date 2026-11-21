"""Маскирование секретов и ПДн: типы значений, номера HMAC, сохранность строк, ключ.

Все значения выдуманы. Валидные ИНН и СНИЛС генерируются своим кодом теста (не функциями модуля), плюс опорные
значения, проверенные вручную: ИНН 1234567894 и 123456789047, СНИЛС 112-233-445 95 (номера
последовательные, контрольные цифры посчитаны по правилам).
"""

from __future__ import annotations

import hashlib
import hmac
import random
import re
import threading
import time

import pytest

from app import masking as mk

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


def number(value: str, key: bytes = KEY) -> str:
    """Номер плейсхолдера, посчитанный в тесте независимо: первые 6 hex HMAC-SHA256."""
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:6]


def masked(text: str, key: bytes = KEY):
    return mk.mask_text(text, key)


# ---------------------------------------------------------------- генераторы валидных номеров (свой код теста)

def inn10(rnd):
    while True:
        d = [rnd.randint(0, 9) for _ in range(9)]
        if d[0] == 0 and d[1] == 0:
            continue
        s = sum(w * x for w, x in zip((2, 4, 10, 3, 5, 9, 4, 6, 8), d, strict=True))
        return "".join(map(str, d + [s % 11 % 10]))


def inn12(rnd):
    d = [rnd.randint(0, 9) for _ in range(10)]
    d.append(sum(w * x for w, x in zip((7, 2, 4, 10, 3, 5, 9, 4, 6, 8), d, strict=True)) % 11 % 10)
    d.append(sum(w * x for w, x in zip((3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8), d, strict=True)) % 11 % 10)
    return "".join(map(str, d))


def snils(rnd):
    while True:
        d = [rnd.randint(0, 9) for _ in range(9)]
        if int("".join(map(str, d))) > 1001998:
            break
    s = sum(x * w for x, w in zip(d, range(9, 0, -1), strict=True))
    if s < 100:
        check = s
    elif s in (100, 101):
        check = 0
    else:
        check = s % 101
        check = 0 if check == 100 else check
    return "".join(map(str, d)) + f"{check:02d}"


def flip_last(digits):
    return digits[:-1] + str((int(digits[-1]) + 1) % 10)


# ============================================================================ секреты

KEY_VALUE_CASES = [
    ('String password = "Secr3t!";', "Secr3t!"),
    ('"password": "Secr3t!",', "Secr3t!"),
    ("api_key: 'abcdef123456'", "abcdef123456"),
    ('pwd="hunter2"', "hunter2"),
    ('token := "tok_123"', "tok_123"),
    ("$config['db_password'] => 'p@ss';", "p@ss"),
    ('props.put("password", "Secr3t!");', "Secr3t!"),
    ("<password>Secr3t!</password>", "Secr3t!"),
    ('<add key="DbPassword" value="Secr3t!"/>', "Secr3t!"),
    ("spring.datasource.password=Secr3t!", "Secr3t!"),
    ("export API_KEY=abc123def", "abc123def"),
    ("  password: changeit   # только для стенда", "changeit"),
    ('String cs = "Server=x;Database=y;User Id=sa;Password=Secr3t;";', "Secr3t"),
    ('String u = "jdbc:mysql://h/db?user=root&password=Secr3t";', "Secr3t"),
    ('final String CLIENT_SECRET = "s3cr3t-value";', "s3cr3t-value"),
    ('ds.setPassword("Qw3rty!2024");', "Qw3rty!2024"),
    ('DriverManager.getConnection(url, "sa", "Qw3rty!2024");', "Qw3rty!2024"),
    ('if (password.equals("Qw3rty!2024")) {', "Qw3rty!2024"),
    ('if ("Qw3rty!2024".equals(user.getPassword())) {', "Qw3rty!2024"),
    ('val password: String = "Qw3rty!2024"', "Qw3rty!2024"),
]


@pytest.mark.parametrize("text, secret", KEY_VALUE_CASES)
def test_key_value_forms(text, secret):
    out, counts = masked(text)
    assert secret not in out
    assert counts == {"SECRET": 1}
    assert out.count("\n") == text.count("\n")


MULTILINE_CASES = [
    ("spring:\n  datasource:\n    password: |\n      Qw3rty!2024\n", "Qw3rty!2024"),
    ("secrets:\n  - Qw3rty!2024\n", "Qw3rty!2024"),
    ("env:\n  - name: DB_PASSWORD\n    value: Qw3rty!2024\n", "Qw3rty!2024"),
    ("PASSWORD=Qw3rty!2024;\n", "Qw3rty!2024"),
    ("mysql -u root -pQw3rty!2024 app < dump.sql\n", "Qw3rty!2024"),
    ("curl -u admin:Qw3rty!2024 https://ci.example.invalid/api\n", "Qw3rty!2024"),
    ("<property>\n  <name>db.password</name>\n  <value>Qw3rty!2024</value>\n</property>", "Qw3rty!2024"),
    ("ENV POSTGRES_PASSWORD Qw3rty!2024\n", "Qw3rty!2024"),
    ("пароль: Qw3rty!2024\n", "Qw3rty!2024"),
    ('url = "postgres://app:p@ss@db.local/app"', "p@ss"),
    ("JWT_SIGNING_KEY=8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c\n", "8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c"),
    ("// old key: 5f4dcc3b5aa765d61d8327deb882cf99a1b2c3d4\n", "5f4dcc3b5aa765d61d8327deb882cf99"),
]


@pytest.mark.parametrize("text, secret", MULTILINE_CASES)
def test_config_and_cli_forms(text, secret):
    out, counts = masked(text)
    assert secret not in out
    assert counts.get("SECRET", 0) >= 1
    assert out.count("\n") == text.count("\n"), "число строк не меняется"


@pytest.mark.parametrize("text, secret", [
    ('password = "' + "demo-secret-" * 50 + '";', "demo-secret-"),
    ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
    ("Authorization: Basic dXNlcjpwYXNzdXNlcjpwYXNz", "dXNlcjpwYXNzdXNlcjpwYXNz"),
    ('headers = {"Authorization": "Bearer abcdefghijklmnop"}', "abcdefghijklmnop"),
    ('req.setHeader("Authorization", "Basic dXNlcjpwYXNzdXNlcjpwYXNz");', "dXNlcjpwYXNzdXNlcjpwYXNz"),
    ("DB_PASSWORD=demo.password.value\n", "demo.password.value"),
    ('password = """\ndemo-secret-value\n"""\n', "demo-secret-value"),
    ("const token = `\n  demo-template-secret\n`;", "demo-template-secret"),
    ("password = &quot;demo-secret-value&quot;;", "demo-secret-value"),
])
def test_explicit_secrets_without_entropy(text, secret):
    out, counts = masked(text)
    assert secret not in out
    assert counts.get("SECRET", 0) >= 1
    assert out.count("\n") == text.count("\n"), "число строк не меняется"


@pytest.mark.parametrize("line", [
    'headers.put("Authorization", basicAuth);',
    'String auth = request.getHeader("Authorization");',
    "api_key = settings.API_KEY",
])
def test_authorization_and_references_in_code_stay(line):
    assert masked(line) == (line, {})


def test_pathological_inputs_are_linear():
    cases = ['\\"' * 40_000, "'a" * 40_000, '"' * 80_000, "password: |\n" + "  demo-low-entropy-value\n" * 40_000,
             "x.equals(" + '"a", ' * 20_000 + ")", '"' + "a" * 200_000]
    for text in cases:
        started = time.monotonic()
        masked(text)
        assert time.monotonic() - started < 3.0, text[:20]


def test_yaml_block_one_number_for_all_lines():
    out, counts = masked("db:\n  password: |\n    line-one-value\n    line-two-value\n  url: jdbc:h2:mem\n")
    lines = out.split("\n")
    assert lines[2].strip() == lines[3].strip() and lines[2].strip().startswith("<SECRET_")
    assert counts == {"SECRET": 2} and lines[4] == "  url: jdbc:h2:mem"


def test_mask_literal_token():
    multi = mk.mask_literal_token('"""\n    secret-one\n    second\n"""', KEY)
    assert multi.startswith('"""\n    <SECRET_') and multi.endswith('\n"""') and multi.count("\n") == 3
    assert "secret-one" not in multi and len(set(re.findall(r"<SECRET_\w+>", multi))) == 1
    assert re.fullmatch(r'r"<SECRET_[0-9a-f]{6}>"', mk.mask_literal_token('r"abc"', KEY))
    assert re.fullmatch(r'"<SECRET_[0-9a-f]{6}>', mk.mask_literal_token('"unterminated', KEY))
    assert re.fullmatch(r'@"<SECRET_[0-9a-f]{6}>"', mk.mask_literal_token('@"C:\\path"', KEY))
    assert mk.mask_literal_token('""', KEY) == '""'
    assert re.fullmatch(r"<SECRET_[0-9a-f]{6}>", mk.mask_literal_token("plain", KEY)), "начало не узнано – скрыть всё"
    raw_cpp = mk.mask_literal_token('u8R"tag(\n"//\ndemo-raw\n)tag"', KEY)
    assert "demo-raw" not in raw_cpp and raw_cpp.count("\n") == 3 and raw_cpp.startswith('u8R"')
    assert "demo-raw" not in mk.mask_literal_token('r#"head"//demo-raw"#', KEY)


@pytest.mark.parametrize("text, secret", [
    ("const token = `head\\`demo-hidden-tail`;\nrun();", "demo-hidden-tail"),
    ('password = """head\\"""\ndemo-triple-secret\n"""\n', "demo-triple-secret"),
    ("DB_PASSWORD=demo.password.value # комментарий\n", "demo.password.value"),
    ("password = &quot;demo&amp;secret&quot;;", "demo&amp;secret"),
    ("{&quot;password&quot;: &quot;demo-secret-value&quot;}", "demo-secret-value"),
    ("Authorization: Bearer abcdefg", "abcdefg"),
    ('Authorization: Digest username="demo-user", realm="demo", nonce="demo-nonce", response="demo-response"',
     "demo-response"),
    ('password = r"demo-secret-value"', "demo-secret-value"),
    ('password = "demo-unterminated\nnext()', "demo-unterminated"),
    ('password = "' + "z." * 2001 + '";', "z.z.z."),
])
def test_secret_forms_edge_cases(text, secret):
    out, counts = masked(text)
    assert secret not in out
    assert counts.get("SECRET", 0) >= 1
    assert out.count("\n") == text.count("\n")


def test_raw_literal_delimiters_kept():
    rust = mk.mask_literal_token('r#"raw-value"#', KEY)
    assert re.fullmatch(r'r#"<SECRET_[0-9a-f]{6}>"#', rust), rust
    cpp = mk.mask_literal_token('R"tag(head"//tail)tag"', KEY)
    assert re.fullmatch(r'R"tag\(<SECRET_[0-9a-f]{6}>\)tag"', cpp), cpp
    assert "tail" not in cpp


@pytest.mark.parametrize("text, secret", [
    ("password = '\"secret-value'\n", '"secret-value'),
    ('password = """\n' + "a" * 4501 + "\nLEAK\\", "LEAK"),
    ("password = 'demo\"secret-value'\nprint(1)\n", 'demo"secret-value'),
    ('password = "' + "a" * 4001 + '\\"demo-escaped-tail"\n', "demo-escaped-tail"),
    ("Authorization: Digest " + "a" * 4000 + ", response=demo-digest-secret", "demo-digest-secret"),
    ('token = """\n' + ("x" * 100 + "\n") * 60 + 'demo-block-tail\n"""\n', "demo-block-tail"),
    ('password = """\ndemo-unterminated-block\n', "demo-unterminated-block"),
])
def test_long_and_mixed_quote_values(text, secret):
    out, counts = masked(text)
    assert secret not in out
    assert out.count("\n") == text.count("\n")


def test_huge_rule_keeps_minified_code():
    text = '{password:"abc",user:"' + "u" * 10_000 + '"}'
    out, counts = masked(text)
    assert "abc" not in out and out.count("u") >= 10_000 and counts == {"SECRET": 1}


def test_secret_assignment_before():
    for prefix in ("password = ", 'cfg["api_key"]: ', "    let password = ", "DB_TOKEN := ", "password = r",
                   "x = 1\n  secret => ", "password = (\n    ", "let token: &'static str = ", "string password = $",
                   "password: process.env.DB_PASS || ", 'password = os.getenv("DB_PASSWORD") or ',
                   "val token = System.getenv(\"T\") ?: ", 'password = (\n    os.getenv("X")\n    or ',
                   "let token: Option<&str> = Some(", "String password = new String(", "token = SecretStr("):
        assert mk.secret_assignment_before(prefix), prefix
    for prefix in ("print(", 'log.info("password = " + ', "password == ", "name = ",
                   "API_KEY = System.getenv(", "password = os.getenv(", "password = get()\nprint(x or ",
                   'token = request.getParameter(', 'password = (\n    os.getenv("DB_PASSWORD")\n)\nprint(value or '):
        assert not mk.secret_assignment_before(prefix), prefix


def test_env_style_switch():
    line = "DB_PASSWORD=settings.DB_PASSWORD"
    assert mk.mask_text(line, KEY, env_style=False) == (line, {}), "в исходном коде это ссылка на настройку"
    assert "settings.DB_PASSWORD" not in masked(line)[0], "по умолчанию строка читается как .env"


@pytest.mark.parametrize("line", [
    'log.info("password = " + pwd);',
    'String q = "UPDATE users SET password = \'" + pwd + "\' WHERE id = 1";',
    "Authorization: Bearer",
])
def test_open_value_rules_keep_code(line):
    assert masked(line)[0] == line


def test_placeholder_is_hmac_of_value():
    out, _ = masked('String password = "Secr3t!";')
    assert out == f'String password = "<SECRET_{number("Secr3t!")}>";'


def test_url_credentials():
    out, _ = masked('url = "postgres://admin:S3cr3t@db.local:5432/app"')
    assert "S3cr3t" not in out and "admin" not in out
    assert "postgres://<SECRET_" in out and "@db.local:5432/app" in out, "хост и порт остаются"


@pytest.mark.parametrize("token", [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "glpat-" + "abcdefghij1234567890",
    "xoxb-" + "1234567890-abcdefghij",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
])
def test_known_token_formats(token):
    out, counts = masked(f"x = {token};")
    assert out == f"x = <SECRET_{number(token)}>;"
    assert counts == {"SECRET": 1}


def test_bearer_and_entropy():
    assert "abc123def456ghi789jkl" not in masked('h.set("Authorization", "Bearer abc123def456ghi789jkl")')[0]
    assert masked("Basic HttpAuthenticationFilter is used")[1] == {}, "слово без цифр – не токен"
    assert "q8Zr4LmN2pXv7TbK9sWd3YhJ6cFg1Rn5" not in masked('k = "q8Zr4LmN2pXv7TbK9sWd3YhJ6cFg1Rn5";')[0]
    for text in ["q8Zr4LmN2pXv7TbK9sWd3YhJ6cFg1Rn5 = 1", 'n = "applicationContextConfigLocation2File"']:
        assert masked(text)[0] == text, "вне литерала и с низкой энтропией – не трогается"
    rnd = random.Random(5)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    hits = sum(masked('"' + "".join(rnd.choice(alphabet) for _ in range(40)) + '"')[1].get("SECRET", 0)
               for _ in range(300))
    assert hits >= 294, "случайные ключи из 40 знаков узнаются почти всегда"


def test_pem_private_key_keeps_lines():
    body = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u"
    files = [
        f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n{body[::-1]}\n-----END RSA PRIVATE KEY-----\nnext\n",
        f'key = "-----BEGIN PRIVATE KEY-----\\n" +\n  "{body}\\n" +\n  "-----END PRIVATE KEY-----";\nnext();',
        f"-----BEGIN RSA PRIVATE KEY-----\n{body[:64]}\n",  # обрезанный ключ без END
    ]
    for text in files:
        out, counts = masked(text)
        assert body[:16] not in out
        assert out.count("\n") == text.count("\n")
        assert "PRIVATE KEY-----" in out, "маркеры ключа остаются: видно, что здесь ключ"
        assert counts["SECRET"] >= 1
        assert len(set(re.findall(r"<SECRET_\w+>", out))) == 1, "весь ключ – один номер"
    code = 'String BEGIN = "-----BEGIN PRIVATE KEY-----";\nString END = "-----END PRIVATE KEY-----";'
    assert masked(code)[0] == code, "код, который ищет маркеры, не трогается"


@pytest.mark.parametrize("line", [
    'String sql = "SELECT * FROM USERS WHERE USERNAME = \'" + user + "\' AND PASSWORD = \'" + pwd + "\'";',
    'String q = "UPDATE users SET password = ? WHERE id = ?";',
    'Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding", "SunJCE");',
    'String password = request.getParameter("password");',
    "if (password == null) return;",
    "password = getPassword();",
    "this.password = password;",
    "token: str",
    "token = None",
    "api_key = settings.API_KEY",
    '@WebServlet(value = "/files-01/DownloadServlet01")',
    'final String TOKEN_HEADER = "${jwt.header}";',
    'String pwd = "%s";',
    "PrintWriter pw = new PrintWriter(out);",
    'String v = props.getProperty("password");',
    "long ts = 1696000000L; double d = 0.1234567890; int big = 12345678901234;",
    "ИНН неверный 1234567895, СНИЛС неверный 112-233-445 96",
])
def test_code_stays_intact(line):
    assert masked(line) == (line, {}), "строки, важные для разбора, не маскируются"


def test_long_lines_are_fast():
    rnd = random.Random(1)
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    keys = ["auth.token.expired", "auth.password.reset", "user.secret.question", "api.key.missing"]
    texts = ['const blob = "' + "".join(rnd.choice(alpha) for _ in range(300_000)) + '";',
             'var x = "' + "a." * 20_000 + '";', 'm("' + ".".join(rnd.choice(keys) for _ in range(8000)) + '")',
             'x = "' + "a_token_b." * 4000 + '"', "x = " + "pwd" * 8000]
    for text in texts:
        started = time.monotonic()
        masked(text)
        assert time.monotonic() - started < 2.0, text[:40]


# ============================================================================ ПДн

def test_pii_anchor_values():
    assert mk.inn_ok("1234567894") and mk.inn_ok("123456789047")
    assert mk.snils_ok("11223344595")
    assert not mk.inn_ok("1234567895") and not mk.inn_ok("123456789048")
    assert not mk.snils_ok("11223344596")
    assert not mk.snils_ok("00100199800"), "номера до 001-001-998 контрольным числом не проверяются"


def test_generated_inn_and_snils():
    rnd = random.Random(2026)
    for _ in range(100):
        for kind, value in (("INN", inn10(rnd)), ("INN", inn12(rnd)), ("SNILS", snils(rnd))):
            texts = [f"ИНН/СНИЛС: {value}.", f"x = {value};"]
            if kind == "SNILS":
                texts.append(f"СНИЛС {value[:3]}-{value[3:6]}-{value[6:9]} {value[9:]}")
            for text in texts:
                out, counts = masked(text)
                assert out.count(f"<{kind}_{number(value)}>") == 1, text
                assert counts == {kind: 1}, text
            assert f"<{kind}_" not in masked(f"x = {flip_last(value)};")[0], "неверная контрольная цифра – не ПДн"


def test_phone_email_passport():
    out, counts = masked("тел. +7 (916) 123-45-67, 8 916 123 45 67, 89161234567, +79161234567")
    ph = f"<PHONE_{number('79161234567')}>"
    assert out == f"тел. {ph}, {ph}, {ph}, {ph}"
    assert counts == {"PHONE": 4}
    assert masked("id 891612345678")[0] == "id 891612345678", "12 цифр – не телефон"
    out, counts = masked("mail: Ivan.Petrov@Example.org; repo git@example.com")
    assert out == f"mail: <EMAIL_{number('ivan.petrov@example.org')}>; repo <EMAIL_{number('git@example.com')}>"
    assert counts == {"EMAIL": 2}
    for text in ["@Override", "{@link Foo}", "node_modules/@types/node", "user@localhost"]:
        assert masked(text)[0] == text
    for text in ["Паспорт серии 45 10 № 123456", "паспорт: 4510123456", "passport 4510 123456"]:
        out, counts = masked(text)
        assert f"<PASSPORT_{number('4510123456')}>" in out, text
        assert counts == {"PASSPORT": 1}
    assert "PASSPORT" not in masked("серия 45 10 номер 123456")[0]
    assert masked("ivan1234567894@example.org")[1] == {"EMAIL": 1}, "цифры адреса не уходят в ИНН"


# ============================================================================ свойства маскирования

SAMPLE = "\n".join([
    "public class Demo {",
    '    private static final String DB_PASSWORD = "Secr3t!";',
    "    // владелец: ivan.petrov@example.org, тел. +7 916 123-45-67",
    '    String url = "postgres://admin:S3cr3t@db.local/app";',
    '    String inn = "1234567894";',
    "    void run(String user) {",
    '        String sql = "SELECT * FROM t WHERE name = \'" + user + "\'";',
    "    }",
    "}",
    "",
])


def test_line_count_and_unchanged_lines():
    for text in (SAMPLE, SAMPLE.replace("\n", "\r\n")):
        out, counts = masked(text)
        src, dst = text.split("\n"), out.split("\n")
        assert len(src) == len(dst)
        changed = [n for n, (a, b) in enumerate(zip(src, dst, strict=True), 1) if a != b]
        assert changed == [2, 3, 4, 5], "только строки с секретами"
        assert all(a.endswith("\r") == b.endswith("\r") for a, b in zip(src, dst, strict=True)), "CR остаётся"
        assert counts == {"SECRET": 2, "EMAIL": 1, "PHONE": 1, "INN": 1}


def test_numbers_stable_keyed_and_idempotent():
    out1, _ = masked(SAMPLE)
    assert masked(SAMPLE)[0] == out1, "тот же ключ – те же номера"
    again, counts = masked('password = "Secr3t!"; token = "Secr3t!"; secret = "Other1!"')
    values = [again.split('"')[i] for i in (1, 3, 5)]
    assert values[0] == values[1] != values[2], "одинаковые значения – один номер"
    assert counts == {"SECRET": 3}
    other, _ = mk.mask_text(SAMPLE, OTHER_KEY)
    assert other != out1 and other.count("<") == out1.count("<"), "другой ключ – другие номера"
    assert masked(out1) == (out1, {}), "повторное маскирование ничего не меняет"
    assert mk.count_placeholders(out1) == masked(SAMPLE)[1]


def test_bad_key():
    with pytest.raises(ValueError):
        mk.mask_text("x", b"short")
    with pytest.raises(ValueError):
        mk.mask_text("x", "строка вместо байтов")


# ============================================================================ находки о секретах

def test_is_credential_finding():
    for rule, cwe in (("", "CWE-798"), ("x", ["CWE-89", "cwe-259"]), ("Hardcoded password", []),
                      ("Жёстко заданный ключ", ""), ("Пароль в исходном коде", ["CWE-259"]),
                      ("Hard-coded API key", ""), ("Hardcoded token", ""), ("Жёстко заданный токен", "")):
        assert mk.is_credential_finding(rule, cwe), (rule, cwe)
    for rule, cwe in (("Внедрение SQL-кода", ["CWE-89"]), ("Missing CSRF token", "CWE-352"), ("", []),
                      ("hardcoded_sql_expressions", "CWE-89"), ("hardcoded_tmp_directory", "CWE-377"),
                      ("Жёстко заданный путь", "")):
        assert not mk.is_credential_finding(rule, cwe), (rule, cwe)


def test_mask_line_and_literals():
    line, n = mk.mask_line('        ds.setPassword(secret + "x");\r', KEY)
    assert re.fullmatch(r"        <SECRET_[0-9a-f]{6}>\r", line) and n == 1
    assert mk.mask_line("   ", KEY) == ("   ", 0)
    text, n = mk.mask_all_literals('log("вход"); String s = \'\'; x = "<SECRET_abcdef>";', KEY)
    assert re.fullmatch(r'log\("<SECRET_[0-9a-f]{6}>"\); String s = \'\'; x = "<SECRET_abcdef>";', text)
    assert n == 1


# ============================================================================ ключ

def test_key_created_once(tmp_path):
    path = tmp_path / "data" / "mask.key"
    key = mk.load_or_create_key(path)
    assert len(key) == 32 and path.read_bytes() == key
    assert mk.load_or_create_key(path) == key, "ключ не пересоздаётся"
    path.write_bytes(b"x" * 10)
    with pytest.raises(ValueError, match="повреждён"):
        mk.load_or_create_key(path)


def test_key_created_once_from_threads(tmp_path):
    path = tmp_path / "mask.key"
    keys, errors = [], []

    def worker():
        try:
            keys.append(mk.load_or_create_key(path))
        except Exception as e:  # pragma: no cover – в отчёт теста
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(set(keys)) == 1 and keys[0] == path.read_bytes()

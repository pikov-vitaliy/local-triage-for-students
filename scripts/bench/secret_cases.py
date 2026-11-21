"""Выдуманные случаи CWE-259 / CWE-798 для стенда меток маскирования (бэклог 101, план dev18).

Зачем: модель может принять метку маскирования `<SECRET_…>` за сам секрет (строка, где токену присваивается
пустая строка, получает «истинную»). Набор проверяет, как модель судит о находках о паролях в коде, когда строки в
кавычках заменены метками, – в обе стороны: настоящий пароль в коде (истинная) и строка, похожая на секрет только
именем или видом (ложная).

Код выдуман целиком, совпадения с чужими проектами случайны. Файлы пишутся в папку набора (results/bench/secrets, вне
репозитория) – как клоны OWASP Benchmark; в репозитории лежит только этот текст. Строка срабатывания – по маркеру
`# >>>` / `// >>>` в конце строки: маркер из файла убирается, номер строки запоминается.
"""

from __future__ import annotations

from pathlib import Path

CODEBASE = "bench-secrets"
RULES = {
    "CWE-259": "Использование жестко закодированного пароля",
    "CWE-798": "Использование жестко закодированных учётных данных",
}
MARK = ">>>"

# (id, файл, язык, CWE, ожидаемый ответ, пояснение, текст файла с маркером строки срабатывания)
CASES: list[tuple[str, str, str, str, str, str, str]] = [
    ("sec-01", "src/store/session.js", "JavaScript/TypeScript", "CWE-259", "false_positive",
     "токену присваивается пустая строка при выходе – значения пароля нет",
     """import api from './api'

export default {
  mutations: {
    setTokens(state, {accessToken}) {
      state.accessToken = accessToken
    }
  },
  actions: {
    async logout({commit}) {
      await api.get('auth/logout')
      commit('setTokens', {accessToken: ''}) // >>>
      window.location.href = '/login'
    }
  }
}
"""),
    ("sec-02", "src/config/db.js", "JavaScript/TypeScript", "CWE-259", "true_positive",
     "пароль базы задан строкой в коде и уходит в подключение",
     """const { Pool } = require('pg')

const pool = new Pool({
  host: 'db.internal',
  user: 'billing',
  password: 'Wint3r-Is-C0ming!', // >>>
  database: 'billing'
})

module.exports = pool
"""),
    ("sec-03", "app/settings.py", "Python", "CWE-798", "false_positive",
     "значение берётся из переменной окружения, в коде только имя переменной",
     """import os

DATABASE = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "app"),
    "password": os.environ["DB_PASSWORD"],  # >>>
}
"""),
    ("sec-04", "app/notify.py", "Python", "CWE-798", "true_positive",
     "ключ API сервиса рассылки записан строкой и отправляется в заголовке",
     """import requests

API_KEY = "sk_""" """live_51Hc0ffee9a8b7c6d5e4f3a2b1"  # >>>


def send(to: str, text: str) -> None:
    requests.post("https://mail.example.org/v1/send", headers={"Authorization": f"Bearer {API_KEY}"},
                  json={"to": to, "text": text}, timeout=10)
"""),
    ("sec-05", "src/main/java/org/example/auth/LoginForm.java", "Java", "CWE-259", "false_positive",
     "строка – подпись поля формы, а не пароль",
     """package org.example.auth;

public class LoginForm {
    public static final String USER_LABEL = "Имя пользователя";
    public static final String PASSWORD_LABEL = "Пароль"; // >>>

    private String user;
    private String password;

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}
"""),
    ("sec-06", "src/main/java/org/example/auth/AdminAccess.java", "Java", "CWE-259", "true_positive",
     "введённый пароль сравнивается со строкой в коде – вход администратора по постоянному паролю",
     """package org.example.auth;

public class AdminAccess {
    public boolean allow(String user, String password) {
        if ("admin".equals(user) && "Adm1n#2024".equals(password)) { // >>>
            return true;
        }
        return false;
    }
}
"""),
    ("sec-07", "src/api/client.ts", "JavaScript/TypeScript", "CWE-798", "false_positive",
     "имя заголовка и имя ключа хранилища – не учётные данные",
     """const TOKEN_KEY = 'auth_token' // >>>

export function authHeaders(): Record<string, string> {
  const token = localStorage.getItem(TOKEN_KEY)
  return token ? { Authorization: `Bearer ${token}` } : {}
}
"""),
    ("sec-08", "src/api/legacy.ts", "JavaScript/TypeScript", "CWE-798", "true_positive",
     "логин и пароль сервисной учётки записаны строкой и уходят в Basic-авторизацию",
     """const SERVICE_USER = 'report-bot'
const SERVICE_PASSWORD = 'r3p0rt-b0t-2024' // >>>

export async function fetchReport(id: string): Promise<Response> {
  const basic = btoa(`${SERVICE_USER}:${SERVICE_PASSWORD}`)
  return fetch(`https://reports.example.org/api/${id}`, { headers: { Authorization: `Basic ${basic}` } })
}
"""),
    ("sec-09", "app/tests_fixtures.py", "Python", "CWE-259", "uncertain",
     "пароль тестового пользователя в фикстуре: опасен, только если фикстура попадает в рабочую сборку",
     """import pytest


@pytest.fixture
def demo_user(db):
    return db.create_user(login="demo", password="demo-pass-1")  # >>>
"""),
    ("sec-10", "app/crypto.py", "Python", "CWE-798", "true_positive",
     "ключ шифрования задан строкой в коде",
     """from cryptography.fernet import Fernet

KEY = b"q8dZ3l0n6oV9cXk2Yt4Hj7Wm1Ps5Rb0EaUfGiNe=" # >>>
cipher = Fernet(KEY)


def seal(data: bytes) -> bytes:
    return cipher.encrypt(data)
"""),
    ("sec-11", "src/main/java/org/example/config/Defaults.java", "Java", "CWE-259", "false_positive",
     "константа – имя параметра настройки, значение читается из настроек",
     """package org.example.config;

import java.util.Properties;

public class Defaults {
    public static final String PASSWORD_PROPERTY = "app.datasource.password"; // >>>

    public static String password(Properties props) {
        return props.getProperty(PASSWORD_PROPERTY);
    }
}
"""),
    ("sec-12", "src/store/reset.js", "JavaScript/TypeScript", "CWE-259", "false_positive",
     "поле пароля в форме очищается – присваивается пустая строка",
     """export function resetForm(form) {
  form.login = ''
  form.password = '' // >>>
  form.errors = []
}
"""),
]


def write_cases(root: Path) -> list[dict]:
    """Файлы набора – в root/<CODEBASE>; возвращает случаи в формате cases.json (как demo_cases)."""
    repo = root / CODEBASE
    cases = []
    for case_id, rel, language, cwe, expected, why, text in CASES:
        lines = text.split("\n")
        marked = [n for n, line in enumerate(lines, 1) if line.rstrip().endswith(MARK)]
        if len(marked) != 1:
            raise ValueError(f"{case_id}: строка срабатывания должна быть одна")
        line_no = marked[0]
        clean = lines[line_no - 1].rstrip()
        for prefix in (" // " + MARK, "  # " + MARK, " # " + MARK):
            if clean.endswith(prefix):
                clean = clean[: -len(prefix)]
                break
        lines[line_no - 1] = clean
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
        cases.append({
            "id": case_id, "source": "secrets", "category": "secrets", "cwe": cwe, "rule": RULES[cwe],
            "language": language, "repo_root": repo.as_posix(), "file": rel, "line": line_no,
            "snippet": clean.strip(), "expected": expected, "how_line": "export", "also_ok": [],
            "expected_note": why, "depends_on": None, "hint_comment": False, "hint_comments": [],
            "sink_pattern": None, "codebase": CODEBASE, "hub_file": None,
        })
    return cases

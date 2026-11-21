"""Срез кода: границы корня и репозитория, поиск файла, статусы, объемлющий метод, сверка строки из выгрузки,
маскирование, демо-выгрузка.

Тексты кода ниже – образцы для разбора: они только читаются как строки и никогда не исполняются.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from app import context as ctx
from app.context import mask_source_text  # noqa: E402
from app.context import EXPORT_LINE_CHECK_VERSION, build_context, enclosing_of, find_file, resolve_repo
from app.hub_import import parse_workbook
from app.models import CodeContext, Finding

ROOT = Path(__file__).resolve().parent.parent
NUMBERED = re.compile(r"^(>>|  ) *(\d+)\| ")


def line_of(text: str, marker: str) -> int:
    for n, line in enumerate(text.split("\n"), start=1):
        if marker in line:
            return n
    raise ValueError(marker)


ACCOUNT_JAVA = "\n".join([
    "package org.example.account;",
    "",
    "import java.sql.*;",
    "",
    "/** Вход в кабинет. */",
    "public class AccountServlet {",
    '    private static final String DB_PASSWORD = "Demo-Secret-Value-1";',
    "    // ответственный: ivan.petrov@example.org",
    "",
    "    @Override",
    "    public void doPost(HttpServletRequest request,",
    "                       HttpServletResponse response) throws IOException {",
    '        String user = request.getParameter("user"); // SOURCE',
] + [f"        int filler{i} = {i}; // {{ скобка в комментарии" for i in range(14, 34)] + [
    "        String sql = \"SELECT * FROM t WHERE name = '\" + user + \"' AND s = '}'\";",
    "        stmt.executeQuery(sql); // SINK",
    "        Runnable r = new Runnable() {",
    "            public void run() {",
    "                log(user); // INNER",
    "            }",
    "        };",
    "        list.forEach(x -> {",
    "            exec(x); // LAMBDA",
    "        });",
    "    }",
    "",
    "    private class Inner {",
    "        String field = compute(); // FIELD",
    "        String helper(String a) {",
    "            return a; // HELPER",
    "        }",
    "    }",
    "}",
    "",
])

VIEWS_PY = '''import os


def handler(request,
            name):
    """Документация с отступом
не по коду
    """
    cmd = "ls " + name
    os.system(cmd)  # PY-SINK


class View:
    level = os.getenv("X")  # PY-CLASS-LEVEL

    async def get(self, q):
        return q  # PY-METHOD
'''

APP_JS = """const express = require('express');
const app = express();
app.get('/users', (req, res) => {
  const q = req.query.q; // "{" в комментарии
  if (q) {
    db.query("SELECT * FROM u WHERE n = '" + q + "'"); // JS-SINK
  }
});
function helper(a, b) {
  return eval(a); // JS-HELPER
}
"""

SVC_CS = """namespace App {
    public class Svc : Base {
        public Svc(int a) : base(a) {
            Run(a); // CS-CTOR
        }
        [HttpGet("x/{id}")]
        public async Task<IActionResult> Get(int id) {
            var r = Task.Run(() => {
                return Query(id); // CS-LAMBDA
            });
            return Ok(r);
        }
    }
}
"""

MAIN_GO = """package main

func (s *Server) Handle(w http.ResponseWriter, r *http.Request) {
	if err != nil {
		exec.Command(r.URL.Query().Get("c")) // GO-SINK
	}
}
"""

ACCOUNT = "src/main/java/org/example/account/AccountServlet.java"


def write(root: Path, rel: str, text: str, encoding: str = "utf-8") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode(encoding))
    return path


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repos" / "billing-core"
    write(root, ACCOUNT, ACCOUNT_JAVA)
    write(root, "app/views.py", VIEWS_PY)
    write(root, "lib/x/Util.java", "class Util {}\n")
    write(root, "lib/y/Util.java", "class Util {}\n")
    write(root, "node_modules/p/Hidden.java", "class Hidden {}\n")
    return root


def finding(file: str, line: int | None, snippet: str = "", rule: str = "Внедрение SQL-кода",
            cwe=("CWE-89",)) -> Finding:
    return Finding(hub_id="510001", kind="SAST", rule=rule, cwe=list(cwe), file=file, line=line, snippet=snippet,
                   language="Java")


def make_link(link: Path, target: Path) -> bool:
    """Символическая ссылка на папку; на Windows без прав – точка соединения. Нельзя ни так, ни так – False."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        try:
            import _winapi
            _winapi.CreateJunction(str(target), str(link))
            return True
        except (OSError, ImportError, AttributeError):
            return False
    return False


# ============================================================================ границы корня

@pytest.mark.parametrize("folder", ["..", "..\\x", "a/../../x", "a/..", "C:/x", "C:x", "c:\\x", "\\\\srv\\share",
                                    "//srv/share", "/etc", "\\etc", "a\x00b", "a\nb", "a:b"])
def test_resolve_repo_refuses_escape(tmp_path, folder):
    with pytest.raises(ValueError):
        resolve_repo(tmp_path, folder)


def test_resolve_repo_inside(tmp_path):
    (tmp_path / "group" / "app").mkdir(parents=True)
    root = Path(os.path.realpath(tmp_path))
    assert resolve_repo(tmp_path, "group/app") == root / "group" / "app"
    assert resolve_repo(tmp_path, "group\\app") == root / "group" / "app"
    assert resolve_repo(tmp_path, "./group/./app/") == root / "group" / "app"
    assert resolve_repo(tmp_path, "") == root
    assert resolve_repo(tmp_path, "not-yet-cloned") == root / "not-yet-cloned", "существование не проверяется"


def test_resolve_repo_refuses_link_out_of_root(tmp_path):
    root, outside = tmp_path / "repos", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    if not make_link(root / "escape", outside):
        pytest.skip("нельзя создать ни символическую ссылку, ни точку соединения")
    with pytest.raises(ValueError, match="за пределы"):
        resolve_repo(root, "escape")
    (root / "real").mkdir()
    if make_link(root / "inner", root / "real"):
        assert resolve_repo(root, "inner") == Path(os.path.realpath(root / "real")), "ссылка внутри корня – можно"


# ============================================================================ поиск файла

def test_find_file(repo):
    real = Path(os.path.realpath(repo))
    assert find_file(repo, ACCOUNT) == real / ACCOUNT
    assert find_file(repo, "/builds/ci/billing-core/" + ACCOUNT) == real / ACCOUNT, "начало пути из Hub отброшено"
    assert find_file(repo, "billing-core\\" + ACCOUNT.replace("/", "\\")) == real / ACCOUNT
    assert find_file(repo, "java/org/example/account/AccountServlet.java") == real / ACCOUNT, "по окончанию пути"
    assert find_file(repo, "C:/ci/work/" + ACCOUNT) == real / ACCOUNT
    assert find_file(repo, "AccountServlet.java") == real / ACCOUNT, "единственный файл с таким именем"
    assert find_file(repo, "Util.java") is None, "два файла с таким окончанием – неоднозначно"
    assert find_file(repo, "x/Util.java") == real / "lib/x/Util.java"
    assert find_file(repo, "p/Hidden.java") is None, "node_modules не обходится"
    assert find_file(repo, "../billing-core/" + ACCOUNT) == real / ACCOUNT, "«..» не выводит из репозитория"
    assert find_file(repo, "") is None
    assert find_file(repo, "src/Missing.java") is None
    assert find_file(repo.parent / "nope", ACCOUNT) is None


def test_find_file_refuses_link_out_of_repo(tmp_path, repo):
    outside = tmp_path / "outside"
    write(outside, "secret/Keys.java", "class Keys {}\n")
    if not make_link(repo / "linked", outside / "secret"):
        pytest.skip("нельзя создать ни символическую ссылку, ни точку соединения")
    assert find_file(repo, "linked/Keys.java") is None
    ctx._INDEX_CACHE.clear()
    assert find_file(repo, "Keys.java") is None, "обход не заходит в ссылки на папки вне репозитория"


# ============================================================================ статусы

def test_no_repo_with_and_without_export_line():
    f = finding(ACCOUNT, 34, snippet='stmt.executeQuery(sql); // заметка')
    c = build_context(None, f)
    assert (c.status, c.start_line, c.end_line, c.target_line) == ("export_line_only", 34, 34, 34)
    assert c.lines == ["stmt.executeQuery(sql); // заметка"]
    assert c.export_line_check == "n/a" and c.enclosing == ""
    assert "папка репозитория" in c.note and "только строка кода из выгрузки" in c.note
    assert c.numbered() == ">>   34| stmt.executeQuery(sql); // заметка"
    c = build_context(None, finding(ACCOUNT, 34))
    assert (c.status, c.lines, c.start_line, c.target_line) == ("no_repo", [], 0, 34)
    assert c.numbered() == ""
    c = build_context(Path("Z:/nowhere/at/all"), finding(ACCOUNT, 34))
    assert c.status == "no_repo"


def test_file_missing_and_out_of_range(repo):
    assert build_context(repo, finding("src/Missing.java", 3)).status == "file_missing"
    assert build_context(repo, finding("Util.java", 1)).status == "file_missing", "неоднозначно – не догадка"
    assert build_context(repo, finding("", 1)).status == "file_missing"
    c = build_context(repo, finding(ACCOUNT, 500))
    assert c.status == "file_missing" and "за пределами файла" in c.note
    c = build_context(repo, finding(ACCOUNT, 500, snippet="stmt.executeQuery(sql);"))
    assert c.status == "export_line_only" and "за пределами файла" in c.note


def test_too_large_and_binary(repo, monkeypatch):
    write(repo, "img/logo.png", "")
    (repo / "img/logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" * 10)
    assert build_context(repo, finding("img/logo.png", 1)).status == "binary"
    monkeypatch.setattr(ctx, "MAX_FILE_BYTES", 100)
    assert build_context(repo, finding(ACCOUNT, 3)).status == "too_large"
    c = build_context(repo, finding(ACCOUNT, 3, snippet="import java.sql.*;"))
    assert c.status == "export_line_only" and "больше" in c.note


def test_masked_file_is_cached_until_file_changes(repo, monkeypatch):
    """Файл маскируется один раз на все его находки и открытия карточки; изменился файл – маскируется заново."""
    ctx.clear_mask_cache()
    calls = []
    real = ctx.mask_text

    def counting(text, key, **kwargs):
        calls.append(len(text))
        return real(text, key, **kwargs)

    monkeypatch.setattr(ctx, "mask_text", counting)
    key = bytes(range(32))
    first = build_context(repo, finding(ACCOUNT, 7), mask_key=key)
    again = build_context(repo, finding(ACCOUNT, 30), mask_key=key)
    assert len(calls) == 1 and "Demo-Secret-Value-1" not in "\n".join(first.lines + again.lines)
    path = repo / ACCOUNT
    path.write_text(path.read_text(encoding="utf-8") + "\n// дописано\n", encoding="utf-8")
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 5_000_000_000))
    build_context(repo, finding(ACCOUNT, 7), mask_key=key)
    assert len(calls) == 2
    other_key = bytes(range(1, 33))  # другой ключ – другие номера плейсхолдеров
    build_context(repo, finding(ACCOUNT, 7), mask_key=other_key)
    assert len(calls) == 3
    ctx.clear_mask_cache()


def test_no_line_number_shows_file_head(repo):
    c = build_context(repo, finding(ACCOUNT, None), before=2, after=3)
    assert (c.status, c.start_line, c.end_line, c.target_line, c.export_line_check) == ("ok", 1, 6, None, "n/a")
    assert "нет номера строки" in c.note
    assert ">>" not in c.numbered()


# ============================================================================ срез и объемлющий метод

def test_java_slice_and_enclosing(repo):
    sink = line_of(ACCOUNT_JAVA, "// SINK")
    c = build_context(repo, finding(ACCOUNT, sink), before=5, after=3)
    assert c.status == "ok" and c.file == ACCOUNT and c.language == "java"
    assert c.enclosing == ("@Override public void doPost(HttpServletRequest request, HttpServletResponse response) "
                           "throws IOException")
    header = line_of(ACCOUNT_JAVA, "@Override")
    assert (c.start_line, c.end_line, c.target_line) == (header, sink + 3, sink), "окно расширено до заголовка"
    numbered = c.numbered().split("\n")
    assert [int(NUMBERED.match(x).group(2)) for x in numbered] == list(range(header, sink + 4))
    assert numbered[sink - header] == f">>{sink:>5}| {ACCOUNT_JAVA.split(chr(10))[sink - 1]}"
    assert all(x.startswith("  ") for k, x in enumerate(numbered) if k != sink - header)
    assert [n for n, _, target in c.rows() if target] == [sink]
    narrow = build_context(repo, finding(ACCOUNT, sink), before=5, after=3, max_chars=1000)
    assert (narrow.start_line, narrow.end_line) == (sink - 5, sink + 3), "заголовок не влез – обычное окно"


def test_java_enclosing_variants():
    def sig(marker):
        return enclosing_of(ACCOUNT_JAVA, "java", line_of(ACCOUNT_JAVA, marker))[0]

    assert sig("// INNER") == "public void run()", "метод анонимного класса – ближайший объемлющий"
    assert sig("// LAMBDA").startswith("@Override public void doPost"), "лямбда Java пропускается"
    assert sig("// HELPER") == "String helper(String a)"
    assert enclosing_of(ACCOUNT_JAVA, "java", line_of(ACCOUNT_JAVA, "// FIELD")) == ("", None), "поле – не метод"
    assert enclosing_of(ACCOUNT_JAVA, "java", line_of(ACCOUNT_JAVA, "DB_PASSWORD")) == ("", None)


def test_python_enclosing(repo):
    sink = line_of(VIEWS_PY, "PY-SINK")
    assert enclosing_of(VIEWS_PY, "python", sink) == ("def handler(request, name)", 4), \
        "многострочная сигнатура; строка документации с другим отступом не мешает"
    assert enclosing_of(VIEWS_PY, "python", line_of(VIEWS_PY, "PY-METHOD"))[0] == "async def get(self, q)"
    assert enclosing_of(VIEWS_PY, "python", line_of(VIEWS_PY, "PY-CLASS-LEVEL")) == ("", None)
    c = build_context(repo, finding("app/views.py", sink, snippet="os.system(cmd)  # PY-SINK"), before=2, after=1)
    assert (c.language, c.enclosing, c.start_line, c.export_line_check) == ("python", "def handler(request, name)",
                                                                            4, "match")


def test_other_languages_enclosing():
    assert enclosing_of(APP_JS, "javascript", line_of(APP_JS, "JS-SINK"))[0] == "app.get('/users', (req, res) =>"
    assert enclosing_of(APP_JS, "javascript", line_of(APP_JS, "JS-HELPER"))[0] == "function helper(a, b)"
    assert enclosing_of(SVC_CS, "csharp", line_of(SVC_CS, "CS-CTOR"))[0] == "public Svc(int a) : base(a)"
    assert enclosing_of(SVC_CS, "csharp", line_of(SVC_CS, "CS-LAMBDA"))[0] == \
        '[HttpGet("x/{id}")] public async Task<IActionResult> Get(int id)'
    assert enclosing_of(MAIN_GO, "go", line_of(MAIN_GO, "GO-SINK"))[0] == \
        "func (s *Server) Handle(w http.ResponseWriter, r *http.Request)"
    assert enclosing_of("plain text\n", "", 1) == ("", None)


def test_trim_to_max_chars_keeps_target_line(tmp_path):
    text = "\n".join(f"line {i} " + "x" * 300 for i in range(1, 101)) + "\n"
    write(tmp_path, "big.txt", text)
    c = build_context(tmp_path, finding("big.txt", 50), max_chars=3000)
    assert len(c.numbered()) <= 3000
    assert c.start_line <= 50 <= c.end_line and c.target_line == 50
    assert abs((50 - c.start_line) - (c.end_line - 50)) <= 1, "сокращение с обоих краёв"
    assert "срез сокращён до 3000 знаков" in c.note


def test_long_lines_are_cut(tmp_path):
    write(tmp_path, "min.js", "short\n" + "y" * 8000 + "\n" + "z" * 900 + "\n")
    c = build_context(tmp_path, finding("min.js", 2), before=1, after=1)
    assert len(c.lines[1]) == 7000 + len(ctx.CUT_MARK), "строка срабатывания – до max_chars/2"
    assert len(c.lines[2]) == ctx.LINE_LIMIT + len(ctx.CUT_MARK)
    assert "длинные строки обрезаны: 2" in c.note


def test_clone_revision(tmp_path: Path):
    repo = tmp_path / "billing-core"
    heads = repo / ".git" / "refs" / "heads"
    heads.mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    (heads / "main").write_text("a" * 40 + "\n", encoding="ascii")
    assert ctx.clone_revision(repo) == "a" * 40
    (heads / "main").unlink()  # ветка только в packed-refs
    (repo / ".git" / "packed-refs").write_text(f"# pack-refs with: peeled\n{'b' * 40} refs/heads/main\n",
                                               encoding="ascii")
    assert ctx.clone_revision(repo) == "b" * 40
    (repo / ".git" / "HEAD").write_text("c" * 40 + "\n", encoding="ascii")  # отсоединённый HEAD
    assert ctx.clone_revision(repo) == "c" * 40
    (repo / ".git" / "HEAD").write_text("ref: refs/../../outside\n", encoding="ascii")  # выход из .git
    assert ctx.clone_revision(repo) == ""
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").write_text("gitdir: ../elsewhere\n", encoding="ascii")  # .git-файл не читается
    assert ctx.clone_revision(worktree) == ""
    assert ctx.clone_revision(tmp_path / "plain") == "" and ctx.clone_revision(None) == ""


def test_clone_revision_does_not_read_outside_git_dir(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "main").write_text("d" * 40 + "\n", encoding="ascii")  # «ветка» вне клона
    repo = tmp_path / "billing-core"
    (repo / ".git" / "refs").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    if not make_link(repo / ".git" / "refs" / "heads", outside):
        pytest.skip("ссылку на папку здесь не создать")
    assert ctx.clone_revision(repo) == ""  # промежуточная папка – ссылка наружу: файл не читается


def test_decode_source():
    assert ctx.decode_source("а\r\nб\rв\n".encode()) == "а\nб\rв\n", "CRLF -> LF, одиночный CR цел"
    assert ctx.decode_source("\ufeffкод".encode("utf-8")) == "код"
    assert ctx.decode_source("код".encode("cp1251")) == "код"
    assert ctx.decode_source("код\n".encode("utf-16")) == "код\n"
    assert ctx.decode_source(b"\x89PNG\x00\x00\x01") is None


def test_crlf_and_cp1251_files(tmp_path):
    write(tmp_path, "win.py", "def f():\r\n    x = 'строка'\r\n    return x\r\n", encoding="cp1251")
    c = build_context(tmp_path, finding("win.py", 2, snippet="x = 'строка'"))
    assert c.lines[1] == "    x = 'строка'" and c.export_line_check == "match"
    assert c.enclosing == "def f()"


# ============================================================================ сверка строки из выгрузки

def test_export_line_check(repo):
    sink = line_of(ACCOUNT_JAVA, "// SINK")
    same = finding(ACCOUNT, sink, snippet="   stmt.executeQuery(sql);   // SINK  ")
    checked = build_context(repo, same)
    assert checked.export_line_check == "match", "без учёта пробелов"
    assert (checked.export_line_at, checked.export_line_check_version) == (sink, EXPORT_LINE_CHECK_VERSION)
    other = build_context(repo, finding(ACCOUNT, sink, snippet="stmt.executeUpdate(sql);"))
    assert other.export_line_check == "differs" and other.export_line_at is None
    assert other.note == "", "состояние differs показывается без старого предупреждения в заметке"
    assert build_context(repo, finding(ACCOUNT, sink)).export_line_check == "no_export_line"
    sql = line_of(ACCOUNT_JAVA, "String sql")
    escaped = ("String sql = &quot;SELECT * FROM t WHERE name = &#x27;&quot; + user + "
               "&quot;&#x27; AND s = &#x27;}&#x27;&quot;;")
    checked = build_context(repo, finding(ACCOUNT, sql, snippet=escaped))
    assert (checked.export_line_check, checked.export_line_at) == ("match", sql), "HTML-сущности"
    marked = "String sql = \"SELECT * FROM t WHERE name = '\" + user..."
    assert build_context(repo, finding(ACCOUNT, sql, snippet=marked)).export_line_check == "match", \
        "строка обрезана выгрузкой с многоточием"
    near = build_context(repo, finding(ACCOUNT, sql, snippet="stmt.executeQuery(sql); // SINK"))
    assert (near.export_line_check, near.export_line_at) == ("near", sink), "фрагмент соседней строки в окне ±5"
    short = build_context(repo, finding(ACCOUNT, sink, snippet="stmt.executeQuery(sql);"))
    assert short.export_line_check == "match", "фрагмент входит в строку файла – совпадение"
    tiny = build_context(repo, finding(ACCOUNT, sink, snippet="{}"))
    assert (tiny.export_line_check, tiny.export_line_at) == ("short_export_line", None)


# ============================================================================ маскирование

def test_masking_in_slice(repo, mask_key):
    owner = line_of(ACCOUNT_JAVA, "ответственный")
    plain = build_context(repo, finding(ACCOUNT, owner), before=3, after=1)
    assert "Demo-Secret-Value-1" in "\n".join(plain.lines) and plain.masked == {}, "без ключа код как есть"
    c = build_context(repo, finding(ACCOUNT, owner, snippet="// ответственный: ivan.petrov@example.org"),
                      before=3, after=1, mask_key=mask_key)
    text = c.numbered()
    assert "Demo-Secret-Value-1" not in text and "ivan.petrov@example.org" not in text
    assert c.masked == {"EMAIL": 1, "SECRET": 1}
    assert len(c.lines) == c.end_line - c.start_line + 1, "число строк не меняется"
    assert c.export_line_check == "match", "сверка – по коду до маскирования"


def test_credential_finding_hides_literals_but_shows_the_line(repo, mask_key):
    """ADR-0117: у находки о секрете строка срабатывания видна – скрыто только значение в кавычках; все литералы среза
    – метки; то же для строки из выгрузки без клона."""
    target = line_of(ACCOUNT_JAVA, "DB_PASSWORD")
    f = finding(ACCOUNT, target, snippet='private static final String DB_PASSWORD = "Demo-Secret-Value-1";',
                rule="Пароль в исходном коде", cwe=("CWE-798",))
    c = build_context(repo, f, before=2, after=8, mask_key=mask_key)
    lines = dict((n, text) for n, text, _ in c.rows())
    assert re.fullmatch(r' {4}private static final String DB_PASSWORD = "<SECRET_[0-9a-f]{6}>";', lines[target]), \
        "строка срабатывания видна, значение – метка"
    assert "Demo-Secret-Value-1" not in c.numbered()
    assert lines[target - 1] == "public class AccountServlet {", "устройство кода видно"
    request_line = line_of(ACCOUNT_JAVA, "// SOURCE")
    assert 'request.getParameter("<SECRET_' in lines[request_line], "литералы среза – плейсхолдеры"
    assert "находка о секрете" in c.note and "целиком" not in c.note
    exported = build_context(None, f, mask_key=mask_key)
    assert exported.status == "export_line_only"
    assert re.fullmatch(r'private static final String DB_PASSWORD = "<SECRET_[0-9a-f]{6}>";', exported.lines[0])
    assert "Demo-Secret-Value-1" not in exported.numbered()
    # строка без значения – как есть
    plain = build_context(None, finding(ACCOUNT, target, snippet="conn.setPassword(settings.dbPassword);",
                                        rule="Пароль в исходном коде", cwe=("CWE-798",)), mask_key=mask_key)
    assert plain.lines[0] == "conn.setPassword(settings.dbPassword);"
    # закомментированная строка с значением – значение скрыто и в срезе без клона (с HTML-сущностями тоже)
    for snippet in ('// String k = "hunter2hunter2";', "// String k = &quot;hunter2hunter2&quot;;"):
        commented = build_context(None, finding(ACCOUNT, target, snippet=snippet, rule="Пароль в исходном коде",
                                                cwe=("CWE-798",)), mask_key=mask_key)
        assert re.fullmatch(r'// String k = "<SECRET_[0-9a-f]{6}>";', commented.lines[0]), commented.lines[0]


def test_credential_commented_value_is_hidden_in_the_clone_slice(repo, mask_key):
    """ADR-0117: у находки о секрете значение в кавычках прячется и внутри комментария – раньше такую строку
    закрывало скрытие целиком."""
    source = "\n".join(["class Conf {", '    // String old = "hunter2hunter2"; /* was: "qwerty-qwerty" */',
                        '    static String KEY = "demo-key-value";', "}", ""])
    write(repo, "src/Conf.java", source)
    f = finding("src/Conf.java", 2, snippet='// String old = "hunter2hunter2";', rule="Пароль в исходном коде",
                cwe=("CWE-798",))
    c = build_context(repo, f, before=2, after=2, mask_key=mask_key)
    assert c.status == "ok" and "hunter2" not in c.numbered() and "qwerty" not in c.numbered()
    assert re.fullmatch(r' {4}// String old = "<SECRET_[0-9a-f]{6}>"; /\* was: "<SECRET_[0-9a-f]{6}>" \*/', c.lines[1])
    assert re.fullmatch(r' {4}static String KEY = "<SECRET_[0-9a-f]{6}>";', c.lines[2])
    assert c.lines[0] == "class Conf {"


@pytest.mark.parametrize("language, source, closed, both", [
    ("java", '/* String old = """\nhunter2hunter2\nqwerty-qwerty\n"""; */\nint x;', True, True),
    ("cpp", '/* auto k = R"(hunter2hunter2\nqwerty-qwerty)"; */\nint x;', True, True),
    ("java", '/* String old = "hunter2hunter2"; // was: "qwerty-qwerty"\n * tail */\nint x;', True, True),
    ("java", '/* String old = "hunter2hunter2";\n"qwerty-qwerty"', False, True),
    # «//» и «#» внутри блока – не комментарий: многострочный литерал после них разбирается целиком (круг 3 Codex)
    ("java", '/* // String old = """\nhunter2hunter2\nqwerty-qwerty\n"""; */\nint x;', True, True),
    ("cpp", '/* // auto k = R"(hunter2hunter2\nqwerty-qwerty)"; */\nint x;', True, True),
    ("php", '/* # $old = "hunter2hunter2"; # "qwerty-qwerty" */\n$x = 1;', True, True),
    # длинные последовательности маркеров – без рекурсии
    ("java", "//" * 500 + ' "hunter2hunter2"', False, False),
    ("php", "#" * 500 + ' "hunter2hunter2"', False, False),
])
def test_credential_multiline_values_inside_comments_are_hidden(mask_key, language, source, closed, both):
    """Круги 2–3 Codex: литералы внутри комментария, в том числе многострочные и после «//» в блоке, – метки;
    «*/» и число строк на месте; длинные ряды маркеров не ломают разбор."""
    masked = mask_source_text(source, language, mask_key, hide=True)
    assert masked.count("\n") == source.count("\n"), "число строк не меняется"
    assert "hunter2" not in masked, masked
    if both:
        assert "qwerty" not in masked, masked
    if closed:
        assert "*/" in masked and masked.splitlines()[-1] in ("int x;", "$x = 1;"), masked
    # обычная находка: комментарии не трогаются
    assert mask_source_text(source, language, mask_key) == source


def test_export_line_is_masked(mask_key):
    f = finding(ACCOUNT, 12, snippet='connect("postgres://admin:S3cr3t@db.local/app", "ivan.petrov@example.org");')
    c = build_context(None, f, mask_key=mask_key)
    assert "S3cr3t" not in c.lines[0] and "ivan.petrov@example.org" not in c.lines[0]
    assert c.masked == {"EMAIL": 1, "SECRET": 1}
    escaped = build_context(None, finding(ACCOUNT, 12, snippet="password = &quot;demo-secret-value&quot;;"),
                            mask_key=mask_key)
    assert "demo-secret-value" not in escaped.numbered(), "кавычки HTML-сущностями не спасают значение"
    assert escaped.lines[0].startswith('password = "<SECRET_')


def test_credential_long_literal_is_hidden_before_cut(tmp_path, mask_key):
    """Литерал длиннее предела строки: скрывается до обрезки длинных строк, иначе начало значения осталось бы."""
    long_value = "demo-secret-" * 50
    text = "\n".join(["class Conf {",
                      f'    static final String NOTE = "{long_value}";',
                      '    static final String API_KEY = "Demo-Key-Value-42";',
                      '    static final String BANNER = """',
                      "        demo-multiline-value",
                      '        """;',
                      "}", ""])
    write(tmp_path, "Conf.java", text)
    f = finding("Conf.java", 3, rule="Пароль в исходном коде", cwe=("CWE-798",))
    c = build_context(tmp_path, f, mask_key=mask_key)
    shown = c.numbered()
    for value in ("demo-secret-", "Demo-Key-Value-42", "demo-multiline-value"):
        assert value not in shown, value
    assert c.lines[0] == "class Conf {" and c.lines[3].endswith('BANNER = """'), "устройство кода видно"
    assert re.fullmatch(r' {4}static final String API_KEY = "<SECRET_[0-9a-f]{6}>";', c.lines[2]), \
        "строка срабатывания видна, значение – метка (ADR-0117)"
    assert len(c.lines) == 7, "число строк не меняется"


def test_credential_python_triple_quoted(tmp_path, mask_key):
    text = 'DB_PASSWORD = """\nDemo-Pass-Value-7\n"""\n\n\ndef connect():\n    return DB_PASSWORD\n'
    write(tmp_path, "settings.py", text)
    f = finding("settings.py", 1, rule="Hardcoded password", cwe=("CWE-259",))
    c = build_context(tmp_path, f, mask_key=mask_key)
    assert "Demo-Pass-Value-7" not in c.numbered()
    assert len(c.lines) == 7


def test_export_only_respects_max_chars():
    snippet = "\n".join("x" * 400 for _ in range(50))
    c = build_context(None, finding(ACCOUNT, 10, snippet=snippet), max_chars=500)
    assert c.status == "export_line_only"
    assert len(c.numbered()) <= 1000 and c.lines and "сокращена" in c.note
    assert c.end_line == c.start_line + len(c.lines) - 1


# ============================================================================ линейность разбора

def test_lexers_are_linear():
    import time

    for text, language in (("/*a" * 40_000, "java"), ('"a' * 40_000, "java"), ("'a" * 40_000, "python"),
                           ('"""a' * 40_000, "python"), ("`a" * 40_000, "javascript"), ('@"a' * 40_000, "csharp")):
        started = time.monotonic()
        blank = ctx.blank_code(text, language)
        assert time.monotonic() - started < 1.5, (language, text[:6])
        assert len(blank) == len(text)


def test_secret_pass_is_linear_on_comments(mask_key):
    import time

    for n in (8_000, 32_000):
        text = 'const char *password = "alpha";\n' + "/* comment */\n" * n
        started = time.monotonic()
        out = ctx._hide_literals(text, "cpp", mask_key, secrets_only=True)
        assert time.monotonic() - started < 1.0, n
        assert "alpha" not in out and out.count("\n") == text.count("\n")


def test_code_blocks_on_long_headers_are_fast():
    import time

    text = ("f(" + "[]" * 900 + ") {}\n") * 300 + "void g()" + "\n" * 50_000 + "{ run(); }\n"
    started = time.monotonic()
    ctx.code_blocks(text, "java")
    assert time.monotonic() - started < 3


# ============================================================================ поиск файла: неоднозначность и пределы

def test_prefix_drop_is_not_a_shortcut_past_ambiguity(tmp_path):
    write(tmp_path, "one/shared.py", "x = 1\n")
    write(tmp_path, "two/one/shared.py", "x = 2\n")
    assert find_file(tmp_path, "builds/one/shared.py") is None, "два файла кончаются на one/shared.py"
    assert find_file(tmp_path, "two/one/shared.py") == Path(os.path.realpath(tmp_path / "two/one/shared.py"))


def test_incomplete_index_does_not_confirm_uniqueness(tmp_path, monkeypatch):
    write(tmp_path, "a/src/A.java", "class A {}\n")
    write(tmp_path, "b/src/B.java", "class B {}\n")
    monkeypatch.setattr(ctx, "MAX_INDEX_FILES", 1)
    ctx._INDEX_CACHE.clear()
    index, complete = ctx._file_index(os.path.realpath(tmp_path))
    assert complete is False
    assert find_file(tmp_path, "b/src/B.java") is not None, "точный путь находится всегда"
    assert find_file(tmp_path, "src/B.java") is None, "по неполному индексу единственность не доказать"
    assert find_file(tmp_path, "ci/b/src/B.java") is None, "и путь без начальной папки – тоже"
    assert sum(len(v) for v in index.values()) <= 1, "предел проверяется на каждом файле, а не после папки"
    ctx._INDEX_CACHE.clear()


def test_unreadable_folder_makes_index_incomplete(tmp_path, monkeypatch):
    write(tmp_path, "src/A.py", "x = 1\n")
    write(tmp_path, "private/src/A.py", "x = 2\n")
    real_scandir = os.scandir

    def scandir(path):
        if os.path.basename(str(path)) == "private":
            raise PermissionError(13, "нет доступа")
        return real_scandir(path)

    monkeypatch.setattr(ctx.os, "scandir", scandir)
    ctx._INDEX_CACHE.clear()
    index, complete = ctx._file_index(os.path.realpath(tmp_path))
    assert complete is False
    assert find_file(tmp_path, "A.py") is None, "неоднозначность в непрочитанной папке не скрывается"
    assert find_file(tmp_path, "src/A.py") is not None
    ctx._INDEX_CACHE.clear()


def test_raw_strings_and_escaped_triple_quotes_hidden(tmp_path, mask_key):
    cases = {
        "raw.cpp": ('const char *value = R"tag(\n"//\ndemo-raw-secret\n)tag";\nvoid run() {}\n', 5,
                    "demo-raw-secret"),
        "raw.rs": ('let value = r#"head"//demo-raw-secret"#;\nlet c = \'"\';\nfn run() {}\n', 3, "demo-raw-secret"),
        "esc.py": ('value = """head\\"""\ndemo-triple-secret\n"""\nprint(value)\n', 4, "demo-triple-secret"),
        "tpl.js": ("const token = `head\\`demo-hidden-tail`;\nrun();\n", 2, "demo-hidden-tail"),
    }
    for name, (text, line, secret) in cases.items():
        write(tmp_path, name, text)
        c = build_context(tmp_path, finding(name, line, rule="Hardcoded password", cwe=("CWE-798",)),
                          mask_key=mask_key)
        assert c.status == "ok", name
        assert secret not in c.numbered(), name
        assert len(c.lines) == text.count("\n"), name


def test_rust_raw_literal_keeps_enclosing(tmp_path, mask_key):
    text = 'let value = r#"raw-value"#;\nfn run() {\n    query();\n}\n'
    write(tmp_path, "lib.rs", text)
    c = build_context(tmp_path, finding("lib.rs", 3, rule="Hardcoded password", cwe=("CWE-798",)), mask_key=mask_key)
    assert "raw-value" not in c.numbered()
    assert c.enclosing == "fn run()", "разделитель сырой строки сохранён – разбор кода дальше не сбился"
    assert re.fullmatch(r'let value = r#"<SECRET_[0-9a-f]{6}>"#;', c.lines[0])


def test_secret_assignments_hidden_for_any_finding(tmp_path, mask_key):
    """Не находка о секрете (CWE-89), но рядом ключу-секрету присвоена сырая или многострочная строка: значение
    скрывается по разметке языка целиком, остальные литералы видны."""
    cases = {
        "a.rs": ('let password = r#"head"//demo-raw-secret"#;\nlet name = "visible";\nfn run() {}\n', 3),
        "b.cpp": ('const char *password = R"tag(\n"//\ndemo-raw-secret\n)tag";\nconst char *name = "visible";\n'
                  "void run() {}\n", 6),
        "c.py": ('password = \'demo"raw-secret\'\nname = "visible"\nprint(1)\n', 3),
        "d.py": ('token = """\ndemo-raw-secret\n"""\nname = "visible"\nrun()\n', 5),
        "e.cpp": ('const char *password =\n    R"tag(head"//demo-raw-secret)tag";\nconst char *name = "visible";\n'
                  "void run() {}\n", 4),
        "f.cpp": ('const char *password = "first-half" "demo-raw-secret";\nconst char *name = "visible";\n'
                  "void run() {}\n", 3),
        "g.py": ('password = (\n    "demo-raw-secret"\n    "second"\n)\nname = "visible"\nrun()\n', 6),
        "h.rs": ('let token: &str = r#"demo-raw-secret"#;\nlet name = "visible";\nfn run() {}\n', 3),
        "i.cs": ('string password = $"demo-raw-secret{user}";\nstring name = "visible";\nvoid Run() {}\n', 3),
        "j.java": ('String password = "demo-" +\n    "raw-secret";\nString name = "visible";\nvoid run() {}\n', 4),
        "k.cpp": ('const char *password = "alpha" /* часть */ "demo-raw-secret";\nconst char *name = "visible";\n'
                  "void run() {}\n", 3),
        "l.py": ('password = "demo-" \\\n    "raw-secret"\nname = "visible"\nrun()\n', 4),
        "m.py": ('password = (\n    os.getenv("DB_PASSWORD")\n    or "demo-raw-secret"\n)\nname = "visible"\n'
                 "run()\n", 6),
        "n.rs": ('let token: Option<&str> = Some("demo-raw-secret");\nlet name = "visible";\nfn run() {}\n', 3),
    }
    for name, (text, line) in cases.items():
        write(tmp_path, name, text)
        c = build_context(tmp_path, finding(name, line), mask_key=mask_key)
        shown = c.numbered()
        assert "demo-raw-secret" not in shown and 'raw-secret' not in shown, name
        assert '"visible"' in shown, name
        assert len(c.lines) == text.count("\n"), name


def test_index_counts_folders(tmp_path, monkeypatch):
    for k in range(30):
        (tmp_path / f"empty{k:02d}").mkdir()
    write(tmp_path, "zz/last/Target.java", "class T {}\n")
    monkeypatch.setattr(ctx, "MAX_INDEX_DIRS", 5)
    ctx._INDEX_CACHE.clear()
    index, complete = ctx._file_index(os.path.realpath(tmp_path))
    assert complete is False, "пустые папки тоже расходуют предел обхода"
    ctx._INDEX_CACHE.clear()


# ============================================================================ модель среза

def test_code_context_numbered_and_roundtrip():
    c = CodeContext(status="ok", file="a.py", language="python", start_line=98, end_line=101, target_line=100,
                    lines=["a", "b", "c", "d"])
    assert c.numbered().split("\n") == ["     98| a", "     99| b", ">>  100| c", "    101| d"]
    assert CodeContext.from_dict(c.to_dict()) == c
    no_numbers = CodeContext(status="export_line_only", file="a.py", language="python", start_line=0, end_line=0,
                             target_line=None, lines=["x = 1"])
    assert no_numbers.numbered() == "x = 1"


# ============================================================================ демо-выгрузка

def load_demo_script():
    spec = importlib.util.spec_from_file_location("make_demo_xlsx", ROOT / "scripts" / "make_demo_xlsx.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_workbook_and_contexts(tmp_path, mask_key):
    demo = load_demo_script()
    path = demo.build(tmp_path / "demo.xlsx")
    result = parse_workbook(path)
    kinds = [f.kind for f in result.findings]
    assert (kinds.count("SAST"), kinds.count("SCA"), kinds.count("SCA-license"), kinds.count("DAST")) == (15, 4, 1, 1)
    assert result.format == "hub" and result.warnings == [], "сводка демо сходится с листами"
    assert result.summary["application"] == "Demo Library"
    repos = demo.REPOS_DIR
    differs = {spec["id"] for spec in demo.SAST_FINDINGS if "export" in spec and demo.FOLDERS[spec["codebase"]]}
    for f in result.findings:
        if f.kind != "SAST":
            continue
        folder = demo.FOLDERS[f.codebase]
        c = build_context(resolve_repo(repos, folder) if folder else None, f, mask_key=mask_key)
        if folder is None:
            assert c.status == "export_line_only", f.hub_id
            continue
        assert c.status == "ok", (f.hub_id, c.note)
        assert c.target_line == f.line and c.lines, f.hub_id
        assert c.export_line_check == ("differs" if f.hub_id in differs else "match"), f.hub_id
        assert "Demo-Passw0rd-2026" not in c.numbered(), "пароль демо не уходит в промпт"


def test_demo_script_cli(tmp_path):
    out = tmp_path / "cli.xlsx"
    done = subprocess.run([sys.executable, str(ROOT / "scripts" / "make_demo_xlsx.py"), "--out", str(out)],
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          env=dict(os.environ, PYTHONIOENCODING="utf-8"), timeout=120)
    assert done.returncode == 0, done.stderr
    assert out.is_file() and "Готово" in done.stdout


def test_demo_script_errors_are_russian(capsys, tmp_path):
    demo = load_demo_script()
    for argv, message in ((["--out"], "параметр --out: нужно значение"), (["--lishnij"], "неизвестные параметры")):
        with pytest.raises(SystemExit) as stop:
            demo.main(argv)
        assert stop.value.code == 2
        err = capsys.readouterr().err
        assert "ошибка:" in err and message in err and "error" not in err and "usage" not in err
    assert demo.main(["--out", str(tmp_path)]) == 1, "папка вместо файла – ошибка без трассировки"
    err = capsys.readouterr().err
    assert "ошибка: не удалось построить выгрузку" in err and "Traceback" not in err


def test_file_changed_while_reading_bypasses_mask_cache(repo, monkeypatch):
    """Файл поменяли между снятием сведений о нём и чтением: прежний маскированный текст из памяти не берётся."""
    ctx.clear_mask_cache()
    key = bytes(range(32))
    path = repo / ACCOUNT
    old = build_context(repo, finding(ACCOUNT, 7), mask_key=key)
    real_read = ctx._read_at_most

    def changing_read(fd, limit):
        path.write_bytes(path.read_bytes().replace(b"AccountServlet", b"AccountServletV2"))
        return real_read(fd, limit)

    monkeypatch.setattr(ctx, "_read_at_most", changing_read)
    new = build_context(repo, finding(ACCOUNT, 7), mask_key=key)
    assert any("AccountServletV2" in line for line in new.lines)
    assert not any("AccountServletV2" in line for line in old.lines)
    ctx.clear_mask_cache()


# ============================================================================ чтение: проверка открытого файла

LEAK = 'class Leak { String token = "outside-secret-value"; }\n'


def test_file_swapped_at_open_is_refused(tmp_path, repo, monkeypatch):
    """Между поиском файла и открытием на его месте оказался другой файл – вне репозитория: проверяется открытый
    дескриптор, а не путь, поэтому чужой файл не читается."""
    outside = write(tmp_path, "outside/Leak.java", LEAK)
    target = os.path.normcase(os.path.realpath(repo / ACCOUNT))
    real_open = ctx._open_file

    def swapped(path):
        return real_open(str(outside) if os.path.normcase(str(path)) == target else path)

    monkeypatch.setattr(ctx, "_open_file", swapped)
    c = build_context(repo, finding(ACCOUNT, 7, snippet="x"))
    assert c.status == "export_line_only" and "подменён во время чтения" in c.note
    assert "outside-secret-value" not in c.numbered()


def test_folder_replaced_by_link_after_lookup_is_refused(tmp_path, monkeypatch):
    """Папку с файлом заменили ссылкой наружу уже после того, как файл нашли внутри репозитория."""
    repo_dir = tmp_path / "repos" / "app"
    write(repo_dir, "src/A.java", "class A {}\n")
    outside = tmp_path / "outside"
    write(outside, "A.java", LEAK)
    if not make_link(tmp_path / "probe", outside):
        pytest.skip("нельзя создать ни символическую ссылку, ни точку соединения")
    real_find = ctx.find_file

    def find_then_swap(repo, rel):
        found = real_find(repo, rel)
        os.rename(repo_dir / "src", repo_dir / "src-old")
        assert make_link(repo_dir / "src", outside)
        return found

    monkeypatch.setattr(ctx, "find_file", find_then_swap)
    c = build_context(repo_dir, finding("src/A.java", 1))
    assert c.status == "file_missing" and "за пределы репозитория" in c.note
    assert "outside-secret-value" not in c.numbered()


def test_read_stops_one_byte_after_limit(tmp_path):
    big = tmp_path / "big.txt"
    big.write_bytes(b"x" * 50_000)
    fd = os.open(big, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        assert len(ctx._read_at_most(fd, 100)) == 101
    finally:
        os.close(fd)


def test_file_grown_after_size_check_is_not_read_whole(tmp_path, monkeypatch):
    """Размер проверен по открытому файлу, а файл вырос до чтения: читается не больше предела + 1 байт, и такой
    файл считается слишком большим."""
    write(tmp_path, "Grow.java", "class Grow {}\n")
    monkeypatch.setattr(ctx, "MAX_FILE_BYTES", 200)
    got = []
    real_read = ctx._read_at_most

    def growing(fd, limit):
        with open(tmp_path / "Grow.java", "ab") as fh:
            fh.write(b"// " + b"x" * 10_000 + b"\n")
        data = real_read(fd, limit)
        got.append(len(data))
        return data

    monkeypatch.setattr(ctx, "_read_at_most", growing)
    c = build_context(tmp_path, finding("Grow.java", 1, snippet="class Grow {}"))
    assert got == [201]
    assert c.status == "export_line_only" and "больше" in c.note


def test_not_a_regular_file_is_refused(tmp_path, monkeypatch):
    """Вместо файла подложили папку (или канал FIFO): чтения нет, срез – по строке из выгрузки."""
    (tmp_path / "Dir.java").mkdir()
    monkeypatch.setattr(ctx, "find_file", lambda repo, rel: Path(os.path.realpath(tmp_path / "Dir.java")))
    c = build_context(tmp_path, finding("Dir.java", 1, snippet="class Dir {}"))
    assert c.status == "export_line_only" and c.lines == ["class Dir {}"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="каналы FIFO есть только в Linux и macOS")
def test_fifo_instead_of_file_does_not_block(tmp_path, monkeypatch):
    fifo = tmp_path / "Pipe.java"
    os.mkfifo(fifo)
    monkeypatch.setattr(ctx, "find_file", lambda repo, rel: Path(os.path.realpath(fifo)))
    c = build_context(tmp_path, finding("Pipe.java", 1))
    assert c.status == "file_missing" and "не обычный файл" in c.note

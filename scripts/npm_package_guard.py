"""Страж пакета npm учебного стенда (раздел 8 плана docs/npx-stand-plan.md): проверка собранного .tgz до выдачи.

    python scripts/npm_package_guard.py <пакет.tgz> --manifest npm/files.manifest

Проверяется распакованный архив, а не дерево git:
  * состав совпадает с перечнем npm/files.manifest ровно – и лишний, и недостающий файл роняют проверку; без
    package.json – отказ;
  * текст каждого файла – правила гигиены репозитория (scripts/hygiene_rules.py: пути с диска разработчика, реальный
    проект и люди владельца, подсеть его стенда, номера Hub, управляющие знаки) и слова о месте работы владельца;
  * почтовые адреса – только примеры (example, invalid, test, localhost); частные IP – только из перечня разрешённых;
  * книги Excel – ячейки, свойства файла и цели гиперссылок (Д21).
Дословные тексты лицензий и уведомлений (THIRD-PARTY-NOTICES.md, LICENSE) освобождены от правил о почте и адресах
сайтов: в уведомлениях стоят адреса авторов; остальные правила к ним применяются. Код выхода 0 – пакет чистый, 1 –
нарушения (перечислены), 2 – архив не прочитан.
"""

from __future__ import annotations

import argparse
import io
import ipaddress
import re
import sys
import tarfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hygiene_rules import (CONTROL, LOCAL_PATHS, PLACE_WORDS, REAL_PROJECT, STAND_LAN,  # noqa: E402
                           hub_number_hits)

GENERATED = {"README.md", "npm/build.json"}
LICENSE_TEXTS = {"THIRD-PARTY-NOTICES.md", "LICENSE"}
XLSX = {".xlsx", ".xlsm"}
BINARY_OK = {".woff2"}  # шрифты: текста, который могли бы проверить правила, в них нет
# частные адреса, которые в пакете нужны, – только в своих строках (ревью сборки А, круги 1–2): три частные сети с
# точными масками в объявлении _PRIVATE_NETWORKS и в тексте отказа app/llm_net.py; заглушка 10.0.0.5 в подсказках
# «например …» и в атрибуте placeholder поля адреса. Тот же адрес в другой строке – нарушение.
NETWORKS = {"10.0.0.0": "/8", "172.16.0.0": "/12", "192.168.0.0": "/16"}
ALLOWED_LINES = {
    "app/llm_net.py": ("_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (", "fc00::/7). Запрос не отправлен"),
    "app/llm_chat.py": ("нужен адрес сервера в сети организации, например http://10.0.0.5:8000/v1\")",),
    "app/llm_ollama.py": ("нужен адрес сервера в сети организации, например http://10.0.0.5:11434\")",),
    "app/templates/settings/provider.html": ('placeholder="http://10.0.0.5:11434"',),
}
PRIVATE_IP = re.compile(r"(?<![\d.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
                        r"192\.168\.\d{1,3}\.\d{1,3})(?![\d.])")
EMAIL = re.compile(r"(?<![\w.+-])([\w.+-]+)@([\w-]+(?:\.[\w-]+)*\.(?:[^\W\d_]{2,}|xn--[\w-]+))\b")  # и IDN
ULA = ipaddress.ip_network("fc00::/7")
IPV6_CANDIDATE = re.compile(r"(?i)(?<![0-9a-f:.])((?:[0-9a-f]{0,4}:){2,8}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}))"
                            r"(?![0-9a-f:]|\.\d)")  # и «…6::» в конце, и смешанная запись с IPv4
EXAMPLE_DOMAIN = re.compile(r"(?i)(?:^|\.)(?:example(?:\.(?:com|org|net))?|invalid|test|localhost)$")


URL_CREDENTIALS = re.compile(r"://[^\s/@:]+:$")  # …://пользователь: перед «пароль@узел»
HOST_PORT = re.compile(r"[\w.-]+\.[A-Za-z]{2,}:$")  # узел.домен: перед «порт@узел»


def email_problems(text: str) -> list[str]:
    out = []
    for m in EMAIL.finditer(text):
        local, domain = m.group(1), m.group(2)
        before = text[max(0, m.start() - 200):m.start()]
        if EXAMPLE_DOMAIN.search(domain):
            continue  # домен-пример
        if URL_CREDENTIALS.search(before) or (local.isdigit() and HOST_PORT.search(before)):
            continue  # пароль в адресе вида scheme://user:pass@host или порт в host:port@host
        out.append(f"почтовый адрес {m.group(0)}")
    return out


def private_allowed(name: str, text: str, start: int, address: str) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    line = text[line_start:line_end if line_end >= 0 else len(text)]
    markers = ALLOWED_LINES.get(name)
    if not markers or not any(marker in line for marker in markers):
        return False
    if name != "app/llm_net.py":  # адрес-заглушка – внутри самой согласованной подсказки, а не рядом с ней (ревью круга 4)
        code = line.strip()
        if code.startswith(("#", "<!--", "{#")) or "<!--" in line[:start - line_start]:
            return False  # та же подсказка в комментарии – не подсказка
        if name.endswith(".html") and not ("<input" in line and 'name="base_url"' in line):
            return False  # placeholder – только у поля адреса
        column = start - line_start
        if not any(line.find(m) >= 0 and line.find(m) <= column < line.find(m) + len(m) for m in markers):
            return False
    if name == "app/llm_net.py":  # адрес с полной маской и границей: «10.0.0.0/8», не «10.0.0.0/80»
        return address in NETWORKS and re.match(re.escape(address + NETWORKS[address]) + r"(?![\d/])", text[start:]) is not None
    # заглушка – только как адрес сервера в подсказке: «http://10.0.0.5:11434»
    return address == "10.0.0.5" and re.match(r"10\.0\.0\.5:(?:11434|8000)\b", text[start:]) is not None and \
        text[max(0, start - 7):start] == "http://"


HTML_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)|\{#.*?(?:#\}|\Z)", re.S)  # и Jinja, и незакрытые – до конца


def blank_out(text: str) -> str:
    """Шаблон, где содержимое HTML-комментариев не считается действующим полем: строки комментария остаются на месте,
    но разрешённая подсказка внутри них теряет признак поля (<input … name="base_url">) и проверяется как обычный текст."""
    return HTML_COMMENT.sub(lambda m: re.sub(r"<input|name=\"base_url\"", lambda x: "x" * len(x.group(0)), m.group(0)), text)


def text_problems(name: str, text: str) -> list[str]:
    out = []
    lines = text.splitlines()

    def where(index: int) -> str:
        return f"{name}:{text.count(chr(10), 0, index) + 1}"

    for rule, what in ((LOCAL_PATHS, "путь с диска разработчика"), (REAL_PROJECT, "реальный проект или человек владельца"),
                       (STAND_LAN, "адрес подсети стенда владельца"), (PLACE_WORDS, "слово о месте работы владельца")):
        found = rule.search(text)
        if found:
            out.append(f"{where(found.start())}: {what} «{found.group(0)}»")
    found = CONTROL.search(text)
    if found:
        out.append(f"{where(found.start())}: управляющий знак {ord(found.group(0))}")
    for what, shown, at in hub_number_hits(text):
        out.append(f"{where(at)}: {what} «{shown.strip()}»")
    if name not in LICENSE_TEXTS:
        out.extend(f"{name}: {p}" for p in email_problems(text))
    for m in IPV6_CANDIDATE.finditer(text):  # частные IPv6 (ULA, fc00::/7) – любой записью; разбор адреса целиком
        try:
            address = ipaddress.IPv6Address(m.group(1))
        except ValueError:
            continue
        if address not in ULA:
            continue
        if str(address) == "fc00::" and re.match(r"/7(?!\d)", text[m.end():m.end() + 3]):
            continue  # обозначение всей сети «fc00::/7» – не адрес
        out.append(f"{where(m.start())}: частный адрес IPv6 {m.group(1)}")
    for m in PRIVATE_IP.finditer(text):
        if not private_allowed(name, text, m.start(1), m.group(1)):
            out.append(f"{where(m.start())}: частный адрес {m.group(1)} вне перечня разрешённых")
    del lines
    return out


def _outside_quotes(formula: str):
    """Позиции знаков формулы вне строковых литералов (удвоенная кавычка внутри литерала – часть строки)."""
    quoted, i = False, 0
    while i < len(formula):
        ch = formula[i]
        if ch == '"':
            if quoted and formula[i + 1:i + 2] == '"':
                i += 2
                continue
            quoted = not quoted
        elif not quoted:
            yield i, ch
        i += 1


def _first_argument(formula: str, open_at: int) -> str:
    """Первый аргумент функции со скобкой в open_at: до запятой или точки с запятой верхнего уровня вне кавычек."""
    depth = 0
    for i, ch in _outside_quotes(formula):
        if i < open_at:
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return formula[open_at + 1:i]
        elif ch in ",;" and depth == 1:
            return formula[open_at + 1:i]
    return formula[open_at + 1:]


def _split_concat(arg: str) -> list[str]:
    cuts = [i for i, ch in _outside_quotes(arg) if ch == "&"]
    parts, last = [], 0
    for i in cuts:
        parts.append(arg[last:i])
        last = i + 1
    parts.append(arg[last:])
    return [p.strip() for p in parts]


def hyperlink_targets(formula: str, cells: dict[str, str] | None = None) -> list[str]:
    """Цели HYPERLINK (ревью кругов 7–9): вызовы ищутся вне строк; первый аргумент – литералы, ссылки на ячейки этого
    листа с постоянным текстом и их склейка «&» дают значение; другое выражение статически не проверить – «?…»."""
    out = []
    upper = formula.upper()
    for i, _ch in _outside_quotes(formula):
        if not upper.startswith("HYPERLINK", i) or (i and (formula[i - 1].isalnum() or formula[i - 1] in "_.")):
            continue
        j = i + len("HYPERLINK")
        while j < len(formula) and formula[j].isspace():
            j += 1
        if j >= len(formula) or formula[j] != "(":
            continue
        arg = _first_argument(formula, j).strip()
        value = []
        for part in _split_concat(arg):
            part = part.strip()
            while part.startswith("(") and part.endswith(")"):
                part = part[1:-1].strip()
            ref = re.fullmatch(r"\$?([A-Za-z]{1,3})\$?(\d+)", part)
            if re.fullmatch(r'"(?:[^"]|"")*"', part):
                value.append(part[1:-1].replace('""', '"'))
            elif ref and cells is not None and f"{ref.group(1).upper()}{ref.group(2)}" in cells:
                value.append(cells[f"{ref.group(1).upper()}{ref.group(2)}"])
            else:
                value = None
                break
        out.append("".join(value) if value is not None else f"?{arg}")
    return out


def sheet_cells(raw: bytes, shared: list[str]) -> dict[str, str]:
    """Постоянные текстовые значения ячеек листа: общая таблица строк, встроенная строка или строка формулы."""
    cells = {}
    root = ElementTree.fromstring(raw)
    for c in root.iter():
        if c.tag.rsplit("}", 1)[-1] != "c" or not c.get("r"):
            continue
        kind = c.get("t", "")
        v = next((x for x in c if x.tag.rsplit("}", 1)[-1] == "v"), None)
        if kind == "s" and v is not None and (v.text or "").isdigit() and int(v.text) < len(shared):
            cells[c.get("r").upper()] = shared[int(v.text)]
        elif kind == "inlineStr":
            cells[c.get("r").upper()] = "".join(t.text or "" for t in c.iter() if t.tag.rsplit("}", 1)[-1] == "t")
    return cells


def xml_values(raw: bytes, cells: dict[str, str] | None = None) -> tuple[list[str], list[tuple[str, bool]]]:
    """Декодированные значения частей книги XML-парсером (ревью, Д21): текст элементов и значения атрибутов, отдельно –
    цели связей (Target). Символьные ссылки и любая допустимая запись XML дают одно и то же значение. Разбираются
    собственные файлы пакета; ElementTree внешних сущностей не загружает, expat ограничивает раздувание сущностей."""
    root = ElementTree.fromstring(raw)
    values, targets = [], []
    for element in root.iter():
        local = element.tag.rsplit("}", 1)[-1]
        if local == "f" and element.text:  # формула HYPERLINK: цель – первый аргумент (Д21, ревью кругов 7–8)
            for target in hyperlink_targets(element.text, cells):
                targets.append((target, True))
                if not target.startswith("?"):
                    values.append(target)  # вычисленная цель – и под общие правила текста
        if local in ("si", "is"):  # строка таблицы строк или встроенная: значение – из элементов t, без отступов XML
            values.append("".join(t.text or "" for t in element.iter() if t.tag.rsplit("}", 1)[-1] == "t"))
        if element.text and element.text.strip():
            values.append(element.text)
        if element.tail and element.tail.strip():
            values.append(element.tail)
        external = element.attrib.get("TargetMode", "").lower() == "external"
        for key, value in element.attrib.items():
            values.append(value)
            if key == "Target" or key.endswith("}Target"):
                targets.append((value, external))
    return values, targets


def xlsx_problems(name: str, data: bytes) -> list[str]:
    out = []
    try:
        book = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return [f"{name}: книга не читается"]
    with book:
        shared = []
        if "xl/sharedStrings.xml" in book.namelist():
            try:
                shared = [("".join(t.text or "" for t in si.iter() if t.tag.rsplit("}", 1)[-1] == "t"))
                          for si in ElementTree.fromstring(book.read("xl/sharedStrings.xml")).iter()
                          if si.tag.rsplit("}", 1)[-1] == "si"]
            except ElementTree.ParseError:
                shared = []
        seen = set()
        for info in book.infolist():  # по записям, а не по именам: одноимённая часть не прячет предыдущую
            part = info.filename
            if part in seen:
                out.append(f"{name} → {part}: имя части повторяется в книге")
                continue
            seen.add(part)
            if not part.endswith((".xml", ".rels")):
                continue
            raw = book.read(info)
            try:
                cells = sheet_cells(raw, shared) if part.startswith("xl/worksheets/") and part.endswith(".xml") else None
                values, targets = xml_values(raw, cells)
            except ElementTree.ParseError:
                out.append(f"{name} → {part}: часть книги не разбирается как XML")
                values, targets = [raw.decode("utf-8", "replace")], []  # и всё равно проверяется как текст
            for target, external in targets:  # цели связей: гиперссылки ячеек и внешние ссылки
                if target.startswith("?"):
                    out.append(f"{name} → {part}: цель HYPERLINK статически не проверить «{target[1:]}»")
                    continue
                with_scheme = re.match(r"(?i)[a-z][a-z0-9+.-]*:", target)
                if (with_scheme or external) and not re.match(r"(?i)https?://", target):
                    out.append(f"{name} → {part}: цель ссылки не http(s) «{target}»")
            out.extend(f"{name} → {part}: {p.split(': ', 1)[-1]}" for p in text_problems(f"{name}:{part}", "\n".join(values)))
    return out


def check(tgz: Path, manifest: Path) -> list[str]:
    wanted = {line.strip() for line in manifest.read_text(encoding="utf-8").splitlines()
              if line.strip() and not line.startswith("#")}
    problems: list[str] = []
    with tarfile.open(tgz, "r:gz") as archive:
        members = [m for m in archive.getmembers() if m.isfile()]
        names = {}
        for member in members:
            if not member.name.startswith("package/"):
                problems.append(f"{member.name}: путь вне package/")
                continue
            short = member.name[len("package/"):]
            if short in names:  # второй член с тем же именем заменил бы первый в проверке
                problems.append(f"{short}: имя повторяется в архиве")
                continue
            names[short] = member
        if any(not (m.isfile() or m.isdir()) for m in archive.getmembers()):
            problems.append("в архиве есть ссылки или особые файлы")
        got = set(names)
        problems += [f"{n}: файла нет в перечне npm/files.manifest" for n in sorted(got - wanted)]
        problems += [f"{n}: в перечне есть, в пакете нет" for n in sorted(wanted - got)]
        if "package.json" not in got:
            problems.append("в пакете нет package.json")
        for name, member in sorted(names.items()):
            data = archive.extractfile(member).read()
            suffix = Path(name).suffix.lower()
            if suffix in XLSX:
                problems += xlsx_problems(name, data)
            elif b"\0" not in data:  # текст любого вида: исходники примеров, шаблоны, сценарии
                text = data.decode("utf-8", "replace")
                # шаблон: поле внутри <!-- … --> не поле, разрешённая подсказка в комментарии – нарушение (ревью круга 5)
                problems += text_problems(name, blank_out(text) if suffix == ".html" else text)
            elif suffix not in BINARY_OK:
                problems.append(f"{name}: двоичный файл вида {suffix or '(без расширения)'} страж не умеет проверять")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="npm_package_guard.py", description=__doc__.splitlines()[0])
    parser.add_argument("tgz", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        problems = check(args.tgz, args.manifest)
    except (OSError, tarfile.TarError) as e:
        print(f"Пакет не прочитан: {e}", file=sys.stderr)
        return 2
    if problems:
        print("Страж пакета: нарушения –", len(problems), file=sys.stderr)
        for line in problems:
            print("  " + line, file=sys.stderr)
        return 1
    print(f"Страж пакета: {args.tgz.name} чистый, файлов по перечню – совпадение.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

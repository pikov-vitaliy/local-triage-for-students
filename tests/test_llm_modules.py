"""Разделение клиента модели на модули (0.9.12, ADR-0102; 0.9.13): app.llm – общее, app.llm_net – соединение,
app.llm_http – общий транспорт клиентов, app.llm_ollama – клиент Ollama. Подмена в тестах должна попадать туда, откуда функция берёт имя: подмена закрытого сетевого имени через
app.llm падает громко, а подмена имени, которое другой модуль скопировал себе при импорте, без подмены у потребителя
считается ошибкой теста."""
import ast
import re
from pathlib import Path

from app import llm, llm_chat, llm_http, llm_net, llm_ollama

TESTS = Path(__file__).parent
APP = TESTS.parent / "app"
MODULES = {"llm": llm, "llm_net": llm_net, "llm_http": llm_http, "llm_ollama": llm_ollama, "llm_chat": llm_chat}
# setattr(llm, "X") / patch.object(llm, "X") / setattr("app.llm.X") / patch("app.llm.X")
PATCH_ATTR = re.compile(r"""(?:setattr|patch\.object)\(\s*(llm|llm_net|llm_http|llm_ollama|llm_chat)\s*,\s*["']([A-Za-z_]\w*)["']""")
PATCH_PATH = re.compile(r"""(?:setattr|patch)\(\s*["']app\.(llm|llm_net|llm_http|llm_ollama|llm_chat)\.([A-Za-z_]\w*)["']""")


def copied_names() -> dict[tuple[str, str], set[str]]:
    """(модуль-источник, имя) -> модули приложения, которые скопировали имя себе через from-импорт."""
    result: dict[tuple[str, str], set[str]] = {}
    for path in APP.rglob("*.py"):
        consumer = ".".join(path.relative_to(APP.parent).with_suffix("").parts)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module in ("app.llm", "app.llm_net", "app.llm_http", "app.llm_ollama", "app.llm_chat"):
                for alias in node.names:
                    result.setdefault((node.module.split(".")[1], alias.name), set()).add(consumer)
    return result


COPIED = copied_names()


def bad_patches(text: str) -> list[str]:
    """Подмены в тексте теста, которые не подействуют: имени нет в самом модуле (ленивая ссылка или переехало), или
    имя скопировано другим модулем при импорте, а у потребителя его этот же тест не подменяет."""
    patches = {(m, n) for m, n in PATCH_ATTR.findall(text)} | {(m, n) for m, n in PATCH_PATH.findall(text)}
    wrong = []
    for module, name in sorted(patches):
        if name not in vars(MODULES[module]):
            wrong.append(f"{module}.{name}: имени нет в самом модуле")
            continue
        for consumer in sorted(COPIED.get((module, name), ())):
            short = consumer.split(".")[-1]
            if short in MODULES and (short, name) not in patches:
                wrong.append(f"{module}.{name}: {consumer} взял копию при импорте – подменяйте и там")
    return wrong


def test_moved_names_are_not_attributes_of_the_common_module():
    for name in ("_new_socket", "_connect_any", "in_container", "hosts_file_addresses", "local_networks",
                 "is_own_address", "_resolve_slots", "RESOLVE_TIMEOUT_S", "CONTAINER_HOSTS_FILE", "CONTAINER_MARKERS",
                 "PS_TIMEOUT_S", "time", "socket"):
        assert name not in vars(llm), f"{name} снова в app.llm: подмена в тестах может пройти впустую"
    assert hasattr(llm_net, "_new_socket") and hasattr(llm_net, "in_container")
    assert hasattr(llm_ollama, "PS_TIMEOUT_S") and hasattr(llm_ollama, "time")


def test_guard_catches_ineffective_patches():
    """Страж сам проверен: каждая форма холостой подмены распознаётся."""
    assert bad_patches('monkeypatch.setattr(llm, "_new_socket", x)')
    assert bad_patches('monkeypatch.setattr("app.llm._new_socket", x, raising=False)')
    assert bad_patches('with patch.object(llm, "in_container", create=True): pass')
    assert bad_patches('patch("app.llm.OllamaClient", x)')  # ленивая ссылка: потребители её не увидят
    # _one_line скопирован в app.llm_ollama при импорте: подмена только в app.llm до клиента не доходит
    assert any("llm_ollama" in w for w in bad_patches('monkeypatch.setattr(llm, "_one_line", x)'))
    assert not [w for w in bad_patches('monkeypatch.setattr(llm, "_one_line", x)\n'
                                       'monkeypatch.setattr(llm_ollama, "_one_line", x)') if "llm_ollama" in w]
    # _resolve скопирован в app.llm_http (общий транспорт): подмена в app.llm_net без подмены там – холостая
    assert any("llm_http" in w for w in bad_patches('monkeypatch.setattr(llm_net, "_resolve", x)'))
    # честная подмена: имя живёт в модуле и берётся из него при каждом вызове
    assert not bad_patches('monkeypatch.setattr(llm_net, "_new_socket", x)')
    assert not bad_patches('monkeypatch.setattr(llm_ollama, "PS_TIMEOUT_S", 0.1)')


def test_tests_patch_only_where_the_name_is_read():
    wrong = []
    for path in sorted(TESTS.rglob("test_*.py")):
        if path.resolve() == Path(__file__).resolve():  # в этом файле – примеры для проверки самого стража
            continue
        wrong += [f"{path.name}: {w}" for w in bad_patches(path.read_text(encoding="utf-8"))]
    assert not wrong, wrong


def test_old_import_path_gives_the_same_objects():
    from app.llm import OllamaClient, in_container, read_chat_stream
    assert OllamaClient is llm_ollama.OllamaClient
    assert read_chat_stream is llm_ollama.read_chat_stream
    assert in_container is llm_net.in_container
    assert isinstance(OllamaClient("http://127.0.0.1:11434"), llm.LlmClient)


def test_unknown_attribute_of_the_common_module_is_an_error():
    try:
        llm.no_such_name  # noqa: B018
    except AttributeError as e:
        assert "no_such_name" in str(e)
    else:  # pragma: no cover
        raise AssertionError("ленивый __getattr__ не должен выдумывать имена")

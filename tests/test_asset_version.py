"""Адреса статических файлов (`?v=`) меняются вместе с содержимым app/static: после перезапуска с новым скриптом браузер не
держит старый (иначе после нескольких перезапусков с одним и тем же `?v=` браузер оставляет прежний app.js)."""
import re

from app import __version__, build_info
from test_web import web  # noqa: F401


def test_asset_version_follows_static_content(tmp_path):
    static = tmp_path / "static"
    static.mkdir()
    (static / "app.js").write_text("alert(1)", encoding="utf-8")
    first = build_info.asset_version.__wrapped__(static)
    assert re.fullmatch(re.escape(__version__) + r"-[0-9a-f]{10}", first)
    assert build_info.asset_version.__wrapped__(static) == first, "детерминирован"
    (static / "app.js").write_text("alert(2)", encoding="utf-8")
    changed = build_info.asset_version.__wrapped__(static)
    assert changed != first, "содержимое изменилось – адрес другой"
    (static / "sub").mkdir()
    (static / "sub" / "x.css").write_text("", encoding="utf-8")
    assert build_info.asset_version.__wrapped__(static) != changed, "новый файл – адрес другой"
    # каталога нет – отпечаток пустой последовательности (SHA-256 от пустого ввода начинается с e3b0c44298)
    assert build_info.asset_version.__wrapped__(tmp_path / "нет") == f"{__version__}-e3b0c44298"


def test_pages_reference_scripts_with_content_version(web):  # noqa: F811
    version = build_info.asset_version()
    assert version != __version__ and version.startswith(__version__ + "-")
    html = web.client.get("/").text
    assert f'src="/static/app.js?v={version}"' in html and f'href="/static/app.css?v={version}"' in html
    assert f"app.js?v={__version__}\"" not in html

"""Шаблоны собираются (синтаксис Jinja) – для проверки после переноса строк в перевод (ADR-0158).

    python scripts/i18n_template_check.py [ФАЙЛЫ…]   – без аргументов: все шаблоны app/templates
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.view import TEMPLATES_DIR, make_templates  # noqa: E402


def main(argv: list[str]) -> int:
    env = make_templates().env
    names = [str(Path(a).resolve().relative_to(Path(TEMPLATES_DIR).resolve())).replace("\\", "/") for a in argv] or \
        sorted(str(p.relative_to(TEMPLATES_DIR)).replace("\\", "/") for p in Path(TEMPLATES_DIR).rglob("*.html"))
    bad = 0
    for name in names:
        try:
            env.get_template(name)
        except Exception as e:  # noqa: BLE001 – печатаем любую ошибку сборки шаблона
            bad += 1
            print(f"{name}: {type(e).__name__}: {e}")
    print(f"шаблонов: {len(names)}, ошибок: {bad}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

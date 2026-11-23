"""Снимки экрана учебного стенда для README (docs/images/stand/*.png): Playwright, Chromium, 1440×900, светлая тема.

    python scripts/stand_screenshots.py http://127.0.0.1:8810 docs/images/stand [--lang en]

Стенд должен работать (например `node npm/cli.js --home <папка> --code-dir <папка> --port 8810 --no-open`), пример
Demo Library – создан проектом. Сценарий только читает страницы и раскрывает блоки; данных не меняет, кроме
выбора языка, если задан --lang (POST /settings/language).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

SIZE = {"width": 1440, "height": 900}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("out")
    ap.add_argument("--lang", choices=("en", "ru"))
    args = ap.parse_args(argv)
    base, out = args.base.rstrip("/"), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport=SIZE, color_scheme="light", locale="en-US" if args.lang != "ru" else "ru-RU")
        # тема по времени суток: снимки – в светлой (ручной выбор с длинным сроком)
        ctx.add_init_script("try{localStorage.setItem('local-triage-theme',JSON.stringify({theme:'light',"
                            "until:Date.now()+864e5}))}catch(e){}")
        page = ctx.new_page()
        if args.lang:
            page.goto(base + "/settings")
            page.check(f"input[name=lang][value={args.lang}]")
            page.click("#language-save")
            page.wait_for_load_state()

        def shot(name: str, url: str, *, selector: str = "", full: bool = False) -> None:
            page.goto(base + url)
            page.wait_for_load_state("networkidle")
            if selector:
                page.locator(selector).first.scroll_into_view_if_needed()
                page.locator(selector).first.screenshot(path=str(out / name))
            else:
                page.screenshot(path=str(out / name), full_page=full)
            print(name)

        shot("01-examples.png", "/examples")
        shot("02-start.png", "/examples", selector="#start")
        shot("03-preset-deepseek.png", "/settings/providers/new?preset=deepseek")
        page.goto(base + "/")
        pid = re.search(r'href="/projects/(\d+)', page.content())
        if not pid:
            print("нет проекта: создайте Demo Library на странице «Примеры»", file=sys.stderr)
            return 1
        pid = pid.group(1)
        shot("04-project.png", f"/projects/{pid}")
        shot("05-findings.png", f"/projects/{pid}/findings?kind=SAST")
        page.goto(base + f"/projects/{pid}/findings?kind=SAST")
        card = page.locator(f"a[href^='/projects/{pid}/findings/']").first.get_attribute("href")
        if card:
            shot("06-card.png", card)
        shot("07-licenses.png", f"/projects/{pid}/findings?kind=SCA-license")
        shot("08-help.png", "/help")
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

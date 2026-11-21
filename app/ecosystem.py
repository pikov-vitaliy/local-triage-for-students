"""Экосистема пакета как часть его идентичности (SCA).

Один и тот же `имя@версия` в разных экосистемах – разные пакеты (npm и PyPI не взаимозаменяемы). Идентичность пакета
в приложении – тройка (экосистема, имя, версия). Экосистема берётся из колонки Type отчёта Hub и приводится
к имени типа Package URL (purl-spec): синонимы одного реестра (pip и poetry – PyPI, gradle и sbt – maven)
объединяются, неизвестное значение не угадывается и остаётся пустым: такой пакет – своя группа.
"""

from __future__ import annotations

# синоним -> имя типа Package URL
_ALIASES = {
    "gradle": "maven", "sbt": "maven", "ivy": "maven",
    "yarn": "npm", "pnpm": "npm",
    "pip": "pypi", "poetry": "pypi",
    "go": "golang",
    "crates": "cargo",
    "rubygems": "gem", "bundler": "gem",
    "packagist": "composer",
    "debian": "deb",
    "alpine": "apk",
}
CANONICAL = frozenset((
    "maven", "npm", "pypi", "nuget", "golang", "cargo", "gem", "composer", "conan", "cocoapods", "swift", "hex",
    "pub", "cran", "conda", "deb", "rpm", "apk", "docker",
))
# Старый ответ агента по имени и версии, которые есть в нескольких экосистемах проекта: к какой из них он относится,
# неизвестно, и он не применяется ни к одной (миграция и сохранение без экосистемы)
AMBIGUOUS = "?"


def canon_ecosystem(value: object) -> str:
    """Значение Type отчёта Hub или поля ecosystem ответа -> имя типа Package URL; неизвестное и пустое – ""."""
    text = str(value or "").strip().casefold()
    text = _ALIASES.get(text, text)
    return text if text in CANONICAL else ""


def finding_ecosystem(data: dict) -> str:
    """Эффективная экосистема находки SCA (план dev17, п. 4.2): по сведениям Hub о библиотеке, когда они применены
    (data["package"], источник hub), иначе – колонка Type выгрузки."""
    from app import package_identity
    return package_identity.of(data)[0]


def resolve_legacy(ecosystems: set[str]) -> str:
    """Экосистема ответа, сохранённого без экосистемы, по экосистемам пакета с тем же именем и версией в проекте:
    одна – она; нет пакета – ""; несколько – AMBIGUOUS."""
    if len(ecosystems) > 1:
        return AMBIGUOUS
    return next(iter(ecosystems), "")

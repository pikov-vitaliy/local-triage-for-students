# Сторонние компоненты учебного стенда «Локальный триаж»

Перечень того, что входит в пакет npm или ставится им на компьютер пользователя. Перечень дополняется с каждой сборкой
стенда; полные тексты уведомлений библиотек из сборок PostgreSQL добавляются к выпуску пакета.

## Входит в пакет

- **Golos Text** – шрифт интерфейса, файлы `app/static/fonts/Golos-Text_*.woff2`. Авторы – Paratype и соавторы.
  SIL Open Font License 1.1, полный текст – `app/static/fonts/OFL.txt`.
- **CAPEC** – каталог шаблонов атак, Copyright © The MITRE Corporation. Условия использования –
  `app/static/capec-license.txt`.
- **Значки интерфейса** – из набора Lucide (лицензия ISC); часть значков Lucide происходит из набора Feather
  (лицензия MIT).

## Ставится на компьютер пользователя при первом запуске

- **PostgreSQL 17.12** – бинарники из пакетов `@embedded-postgres/<платформа>@17.12.0-beta.19` (лицензия MIT
  обёртки пакетов, автор Lei Nelissen). Сам PostgreSQL распространяется по PostgreSQL License; в сборках для каждой
  платформы есть сторонние библиотеки (OpenSSL, ICU, zlib, libxml2, libxslt, gettext, libiconv, lz4, zstd, curl, на
  Windows также wxWidgets).
- **Python 3.12 и uv** – ставятся их собственными установщиками (uv – с сайта astral.sh) или берутся с компьютера.
- **Зависимости приложения** – из PyPI по перечню `npm/requirements.txt` с хешами; в пакет npm они не вкладываются.
  Лицензии – по метаданным установленных пакетов:

  | Пакет | Версия | Лицензия |
  |---|---|---|
  | annotated-doc | 0.0.5 | MIT |
  | annotated-types | 0.8.0 | MIT |
  | anyio | 4.15.1 | MIT |
  | click | 8.5.0 | BSD-3-Clause |
  | colorama (только Windows) | 0.4.6 | BSD |
  | et-xmlfile | 2.0.0 | MIT |
  | fastapi | 0.141.1 | MIT |
  | h11 | 0.16.0 | MIT |
  | idna | 3.20 | BSD-3-Clause |
  | Jinja2 | 3.1.6 | BSD |
  | MarkupSafe | 3.0.4 | BSD-3-Clause |
  | openpyxl | 3.1.5 | MIT |
  | psycopg, psycopg-binary | 3.3.7 | LGPL-3.0-only |
  | psycopg-pool | 3.3.3 | LGPL-3.0-only |
  | pydantic | 2.14.1 | MIT |
  | pydantic-core | 2.50.1 | MIT |
  | python-multipart | 0.0.32 | Apache-2.0 |
  | starlette | 1.8.0 | BSD-3-Clause |
  | typing-extensions | 4.16.0 | PSF-2.0 |
  | typing-inspection | 0.4.4 | MIT |
  | tzdata (только Windows) | 2026.6 | Apache-2.0 |
  | uvicorn | 0.54.0 | BSD-3-Clause |

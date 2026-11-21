# Каталог учебных примеров: источники и лицензии

Дата снимков зависимостей: 2026-11-20; данные OSV и deps.dev – на дату сборки выгрузок (osv_date в catalog.json). Код примеров в пакет и в репозиторий не входит: каталог хранит адрес репозитория и полный коммит, исходники скачиваются с GitHub при первом запуске стенда и сверяются по хешу дерева. Выгрузки `*/export.xlsx` содержат только номера находок, правила, пути, номера строк, компоненты и версии; колонка Source code пустая и заполняется на компьютере студента из скачанных файлов.

## Примеры

| № | Пример | Репозиторий и коммит | Лицензия | SAST | SCA | Лицензии |
|---|---|---|---|---|---|---|
| 1 | OWASP Juice Shop | https://github.com/juice-shop/juice-shop (`c9f99228d9d56afb5f5ca7925376292f7fa44b13`) | MIT | 80 | 57 | 24 |
| 2 | OWASP WebGoat | https://github.com/WebGoat/WebGoat (`4e98f1cbbf896fdd06edcc9930515ebe0ade7c69`) | GPL-2.0-or-later | 80 | 36 | 8 |
| 3 | PyGoat | https://github.com/adeyosemanputra/pygoat (`2aa4cc14f251e4a780e94e200aed6b36a5b15c21`) | MIT | 80 | 60 | 11 |
| 4 | OWASP NodeGoat | https://github.com/OWASP/NodeGoat (`c5cb68a7084e4ae7dcc60e6a98768720a81841e8`) | Apache-2.0 | 28 | 60 | 30 |
| 5 | DVWA | https://github.com/digininja/DVWA (`502ac150ce37c20ca6e04cab7c5ca959f315f2d0`) | GPL-3.0-or-later | 80 | 0 | 0 |
| 6 | OWASP RailsGoat | https://github.com/OWASP/railsgoat (`f5951f13089d85c979de09e7da3c8c0fb982f94a`) | MIT | 17 | 60 | 0 |
| 7 | Damn Vulnerable GraphQL Application | https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application (`a961308c02d1fb462b192681c336b0739e432da7`) | MIT | 13 | 56 | 10 |
| 8 | go-test-bench | https://github.com/Contrast-Security-OSS/go-test-bench (`92445700823205281369911a72b7127f18c8c9ed`) | MIT | 26 | 60 | 0 |
| 9 | VulnerableLightApp | https://github.com/Aif4thah/VulnerableLightApp (`8998b55caab6a4a5bb2d725ad054c797c7d101f4`) | GPL-3.0-only | 9 | 1 | 0 |
| 10 | OWASP crAPI | https://github.com/OWASP/crAPI (`b5fc307f3e5f875809b095b771108ef342a33724`) | Apache-2.0 | 80 | 60 | 30 |

Лицензия каждого примера установлена по файлу LICENSE и разделу о лицензии README закреплённой ревизии. Примеры распространяют их авторы; стенд скачивает их с GitHub по запросу.

## Анализаторы

- SAST: Semgrep CE 1.181.1, учебные правила examples/rules – движок Semgrep CE (LGPL-2.1, https://github.com/semgrep/semgrep) с собственными учебными правилами репозитория (`examples/rules`, лицензия MIT); правила реестра Semgrep не используются.
- SAST Python: Bandit 1.8.6 (Apache-2.0, https://github.com/PyCQA/bandit).
- SAST Go: gosec 2.22.10 (Apache-2.0, https://github.com/securego/gosec).
- SCA и лицензии компонентов: OSV-Scanner 2.2.4 (Apache-2.0, https://github.com/google/osv-scanner). Уязвимости – из базы OSV (https://osv.dev), лицензии компонентов – из deps.dev (https://deps.dev) на дату сборки.

## Данные OSV

Префиксы идентификаторов записей OSV, вошедших во входы каталога, по примерам (источник записи – по префиксу: GHSA – GitHub Advisory Database, PYSEC – PyPI Advisory Database, GO – Go Vulnerability Database и т. д.):

- OWASP Juice Shop: GHSA
- OWASP WebGoat: GHSA
- PyGoat: GHSA, PYSEC
- OWASP NodeGoat: GHSA, MAL
- DVWA: записей нет
- OWASP RailsGoat: GHSA
- Damn Vulnerable GraphQL Application: GHSA, PYSEC
- go-test-bench: GHSA, GO
- VulnerableLightApp: GHSA
- OWASP crAPI: GHSA, GO, PYSEC

Условия использования данных – по таблице источников OSV (https://google.github.io/osv.dev/data/):

| Префикс | Источник | Лицензия данных |
|---|---|---|
| GHSA | GitHub Advisory Database, https://github.com/github/advisory-database | CC-BY 4.0 |
| GO | Go Vulnerability Database, https://pkg.go.dev/vuln/ | CC-BY 4.0 |
| MAL | OpenSSF Malicious Packages, https://github.com/ossf/malicious-packages | Apache 2.0 |
| PYSEC | PyPI Advisory Database, https://github.com/pypa/advisory-database | CC-BY 4.0 |

## Учебная политика лицензий

Находка листа SCA Compliance – компонент, лицензия которого не входит в перечень разрешительных лицензий учебной политики (`scripts/examples/sca_step.py`, ALLOWED_LICENSES). Сильный копилефт (GPL, AGPL и др.) – High, слабый копилефт (LGPL, MPL, EPL, OFL и др.) – Medium, прочие и компоненты без сведений о лицензии – Low. У экосистем, по которым deps.dev сведений о лицензиях не даёт (RubyGems, Packagist), отсутствие лицензии находкой не считается.

## Что не вошло в выгрузки

- OWASP Juice Shop: SAST, вендорские и собранные файлы – 11; SAST, повтор той же строки – 1; SAST, сверх предела – 16; SAST, тесты – 59
- OWASP WebGoat: SAST, вендорские и собранные файлы – 113; SAST, сверх предела – 1
- PyGoat: SAST, повтор той же строки – 52; SAST, сверх предела – 22; SCA, сверх предела – 130
- OWASP NodeGoat: SCA, сверх предела – 251; лицензии, сверх предела – 17
- DVWA: SAST, вендорские и собранные файлы – 1; SAST, повтор той же строки – 1; SAST, сверх предела – 116; лицензии, нет данных о лицензиях экосистемы – 6
- OWASP RailsGoat: SAST, вендорские и собранные файлы – 15; SAST, повтор той же строки – 1; SCA, сверх предела – 54; лицензии, нет данных о лицензиях экосистемы – 167
- Damn Vulnerable GraphQL Application: SAST, повтор той же строки – 10
- go-test-bench: SAST, повтор той же строки – 5; SCA, псевдопакет Go (stdlib, toolchain) – 128; SCA, сверх предела – 7; лицензии, нет данных о лицензиях экосистемы – 1
- VulnerableLightApp: SAST, повтор той же строки – 1
- OWASP crAPI: SAST, повтор той же строки – 19; SAST, сверх предела – 59; SAST, тесты – 19; SCA, псевдопакет Go (stdlib, toolchain) – 162; SCA, сверх предела – 339; лицензии, нет данных о лицензиях экосистемы – 2; лицензии, сверх предела – 15; манифест services/identity/build.gradle.kts – экосистема gradle не поддерживается сборщиком (нет файла блокировки)

Предел выгрузки: до 80 находок SAST (по кругу между правилами), до 60 строк SCA (сначала рабочие зависимости и больший CVSS), до 30 находок о лицензиях. Строка SCA без разрешённой версии в выгрузку не идёт: снимки разрешения зависимостей лежат во входах `*/inputs/lock/`.

---
title: "Тестовые проекты без AppSec.Hub: клон с GitHub, открытый анализатор, своя выгрузка"
type: guide
status: active
date: 2026-10-25
tags: [demo, sast, sca, hub-format, training]
related: [DEMO.md, hub-format.md, external-providers.md]
---

# Тестовые проекты без AppSec.Hub

Чтобы показать полный цикл работы приложения – от выгрузки до разбора находок с кодом и исследования компонентов –
доступ к AppSec.Hub не нужен. Приложение принимает выгрузку формата Hub как обычный файл `.xlsx`
([hub-format.md](hub-format.md)), а исходники для разбора – это клон репозитория в корне папок с репозиториями.
Два сценария в `scripts/` собирают такую выгрузку из отчётов открытых анализаторов по намеренно уязвимым
проектам с GitHub: PyGoat, OWASP Juice Shop и OWASP WebGoat.

Отличия от настоящей выгрузки Hub: номера находок – синтетические (сценарий нумерует их сам от `--start-id`),
категории – от анализатора (Bandit, Semgrep), а не от Hub; лист SCA строится по манифесту зависимостей и открытой
базе OSV, а не по анализатору состава Hub. На работу приложения это не влияет: демонстрационная выгрузка
`examples/demo` устроена так же.

## Что нужно

- окружение разработки (`.venv`, см. README) и Docker (для Semgrep: образ `semgrep/semgrep`, свой Semgrep на
  Windows не ставится);
- Bandit в окружении разработки: `.venv\Scripts\python -m pip install bandit` (только для Python-проектов);
- доступ в интернет на время подготовки: клонирование, правила Semgrep, запросы к OSV. Загрузка готового файла
  выгрузки и разбор локальной моделью в интернет не ходят; внешний профиль и исследование провайдером (шаг 5) –
  отдельное решение с отметкой и согласием, как описано в [external-providers.md](external-providers.md).

Папка тестовых проектов – вне репозитория приложения, например `<корень клонов>` = папка `triage-test-projects` на диске с клонами
(в примерах ниже – `test-projects`). Она же становится корнем папок с репозиториями приложения
(`.\start.ps1 -ReposRoot <корень клонов>`); демо-репозитории из `examples/demo/repos` можно скопировать туда же,
чтобы демо-проекты продолжали находить свои папки.

## Порядок

1. **Клон.** `git clone --depth 1 <адрес> test-projects/<имя>` – имя папки клона будет именем кодовой базы в
   выгрузке.
2. **Находки SAST.**
   - Python: `.venv\Scripts\python -m bandit -r test-projects/pygoat -f json -o test-projects/pygoat-bandit.json
     -q --exclude test-projects/pygoat/Solutions`;
   - любой язык, Semgrep из образа Docker (папка клона подключается только для чтения):
     `docker run --rm -v <корень клонов>/pygoat:/src:ro -v <корень клонов>:/out -w /src semgrep/semgrep
     semgrep scan --config p/python --config p/owasp-top-ten --json --metrics=off -o /out/pygoat-semgrep.json .`
     (для Java – `p/java`, `p/security-audit`; для JavaScript/TypeScript – `p/javascript`, `p/typescript`,
     `p/nodejs`).
3. **Компоненты с уязвимостями** (лист «SCA Security»):
   `.venv\Scripts\python scripts/osv_sca_csv.py --requirements test-projects/pygoat/requirements.txt --out
   test-projects/pygoat-sca.csv` (`--package-lock`, `--package-json`, `--pom` – для npm и Maven; у `pom.xml` берутся
   зависимости с версией в `<version>`, в `<properties>` или в `<dependencyManagement>` этого же файла – версии из
   родительского BOM сценарий не разрешает; комментарии, профили и плагины не считаются;
   у `package.json` без файла блокировки диапазон `^`, `~`, `>=` сводится к нижней границе, и это записывается в
   колонку `note` и в категорию находки). Оценка CVSS – число из записи OSV или базовая оценка по вектору CVSS 3.x;
   версия исправления – из диапазона OSV, в который попадает версия компонента. На компонент берётся не больше
   `--limit` (5) уязвимостей, усечение отмечается в `note`. Запрос к OSV не удался – компонент пропущен, код выхода 2:
   такой CSV неполон, повторить сбор.
4. **Выгрузка.** `.venv\Scripts\python scripts/make_hub_from_sast.py --app "PyGoat" --codebase pygoat --language
   Python --bandit … --semgrep … --source-root test-projects/pygoat --sca … --out test-projects/pygoat-hub.xlsx`
   (номера находок – с 900001; у Juice Shop – `--start-id 700001`, у WebGoat – `--start-id 800001`). Пути из отчётов
   приводятся к путям внутри клона: всё до папки `pygoat/` снимается, откуда бы ни запускались анализаторы, а с
   `--source-root` берётся тот вариант пути, файл которого есть в клоне (имя клона бывает и папкой внутри проекта –
   у WebGoat это пакет `org/owasp/webgoat`). Строка кода находки Semgrep без входа в учётную запись Semgrep в отчёте –
   заглушка «requires login»: с `--source-root` строка берётся из файла клона. Язык находки – по файлу (Dockerfile,
   HTML, TypeScript…), `--language` – для остальных. Одна находка на (файл, строка): срабатывания Bandit и Semgrep на
   одной строке не дублируются; критичность Bandit HIGH/MEDIUM/LOW и Semgrep ERROR/WARNING/INFO переводится в
   High/Medium/Low.
   - **Исправлено 25.10:** выгрузки до исправления несли у всех находок Semgrep строку «requires
     login» (модель получала «фрагмент не найден рядом со строкой находки»), язык всей выгрузки у Dockerfile и
     шаблонов, а у WebGoat 43 пути из 45 вели к несуществующим файлам. Выгрузки пересобраны с прежними номерами
     находок (у WebGoat 4 номера сдвинулись: порядок – по пути файла); прежние лежат рядом с суффиксом
     `.before-fix-20261025`. Проекты, загруженные из прежних выгрузок, нужно загрузить заново.
5. **В приложении.** Новый проект → загрузить `…-hub.xlsx` → папка с клонами: корень (`.`) или папка проекта, кодовая
   база подбирается по имени папки → триаж (Ollama или внешний профиль с отметкой «код не секретный») → «Компоненты» →
   «Собрать задание» → исследование файлом или провайдером.

## Что получилось 25.10.2026

| Проект | Язык | Срабатываний анализаторов | SAST в выгрузке (High/Medium/Low) | SCA (OSV) |
|---|---|---|---|---|
| PyGoat (`adeyosemanputra/pygoat`) | Python/Django | Bandit 30, Semgrep 18 | 33 (7/3/23) в 14 файлах | 32 компонента, 57 уязвимостей |
| OWASP Juice Shop (`juice-shop/juice-shop`) | TypeScript/Node.js | Semgrep 43 | 26 (7/19/0) в 19 файлах | 64 компонента (нижние границы диапазонов), 29 уязвимостей |
| OWASP WebGoat (`WebGoat/WebGoat`) | Java/Spring | Semgrep 70 | 45 (16/29/0) в 31 файле | 24 компонента с версией в файле (явной, из `<properties>` или `<dependencyManagement>`), 5 уязвимостей (xstream 1.4.5, усечено по пределу) |

## Эталон: известные ответы по тестовым проектам

Выгрузки по анализаторам показывают цикл, но не дают известных ответов – для замера
вердиктов нужен эталон. Сборщик `scripts/bench/build_cases_projects.py` строит набор в схеме стенда замера
([model-benchmark.md](model-benchmark.md)) и, по желанию, выгрузки формата Hub из тех же случаев:

- **OWASP Juice Shop – по авторским меткам.** В коде проекта авторы помечают строки комментариями
  `vuln-code-snippet vuln-line <задание>` (строка намеренно уязвима) и `vuln-code-snippet neutral-line <задание>`
  (строка внутри уязвимого фрагмента, но не уязвимая); задание – в `data/static/challenges.yml` (название,
  категория, сложность). Сборщик даёт случай «истинная» на каждую `vuln-line` и «ложная (допустимо «неясно»)» на
  каждую `neutral-line` – второе толкование наше, не авторское; класс CWE по категории задания – тоже наше
  соответствие (у авторов классов нет). Метка стоит в самой строке комментарием, то есть **модель видит
  подсказку**; в наборе такие случаи помечены `hint_comment`, как подсказки в OWASP Benchmark. На клоне 25.10.2026:
  33 уязвимые строки и 64 нейтральные в 11 файлах (TypeScript и YAML); 97 находок в `juice-shop-known-hub.xlsx`.
- **PyGoat и WebGoat – вручную.** Список уязвимых строк по лабораториям и урокам (`--known ФАЙЛ.json`: проект,
  урок, файл, строка, текст строки, CWE, обоснование, уверенность) сборщик сверяет с файлом клона: нет файла или
  строки, не совпал текст – запись отклоняется с замечанием. Уверенность ниже высокой даёт «допустимо «неясно»».
  Список 25.10.2026 (`known-pygoat-webgoat.json` в папке клонов, в репозиторий не кладётся – в нём строки чужого
  кода): PyGoat v3.0.0 – 33 записи (лаборатории живут в `dockerized_labs/*` и `challenge/labs/*`; в
  `introduction/views.py` только показ страниц), WebGoat – 59 записей (уроки `sqlinjection`, `xss`, `pathtraversal`,
  `deserialization`, `jwt`, `xxe`, `idor`, `cryptography`, `passwordreset`, `challenges`, `commandinjection` и др.;
  уроки без уязвимой серверной строки – `bypassrestrictions`, `htmltampering`, `securepasswords` – в список не
  вошли). Каждая запись проверена сборщиком по тексту строки; выборочно – чтением кода.

```powershell
.venv\Scripts\python -I -B scripts/bench/build_cases_projects.py --juice-shop <корень клонов>/juice-shop `
    --known <корень клонов>/known-pygoat-webgoat.json --pygoat <корень клонов>/pygoat --webgoat <корень клонов>/webgoat `
    --hub-out <корень клонов>
```

Результат – `results/bench/cases-projects.json` и `cases_meta-projects.json` (в репозиторий не кладутся: там
абсолютные пути и строки чужого кода); прогон через стенд – `run_bench.py --cases results/bench/cases-projects.json`.

Срабатываний больше, чем находок в выгрузке: убраны папки сборки и инфраструктуры (`.github`, `terraform`,
`infrastructure`) и повторы на одной строке файла. Лицензии проектов – их собственные (PyGoat и WebGoat – GPL/MIT
по их репозиториям, Juice Shop – MIT); клоны и отчёты анализаторов в репозиторий приложения не копируются.

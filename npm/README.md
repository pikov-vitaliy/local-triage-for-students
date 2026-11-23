# Local Triage – training stand · Локальный триаж – учебный стенд

**[English](#english)** · **[Русский](#русский)**

The interface is in English by default; Russian is available in Settings, under Interface language.
Интерфейс по умолчанию на английском; русский включается в «Settings», раздел «Interface language».

# English

## What it is

Security analyzers scan code and flag suspicious places: a possible SQL injection, a password written straight into
the code, an outdated library with a known vulnerability. There are usually hundreds of such findings, and some of them
are false. Someone has to go through each one: look at the code, decide whether the problem is real and record the
decision. This work is called **triage**.

Local Triage is a training stand for learning it. It comes with ten open training applications that contain deliberate
vulnerabilities, plus ready-made scan results for them. You open a finding, read the code and the language model's
hint, and make the decision yourself: "False positive" or "Confirm defect".

What you triage on the stand:

- **SAST** – findings in the source code (injections, cross-site scripting, path traversal, secrets in code and more);
- **SCA** – vulnerabilities in third-party components the application uses (for example, an old library version);
- **component licences** – components whose licence terms have to be taken into account.

Everything runs on your computer, in the browser. The stand installs with one command, no Docker needed.

## Before you start

1. **A computer** with Windows 10 or 11 (64-bit) or Linux. The stand has not been tested on macOS. Windows on ARM
   processors is not supported.
2. **Node.js 20 or newer.**

   On Windows, Node.js installs with one PowerShell command, no need to visit the website:

   ```powershell
   winget install OpenJS.NodeJS.LTS
   ```

   If Windows asks for permission to make changes, answer "Yes". After the installation, close the terminal window and
   open a new one, otherwise the `node` and `npm` commands will not be found. To check: `node -v` should print v20 or
   higher. If you already have an older Node.js, update it with one command too: `winget upgrade OpenJS.NodeJS.LTS`.
   If winget is disabled on the computer, download the LTS installer from https://nodejs.org/ and run it with the
   default settings.

3. **About 2 GB of free disk space and internet access** on the first start: the stand downloads Python and everything
   else it needs by itself.

## Installation and first start

1. Open a terminal: PowerShell on Windows (press Start and type "PowerShell"), Terminal on Linux.
2. Type the command and press Enter:

   ```
   npx local-triage
   ```

   If you see the question `Ok to proceed? (y)`, press `y` and Enter.

3. Wait a few minutes. The window shows lines about the installation progress. When everything is ready, the line
   "The stand is running: http://127.0.0.1:8765/" appears and the browser opens the stand. If port 8765 is busy, the
   stand takes the next free one – the number will be different, so open the address from that line. If the browser
   does not open, copy the address into the browser yourself.
4. **Keep the terminal window open while you work.** The stand runs in it. Close the window and the stand stops.
5. When you finish, press Ctrl+C in the terminal window or just close it. All your decisions are saved.

Next time, start the stand with the same `npx local-triage` command: it takes a few seconds.

Terminal messages are in English by default; `npx local-triage --lang ru` shows them in Russian.

## First steps on the stand

### 1. Connect a language model

The model reads the code of a finding and suggests its verdict. You can also work without a model: you make the
decisions, just without the hint.

In the stand, open the **Examples** tab, the **Getting started** block, and choose one of two options.

- **Ollama – a model on your computer.** Suitable if your graphics card has 16 GB of memory or more. The code stays on
  your computer.
  1. Install Ollama from https://ollama.com.
  2. In a terminal, run `ollama pull gpt-oss:20b` – the model is downloaded once, it takes several gigabytes.
  3. In the stand, click the "Ollama on this computer" preset link, then **Check** and **Save**.
- **DeepSeek – a model on the internet.** Suitable for any computer. You need your own DeepSeek API key
  (https://platform.deepseek.com); requests to the model are paid.
  1. Get a key in your DeepSeek account and set a spending limit there right away.
  2. In the stand, click the DeepSeek preset link: the address, the model and the **Advanced** section (reasoning,
     limits, search) are already filled in with recommended values, and every field has a hint. If you created a
     DeepSeek profile earlier, open it, expand **Advanced** and press **Fill in recommended DeepSeek values**.
  3. Paste the key into the **Key** field, press **Check**, then **Save**.

  Code goes to DeepSeek only for a project marked "code is not secret". Projects of the training examples get this
  mark right away: the ten downloadable examples have open code, and Demo Library is made up. You can remove the mark
  in **Project settings**. The data is processed by the provider in China.

When the interface is in English, the model writes its explanations in English as well.

![The Getting started block on the Examples tab](https://raw.githubusercontent.com/pikov-vitaliy/local-triage-for-students/main/docs/images/stand/02-start.png)

![The DeepSeek profile preset](https://raw.githubusercontent.com/pikov-vitaliy/local-triage-for-students/main/docs/images/stand/03-preset-deepseek.png)

In the same block, choose the saved profile in the **Profile for examples** field and press **Save** – then the model
connects by itself to every new project created from the ten training applications. Demo Library uses the default
profile: a different profile is chosen in its project settings. If the stand is started with `--local-only`, an
external profile (DeepSeek) is not assigned to new projects – they get the default profile; if that one is external
too, choose Ollama for triage in the project settings.

### 2. Choose an example and create a project

The **Examples** tab has cards for the training applications: OWASP Juice Shop, OWASP WebGoat, PyGoat, OWASP NodeGoat,
DVWA, OWASP RailsGoat, DVGA, go-test-bench, VulnerableLightApp, OWASP crAPI. There is also a small made-up example,
Demo Library – a good place to start.

![The Examples tab](https://raw.githubusercontent.com/pikov-vitaliy/local-triage-for-students/main/docs/images/stand/01-examples.png)

1. After the first start, the stand downloads the source code of the examples from GitHub by itself. Wait until the
   card shows that the example is downloaded. If it says "Not downloaded", press **Download**.
2. Press **Create project**. The stand loads the example's findings and opens the project page.

Each example has one project. Once it is created, the card shows **Open project** instead of **Create project**: your
decisions on the findings are kept in it.

### 3. Triage the findings

1. On the project page, open the **Findings** tab – the list of all project findings; SAST findings in the code are
   under the **Kind** filter set to "SAST" (or the **Unreviewed** selection).
2. Open a finding. The card shows the rule that fired, the vulnerability class (CWE) with a link to its description,
   and the code around the flagged line. **Open in VS Code** opens the file at that line if the VS Code editor is
   installed.
3. Press **Analyze with the model** to get a hint, or work it out yourself.
4. Choose a decision: **False positive** (with a short reason) or **Confirm defect**.
5. Component vulnerabilities are on the **SCA** tab; licence findings are in the general findings list, kind
   "SCA, licences".

![The project's findings list](https://raw.githubusercontent.com/pikov-vitaliy/local-triage-for-students/main/docs/images/stand/05-findings.png)

![A finding card](https://raw.githubusercontent.com/pikov-vitaliy/local-triage-for-students/main/docs/images/stand/06-card.png)

![Component licence findings](https://raw.githubusercontent.com/pikov-vitaliy/local-triage-for-students/main/docs/images/stand/07-licenses.png)

Detailed help and a glossary are behind the **Help** button in the top bar of the stand.

## Where the files are

The stand creates two folders:

- **The code folder** – the `local-triage` folder in your home folder: `%USERPROFILE%\local-triage` on Windows,
  `~/local-triage` on Linux. It holds the source code of the examples. You can open this folder in VS Code and change
  the code: the stand does not touch your edits. To get a clean copy of an example, press **Download again** on its
  card – the new copy appears next to the old one, and the old one stays.
- **The service folder** – `%LOCALAPPDATA%\local-triage` on Windows, `~/.local/share/local-triage` on Linux. It holds
  the database with your decisions, Python and the logs. Nothing in it needs changing.

The `npx local-triage --where` command shows both folders with full paths. On Windows, a path like
`%USERPROFILE%\local-triage` can be pasted into the File Explorer address bar to open the folder.

## By design

This behaviour may look like a bug, but it is intentional.

- **The model's analysis details are collapsed.** The model's verdict, its confidence and the summary are always
  visible at the top of the card. Only the **Analysis details** section is collapsed – what the code does, why the
  verdict is what it is, the data path. Expand it once and the stand remembers: it stays open in other cards too.
- **"Re-analyze with a model" and "Move to archive" are inside collapsed blocks.** These are rare actions: a repeated
  analysis keeps the model busy for a long time (the "Re-analyze with a model" block on the finding card), and the
  archive removes a project from the list (the **Project settings** block). They sit in collapsed blocks so that
  nobody presses them by accident; archiving asks for confirmation first. Deleting a project is there as well, in
  **Project settings**, and leads to a separate confirmation page.
- **An example cannot have a second project.** Each example has one project, which keeps your decisions. Once the
  project exists, the example card shows **Open project**. For a clean copy of the code, use **Download again** – your
  decisions are not lost.
- **Vulnerability feeds load one at a time.** While one archive is being processed, the **Upload** buttons on the other
  cards are unavailable. Wait until it is done and load the next one.
- **GitHub shows hundreds of vulnerability alerts.** They refer to the dependency snapshots of the training examples
  (`examples/catalog/*/inputs/lock`): Juice Shop, WebGoat and the other applications are vulnerable on purpose, and
  students learn to triage SCA findings on these snapshots. The stand itself does not install or run these
  dependencies.
- **After the stand is killed in Task Manager, the next start waits.** The stand prints "A previous app process still
  holds the data folder – waiting for its lock mark to expire…" and continues by itself in less than a minute,
  connecting to its database. No decisions are lost. The normal way to stop it is Ctrl+C in the stand window or
  closing the window.
- **Earlier decisions and model answers keep their language.** Switching the interface language does not translate
  what is already saved. To get a model answer in the new language, analyze the finding with the model again.

## If something goes wrong

- **The `npx` command is not found.** Node.js is not installed, or the terminal was opened before the installation.
  Install Node.js with `winget install OpenJS.NodeJS.LTS`, close the terminal and open it again.
- **The stand is already running in another window.** Then `npx local-triage` just opens the browser with the running
  stand: a second stand is not needed.
- **An example does not download.** Direct internet access to github.com is required. Press **Retry** on the card.
- **Environment check:** `npx local-triage --doctor` checks the environment and prints the result.
- The logs are in the `logs` folder of the service folder – you can attach them to a question to your teacher.

## Command options

Usually no options are needed. They go after the command, for example `npx local-triage --no-open`.

| Option | What it does |
|---|---|
| `--no-open` | do not open the browser on start |
| `--port 8800` | open the stand on this port; without it the stand takes the first free port starting from 8765 |
| `--local-only` | forbid models on the internet (DeepSeek): only models on your computer and on the local network work |
| `--lang ru` | terminal messages in Russian (`en` – in English, the default) |
| `--where` | show where the stand's folders are |
| `--doctor` | check the environment |
| `--new-database` | start with a clean database; the previous one is kept in the service folder, in `pg\backups` |
| `--home FOLDER` | keep the service files in another folder – this gives a separate stand with its own database; use a new empty folder |
| `--code-dir FOLDER` | a different code folder; set on the first start and not changed afterwards |
| `--version`, `--help` | version and short help |

## What the stand does not do

- **It does not send decisions to external systems.** In organisations, the results of all analyzers are collected in
  an ASOC system (Application Security Orchestration and Correlation). One such system is AppSec.Hub, and the Local
  Triage application can send decisions to it. The training stand has no such connection: all decisions stay only in
  the database on your computer. The example findings are prepared in the AppSec.Hub export format, which is why the
  program mentions "Hub" and "Transfer to Hub (ASOC)".
- **It does not work through a proxy server.** The stand connects to DeepSeek and to GitHub (example downloads)
  directly.
- **On Linux it does not start as root** – start it as a regular user.

## Restore the database from before the update

When a new version of the stand comes out, it may update the database structure. Before that, the stand saves a copy of
the previous database in the `pg\backups\<copy name>` folder of the service folder. Next to it are the file
`<copy name>.json` (the `npm_version` field holds the stand version that worked with this database) and the file
`<copy name>.pg.pw` – the password of this database. To go back to the copy:

1. Close the stand window.
2. In the service folder, rename the `pg\data` folder to `pg\data-new` and the `secrets\pg.pw` file to
   `secrets\pg.pw-new`.
3. Rename the copy folder to `pg\data`, and copy its password file `<copy name>.pg.pw` to `secrets\pg.pw`.
4. Start the stand version given in the `npm_version` field: `npx local-triage@<version>`. If it says `unknown`, you
   can find the version in the `logs\supervisor-<date>.log` log for the day this database was in use. If the previous
   version cannot be started, the new version updates the database again, and a copy from before the update is saved
   again.

Copies made by the `--new-database` option are named `<time>-replaced-v<version>`: the database and the password are
inside the copy folder (`data` and `pg.pw`), and the version is in the `<copy name>.json` file.

## How to remove the stand

1. Close the stand window.
2. Find the service folder: `npx local-triage --where`. If it contains a `uv` folder, the stand installed Python with
   the uv program, and the downloaded Python and the uv cache are outside the service folder. Before deleting the
   service folder, check where they are: run `uv\uv.exe python dir` and `uv\uv.exe cache dir` from the service folder
   (`uv/uv` on Linux). Delete those folders if you no longer need uv. If there is no `uv` folder, the stand installed
   Python without uv and this step is not needed.
3. Delete the service folder.
4. Delete the code folder only if it holds none of your work.

## For those who want to look at the stand's code

The source code is at https://github.com/pikov-vitaliy/local-triage-for-students. To run the stand from source you
also need Git:

```
git clone https://github.com/pikov-vitaliy/local-triage-for-students.git
cd local-triage-for-students
npm install
npx local-triage
```

The sources of the training examples and their licences are in `examples/catalog/NOTICE.md`.

---

# Русский

Интерфейс стенда по умолчанию на английском. Чтобы включить русский, откройте «Settings», в разделе «Interface
language» выберите «Русский» и нажмите «Save language»: выбор сохраняется в базе стенда. Названия кнопок ниже даны
по-русски – так они выглядят после переключения.

## Что это

Программы проверки безопасности кода (анализаторы) находят в нём подозрительные места: возможную SQL-инъекцию,
пароль, записанный прямо в коде, устаревшую библиотеку с известной уязвимостью. Таких находок обычно сотни, и часть из
них ложные. Человек должен разобрать каждую: посмотреть код, понять, есть ли настоящая проблема, и записать решение.
Этот разбор называется **триажем**.

Учебный стенд «Локальный триаж» – приложение, на котором этому учатся. В нём уже есть десять открытых учебных
приложений с намеренно оставленными уязвимостями и готовые результаты их проверки. Вы открываете находку, смотрите код,
читаете подсказку языковой модели и принимаете решение сами: «ложное срабатывание» или «подтверждаю дефект».

Что разбирается на стенде:

- **SAST** – находки в исходном коде (инъекции, межсайтовый скриптинг, обход пути, секреты в коде и другие);
- **SCA** – уязвимости сторонних компонентов, которые использует приложение (например, старая версия библиотеки);
- **лицензии компонентов** – компоненты, условия лицензии которых нужно учитывать.

Всё работает на вашем компьютере, в браузере. Стенд ставится одной командой, Docker не нужен.

## Что нужно заранее

1. **Компьютер:** Windows 10 или 11 (64-разрядная) или Linux. На macOS стенд не проверялся. Windows на процессорах ARM
   не поддерживается.
2. **Node.js версии 20 или новее.**

   На Windows Node.js ставится одной командой в PowerShell, на сайт заходить не нужно:

   ```powershell
   winget install OpenJS.NodeJS.LTS
   ```

   Если Windows спросит разрешение на изменения, ответьте «Да». После установки закройте окно терминала и откройте
   новое, иначе команды `node` и `npm` не найдутся. Проверка: `node -v` – должно быть v20 или больше. Node.js уже
   стоит, но старый – обновите его так же одной командой: `winget upgrade OpenJS.NodeJS.LTS`. Если winget на
   компьютере отключён, скачайте установщик LTS с https://nodejs.org/ и пройдите его с настройками по умолчанию.

3. **Около 2 ГБ свободного места и интернет** при первом запуске: стенд сам скачает Python и всё, что ему нужно.

## Установка и первый запуск

1. Откройте терминал: на Windows – PowerShell (нажмите «Пуск», наберите «PowerShell»), на Linux – «Терминал».
2. Введите команду и нажмите Enter:

   ```
   npx local-triage
   ```

   Если появится вопрос `Ok to proceed? (y)`, нажмите `y` и Enter.

3. Подождите несколько минут. В окне будут появляться строки о ходе установки. Когда всё будет готово, появится строка
   «The stand is running: http://127.0.0.1:8765/» (с ключом `--lang ru` – «Стенд работает: …») и откроется браузер со страницей стенда. Если порт 8765 занят, стенд
   сам возьмёт следующий свободный – номер будет другим, открывайте адрес из этой строки. Если браузер не открылся,
   скопируйте этот адрес в браузер сами.
4. **Не закрывайте окно терминала, пока работаете.** В нём работает стенд. Закрыли окно – стенд остановился.
5. Закончили работу – нажмите в окне терминала Ctrl+C или просто закройте окно. Все ваши решения сохраняются.

В следующий раз запускайте стенд той же командой `npx local-triage`: запуск займёт несколько секунд.

## Первые шаги в стенде

### 1. Подключите языковую модель

Модель читает код находки и предлагает свой вердикт. Без модели тоже можно работать: решения принимаете вы, просто
без подсказки.

Откройте в стенде вкладку **«Примеры»**, блок **«Начало работы»**, и выберите один из двух вариантов.

- **Ollama – модель на вашем компьютере.** Подходит, если у видеокарты 16 ГБ памяти или больше. Код никуда не уходит.
  1. Установите Ollama с https://ollama.com.
  2. В терминале выполните `ollama pull gpt-oss:20b` – модель скачивается один раз, это несколько гигабайт.
  3. В стенде нажмите ссылку «заготовка «Ollama на этом компьютере»», затем «Проверить» и «Сохранить».
- **DeepSeek – модель в интернете.** Подходит для любого компьютера. Нужен свой ключ API DeepSeek
  (https://platform.deepseek.com), запросы к модели платные.
  1. Получите ключ в кабинете DeepSeek и сразу поставьте там лимит расхода.
  2. В стенде нажмите ссылку «заготовка DeepSeek»: адрес, модель и раздел «Дополнительно» (рассуждение, пределы,
     поиск) уже заполнены рекомендуемыми значениями, у каждого поля – подсказка. Если профиль DeepSeek создан раньше,
     откройте его, раскройте «Дополнительно» и нажмите «Подставить рекомендуемые значения DeepSeek».
  3. Вставьте ключ в поле «Ключ», нажмите «Проверить», затем «Сохранить».

  Код уходит в DeepSeek только у проекта с отметкой «код не секретный». Проекты учебных примеров получают её сразу:
  у десяти скачиваемых примеров код открытый, у Demo Library – выдуманный. Снять отметку можно в «Параметрах
  проекта». Данные обрабатываются провайдером в Китае.

![Блок «Начало работы» на вкладке «Примеры»](https://raw.githubusercontent.com/pikov-vitaliy/local-triage-for-students/main/docs/images/stand/ru/02-start.png)

![Заготовка профиля DeepSeek](https://raw.githubusercontent.com/pikov-vitaliy/local-triage-for-students/main/docs/images/stand/ru/03-preset-deepseek.png)

В том же блоке выберите сохранённый профиль в поле **«Профиль для примеров»** и нажмите «Сохранить» – тогда модель
будет подключаться к каждому новому проекту из десяти учебных приложений сама. Demo Library работает с профилем по
умолчанию: другой профиль выбирается в параметрах её проекта. Если стенд запущен с `--local-only`, внешний профиль
(DeepSeek) новым проектам не назначается – они получают профиль по умолчанию; если и он внешний, выберите для разбора
Ollama в параметрах проекта.

### 2. Выберите пример и создайте проект

На вкладке «Примеры» – карточки учебных приложений: OWASP Juice Shop, OWASP WebGoat, PyGoat, OWASP NodeGoat, DVWA,
OWASP RailsGoat, DVGA, go-test-bench, VulnerableLightApp, OWASP crAPI. Есть и небольшой выдуманный пример Demo Library –
с него удобно начать.

![Вкладка «Примеры»](https://raw.githubusercontent.com/pikov-vitaliy/local-triage-for-students/main/docs/images/stand/ru/01-examples.png)

1. После первого запуска стенд сам скачивает исходный код примеров с GitHub. Подождите, пока на карточке появится
   «Скачан». Если написано «Не скачан», нажмите «Скачать».
2. Нажмите **«Создать проект»**. Стенд загрузит находки примера и откроет страницу проекта.

У каждого примера один проект. Когда он уже создан, на карточке вместо «Создать проект» стоит «Открыть проект»: ваши
решения по находкам хранятся в нём.

### 3. Разберите находки

1. На странице проекта откройте вкладку **«Находки»** – общий список находок проекта; находки SAST в коде – фильтр
   «Вид»: «SAST» (или подборка «Непроверенные»).
2. Откройте находку. В карточке – правило, которое сработало, класс уязвимости (CWE) со ссылкой на описание и код
   вокруг строки срабатывания. Кнопка **«Открыть в VS Code»** открывает файл на нужной строке, если установлен
   редактор VS Code.
3. Нажмите «Разобрать моделью», чтобы получить подсказку, или разберитесь сами.
4. Выберите решение: **«Ложное срабатывание»** (с короткой причиной) или **«Подтверждаю дефект»**.
5. Уязвимости компонентов – на вкладке **«SCA»**, находки о лицензиях – в общем списке находок, вид «SCA, лицензии».

![Список находок проекта](https://raw.githubusercontent.com/pikov-vitaliy/local-triage-for-students/main/docs/images/stand/ru/05-findings.png)

![Карточка находки](https://raw.githubusercontent.com/pikov-vitaliy/local-triage-for-students/main/docs/images/stand/ru/06-card.png)

![Находки о лицензиях компонентов](https://raw.githubusercontent.com/pikov-vitaliy/local-triage-for-students/main/docs/images/stand/ru/07-licenses.png)

Подробная справка и словарь терминов – кнопка **«Справка»** в верхней строке стенда.

## Где лежат файлы

Стенд создаёт две папки:

- **Папка кода** – папка `local-triage` в вашей личной папке: `%USERPROFILE%\local-triage` на Windows,
  `~/local-triage` на Linux. Здесь лежит исходный код
  примеров. Эту папку можно открыть в VS Code и менять код: стенд ваши правки не трогает. Чтобы получить чистую копию
  примера, нажмите на его карточке «Скачать заново» – новая копия появится рядом, старая останется.
- **Служебная папка** – `%LOCALAPPDATA%\local-triage` на Windows, `~/.local/share/local-triage` на Linux. Здесь база с вашими решениями, Python и журналы. Менять в ней ничего не нужно.

Команда `npx local-triage --where` покажет обе папки полными путями. На Windows путь вида `%USERPROFILE%\local-triage`
можно вставить в адресную строку Проводника – откроется нужная папка.

## Так задумано

Это поведение может показаться ошибкой, но оно намеренное.

- **Подробности разбора модели свёрнуты.** Вердикт модели, её уверенность и итог всегда видны вверху карточки. Свёрнут только раздел «Подробности разбора» – что делает код, почему такой вердикт, путь данных. Раскройте его один раз, и стенд запомнит: дальше он будет открыт и в других карточках.
- **«Пересмотреть моделью» и «Убрать в архив» спрятаны в свёрнутых блоках.** Это редкие действия: повторный разбор надолго занимает модель (блок «Пересмотреть моделью» в карточке находки), архив убирает проект из списка (блок «Параметры проекта»). Чтобы их не нажали случайно, они лежат в свёрнутых блоках; архив перед действием спрашивает подтверждение. «Удалить проект» – там же, в «Параметрах проекта», и ведёт на отдельную страницу подтверждения.
- **У примера нельзя создать второй проект.** У каждого примера один проект: в нём хранятся ваши решения. Когда проект создан, на карточке примера стоит «Открыть проект». Чистая копия кода – кнопка «Скачать заново», решения при этом не пропадают.
- **Справочники загружаются по одному.** Пока разбирается один архив, кнопки «Загрузить» в других карточках недоступны. Дождитесь строки «Готово» и загрузите следующий.
- **GitHub показывает сотни предупреждений об уязвимостях.** Они относятся к снимкам зависимостей учебных примеров (`examples/catalog/*/inputs/lock`): Juice Shop, WebGoat и другие приложения уязвимы нарочно, по этим снимкам студенты учатся разбирать находки SCA. Сам стенд эти зависимости не устанавливает и не запускает.
- **После снятия стенда через Диспетчер задач следующий запуск ждёт.** Стенд пишет «A previous app process still holds the data folder – waiting…» (с `--lang ru` – «Прежний процесс приложения ещё держит папку данных – жду…») и меньше чем через минуту продолжает сам, подключаясь к своей базе. Решения не теряются. Обычная остановка – Ctrl+C в окне стенда или закрыть окно.
- **Прежние решения и ответы модели остаются на своём языке.** Смена языка интерфейса не переводит сохранённое. Чтобы получить ответ модели на новом языке, разберите находку моделью заново.

## Если что-то пошло не так

- **Команда `npx` не найдена.** Node.js не установлен или терминал открыт до установки. Установите Node.js командой
  `winget install OpenJS.NodeJS.LTS`, закройте
  терминал и откройте его снова.
- **Стенд уже запущен в другом окне.** Тогда команда `npx local-triage` просто откроет браузер со стендом: второй
  стенд не нужен.
- **Пример не скачивается.** Нужен прямой доступ в интернет к github.com. Нажмите на карточке «Повторить».
- **Проверка окружения:** `npx local-triage --doctor` проверит окружение и напечатает результат.
- Журналы работы лежат в папке `logs` служебной папки – их можно приложить к вопросу преподавателю.

## Параметры команды

Обычно параметры не нужны. Пишутся после команды, например `npx local-triage --no-open`.

| Параметр | Что делает |
|---|---|
| `--no-open` | не открывать браузер при запуске |
| `--port 8800` | открыть стенд на заданном порту; без этого ключа стенд сам берёт первый свободный порт, начиная с 8765 |
| `--local-only` | запретить модели в интернете (DeepSeek): работают только модели на вашем компьютере и в локальной сети |
| `--lang ru` | сообщения в терминале по-русски (`en` – по-английски, по умолчанию) |
| `--where` | показать, где лежат папки стенда |
| `--doctor` | проверить окружение |
| `--new-database` | начать с чистой базы; прежняя база сохраняется в служебной папке, в `pg\backups` |
| `--home ПАПКА` | держать служебные файлы в другой папке – получится отдельный стенд со своей базой; указывайте новую пустую папку |
| `--code-dir ПАПКА` | другая папка кода; задаётся при первом запуске и потом не меняется |
| `--version`, `--help` | версия и краткая справка |

## Что стенд не умеет

- **Не передаёт решения во внешние системы.** В организациях результаты всех анализаторов собирают в системе класса
  ASOC (Application Security Orchestration and Correlation – оркестрация и корреляция результатов анализа
  защищённости). Одна из таких систем – AppSec.Hub, и приложение «Локальный триаж» умеет отправлять в неё решения. На
  учебном стенде этой связи нет: все решения остаются только в базе на вашем компьютере. Находки примеров подготовлены
  в формате выгрузки AppSec.Hub, поэтому в программе встречаются слова «Hub» и «Перенос в Hub (ASOC)».
- **Не работает через прокси-сервер.** К DeepSeek и к GitHub (скачивание примеров) стенд подключается напрямую.
- **На Linux не запускается от пользователя root** – запускайте от обычного пользователя.

## Вернуть базу, какой она была до обновления

Когда выходит новая версия стенда, она может обновить устройство базы. Перед этим стенд сохраняет копию прежней базы
в папке `pg\backups\<имя копии>` служебной папки. Рядом лежат файл `<имя копии>.json` (в поле `npm_version` – версия
стенда, которая работала с этой базой) и файл `<имя копии>.pg.pw` – пароль этой базы. Чтобы вернуться к копии:

1. Закройте окно стенда.
2. В служебной папке переименуйте папку `pg\data` в `pg\data-new` и файл `secrets\pg.pw` в `secrets\pg.pw-new`.
3. Переименуйте папку копии в `pg\data`, а её файл пароля `<имя копии>.pg.pw` скопируйте в `secrets\pg.pw`.
4. Запустите ту версию стенда, что указана в поле `npm_version`: `npx local-triage@<версия>`. Если там `unknown`,
   версию можно найти в журнале `logs\supervisor-<дата>.log` за день, когда работала эта база, в строке
   «Учебный стенд «Локальный триаж» … (пакет npm <версия>)». Если запустить прежнюю версию нельзя, новая версия снова
   обновит базу, а копия до обновления опять сохранится.

Копии, которые делает параметр `--new-database`, называются `<время>-replaced-v<версия>`: база и пароль лежат внутри
папки копии (`data` и `pg.pw`), версия – в файле `<имя копии>.json`.

## Как удалить стенд

1. Закройте окно стенда.
2. Узнайте служебную папку: `npx local-triage --where`. Если в ней есть папка `uv`, стенд ставил Python через
   программу uv, и скачанный Python и кэш uv лежат вне служебной папки. До удаления служебной папки посмотрите, где
   они: запустите `uv\uv.exe python dir` и `uv\uv.exe cache dir` из служебной папки (на Linux – `uv/uv`). Эти папки
   удалите, если uv вам больше не нужен. Если папки `uv` нет, стенд ставил Python без uv – этот шаг не нужен.
3. Удалите служебную папку.
4. Папку кода удаляйте, только если в ней нет вашей работы.

## Для тех, кто хочет посмотреть код стенда

Исходный код – https://github.com/pikov-vitaliy/local-triage-for-students. Чтобы запустить стенд из исходников, нужен
ещё Git:

```
git clone https://github.com/pikov-vitaliy/local-triage-for-students.git
cd local-triage-for-students
npm install
npx local-triage
```

Источники учебных примеров и их лицензии – в файле `examples/catalog/NOTICE.md`.

# Local Triage – training stand for SAST and SCA triage

**English** · [Русский](README.ru.md)

A training stand for secure development courses. Static analysis (SAST) and software composition analysis (SCA)
findings are triaged in the browser: the student reads the code and the language model's hint, decides whether a
finding is a false positive or a confirmed defect, and drafts the defect text. Ten open, deliberately vulnerable
applications (OWASP Juice Shop, WebGoat, PyGoat, NodeGoat, DVWA, RailsGoat, DVGA, go-test-bench, VulnerableLightApp,
crAPI) and a small made-up Demo Library come with ready scan results.

The interface is in English by default; Russian is available in Settings, under Interface language.

## Quick start

One command, no Docker (Windows 10/11 or Linux, Node.js 20 or newer):

```
npx local-triage
```

The stand downloads Python and everything else it needs on the first start and opens the browser. The full guide –
installation, connecting a model (Ollama on your computer or DeepSeek), first steps, files, options, troubleshooting –
is in [npm/README.md](npm/README.md).

## Docker installation and AppSec.Hub

The application can also run in Docker and exchange decisions with AppSec.Hub (an ASOC system). That mode, the
architecture notes and the rest of the documentation are in Russian: see [README.ru.md](README.ru.md) and
[docs/README.md](docs/README.md).

## About the GitHub vulnerability alerts

GitHub vulnerability alerts in this repository refer to the dependency snapshots of the training examples
(`examples/catalog/*/inputs/lock`): Juice Shop, WebGoat and the other applications are vulnerable on purpose, and
students learn to triage SCA findings on these snapshots. The stand itself does not install or run these
dependencies.

## License

MIT – see [LICENSE](LICENSE). Third-party components and the sources of the training examples are listed in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) and [examples/catalog/NOTICE.md](examples/catalog/NOTICE.md).

"""Modelfile для моделей замера, собранных из весов с hf.co или из другой модели Ollama (modelfiles/models.json).

Зачем: у части моделей с hf.co Ollama берёт шаблон диалога из файла GGUF, и вызов с полем think или с ответом
по схеме JSON работает не так, как у моделей из библиотеки Ollama. Для замера такие модели пересобирались:
  * остаются веса модели (первая строка FROM); проектор для картинок (вторая FROM) убирается, если в описании
    keep_projector = false, – иначе модель занимает больше видеопамяти, чем при замере;
  * шаблон (TEMPLATE), стоп-слова и параметры выборки из исходного Modelfile убираются;
  * добавляются RENDERER и PARSER встроенного шаблона Ollama и параметры из описания.

Порядок (Ollama на этом компьютере, модель-источник уже скачана: ollama pull <source>):
    .venv\\Scripts\\python -I -B scripts/bench/make_modelfile.py qwen38-27b-iq3            # только Modelfile
    .venv\\Scripts\\python -I -B scripts/bench/make_modelfile.py qwen38-27b-iq3 --create   # и ollama create

Modelfile пишется в results/bench/modelfiles/<имя>.Modelfile: строки FROM в нём – пути к весам на этом компьютере,
в репозиторий он не кладётся.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
from pathlib import Path  # noqa: E402

HERE = Path(__file__).resolve().parent
MODELS_FILE = HERE / "modelfiles" / "models.json"
OUT_DIR = HERE.parent.parent / "results" / "bench" / "modelfiles"
# Параметры исходного Modelfile, которые заменяются параметрами из описания
DROP_PARAMS = {"stop", "temperature", "top_p", "top_k", "num_ctx", "min_p", "repeat_penalty", "presence_penalty"}


def _closed(text: str) -> bool:
    """Есть ли в text неэкранированная закрывающая кавычка."""
    i = 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            return True
        i += 1
    return False


def transform(text: str, spec: dict) -> tuple[str, list[str]]:
    """Исходный Modelfile (вывод ollama show --modelfile) -> (новый Modelfile, отброшенные строки FROM)."""
    lines = text.splitlines()
    out: list[str] = []
    dropped: list[str] = []
    froms = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        s = line.strip()
        head = s.split(None, 1)
        word = head[0].upper() if head else ""
        rest = head[1] if len(head) > 1 else ""
        if not s or s.startswith("#"):
            i += 1
            continue
        if word == "FROM":
            froms += 1
            if froms == 1 or spec.get("keep_projector"):
                out.append(s)
            else:
                dropped.append(s)
            i += 1
            continue
        if word in ("TEMPLATE", "RENDERER", "PARSER", "SYSTEM", "LICENSE"):
            # значение – в одну строку, в кавычках или в тройных кавычках на несколько строк
            if rest.startswith('"""'):
                i += 1
                if '"""' not in rest[3:]:
                    while i < len(lines) and '"""' not in lines[i]:
                        i += 1
                    i += 1
                continue
            if rest.startswith('"') and not _closed(rest[1:]):
                i += 1
                while i < len(lines) and not _closed(lines[i]):
                    i += 1
                i += 1
                continue
            i += 1
            continue
        if word == "PARAMETER":
            parts = s.split()
            if len(parts) > 1 and parts[1].lower() in DROP_PARAMS:
                i += 1
                continue
        out.append(s)
        i += 1
    if froms < 1:
        raise ValueError("в исходном Modelfile нет строки FROM")
    out += [f"RENDERER {spec['renderer']}", f"PARSER {spec['parser']}"]
    out += [f"PARAMETER {k} {v}" for k, v in (spec.get("parameters") or {}).items()]
    return "\n".join(out) + "\n", dropped


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    models = json.loads(MODELS_FILE.read_text(encoding="utf-8"))["models"]
    p = argparse.ArgumentParser(description="Modelfile для модели замера из modelfiles/models.json.")
    p.add_argument("name", choices=sorted(models), help="имя модели в Ollama после ollama create")
    p.add_argument("--create", action="store_true", help="сразу выполнить ollama create")
    p.add_argument("--out-dir", type=Path, default=OUT_DIR, help="куда записать Modelfile (по умолчанию "
                                                                  "results/bench/modelfiles)")
    args = p.parse_args(argv)
    spec = models[args.name]
    ollama = shutil.which("ollama")
    if not ollama:
        print("Нет команды ollama: Modelfile готовится на компьютере с Ollama.", file=sys.stderr)
        return 2
    shown = subprocess.run([ollama, "show", "--modelfile", spec["source"]], capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    if shown.returncode != 0:
        print(f"ollama show {spec['source']} не удался: {shown.stderr.strip()}\nСначала: ollama pull "
              f"{spec['source']}", file=sys.stderr)
        return 2
    text, dropped = transform(shown.stdout, spec)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{args.name}.Modelfile"
    out.write_text(text, encoding="utf-8", newline="\n")
    for line in dropped:
        print(f"убрано: {line}")
    print(f"Записано: {out}\n{text}")
    command = [ollama, "create", args.name, "-f", str(out)]
    if not args.create:
        print("Создать модель: ollama create " + args.name + " -f " + str(out))
        return 0
    return subprocess.run(command).returncode


if __name__ == "__main__":
    sys.exit(main())

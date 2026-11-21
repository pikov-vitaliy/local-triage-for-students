"""Фоновые задачи каталога: распаковка архивов поставщиков, импорт настроек, восстановление корзины."""

import base64
import pickle
import subprocess

import yaml

UPLOAD_DIR = "/srv/catalog/uploads"


def unpack_supplier_archive(filename: str) -> None:
    command = f"tar -xzf {UPLOAD_DIR}/{filename} -C {UPLOAD_DIR}/unpacked"
    subprocess.run(command, shell=True, check=True)


def load_import_settings(text: str) -> dict:
    settings = yaml.safe_load(text) or {}
    return {"currency": settings.get("currency", "RUB"), "batch": int(settings.get("batch", 100))}


def restore_cart(cookie_value: str) -> dict:
    data = base64.b64decode(cookie_value)
    return pickle.loads(data)

"""Файлы миграций неизменны: сумма каждого файла записана в базе при применении, и правка даже комментария
останавливает запуск со старой базой (app/storage/migrate.py). Новая миграция – новым файлом и новой строкой ниже."""

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "app" / "storage" / "migrations"
FROZEN = {
    "postgresql/0001_baseline.sql": "de2e0569eadc3d57dfb02a994ef604971e2b0fe2add6a0c5fec9decc57ff7652",
    "postgresql/0002_feeds_and_secrets.sql": "47747a4b6940a2005749c851aed5a298c0f82496f3c2abcab4b3cbe2e9473b7e",
    "postgresql/0003_project_mask_display.sql": "6c3724f54e2cf99096db5bab16a5f32583e00ed5e39e32fb2c33fb8f1aa19652",
    "postgresql/0004_package_identity.sql": "40f9b609d5f6e3fa199ea04434815862dca4dae35aedfcb36a4aa26282feebfb",
}


def test_applied_migrations_are_byte_identical():
    for rel, digest in FROZEN.items():
        assert hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() == digest, f"изменён файл уже применённой миграции {rel}"


def test_every_migration_file_is_pinned():
    present = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*.sql")}
    assert present == set(FROZEN), sorted(present ^ set(FROZEN))

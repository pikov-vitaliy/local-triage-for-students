"""Перевод позиционных «?» в маркеры драйвера (app/storage/sql.py): литералы, комментарии, проценты."""

from __future__ import annotations

import pytest

from app.storage.sql import PlaceholderError, translate


@pytest.mark.parametrize("sql, text, count", [
    ("SELECT 1", "SELECT 1", 0),
    ("SELECT * FROM t WHERE a = ? AND b = ?", "SELECT * FROM t WHERE a = %s AND b = %s", 2),
    ("SELECT '?' , ?", "SELECT '?' , %s", 1),
    ("SELECT 'it''s ?', ?", "SELECT 'it''s ?', %s", 1),
    ('SELECT "col?" FROM t WHERE a = ?', 'SELECT "col?" FROM t WHERE a = %s', 1),
    ("SELECT a -- ? комментарий\nFROM t WHERE b = ?", "SELECT a -- ? комментарий\nFROM t WHERE b = %s", 1),
    ("SELECT a /* ? */ FROM t WHERE b = ?", "SELECT a /* ? */ FROM t WHERE b = %s", 1),
    ("a LIKE 'SCA%' AND b = ?", "a LIKE 'SCA%%' AND b = %s", 1),
    ("a ILIKE '%already has%' AND b = ?", "a ILIKE '%%already has%%' AND b = %s", 1),
    ("a % 2 = ?", "a %% 2 = %s", 1),
    ("-- 100%\nSELECT ?", "-- 100%%\nSELECT %s", 1),
    ("/* 5% */ SELECT ?", "/* 5%% */ SELECT %s", 1),
])
def test_translate(sql: str, text: str, count: int):
    assert translate(sql) == (text, count)


def test_numbered_placeholder_is_refused():
    with pytest.raises(PlaceholderError):
        translate("SELECT ?1")


def test_unterminated_literal_does_not_hang():
    assert translate("SELECT 'abc")[1] == 0

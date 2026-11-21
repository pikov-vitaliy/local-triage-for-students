"""Поиск и выдача карточек товаров каталога."""

import sqlite3

PAGE_SIZE = 50


def _as_dict(row) -> dict:
    return {"id": row[0], "title": row[1], "price": row[2]}


def search_products(conn: sqlite3.Connection, term: str, page: int = 0) -> list[dict]:
    offset = max(0, page) * PAGE_SIZE
    query = (f"SELECT id, title, price FROM product WHERE title LIKE '%{term}%' "
             f"ORDER BY title LIMIT {PAGE_SIZE} OFFSET {offset}")
    rows = conn.execute(query).fetchall()
    return [_as_dict(row) for row in rows]


def get_product(conn: sqlite3.Connection, product_id: int) -> dict | None:
    row = conn.execute("SELECT id, title, price FROM product WHERE id = ?", (product_id,)).fetchone()
    if row is None:
        return None
    return _as_dict(row)

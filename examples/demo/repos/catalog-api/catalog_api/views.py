"""Обработчики запросов каталога."""

from catalog_api import products, tasks


def search(request, conn) -> list[dict]:
    term = request.args.get("q", "")
    page = int(request.args.get("page", "0"))
    return products.search_products(conn, term, page)


def product_card(request, conn, product_id: int) -> dict | None:
    return products.get_product(conn, product_id)


def cart(request) -> dict:
    return tasks.restore_cart(request.cookies.get("cart", ""))

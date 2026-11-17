import pytest
from playwright.sync_api import sync_playwright

from account_access.errors import AccessError
from account_access.public_demo import configuration, inventory_result


@pytest.fixture(scope="module")
def page():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        yield page
        browser.close()


def markup(name="Public backpack", price="$29.99"):
    return ("<div data-test='inventory-list'><div data-test='inventory-item'>"
            f"<div data-test='inventory-item-name'>{name}</div>"
            "<div data-test='inventory-item-desc'>Do not return this description</div>"
            f"<div data-test='inventory-item-price'>{price}</div>"
            "<button>Add to cart</button></div></div>")


def result(page):
    account = configuration().accounts['sauce-standard']
    return inventory_result(page, account.operations['inventory'], account)


def test_only_names_and_prices_are_read_from_the_reviewed_example(page):
    page.set_content(markup())
    assert result(page) == {'items': [{'name': 'Public backpack', 'price': '$29.99'}]}


@pytest.mark.parametrize('html', [
    '', markup() + markup(), markup('', '$1.00'), markup('x' * 257), markup(price='call us'),
    markup().replace("<div data-test='inventory-item-price'>", "<div data-test='other'>"),
    markup().replace("<button>", "<span data-test='inventory-item-name'>duplicate</span><button>"),
    "<div data-test='inventory-list'></div>",
    "<div data-test='inventory-list'>" + "<div data-test='inventory-item'></div>" * 33 + "</div>",
])
def test_changed_or_ambiguous_example_layout_refuses_without_broad_text_fallback(page, html):
    page.set_content(html)
    with pytest.raises(AccessError, match='public_example_layout_changed'):
        result(page)


def test_unrelated_operations_keep_their_approved_extractor(page):
    account = configuration().accounts['sauce-standard']
    op = account.operations['inventory'].model_copy(deep=True)
    op.url = 'https://www.saucedemo.com/other'
    assert inventory_result(page, op, account) is None
    op = account.operations['inventory'].model_copy(deep=True)
    op.fields = {'approved': '#explicitly-approved'}
    assert inventory_result(page, op, account) is None

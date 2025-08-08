import pytest
from playwright.sync_api import Page, expect
import time

from .test_auth import UNIQUE_EMAIL

@pytest.mark.dependency(depends=["test_successful_login"])
def test_bread_workflow_for_calculations(page: Page):
    page.goto("http://localhost:8000/static/login.html")
    page.get_by_label("Email:").fill(UNIQUE_EMAIL)
    page.get_by_label("Password:").fill("password123")
    page.get_by_role("button", name="Login").click()

    expect(page).to_have_url("http://localhost:8000/static/calculations.html")
    expect(page.get_by_role("heading", name="My Calculations")).to_be_visible()

    page.get_by_placeholder("Value A").fill("10")
    page.get_by_placeholder("Value B").fill("5")
    page.get_by_role("combobox").select_option("add")
    page.get_by_role("button", name="Save Calculation").click()

    list_item = page.locator("#calcList li").first
    expect(list_item).to_contain_text("10 add 5 = 15")

    calc_id = list_item.get_by_role("button", name="Edit").get_attribute("data-id")
    assert calc_id is not None

    list_item.get_by_role("button", name="Edit").click()
    expect(page.get_by_placeholder("Value A")).to_have_value("10")
    
    page.get_by_placeholder("Value B").fill("3")
    page.get_by_role("combobox").select_option("multiply")
    page.get_by_role("button", name="Save Calculation").click()

    expect(list_item).to_contain_text("10 multiply 3 = 30")

    list_item.get_by_role("button", name="Delete").click()
    page.on("dialog", lambda dialog: dialog.accept())

    expect(page.locator("#calcList li")).to_have_count(0)
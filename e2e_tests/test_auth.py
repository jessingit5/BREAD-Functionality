import pytest
from playwright.sync_api import Page, expect
import time

UNIQUE_EMAIL = f"testuser_{int(time.time())}@example.com"

def test_successful_registration(page: Page):
    page.goto("http://localhost:8000/static/register.html")

    page.get_by_label("Username:").fill("testuser")
    page.get_by_label("Email:").fill(UNIQUE_EMAIL)
    page.get_by_label("Password:").fill("password123")
    page.get_by_role("button", name="Register").click()

    success_message = page.locator("#message")
    expect(success_message).to_have_text("Registration successful! You can now log in.")

def test_registration_with_short_password(page: Page):
    page.goto("http://localhost:8000/static/register.html")
    
    page.get_by_label("Username:").fill("shortpassuser")
    page.get_by_label("Email:").fill("shortpass@example.com")
    page.get_by_label("Password:").fill("123")
    page.get_by_role("button", name="Register").click()
    
    error_message = page.locator("#message")
    expect(error_message).to_have_text("Password must be at least 8 characters long.")

def test_successful_login(page: Page):
    page.goto("http://localhost:8000/static/login.html")
    
    page.get_by_label("Email:").fill(UNIQUE_EMAIL)
    page.get_by_label("Password:").fill("password123")
    
    page.get_by_role("button", name="Login").click()
    
    expect(page).to_have_url("http://localhost:8000/static/calculations.html")
   
    expect(page.get_by_role("heading", name="My Calculations")).to_be_visible()

def test_login_with_wrong_password(page: Page):
    page.goto("http://localhost:8000/static/login.html")
    
    page.get_by_label("Email:").fill(UNIQUE_EMAIL)
    page.get_by_label("Password:").fill("wrongpassword")
    
    page.get_by_role("button", name="Login").click()
    
    error_message = page.locator("#message")
    expect(error_message).to_have_text("Error: Incorrect email or password")
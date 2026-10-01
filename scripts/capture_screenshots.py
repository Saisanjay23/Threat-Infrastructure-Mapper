"""Capture high-resolution screenshots of Threat Infrastructure Mapper (TIM) via SPA navigation."""

import time
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:4000"
OUT_DIR = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
OUT_DIR.mkdir(parents=True, exist_ok=True)

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1600, "height": 950},
            color_scheme="dark",
            device_scale_factor=2,  # Crisp high-DPI quality
        )
        page = context.new_page()

        print("[*] Navigating to login...")
        page.goto(f"{BASE_URL}/login")
        page.wait_for_selector("#username", timeout=10000)

        # Log in
        page.fill("#username", "admin")
        page.fill("#password", "ChangeMe!2026")
        page.click("button[type='submit']")

        print("[*] Waiting for dashboard...")
        page.wait_for_url(f"{BASE_URL}/", timeout=10000)
        time.sleep(3)  # Allow dashboard cards & charts to load

        # 1. Dashboard
        page.screenshot(path=str(OUT_DIR / "dashboard.png"))
        print("[+] Captured dashboard.png")

        # 2. Investigations List (SPA navigation)
        print("[*] Navigating to Investigations...")
        page.click('a[href="/investigations"]')
        time.sleep(3)
        page.screenshot(path=str(OUT_DIR / "investigations.png"))
        print("[+] Captured investigations.png")

        # 3. Investigation Detail (click first row link)
        print("[*] Opening first investigation...")
        try:
            first_inv = page.locator("table tbody tr td a").first
            first_inv.click()
            time.sleep(3)
            page.screenshot(path=str(OUT_DIR / "investigation_detail.png"))
            print("[+] Captured investigation_detail.png")
        except Exception as e:
            print("[-] Could not open investigation detail:", e)

        # 4. Graph Explorer (SPA navigation)
        print("[*] Navigating to Graph Explorer...")
        page.click('a[href="/graph"]')
        time.sleep(4)  # Allow React Flow layout to calculate positions
        page.screenshot(path=str(OUT_DIR / "graph_explorer.png"))
        print("[+] Captured graph_explorer.png")

        # 5. Clusters (SPA navigation)
        print("[*] Navigating to Threat Clusters...")
        page.click('a[href="/clusters"]')
        time.sleep(3)
        page.screenshot(path=str(OUT_DIR / "clusters.png"))
        print("[+] Captured clusters.png")

        # 6. Providers (SPA navigation)
        print("[*] Navigating to Providers...")
        page.click('a[href="/providers"]')
        time.sleep(3)
        page.screenshot(path=str(OUT_DIR / "providers.png"))
        print("[+] Captured providers.png")

        browser.close()
        print("[+] All screenshots successfully captured!")

if __name__ == "__main__":
    main()

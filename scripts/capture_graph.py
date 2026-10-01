"""Capture real, populated interactive Graph Explorer screenshot with nodes and edges."""

import time
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:4000"
OUT_DIR = Path(__file__).resolve().parent.parent / "docs" / "screenshots"

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1600, "height": 950},
            color_scheme="dark",
            device_scale_factor=2,
        )
        page = context.new_page()

        print("[*] Logging in...")
        page.goto(f"{BASE_URL}/login")
        page.wait_for_selector("#username", timeout=10000)
        page.fill("#username", "admin")
        page.fill("#password", "ChangeMe!2026")
        page.click("button[type='submit']")

        page.wait_for_url(f"{BASE_URL}/", timeout=10000)
        time.sleep(2)

        # Go to investigations
        print("[*] Navigating to Investigations...")
        page.click('a[href="/investigations"]')
        time.sleep(2)

        # Open the first completed investigation
        print("[*] Opening first investigation...")
        first_inv = page.locator("table tbody tr td a").first
        first_inv.click()
        time.sleep(2.5)

        # Click Open graph
        print("[*] Clicking Open Graph...")
        open_graph_btn = page.locator('a:has-text("Open graph")')
        open_graph_btn.click()
        
        # Wait for ReactFlow to fetch graph payload and render canvas
        print("[*] Waiting for React Flow canvas to render...")
        time.sleep(4)
        page.wait_for_selector(".react-flow__node", timeout=10000)
        
        node_count = page.locator(".react-flow__node").count()
        edge_count = page.locator(".react-flow__edge").count()
        print(f"[+] Loaded {node_count} nodes and {edge_count} edges into view!")

        # Click on a prominent node to open the Evidence Sidebar with correlation scores
        try:
            page.locator(".react-flow__node").first.click()
            time.sleep(1)
        except Exception as e:
            print("[-] Could not select node:", e)

        # Take screenshot of the populated graph
        graph_path = OUT_DIR / "graph_explorer.png"
        page.screenshot(path=str(graph_path))
        print(f"[+] Successfully captured rich graph screenshot to: {graph_path.name}")

        browser.close()

if __name__ == "__main__":
    main()

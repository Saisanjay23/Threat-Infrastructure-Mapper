"""
Threat Infrastructure Mapper (TIM) - Unified Runner
===================================================

Run the complete application (Web UI + Backend API) with one simple command:

    python run.py                     # Start on default port 8000
    python run.py --port 9000          # Start on custom port 9000
    python run.py --host 0.0.0.0       # Bind to all network interfaces
    python run.py --share              # Launch with free public Cloudflare tunnel
    python run.py --no-browser         # Don't auto-open browser
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIR = ROOT_DIR / "frontend"
DIST_DIR = FRONTEND_DIR / "dist"
SCRIPTS_DIR = ROOT_DIR / "scripts"

# Locate virtual environment python
if sys.platform == "win32":
    VENV_PYTHON = BACKEND_DIR / ".venv" / "Scripts" / "python.exe"
    CLOUDFLARED = ROOT_DIR / "cloudflared.exe"
    if not CLOUDFLARED.exists():
        CLOUDFLARED = SCRIPTS_DIR / "cloudflared.exe"
else:
    VENV_PYTHON = BACKEND_DIR / ".venv" / "bin" / "python"
    CLOUDFLARED = ROOT_DIR / "cloudflared"


def ensure_venv() -> None:
    """If running with global Python, automatically re-execute with the project's venv."""
    if VENV_PYTHON.exists():
        current_exe = Path(sys.executable).resolve()
        target_exe = VENV_PYTHON.resolve()
        if current_exe != target_exe:
            # Re-spawn inside venv
            cmd = [str(target_exe), str(Path(__file__).resolve()), *sys.argv[1:]]
            try:
                sys.exit(subprocess.call(cmd))
            except KeyboardInterrupt:
                sys.exit(0)


def check_mongo(host: str = "127.0.0.1", port: int = 27017) -> bool:
    """Quick check if MongoDB is reachable."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex((host, port)) == 0


def ensure_frontend_built() -> None:
    """Ensure frontend production build exists so FastAPI can serve it."""
    if not (DIST_DIR / "index.html").exists():
        print("[*] Building frontend assets (first run)...")
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        subprocess.run([npm_cmd, "run", "build"], cwd=str(FRONTEND_DIR), check=True)
        print("[+] Frontend build complete.")


def start_tunnel(port: int) -> None:
    """Start optional Cloudflare tunnel."""
    if not CLOUDFLARED.exists():
        print("[!] cloudflared executable not found. Skipping tunnel.")
        return

    def _tunnel():
        print("[*] Starting Cloudflare Tunnel...")
        subprocess.run([str(CLOUDFLARED), "tunnel", "--url", f"http://127.0.0.1:{port}"])

    threading.Thread(target=_tunnel, daemon=True).start()


def open_browser(url: str, delay: float = 1.2) -> None:
    """Open user's default browser after server initializes."""
    def _open():
        time.sleep(delay)
        webbrowser.open(url)
    threading.Thread(target=_open, daemon=True).start()


def main() -> None:
    ensure_venv()

    parser = argparse.ArgumentParser(description="Threat Infrastructure Mapper (TIM)")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the application on (default: 8000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface to bind to (default: 127.0.0.1)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    parser.add_argument("--share", action="store_true", help="Launch a public Cloudflare tunnel")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the browser")
    args = parser.parse_args()

    # Pre-flight checks
    if not check_mongo():
        print("[!] WARNING: MongoDB does not seem to be running on 127.0.0.1:27017.")
        print("    If you encounter database errors, please start your MongoDB service.\n")

    ensure_frontend_built()

    # Set environment variables for FastAPI backend
    os.environ["TIM_HOST"] = args.host
    os.environ["TIM_PORT"] = str(args.port)
    os.chdir(str(BACKEND_DIR))
    if str(BACKEND_DIR) not in sys.path:
        sys.path.insert(0, str(BACKEND_DIR))

    local_url = f"http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}"

    print("=" * 63)
    print("  Threat Infrastructure Mapper (TIM)")
    print("=" * 63)
    print(f"  Web UI:    {local_url}")
    print(f"  API Docs:  {local_url}/docs")
    print("  Login:     admin / ChangeMe!2026")
    if args.share:
        print("  Sharing:   Public Cloudflare tunnel enabled")
    print("=" * 63)
    print("  Press Ctrl+C to stop the server\n")

    if args.share:
        start_tunnel(args.port)

    if not args.no_browser:
        open_browser(local_url)

    import uvicorn
    try:
        uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)
    except KeyboardInterrupt:
        print("\n[*] TIM shut down cleanly.")


if __name__ == "__main__":
    main()

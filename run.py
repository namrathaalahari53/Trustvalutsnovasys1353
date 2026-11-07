"""
TrustVault Production & Development Server Runner
Listens on port 3000 host 0.0.0.0
"""
import os
import sys
import subprocess

# Self-re-exec into .venv if not already running in it
WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_PYTHON = os.path.join(WORKSPACE_DIR, ".venv", "bin", "python3")

if os.path.exists(VENV_PYTHON) and sys.executable != VENV_PYTHON:
    os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)

# If uvicorn cannot be imported directly, attempt automatic bootstrap
try:
    import uvicorn
except ImportError:
    print("[TrustVault] Bootstrapping environment dependencies...")
    reqs_file = os.path.join(WORKSPACE_DIR, "requirements.txt")
    if os.path.exists(VENV_PYTHON):
        subprocess.check_call([VENV_PYTHON, "-m", "pip", "install", "-r", reqs_file])
        os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)
    else:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--break-system-packages", "-r", reqs_file])
    import uvicorn

if __name__ == "__main__":
    port = 3000
    host = "0.0.0.0"

    # Check for custom port in args if provided
    for i, arg in enumerate(sys.argv):
        if arg in ("--port", "-p") and i + 1 < len(sys.argv):
            try:
                port = int(sys.argv[i + 1])
            except ValueError:
                pass
        elif arg.startswith("--port="):
            try:
                port = int(arg.split("=")[1])
            except ValueError:
                pass

    print(f"Starting TrustVault on http://{host}:{port} ...")
    uvicorn.run("app.main:app", host=host, port=port, log_level="info")


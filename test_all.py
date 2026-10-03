import subprocess
import time
import requests
import os
import sys

env = os.environ.copy()

server = subprocess.Popen([r".venv\Scripts\python", "-m", "uvicorn", "backend.api.main:app_factory", "--host", "127.0.0.1", "--port", "8000", "--env-file", ".env"], env=env)
try:
    print("Waiting for server...")
    time.sleep(5)
    resp = requests.get("http://127.0.0.1:8000/api/v1/health")
    print("Health check:", resp.json())

    # run npm test in extension/
    ext_env = env.copy()
    ext_env["PG_API"] = "http://127.0.0.1:8000"
    ext_env["PG_SCAN_KEY"] = "Pr7u7KCAppF2Y6pjnT83N83tNxMcCnQcYIYuRygSBIc"
    ext_env["PG_ADMIN_KEY"] = "6Q78hM4a_Cq_0sP89szUoMO7V5SddPZMgiwOXqkMed8"

    print("Running extension tests...")
    res = subprocess.run("npm test", cwd="extension", env=ext_env, capture_output=True, text=True, shell=True)
    print("Extension tests exit code:", res.returncode)
    print("Extension stdout:")
    print(res.stdout)
    if res.stderr:
        print("Extension stderr:")
        print(res.stderr)
finally:
    server.terminate()

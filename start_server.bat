@echo off
call .venv\Scripts\activate.bat
python -m uvicorn backend.api.main:app_factory --host 127.0.0.1 --port 8000 --env-file .env

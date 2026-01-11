bash:
	docker run --rm \
	-w /app \
	-v ./:/app \
	-p 8000:8000 \
	-it python:3.11 bash

venv:
    python3 -m venv .venv

install:
    source .venv/bin/activate && uv sync

precommit:
    source .venv/bin/activate && pre-commit run --all-files

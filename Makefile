.PHONY: test lint build verify-injection install

install:
	uv sync --extra dev || uv pip install -e ".[dev]"

test:
	uv run pytest

lint:
	uv run ruff check .

build:
	uv build

# Verify the prompt-injection defense: the same agent, ungoverned vs. governed.
verify-injection:
	uv run python demos/injection/demo.py

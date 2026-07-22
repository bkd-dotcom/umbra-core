.PHONY: test lint demo demo-json install

install:
	uv sync --extra dev || uv pip install -e ".[dev]"

test:
	uv run pytest

lint:
	uv run ruff check .

# The one-command proof: raw agent vs. the same agent governed by umbra-core.
demo:
	uv run python demos/injection/demo.py

demo-json:
	uv run python demos/injection/demo.py --json

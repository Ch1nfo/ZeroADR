PYTHON ?= python

.PHONY: test lint typecheck check check-all

test:
	@if [ -d tests_local ]; then \
		$(PYTHON) -m pytest tests_local; \
	else \
		echo "No tests_local directory; skipping local tests"; \
	fi

lint:
	@if [ -d tests_local ]; then \
		$(PYTHON) -m ruff check src tests_local; \
	else \
		$(PYTHON) -m ruff check src; \
	fi

typecheck:
	$(PYTHON) -m mypy src

check: lint typecheck test

check-all: check

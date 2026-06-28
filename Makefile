PYTHON ?= python

.PHONY: test lint typecheck check evaluation-test evaluation-lint evaluation-typecheck check-evaluation check-all

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

evaluation-test:
	cd evaluation/agentdojo && $(PYTHON) -m pytest tests_local

evaluation-lint:
	$(PYTHON) -m ruff check evaluation/agentdojo/src evaluation/agentdojo/tests_local

evaluation-typecheck:
	$(PYTHON) -m mypy --config-file evaluation/agentdojo/pyproject.toml evaluation/agentdojo/src

check-evaluation: evaluation-lint evaluation-typecheck evaluation-test

check-all: check check-evaluation

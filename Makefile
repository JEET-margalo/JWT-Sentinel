.PHONY: help test samples demo clean fuzz export
PYTHON ?= python3

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

test:  ## Run the test suite
	$(PYTHON) -m pytest tests/

samples:  ## Regenerate the demo tokens
	$(PYTHON) data/generate_samples.py

demo:  ## Inspect the weak sample token
	$(PYTHON) -m jwtsentinel.cli inspect $$($(PYTHON) -c "import json;print(json.load(open('data/sample_tokens.json'))[0]['token'])")

fuzz:  ## Run fuzzing tests
	$(PYTHON) -m pytest tests/test_fuzz.py -v

export:  ## Export analysis as SARIF
	$(PYTHON) -m jwtsentinel.cli export --sarif --output report.sarif --token $$($(PYTHON) -c "import json;print(json.load(open('data/sample_tokens.json'))[0]['token'])")

clean:  ## Remove caches
	rm -rf .pytest_cache .ruff_cache */__pycache__ **/__pycache__
.PHONY: help install test test-integration run-cli run-ui clean

help:
	@echo "BoundaryBench Development Commands:"
	@echo "  make install           Install dependencies in virtual environment"
	@echo "  make test              Run offline unit tests"
	@echo "  make test-integration  Run live Gemma 4 Ollama integration test"
	@echo "  make run-cli           Run CLI test against vulnerable and secure modes"
	@echo "  make run-ui            Launch Streamlit web interface"
	@echo "  make clean             Clean caches and temporary artifacts"

install:
	pip install -r requirements-dev.txt
	pip install -e .

test:
	pytest -v

test-integration:
	pytest -v --run-integration

run-cli:
	python -m boundary_bench.cli

run-ui:
	streamlit run boundary_bench/ui.py

clean:
	rm -rf __pycache__ .pytest_cache build dist *.egg-info
	find . -type d -name "__pycache__" -exec rm -rf {} +

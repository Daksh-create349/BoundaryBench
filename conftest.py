import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run real local Ollama integration tests",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "integration: mark test as requiring real local Ollama model"
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-integration"):
        return
    skip_integration = pytest.mark.skip(
        reason="Skipped: pass --run-integration to run real local Ollama tests"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)

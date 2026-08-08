import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent.parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("external-smoke")
    group.addoption(
        "--run-live-llm",
        action="store_true",
        default=False,
        help="Enable opt-in live LLM smoke tests.",
    )
    group.addoption(
        "--run-zap-docker",
        action="store_true",
        default=False,
        help="Enable opt-in real ZAP Docker smoke tests.",
    )
    group.addoption(
        "--zap-docker-pull-image",
        action="store_true",
        default=False,
        help="Allow ZAP Docker smoke tests to pull the stable ZAP image when missing.",
    )

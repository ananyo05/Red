"""
Pytest configuration and fixtures.
"""

import pytest
from backend import db
from backend.scenarios import get_all_scenarios


@pytest.fixture(autouse=True)
def setup_test_db():
    """Ensure database and scenario records exist before each test."""
    db.init_db()
    scenarios_dicts = [s.to_dict() for s in get_all_scenarios()]
    db.save_scenario_metadata(scenarios_dicts)


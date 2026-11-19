"""
Tests for scenario definitions, registry, rendering, and benign utility checks.
"""

from backend.scenarios import SCENARIOS, get_all_scenarios, get_scenario, get_scenario_families


def test_scenario_registry_completeness():
    scenarios = get_all_scenarios()
    # Must have at least 10 scenarios
    assert len(scenarios) >= 10

    # Must cover at least 5 distinct families
    families = get_scenario_families()
    assert len(families) >= 5
    assert "email_assistant" in families
    assert "web_summarizer" in families
    assert "support_bot" in families
    assert "code_review_bot" in families
    assert "calendar_agent" in families


def test_scenario_fields_validity():
    for s in SCENARIOS:
        assert s.id
        assert s.family
        assert s.name
        assert s.system_prompt
        assert s.user_task
        assert s.untrusted_slot
        assert "{{INJECTION}}" in s.document_template
        assert s.attacker_goal_type in ("canary_leak", "forbidden_tool", "marker_phrase")
        assert s.attacker_goal_desc
        assert s.benign_injection_text

        # Verify template rendering
        rendered = s.render_untrusted_document("TEST_PAYLOAD")
        assert "TEST_PAYLOAD" in rendered
        assert "{{INJECTION}}" not in rendered


def test_benign_utility_checks():
    # Benign responses should pass utility checks and not trigger attack alerts
    for s in SCENARIOS:
        rendered_benign = s.render_untrusted_document(s.benign_injection_text)
        assert s.benign_injection_text in rendered_benign

        # Realistic benign answer mentioning scenario topics
        if s.family == "email_assistant":
            resp = "The email outlines Q3 planning and budget allocation for the team."
        elif s.family == "web_summarizer":
            resp = "Summary of CloudSync solutions and autonomous software backup features."
        elif s.family == "support_bot":
            resp = "I have checked your support ticket regarding the order and network status."
        elif s.family == "code_review_bot":
            resp = "Code review: verified connection pool logic and security parameters."
        else:
            resp = "The meeting with Acme has been scheduled for Tuesday."

        utility_passed, reason = s.check_benign_utility(resp, [])
        assert utility_passed is True, f"Scenario {s.id} failed benign utility check: {reason}"


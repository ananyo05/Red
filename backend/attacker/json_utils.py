"""
Robust JSON parsing and repair utilities for LLM structured outputs.

Handles common LLM formatting idiosyncrasies:
- Markdown fences (```json ... ```)
- Conversational preamble/postamble
- Trailing commas in arrays and objects
- Single quotes, unescaped newlines, and loose formatting
- Fallback heuristic extraction
"""

import json
import logging
import re
from typing import Any, Optional

logger = logging.getLogger("redloop.attacker.json_utils")


def clean_json_text(text: str) -> str:
    """Removes trailing commas and strips whitespace/fences."""
    # Remove markdown code blocks if wrapped
    cleaned = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    # Remove trailing commas: e.g. [1, 2,] or {"a": 1,}
    cleaned = re.sub(r",\s*([\]}])", r"\1", cleaned)
    return cleaned.strip()


def extract_json_substring(text: str) -> Optional[str]:
    """Finds the outermost JSON object {...} or array [...] in the text."""
    # First search for fenced block
    fence_match = re.search(r"```(?:json)?\s*([\[\{].*?[\]\}])\s*```", text, re.DOTALL | re.IGNORECASE)
    if fence_match:
        return clean_json_text(fence_match.group(1))

    # Next find outermost brackets
    start_bracket = -1
    open_char = ""
    close_char = ""

    first_brace = text.find("{")
    first_bracket = text.find("[")

    if first_brace != -1 and (first_bracket == -1 or first_brace < first_bracket):
        start_bracket = first_brace
        open_char = "{"
        close_char = "}"
    elif first_bracket != -1:
        start_bracket = first_bracket
        open_char = "["
        close_char = "]"

    if start_bracket != -1:
        end_bracket = text.rfind(close_char)
        if end_bracket > start_bracket:
            candidate = text[start_bracket : end_bracket + 1]
            return clean_json_text(candidate)

    return None


def parse_structured_json(text: str, default: Optional[Any] = None) -> Any:
    """
    Parses JSON from raw model output with multi-stage fallback and repair.
    """
    if not text or not text.strip():
        if default is not None:
            return default
        raise ValueError("Cannot parse empty response as JSON")

    # 1. Direct parse attempt
    try:
        return json.loads(text.strip())
    except Exception:
        pass

    # 2. Extract substring and clean
    extracted = extract_json_substring(text)
    if extracted:
        try:
            return json.loads(extracted)
        except Exception:
            pass

        # 3. Aggressive repairs (handle unescaped newlines in string literals)
        try:
            # Replace unescaped newlines inside strings
            repaired = re.sub(r'(?<!\\)\n', r'\\n', extracted)
            # Fix trailing commas again
            repaired = re.sub(r",\s*([\]}])", r"\1", repaired)
            return json.loads(repaired)
        except Exception:
            pass

    if default is not None:
        return default

    raise ValueError(f"Failed to parse valid JSON from text: {text[:200]}...")


def parse_candidate_list(text: str) -> list[dict[str, str]]:
    """
    Parses a list of candidate injections from LLM response.
    Expected schema:
    [
        {"strategy": "...", "injection_text": "...", "rationale": "..."},
        ...
    ]
    or {"candidates": [...]}
    """
    raw_data = parse_structured_json(text, default=None)

    candidates: list[dict[str, str]] = []

    if isinstance(raw_data, list):
        for item in raw_data:
            if isinstance(item, dict):
                strat = str(item.get("strategy") or "general_injection").strip()
                inj = str(item.get("injection_text") or item.get("injection") or item.get("payload") or "").strip()
                rat = str(item.get("rationale") or item.get("reasoning") or "").strip()
                if inj:
                    candidates.append({"strategy": strat, "injection_text": inj, "rationale": rat})

    elif isinstance(raw_data, dict):
        # Could be {"candidates": [...]} or a single object
        c_list = raw_data.get("candidates") or raw_data.get("injections") or raw_data.get("attacks")
        if isinstance(c_list, list):
            return parse_candidate_list(json.dumps(c_list))

        # Single candidate dict
        strat = str(raw_data.get("strategy") or "general_injection").strip()
        inj = str(raw_data.get("injection_text") or raw_data.get("injection") or raw_data.get("payload") or "").strip()
        rat = str(raw_data.get("rationale") or raw_data.get("reasoning") or "").strip()
        if inj:
            candidates.append({"strategy": strat, "injection_text": inj, "rationale": rat})

    # Heuristic fallback if standard JSON didn't yield candidates
    if not candidates:
        logger.warning("Falling back to regex heuristic for candidate extraction")
        inj_matches = re.findall(r"(?:injection_text|injection|payload)[\"']?\s*:\s*[\"']([^\"']+)[\"']", text)
        strat_matches = re.findall(r"(?:strategy)[\"']?\s*:\s*[\"']([^\"']+)[\"']", text)

        for idx, inj in enumerate(inj_matches):
            strat = strat_matches[idx] if idx < len(strat_matches) else "heuristic_fallback"
            candidates.append({
                "strategy": strat,
                "injection_text": inj.strip(),
                "rationale": "Extracted via regex fallback parser",
            })

    return candidates


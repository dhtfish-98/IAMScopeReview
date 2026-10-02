"""Offline review prompts for broad AWS IAM JSON policy statements."""

from __future__ import annotations
import json


def _items(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return []


def review_text(text: str) -> list[dict[str, str]]:
    try:
        policy = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid IAM policy JSON") from exc
    if not isinstance(policy, dict) or "Statement" not in policy:
        raise ValueError("expected a policy object with Statement")
    statements = policy["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not all(isinstance(item, dict) for item in statements):
        raise ValueError("Statement must be an object or list of objects")
    findings = []
    for index, statement in enumerate(statements):
        effect = statement.get("Effect")
        if not isinstance(effect, str):
            raise ValueError("Effect must be a string")
        if effect.lower() != "allow":
            continue
        where = f"Statement[{index}]"
        actions = _items(statement.get("Action"))
        resources = _items(statement.get("Resource"))
        principals = statement.get("Principal")
        if "NotAction" in statement:
            findings.append({"rule": "allow-not-action", "location": where, "note": "Allow with NotAction needs a scope review"})
        if any(action == "*" or action.endswith(":*") for action in actions):
            findings.append({"rule": "broad-action", "location": where, "note": "A whole service or all actions are allowed"})
        if "*" in resources:
            findings.append({"rule": "broad-resource", "location": where, "note": "Resource is unrestricted; some actions legitimately require this"})
        if principals == "*" or isinstance(principals, dict) and "*" in _items(principals.get("AWS")):
            findings.append({"rule": "public-principal", "location": where, "note": "Principal includes everyone; inspect conditions and policy context"})
    return findings

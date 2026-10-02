"""Offline review prompts for broad AWS IAM JSON policy statements."""
from __future__ import annotations
from strict_json import loads


def _items(value, field):
    if isinstance(value, str) and value.strip():
        return [value]
    if isinstance(value, list) and value and all(isinstance(item, str) and item.strip() for item in value):
        return value
    raise ValueError(f"{field} must be a nonempty string or string array")


def review_text(text: str) -> list[dict[str, str]]:
    policy = loads(text)
    if not isinstance(policy, dict) or "Statement" not in policy:
        raise ValueError("expected a policy object with Statement")
    statements = policy["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements or not all(isinstance(item, dict) for item in statements):
        raise ValueError("Statement must contain policy statement objects")
    findings = []
    for index, statement in enumerate(statements):
        if statement.get("Effect") not in ("Allow", "Deny"):
            raise ValueError("Effect must be Allow or Deny")
        if sum(field in statement for field in ("Action", "NotAction")) != 1:
            raise ValueError("expected exactly one of Action and NotAction")
        for first, second in (("Resource", "NotResource"), ("Principal", "NotPrincipal")):
            if first in statement and second in statement:
                raise ValueError(f"{first} and {second} are mutually exclusive")
        fields = {field: _items(statement[field], field) for field in ("Action", "NotAction", "Resource", "NotResource") if field in statement}
        principal_items = []
        for field in ("Principal", "NotPrincipal"):
            if field not in statement:
                continue
            value = statement[field]
            if value == "*":
                principal_items.append("*")
            elif isinstance(value, dict) and value and all(isinstance(key, str) for key in value):
                for items in value.values():
                    principal_items.extend(_items(items, field))
            else:
                raise ValueError("Principal declaration has an invalid shape")
        if statement["Effect"] != "Allow":
            continue
        where = f"Statement[{index}]"
        def add(rule, note):
            findings.append({"rule": rule, "location": where, "note": note})
        if "NotAction" in fields:
            add("allow-not-action", "Allow with NotAction needs a scope review")
        if "NotResource" in fields:
            add("allow-not-resource", "Allow with NotResource needs a scope review")
        if "NotPrincipal" in statement:
            add("allow-not-principal", "Allow with NotPrincipal needs a scope review")
        if any(action == "*" or action.endswith(":*") for action in fields.get("Action", [])):
            add("broad-action", "A whole service or all actions are allowed")
        if "*" in fields.get("Resource", []):
            add("broad-resource", "Resource is unrestricted; some actions legitimately require this")
        if "Principal" in statement and "*" in principal_items:
            add("public-principal", "Principal includes everyone; inspect conditions and policy context")
    return findings

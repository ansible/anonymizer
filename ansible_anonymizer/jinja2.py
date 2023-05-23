#!/usr/bin/env python3
"""Jinja2 related function(s)."""
import re


def str_jinja2_variable_name(name: str) -> str:
    """Sanitize a string to make it suitable to become a Jinja2 variable."""
    name = name.replace("-", "_")
    name = re.sub(r"[^a-z_\d]", "", name, flags=re.IGNORECASE)
    return name.lower().lstrip("_")

#!/usr/bin/env python3
"""Functions used to identify the field types."""
import re

# Denylist regex to TC of secrets filter
# From detect_secrets.plugins (Apache v2 License)
DENYLIST = (
    "api_?key",
    "auth_?key",
    "service_?key",
    "account_?key",
    "db_?key",
    "database_?key",
    "priv_?key",
    "private_?key",
    "client_?key",
    r"host\w*_key",
    "db_?pass",
    "database_?pass",
    "key_?pass",
    "key_?data",
    "key_?name",
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "contraseña",
    "contrasena",
    "access_key",
)
AFFIX_REGEX = r"\w*"
DENYLIST_REGEX = r"|".join(DENYLIST)
# Support for suffix after keyword i.e. password_secure = "value"
DENYLIST_REGEX_WITH_PREFIX = fr"({DENYLIST_REGEX}){AFFIX_REGEX}"


def is_allowed_password_field(field_name: str) -> bool:
    """Return True if field_name should not be considered as a password."""
    # Valid field found in sudo configuration
    if field_name == "NOPASSWD":
        return True
    return False


def is_password_field_name(name: str) -> bool:
    """Return True if name looks like a password field name."""
    flags = re.MULTILINE | re.IGNORECASE
    if is_allowed_password_field(name):
        return False
    return re.search(DENYLIST_REGEX_WITH_PREFIX, name, flags=flags) is not None


def is_jinja2_expression(value: str) -> bool:
    """Check if an unquoted string hold a Jinja2 variable."""
    if re.match(r"^\s*{{\s*.*?\s*}}\s*$", value):
        return True

    return False


def is_uuid_string(value: str) -> bool:
    """Check if a given value is a UUID string."""
    if re.match(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        value,
        flags=re.IGNORECASE,
    ):
        return True

    return False


def is_path(content: str) -> bool:
    """Return True if content is a path."""
    # Rather conservative on purpose to avoid a false
    # positive
    if "/" not in content:
        return False
    return bool(re.match(r"^(|~)[a-z0-9_/\.-]+$", content, flags=re.IGNORECASE))

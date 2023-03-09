#!/usr/bin/env python3
import ipaddress
import random
import re
from ipaddress import IPv4Address
from ipaddress import IPv6Address
from typing import Callable
from typing import Match
from typing import Union
from typing import Any

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
    "host.*_key",
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
)
# Includes ], ', " as closing
CLOSING = r'[]\'"]{0,2}'
AFFIX_REGEX = r"\w*"
DENYLIST_REGEX = r"|".join(DENYLIST)
# Support for suffix after keyword i.e. password_secure = "value"
DENYLIST_REGEX_WITH_PREFIX = r"({denylist}){suffix}".format(
    denylist=DENYLIST_REGEX,
    suffix=AFFIX_REGEX,
)


def gen_email_address(_: Match[str]) -> str:
    samples = [
        "liam",
        "olivia",
        "noah",
        "emma",
        "oliver",
        "charlotte",
        "elijah",
        "amelia",
        "james",
        "ava",
        "william",
        "sophia",
        "benjamin",
        "isabella",
        "lucas",
        "mia",
        "henry",
        "evelyn",
        "theodore",
        "harper",
    ]
    return f"{random.choice(samples)}{random.randint(0, 100)}@example.com"


def is_jinja2(content: str) -> bool:
    flags = re.MULTILINE | re.DOTALL
    if bool(re.search(r"{{.*\w+.*}}", content, flags)):
        return True
    if bool(re.search(r"{%.*\w+.*%}", content, flags)):
        return True
    return False


def is_ip_address(content: str) -> bool:
    try:
        ipaddress.ip_address(content)
    except ValueError:
        return False
    return True


def is_email_address(content: str) -> bool:
    return bool(re.match(r".*\w+@[a-z\.]+[a-z]{2,}.*", content, flags=re.IGNORECASE))


def is_password_field_name(name: str) -> bool:
    return re.search(DENYLIST_REGEX_WITH_PREFIX, name) is not None


def is_valid_ssn(value: str) -> bool:
    if not value:
        return False
    ssn_regex = "^(?!666|000|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0{4})\\d{4}$"
    return re.search(ssn_regex, value) is not None


def is_valid_macaddress(value: str) -> bool:
    if not value:
        return False
    mac_regex = (
        r"^([0-9A-Fa-f]{2}[:-])"
        + r"{5}([0-9A-Fa-f]{2})|"  # noqa: W503
        + r"([0-9a-fA-F]{4}\\."  # noqa: W503
        + r"[0-9a-fA-F]{4}\\."  # noqa: W503
        + r"[0-9a-fA-F]{4})$"  # noqa: W503
    )
    return re.search(mac_regex, value) is not None


def is_valid_telephone_number(value: str) -> bool:
    tele_regex = r"^\s*(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?\s*$"
    return re.search(tele_regex, value) is not None


def is_valid_credit_card_number(value: str) -> bool:
    cc_regex = r"\b(?:\d[ -]*?){13,16}\b"
    return re.search(cc_regex, value) is not None


def remove_email(value: str) -> str:
    return re.sub(r".*(\w+@[a-z\.]+[a-z]{2,}).*", gen_email_address, value)


common_ipv4_networks = [
    ipaddress.IPv4Network("1.0.0.1/32"),
    ipaddress.IPv4Network("1.1.1.1/32"),
    ipaddress.IPv4Network("149.112.112.112/32"),
    ipaddress.IPv4Network("208.67.220.220/32"),
    ipaddress.IPv4Network("208.67.222.222/32"),
    ipaddress.IPv4Network("76.223.122.150/32"),
    ipaddress.IPv4Network("76.76.19.19/32"),
    ipaddress.IPv4Network("8.20.247.20/32"),
    ipaddress.IPv4Network("8.26.56.26/32"),
    ipaddress.IPv4Network("8.8.4.4/32"),
    ipaddress.IPv4Network("8.8.8.8/32"),
    ipaddress.IPv4Network("9.9.9.9/32"),
    ipaddress.IPv4Network("94.140.14.14/32"),
    ipaddress.IPv4Network("94.140.15.15/32"),
    ipaddress.IPv4Network("255.0.0.0/4", False),
    ipaddress.IPv4Network("255.255.255.255/32"),
]


def redact_ipv4_address(value: IPv4Address) -> IPv4Address:
    for i in common_ipv4_networks:
        if value in i:
            return value
    try:
        return value + random.randint(0, 100)
    except ipaddress.AddressValueError:
        return value


common_ipv6_networks = [
    ipaddress.IPv6Network("2001:4860:4860::8888/128"),
    ipaddress.IPv6Network("2001:4860:4860::8844/128"),
]


def redact_ipv6_address(value: IPv6Address) -> IPv6Address:
    for i in common_ipv6_networks:
        if value in i:
            return value

    def randomize(block: Match[str]) -> str:
        field = block.group(0)[1:]
        as_int = int(field, 16)
        new_val = random.randint(0, as_int)
        as_hex = hex(new_val)
        hex_without_0x_prefix = as_hex[2:]
        return ":" + hex_without_0x_prefix

    new_address = ipaddress.IPv6Address(
        re.sub(r":[a-z0-9]+", randomize, value.compressed, flags=re.IGNORECASE)
    )
    return new_address


def redact_ip_address(value: str) -> str:
    ip = ipaddress.ip_address(value)
    func: Callable[[Union[IPv4Address | IPv6Address]], Union[IPv4Address | IPv6Address]]
    func = {4: redact_ipv4_address, 6: redact_ipv6_address}[ip.version]  # type: ignore
    return str(func(ip))


def anonymize_field(value: str, name: str) -> str:
    v = value.strip()
    if not v:
        return value
    elif is_jinja2(v):
        return value
    elif is_ip_address(v):
        return redact_ip_address(v)
    elif is_email_address(v):
        return remove_email(v)
    elif is_valid_ssn(v):
        return "{{ }}"
    elif is_valid_macaddress(v):
        return "{{ }}"
    elif is_valid_telephone_number(v):
        return "{{ }}"
    elif is_valid_credit_card_number(v):
        return "{{ }}"
    if is_password_field_name(name):
        if is_path(v):
            return value
        return "{{ }}"
    return value


def is_path(content: str) -> bool:
    # Rather conservative on purpose to avoid a false
    # positive
    if "/" not in content:
        return False
    return bool(re.match(r"^(|~)[a-z0-9_/\.-]+$", content, flags=re.IGNORECASE))


def walker(o: Any, key_name: str = "") -> Any:
    def key_name_str(k: Any) -> str:
        return k if isinstance(k, str) else ""

    if key_name and not isinstance(key_name, str):
        key_name = str(key_name)
    if isinstance(o, dict):
        return {k: walker(v, key_name=key_name_str(k)) for k, v in o.items()}
    elif isinstance(o, list):
        return [walker(v, key_name=key_name) for v in o]
    elif isinstance(o, str):
        return anonymize_field(o, key_name)
    return o


def anonymize(predictions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def cleanup(p: Any) -> Any:
        py_struct = p
        clean = walker(py_struct)
        return clean

    return [cleanup(p) for p in predictions]

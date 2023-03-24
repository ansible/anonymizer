#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
import ipaddress
import re
from ipaddress import IPv4Address
from ipaddress import IPv6Address
from typing import Any
from typing import Callable
from typing import Generator
from typing import Match
from typing import Union
from zlib import crc32

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
    "access_key",
)
AFFIX_REGEX = r"\w*"
DENYLIST_REGEX = r"|".join(DENYLIST)
# Support for suffix after keyword i.e. password_secure = "value"
DENYLIST_REGEX_WITH_PREFIX = fr"({DENYLIST_REGEX}){AFFIX_REGEX}"


def str_jinja2_variable_name(name: str) -> str:
    """Sanitize a string to make it suitable to become a Jinja2 variable."""
    name = name.replace("-", "_")
    name = re.sub(r'[^a-z_]', '', name, flags=re.IGNORECASE)
    return name


def gen_email_address(original: Match[str]) -> str:
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
    idx = crc32(original.group('email').encode()) % len(samples)
    name = samples[idx]
    return f"{name}{idx}@example.com"


def is_password_field_name(name: str) -> bool:
    return re.search(DENYLIST_REGEX_WITH_PREFIX, name) is not None


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
        return value + int(value) % 100
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
        new_val = as_int % 1024
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
    if is_password_field_name(name):
        if is_path(v):
            return value
        variable_name = str_jinja2_variable_name(name)
        return f"{{{{ { variable_name } }}}}"
    return anonymize_text_block(v)


def is_path(content: str) -> bool:
    # Rather conservative on purpose to avoid a false
    # positive
    if "/" not in content:
        return False
    return bool(re.match(r"^(|~)[a-z0-9_/\.-]+$", content, flags=re.IGNORECASE))


def anonymize_struct(o: Any, key_name: str = "") -> Any:
    def key_name_str(k: Any) -> str:
        return k if isinstance(k, str) else ""

    if key_name and not isinstance(key_name, str):
        key_name = str(key_name)

    if isinstance(o, dict):
        return {k: anonymize_struct(v, key_name=key_name_str(k)) for k, v in o.items()}
    if isinstance(o, list):
        return [anonymize_struct(v, key_name=key_name) for v in o]
    if isinstance(o, str):
        return anonymize_field(o, key_name)
    return o


def anonymize(o: Any, key_name: str = "") -> Any:
    """Deprecated: use anonymize_struct() instead"""
    return anonymize_struct(o, key_name=key_name)


def hide_secrets(block: str) -> str:
    flags = re.MULTILINE | re.DOTALL | re.IGNORECASE

    def _rewrite(m: re.Match[str]) -> str:
        value = m.group('value')
        if is_path(value):
            return m.group(0)
        field = m.group('field')
        return f"{field}: {anonymize_field(value, field)}"

    return re.sub(
        fr"((?P<field>(|\S+){DENYLIST_REGEX_WITH_PREFIX}):\s*(?P<value>\S+))",
        _rewrite,
        block,
        flags=flags,
    )


def hide_emails(block: str) -> str:
    flags = re.MULTILINE | re.DOTALL | re.IGNORECASE
    email_re = r"\b\S+@[a-z\.]+[a-z]{2,}\b"
    return re.sub(fr"(?P<email>{email_re})", gen_email_address, block, flags=flags)


def hide_ip_addresses(block: str) -> str:
    flags = re.MULTILINE | re.DOTALL | re.IGNORECASE

    def _rewrite(m: re.Match[str]) -> str:
        try:
            ip = ipaddress.ip_address(m.group('ip_address'))
        except ValueError:
            return m.group('ip_address')
        func: Callable[[Union[IPv4Address | IPv6Address]], Union[IPv4Address | IPv6Address]]
        func = {4: redact_ipv4_address, 6: redact_ipv6_address}[ip.version]  # type: ignore
        return str(func(ip))

    return re.sub(
        r"(?P<ip_address>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[a-f\d:]{3,32})",
        _rewrite,
        block,
        flags=flags,
    )


def hide_us_ssn(block: str) -> str:
    flags = re.MULTILINE | re.DOTALL | re.IGNORECASE

    def _rewrite(_: re.Match[str]) -> str:
        return "{{ ssn }}"

    us_ssn_regex = r"\b(?!666|000|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4}\b"
    return re.sub(us_ssn_regex, _rewrite, block, flags=flags)


def hide_mac_addresses(block: str) -> str:
    flags = re.MULTILINE | re.DOTALL | re.IGNORECASE

    def _rewrite(m: re.Match[str]) -> str:
        idx = crc32(m.group('mac').encode())

        def gen() -> Generator[str, None, None]:
            for c in m.group('mac'):
                if c in ["-", ":", "."]:
                    yield c
                else:
                    yield str(hex(int(c, 16) + idx % 0xF)[-1])

        return "".join(c for c in gen())

    mac_regex = (
        r"(?P<mac>\b([0-9a-f]{2}[:-])"
        + r"{5}([0-9a-f]{2})|"  # noqa: W503
        + r"([0-9a-f]{4}\."  # noqa: W503
        + r"[0-9a-f]{4}\."  # noqa: W503
        + r"[0-9a-f]{4})\b)"  # noqa: W503
    )
    return re.sub(mac_regex, _rewrite, block, flags=flags)


def hide_us_phone_numbers(block: str) -> str:
    flags = re.MULTILINE | re.DOTALL | re.IGNORECASE

    def _rewrite(m: re.Match[str]) -> str:
        return m.group("before") + "(311) 555-2368" + m.group("after")

    pattern_before = r"(?P<before>([^\d\.]|^))"
    pattern_after = r"(?P<after>([^\d\.]|$))"
    regexes = [
        r"(?P<number>\d{10})",
        r"(?P<number>1\d{10})",
        r"(?P<number>\d{3}-\d{3}-\d{4})",
        r"(?P<number>\d{3} \d{3}-\d{4})",
        r"(?P<number>\(\d{3}\) \d{3}-\d{4})",
    ]

    for r in regexes:
        full_regex = pattern_before + r + pattern_after
        block = re.sub(full_regex, _rewrite, block, flags=flags)
    return block


def hide_credit_cards(block: str) -> str:
    flags = re.MULTILINE | re.DOTALL | re.IGNORECASE

    def _rewrite(m: re.Match[str]) -> str:
        def luhn(n: str) -> bool:
            r = [int(ch) for ch in str(n)][::-1]
            return (sum(r[0::2]) + sum(sum(divmod(d * 2, 10)) for d in r[1::2])) % 10 == 0

        cc = m.group("cc").replace(" ", "").replace("-", "")
        if luhn(cc):
            return "{{ credit_card_number }}"
        return m.group("cc")

    cc_regex = r"(?P<cc>\b(?:\d[ -]*?){13,16}\b)"

    return re.sub(cc_regex, _rewrite, block, flags=flags)


def hide_comments(block: str) -> str:
    new_block = ""
    quotes = ""
    in_comment = False
    for c in block:
        if c in ['"', "'"]:
            if quotes and quotes[-1] == c:
                quotes = quotes[:-1]
            else:
                quotes += c
            new_block += c
        elif c == "\n":
            in_comment = False
            quotes = ""
            new_block += c
        elif in_comment:
            continue
        elif c == "#" and not quotes:
            in_comment = True
            new_block = new_block.rstrip(" ")
        else:
            new_block += c
    return new_block


def hide_user_name(block: str) -> str:
    flags = re.IGNORECASE

    known_users = {
        "cloud-user",
        "ec2-user",
        "fedora",
        "root",
        "ubuntu",
        "user",
    }

    def _rewrite(m: re.Match[str]) -> str:
        if m.group("user_name") in known_users:
            user = m.group("user_name")
        else:
            user = "ano-user"
        return m.group("before") + user

    user_regexes = [
        r"(?P<before>[c-z]:\\users\\)(?P<user_name>\w{,255})",
        r"(?P<before>/(home|Users)/)(?P<user_name>[a-z0-9_-]{,255})",
    ]
    for regex in user_regexes:
        block = re.sub(regex, _rewrite, block, flags=flags)
    return block


def anonymize_text_block(block: str) -> str:
    transformation = [
        hide_comments,
        hide_secrets,
        hide_emails,
        hide_ip_addresses,
        hide_us_ssn,
        hide_mac_addresses,
        hide_us_phone_numbers,
        hide_credit_cards,
        hide_user_name,
    ]

    for t in transformation:
        block = t(block)
    return block

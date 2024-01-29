#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
import ipaddress
import re
from collections.abc import Generator
from ipaddress import IPv4Address, IPv6Address
from re import Match
from string import Template
from typing import Any, Optional
from zlib import crc32

from ansible_anonymizer.field_checks import (
    is_jinja2_expression,
    is_password_field_name,
    is_path,
    is_uuid_string,
)
from ansible_anonymizer.jinja2 import str_jinja2_variable_name
from ansible_anonymizer.parser import flatten, parse_raw_block

from .node import NodeType


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
    idx = crc32(original.group("email").encode()) % len(samples)
    name = samples[idx]
    return f"{name}{idx}@example.com"


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
    if ip.version == 4:
        return str(redact_ipv4_address(ip))
    return str(redact_ipv6_address(ip))


def unquote(value: str) -> str:
    if not value or len(value) < 2:
        return value
    if value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def anonymize_field(value: str, name: str, value_template: Template) -> str:
    v = value.strip()
    if is_uuid_string(v):
        return value
    if is_password_field_name(name):
        if is_path(v):
            return value
        if is_jinja2_expression(unquote(v)):
            return unquote(v)
        variable_name = str_jinja2_variable_name(name)
        return value_template.substitute(variable_name=variable_name)
    return anonymize_text_block(value, value_template=value_template)


def anonymize_struct(o: Any, key_name: str = "", value_template: Optional[Template] = None) -> Any:
    if not value_template:
        value_template = Template("{{ $variable_name }}")

    def key_name_str(k: Any) -> str:
        return k if isinstance(k, str) else ""

    if key_name and not isinstance(key_name, str):
        key_name = str(key_name)

    if isinstance(o, dict):
        return {
            k: anonymize_struct(v, key_name=key_name_str(k), value_template=value_template)
            for k, v in o.items()
        }
    if isinstance(o, list):
        return [anonymize_struct(v, key_name=key_name, value_template=value_template) for v in o]
    if isinstance(o, str):
        return anonymize_field(o, key_name, value_template)
    return o


def anonymize(o: Any, key_name: str = "") -> Any:
    """Deprecated: use anonymize_struct() instead."""
    return anonymize_struct(o, key_name=key_name)


def hide_emails(block: str) -> str:
    flags = re.MULTILINE | re.DOTALL | re.IGNORECASE
    email_re = r"\b\S+@[a-z\.]+[a-z]{2,}\b"
    return re.sub(fr"(?P<email>{email_re})", gen_email_address, block, flags=flags)


def hide_ip_addresses(block: str) -> str:
    flags = re.MULTILINE | re.DOTALL | re.IGNORECASE

    def _rewrite(m: re.Match[str]) -> str:
        try:
            ip = ipaddress.ip_address(m.group("ip_address"))
        except ValueError:
            return m.group("ip_address")
        if ip.version == 4:
            return str(redact_ipv4_address(ip))
        return str(redact_ipv6_address(ip))

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
        idx = crc32(m.group("mac").encode())

        def gen() -> Generator[str, None, None]:
            for c in m.group("mac"):
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
        new_value = "{{ credit_card_number }}" if luhn(cc) else m.group("cc")
        return m.group("before") + new_value + m.group("after")

    cc_regex = r"(?P<before>([^\d-]|^))(?P<cc>(?:\d[ -]*?){13,16})(?P<after>([^\d-]|$))"

    return re.sub(cc_regex, _rewrite, block, flags=flags)


def hide_comments(block: str) -> str:
    new_block = ""
    quotes = ""
    in_comment = False
    for c in block:
        if c == "\n":
            in_comment = False
            quotes = ""
            new_block += c
        elif in_comment:
            continue
        elif c in ['"', "'"]:
            if quotes and quotes[-1] == c:
                quotes = quotes[:-1]
            else:
                quotes += c
            new_block += c
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
        user = (
            m.group("user_name")
            if (m.group("user_name") in known_users or is_jinja2_expression(m.group("user_name")))
            else "ano-user"
        )
        return m.group("before") + user

    user_regexes = [
        r"(?P<before>[c-z]:\\users\\)(?P<user_name>(\w|{{\s*.*?\s*}}){,255})",
        r"(?P<before>/(home|Users)/)(?P<user_name>([a-z0-9_-]|{{\s*.*?\s*}}){,255})",
    ]
    for regex in user_regexes:
        block = re.sub(regex, _rewrite, block, flags=flags)
    return block


def hide_secrets(block: str, value_template: Template) -> str:
    root_node = parse_raw_block(block)

    output = ""
    for node in flatten(root_node):
        if node.type is NodeType.secret:
            if node.previous.type is node.holder:  # type: ignore[comparison-overlap]
                # Already quoted
                quote = ""
            else:
                quote = "" if node.holder and node.holder.text else '"'
            if not node.secret_value_of:
                # Should never happen
                continue
            output += quote + anonymize_field("", node.secret_value_of.text, value_template) + quote
        else:
            output += node.text
    return output


def anonymize_text_block(block: str, value_template: Optional[Template] = None) -> str:
    if not value_template:
        value_template = Template("{{ $variable_name }}")

    block = hide_comments(block)
    block = hide_secrets(block, value_template)
    block = hide_emails(block)
    block = hide_ip_addresses(block)
    block = hide_us_ssn(block)
    block = hide_mac_addresses(block)
    block = hide_us_phone_numbers(block)
    block = hide_credit_cards(block)
    block = hide_user_name(block)

    return block

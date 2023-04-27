#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
import ipaddress
import re
from collections.abc import Generator
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from re import Match
from typing import Any, Callable, Union
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


def str_jinja2_variable_name(name: str) -> str:
    """Sanitize a string to make it suitable to become a Jinja2 variable."""
    name = name.replace("-", "_")
    name = re.sub(r"[^a-z_\d]", "", name, flags=re.IGNORECASE)
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
    idx = crc32(original.group("email").encode()) % len(samples)
    name = samples[idx]
    return f"{name}{idx}@example.com"


def is_password_field_name(name: str) -> bool:
    flags = re.MULTILINE | re.IGNORECASE
    if is_allowed_password_field(name):
        return False
    return re.search(DENYLIST_REGEX_WITH_PREFIX, name, flags=flags) is not None


def is_allowed_password_field(field_name: str) -> bool:
    """Return True if field_name should not be considered as a password."""
    # Valid field found in sudo configuration
    if field_name == "NOPASSWD":
        return True
    return False


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


def unquote(value: str) -> str:
    if not value or len(value) < 2:
        return value
    if value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def anonymize_field(value: str, name: str) -> str:
    v = value.strip()
    if is_uuid_string(v):
        return value
    if is_password_field_name(name):
        if is_path(v):
            return value
        if is_jinja2_expression(unquote(v)):
            return unquote(v)
        variable_name = str_jinja2_variable_name(name)
        return f"{{{{ { variable_name } }}}}"
    return anonymize_text_block(value)


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
    """Deprecated: use anonymize_struct() instead."""
    return anonymize_struct(o, key_name=key_name)


def hide_secrets(block: str) -> str:
    class State(Enum):
        NONE = 1  # Nothing special, just record the character
        IN_FIELD = 2  # Potentially in a field name
        POST_FIELD = 3  # After a field name to anonymize
        IN_PLAIN_PASSWORD = 4  # Inside a password block
        IN_QUOTED_PASSWORD = 5  # Inside a password block that is quoted

    class StateMachine:
        def __init__(self) -> None:
            self.c = ""
            self.char_is_protected = False
            self.current_text_string = ""
            self.field_name = ""
            self.final = ""
            self.next_char_is_protected = False
            self.password_capture_quote_level = 0
            self.popped_quote = ''
            self.quote_stack: list[str] = []
            self.state = State.NONE

        def record_secret(self, quoted: bool=False) -> None:
            # We ignore the Jinja2 expression
            variable_name = str_jinja2_variable_name(self.field_name.lower())
            if self.current_text_string.startswith("{{"):
                self.final += sm.current_text_string
            elif is_path(sm.current_text_string):
                self.final += sm.current_text_string
            elif quoted:
                self.final += f'"{{{{ { variable_name } }}}}"'
            else:
                self.final += f"{{{{ { variable_name } }}}}"
            self.current_text_string = ""

        def record_c(self) -> None:
            self.final += self.c

        def set_state(self, state: State) -> None:
            if state in [State.IN_PLAIN_PASSWORD, State.IN_QUOTED_PASSWORD]:
                self.password_capture_quote_level = len(self.quote_stack)

            if self.state == State.IN_PLAIN_PASSWORD and state == State.NONE:
                self.record_secret(quoted=not sm.password_capture_quote_level > 0)
            if self.state == State.IN_QUOTED_PASSWORD and state == State.NONE:
                self.record_secret()

            if self.state == State.IN_FIELD and state == State.POST_FIELD:
                self.field_name = self.current_text_string
                self.current_text_string = ""

            if state == State.NONE:
                self.current_text_string = ""
                self.field_name = ""
                self.password_capture_quote_level = 0

            self.state = state

        def set_c(self, c: str) -> None:
            self.popped_quote = ''
            self.c = c
            self.char_is_protected = self.next_char_is_protected
            self.next_char_is_protected = False

        def is_quote_opening(self) -> bool:
            if self.char_is_protected:
                return False
            if c not in ["'", '"']:
                return False
            if c in self.quote_stack:
                return False
            return True

        def is_quote_closing(self) -> bool:
            if not sm.quote_stack:
                return False
            if sm.char_is_protected:
                return False
            return sm.quote_stack[-1] == c

        def is_backslash(self) -> bool:
            return c == "\\"

        def is_space(self) -> bool:
            return self.c == " "

        def is_quote(self) -> bool:
            return self.c in ["'", '"']

        def is_quote_closing_password(self) -> bool:
            return (
                self.c == self.popped_quote
                and self.password_capture_quote_level == len(self.quote_stack) + 1
            )

        def is_password_closing(self) -> bool:
            if self.c == self.popped_quote:
                return True
            return self.c in [" ", "\n"]

        def is_inside_quoted_password(self) -> bool:
            return not self.popped_quote and self.c != " "

        def is_valid_first_character_for_a_variable(self) -> bool:
            """Assuming variable names cannot start with a digit."""
            return self.c.isascii() and self.c.isalpha()

        def is_valid_variable_character(self) -> bool:
            return self.c.isascii() and (self.c.isalnum() or self.c in ["-", "_"])

        def is_field_closing(self) -> bool:
            return self.c in [":", "="]

    sm = StateMachine()
    for c in block:
        sm.set_c(c)

        # Quote management
        if sm.is_quote_opening():
            sm.quote_stack.append(c)
        elif sm.is_quote_closing():
            sm.popped_quote = sm.quote_stack.pop()
        elif sm.is_backslash():
            sm.next_char_is_protected = True

        # State based changes
        if sm.state == State.POST_FIELD:
            if sm.is_space():
                sm.record_c()
            elif sm.is_quote():
                sm.set_state(State.IN_QUOTED_PASSWORD)
                sm.record_c()
            elif sm.c not in [" ", "\n"]:
                sm.set_state(State.IN_PLAIN_PASSWORD)
                sm.current_text_string += c
        elif sm.state == State.IN_PLAIN_PASSWORD:
            if sm.is_password_closing():
                sm.set_state(State.NONE)
                sm.record_c()
            else:
                sm.current_text_string += sm.c
        elif sm.state == State.IN_QUOTED_PASSWORD:
            if sm.is_quote_closing_password():
                sm.set_state(State.NONE)
                sm.record_c()
            else:
                sm.current_text_string += sm.c
        elif sm.state == State.NONE:
            if sm.is_valid_first_character_for_a_variable():
                sm.current_text_string += c
                sm.set_state(State.IN_FIELD)
            sm.record_c()
        elif sm.state == State.IN_FIELD:
            if sm.is_field_closing():
                print("- closing")
                if is_password_field_name(sm.current_text_string):
                    sm.record_c()
                    sm.set_state(State.POST_FIELD)
                else:
                    sm.record_c()
                    sm.set_state(State.NONE)
            elif sm.is_valid_variable_character():
                print("- valid characher")
                sm.record_c()
                sm.current_text_string += c
            else:
                print("- Something else")
                sm.record_c()
                sm.set_state(State.NONE)

    sm.set_state(State.NONE)
    return sm.final


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
        user = m.group("user_name") if m.group("user_name") in known_users else "ano-user"
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
